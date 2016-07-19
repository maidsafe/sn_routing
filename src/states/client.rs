// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use crust::{PeerId, Service};
use crust::Event as CrustEvent;
#[cfg(feature = "use-mock-crust")]
use kademlia_routing_table::RoutingTable;
use lru_time_cache::LruCache;
use maidsafe_utilities::serialisation;
use std::fmt::{self, Debug, Formatter};
use std::sync::mpsc::Sender;
use std::time::Duration;

use ack_manager::{ACK_TIMEOUT_SECS, AckManager};
use action::Action;
use authority::Authority;
use cache::Cache;
use error::{InterfaceError, RoutingError};
use event::Event;
use id::{FullId, PublicId};
use message_accumulator::MessageAccumulator;
use messages::{HopMessage, Message, MessageContent, RoutingMessage, SignedMessage, UserMessage,
               UserMessageCache};
use peer_manager::{GROUP_SIZE, NodeInfo, PeerManager};
use signed_message_filter::SignedMessageFilter;
use state_machine::Transition;
use stats::Stats;
use super::common::{self, USER_MSG_CACHE_EXPIRY_DURATION_SECS};
use super::Node;
use timer::Timer;
use tunnels::Tunnels;
use types::MessageId;
use xor_name::XorName;

/// Time (in seconds) after which a `GetNodeName` request is resent.
const GET_NODE_NAME_TIMEOUT_SECS: u64 = 60;

pub struct Client {
    ack_mgr: AckManager,
    cache: Box<Cache>,
    crust_service: Service,
    event_sender: Sender<Event>,
    full_id: FullId,
    get_node_name_timer_token: Option<u64>,
    is_listening: bool,
    msg_accumulator: MessageAccumulator,
    peer_mgr: PeerManager,
    signed_msg_filter: SignedMessageFilter,
    stats: Stats,
    timer: Timer,
    tunnels: Tunnels,
    user_msg_cache: UserMessageCache,
}

impl Client {
    #[cfg_attr(feature = "clippy", allow(too_many_arguments))]
    pub fn from_bootstrapping(proxy_public_id: PublicId,
                              proxy_peer_id: PeerId,
                              quorum_size: usize,
                              cache: Box<Cache>,
                              client_restriction: bool,
                              crust_service: Service,
                              event_sender: Sender<Event>,
                              full_id: FullId,
                              stats: Stats,
                              timer: Timer)
                              -> Self {
        let our_info = NodeInfo::new(*full_id.public_id(), crust_service.id());
        let mut peer_mgr = PeerManager::new(our_info);
        let _ = peer_mgr.set_proxy(proxy_peer_id, proxy_public_id);

        let mut msg_accumulator = MessageAccumulator::new();
        msg_accumulator.set_quorum_size(quorum_size);

        let user_msg_cache_duration = Duration::from_secs(USER_MSG_CACHE_EXPIRY_DURATION_SECS);

        let mut client = Client {
            ack_mgr: AckManager::new(),
            cache: cache,
            crust_service: crust_service,
            event_sender: event_sender,
            full_id: full_id,
            get_node_name_timer_token: None,
            is_listening: false,
            msg_accumulator: msg_accumulator,
            peer_mgr: peer_mgr,
            signed_msg_filter: SignedMessageFilter::new(),
            stats: stats,
            timer: timer,
            tunnels: Default::default(),
            user_msg_cache: UserMessageCache::with_expiry_duration(user_msg_cache_duration),
        };

        debug!("{:?} - State changed to client, quorum size: {}.",
               client,
               quorum_size);

        if client_restriction {
            let _ = client.event_sender.send(Event::Connected);
        } else if !client.start_listening() {
            // We are a client trying to become a node.
            let _ = client.event_sender.send(Event::Terminate);
        }

        client
    }

    pub fn handle_action(&mut self, action: Action) -> Transition {
        let result = match action {
            Action::ClientSendRequest { content, dst, priority, result_tx } => {
                let result = if let Ok(src) = self.get_client_authority() {
                    let user_msg = UserMessage::Request(content);

                    match self.send_user_message(src, dst, user_msg, priority) {
                        Err(RoutingError::Interface(err)) => Err(err),
                        Err(_) | Ok(_) => Ok(()),
                    }
                } else {
                    Err(InterfaceError::NotConnected)
                };

                result_tx.send(result).is_ok()
            }
            Action::NodeSendMessage { src, dst, content, priority, result_tx } => {
                let result = match self.send_user_message(src, dst, content, priority) {
                    Err(RoutingError::Interface(err)) => Err(err),
                    Err(_) | Ok(()) => Ok(()),
                };

                result_tx.send(result).is_ok()
            }
            Action::CloseGroup { result_tx, .. } => result_tx.send(None).is_ok(),
            Action::Name { result_tx } => result_tx.send(*self.name()).is_ok(),
            Action::QuorumSize { result_tx } => {
                // TODO: return the actual quorum size. To do that, we need to
                // extend the MessageAccumulator's API with a method to retrieve it.
                result_tx.send(0).is_ok()
            }
            Action::Timeout(token) => self.handle_timeout(token),
            Action::Terminate => false,
        };

        if result {
            Transition::Stay
        } else {
            Transition::Terminate
        }
    }

    pub fn handle_crust_event(&mut self, crust_event: CrustEvent) -> Transition {
        match crust_event {
            CrustEvent::BootstrapConnect(peer_id, _) => {
                self.disconnect_peer(&peer_id);
                Transition::Stay
            }
            CrustEvent::ListenerStarted(port) => self.handle_listener_started(port),
            CrustEvent::ListenerFailed => {
                error!("{:?} Failed to start listening.", self);
                let _ = self.event_sender.send(Event::Terminate);
                Transition::Terminate
            }
            CrustEvent::LostPeer(peer_id) => {
                self.handle_lost_peer(peer_id);
                Transition::Stay
            }
            CrustEvent::NewMessage(peer_id, bytes) => {
                match self.handle_new_message(peer_id, bytes) {
                    Ok(transition) => transition,
                    Err(RoutingError::FilterCheckFailed) => Transition::Stay,
                    Err(error) => {
                        debug!("{:?} - {:?}", self, error);
                        Transition::Stay
                    }
                }
            }
            _ => {
                debug!("{:?} Unhandled crust event {:?}", self, crust_event);
                Transition::Stay
            }
        }
    }

    pub fn into_node(self, close_group_ids: Vec<PublicId>, dst: Authority) -> Node {
        Node::from_client(close_group_ids,
                          dst,
                          self.cache,
                          self.crust_service,
                          self.event_sender,
                          self.full_id,
                          self.msg_accumulator,
                          self.peer_mgr,
                          self.stats,
                          self.timer,
                          self.tunnels)
    }

    /// Returns the `XorName` of this node.
    pub fn name(&self) -> &XorName {
        self.full_id.public_id().name()
    }

    /// Routing table of this node.
    #[cfg(feature = "use-mock-crust")]
    pub fn routing_table(&self) -> &RoutingTable<XorName> {
        self.peer_mgr.routing_table()
    }

    /// Resends all unacknowledged messages.
    #[cfg(feature = "use-mock-crust")]
    pub fn resend_unacknowledged(&mut self) -> bool {
        self.timer.stop();
        let timer_tokens = self.ack_mgr.timer_tokens();
        for timer_token in &timer_tokens {
            self.resend_timed_out_unacknowledged(*timer_token);
        }
        !timer_tokens.is_empty()
    }

    /// Are there any unacknowledged messages?
    #[cfg(feature = "use-mock-crust")]
    pub fn has_unacknowledged(&self) -> bool {
        self.ack_mgr.has_pending()
    }

    /// Clears all state containers except `bootstrap_blacklist`.
    #[cfg(feature = "use-mock-crust")]
    pub fn clear_state(&mut self) {
        self.ack_mgr.clear();
        self.msg_accumulator.clear();
        self.peer_mgr.clear_caches();
        self.signed_msg_filter.clear();
    }

    fn handle_listener_started(&mut self, port: u16) -> Transition {
        trace!("{:?} Listener started on port {}.", self, port);
        self.crust_service.set_service_discovery_listen(true);

        if let Err(error) = self.relocate() {
            error!("{:?} Failed to start relocation: {:?}", self, error);
            let _ = self.event_sender.send(Event::RestartRequired);
            Transition::Terminate
        } else {
            Transition::Stay
        }
    }

    fn handle_new_message(&mut self,
                          peer_id: PeerId,
                          bytes: Vec<u8>)
                          -> Result<Transition, RoutingError> {
        match serialisation::deserialise(&bytes) {
            Ok(Message::Hop(ref hop_msg)) => self.handle_hop_message(hop_msg, peer_id),
            Ok(message) => {
                debug!("{:?} - Unhandled new message: {:?}", self, message);
                Ok(Transition::Stay)
            }
            Err(error) => Err(RoutingError::SerialisationError(error)),
        }
    }

    fn handle_hop_message(&mut self,
                          hop_msg: &HopMessage,
                          peer_id: PeerId)
                          -> Result<Transition, RoutingError> {
        if let Some(pub_id) = self.peer_mgr.get_proxy_public_id(&peer_id) {
            try!(hop_msg.verify(pub_id.signing_public_key()));
        } else {
            return Err(RoutingError::UnknownConnection(peer_id));
        }

        let signed_msg = hop_msg.content();
        try!(signed_msg.check_integrity());

        // Prevents someone sending messages repeatedly to us
        if self.signed_msg_filter.filter_incoming(signed_msg) > GROUP_SIZE {
            return Err(RoutingError::FilterCheckFailed);
        }

        let routing_msg = signed_msg.routing_message();

        if !self.is_recipient(&routing_msg.dst) {
            return Ok(Transition::Stay);
        }

        self.handle_routing_message(routing_msg, *signed_msg.public_id())
    }

    fn handle_routing_message(&mut self,
                              routing_msg: &RoutingMessage,
                              public_id: PublicId)
                              -> Result<Transition, RoutingError> {
        if let Some(msg) = try!(self.msg_accumulator.add(routing_msg, public_id)) {
            if msg.src.is_group() {
                self.send_ack(&msg, 0);
            }

            Ok(self.dispatch_routing_message(&msg))
        } else {
            Ok(Transition::Stay)
        }
    }

    fn dispatch_routing_message(&mut self, routing_msg: &RoutingMessage) -> Transition {
        let msg_content = routing_msg.content.clone();
        let msg_src = routing_msg.src.clone();
        let msg_dst = routing_msg.dst.clone();

        match msg_content {
            MessageContent::Ack(..) => (),
            _ => {
                trace!("{:?} Got routing message {:?} from {:?} to {:?}.",
                       self,
                       msg_content,
                       msg_src,
                       msg_dst)
            }
        }

        match (msg_content, msg_src, msg_dst) {
            // Ack
            (MessageContent::Ack(ack, _), _, _) => self.handle_ack_response(ack),
            // GetNodeNameResponse
            (MessageContent::GetNodeNameResponse { relocated_id, close_group_ids, .. },
             Authority::NodeManager(_),
             dst) => self.handle_get_node_name_response(relocated_id, close_group_ids, dst),
            // UserMessagePart
            (MessageContent::UserMessagePart { hash, part_count, part_index, payload, .. },
             src,
             dst) => self.handle_user_message_part(hash, part_count, part_index, payload, src, dst),
            // other
            _ => {
                debug!("{:?} - Unhandled routing message: {:?}", self, routing_msg);
                Transition::Stay
            }
        }
    }

    fn handle_get_node_name_response(&mut self,
                                     relocated_id: PublicId,
                                     close_group_ids: Vec<PublicId>,
                                     dst: Authority)
                                     -> Transition {
        self.full_id.public_id_mut().set_name(*relocated_id.name());
        let our_info = NodeInfo::new(*self.full_id.public_id(), self.crust_service.id());
        self.peer_mgr.reset_routing_table(our_info);

        Transition::IntoNode {
            close_group_ids: close_group_ids,
            dst: dst,
        }
    }

    fn handle_ack_response(&mut self, ack: u64) -> Transition {
        self.ack_mgr.receive(ack);
        Transition::Stay
    }

    fn handle_user_message_part(&mut self,
                                hash: u64,
                                part_count: u32,
                                part_index: u32,
                                payload: Vec<u8>,
                                src: Authority,
                                dst: Authority)
                                -> Transition {
        if let Some(msg) = self.user_msg_cache.add(hash, part_count, part_index, payload) {
            common::handle_user_message(msg, src, dst, &self.event_sender, &mut self.stats)
        }

        Transition::Stay
    }

    fn handle_timeout(&mut self, token: u64) -> bool {
        if self.get_node_name_timer_token == Some(token) {
            info!("{:?} Failed to get GetNodeName response.", self);
            let _ = self.event_sender.send(Event::RestartRequired);
            return false;
        }

        self.resend_timed_out_unacknowledged(token);

        true
    }

    fn handle_lost_peer(&mut self, peer_id: PeerId) {
        if peer_id == self.crust_service.id() {
            error!("{:?} LostPeer fired with our crust peer id", self);
            return;
        }

        debug!("{:?} Received LostPeer - {:?}", self, peer_id);
        let _ = self.peer_mgr.remove_peer(&peer_id);
        self.dropped_proxy_connection(&peer_id);
    }

    fn dropped_proxy_connection(&mut self, peer_id: &PeerId) {
        if self.peer_mgr.get_proxy_public_id(peer_id).is_some() {
            if let Some((_, _, public_id)) = self.peer_mgr.remove_proxy() {
                debug!("{:?} Lost bootstrap connection to {:?} ({:?}).",
                       self,
                       public_id.name(),
                       peer_id);
                let _ = self.event_sender.send(Event::Terminate);
            }
        }
    }

    fn start_listening(&mut self) -> bool {
        if !self.is_listening {
            if let Err(error) = self.crust_service.start_listening_tcp() {
                error!("{:?} Failed to start listening: {:?}", self, error);
            } else {
                info!("{:?} Attempting to start listener.", self);
                self.is_listening = true;
            }
        }

        self.is_listening
    }

    fn relocate(&mut self) -> Result<(), RoutingError> {
        let duration = Duration::from_secs(GET_NODE_NAME_TIMEOUT_SECS);
        self.get_node_name_timer_token = Some(self.timer.schedule(duration));

        let request_content = MessageContent::GetNodeName {
            current_id: *self.full_id.public_id(),
            message_id: MessageId::new(),
        };

        let request_msg = RoutingMessage {
            src: try!(self.get_client_authority()),
            dst: Authority::NaeManager(*self.name()),
            content: request_content,
        };

        info!("{:?} Sending GetNodeName request with: {:?}. This can take a while.",
              self,
              self.full_id.public_id());
        self.send_routing_message(request_msg)
    }

    /// Sends the given message, possibly splitting it up into smaller parts.
    fn send_user_message(&mut self,
                         src: Authority,
                         dst: Authority,
                         user_msg: UserMessage,
                         priority: u8)
                         -> Result<(), RoutingError> {
        match user_msg {
            UserMessage::Request(ref request) => {
                let hash = maidsafe_utilities::big_endian_sip_hash(&user_msg);
                let _ = self.request_msg_ids.insert(hash, request.message_id());
                self.stats.count_request(request);
            }
            UserMessage::Response(ref response) => self.stats.count_response(response),
        }
        for part in try!(user_msg.to_parts(priority)) {
            try!(self.send_routing_message(RoutingMessage {
                src: src.clone(),
                dst: dst.clone(),
                content: part,
            }));
        }
        Ok(())
    }

    fn send_routing_message(&mut self, routing_msg: RoutingMessage) -> Result<(), RoutingError> {
        self.send_routing_message_via_route(routing_msg, 0)
    }

    fn send_routing_message_via_route(&mut self,
                                      routing_msg: RoutingMessage,
                                      route: u8)
                                      -> Result<(), RoutingError> {
        if let Authority::Client { .. } = routing_msg.dst {
            if self.is_recipient(&routing_msg.dst) {
                return Ok(()); // Message is for us.
            }
        }

        // Get the recipient peer id.
        let peer_id = if let Authority::Client { ref proxy_node_name, .. } = routing_msg.src {
            if let Some(&peer_id) = self.peer_mgr.get_proxy_peer_id(proxy_node_name) {
                peer_id
            } else {
                error!("{:?} - Unable to find connection to proxy node in proxy map",
                       self);
                return Err(RoutingError::ProxyConnectionNotFound);
            }
        } else {
            error!("{:?} - Source should be client if our state is a Client",
                   self);
            return Err(RoutingError::InvalidSource);
        };

        let signed_msg = try!(SignedMessage::new(routing_msg, &self.full_id));

        if !self.ack_mgr.add_to_pending(&signed_msg,
                                        route,
                                        self.full_id.public_id(),
                                        &mut self.timer) {
            return Ok(());
        }

        let (peer_id, bytes) = if self.crust_service.is_connected(&peer_id) {
            let bytes =
                try!(common::to_hop_bytes(signed_msg.clone(), route, Vec::new(), &self.full_id));
            (peer_id, bytes)
        } else {
            trace!("{:?} - Not connected to {:?}. Dropping peer.",
                   self,
                   peer_id);
            self.disconnect_peer(&peer_id);
            return Ok(());
        };

        if !self.filter_outgoing_signed_msg(&signed_msg, &peer_id, route) {
            if let Err(error) = self.send_or_drop(&peer_id, bytes, signed_msg.priority()) {
                info!("{:?} - Error sending message to {:?}: {:?}.",
                      self,
                      peer_id,
                      error);
            }
        }

        Ok(())
    }

    fn send_ack(&mut self, routing_msg: &RoutingMessage, route: u8) {
        if let MessageContent::Ack(..) = routing_msg.content {
            return;
        }

        let response = match RoutingMessage::ack(routing_msg) {
            Ok(response) => response,
            Err(error) => {
                error!("{:?} - Failed to create ack: {:?}", self, error);
                return;
            }
        };

        if let Err(error) = self.send_routing_message_via_route(response, route) {
            error!("{:?} - Failed to send ack: {:?}", self, error);
        }
    }

    fn resend_timed_out_unacknowledged(&mut self, token: u64) {
        if let Some((unacked_msg, ack)) = self.ack_mgr.find_timed_out(token) {
            trace!("{:?} - Timed out waiting for ack({}) {:?}",
                   self,
                   ack,
                   unacked_msg);

            if unacked_msg.route as usize == GROUP_SIZE {
                debug!("{:?} - Message unable to be acknowledged - giving up. {:?}",
                       self,
                       unacked_msg);
                self.stats.count_unacked();
                if let MessageContent::UserMessagePart { ref hash, .. } = unacked_msg.routing_msg
                    .content {
                    if let Some(msg_id) = self.request_msg_ids.remove(hash) {
                        let _ = self.event_sender.send(Event::RequestFailure(msg_id));
                    }
                }
            } else if let Err(error) =
                   self.send_routing_message_via_route(unacked_msg.routing_msg, unacked_msg.route) {
                debug!("{:?} Failed to send message: {:?}", self, error);
            }
        }
    }

    /// Returns whether we are the recipient of a message for the given authority.
    fn is_recipient(&self, dst: &Authority) -> bool {
        if let Authority::Client { ref client_key, .. } = *dst {
            client_key == self.full_id.public_id().signing_public_key()
        } else {
            false
        }
    }

    /// Sends the given `bytes` to the peer with the given Crust `PeerId`. If that results in an
    /// error, it disconnects from the peer.
    fn send_or_drop(&mut self,
                    peer_id: &PeerId,
                    bytes: Vec<u8>,
                    priority: u8)
                    -> Result<(), RoutingError> {
        self.stats.count_bytes(bytes.len());

        if let Err(err) = self.crust_service.send(*peer_id, bytes.clone(), priority) {
            info!("{:?} Connection to {:?} failed. Calling crust::Service::disconnect.",
                  self,
                  peer_id);
            self.crust_service.disconnect(*peer_id);
            self.handle_lost_peer(*peer_id);
            return Err(err.into());
        }
        Ok(())
    }

    /// Adds the outgoing signed message to the statistics and returns `true`
    /// if it should be blocked due to deduplication.
    fn filter_outgoing_signed_msg(&mut self,
                                  msg: &SignedMessage,
                                  peer_id: &PeerId,
                                  route: u8)
                                  -> bool {
        if self.signed_msg_filter.filter_outgoing(msg, peer_id, route) {
            return true;
        }

        self.stats.count_routing_message(msg.routing_message());
        false
    }

    fn disconnect_peer(&mut self, peer_id: &PeerId) {
        if let Some(&public_id) = self.peer_mgr.get_proxy_public_id(peer_id) {
            debug!("{:?} Not disconnecting proxy node {:?} ({:?}).",
                   self,
                   public_id.name(),
                   peer_id);
        } else {
            debug!("{:?} Disconnecting {:?}. Calling crust::Service::disconnect.",
                   self,
                   peer_id);
            let _ = self.crust_service.disconnect(*peer_id);
        }
    }

    fn get_client_authority(&self) -> Result<Authority, RoutingError> {
        match *self.peer_mgr.proxy() {
            Some((_, _, ref bootstrap_pub_id)) => {
                Ok(Authority::Client {
                    client_key: *self.full_id.public_id().signing_public_key(),
                    proxy_node_name: *bootstrap_pub_id.name(),
                    peer_id: self.crust_service.id(),
                })
            }
            None => Err(RoutingError::NotBootstrapped),
        }
    }
}

impl Debug for Client {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "Client({})", self.name())
    }
}
