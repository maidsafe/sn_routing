// Copyright 2015 MaidSafe.net limited.
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

use crust::{ConnectionInfoResult, PeerId, Service};
use crust::Event as CrustEvent;
#[cfg(feature = "use-mock-crust")]
use kademlia_routing_table::RoutingTable;
use maidsafe_utilities::serialisation;
use std::fmt::{self, Debug, Formatter};
use std::sync::mpsc::Sender;
use std::time::Duration;

use ack_manager::{Ack, AckManager};
use action::Action;
use authority::Authority;
use cache::Cache;
use error::{InterfaceError, RoutingError};
use event::Event;
use id::{FullId, PublicId};
use message_accumulator::MessageAccumulator;
use messages::{DirectMessage, Message, MessageContent, RoutingMessage};
use peer_manager::{GROUP_SIZE, PeerManager};
use signed_message_filter::SignedMessageFilter;
use state_machine::Transition;
use stats::Stats;
use super::common::{self, AnyState, Bootstrapped, Connect, HandleHopMessage, ProxyClient,
                    SendRoutingMessage};
#[cfg(feature = "use-mock-crust")]
use super::common::Testable;
use super::Node;
use timer::Timer;
use types::MessageId;
#[cfg(feature = "use-mock-crust")]
use xor_name::XorName;

/// Time (in seconds) after which a `GetNodeName` request is resent.
const GET_NODE_NAME_TIMEOUT_SECS: u64 = 60;

pub struct JoiningNode {
    ack_mgr: AckManager,
    cache: Box<Cache>,
    crust_service: Service,
    event_sender: Sender<Event>,
    full_id: FullId,
    get_node_name_timer_token: Option<u64>,
    msg_accumulator: MessageAccumulator,
    peer_mgr: PeerManager,
    signed_msg_filter: SignedMessageFilter,
    stats: Stats,
    timer: Timer,
}

impl JoiningNode {
    #[cfg_attr(feature = "clippy", allow(too_many_arguments))]
    pub fn from_bootstrapping(cache: Box<Cache>,
                              crust_service: Service,
                              event_sender: Sender<Event>,
                              full_id: FullId,
                              proxy_peer_id: PeerId,
                              proxy_public_id: PublicId,
                              quorum_size: usize,
                              stats: Stats,
                              timer: Timer)
                              -> Option<Self> {
        let mut peer_mgr = PeerManager::new(*full_id.public_id());
        let _ = peer_mgr.set_proxy(proxy_peer_id, proxy_public_id);

        let mut node = JoiningNode {
            ack_mgr: AckManager::new(),
            cache: cache,
            crust_service: crust_service,
            event_sender: event_sender,
            full_id: full_id,
            get_node_name_timer_token: None,
            msg_accumulator: MessageAccumulator::with_quorum_size(quorum_size),
            peer_mgr: peer_mgr,
            signed_msg_filter: SignedMessageFilter::new(),
            stats: stats,
            timer: timer,
        };

        debug!("{:?} - State changed to joining node.", node);

        if node.start_listening() {
            Some(node)
        } else {
            node.send_event(Event::Terminate);
            None
        }
    }

    pub fn into_node(self, peer_id: PeerId, public_id: PublicId) -> Node {
        Node::from_joining_node(peer_id,
                                public_id,
                                self.cache,
                                self.crust_service,
                                self.event_sender,
                                self.full_id,
                                self.msg_accumulator,
                                self.peer_mgr,
                                self.stats,
                                self.timer)
    }

    pub fn handle_action(&mut self, action: Action) -> Transition {
        match action {
            Action::Name { result_tx } => {
                let _ = result_tx.send(*self.name());
            }
            Action::ClientSendRequest { ref result_tx, .. } => {
                let _ = result_tx.send(Err(InterfaceError::InvalidState));
            }
            Action::NodeSendMessage { ref result_tx, .. } => {
                warn!("{:?} - Cannot handle {:?} - not bootstrapped", self, action);
                // TODO: return Err here eventually. Returning Ok for now to
                // preserve the pre-refactor behaviour.
                let _ = result_tx.send(Ok(()));
            }
            Action::Timeout(token) => {
                if !self.handle_timeout(token) {
                    return Transition::Terminate;
                }
            }
            Action::Terminate => {
                return Transition::Terminate;
            }

            // TODO: these actions make no sense in this state, but we handle
            // them for now, to preserve the pre-refactor behaviour.
            Action::CloseGroup { result_tx, .. } => {
                let _ = result_tx.send(None);
            }
            Action::QuorumSize { result_tx } => {
                let _ = result_tx.send(0);
            }
        }

        Transition::Stay
    }

    pub fn handle_crust_event(&mut self, crust_event: CrustEvent) -> Transition {
        match crust_event {
            CrustEvent::ConnectSuccess(peer_id) => {
                self.handle_connect_success(peer_id);
                Transition::Stay
            }
            CrustEvent::ListenerStarted(port) => self.handle_listener_started(port),
            CrustEvent::ListenerFailed => {
                error!("{:?} Failed to start listening.", self);
                self.send_event(Event::Terminate);
                Transition::Terminate
            }
            CrustEvent::NewMessage(peer_id, bytes) => self.handle_new_message(peer_id, bytes),
            CrustEvent::ConnectionInfoPrepared(ConnectionInfoResult { result_token, result }) => {
                self.handle_connection_info_prepared(result_token, result);
                Transition::Stay
            }
            _ => {
                debug!("{:?} - Unhandled crust event {:?}", self, crust_event);
                Transition::Stay
            }
        }
    }

    /// Routing table of this node.
    #[cfg(feature = "use-mock-crust")]
    pub fn routing_table(&self) -> &RoutingTable<XorName> {
        self.peer_mgr.routing_table()
    }

    fn handle_timeout(&mut self, token: u64) -> bool {
        if self.get_node_name_timer_token == Some(token) {
            info!("{:?} Failed to get GetNodeName response.", self);
            self.send_event(Event::RestartRequired);
            return false;
        }

        true
    }

    fn handle_listener_started(&mut self, port: u16) -> Transition {
        trace!("{:?} Listener started on port {}.", self, port);
        self.crust_service.set_service_discovery_listen(true);

        if let Err(error) = self.relocate() {
            error!("{:?} Failed to start relocation: {:?}", self, error);
            self.send_event(Event::RestartRequired);
            Transition::Terminate
        } else {
            Transition::Stay
        }
    }

    fn handle_connect_success(&mut self, peer_id: PeerId) {
        if peer_id == self.crust_service.id() {
            debug!("{:?} Received ConnectSuccess event with our Crust peer ID.",
                   self);
            return;
        }

        // TODO(afck): Keep track of this connection: Disconnect if we don't receive a
        // NodeIdentify.

        self.peer_mgr.connected_to(peer_id);
        debug!("{:?} Received ConnectSuccess from {:?}. Sending NodeIdentify.",
               self,
               peer_id);
        let _ = self.send_node_identify(peer_id);
    }

    fn handle_new_message(&mut self, peer_id: PeerId, bytes: Vec<u8>) -> Transition {
        let result = match serialisation::deserialise(&bytes) {
            Ok(Message::Hop(hop_msg)) => self.handle_hop_message(hop_msg, peer_id),
            Ok(Message::Direct(direct_msg)) => self.handle_direct_message(direct_msg, peer_id),
            Ok(message) => {
                debug!("{:?} - Unhandled new message: {:?}", self, message);
                Ok(Transition::Stay)
            }
            Err(error) => Err(RoutingError::SerialisationError(error)),
        };

        match result {
            Ok(transition) => transition,
            Err(RoutingError::FilterCheckFailed) => Transition::Stay,
            Err(error) => {
                debug!("{:?} - {:?}", self, error);
                Transition::Stay
            }
        }
    }

    fn handle_direct_message(&mut self,
                             direct_message: DirectMessage,
                             peer_id: PeerId)
                             -> Result<Transition, RoutingError> {
        match direct_message {
            DirectMessage::NodeIdentify { ref serialised_public_id, ref signature } => {
                if let Ok(public_id) = common::verify_signed_public_id(serialised_public_id,
                                                                       signature) {
                    Ok(self.handle_node_identify(public_id, peer_id))
                } else {
                    warn!("{:?} Signature check failed in NodeIdentify - Dropping peer {:?}",
                          self,
                          peer_id);
                    self.disconnect_peer(&peer_id);
                    Ok(Transition::Stay)
                }
            }
            _ => {
                debug!("{:?} - Unhandled direct message: {:?}",
                       self,
                       direct_message);
                Ok(Transition::Stay)
            }
        }
    }

    fn handle_ack_response(&mut self, ack: Ack) -> Transition {
        self.ack_mgr.receive(ack);
        Transition::Stay
    }

    fn handle_get_node_name_response(&mut self,
                                     relocated_id: PublicId,
                                     mut close_group_ids: Vec<PublicId>,
                                     dst: Authority)
                                     -> Transition {
        self.full_id.public_id_mut().set_name(*relocated_id.name());
        self.peer_mgr.reset_routing_table(*self.full_id.public_id());

        close_group_ids.truncate(GROUP_SIZE / 2);

        let mut result = Transition::Stay;

        for close_node_id in close_group_ids {
            debug!("{:?} Sending connection info to {:?} on GetNodeName response.",
                   self,
                   close_node_id);

            match self.send_connection_info(close_node_id,
                                            dst.clone(),
                                            Authority::ManagedNode(*close_node_id.name())) {
                Ok(transition) => {
                    if let Transition::Stay = result {
                        result = transition;
                    }
                }
                Err(error) => {
                    debug!("{:?} - Failed to send connection info to {:?}: {:?}",
                           self,
                           close_node_id,
                           error);
                }
            }
        }

        result
    }

    fn start_listening(&mut self) -> bool {
        if let Err(error) = self.crust_service.start_listening_tcp() {
            error!("{:?} Failed to start listening: {:?}", self, error);
            false
        } else {
            info!("{:?} Attempting to start listener.", self);
            true
        }
    }

    fn relocate(&mut self) -> Result<(), RoutingError> {
        let duration = Duration::from_secs(GET_NODE_NAME_TIMEOUT_SECS);
        self.get_node_name_timer_token = Some(self.timer.schedule(duration));

        let request_content = MessageContent::GetNodeName {
            current_id: *self.full_id.public_id(),
            message_id: MessageId::new(),
        };

        let src = Authority::Client {
            client_key: *self.full_id.public_id().signing_public_key(),
            proxy_node_name: *self.proxy_public_id().name(),
            peer_id: self.crust_service.id(),
        };

        let request_msg = RoutingMessage {
            src: src,
            dst: Authority::NaeManager(*self.name()),
            content: request_content,
        };

        info!("{:?} Sending GetNodeName request with: {:?}. This can take a while.",
              self,
              self.full_id.public_id());
        self.send_routing_message(request_msg)
    }

    fn disconnect_peer(&self, peer_id: &PeerId) {
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
}

impl AnyState for JoiningNode {
    fn crust_service(&self) -> &Service {
        &self.crust_service
    }

    fn full_id(&self) -> &FullId {
        &self.full_id
    }

    fn handle_lost_peer(&mut self, peer_id: PeerId) -> Transition {
        if peer_id == self.crust_service().id() {
            error!("{:?} LostPeer fired with our crust peer id", self);
            return Transition::Stay;
        }

        debug!("{:?} Received LostPeer - {:?}", self, peer_id);

        let _ = self.peer_mgr.remove_peer(&peer_id);

        if *self.proxy_peer_id() == peer_id {
            debug!("{:?} Lost bootstrap connection to {:?} ({:?}).",
                   self,
                   self.proxy_public_id().name(),
                   peer_id);
            self.send_event(Event::Terminate);
            Transition::Terminate
        } else {
            Transition::Stay
        }
    }

    fn send_event(&self, event: Event) {
        let _ = self.event_sender.send(event);
    }

    fn stats(&mut self) -> &mut Stats {
        &mut self.stats
    }
}

impl Bootstrapped for JoiningNode {
    fn accumulate(&mut self,
                  routing_msg: &RoutingMessage,
                  public_id: &PublicId)
                  -> Result<Option<RoutingMessage>, RoutingError> {
        self.msg_accumulator.add(routing_msg, public_id)
    }

    fn ack_mgr(&self) -> &AckManager {
        &self.ack_mgr
    }

    fn ack_mgr_mut(&mut self) -> &mut AckManager {
        &mut self.ack_mgr
    }

    fn dispatch_routing_message(&mut self,
                                routing_msg: RoutingMessage)
                                -> Result<Transition, RoutingError> {
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
            (MessageContent::Ack(ack, _), _, _) => Ok(self.handle_ack_response(ack)),
            // GetNodeNameResponse
            (MessageContent::GetNodeNameResponse { relocated_id, close_group_ids, .. },
             Authority::NodeManager(_),
             dst) => Ok(self.handle_get_node_name_response(relocated_id, close_group_ids, dst)),
            // ConnectionInfo
            (MessageContent::ConnectionInfo { encrypted_connection_info, nonce_bytes, public_id },
             src @ Authority::Client { .. },
             Authority::ManagedNode(dst_name)) => {
                self.handle_connection_info_from_client(encrypted_connection_info,
                                                        nonce_bytes,
                                                        src,
                                                        dst_name,
                                                        public_id)
            }
            (MessageContent::ConnectionInfo { encrypted_connection_info, nonce_bytes, public_id },
             Authority::ManagedNode(src_name),
             Authority::Client { .. }) |
            (MessageContent::ConnectionInfo { encrypted_connection_info, nonce_bytes, public_id },
             Authority::ManagedNode(src_name),
             Authority::ManagedNode(_)) => {
                self.handle_connection_info_from_node(encrypted_connection_info,
                                                      nonce_bytes,
                                                      src_name,
                                                      routing_msg.dst.clone(),
                                                      public_id)
            }
            // other
            _ => {
                debug!("{:?} - Unhandled routing message: {:?}", self, routing_msg);
                Ok(Transition::Stay)
            }
        }
    }

    fn signed_msg_filter(&mut self) -> &mut SignedMessageFilter {
        &mut self.signed_msg_filter
    }

    fn timer(&mut self) -> &mut Timer {
        &mut self.timer
    }
}

impl Connect for JoiningNode {
    fn handle_node_identify(&mut self, public_id: PublicId, peer_id: PeerId) -> Transition {
        debug!("{:?} Handling NodeIdentify from {:?}.",
               self,
               public_id.name());

        Transition::IntoNode {
            peer_id: peer_id,
            public_id: public_id,
        }
    }

    fn peer_mgr(&self) -> &PeerManager {
        &self.peer_mgr
    }

    fn peer_mgr_mut(&mut self) -> &mut PeerManager {
        &mut self.peer_mgr
    }
}

impl Debug for JoiningNode {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "JoiningNode({})", self.name())
    }
}

impl ProxyClient for JoiningNode {
    fn proxy_peer_id(&self) -> &PeerId {
        // It should safe to unwrap here, because we set the proxy node in the
        // constructor and never remove it.
        &unwrap!(self.peer_mgr.proxy().as_ref()).1
    }

    fn proxy_public_id(&self) -> &PublicId {
        // Safe to unwrap. See the above comment.
        &unwrap!(self.peer_mgr.proxy().as_ref()).2
    }
}

#[cfg(feature = "use-mock-crust")]
impl Testable for JoiningNode {
    fn clear_state(&mut self) {
        self.ack_mgr.clear();
        self.msg_accumulator.clear();
        self.peer_mgr.clear_caches();
        self.signed_msg_filter.clear();
    }
}
