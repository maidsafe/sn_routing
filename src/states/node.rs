// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.1.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use ack_manager::{Ack, AckManager};
use action::Action;
use cache::Cache;
use crust::{ConnectionInfoResult, CrustError, PeerId, PrivConnectionInfo, PubConnectionInfo,
            Service};
use crust::Event as CrustEvent;
use error::{InterfaceError, RoutingError};
use event::Event;
use id::{FullId, PublicId};
use itertools::Itertools;
use log::LogLevel;
use maidsafe_utilities::serialisation;
use messages::{ConnectionInfo, DEFAULT_PRIORITY, DirectMessage, GroupList, HopMessage, Message,
               MessageContent, RoutingMessage, SignedMessage, UserMessage, UserMessageCache};
use peer_manager::{ConnectionInfoPreparedResult, ConnectionInfoReceivedResult, PeerManager,
                   PeerState};
use routing_message_filter::{FilteringResult, RoutingMessageFilter};
use routing_table::{OtherMergeDetails, OwnMergeDetails, OwnMergeState, Prefix, RemovalDetails,
                    Xorable};
use routing_table::Authority;
use routing_table::Error as RoutingTableError;
#[cfg(feature = "use-mock-crust")]
use routing_table::RoutingTable;
use rust_sodium::crypto::{box_, sign};
use rust_sodium::crypto::hash::sha256;
use signature_accumulator::SignatureAccumulator;
use state_machine::Transition;
use stats::Stats;
use std::{fmt, iter};
use std::collections::{BTreeSet, HashSet, VecDeque};
use std::fmt::{Debug, Formatter};
use std::sync::mpsc::Sender;
use std::time::Duration;
use super::common::{Base, Bootstrapped, USER_MSG_CACHE_EXPIRY_DURATION_SECS};
use timer::Timer;
use tunnels::Tunnels;
use types::MessageId;
use utils;
use xor_name::XorName;

/// Time (in seconds) after which a `Tick` event is sent.
const TICK_TIMEOUT_SECS: u64 = 60;
/// Time (in seconds) after which a `GetNodeName` request is resent.
const GET_NODE_NAME_TIMEOUT_SECS: u64 = 60;
/// in bits
const RESOURCE_PROOF_DIFFICULTY: u32 = 10;

// in Bytes
fn resource_proof_target_size(group_len: usize) -> u32 {
    (40 / group_len as u32) * 100 * 1024 / 2
}

pub struct Node {
    ack_mgr: AckManager,
    cacheable_user_msg_cache: UserMessageCache,
    crust_service: Service,
    event_sender: Sender<Event>,
    full_id: FullId,
    get_node_name_timer_token: Option<u64>,
    is_first_node: bool,
    /// The queue of routing messages addressed to us. These do not themselves need
    /// forwarding, although they may wrap a message which needs forwarding.
    msg_queue: VecDeque<RoutingMessage>,
    peer_mgr: PeerManager,
    response_cache: Box<Cache>,
    routing_msg_filter: RoutingMessageFilter,
    sig_accumulator: SignatureAccumulator,
    stats: Stats,
    tick_timer_token: u64,
    timer: Timer,
    tunnels: Tunnels,
    user_msg_cache: UserMessageCache,
    // Value which can be set in mock-crust tests to be used as the calculated name for the next
    // relocation request received by this node.
    next_node_name: Option<XorName>,
}

impl Node {
    pub fn first(cache: Box<Cache>,
                 crust_service: Service,
                 event_sender: Sender<Event>,
                 mut full_id: FullId,
                 min_group_size: usize,
                 timer: Timer)
                 -> Option<Self> {
        let name = XorName(sha256::hash(&full_id.public_id().name().0).0);
        full_id.public_id_mut().set_name(name);

        Self::new(cache,
                  crust_service,
                  event_sender,
                  true,
                  full_id,
                  min_group_size,
                  Stats::new(),
                  timer)
    }

    #[cfg_attr(feature = "clippy", allow(too_many_arguments))]
    pub fn from_bootstrapping(cache: Box<Cache>,
                              crust_service: Service,
                              event_sender: Sender<Event>,
                              full_id: FullId,
                              min_group_size: usize,
                              proxy_peer_id: PeerId,
                              proxy_public_id: PublicId,
                              stats: Stats,
                              timer: Timer)
                              -> Option<Self> {
        let mut node = Self::new(cache,
                                 crust_service,
                                 event_sender,
                                 false,
                                 full_id,
                                 min_group_size,
                                 stats,
                                 timer);

        if let Some(ref mut node) = node {
            let _ = node.peer_mgr.set_proxy(proxy_peer_id, proxy_public_id);
        }

        node
    }

    #[cfg_attr(feature = "clippy", allow(too_many_arguments))]
    fn new(cache: Box<Cache>,
           crust_service: Service,
           event_sender: Sender<Event>,
           first_node: bool,
           full_id: FullId,
           min_group_size: usize,
           stats: Stats,
           mut timer: Timer)
           -> Option<Self> {
        let public_id = *full_id.public_id();
        let tick_period = Duration::from_secs(TICK_TIMEOUT_SECS);
        let tick_timer_token = timer.schedule(tick_period);
        let user_msg_cache_duration = Duration::from_secs(USER_MSG_CACHE_EXPIRY_DURATION_SECS);

        let mut node = Node {
            ack_mgr: AckManager::new(),
            cacheable_user_msg_cache:
                UserMessageCache::with_expiry_duration(user_msg_cache_duration),
            crust_service: crust_service,
            event_sender: event_sender.clone(),
            full_id: full_id,
            get_node_name_timer_token: None,
            is_first_node: first_node,
            msg_queue: VecDeque::new(),
            peer_mgr: PeerManager::new(min_group_size, public_id),
            response_cache: cache,
            routing_msg_filter: RoutingMessageFilter::new(),
            sig_accumulator: Default::default(),
            stats: stats,
            tick_timer_token: tick_timer_token,
            timer: timer,
            tunnels: Default::default(),
            user_msg_cache: UserMessageCache::with_expiry_duration(user_msg_cache_duration),
            next_node_name: None,
        };

        if node.start_listening() {
            debug!("{:?} - State changed to node.", node);
            Some(node)
        } else {
            node.send_event(Event::Terminate);
            None
        }
    }

    fn update_stats(&mut self) {
        let old_client_num = self.stats.cur_client_num;
        self.stats.cur_client_num = self.peer_mgr.client_num();
        if self.stats.cur_client_num != old_client_num {
            if self.stats.cur_client_num > old_client_num {
                self.stats.cumulative_client_num += self.stats.cur_client_num - old_client_num;
            }
            info!(target: "routing_stats", "{:?} - Connected clients: {}, cumulative: {}",
                  self,
                  self.stats.cur_client_num,
                  self.stats.cumulative_client_num);
        }
        if self.stats.tunnel_connections != self.tunnels.tunnel_count() ||
           self.stats.tunnel_client_pairs != self.tunnels.client_count() {
            self.stats.tunnel_connections = self.tunnels.tunnel_count();
            self.stats.tunnel_client_pairs = self.tunnels.client_count();
            info!(target: "routing_stats", "{:?} - Indirect connections: {}, tunneling for: {}",
                  self,
                  self.stats.tunnel_connections,
                  self.stats.tunnel_client_pairs);
        }

        if self.stats.cur_routing_table_size != self.peer_mgr.routing_table().len() {
            self.stats.cur_routing_table_size = self.peer_mgr.routing_table().len();

            const TABLE_LVL: LogLevel = LogLevel::Info;
            if log_enabled!(TABLE_LVL) {
                let status_str = format!("{:?} {:?} - Routing Table size: {:3}",
                                         self,
                                         self.crust_service.id(),
                                         self.stats.cur_routing_table_size);
                let sep_str = iter::repeat('-').take(status_str.len()).collect::<String>();
                log!(target: "routing_stats", TABLE_LVL, " -{}- ", sep_str);
                log!(target: "routing_stats", TABLE_LVL, "| {} |", status_str);
                log!(target: "routing_stats", TABLE_LVL, " -{}- ", sep_str);
            }
        }
    }

    pub fn handle_action(&mut self, action: Action) -> Transition {
        match action {
            Action::ClientSendRequest { result_tx, .. } => {
                let _ = result_tx.send(Err(InterfaceError::InvalidState));
            }
            Action::NodeSendMessage { src, dst, content, priority, result_tx } => {
                let result = match self.send_user_message(src, dst, content, priority) {
                    Err(RoutingError::Interface(err)) => Err(err),
                    Err(_) | Ok(_) => Ok(()),
                };

                let _ = result_tx.send(result);
            }
            Action::CloseGroup { name, count, result_tx } => {
                let _ = result_tx.send(self.peer_mgr
                    .routing_table()
                    .closest_names(&name, count)
                    .map(|names| names.into_iter().cloned().collect_vec()));
            }
            Action::Name { result_tx } => {
                let _ = result_tx.send(*self.name());
            }
            Action::Timeout(token) => {
                if !self.handle_timeout(token) {
                    return Transition::Terminate;
                }
            }
            Action::Terminate => {
                return Transition::Terminate;
            }
        }

        self.handle_routing_messages();
        self.update_stats();
        Transition::Stay
    }

    pub fn handle_crust_event(&mut self, crust_event: CrustEvent) -> Transition {
        match crust_event {
            CrustEvent::BootstrapAccept(peer_id) => self.handle_bootstrap_accept(peer_id),
            CrustEvent::BootstrapConnect(peer_id, _) => self.handle_bootstrap_connect(peer_id),
            CrustEvent::ConnectSuccess(peer_id) => self.handle_connect_success(peer_id),
            CrustEvent::ConnectFailure(peer_id) => self.handle_connect_failure(peer_id),
            CrustEvent::LostPeer(peer_id) => {
                if let Transition::Terminate = self.handle_lost_peer(peer_id) {
                    return Transition::Terminate;
                }
            }
            CrustEvent::NewMessage(peer_id, bytes) => {
                match self.handle_new_message(peer_id, bytes) {
                    Err(RoutingError::FilterCheckFailed) |
                    Ok(_) => (),
                    Err(err) => debug!("{:?} - {:?}", self, err),
                }
            }
            CrustEvent::ConnectionInfoPrepared(ConnectionInfoResult { result_token, result }) => {
                self.handle_connection_info_prepared(result_token, result)
            }
            CrustEvent::ListenerStarted(port) => {
                if let Transition::Terminate = self.handle_listener_started(port) {
                    return Transition::Terminate;
                }
            }
            CrustEvent::ListenerFailed => {
                error!("{:?} Failed to start listening.", self);
                self.send_event(Event::Terminate);
                return Transition::Terminate;
            }
            CrustEvent::WriteMsgSizeProhibitive(peer_id, msg) => {
                error!("{:?} Failed to send {}-byte message to {:?}. Message too large.",
                       self,
                       msg.len(),
                       peer_id);
            }
            _ => {
                debug!("{:?} - Unhandled crust event: {:?}", self, crust_event);
            }
        }

        self.handle_routing_messages();
        self.update_stats();
        Transition::Stay
    }

    fn handle_routing_messages(&mut self) {
        while let Some(routing_msg) = self.msg_queue.pop_front() {
            if self.in_authority(&routing_msg.dst) {
                if let Err(err) = self.dispatch_routing_message(routing_msg) {
                    warn!("{:?} Routing message dispatch failed: {:?}", self, err);
                }
            }
        }
    }

    fn handle_listener_started(&mut self, port: u16) -> Transition {
        trace!("{:?} Listener started on port {}.", self, port);
        self.crust_service.set_service_discovery_listen(true);

        if self.is_first_node {
            info!("{:?} - Started a new network as a seed node.", self);
            Transition::Stay
        } else if let Err(error) = self.relocate() {
            error!("{:?} Failed to start relocation: {:?}", self, error);
            self.send_event(Event::RestartRequired);
            Transition::Terminate
        } else {
            Transition::Stay
        }
    }

    fn handle_bootstrap_accept(&mut self, peer_id: PeerId) {
        trace!("{:?} Received BootstrapAccept from {:?}.", self, peer_id);
        // TODO: Keep track of that peer to make sure we receive a message from them.
    }

    fn handle_bootstrap_connect(&mut self, peer_id: PeerId) {
        self.disconnect_peer(&peer_id)
    }

    fn handle_connect_success(&mut self, peer_id: PeerId) {
        if peer_id == self.crust_service.id() {
            debug!("{:?} Received ConnectSuccess event with our Crust peer ID.",
                   self);
            return;
        }
        if !self.crust_service.is_peer_whitelisted(&peer_id) {
            debug!("{:?} Received ConnectSuccess, but {:?} is not whitelisted.",
                   self,
                   peer_id);
            self.disconnect_peer(&peer_id);
            return;
        }

        // Remove tunnel connection if we have one for this peer already
        let mut connected = false;
        if let Some(tunnel_id) = self.tunnels.remove_tunnel_for(&peer_id) {
            debug!("{:?} Removing unwanted tunnel for {:?}", self, peer_id);
            let message = DirectMessage::TunnelDisconnect(peer_id);
            let _ = self.send_direct_message(&tunnel_id, message);
        } else if let Some(pub_id) = self.peer_mgr.get_routing_peer(&peer_id) {
            warn!("{:?} Received ConnectSuccess from {:?}, but node {:?} is already in routing \
                   state in peer_map.",
                  self,
                  peer_id,
                  pub_id.name());
            connected = true;
        }

        if !connected {
            self.peer_mgr.connected_to(&peer_id);
        }

        debug!("{:?} Received ConnectSuccess from {:?}. Sending NodeIdentify.",
               self,
               peer_id);
        if let Err(error) = self.send_node_identify(peer_id) {
            warn!("{:?} Failed to send NodeIdentify to {:?}: {:?}",
                  self,
                  peer_id,
                  error);
            self.disconnect_peer(&peer_id);
        }
    }

    fn handle_connect_failure(&mut self, peer_id: PeerId) {
        if peer_id == self.crust_service.id() {
            debug!("{:?} Received ConnectFailure event with our Crust peer ID.",
                   self);
            return;
        }

        if let Some(&pub_id) = self.peer_mgr.get_connecting_peer(&peer_id) {
            info!("{:?} Failed to connect to peer {:?} with pub_id {:?}.",
                  self,
                  peer_id,
                  pub_id);
            self.find_tunnel_for_peer(peer_id, &pub_id);
        }
    }

    fn find_tunnel_for_peer(&mut self, peer_id: PeerId, pub_id: &PublicId) {
        for (name, dst_peer_id) in self.peer_mgr.set_searching_for_tunnel(peer_id, *pub_id) {
            trace!("{:?} Asking {:?} to serve as a tunnel for {:?}.",
                   self,
                   name,
                   peer_id);
            let tunnel_request = DirectMessage::TunnelRequest(peer_id);
            let _ = self.send_direct_message(&dst_peer_id, tunnel_request);
        }
    }

    fn handle_new_message(&mut self, peer_id: PeerId, bytes: Vec<u8>) -> Result<(), RoutingError> {
        match serialisation::deserialise(&bytes) {
            Ok(Message::Hop(hop_msg)) => self.handle_hop_message(hop_msg, peer_id),
            Ok(Message::Direct(direct_msg)) => self.handle_direct_message(direct_msg, peer_id),
            Ok(Message::TunnelDirect { content, src, dst }) => {
                if dst == self.crust_service.id() &&
                   self.tunnels.tunnel_for(&src) == Some(&peer_id) {
                    self.handle_direct_message(content, src)
                } else if self.tunnels.has_clients(src, dst) {
                    self.send_or_drop(&dst, bytes, content.priority())
                } else if self.tunnels.accept_clients(src, dst) {
                    self.send_direct_message(&dst, DirectMessage::TunnelSuccess(src))?;
                    self.send_or_drop(&dst, bytes, content.priority())
                } else {
                    debug!("{:?} Invalid TunnelDirect message received via {:?}: {:?} -> {:?} {:?}",
                           self,
                           peer_id,
                           src,
                           dst,
                           content);
                    Err(RoutingError::InvalidDestination)
                }
            }
            Ok(Message::TunnelHop { content, src, dst }) => {
                if dst == self.crust_service.id() &&
                   self.tunnels.tunnel_for(&src) == Some(&peer_id) {
                    self.handle_hop_message(content, src)
                } else if self.tunnels.has_clients(src, dst) {
                    self.send_or_drop(&dst, bytes, content.content.priority())
                } else {
                    debug!("{:?} Invalid TunnelHop message received via {:?}: {:?} -> {:?} {:?}",
                           self,
                           peer_id,
                           src,
                           dst,
                           content);
                    Err(RoutingError::InvalidDestination)
                }
            }
            Err(error) => Err(RoutingError::SerialisationError(error)),
        }
    }

    fn handle_direct_message(&mut self,
                             direct_message: DirectMessage,
                             peer_id: PeerId)
                             -> Result<(), RoutingError> {
        use messages::DirectMessage::*;
        match direct_message {
            MessageSignature(digest, sig) => self.handle_message_signature(digest, sig, peer_id),
            ClientIdentify { ref serialised_public_id, ref signature, client_restriction } => {
                if let Ok(public_id) = verify_signed_public_id(serialised_public_id, signature) {
                    self.handle_client_identify(public_id, peer_id, client_restriction)
                } else {
                    warn!("{:?} Signature check failed in ClientIdentify - Dropping connection \
                           {:?}",
                          self,
                          peer_id);
                    self.disconnect_peer(&peer_id);
                    Ok(())
                }
            }
            NodeIdentify { ref serialised_public_id, ref signature } => {
                if let Ok(public_id) = verify_signed_public_id(serialised_public_id, signature) {
                    self.handle_node_identify(public_id, peer_id);
                } else {
                    warn!("{:?} Signature check failed in NodeIdentify - Dropping peer {:?}",
                          self,
                          peer_id);
                    self.disconnect_peer(&peer_id);
                }
                Ok(())
            }
            TunnelRequest(dst_id) => self.handle_tunnel_request(peer_id, dst_id),
            TunnelSuccess(dst_id) => self.handle_tunnel_success(peer_id, dst_id),
            TunnelClosed(dst_id) => self.handle_tunnel_closed(peer_id, dst_id),
            TunnelDisconnect(dst_id) => self.handle_tunnel_disconnect(peer_id, dst_id),
            ResourceProof { seed, target_size, difficulty } => {
                self.handle_resource_proof_request(peer_id, seed, target_size, difficulty)
            }
            ResourceProofResponse { proof, leading_zero_bytes } => {
                self.handle_resource_proof_response(peer_id, proof, leading_zero_bytes);
                Ok(())
            }
            NodeApproval { groups } => {
                self.handle_node_approval(groups);
                Ok(())
            }
            msg @ BootstrapIdentify { .. } |
            msg @ BootstrapDeny => {
                debug!("{:?} - Unhandled direct message: {:?}", self, msg);
                Ok(())
            }
        }
    }

    fn handle_message_signature(&mut self,
                                digest: sha256::Digest,
                                sig: sign::Signature,
                                peer_id: PeerId)
                                -> Result<(), RoutingError> {
        if let Some(&pub_id) = self.peer_mgr.get_routing_peer(&peer_id) {
            let min_group_size = self.min_group_size();
            if let Some((signed_msg, route)) =
                self.sig_accumulator.add_signature(min_group_size, digest, sig, pub_id) {
                let hop = *self.name(); // we accumulated the message, so now we act as the last hop
                trace!("{:?} Message accumulated - handling: {:?}", self, signed_msg);
                return self.handle_signed_message(signed_msg, route, hop, &BTreeSet::new());
            }
        } else {
            warn!("{:?} Received message signature from unknown peer {:?}",
                  self,
                  peer_id);
        }
        Ok(())
    }

    fn hop_pub_ids(&self, hop_name: &XorName) -> Result<BTreeSet<PublicId>, RoutingError> {
        if let Some(group) = self.peer_mgr.routing_table().get_group(hop_name) {
            let mut group = group.clone();
            if self.peer_mgr.routing_table().our_group_prefix().matches(hop_name) {
                let _ = group.insert(*self.name());
            }
            Ok(self.peer_mgr.get_pub_ids(&group).into_iter().collect::<BTreeSet<_>>())
        } else {
            Err(RoutingError::RoutingTable(RoutingTableError::NoSuchPeer))
        }
    }

    fn handle_hop_message(&mut self,
                          hop_msg: HopMessage,
                          peer_id: PeerId)
                          -> Result<(), RoutingError> {
        let hop_name = if let Some(peer) = self.peer_mgr.get_connected_peer(&peer_id) {
            hop_msg.verify(peer.pub_id().signing_public_key())?;

            match *peer.state() {
                PeerState::Client => {
                    self.check_valid_client_message(hop_msg.content.routing_message())?;
                    *self.name()
                }
                PeerState::JoiningNode => *self.name(),
                _ => *peer.name(),
            }
        } else {
            return Err(RoutingError::UnknownConnection(peer_id));
        };

        let HopMessage { content, route, sent_to, .. } = hop_msg;
        self.handle_signed_message(content, route, hop_name, &sent_to)
    }

    // Acknowledge reception of the message and broadcast to our group if necessary
    // The function is only called when we are in the destination authority
    fn ack_and_broadcast(&mut self,
                         signed_msg: &SignedMessage,
                         route: u8,
                         hop_name: XorName,
                         sent_to: &BTreeSet<XorName>) {
        self.send_ack(signed_msg.routing_message(), route);
        // If the destination is our group we need to forward it to the rest of the group
        if signed_msg.routing_message().dst.is_multiple() {
            if let Err(error) = self.send_signed_message(signed_msg, route, &hop_name, sent_to) {
                debug!("{:?} Failed to send {:?}: {:?}", self, signed_msg, error);
            }
        }
    }

    fn handle_signed_message(&mut self,
                             signed_msg: SignedMessage,
                             route: u8,
                             hop_name: XorName,
                             sent_to: &BTreeSet<XorName>)
                             -> Result<(), RoutingError> {
        signed_msg.check_integrity()?;

        match self.routing_msg_filter.filter_incoming(signed_msg.routing_message(), route) {
            FilteringResult::KnownMessageAndRoute => {
                warn!("{:?} Duplicate message received on route {}: {:?}",
                      self,
                      route,
                      signed_msg.routing_message());
                return Ok(());
            }
            FilteringResult::KnownMessage => {
                if self.in_authority(&signed_msg.routing_message().dst) {
                    self.ack_and_broadcast(&signed_msg, route, hop_name, sent_to);
                    return Ok(());
                }
                // known message, but new route - we still need to relay it in this case
            }
            FilteringResult::NewMessage => {
                if self.in_authority(&signed_msg.routing_message().dst) {
                    self.ack_and_broadcast(&signed_msg, route, hop_name, sent_to);
                    // if addressed to us, then we just queue it and return
                    self.msg_queue.push_back(signed_msg.into_routing_message());
                    return Ok(());
                }
            }
        }

        if self.respond_from_cache(signed_msg.routing_message(), route)? {
            return Ok(());
        }

        if let Err(error) = self.send_signed_message(&signed_msg, route, &hop_name, sent_to) {
            debug!("{:?} Failed to send {:?}: {:?}", self, signed_msg, error);
        }

        Ok(())
    }

    fn dispatch_routing_message(&mut self,
                                routing_msg: RoutingMessage)
                                -> Result<(), RoutingError> {
        use messages::MessageContent::*;
        use Authority::{Client, ManagedNode, PrefixSection, Section};

        match routing_msg.content {
            Ack(..) => (),
            _ => trace!("{:?} Got routing message {:?}.", self, routing_msg),
        }

        match (routing_msg.content, routing_msg.src, routing_msg.dst) {
            (GetNodeName { current_id, message_id },
             Client { client_key, proxy_node_name, peer_id },
             Section(dst_name)) => {
                self.handle_get_node_name_request(current_id,
                                                  client_key,
                                                  proxy_node_name,
                                                  dst_name,
                                                  peer_id,
                                                  message_id)
            }
            (GetNodeNameResponse { relocated_id, group, .. }, Section(_), dst) => {
                self.handle_get_node_name_response(relocated_id, group, dst);
                Ok(())
            }
            (ExpectCloseNode { expect_id, client_auth, message_id }, Section(_), Section(_)) => {
                self.handle_expect_close_node_request(expect_id, client_auth, message_id)
            }
            (ConnectionInfo(conn_info), src @ Client { .. }, dst @ ManagedNode(_)) => {
                self.handle_connection_info_from_client(conn_info, src, dst)
            }
            (ConnectionInfo(conn_info), ManagedNode(src_name), dst @ Client { .. }) |
            (ConnectionInfo(conn_info), ManagedNode(src_name), dst @ ManagedNode(_)) => {
                self.handle_connection_info_from_node(conn_info, src_name, dst)
            }
            (CandidateApproval(validity), Section(_), Section(candidate_name)) => {
                self.handle_node_approval_vote(candidate_name, validity)
            }
            (NodeApproval { relocated_id, groups }, Section(_), dst @ Client { .. }) => {
                self.handle_node_approval_no_resource_proof(relocated_id, groups, dst);
                Ok(())
            }
            (SectionUpdate { prefix, members }, Section(_), PrefixSection(_)) => {
                self.handle_section_update(prefix, members)
            }
            (GroupSplit(prefix, joining_node), _, _) => {
                self.handle_group_split(prefix, joining_node)
            }
            (OwnGroupMerge { sender_prefix, merge_prefix, groups }, _, _) => {
                self.handle_own_group_merge(sender_prefix, merge_prefix, groups)
            }
            (OtherGroupMerge { prefix, group }, _, _) => {
                self.handle_other_group_merge(prefix, group)
            }
            (Ack(ack, _), _, _) => self.handle_ack_response(ack),
            (UserMessagePart { hash, part_count, part_index, payload, .. }, src, dst) => {
                if let Some(msg) = self.user_msg_cache.add(hash, part_count, part_index, payload) {
                    self.stats().count_user_message(&msg);
                    self.send_event(msg.into_event(src, dst));
                }
                Ok(())
            }
            (content, src, dst) => {
                debug!("{:?} Unhandled routing message {:?} from {:?} to {:?}",
                       self,
                       content,
                       src,
                       dst);
                Err(RoutingError::BadAuthority)
            }
        }
    }

    fn handle_node_approval_vote(&mut self,
                                 candidate_name: XorName,
                                 validity: bool)
                                 -> Result<(), RoutingError> {
        let groups = self.peer_mgr.get_sections_to_join(&candidate_name, self.full_id.public_id())?;
        let (approval, peer_info) = self.peer_mgr
            .handle_node_approval_vote(candidate_name, validity);
        let peer_id = if let Some(peer_id) = self.peer_mgr.get_peer_id(&candidate_name) {
            *peer_id
        } else {
            // Once the joining node joined, it may receive the vote regarding itself.
            // Or a node may receive CandidateApproval before connection established.
            warn!("{:?} cannot get peer_id of candidate {:?}", self, candidate_name);
            return Ok(());
        };
        if !validity {
            self.disconnect_peer(&peer_id);
        }
        if approval && validity {
            if let Some((pub_id, peer_id)) = peer_info {
                self.add_to_routing_table(&pub_id, &peer_id);
            }
            let direct_message = DirectMessage::NodeApproval { groups: groups };
            return self.send_direct_message(&peer_id, direct_message);
        }
        Ok(())
    }

    fn handle_node_approval(&mut self, groups: Vec<(Prefix<XorName>, Vec<PublicId>)>) {
        let result = self.peer_mgr.peer_candidates();
        if result.len() > 0 {
            self.peer_mgr.populate_routing_table(&groups);
            for peer_info in &result {
                self.add_to_routing_table(&peer_info.0, &peer_info.1);
            }

            for group in &groups {
                for pub_id in &group.1 {
                    if !self.peer_mgr.routing_table().has(pub_id.name()) {
                        debug!("{:?} Sending connection info to {:?} on NodeApproval.",
                               self,
                               pub_id);
                        let src = Authority::ManagedNode(*self.name());
                        let node_auth = Authority::ManagedNode(*pub_id.name());
                        if let Err(error) = self.send_connection_info(*pub_id, src, node_auth) {
                            debug!("{:?} - Failed to send connection info to {:?}: {:?}",
                                   self,
                                   pub_id,
                                   error);
                        }
                    }
                }
            }
        }
    }

    fn handle_resource_proof_request(&mut self,
                                     peer_id: PeerId,
                                     seed: Vec<u8>,
                                     _target_size: u32,
                                     _difficulty: u32)
                                     -> Result<(), RoutingError> {
        let direct_message = DirectMessage::ResourceProofResponse {
            proof: seed,
            leading_zero_bytes: 0,
        };
        self.send_direct_message(&peer_id, direct_message)
    }

    fn handle_resource_proof_response(&mut self,
                                      peer_id: PeerId,
                                      proof: Vec<u8>,
                                      leading_zero_bytes: u32) {
        let name = if let Some(name) = self.peer_mgr.get_peer_name(&peer_id) {
            *name
        } else {
            return;
        };
        if let Some(valid_candidate) =
            self.peer_mgr
                .verify_candidate(name, proof, leading_zero_bytes, RESOURCE_PROOF_DIFFICULTY) {
            let response_content = MessageContent::CandidateApproval(valid_candidate);
            let response_msg = RoutingMessage {
                src: Authority::Section(name),
                dst: Authority::Section(name),
                content: response_content,
            };
            info!("{:?} Sending CandidateApproval {:?} to group.",
                  self,
                  valid_candidate);
            let _ = self.send_routing_message(response_msg);
        }
    }

    /// Returns `Ok` if a client is allowed to send the given message.
    fn check_valid_client_message(&self, msg: &RoutingMessage) -> Result<(), RoutingError> {
        match msg.content {
            MessageContent::Ack(..) => Ok(()),
            MessageContent::UserMessagePart { priority, .. } if priority >= DEFAULT_PRIORITY => {
                Ok(())
            }
            _ => {
                debug!("{:?} Illegitimate client message {:?}. Refusing to relay.",
                       self,
                       msg);
                Err(RoutingError::RejectedClientMessage)
            }
        }
    }

    fn respond_from_cache(&mut self,
                          routing_msg: &RoutingMessage,
                          route: u8)
                          -> Result<bool, RoutingError> {
        if let MessageContent::UserMessagePart { hash,
                                                 part_count,
                                                 part_index,
                                                 cacheable,
                                                 ref payload,
                                                 .. } = routing_msg.content {
            if !cacheable {
                return Ok(false);
            }

            match self.cacheable_user_msg_cache.add(hash, part_count, part_index, payload.clone()) {
                Some(UserMessage::Request(request)) => {
                    if let Some(response) = self.response_cache.get(&request) {
                        debug!("{:?} Found cached response to {:?}", self, request);

                        let priority = response.priority();
                        let src = Authority::ManagedNode(*self.name());
                        let dst = routing_msg.src;

                        self.send_ack_from(routing_msg, route, src);

                        try!(self.send_user_message(src,
                                                    dst,
                                                    UserMessage::Response(response),
                                                    priority));

                        return Ok(true);
                    }
                }

                Some(UserMessage::Response(response)) => {
                    debug!("{:?} Putting {:?} in cache", self, response);
                    self.response_cache.put(response);
                }

                None => (),
            }
        }

        Ok(false)
    }

    fn start_listening(&mut self) -> bool {
        if let Err(error) = self.crust_service.start_listening_tcp() {
            error!("{:?} Failed to start listening: {:?}", self, error);
            false
        } else {
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

        let proxy_name = if let Some((_, proxy_pub_id)) = self.peer_mgr.proxy() {
            *proxy_pub_id.name()
        } else {
            return Err(RoutingError::ProxyConnectionNotFound);
        };

        let src = Authority::Client {
            client_key: *self.full_id.public_id().signing_public_key(),
            proxy_node_name: proxy_name,
            peer_id: self.crust_service.id(),
        };

        let request_msg = RoutingMessage {
            src: src,
            dst: Authority::Section(*self.name()),
            content: request_content,
        };

        info!("{:?} Sending GetNodeName request with: {:?}. This can take a while.",
              self,
              self.full_id.public_id());

        self.send_routing_message(request_msg)
    }

    fn send_bootstrap_identify(&mut self, peer_id: PeerId) -> Result<(), RoutingError> {
        let direct_message =
            DirectMessage::BootstrapIdentify { public_id: *self.full_id.public_id() };
        self.send_direct_message(&peer_id, direct_message)
    }

    fn handle_client_identify(&mut self,
                              public_id: PublicId,
                              peer_id: PeerId,
                              client_restriction: bool)
                              -> Result<(), RoutingError> {
        if !client_restriction && !self.crust_service.is_peer_whitelisted(&peer_id) {
            warn!("{:?} Client is not whitelisted - dropping", self);
            self.disconnect_peer(&peer_id);
            return Ok(());
        }
        if *public_id.name() != XorName(sha256::hash(&public_id.signing_public_key().0).0) {
            warn!("{:?} Incoming Connection not validated as a proper client - dropping",
                  self);
            self.disconnect_peer(&peer_id);
            return Ok(());
        }

        for peer_id in self.peer_mgr.remove_expired_joining_nodes() {
            debug!("{:?} Removing stale joining node with Crust ID {:?}",
                   self,
                   peer_id);
            self.disconnect_peer(&peer_id);
        }

        if (client_restriction || !self.is_first_node) &&
           self.peer_mgr.routing_table().len() < self.min_group_size() - 1 {
            debug!("{:?} Client {:?} rejected: Routing table has {} entries. {} required.",
                    self,
                    public_id.name(),
                    self.peer_mgr.routing_table().len(),
                    self.min_group_size() - 1);
            return self.send_direct_message(&peer_id, DirectMessage::BootstrapDeny);
        }

        let non_unique = if client_restriction {
            self.peer_mgr.insert_client(peer_id, public_id)
        } else {
            self.peer_mgr.insert_joining_node(peer_id, public_id)
        };

        if non_unique {
            debug!("{:?} Received two ClientInfo from the same peer ID {:?}.",
                   self,
                   peer_id);
        }

        debug!("{:?} Accepted client {:?}.", self, public_id.name());

        self.send_bootstrap_identify(peer_id)
    }

    fn handle_node_identify(&mut self, public_id: PublicId, peer_id: PeerId) {
        debug!("{:?} Handling NodeIdentify from {:?}.",
               self,
               public_id.name());
        if self.peer_mgr.is_peer_candidate(&public_id, &peer_id) {
            return;
        }
        if let Ok(Some((tunnel, seed))) = self.peer_mgr.is_node_candidate(&public_id, &peer_id) {
            if tunnel {
                /// if connection is in tunnel, vote NO directly, don't carry out profiling
                /// limitation: joining node ONLY carries out QUORAM valid connection/evaluations
                info!("{:?} Sending CandidateApproval false to group rejetcing {:?}.",
                      self,
                      *public_id.name());
                // From Y -> Y
                let _ = self.send_routing_message(RoutingMessage {
                    src: Authority::Section(*public_id.name()),
                    dst: Authority::Section(*public_id.name()),
                    content: MessageContent::CandidateApproval(false),
                });
            } else {
                // From Y -> A
                let direct_message = DirectMessage::ResourceProof {
                    seed: seed,
                    target_size: resource_proof_target_size(self.peer_mgr
                        .routing_table()
                        .our_group()
                        .len()),
                    difficulty: RESOURCE_PROOF_DIFFICULTY,
                };
                let _ = self.send_direct_message(&peer_id, direct_message);

                debug!("{:?} requesting resource_proof from node candidate {:?}.",
                       self,
                       *public_id.name());

            }
        } else {
            self.add_to_routing_table(&public_id, &peer_id);
        }
    }

    fn add_to_routing_table(&mut self, public_id: &PublicId, peer_id: &PeerId) {
        match self.peer_mgr.add_to_routing_table(public_id, peer_id) {
            Err(RoutingTableError::AlreadyExists) => return,  // already in RT
            Err(error) => {
                debug!("{:?} Peer {:?} was not added to the routing table: {}",
                       self,
                       peer_id,
                       error);
                self.disconnect_peer(peer_id);
                return;
            }
            Ok(true) => {
                // i.e. the group should split
                let our_group_prefix = *self.peer_mgr.routing_table().our_group_prefix();
                // In the future we'll look to remove this restriction so we always call
                // `send_group_split()` here and also check whether another round of splitting is
                // required in `handle_group_split()` so splitting becomes recursive like merging.
                if our_group_prefix.matches(public_id.name()) {
                    self.send_group_split(our_group_prefix, *public_id.name());
                }
            }
            Ok(false) => {
                self.merge_if_necessary();
            }
        }

        debug!("{:?} Added {:?} to routing table.", self, public_id.name());
        if self.peer_mgr.routing_table().len() == 1 {
            self.send_event(Event::Connected);
        }

        let event = Event::NodeAdded(*public_id.name(), self.peer_mgr.routing_table().clone());
        if let Err(err) = self.event_sender.send(event) {
            error!("{:?} Error sending event to routing user - {:?}", self, err);
        }

        if self.peer_mgr.routing_table().is_in_our_group(public_id.name()) {
            // TODO: we probably don't need to send this if we're splitting, but in that case
            // we should send something else instead. This will do for now.
            self.send_section_update();
        }

        for dst_id in self.peer_mgr.peers_needing_tunnel() {
            trace!("{:?} Asking {:?} to serve as a tunnel for {:?}",
                   self,
                   peer_id,
                   dst_id);
            let tunnel_request = DirectMessage::TunnelRequest(dst_id);
            let _ = self.send_direct_message(peer_id, tunnel_request);
        }
    }

    // Tell all neighbouring sections that our member list changed.
    // Currently we only send this when nodes join and it's only used to add missing members.
    fn send_section_update(&mut self) {
        trace!("{:?} Sending section update", self);
        let names = self.peer_mgr.routing_table().our_names();
        let members = self.peer_mgr.get_pub_ids(&names).iter().cloned().sorted();

        let content = MessageContent::SectionUpdate {
            prefix: *self.peer_mgr.routing_table().our_group_prefix(),
            members: members,
        };

        let neighbours = self.peer_mgr.routing_table().other_prefixes();
        for neighbour_pfx in neighbours {
            let request_msg = RoutingMessage {
                src: Authority::Section(self.peer_mgr
                    .routing_table()
                    .our_group_prefix()
                    .lower_bound()),
                dst: Authority::PrefixSection(neighbour_pfx),
                content: content.clone(),
            };

            if let Err(err) = self.send_routing_message(request_msg) {
                debug!("{:?} Failed to send section update to {:?}: {:?}",
                    self,
                    neighbour_pfx,
                    err);
            }
        }
    }

    fn handle_connection_info_prepared(&mut self,
                                       result_token: u32,
                                       result: Result<PrivConnectionInfo, CrustError>) {
        let our_connection_info = match result {
            Err(err) => {
                error!("{:?} Failed to prepare connection info: {:?}", self, err);
                return;
            }
            Ok(connection_info) => connection_info,
        };
        let encoded_connection_info =
            match serialisation::serialise(&our_connection_info.to_pub_connection_info()) {
                Err(err) => {
                    error!("{:?} Failed to serialise connection info: {:?}", self, err);
                    return;
                }
                Ok(encoded_connection_info) => encoded_connection_info,
            };

        let (pub_id, src, dst) = match self.peer_mgr
            .connection_info_prepared(result_token, our_connection_info) {
            Err(error) => {
                // This usually means we have already connected.
                debug!("{:?} Prepared connection info, but no entry found in token map: {:?}",
                       self,
                       error);
                return;
            }
            Ok(ConnectionInfoPreparedResult { pub_id, src, dst, infos }) => {
                match infos {
                    None => {
                        debug!("{:?} Prepared connection info for {:?}.",
                               self,
                               pub_id.name());
                    }
                    Some((our_info, their_info)) => {
                        debug!("{:?} Trying to connect to {:?} as {:?}.",
                               self,
                               their_info.id(),
                               pub_id.name());
                        let _ = self.crust_service.connect(our_info, their_info);
                    }
                }
                (pub_id, src, dst)
            }
        };

        let nonce = box_::gen_nonce();
        let encrypted_connection_info = box_::seal(&encoded_connection_info,
                                                   &nonce,
                                                   pub_id.encrypting_public_key(),
                                                   self.full_id().encrypting_private_key());

        let request_content = ConnectionInfo {
                encrypted_connection_info: encrypted_connection_info,
                nonce_bytes: nonce.0,
                public_id: *self.full_id().public_id(),
            }
            .into_msg();

        let request_msg = RoutingMessage {
            src: src,
            dst: dst,
            content: request_content,
        };

        if let Err(err) = self.send_routing_message(request_msg) {
            debug!("{:?} Failed to send connection info for {:?}: {:?}.",
                   self,
                   pub_id.name(),
                   err);
        }
    }

    // TODO: check whether these two methods can be merged into one.
    fn handle_connection_info_from_client(&mut self,
                                          conn_info: ConnectionInfo,
                                          src: Authority<XorName>,
                                          dst: Authority<XorName>)
                                          -> Result<(), RoutingError> {
        self.peer_mgr.allow_connect(conn_info.public_id.name())?;
        self.connect(conn_info, dst, src)
    }

    fn handle_connection_info_from_node(&mut self,
                                        conn_info: ConnectionInfo,
                                        src_name: XorName,
                                        dst: Authority<XorName>)
                                        -> Result<(), RoutingError> {
        self.peer_mgr.allow_connect(&src_name)?;
        self.connect(conn_info, dst, Authority::ManagedNode(src_name))
    }

    /// Handle a request by `peer_id` to act as a tunnel connecting it with `dst_id`.
    fn handle_tunnel_request(&mut self,
                             peer_id: PeerId,
                             dst_id: PeerId)
                             -> Result<(), RoutingError> {
        if self.peer_mgr.can_tunnel_for(&peer_id, &dst_id) {
            if let Some((id0, id1)) = self.tunnels.consider_clients(peer_id, dst_id) {
                debug!("{:?} Accepted tunnel request from {:?} for {:?}.",
                       self,
                       peer_id,
                       dst_id);
                return self.send_direct_message(&id0, DirectMessage::TunnelSuccess(id1));
            }
        } else {
            debug!("{:?} Rejected tunnel request from {:?} for {:?}.",
                   self,
                   peer_id,
                   dst_id);
        }
        Ok(())
    }

    /// Handle a `TunnelSuccess` response from `peer_id`: It will act as a tunnel to `dst_id`.
    fn handle_tunnel_success(&mut self,
                             peer_id: PeerId,
                             dst_id: PeerId)
                             -> Result<(), RoutingError> {
        if !self.peer_mgr.tunnelling_to(&dst_id) {
            debug!("{:?} Received TunnelSuccess for a peer we are already connected to: {:?}",
                   self,
                   dst_id);
            let message = DirectMessage::TunnelDisconnect(dst_id);
            self.send_direct_message(&peer_id, message)?;
            return Ok(());
        }
        if self.tunnels.add(dst_id, peer_id) {
            debug!("{:?} Adding {:?} as a tunnel node for {:?}.",
                   self,
                   peer_id,
                   dst_id);
            return self.send_node_identify(dst_id);
        }
        Ok(())
    }

    /// Handle a `TunnelClosed` message from `peer_id`: `dst_id` disconnected.
    fn handle_tunnel_closed(&mut self,
                            peer_id: PeerId,
                            dst_id: PeerId)
                            -> Result<(), RoutingError> {
        if self.tunnels.remove(dst_id, peer_id) {
            debug!("{:?} Tunnel to {:?} via {:?} closed.",
                   self,
                   dst_id,
                   peer_id);
            if !self.crust_service.is_connected(&dst_id) {
                self.dropped_peer(&dst_id);
            }
        }
        Ok(())
    }

    /// Handle a `TunnelDisconnect` message from `peer_id` who wants to disconnect `dst_id`.
    fn handle_tunnel_disconnect(&mut self,
                                peer_id: PeerId,
                                dst_id: PeerId)
                                -> Result<(), RoutingError> {
        debug!("{:?} Closing tunnel connecting {:?} and {:?}.",
               self,
               dst_id,
               peer_id);
        if self.tunnels.drop_client_pair(dst_id, peer_id) {
            self.send_direct_message(&dst_id, DirectMessage::TunnelClosed(peer_id))
        } else {
            Ok(())
        }
    }

    /// Disconnects from the given peer, via Crust or by dropping the tunnel node, if the peer is
    /// not a proxy, client or routing table entry.
    fn disconnect_peer(&mut self, peer_id: &PeerId) {
        if let Some(&pub_id) = self.peer_mgr.get_routing_peer(peer_id) {
            debug!("{:?} Not disconnecting routing table entry {:?} ({:?}).",
                   self,
                   pub_id.name(),
                   peer_id);
        } else if let Some(&public_id) = self.peer_mgr.get_proxy_public_id(peer_id) {
            debug!("{:?} Not disconnecting proxy node {:?} ({:?}).",
                   self,
                   public_id.name(),
                   peer_id);
        } else if self.peer_mgr.get_client(peer_id).is_some() {
            debug!("{:?} Not disconnecting client {:?}.", self, peer_id);
        } else if self.peer_mgr.get_joining_node(peer_id).is_some() {
            debug!("{:?} Not disconnecting joining node {:?}.", self, peer_id);
        } else if let Some(tunnel_id) = self.tunnels.remove_tunnel_for(peer_id) {
            debug!("{:?} Disconnecting {:?} (indirect).", self, peer_id);
            let message = DirectMessage::TunnelDisconnect(*peer_id);
            let _ = self.send_direct_message(&tunnel_id, message);
        } else {
            debug!("{:?} Disconnecting {:?}. Calling crust::Service::disconnect.",
                   self,
                   peer_id);
            let _ = self.crust_service.disconnect(*peer_id);
            let _ = self.peer_mgr.remove_peer(peer_id);
        }
    }

    // Received by X; From A -> X
    fn handle_get_node_name_request(&mut self,
                                    mut their_public_id: PublicId,
                                    client_key: sign::PublicKey,
                                    proxy_name: XorName,
                                    dst_name: XorName,
                                    peer_id: PeerId,
                                    message_id: MessageId)
                                    -> Result<(), RoutingError> {
        let hashed_key = sha256::hash(&client_key.0);
        let close_group_to_client = XorName(hashed_key.0);

        // Validate Client (relocating node) has contacted the correct Group-X
        if close_group_to_client != dst_name {
            return Err(RoutingError::InvalidDestination);
        }

        let close_group = match self.peer_mgr.routing_table().close_names(&dst_name) {
            Some(close_group) => close_group.into_iter().collect(),
            None => return Err(RoutingError::InvalidDestination),
        };
        let relocated_name =
            self.next_node_name.take().unwrap_or_else(|| {
                utils::calculate_relocated_name(close_group, their_public_id.name())
            });
        their_public_id.set_name(relocated_name);

        // From X -> Y; Send to close group of the relocated name
        let request_content = MessageContent::ExpectCloseNode {
            expect_id: their_public_id,
            client_auth: Authority::Client {
                client_key: client_key,
                proxy_node_name: proxy_name,
                peer_id: peer_id,
            },
            message_id: message_id,
        };

        let request_msg = RoutingMessage {
            src: Authority::Section(dst_name),
            dst: Authority::Section(relocated_name),
            content: request_content,
        };

        self.send_routing_message(request_msg)
    }

    // Context: we're a new node joining a group. This message should have been
    // sent by each node in the target group with the new node name and routing table.
    fn handle_node_approval_no_resource_proof(&mut self,
                                              relocated_id: PublicId,
                                              groups: Vec<(Prefix<XorName>, Vec<PublicId>)>,
                                              dst: Authority<XorName>) {
        if !self.peer_mgr.routing_table().is_empty() {
            warn!("{:?} Received duplicate NodeApproval.", self);
            return;
        }
        self.get_node_name_timer_token = None;

        self.full_id.public_id_mut().set_name(*relocated_id.name());
        self.peer_mgr.reset_routing_table(*self.full_id.public_id(), &groups);

        for pub_id in groups.into_iter().flat_map(|(_, group)| group.into_iter()) {
            debug!("{:?} Sending connection info to {:?} on NodeApproval.",
                   self,
                   pub_id);

            let node_auth = Authority::ManagedNode(*pub_id.name());
            if let Err(error) = self.send_connection_info(pub_id, dst, node_auth) {
                debug!("{:?} - Failed to send connection info to {:?}: {:?}",
                       self,
                       pub_id,
                       error);
            }
        }
    }

    // Context: we're a new node joining a group. This message should have been
    // sent by each node in the target group with the new node name and group for resource proving.
    fn handle_get_node_name_response(&mut self,
                                     relocated_id: PublicId,
                                     group: (Prefix<XorName>, Vec<PublicId>),
                                     dst: Authority<XorName>) {
        if !self.peer_mgr.routing_table().is_empty() {
            warn!("{:?} Received duplicate GetNodeName response.", self);
            return;
        }
        self.get_node_name_timer_token = None;

        self.full_id.public_id_mut().set_name(*relocated_id.name());
        self.peer_mgr.restart_routing_table(*self.full_id.public_id());
        trace!("{:?} GetNodeName completed. Prefixes: {:?}",
               self,
               self.peer_mgr.routing_table().prefixes());

        for pub_id in group.1.into_iter() {
            self.peer_mgr.add_as_peer_candidate(*pub_id.name());
            debug!("{:?} Sending connection info to {:?} on GetNodeName response.",
                   self,
                   pub_id);

            let node_auth = Authority::ManagedNode(*pub_id.name());
            if let Err(error) = self.send_connection_info(pub_id, dst, node_auth) {
                debug!("{:?} - Failed to send connection info to {:?}: {:?}",
                       self,
                       pub_id,
                       error);
            }
        }
    }

    // Received by Y; From X -> Y
    // Context: we're part of the `NaeManager` for the new name of a node
    // (i.e. a node is joining our group). Send the node our routing table.
    fn handle_expect_close_node_request(&mut self,
                                        expect_id: PublicId,
                                        client_auth: Authority<XorName>,
                                        message_id: MessageId)
                                        -> Result<(), RoutingError> {
        if expect_id == *self.full_id.public_id() {
            // If we're the joining node: stop
            return Ok(());
        }

        // TODO - do we need to reply if `expect_id` triggers a failure here?
        let (resource_proving, own_group) = self.peer_mgr
            .expect_join_our_group(expect_id.name(), self.full_id.public_id())?;

        let response_content = if resource_proving {
            // From Y -> A (via B)
            let response_content = MessageContent::GetNodeNameResponse {
                relocated_id: expect_id,
                group: own_group,
                message_id: message_id,
            };

            debug!("{:?} Responding to client {:?}: {:?}.",
                   self,
                   client_auth,
                   response_content);
            response_content
        } else {
            let groups = self.peer_mgr
                .get_sections_to_join(expect_id.name(), self.full_id.public_id())?;
            // From Y -> A
            let response_content = MessageContent::NodeApproval {
                relocated_id: expect_id,
                groups: groups,
            };

            debug!("{:?} sending NodeApproval to {:?}: {:?}.",
                   self,
                   client_auth,
                   response_content);

            response_content
        };
        let response_msg = RoutingMessage {
            src: Authority::Section(*expect_id.name()),
            dst: client_auth,
            content: response_content,
        };

        self.send_routing_message(response_msg)
    }

    fn handle_section_update(&mut self,
                             prefix: Prefix<XorName>,
                             members: Vec<PublicId>)
                             -> Result<(), RoutingError> {
        trace!("{:?} Got section update for {:?}", self, prefix);
        // Filter list of members to just those we don't know about:
        let members = if let Some(section) = self.peer_mgr.routing_table().section_ref(&prefix) {
            let f = |id: &PublicId| !(section.is_member(id.name()) || section.is_needed(id.name()));
            members.into_iter().filter(f).collect_vec()
        } else {
            warn!("{:?} Section update received from unknown neighbour {:?}", self, prefix);
            return Ok(());
        };

        let own_name = *self.name();
        for pub_id in members {
            self.peer_mgr.mark_needed(pub_id.name())?;
            if let Err(error) = self.send_connection_info(pub_id,
                                                          Authority::ManagedNode(own_name),
                                                          Authority::ManagedNode(*pub_id.name())) {
                debug!("{:?} - Failed to send connection info to {:?}: {:?}",
                    self,
                    pub_id,
                    error);
            }
        }
        Ok(())
    }

    fn handle_group_split(&mut self,
                          prefix: Prefix<XorName>,
                          joining_node: XorName)
                          -> Result<(), RoutingError> {
        // Send GroupSplit notifications if we don't know of the new node yet
        if prefix == *self.peer_mgr.routing_table().our_group_prefix() &&
           !self.peer_mgr.routing_table().has(&joining_node) {
            self.send_group_split(prefix, joining_node);
        }
        // None of the `peers_to_drop` will have been in our group, so no need to notify Routing
        // user about them.
        let (peers_to_drop, our_new_prefix) = self.peer_mgr.split_group(prefix);
        if let Some(new_prefix) = our_new_prefix {
            if let Err(err) = self.event_sender.send(Event::GroupSplit(new_prefix)) {
                error!("{:?} Error sending event to routing user - {:?}", self, err);
            }
        }

        for (name, peer_id) in peers_to_drop {
            self.disconnect_peer(&peer_id);
            info!("{:?} Dropped {:?} from the routing table.", self, name);
        }
        trace!("{:?} Split completed. Prefixes: {:?}",
               self,
               self.peer_mgr.routing_table().prefixes());

        self.merge_if_necessary();
        Ok(())
    }

    fn handle_own_group_merge(&mut self,
                              sender_prefix: Prefix<XorName>,
                              merge_prefix: Prefix<XorName>,
                              groups: Vec<(Prefix<XorName>, Vec<PublicId>)>)
                              -> Result<(), RoutingError> {
        let (merge_state, needed_peers) = self.peer_mgr
            .merge_own_group(sender_prefix, merge_prefix, groups);
        let src =
            Authority::Section(self.peer_mgr.routing_table().our_group_prefix().lower_bound());
        match merge_state {
            OwnMergeState::Initialised { merge_details } => {
                self.send_own_group_merge(merge_details, src)
            }
            OwnMergeState::Ongoing |
            OwnMergeState::AlreadyMerged => (),
            OwnMergeState::Completed { targets, merge_details } => {
                // TODO - the event should maybe only fire once all new connections have been made?
                if let Err(err) = self.event_sender.send(Event::GroupMerge(merge_details.prefix)) {
                    error!("{:?} Error sending event to routing user - {:?}", self, err);
                }
                trace!("{:?} Merge completed. Prefixes: {:?}",
                       self,
                       self.peer_mgr.routing_table().prefixes());
                self.merge_if_necessary();
                self.send_other_group_merge(targets, merge_details, src)
            }
        }

        let own_name = *self.name();
        for needed in &needed_peers {
            debug!("{:?} Sending connection info to {:?} due to merging own group.",
                   self,
                   needed);
            if let Err(error) = self.send_connection_info(*needed,
                                                          Authority::ManagedNode(own_name),
                                                          Authority::ManagedNode(*needed.name())) {
                debug!("{:?} - Failed to send connection info to {:?}: {:?}",
                       self,
                       needed,
                       error);
            }
        }
        Ok(())
    }

    fn handle_other_group_merge(&mut self,
                                prefix: Prefix<XorName>,
                                group: BTreeSet<PublicId>)
                                -> Result<(), RoutingError> {
        let needed_peers = self.peer_mgr.merge_other_group(prefix, group);
        let own_name = *self.name();
        for needed in needed_peers {
            debug!("{:?} Sending connection info to {:?} due to merging other group.",
                   self,
                   needed);
            let needed_name = *needed.name();
            if let Err(error) = self.send_connection_info(needed,
                                                          Authority::ManagedNode(own_name),
                                                          Authority::ManagedNode(needed_name)) {
                debug!("{:?} - Failed to send connection info: {:?}", self, error);
            }
        }
        trace!("{:?} Other merge completed. Prefixes: {:?}",
               self,
               self.peer_mgr.routing_table().prefixes());
        self.merge_if_necessary();
        Ok(())
    }

    fn handle_ack_response(&mut self, ack: Ack) -> Result<(), RoutingError> {
        self.ack_mgr.receive(ack);
        Ok(())
    }

    fn handle_timeout(&mut self, token: u64) -> bool {
        if self.get_node_name_timer_token == Some(token) {
            info!("{:?} Failed to get GetNodeName response.", self);
            self.send_event(Event::RestartRequired);
            return false;
        }

        if self.tick_timer_token == token {
            let _ = self.event_sender.send(Event::Tick);
            let tick_period = Duration::from_secs(TICK_TIMEOUT_SECS);
            self.tick_timer_token = self.timer.schedule(tick_period);

            for peer_id in self.peer_mgr.remove_expired_connections() {
                debug!("{:?} Disconnecting from timed out peer {:?}", self, peer_id);
                let _ = self.crust_service.disconnect(peer_id);
            }

            return true;
        }

        self.resend_unacknowledged_timed_out_msgs(token);

        true
    }

    fn connect(&mut self,
               conn_info: ConnectionInfo,
               src: Authority<XorName>,
               dst: Authority<XorName>)
               -> Result<(), RoutingError> {
        let decipher_result = box_::open(&conn_info.encrypted_connection_info,
                                         &box_::Nonce(conn_info.nonce_bytes),
                                         conn_info.public_id.encrypting_public_key(),
                                         self.full_id.encrypting_private_key());

        let serialised_connection_info =
            decipher_result.map_err(|()| RoutingError::AsymmetricDecryptionFailure)?;
        let their_connection_info: PubConnectionInfo =
            serialisation::deserialise(&serialised_connection_info)?;
        let peer_id = their_connection_info.id();
        match self.peer_mgr
            .connection_info_received(src, dst, conn_info.public_id, their_connection_info) {
            Ok(ConnectionInfoReceivedResult::Ready(our_info, their_info)) => {
                debug!("{:?} Received connection info. Trying to connect to {:?} ({:?}).",
                       self,
                       conn_info.public_id.name(),
                       peer_id);
                let _ = self.crust_service.connect(our_info, their_info);
            }
            Ok(ConnectionInfoReceivedResult::Prepare(token)) => {
                self.crust_service.prepare_connection_info(token);
            }
            Ok(ConnectionInfoReceivedResult::IsProxy) |
            Ok(ConnectionInfoReceivedResult::IsClient) |
            Ok(ConnectionInfoReceivedResult::IsJoiningNode) => {
                self.send_node_identify(peer_id)?;
                self.handle_node_identify(conn_info.public_id, peer_id);
            }
            Ok(ConnectionInfoReceivedResult::Waiting) |
            Ok(ConnectionInfoReceivedResult::IsConnected) => (),
            Err(error) => {
                warn!("{:?} Failed to insert connection info from {:?} ({:?}): {:?}",
                      self,
                      conn_info.public_id.name(),
                      peer_id,
                      error)
            }
        }

        Ok(())
    }

    // ----- Send Functions -----------------------------------------------------------------------
    fn send_user_message(&mut self,
                         src: Authority<XorName>,
                         dst: Authority<XorName>,
                         user_msg: UserMessage,
                         priority: u8)
                         -> Result<(), RoutingError> {
        self.stats.count_user_message(&user_msg);

        for part in user_msg.to_parts(priority)? {
            self.send_routing_message(RoutingMessage {
                    src: src,
                    dst: dst,
                    content: part,
                })?;
        }
        Ok(())
    }

    fn accumulate_message(&mut self,
                          signed_msg: SignedMessage,
                          route: u8)
                          -> Result<(), RoutingError> {
        let our_name = *self.name();
        let min_group_size = self.min_group_size();
        if let Some((msg, route)) =
            self.sig_accumulator.add_message(signed_msg, min_group_size, route) {
            trace!("{:?} Message accumulated - sending: {:?}", self, msg);
            if self.in_authority(&msg.routing_message().dst) {
                self.handle_signed_message(msg, route, our_name, &BTreeSet::new())?;
            } else {
                self.send_signed_message(&msg, route, &our_name, &BTreeSet::new())?;
            }
        }
        Ok(())
    }

    fn send_signed_message(&mut self,
                           signed_msg: &SignedMessage,
                           route: u8,
                           hop: &XorName,
                           sent_to: &BTreeSet<XorName>)
                           -> Result<(), RoutingError> {
        let sent_by_us = hop == self.name() && signed_msg.signed_by(self.full_id().public_id());
        if sent_by_us {
            self.stats.count_route(route);
        }

        let routing_msg = signed_msg.routing_message();

        if let Authority::Client { ref peer_id, .. } = routing_msg.dst {
            if *self.name() == routing_msg.dst.name() {
                // This is a message for a client we are the proxy of. Relay it.
                return self.relay_to_client(signed_msg.clone(), peer_id);
            } else if self.in_authority(&routing_msg.dst) {
                return Ok(()); // Message is for us as a client.
            }
        }

        let (new_sent_to, target_peer_ids) = self.get_targets(routing_msg, route, hop, sent_to)?;

        for target_peer_id in target_peer_ids {
            match self.send_signed_msg_to_peer(signed_msg,
                                               target_peer_id,
                                               route,
                                               new_sent_to.clone()) {
                Ok(_) => {}
                Err(err) => {
                    warn!("{:?} failed with {:?} in sending {:?} to peer {:?}",
                          self, err, routing_msg, target_peer_id);
                }
            }

        }
        Ok(())
    }

    fn send_direct_msg_to_peer(&mut self,
                               msg: DirectMessage,
                               target: PeerId,
                               priority: u8)
                               -> Result<(), RoutingError> {
        let (peer_id, bytes) = if self.crust_service.is_connected(&target) {
            (target, serialisation::serialise(&Message::Direct(msg))?)
        } else if let Some(&tunnel_id) = self.tunnels
            .tunnel_for(&target) {
            let message = Message::TunnelDirect {
                content: msg,
                src: self.crust_service.id(),
                dst: target,
            };
            (tunnel_id, serialisation::serialise(&message)?)
        } else {
            trace!("{:?} Not connected or tunneling to {:?}. Dropping peer.",
                   self,
                   target);
            self.disconnect_peer(&target);
            return Ok(());
        };
        // TODO: Refactor so that filtering is possible here as well
        // if !self.filter_outgoing_routing_msg(signed_msg.routing_message(), &target, route) {
        if let Err(err) = self.send_or_drop(&peer_id, bytes, priority) {
            info!("{:?} Error sending message to {:?}: {:?}.",
                      self,
                      target,
                      err);
        }
        // }
        Ok(())
    }

    fn send_signed_msg_to_peer(&mut self,
                               signed_msg: &SignedMessage,
                               target: PeerId,
                               route: u8,
                               sent_to: BTreeSet<XorName>)
                               -> Result<(), RoutingError> {
        let (peer_id, bytes) = if self.crust_service.is_connected(&target) {
            (target, self.to_hop_bytes(signed_msg.clone(), route, sent_to)?)
        } else if let Some(&tunnel_id) = self.tunnels
            .tunnel_for(&target) {
            (tunnel_id, self.to_tunnel_hop_bytes(signed_msg.clone(), route, sent_to, target)?)
        } else {
            trace!("{:?} Not connected or tunneling to {:?}. Dropping peer.",
                   self,
                   target);
            self.disconnect_peer(&target);
            return Ok(());
        };
        if !self.filter_outgoing_routing_msg(signed_msg.routing_message(), &target, route) {
            if let Err(err) = self.send_or_drop(&peer_id, bytes, signed_msg.priority()) {
                info!("{:?} Error sending message to {:?}: {:?}.",
                      self,
                      target,
                      err);
            }
        }
        Ok(())
    }

    fn relay_to_client(&mut self,
                       signed_msg: SignedMessage,
                       peer_id: &PeerId)
                       -> Result<(), RoutingError> {
        let priority = signed_msg.priority();

        if self.peer_mgr.get_connected_peer(peer_id).is_some() {
            if self.filter_outgoing_routing_msg(signed_msg.routing_message(), peer_id, 0) {
                return Ok(());
            }
            let hop_msg = HopMessage::new(signed_msg,
                                          0,
                                          BTreeSet::new(),
                                          self.full_id.signing_private_key())?;
            let message = Message::Hop(hop_msg);
            let raw_bytes = serialisation::serialise(&message)?;
            self.send_or_drop(peer_id, raw_bytes, priority)
        } else {
            // Acknowledge the message so that the sender doesn't retry.
            let hop = *self.name();
            self.send_ack_from(signed_msg.routing_message(), 0, Authority::ManagedNode(hop));
            debug!("{:?} Client connection not found for message {:?}.",
                   self,
                   signed_msg);
            Err(RoutingError::ClientConnectionNotFound)
        }
    }

    /// Returns the peer that is responsible for collecting our signature for a group message.
    fn get_signature_target(&self, src: &Authority<XorName>, route: u8) -> Option<XorName> {
        if !src.is_multiple() {
            return Some(*self.name());
        }
        let mut group = if let Authority::PrefixSection(ref pfx) = *src {
            self.peer_mgr
                .routing_table()
                .iter()
                .filter(|name| pfx.matches(name))
                .chain(iter::once(self.name()))
                .sorted_by(|&lhs, &rhs| src.name().cmp_distance(lhs, rhs))
        } else {
            self.peer_mgr
                .routing_table()
                .our_group()
                .iter()
                .chain(iter::once(self.name()))
                .sorted_by(|&lhs, &rhs| src.name().cmp_distance(lhs, rhs))
        };
        group.truncate(self.min_group_size());
        if !group.contains(&self.name()) {
            None
        } else {
            Some(*group[route as usize % group.len()])
        }
    }

    /// Returns a list of target peer IDs.
    fn get_targets(&self,
                   routing_msg: &RoutingMessage,
                   route: u8,
                   hop: &XorName,
                   sent_to: &BTreeSet<XorName>)
                   -> Result<(BTreeSet<XorName>, Vec<PeerId>), RoutingError> {
        let force_via_proxy = match routing_msg.content {
            MessageContent::ConnectionInfo(ConnectionInfo { public_id, .. }) => {
                routing_msg.src.is_client() && public_id == *self.full_id.public_id()
            }
            _ => false,
        };

        if self.is_proper() && !force_via_proxy {
            let targets: HashSet<_> = self.peer_mgr
                .routing_table()
                .targets(&routing_msg.dst, *hop, route as usize)?
                .into_iter()
                .filter(|target| !sent_to.contains(target))
                .collect();
            let new_sent_to = if self.in_authority(&routing_msg.dst) {
                sent_to.iter()
                    .chain(targets.iter())
                    .chain(iter::once(self.name()))
                    .cloned()
                    .collect()
            } else {
                BTreeSet::new()
            };
            Ok((new_sent_to, self.peer_mgr.get_peer_ids(&targets)))
        } else if let Authority::Client { ref proxy_node_name, .. } = routing_msg.src {
            // We don't have any contacts in our routing table yet. Keep using
            // the proxy connection until we do.
            if let Some(&peer_id) = self.peer_mgr.get_proxy_peer_id(proxy_node_name) {
                Ok((BTreeSet::new(), vec![peer_id]))
            } else {
                error!("{:?} - Unable to find connection to proxy node in proxy map",
                       self);
                Err(RoutingError::ProxyConnectionNotFound)
            }
        } else {
            error!("{:?} - Source should be client if our state is a Client",
                   self);
            Err(RoutingError::InvalidSource)
        }
    }

    fn to_tunnel_hop_bytes(&self,
                           signed_msg: SignedMessage,
                           route: u8,
                           sent_to: BTreeSet<XorName>,
                           dst: PeerId)
                           -> Result<Vec<u8>, RoutingError> {
        let hop_msg = HopMessage::new(signed_msg.clone(),
                                      route,
                                      sent_to,
                                      self.full_id.signing_private_key())?;
        let message = Message::TunnelHop {
            content: hop_msg,
            src: self.crust_service.id(),
            dst: dst,
        };

        Ok(serialisation::serialise(&message)?)
    }

    fn send_node_identify(&mut self, peer_id: PeerId) -> Result<(), RoutingError> {
        let serialised_public_id = serialisation::serialise(self.full_id().public_id())?;
        let signature = sign::sign_detached(&serialised_public_id,
                                            self.full_id().signing_private_key());
        let direct_message = DirectMessage::NodeIdentify {
            serialised_public_id: serialised_public_id,
            signature: signature,
        };

        self.send_direct_message(&peer_id, direct_message)
    }

    fn send_connection_info(&mut self,
                            their_public_id: PublicId,
                            src: Authority<XorName>,
                            dst: Authority<XorName>)
                            -> Result<(), RoutingError> {
        let their_name = *their_public_id.name();
        if let Some(peer_id) = self.peer_mgr
            .get_proxy_or_client_or_joining_node_peer_id(&their_public_id) {
            self.send_node_identify(peer_id)?;
            self.handle_node_identify(their_public_id, peer_id);
            return Ok(());
        }

        self.peer_mgr.allow_connect(&their_name)?;
        if let Some(token) = self.peer_mgr.get_connection_token(src, dst, their_public_id) {
            self.crust_service.prepare_connection_info(token);
        } else {
            trace!("{:?} Already sent connection info to {:?}!",
                   self,
                   their_name);
        }
        Ok(())
    }

    // Handle dropped peer with the given peer id. Returns true if we should keep running, false if
    // we should terminate.
    fn dropped_peer(&mut self, peer_id: &PeerId) -> bool {
        let (peer, removal_result) = match self.peer_mgr.remove_peer(peer_id) {
            Some(result) => result,
            None => return true,
        };

        if let Ok(removal_details) = removal_result {
            if !self.dropped_routing_node(removal_details) {
                return false;
            }
        }

        match *peer.state() {
            PeerState::Client => {
                debug!("{:?} Client disconnected: {:?}", self, peer_id);
            }
            PeerState::JoiningNode => {
                debug!("{:?} Joining node {:?} dropped. {} remaining.",
                       self,
                       peer_id,
                       self.peer_mgr.joining_nodes_num());
            }
            PeerState::Proxy => {
                debug!("{:?} Lost bootstrap connection to {:?} ({:?}).",
                       self,
                       peer.name(),
                       peer_id);

                if self.peer_mgr.routing_table().len() < self.min_group_size() - 1 {
                    self.send_event(Event::Terminate);
                    return false;
                }
            }
            _ => (),
        }

        true
    }

    // Handle dropped routing peer with the given name and removal details. Returns true if we
    // should keep running, false if we should terminate.
    fn dropped_routing_node(&mut self, details: RemovalDetails<XorName>) -> bool {
        info!("{:?} Dropped {:?} from the routing table.",
              self,
              details.name);

        let event = Event::NodeLost(details.name, self.peer_mgr.routing_table().clone());
        if let Err(err) = self.event_sender.send(event) {
            error!("{:?} Error sending event to routing user - {:?}", self, err);
        }

        self.merge_if_necessary();

        if self.peer_mgr.routing_table().len() < self.min_group_size() - 1 {
            debug!("{:?} Lost connection, less than {} remaining.",
                   self,
                   self.min_group_size() - 1);
            if !self.is_first_node {
                self.send_event(Event::RestartRequired);
                return false;
            }
        }

        true
    }

    fn send_group_split(&mut self, our_prefix: Prefix<XorName>, joining_node: XorName) {
        for prefix in self.peer_mgr.routing_table().prefixes() {
            let request_msg = RoutingMessage {
                // this way of calculating the source avoids using the joining node as the route
                src: Authority::Section(our_prefix.substituted_in(!joining_node)),
                dst: Authority::PrefixSection(prefix),
                content: MessageContent::GroupSplit(our_prefix, joining_node),
            };
            if let Err(err) = self.send_routing_message(request_msg) {
                debug!("{:?} Failed to send GroupSplit: {:?}.", self, err);
            }
        }
    }

    fn merge_if_necessary(&mut self) {
        if let Some(merge_details) = self.peer_mgr.routing_table().should_merge() {
            let src_name = self.peer_mgr.routing_table().our_group_prefix().lower_bound();
            self.send_own_group_merge(merge_details, Authority::Section(src_name));
        }
    }

    fn send_own_group_merge(&mut self,
                            merge_details: OwnMergeDetails<XorName>,
                            src: Authority<XorName>) {
        let groups = merge_details.groups
            .into_iter()
            .map(|(prefix, members)| {
                (prefix, self.peer_mgr.get_pub_ids(&members).into_iter().sorted())
            })
            .sorted();
        let request_content = MessageContent::OwnGroupMerge {
            sender_prefix: merge_details.sender_prefix,
            merge_prefix: merge_details.merge_prefix,
            groups: groups,
        };
        let request_msg = RoutingMessage {
            src: src,
            dst: Authority::PrefixSection(merge_details.merge_prefix),
            content: request_content.clone(),
        };
        if let Err(err) = self.send_routing_message(request_msg) {
            debug!("{:?} Failed to send OwnGroupMerge: {:?}.", self, err);
        }
    }

    fn send_other_group_merge(&mut self,
                              targets: BTreeSet<Prefix<XorName>>,
                              merge_details: OtherMergeDetails<XorName>,
                              src: Authority<XorName>) {
        let group: BTreeSet<PublicId> =
            self.peer_mgr.get_pub_ids(&merge_details.group).into_iter().collect();
        for target in &targets {
            let request_content = MessageContent::OtherGroupMerge {
                prefix: merge_details.prefix,
                group: group.clone(),
            };
            let request_msg = RoutingMessage {
                src: src,
                dst: Authority::PrefixSection(*target),
                content: request_content,
            };

            if let Err(err) = self.send_routing_message(request_msg) {
                debug!("{:?} Failed to send OtherGroupMerge: {:?}.", self, err);
            }
        }
    }

    fn dropped_tunnel_client(&mut self, peer_id: &PeerId) {
        for other_id in self.tunnels.drop_client(peer_id) {
            let message = DirectMessage::TunnelClosed(*peer_id);
            let _ = self.send_direct_message(&other_id, message);
        }
    }

    fn dropped_tunnel_node(&mut self, peer_id: &PeerId) {
        let peers = self.tunnels
            .remove_tunnel(peer_id)
            .into_iter()
            .filter_map(|dst_id| {
                self.peer_mgr.get_routing_peer(&dst_id).map(|dst_pub_id| (dst_id, *dst_pub_id))
            })
            .collect_vec();
        for (dst_id, pub_id) in peers {
            self.dropped_peer(&dst_id);
            debug!("{:?} Lost tunnel for peer {:?} ({:?}). Requesting new tunnel.",
                   self,
                   dst_id,
                   pub_id.name());
            self.find_tunnel_for_peer(dst_id, &pub_id);
        }
    }

    // Proper node is either the first node in the network or a node which has at least one entry
    // in its routing table.
    fn is_proper(&self) -> bool {
        self.is_first_node || self.peer_mgr.routing_table().len() >= 1
    }

    fn send_direct_message(&mut self,
                           dst_id: &PeerId,
                           direct_message: DirectMessage)
                           -> Result<(), RoutingError> {
        self.stats().count_direct_message(&direct_message);

        if let Some(&tunnel_id) = self.tunnels.tunnel_for(dst_id) {
            let message = Message::TunnelDirect {
                content: direct_message,
                src: self.crust_service.id(),
                dst: *dst_id,
            };
            self.send_message(&tunnel_id, message)
        } else {
            self.send_message(dst_id, Message::Direct(direct_message))
        }
    }
}

impl Base for Node {
    fn crust_service(&self) -> &Service {
        &self.crust_service
    }

    fn full_id(&self) -> &FullId {
        &self.full_id
    }

    fn in_authority(&self, auth: &Authority<XorName>) -> bool {
        if let Authority::Client { ref client_key, .. } = *auth {
            client_key == self.full_id.public_id().signing_public_key()
        } else {
            self.is_proper() && self.peer_mgr.routing_table().in_authority(auth)
        }
    }

    fn handle_lost_peer(&mut self, peer_id: PeerId) -> Transition {
        if peer_id == self.crust_service.id() {
            error!("{:?} LostPeer fired with our crust peer id", self);
            return Transition::Stay;
        }

        debug!("{:?} Received LostPeer - {:?}", self, peer_id);

        self.dropped_tunnel_client(&peer_id);
        self.dropped_tunnel_node(&peer_id);

        if self.dropped_peer(&peer_id) {
            Transition::Stay
        } else {
            Transition::Terminate
        }
    }

    fn send_event(&self, event: Event) {
        let _ = self.event_sender.send(event);
    }

    fn stats(&mut self) -> &mut Stats {
        &mut self.stats
    }
}

#[cfg(feature = "use-mock-crust")]
impl Node {
    /// Routing table of this node.
    pub fn routing_table(&self) -> &RoutingTable<XorName> {
        self.peer_mgr.routing_table()
    }

    /// Resends all unacknowledged messages.
    pub fn resend_unacknowledged(&mut self) -> bool {
        let timer_tokens = self.ack_mgr.timer_tokens();
        for timer_token in &timer_tokens {
            self.resend_unacknowledged_timed_out_msgs(*timer_token);
        }
        !timer_tokens.is_empty()
    }

    /// Are there any unacknowledged messages?
    pub fn has_unacknowledged(&self) -> bool {
        self.ack_mgr.has_pending()
    }

    pub fn clear_state(&mut self) {
        self.ack_mgr.clear();
        self.peer_mgr.remove_connecting_peers();
        self.routing_msg_filter.clear();
    }

    pub fn set_next_node_name(&mut self, relocation_name: Option<XorName>) {
        self.next_node_name = relocation_name;
    }
}

impl Bootstrapped for Node {
    fn ack_mgr(&self) -> &AckManager {
        &self.ack_mgr
    }

    fn ack_mgr_mut(&mut self) -> &mut AckManager {
        &mut self.ack_mgr
    }

    fn min_group_size(&self) -> usize {
        self.peer_mgr.routing_table().min_group_size()
    }


    fn send_routing_message_via_route(&mut self,
                                      routing_msg: RoutingMessage,
                                      route: u8)
                                      -> Result<(), RoutingError> {
        if !self.in_authority(&routing_msg.src) {
            trace!("{:?} Not part of the source authority. Not sending message {:?}.",
                   self,
                   routing_msg);
            return Ok(());
        }
        let group_list = if routing_msg.src.is_multiple() {
            GroupList { pub_ids: self.hop_pub_ids(self.name())? }
        } else {
            GroupList { pub_ids: iter::once(*self.full_id().public_id()).collect() }
        };

        let mut signed_msg = SignedMessage::new(routing_msg, &self.full_id)?;
        signed_msg.add_group_list(group_list);
        if !self.add_to_pending_acks(&signed_msg, route) {
            debug!("{:?} already received an ack for {:?} - so not resending it.",
                   self,
                   signed_msg);
            return Ok(());
        }

        match self.get_signature_target(&signed_msg.routing_message().src, route) {
            None => Ok(()),
            Some(target_name) if target_name == *self.name() => {
                trace!("{:?} Starting message accumulation for {:?}", self, signed_msg);
                self.accumulate_message(signed_msg, route)
            }
            Some(target_name) => {
                if let Some(&peer_id) = self.peer_mgr.get_peer_id(&target_name) {
                    let direct_msg = {
                        let sign_key = self.full_id().signing_private_key();
                        signed_msg.routing_message().to_signature(sign_key)?
                    };
                    trace!("{:?} Sending signature for {:?} to {:?}",
                           self,
                           signed_msg,
                           target_name);
                    self.send_direct_msg_to_peer(direct_msg, peer_id, signed_msg.priority())
                } else {
                    Err(RoutingError::RoutingTable(RoutingTableError::NoSuchPeer))
                }
            }
        }
    }

    fn routing_msg_filter(&mut self) -> &mut RoutingMessageFilter {
        &mut self.routing_msg_filter
    }

    fn timer(&mut self) -> &mut Timer {
        &mut self.timer
    }
}

impl Debug for Node {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "Node({})", self.name())
    }
}

// Verify the serialised public id against the signature.
fn verify_signed_public_id(serialised_public_id: &[u8],
                           signature: &sign::Signature)
                           -> Result<PublicId, RoutingError> {
    let public_id: PublicId = serialisation::deserialise(serialised_public_id)?;
    let public_key = public_id.signing_public_key();
    if sign::verify_detached(signature, serialised_public_id, public_key) {
        Ok(public_id)
    } else {
        Err(RoutingError::FailedSignature)
    }
}
