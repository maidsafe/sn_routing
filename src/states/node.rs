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
use evented::{Evented, ToEvented};
use id::{FullId, PublicId};
use itertools::Itertools;
use log::LogLevel;
use maidsafe_utilities::serialisation;
use messages::{DEFAULT_PRIORITY, DirectMessage, HopMessage, MAX_PART_LEN, Message, MessageContent,
               RoutingMessage, SectionList, SignedMessage, UserMessage, UserMessageCache};
use peer_manager::{ConnectionInfoPreparedResult, PeerManager, PeerState,
                   RESOURCE_PROOF_DURATION_SECS, SectionMap};
use rand::{self, Rng};
use resource_proof::ResourceProof;
use routing_message_filter::{FilteringResult, RoutingMessageFilter};
use routing_table::{Authority, OtherMergeDetails, OwnMergeDetails, OwnMergeState, Prefix,
                    RemovalDetails, Xorable};
use routing_table::Error as RoutingTableError;
#[cfg(feature = "use-mock-crust")]
use routing_table::RoutingTable;
use rust_sodium::crypto::{box_, sign};
use rust_sodium::crypto::hash::sha256;
use section_list_cache::SectionListCache;
use signature_accumulator::{ACCUMULATION_TIMEOUT_SECS, SignatureAccumulator};
use state_machine::Transition;
use stats::Stats;
use std::{cmp, fmt, iter, mem};
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
#[cfg(feature = "use-mock-crust")]
use std::collections::BTreeMap;
use std::fmt::{Debug, Formatter};
use std::time::{Duration, Instant};
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
/// The number of required leading zero bits for the resource proof
const RESOURCE_PROOF_DIFFICULTY: u8 = 0;
/// The total size of the resource proof data.
const RESOURCE_PROOF_TARGET_SIZE: usize = 250 * 1024 * 1024;
/// Initial delay between a routing table change and sending a `RoutingTableRequest`, in seconds.
const RT_MIN_TIMEOUT_SECS: u64 = 30;
/// Maximal delay between two subsequent `RoutingTableRequest`s, in seconds.
const RT_MAX_TIMEOUT_SECS: u64 = 300;
/// Interval between displaying info about ongoing approval progress, in seconds.
const APPROVAL_PROGRESS_INTERVAL_SECS: u64 = 30;
/// Used to decide the `Event` sent on approval timing out.  If the percentage of
/// `ResourceProofResponse` parts delivered at timeout is below this value, the node will send
/// `Terminate`, otherwise it will send `RestartRequired`.
const APPROVAL_RETRY_THRESHOLD: usize = 95;

pub struct Node {
    ack_mgr: AckManager,
    cacheable_user_msg_cache: UserMessageCache,
    crust_service: Service,
    full_id: FullId,
    get_approval_timer_token: Option<u64>,
    approval_progress_timer_token: Option<u64>,
    approval_expiry_time: Instant,
    is_first_node: bool,
    is_approved: bool,
    /// The queue of routing messages addressed to us. These do not themselves need
    /// forwarding, although they may wrap a message which needs forwarding.
    msg_queue: VecDeque<RoutingMessage>,
    peer_mgr: PeerManager,
    response_cache: Box<Cache>,
    routing_msg_filter: RoutingMessageFilter,
    sig_accumulator: SignatureAccumulator,
    section_list_sigs: SectionListCache,
    stats: Stats,
    tick_timer_token: u64,
    timer: Timer,
    tunnels: Tunnels,
    user_msg_cache: UserMessageCache,
    /// Value which can be set in mock-crust tests to be used as the calculated name for the next
    /// relocation request received by this node.
    next_node_name: Option<XorName>,
    /// The message ID of the current `RoutingTableRequest` we sent to our section.
    rt_msg_id: Option<MessageId>,
    /// The current duration between `RoutingTableRequest`s we send. Doubles with every message.
    rt_timeout: Duration,
    /// The timer token for sending the next `RoutingTableRequest`.
    rt_timer_token: Option<u64>,
    /// `RoutingMessage`s affecting the routing table that arrived before `NodeApproval`.
    routing_msg_backlog: Vec<RoutingMessage>,
    /// The timer token for sending a `CandidateApproval` message.
    candidate_timer_token: Option<u64>,
    /// Map of ResourceProofResponse parts.
    resource_proof_response_parts: HashMap<PeerId, Vec<DirectMessage>>,
}

impl Node {
    pub fn first(cache: Box<Cache>,
                 crust_service: Service,
                 mut full_id: FullId,
                 min_section_size: usize,
                 timer: Timer)
                 -> Option<Self> {
        let name = XorName(sha256::hash(&full_id.public_id().name().0).0);
        full_id.public_id_mut().set_name(name);

        Self::new(cache,
                  crust_service,
                  true,
                  full_id,
                  min_section_size,
                  Stats::new(),
                  timer)
    }

    #[cfg_attr(feature = "cargo-clippy", allow(too_many_arguments))]
    pub fn from_bootstrapping(cache: Box<Cache>,
                              crust_service: Service,
                              full_id: FullId,
                              min_section_size: usize,
                              proxy_peer_id: PeerId,
                              proxy_public_id: PublicId,
                              stats: Stats,
                              timer: Timer)
                              -> Option<Self> {
        let mut node = Self::new(cache,
                                 crust_service,
                                 false,
                                 full_id,
                                 min_section_size,
                                 stats,
                                 timer);

        if let Some(ref mut node) = node {
            let _ = node.peer_mgr.set_proxy(proxy_peer_id, proxy_public_id);
        }

        node
    }

    #[cfg_attr(feature = "cargo-clippy", allow(too_many_arguments))]
    fn new(cache: Box<Cache>,
           crust_service: Service,
           first_node: bool,
           full_id: FullId,
           min_section_size: usize,
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
            full_id: full_id,
            get_approval_timer_token: None,
            approval_progress_timer_token: None,
            approval_expiry_time: Instant::now(),
            is_first_node: first_node,
            is_approved: first_node,
            msg_queue: VecDeque::new(),
            peer_mgr: PeerManager::new(min_section_size, public_id),
            response_cache: cache,
            routing_msg_filter: RoutingMessageFilter::new(),
            sig_accumulator: Default::default(),
            section_list_sigs: SectionListCache::new(),
            stats: stats,
            tick_timer_token: tick_timer_token,
            timer: timer,
            tunnels: Default::default(),
            user_msg_cache: UserMessageCache::with_expiry_duration(user_msg_cache_duration),
            next_node_name: None,
            rt_msg_id: None,
            rt_timeout: Duration::from_secs(RT_MIN_TIMEOUT_SECS),
            rt_timer_token: None,
            routing_msg_backlog: vec![],
            candidate_timer_token: None,
            resource_proof_response_parts: HashMap::new(),
        };

        if node.start_listening() {
            debug!("{:?} - State changed to node.", node);
            Some(node)
        } else {
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
            info!(target: "routing_stats", "{:?} - Indirect connections: {}, tunnelling for: {}",
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

    pub fn handle_action(&mut self, action: Action) -> Evented<Transition> {
        let mut events = Evented::empty();

        match action {
            Action::ClientSendRequest { result_tx, .. } => {
                let _ = result_tx.send(Err(InterfaceError::InvalidState));
            }
            Action::NodeSendMessage { src, dst, content, priority, result_tx } => {
                let result = match self.send_user_message(src, dst, content, priority) {
                    Err(RoutingError::Interface(err)) => Err(err),
                    Err(_) | Ok(()) => Ok(()),
                };

                let _ = result_tx.send(result);
            }
            Action::Name { result_tx } => {
                let _ = result_tx.send(*self.name());
            }
            Action::Timeout(token) => {
                if !self.handle_timeout(token).extract(&mut events) {
                    return events.with_value(Transition::Terminate);
                }
            }
            Action::Terminate => {
                return Transition::Terminate.to_evented();
            }
        }

        self.handle_routing_messages().extract(&mut events);
        self.update_stats();
        events.with_value(Transition::Stay)
    }

    pub fn handle_crust_event(&mut self, crust_event: CrustEvent) -> Evented<Transition> {
        let mut events = Evented::empty();

        match crust_event {
            CrustEvent::BootstrapAccept(peer_id) => self.handle_bootstrap_accept(peer_id),
            CrustEvent::BootstrapConnect(peer_id, _) => self.handle_bootstrap_connect(peer_id),
            CrustEvent::ConnectSuccess(peer_id) => self.handle_connect_success(peer_id),
            CrustEvent::ConnectFailure(peer_id) => self.handle_connect_failure(peer_id),
            CrustEvent::LostPeer(peer_id) => {
                if let Transition::Terminate = self.handle_lost_peer(peer_id).extract(&mut events) {
                    return events.with_value(Transition::Terminate);
                }
            }
            CrustEvent::NewMessage(peer_id, bytes) => {
                match self.handle_new_message(peer_id, bytes).extract(&mut events) {
                    Err(RoutingError::FilterCheckFailed) |
                    Ok(_) => (),
                    Err(err) => debug!("{:?} - {:?}", self, err),
                }
            }
            CrustEvent::ConnectionInfoPrepared(ConnectionInfoResult { result_token, result }) => {
                self.handle_connection_info_prepared(result_token, result)
            }
            CrustEvent::ListenerStarted(port) => {
                if let Transition::Terminate = self.handle_listener_started(port)
                    .extract(&mut events) {
                    return events.with_value(Transition::Terminate);
                }
            }
            CrustEvent::ListenerFailed => {
                error!("{:?} Failed to start listening.", self);
                events.add_event(Event::Terminate);
                return events.with_value(Transition::Terminate);
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

        self.handle_routing_messages().extract(&mut events);
        self.update_stats();
        events.with_value(Transition::Stay)
    }

    fn handle_routing_messages(&mut self) -> Evented<()> {
        let mut result = Evented::empty();

        while let Some(routing_msg) = self.msg_queue.pop_front() {
            if self.in_authority(&routing_msg.dst) {
                if let Err(err) = self.dispatch_routing_message(routing_msg).extract(&mut result) {
                    debug!("{:?} Routing message dispatch failed: {:?}", self, err);
                }
            }
        }

        result
    }

    fn handle_listener_started(&mut self, port: u16) -> Evented<Transition> {
        trace!("{:?} Listener started on port {}.", self, port);
        self.crust_service.set_service_discovery_listen(true);

        let mut result = Evented::empty();

        if self.is_first_node {
            info!("{:?} Started a new network as a seed node.", self);
            result.with_value(Transition::Stay)
        } else if let Err(error) = self.relocate() {
            error!("{:?} Failed to start relocation: {:?}", self, error);
            result.add_event(Event::RestartRequired);
            result.with_value(Transition::Terminate)
        } else {
            result.with_value(Transition::Stay)
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
        if let Some(tunnel_id) = self.tunnels.remove_tunnel_for(&peer_id) {
            debug!("{:?} Removing unwanted tunnel for {:?}", self, peer_id);
            let message = DirectMessage::TunnelDisconnect(peer_id);
            let _ = self.send_direct_message(tunnel_id, message);
        } else if let Some(pub_id) = self.peer_mgr.get_routing_peer(&peer_id) {
            warn!("{:?} Received ConnectSuccess from {:?}, but node {:?} is already in routing \
                   state in peer_map.",
                  self,
                  peer_id,
                  pub_id.name());
            return;
        }

        self.peer_mgr.connected_to(&peer_id);

        let id_type = if self.is_approved {
            "NodeIdentify"
        } else {
            "CandidateIdentify"
        };
        debug!("{:?} Received ConnectSuccess from {:?}. Sending {}.",
               self,
               peer_id,
               id_type);
        if self.send_node_identify(peer_id).is_err() {
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
            debug!("{:?} Failed to connect to peer {:?} with pub_id {:?}.",
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
            let _ = self.send_direct_message(dst_peer_id, tunnel_request);
        }
    }

    fn handle_new_message(&mut self,
                          peer_id: PeerId,
                          bytes: Vec<u8>)
                          -> Evented<Result<(), RoutingError>> {
        match serialisation::deserialise(&bytes) {
            Ok(Message::Hop(hop_msg)) => self.handle_hop_message(hop_msg, peer_id).to_evented(),
            Ok(Message::Direct(direct_msg)) => self.handle_direct_message(direct_msg, peer_id),
            Ok(Message::TunnelDirect { content, src, dst }) => {
                if dst == self.crust_service.id() &&
                   self.tunnels.tunnel_for(&src) == Some(&peer_id) {
                    self.handle_direct_message(content, src)
                } else if self.tunnels.has_clients(src, dst) {
                    self.send_or_drop(&dst, bytes, content.priority());
                    Ok(()).to_evented()
                } else if self.tunnels.accept_clients(src, dst) {
                    try_ev!(self.send_direct_message(dst, DirectMessage::TunnelSuccess(src)),
                            Evented::empty());
                    self.send_or_drop(&dst, bytes, content.priority());
                    Ok(()).to_evented()
                } else {
                    debug!("{:?} Invalid TunnelDirect message received via {:?}: {:?} -> {:?} \
                            {:?}",
                           self,
                           peer_id,
                           src,
                           dst,
                           content);
                    Err(RoutingError::InvalidDestination).to_evented()
                }
            }
            Ok(Message::TunnelHop { content, src, dst }) => {
                if dst == self.crust_service.id() &&
                   self.tunnels.tunnel_for(&src) == Some(&peer_id) {
                    self.handle_hop_message(content, src).to_evented()
                } else if self.tunnels.has_clients(src, dst) {
                    self.send_or_drop(&dst, bytes, content.content.priority());
                    Ok(()).to_evented()
                } else {
                    debug!("{:?} Invalid TunnelHop message received via {:?}: {:?} -> {:?} {:?}",
                           self,
                           peer_id,
                           src,
                           dst,
                           content);
                    Err(RoutingError::InvalidDestination).to_evented()
                }
            }
            Err(error) => Err(RoutingError::SerialisationError(error)).to_evented(),
        }
    }

    fn handle_direct_message(&mut self,
                             direct_message: DirectMessage,
                             peer_id: PeerId)
                             -> Evented<Result<(), RoutingError>> {
        use messages::DirectMessage::*;
        match direct_message {
            MessageSignature(digest, sig) => {
                self.handle_message_signature(digest, sig, peer_id).to_evented()
            }
            SectionListSignature(prefix, section_list, sig) => {
                self.handle_section_list_signature(peer_id, prefix, section_list, sig).to_evented()
            }
            ClientIdentify { ref serialised_public_id, ref signature, client_restriction } => {
                if let Ok(public_id) = verify_signed_public_id(serialised_public_id, signature) {
                    self.handle_client_identify(public_id, peer_id, client_restriction).to_evented()
                } else {
                    warn!("{:?} Signature check failed in ClientIdentify, so dropping connection \
                           {:?}.",
                          self,
                          peer_id);
                    self.disconnect_peer(&peer_id);
                    Ok(()).to_evented()
                }
            }
            NodeIdentify { ref serialised_public_id, ref signature } => {
                if let Ok(public_id) = verify_signed_public_id(serialised_public_id, signature) {
                    self.handle_node_identify(public_id, peer_id).map(Ok)
                } else {
                    warn!("{:?} Signature check failed in NodeIdentify, so dropping peer {:?}.",
                          self,
                          peer_id);
                    self.disconnect_peer(&peer_id);
                    Ok(()).to_evented()
                }
            }
            CandidateIdentify { ref serialised_public_id, ref signature } => {
                if let Ok(public_id) = verify_signed_public_id(serialised_public_id, signature) {
                    self.handle_candidate_identify(public_id, peer_id).map(Ok)
                } else {
                    warn!("{:?} Signature check failed in CandidateIdentify, so dropping peer \
                           {:?}.",
                          self,
                          peer_id);
                    self.disconnect_peer(&peer_id);
                    Ok(()).to_evented()
                }
            }
            TunnelRequest(dst_id) => self.handle_tunnel_request(peer_id, dst_id).to_evented(),
            TunnelSuccess(dst_id) => self.handle_tunnel_success(peer_id, dst_id).to_evented(),
            TunnelClosed(dst_id) => self.handle_tunnel_closed(peer_id, dst_id),
            TunnelDisconnect(dst_id) => self.handle_tunnel_disconnect(peer_id, dst_id).to_evented(),
            ResourceProof { seed, target_size, difficulty } => {
                self.handle_resource_proof_request(peer_id, seed, target_size, difficulty)
                    .to_evented()
            }
            ResourceProofResponseReceipt => {
                self.handle_resource_proof_response_receipt(peer_id);
                Ok(()).to_evented()
            }
            ResourceProofResponse { part_index, part_count, proof, leading_zero_bytes } => {
                self.handle_resource_proof_response(peer_id,
                                                    part_index,
                                                    part_count,
                                                    proof,
                                                    leading_zero_bytes);
                Ok(()).to_evented()
            }
            msg @ BootstrapIdentify { .. } |
            msg @ BootstrapDeny => {
                debug!("{:?} Unhandled direct message: {:?}", self, msg);
                Ok(()).to_evented()
            }
        }
    }

    fn handle_message_signature(&mut self,
                                digest: sha256::Digest,
                                sig: sign::Signature,
                                peer_id: PeerId)
                                -> Result<(), RoutingError> {
        if let Some(&pub_id) = self.peer_mgr.get_routing_peer(&peer_id) {
            let min_section_size = self.min_section_size();
            if let Some((signed_msg, route)) =
                self.sig_accumulator.add_signature(min_section_size, digest, sig, pub_id) {
                let hop = *self.name(); // we accumulated the message, so now we act as the last hop
                trace!("{:?} Message accumulated - handling: {:?}",
                       self,
                       signed_msg);
                return self.handle_signed_message(signed_msg, route, hop, &BTreeSet::new());
            }
        } else {
            warn!("{:?} Received message signature from unknown peer {:?}",
                  self,
                  peer_id);
        }
        Ok(())
    }

    fn get_section(&self, prefix: &Prefix<XorName>) -> Result<HashSet<XorName>, RoutingError> {
        let section = self.peer_mgr
            .routing_table()
            .get_section(&prefix.lower_bound())
            .ok_or(RoutingError::InvalidSource)?
            .iter()
            .cloned()
            .collect();
        Ok(section)
    }

    fn get_section_list(&self, prefix: &Prefix<XorName>) -> Result<SectionList, RoutingError> {
        Ok(SectionList::new(*prefix,
                            self.peer_mgr.get_pub_ids(&self.get_section(prefix)?)))
    }

    /// Sends a signature for the list of members of a section with prefix `prefix` to our whole
    /// section if `dst` is `None`, or to the given node if it is `Some(name)`
    fn send_section_list_signature(&mut self, prefix: Prefix<XorName>, dst: Option<XorName>) {
        let section = match self.get_section_list(&prefix) {
            Ok(section) => section,
            Err(err) => {
                warn!("{:?} Error getting section list for {:?}: {:?}",
                      self,
                      prefix,
                      err);
                return;
            }
        };
        let serialised = match serialisation::serialise(&section) {
            Ok(serialised) => serialised,
            Err(err) => {
                warn!("{:?} Error serialising section list for {:?}: {:?}",
                      self,
                      prefix,
                      err);
                return;
            }
        };
        let sig = sign::sign_detached(&serialised, self.full_id.signing_private_key());

        self.section_list_sigs.add_signature(prefix,
                                             *self.full_id.public_id(),
                                             section.clone(),
                                             sig,
                                             self.peer_mgr.routing_table().our_section().len());

        // this defines whom we are sending signature to: our section if dst is None, or given
        // name if it's Some
        let peers = if let Some(dst) = dst {
            self.peer_mgr.get_peer_id(&dst).into_iter().cloned().collect_vec()
        } else {
            self.peer_mgr
                .routing_table()
                .our_section()
                .into_iter()
                .filter(|&x| *x != *self.name())    // we don't want to send to ourselves
                .filter_map(|x| self.peer_mgr.get_peer_id(x))   // map names to peer ids
                .cloned()
                .collect_vec()
        };

        for peer_id in peers {
            let msg = DirectMessage::SectionListSignature(prefix, section.clone(), sig);
            if let Err(e) = self.send_direct_message(peer_id, msg) {
                warn!("{:?} Error sending section list signature for {:?} to {:?}: {:?}",
                      self,
                      prefix,
                      peer_id,
                      e);
            }
        }
    }

    fn handle_section_list_signature(&mut self,
                                     peer_id: PeerId,
                                     prefix: Prefix<XorName>,
                                     section_list: SectionList,
                                     sig: sign::Signature)
                                     -> Result<(), RoutingError> {
        let src_pub_id =
            self.peer_mgr.get_routing_peer(&peer_id).ok_or(RoutingError::InvalidSource)?;
        let serialised = serialisation::serialise(&section_list)?;
        if sign::verify_detached(&sig, &serialised, src_pub_id.signing_public_key()) {
            self.section_list_sigs
                .add_signature(prefix,
                               *src_pub_id,
                               section_list,
                               sig,
                               self.peer_mgr.routing_table().our_section().len());
            Ok(())
        } else {
            Err(RoutingError::FailedSignature)
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

    // Acknowledge reception of the message and broadcast to our section if necessary
    // The function is only called when we are in the destination authority
    fn ack_and_broadcast(&mut self,
                         signed_msg: &SignedMessage,
                         route: u8,
                         hop_name: XorName,
                         sent_to: &BTreeSet<XorName>) {
        self.send_ack(signed_msg.routing_message(), route);
        // If the destination is our section we need to forward it to the rest of the section
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
        signed_msg.check_integrity(self.min_section_size())?;

        match self.routing_msg_filter.filter_incoming(signed_msg.routing_message(), route) {
            FilteringResult::KnownMessageAndRoute => {
                debug!("{:?} Duplicate message received on route {}: {:?}",
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
                                -> Evented<Result<(), RoutingError>> {
        use messages::MessageContent::*;
        use Authority::{Client, ManagedNode, PrefixSection, Section};

        if !self.is_approved {
            match routing_msg.content {
                SectionSplit(..) |
                OwnSectionMerge { .. } |
                OtherSectionMerge { .. } |
                ExpectCandidate { .. } |
                AcceptAsCandidate { .. } |
                CandidateApproval { .. } |
                ConnectionInfoRequest { .. } |
                SectionUpdate { .. } |
                RoutingTableRequest(..) |
                RoutingTableResponse { .. } => {
                    trace!("{:?} Not approved yet. Delaying message handling: {:?}",
                           self,
                           routing_msg);
                    self.routing_msg_backlog.push(routing_msg);
                    return Ok(()).to_evented();
                }
                _ => (),
            }
        }

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
                    .to_evented()
            }
            (GetNodeNameResponse { relocated_id, section, .. }, Section(_), dst) => {
                self.handle_get_node_name_response(relocated_id, section, dst).map(Ok)
            }
            (ExpectCandidate { expect_id, client_auth, message_id }, Section(_), Section(_)) => {
                self.handle_expect_candidate(expect_id, client_auth, message_id).to_evented()
            }
            (AcceptAsCandidate { expect_id, client_auth, message_id }, Section(_), Section(_)) => {
                self.handle_accept_as_candidate(expect_id, client_auth, message_id)
                    .to_evented()
            }
            (ConnectionInfoRequest { encrypted_conn_info, nonce, pub_id, msg_id },
             src @ Client { .. },
             dst @ ManagedNode(_)) |
            (ConnectionInfoRequest { encrypted_conn_info, nonce, pub_id, msg_id },
             src @ ManagedNode(_),
             dst @ ManagedNode(_)) => {
                self.handle_connection_info_request(encrypted_conn_info,
                                                    nonce,
                                                    pub_id,
                                                    msg_id,
                                                    src,
                                                    dst)
            }
            (ConnectionInfoResponse { encrypted_conn_info, nonce, pub_id, msg_id },
             ManagedNode(src_name),
             dst @ Client { .. }) |
            (ConnectionInfoResponse { encrypted_conn_info, nonce, pub_id, msg_id },
             ManagedNode(src_name),
             dst @ ManagedNode(_)) => {
                self.handle_connection_info_response(encrypted_conn_info,
                                                     nonce,
                                                     pub_id,
                                                     msg_id,
                                                     src_name,
                                                     dst)
                    .to_evented()
            }
            (CandidateApproval { candidate_id, client_auth, sections }, Section(_), Section(_)) => {
                self.handle_candidate_approval(candidate_id, client_auth, sections)
            }
            (NodeApproval { sections }, Section(_), Client { .. }) => {
                self.handle_node_approval(&sections)
            }
            (SectionUpdate { prefix, members }, Section(_), PrefixSection(_)) => {
                self.handle_section_update(prefix, members)
            }
            (RoutingTableRequest(msg_id, digest), src @ ManagedNode(_), dst @ PrefixSection(_)) => {
                self.handle_rt_req(msg_id, digest, src, dst).to_evented()
            }
            (RoutingTableResponse { prefix, members, message_id },
             PrefixSection(_),
             ManagedNode(_)) => self.handle_rt_rsp(prefix, members, message_id),
            (SectionSplit(prefix, joining_node), _, _) => {
                self.handle_section_split(prefix, joining_node)
            }
            (OwnSectionMerge { sender_prefix, merge_prefix, sections }, _, _) => {
                self.handle_own_section_merge(sender_prefix, merge_prefix, sections)
            }
            (OtherSectionMerge { prefix, section }, _, _) => {
                self.handle_other_section_merge(prefix, section)
            }
            (Ack(ack, _), _, _) => self.handle_ack_response(ack).to_evented(),
            (UserMessagePart { hash, part_count, part_index, payload, .. }, src, dst) => {
                if let Some(msg) = self.user_msg_cache.add(hash, part_count, part_index, payload) {
                    self.stats().count_user_message(&msg);
                    Evented::single(msg.into_event(src, dst), Ok(()))
                } else {
                    Ok(()).to_evented()
                }
            }
            (content, src, dst) => {
                debug!("{:?} Unhandled routing message {:?} from {:?} to {:?}",
                       self,
                       content,
                       src,
                       dst);
                Err(RoutingError::BadAuthority).to_evented()
            }
        }
    }

    fn handle_candidate_approval(&mut self,
                                 candidate_id: PublicId,
                                 client_auth: Authority<XorName>,
                                 sections: SectionMap)
                                 -> Evented<Result<(), RoutingError>> {
        for peer_id in self.peer_mgr.remove_expired_candidates() {
            self.disconnect_peer(&peer_id);
        }

        let mut result = Evented::empty();
        // Once the joining node joined, it may receive the vote regarding itself.
        // Or a node may receive CandidateApproval before connection established.
        let opt_peer_id = match self.peer_mgr
            .handle_candidate_approval(*candidate_id.name(), client_auth) {
            Ok(peer_id) => Some(peer_id),
            Err(_) => {
                let src = Authority::ManagedNode(*self.name());
                if let Err(error) =
                    self.send_connection_info_request(candidate_id, src, client_auth)
                        .extract(&mut result) {
                    debug!("{:?} - Failed to send connection info to {:?}: {:?}",
                           self,
                           candidate_id,
                           error);
                }
                None
            }
        };

        debug!("{:?} Sending NodeApproval to {}.",
               self,
               candidate_id.name());
        if let Err(error) = self.send_routing_message(RoutingMessage {
            src: Authority::Section(*candidate_id.name()),
            dst: client_auth,
            content: MessageContent::NodeApproval { sections: sections },
        }) {
            debug!("{:?} Failed sending NodeApproval to {}: {:?}",
                   self,
                   candidate_id.name(),
                   error);
        }

        if let Some(peer_id) = opt_peer_id {
            self.add_to_routing_table(&candidate_id, &peer_id).extract(&mut result);
        }
        result.map(Ok)
    }

    fn handle_node_approval(&mut self, sections: &SectionMap) -> Evented<Result<(), RoutingError>> {
        let mut events = Evented::empty();
        if self.is_approved {
            warn!("{:?} Received duplicate NodeApproval.", self);
            return events.with_value(Ok(()));
        }

        self.get_approval_timer_token = None;
        self.approval_progress_timer_token = None;
        if let Err(error) = self.peer_mgr.add_prefixes(sections.keys().cloned().collect()) {
            info!("{:?} Received invalid prefixes in NodeApproval: {:?}. Restarting.",
                  self,
                  error);
            events.add_event(Event::RestartRequired);
            return events.with_value(Err(error));
        }

        let our_prefix = *self.peer_mgr.routing_table().our_prefix();
        self.send_section_list_signature(our_prefix, None);

        for section in sections.values() {
            for pub_id in section.iter() {
                if !self.peer_mgr.routing_table().has(pub_id.name()) {
                    self.peer_mgr.expect_peer(pub_id);
                    debug!("{:?} Sending connection info to {:?} on NodeApproval.",
                           self,
                           pub_id);
                    let src = Authority::ManagedNode(*self.name());
                    let node_auth = Authority::ManagedNode(*pub_id.name());
                    if let Err(error) = self.send_connection_info_request(*pub_id, src, node_auth)
                        .extract(&mut events) {
                        debug!("{:?} - Failed to send connection info to {:?}: {:?}",
                               self,
                               pub_id,
                               error);
                    }
                }
            }
        }

        info!("{:?} Node approval completed. Prefixes: {:?}",
              self,
              self.peer_mgr.routing_table().prefixes());
        events.add_event(Event::Connected);
        for name in self.peer_mgr.routing_table().iter() {
            // TODO: try to remove this as safe_core/safe_vault may not require this notification
            events.add_event(Event::NodeAdded(*name, self.peer_mgr.routing_table().clone()));
        }
        self.is_approved = true;
        let backlog = mem::replace(&mut self.routing_msg_backlog, vec![]);
        backlog.into_iter().rev().foreach(|msg| self.msg_queue.push_front(msg));
        self.resource_proof_response_parts.clear();
        self.reset_rt_timer();
        events.with_value(Ok(()))
    }

    fn handle_resource_proof_request(&mut self,
                                     peer_id: PeerId,
                                     seed: Vec<u8>,
                                     target_size: usize,
                                     difficulty: u8)
                                     -> Result<(), RoutingError> {
        if self.resource_proof_response_parts.is_empty() {
            info!("{:?} Starting approval process to test this node's resources. This will take \
                   at least {} seconds.",
                  self,
                  RESOURCE_PROOF_DURATION_SECS);
        }
        let start = Instant::now();
        let rp_object = ResourceProof::new(target_size, difficulty);
        let mut proof = rp_object.create_proof_data(&seed);
        let leading_zero_bytes = rp_object.create_proof(&mut proof);
        let elapsed = start.elapsed();
        let parts = proof.into_iter()
            .chunks(MAX_PART_LEN)
            .into_iter()
            .map(|chunk| chunk.collect_vec())
            .collect_vec();
        let part_count = parts.len();
        let mut messages = parts.into_iter()
            .enumerate()
            .rev()
            .map(|(part_index, part)| {
                DirectMessage::ResourceProofResponse {
                    part_index: part_index,
                    part_count: part_count,
                    proof: part,
                    leading_zero_bytes: leading_zero_bytes,
                }
            })
            .collect_vec();
        let first_message = match messages.pop() {
            Some(message) => message,
            None => {
                DirectMessage::ResourceProofResponse {
                    part_index: 0,
                    part_count: 1,
                    proof: vec![],
                    leading_zero_bytes: leading_zero_bytes,
                }
            }
        };
        let _ = self.resource_proof_response_parts.insert(peer_id, messages);
        self.send_direct_message(peer_id, first_message)?;
        trace!("{:?} created proof data in {}.  Min section size: {}, Target size: {}, \
                Difficulty: {}, Seed: {:?}",
               self,
               Self::format(elapsed),
               self.min_section_size(),
               target_size,
               difficulty,
               seed);
        Ok(())
    }

    fn handle_resource_proof_response_receipt(&mut self, peer_id: PeerId) {
        let popped_message =
            self.resource_proof_response_parts.get_mut(&peer_id).and_then(Vec::pop);
        if let Some(message) = popped_message {
            if let Err(error) = self.send_direct_message(peer_id, message) {
                debug!("{:?} Failed to send ResourceProofResponse to {:?}: {:?}",
                       self,
                       peer_id,
                       error);
            }
        }
    }

    fn handle_resource_proof_response(&mut self,
                                      peer_id: PeerId,
                                      part_index: usize,
                                      part_count: usize,
                                      proof: Vec<u8>,
                                      leading_zero_bytes: u64) {
        if self.candidate_timer_token.is_none() {
            debug!("{:?} Won't handle resource proof response from {:?} - not currently waiting.",
                   self,
                   peer_id);
            return;
        }

        let name = if let Some(name) = self.peer_mgr.get_peer_name(&peer_id) {
            *name
        } else {
            debug!("{:?} Failed to get peer name while handling resource proof response from {:?}",
                   self,
                   peer_id);
            return;
        };

        match self.peer_mgr
            .verify_candidate(&name, part_index, part_count, proof, leading_zero_bytes) {
            Err(error) => {
                debug!("{:?} Failed to verify candidate {}: {:?}",
                       self,
                       name,
                       error);
                self.candidate_timer_token = None;
            }
            Ok(None) => {
                debug!("{:?} Candidate {} sent part {}/{}.",
                       self,
                       name,
                       part_index + 1,
                       part_count);
                let _ =
                    self.send_direct_message(peer_id, DirectMessage::ResourceProofResponseReceipt);
            }
            Ok(Some((target_size, difficulty, elapsed))) if difficulty == 0 &&
                                                            target_size < 1000 => {
                // Small tests don't require waiting for synchronisation. Send approval now.
                debug!("{:?} Candidate {} passed our challenge in {}.  Sending CandidateApproval.",
                       self,
                       name,
                       Self::format(elapsed));
                self.candidate_timer_token = None;
                let _ = self.send_candidate_approval();
            }
            Ok(Some((_, _, elapsed))) => {
                debug!("{:?} Candidate {} passed our challenge in {}.  Waiting to send \
                        CandidateApproval.",
                       self,
                       name,
                       Self::format(elapsed));
            }
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
                        let msg = UserMessage::Response(response);

                        self.send_ack_from(routing_msg, route, src);
                        self.send_user_message(src, dst, msg, priority)?;

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
        self.get_approval_timer_token = Some(self.timer.schedule(duration));

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

        info!("{:?} Requesting a relocated name from the network. This can take a while.",
              self);

        self.send_routing_message(request_msg)
    }

    fn send_bootstrap_identify(&mut self, peer_id: PeerId) -> Result<(), RoutingError> {
        let direct_message =
            DirectMessage::BootstrapIdentify { public_id: *self.full_id.public_id() };
        self.send_direct_message(peer_id, direct_message)
    }

    fn handle_client_identify(&mut self,
                              public_id: PublicId,
                              peer_id: PeerId,
                              client_restriction: bool)
                              -> Result<(), RoutingError> {
        if !client_restriction && !self.crust_service.is_peer_whitelisted(&peer_id) {
            warn!("{:?} Client is not whitelisted, so dropping connection.",
                  self);
            self.disconnect_peer(&peer_id);
            return Ok(());
        }
        if *public_id.name() != XorName(sha256::hash(&public_id.signing_public_key().0).0) {
            warn!("{:?} Incoming connection not validated as a proper client, so dropping it.",
                  self);
            self.disconnect_peer(&peer_id);
            return Ok(());
        }

        for peer_id in self.peer_mgr.remove_expired_joining_nodes() {
            debug!("{:?} Removing stale joining node with peer ID {:?}",
                   self,
                   peer_id);
            self.disconnect_peer(&peer_id);
        }

        if (client_restriction || !self.is_first_node) &&
           self.peer_mgr.routing_table().len() < self.min_section_size() - 1 {
            debug!("{:?} Client {:?} rejected: Routing table has {} entries. {} required.",
                   self,
                   public_id.name(),
                   self.peer_mgr.routing_table().len(),
                   self.min_section_size() - 1);
            return self.send_direct_message(peer_id, DirectMessage::BootstrapDeny);
        }

        let non_unique = if client_restriction {
            self.peer_mgr.insert_client(peer_id, public_id)
        } else {
            self.peer_mgr.insert_joining_node(peer_id, public_id)
        };

        if non_unique {
            debug!("{:?} Received two ClientInfo messages from the same peer ID {:?}.",
                   self,
                   peer_id);
        }

        debug!("{:?} Accepted client {:?}.", self, public_id.name());

        self.send_bootstrap_identify(peer_id)
    }

    fn handle_node_identify(&mut self, public_id: PublicId, peer_id: PeerId) -> Evented<()> {
        let mut result = Evented::empty();
        debug!("{:?} Handling NodeIdentify from {:?}.",
               self,
               public_id.name());
        self.add_to_routing_table(&public_id, &peer_id).extract(&mut result);

        if let Some(prefix) = self.peer_mgr.routing_table().find_section_prefix(public_id.name()) {
            self.send_section_list_signature(prefix, None);
            if prefix == *self.peer_mgr.routing_table().our_prefix() {
                // if the node joined our section, send signatures for all section lists to it
                for pfx in self.peer_mgr.routing_table().prefixes() {
                    self.send_section_list_signature(pfx, Some(*public_id.name()));
                }
            }
        }
        result
    }

    fn handle_candidate_identify(&mut self, public_id: PublicId, peer_id: PeerId) -> Evented<()> {
        let mut result = Evented::empty();
        let name = public_id.name();
        debug!("{:?} Handling CandidateIdentify from {:?}.", self, name);
        let (difficulty, target_size) = if self.crust_service.is_peer_hard_coded(&peer_id) ||
                                           self.peer_mgr.get_joining_node(&peer_id).is_some() {
            (0, 1)
        } else {
            (RESOURCE_PROOF_DIFFICULTY,
             RESOURCE_PROOF_TARGET_SIZE / (self.peer_mgr.routing_table().our_section().len() + 1))
        };
        let seed: Vec<u8> = if cfg!(feature = "use-mock-crust") {
            vec![5u8; 4]
        } else {
            rand::thread_rng().gen_iter().take(10).collect()
        };
        match self.peer_mgr.handle_candidate_identify(&public_id,
                                                      &peer_id,
                                                      target_size,
                                                      difficulty,
                                                      seed.clone()) {
            Ok(true) => {
                let direct_message = DirectMessage::ResourceProof {
                    seed: seed,
                    target_size: target_size,
                    difficulty: difficulty,
                };
                if let Err(error) = self.send_direct_message(peer_id, direct_message) {
                    debug!("{:?} failed requesting resource_proof from node candidate {:?}/{:?}.",
                           self,
                           name,
                           error);
                }
            }
            Ok(false) => {
                self.add_to_routing_table(&public_id, &peer_id).extract(&mut result);
            }
            Err(error) => {
                debug!("{:?} failed to handle CandidateIdentify from {:?}: {:?} - disconnecting",
                       self,
                       name,
                       error);
                self.disconnect_peer(&peer_id);
            }
        }
        result
    }

    fn add_to_routing_table(&mut self, public_id: &PublicId, peer_id: &PeerId) -> Evented<()> {
        let mut result = Evented::empty();
        match self.peer_mgr.add_to_routing_table(public_id, peer_id) {
            Err(RoutingTableError::AlreadyExists) => return Evented::empty(),  // already in RT
            Err(error) => {
                debug!("{:?} Peer {:?} was not added to the routing table: {}",
                       self,
                       peer_id,
                       error);
                self.disconnect_peer(peer_id);
                return result;
            }
            Ok(true) => {
                // i.e. the section should split
                let our_prefix = *self.peer_mgr.routing_table().our_prefix();
                // In the future we'll look to remove this restriction so we always call
                // `send_section_split()` here and also check whether another round of splitting is
                // required in `handle_section_split()` so splitting becomes recursive like merging.
                if our_prefix.matches(public_id.name()) {
                    self.send_section_split(our_prefix, *public_id.name());
                }
            }
            Ok(false) => {
                self.merge_if_necessary();
            }
        }

        if self.peer_mgr.routing_table().our_section().contains(public_id.name()) {
            self.reset_rt_timer();
        }

        debug!("{:?} Added {:?} to routing table.", self, public_id.name());
        if self.is_first_node && self.peer_mgr.routing_table().len() == 1 {
            trace!("{:?} Node approval completed. Prefixes: {:?}",
                   self,
                   self.peer_mgr.routing_table().prefixes());
            result.add_event(Event::Connected);
        }

        if self.is_approved {
            result.add_event(Event::NodeAdded(*public_id.name(),
                                              self.peer_mgr.routing_table().clone()));
        }

        // TODO: we probably don't need to send this if we're splitting, but in that case
        // we should send something else instead. This will do for now.
        self.send_section_update();

        for dst_id in self.peer_mgr.peers_needing_tunnel() {
            trace!("{:?} Asking {:?} to serve as a tunnel for {:?}",
                   self,
                   peer_id,
                   dst_id);
            let tunnel_request = DirectMessage::TunnelRequest(dst_id);
            let _ = self.send_direct_message(*peer_id, tunnel_request);
        }

        if let Some(prefix) = self.peer_mgr.routing_table().find_section_prefix(public_id.name()) {
            self.send_section_list_signature(prefix, None);
            if prefix == *self.peer_mgr.routing_table().our_prefix() {
                // if the node joined our section, send signatures for all section lists to it
                for pfx in self.peer_mgr.routing_table().prefixes() {
                    self.send_section_list_signature(pfx, Some(*public_id.name()));
                }
            }
        }

        result
    }

    // Tell all neighbouring sections that our member list changed.
    // Currently we only send this when nodes join and it's only used to add missing members.
    fn send_section_update(&mut self) {
        if !self.peer_mgr.routing_table().is_valid() {
            trace!("{:?} Not sending section update since RT invariant not held.",
                   self);
            return;
        }
        trace!("{:?} Sending section update", self);
        let members = self.peer_mgr.get_pub_ids(self.peer_mgr.routing_table().our_section());

        let content = MessageContent::SectionUpdate {
            prefix: *self.peer_mgr.routing_table().our_prefix(),
            members: members,
        };

        let neighbours = self.peer_mgr.routing_table().other_prefixes();
        for neighbour_pfx in neighbours {
            let request_msg = RoutingMessage {
                src: Authority::Section(self.peer_mgr
                    .routing_table()
                    .our_prefix()
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

    // If `msg_id` is `Some` this is sent as a response, otherwise as a request.
    fn send_connection_info(&mut self,
                            our_pub_info: PubConnectionInfo,
                            their_pub_id: PublicId,
                            src: Authority<XorName>,
                            dst: Authority<XorName>,
                            msg_id: Option<MessageId>) {
        let encoded_connection_info = match serialisation::serialise(&our_pub_info) {
            Ok(encoded_connection_info) => encoded_connection_info,
            Err(err) => {
                debug!("{:?} Failed to serialise connection info for {:?}: {:?}.",
                       self,
                       their_pub_id.name(),
                       err);
                return;
            }
        };
        let nonce = box_::gen_nonce();
        let encrypted_conn_info = box_::seal(&encoded_connection_info,
                                             &nonce,
                                             their_pub_id.encrypting_public_key(),
                                             self.full_id().encrypting_private_key());
        let msg_content = if let Some(msg_id) = msg_id {
            MessageContent::ConnectionInfoResponse {
                encrypted_conn_info: encrypted_conn_info,
                nonce: nonce.0,
                pub_id: *self.full_id().public_id(),
                msg_id: msg_id,
            }
        } else {
            MessageContent::ConnectionInfoRequest {
                encrypted_conn_info: encrypted_conn_info,
                nonce: nonce.0,
                pub_id: *self.full_id().public_id(),
                msg_id: MessageId::new(),
            }
        };

        let msg = RoutingMessage {
            src: src,
            dst: dst,
            content: msg_content,
        };

        if let Err(err) = self.send_routing_message(msg) {
            debug!("{:?} Failed to send connection info for {:?}: {:?}.",
                   self,
                   their_pub_id.name(),
                   err);
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

        let our_pub_info = our_connection_info.to_pub_connection_info();
        match self.peer_mgr.connection_info_prepared(result_token, our_connection_info) {
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
                        self.send_connection_info(our_pub_info, pub_id, src, dst, None);
                    }
                    Some((our_info, their_info, msg_id)) => {
                        debug!("{:?} Trying to connect to {:?} as {:?}.",
                               self,
                               their_info.id(),
                               pub_id.name());
                        self.send_connection_info(our_pub_info, pub_id, src, dst, Some(msg_id));
                        let _ = self.crust_service.connect(our_info, their_info);
                    }
                }
            }
        }
    }

    fn handle_connection_info_request(&mut self,
                                      encrypted_connection_info: Vec<u8>,
                                      nonce_bytes: [u8; box_::NONCEBYTES],
                                      public_id: PublicId,
                                      message_id: MessageId,
                                      src: Authority<XorName>,
                                      dst: Authority<XorName>)
                                      -> Evented<Result<(), RoutingError>> {
        let mut result = Evented::empty();
        let name = match src {
            Authority::Client { .. } => public_id.name(),
            Authority::ManagedNode(ref name) => name,
            _ => unreachable!(),
        };
        try_ev!(self.peer_mgr.allow_connect(name), result);
        let their_connection_info = try_ev!(self.decrypt_connection_info(&encrypted_connection_info,
                                                 &box_::Nonce(nonce_bytes),
                                                 &public_id),
                    result);
        let peer_id = their_connection_info.id();
        use peer_manager::ConnectionInfoReceivedResult::*;
        match self.peer_mgr
            .connection_info_received(src, dst, public_id, their_connection_info, message_id) {
            Ok(Ready(our_info, their_info)) => {
                debug!("{:?} Already sent a connection info request to {:?} ({:?}); resending \
                        our same details as a response.",
                       self,
                       public_id.name(),
                       peer_id);
                self.send_connection_info(our_info.to_pub_connection_info(),
                                          public_id,
                                          dst,
                                          src,
                                          Some(message_id));
                if let Err(error) = self.crust_service.connect(our_info, their_info) {
                    trace!("{:?} Unable to connect to {:?} - {:?}", self, src, error);
                }
            }
            Ok(Prepare(token)) => {
                self.crust_service.prepare_connection_info(token);
            }
            Ok(IsProxy) |
            Ok(IsClient) |
            Ok(IsJoiningNode) => {
                try_ev!(self.send_node_identify(peer_id), result);
                self.handle_node_identify(public_id, peer_id).extract(&mut result);
            }
            Ok(Waiting) | Ok(IsConnected) => (),
            Err(error) => {
                warn!("{:?} Failed to insert connection info from {:?} ({:?}): {:?}",
                      self,
                      public_id.name(),
                      peer_id,
                      error)
            }
        }
        result.with_value(Ok(()))
    }

    fn handle_connection_info_response(&mut self,
                                       encrypted_connection_info: Vec<u8>,
                                       nonce_bytes: [u8; box_::NONCEBYTES],
                                       public_id: PublicId,
                                       message_id: MessageId,
                                       src: XorName,
                                       dst: Authority<XorName>)
                                       -> Result<(), RoutingError> {
        self.peer_mgr.allow_connect(&src)?;
        let their_connection_info = self.decrypt_connection_info(&encrypted_connection_info,
                                     &box_::Nonce(nonce_bytes),
                                     &public_id)?;
        let peer_id = their_connection_info.id();
        use peer_manager::ConnectionInfoReceivedResult::*;
        match self.peer_mgr
            .connection_info_received(Authority::ManagedNode(src),
                                      dst,
                                      public_id,
                                      their_connection_info,
                                      message_id) {
            Ok(Ready(our_info, their_info)) => {
                trace!("{:?} Received connection info response. Trying to connect to {:?} ({:?}).",
                       self,
                       public_id.name(),
                       peer_id);
                if let Err(error) = self.crust_service.connect(our_info, their_info) {
                    debug!("{:?} Crust failed initiating a connection to  {:?} ({:?}): {:?}",
                           self,
                           public_id.name(),
                           peer_id,
                           error);
                }
            }
            Ok(Prepare(_)) |
            Ok(IsProxy) |
            Ok(IsClient) |
            Ok(IsJoiningNode) => {
                debug!("{:?} Received connection info response from {:?} ({:?}) when we haven't \
                      sent a corresponding request",
                       self,
                       public_id.name(),
                       peer_id);
            }
            Ok(Waiting) | Ok(IsConnected) => (),
            Err(error) => {
                warn!("{:?} Failed to insert connection info from {:?} ({:?}): {:?}",
                      self,
                      public_id.name(),
                      peer_id,
                      error)
            }
        }
        Ok(())
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
                return self.send_direct_message(id0, DirectMessage::TunnelSuccess(id1));
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
            return self.send_direct_message(peer_id, message);
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
                            -> Evented<Result<(), RoutingError>> {
        let mut result = Evented::empty();
        if self.tunnels.remove(dst_id, peer_id) {
            debug!("{:?} Tunnel to {:?} via {:?} closed.",
                   self,
                   dst_id,
                   peer_id);
            if !self.crust_service.is_connected(&dst_id) {
                self.dropped_peer(&dst_id).extract(&mut result);
            }
        }
        result.with_value(Ok(()))
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
            self.send_direct_message(dst_id, DirectMessage::TunnelClosed(peer_id))
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
            let _ = self.send_direct_message(tunnel_id, message);
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
        let section_matching_client_name = XorName(hashed_key.0);

        // Validate Client (relocating node) has contacted the correct Section-X
        if section_matching_client_name != dst_name {
            return Err(RoutingError::InvalidDestination);
        }

        let close_section = match self.peer_mgr.routing_table().close_names(&dst_name) {
            Some(close_section) => close_section.into_iter().collect(),
            None => return Err(RoutingError::InvalidDestination),
        };
        let relocated_name = self.next_node_name.take().unwrap_or_else(|| {
            utils::calculate_relocated_name(close_section, their_public_id.name())
        });
        their_public_id.set_name(relocated_name);

        // From X -> Y; Send to close section of the relocated name
        let request_content = MessageContent::ExpectCandidate {
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

    // Context: we're a new node joining a section. This message should have been sent by each node
    // in the target section with the new node name and the section for resource proving.
    fn handle_get_node_name_response(&mut self,
                                     relocated_id: PublicId,
                                     section: BTreeSet<PublicId>,
                                     dst: Authority<XorName>)
                                     -> Evented<()> {
        if !self.peer_mgr.routing_table().is_empty() {
            warn!("{:?} Received duplicate GetNodeName response.", self);
            return Evented::empty();
        }

        let duration = Duration::from_secs(RESOURCE_PROOF_DURATION_SECS +
                                           ACCUMULATION_TIMEOUT_SECS);
        self.approval_expiry_time = Instant::now() + duration;
        self.get_approval_timer_token = Some(self.timer.schedule(duration));
        self.approval_progress_timer_token = Some(self.timer
            .schedule(Duration::from_secs(APPROVAL_PROGRESS_INTERVAL_SECS)));

        self.full_id.public_id_mut().set_name(*relocated_id.name());
        self.peer_mgr.reset_routing_table(*self.full_id.public_id());
        trace!("{:?} GetNodeName completed. Prefixes: {:?}",
               self,
               self.peer_mgr.routing_table().prefixes());
        info!("{:?} Received relocated name. Establishing connections to {} peers.",
              self,
              section.len());
        let mut result = Evented::empty();

        for pub_id in &section {
            debug!("{:?} Sending connection info to {:?} on GetNodeName response.",
                   self,
                   pub_id);
            let node_auth = Authority::ManagedNode(*pub_id.name());
            if let Err(error) = self.send_connection_info_request(*pub_id, dst, node_auth)
                .extract(&mut result) {
                debug!("{:?} - Failed to send connection info to {:?}: {:?}",
                       self,
                       pub_id,
                       error);
            }
        }
        result
    }

    // Received by Y; From X -> Y
    // Context: a node is joining our section. Sends `AcceptAsCandidate` to our section.
    fn handle_expect_candidate(&mut self,
                               candidate_id: PublicId,
                               client_auth: Authority<XorName>,
                               message_id: MessageId)
                               -> Result<(), RoutingError> {
        for peer_id in self.peer_mgr.remove_expired_candidates() {
            self.disconnect_peer(&peer_id);
        }

        if candidate_id == *self.full_id.public_id() {
            // If we're the joining node: stop
            return Ok(());
        }

        // TODO - do we need to reply if `candidate_id` triggers a failure here?
        self.peer_mgr.expect_candidate(*candidate_id.name(), client_auth)?;
        let response_content = MessageContent::AcceptAsCandidate {
            expect_id: candidate_id,
            client_auth: client_auth,
            message_id: message_id,
        };
        trace!("{:?} Responding to section {:?}.", self, response_content);
        self.send_routing_message(RoutingMessage {
            src: Authority::Section(*candidate_id.name()),
            dst: Authority::Section(*candidate_id.name()),
            content: response_content,
        })
    }

    // Received by Y; From Y -> Y
    // Context: a node is joining our section. Sends the node our section.
    fn handle_accept_as_candidate(&mut self,
                                  candidate_id: PublicId,
                                  client_auth: Authority<XorName>,
                                  message_id: MessageId)
                                  -> Result<(), RoutingError> {
        for peer_id in self.peer_mgr.remove_expired_candidates() {
            self.disconnect_peer(&peer_id);
        }

        if candidate_id == *self.full_id.public_id() {
            // If we're the joining node: stop
            return Ok(());
        }

        self.candidate_timer_token = Some(self.timer
            .schedule(Duration::from_secs(RESOURCE_PROOF_DURATION_SECS)));

        let own_section = self.peer_mgr.accept_as_candidate(*candidate_id.name(), client_auth)?;
        let response_content = MessageContent::GetNodeNameResponse {
            relocated_id: candidate_id,
            section: own_section,
            message_id: message_id,
        };
        trace!("{:?} Responding to candidate {:?}: {:?}.",
               self,
               client_auth,
               response_content);
        self.send_routing_message(RoutingMessage {
            src: Authority::Section(*candidate_id.name()),
            dst: client_auth,
            content: response_content,
        })
    }

    fn handle_section_update(&mut self,
                             prefix: Prefix<XorName>,
                             members: BTreeSet<PublicId>)
                             -> Evented<Result<(), RoutingError>> {
        let mut result = Evented::empty();
        trace!("{:?} Got section update for {:?}", self, prefix);

        // Perform splits that we missed, according to the section update.
        // TODO: This is a temporary fix and it shouldn't be necessary anymore once the new message
        //       flow for joining nodes is in place and we send the routing table to the new node
        //       at the point where it gets added to the section.
        let pfx_name = prefix.lower_bound();
        while let Some(rt_pfx) = self.peer_mgr.routing_table().find_section_prefix(&pfx_name) {
            if rt_pfx.bit_count() >= prefix.bit_count() {
                break;
            }
            debug!("{:?} Splitting {:?} on section update.", self, rt_pfx);
            let _ = self.handle_section_split(rt_pfx, rt_pfx.lower_bound());
        }
        // Filter list of members to just those we don't know about:
        let members =
            if let Some(section) = self.peer_mgr.routing_table().section_with_prefix(&prefix) {
                let f = |id: &PublicId| !section.contains(id.name());
                members.into_iter().filter(f).collect_vec()
            } else {
                warn!("{:?} Section update received from unknown neighbour {:?}",
                      self,
                      prefix);
                return Ok(()).to_evented();
            };
        let members = members.into_iter()
            .filter(|id: &PublicId| !self.peer_mgr.is_expected(id.name()))
            .collect_vec();

        let own_name = *self.name();
        for pub_id in members {
            self.peer_mgr.expect_peer(&pub_id);
            if let Err(error) = self.send_connection_info_request(pub_id,
                                              Authority::ManagedNode(own_name),
                                              Authority::ManagedNode(*pub_id.name()))
                .extract(&mut result) {
                debug!("{:?} - Failed to send connection info to {:?}: {:?}",
                       self,
                       pub_id,
                       error);
            }
        }
        result.with_value(Ok(()))
    }

    fn handle_rt_req(&mut self,
                     msg_id: MessageId,
                     digest: sha256::Digest,
                     src: Authority<XorName>,
                     dst: Authority<XorName>)
                     -> Result<(), RoutingError> {
        let sections = self.peer_mgr.pub_ids_by_section();
        let serialised_sections = serialisation::serialise(&sections)?;
        if digest == sha256::hash(&serialised_sections) {
            return Ok(());
        }
        for (prefix, members) in sections {
            let content = MessageContent::RoutingTableResponse {
                message_id: msg_id,
                prefix: prefix,
                members: members,
            };
            let request_msg = RoutingMessage {
                src: dst,
                dst: src,
                content: content,
            };
            if let Err(err) = self.send_routing_message(request_msg) {
                debug!("{:?} Failed to send RoutingTableResponse: {:?}.", self, err);
            }
        }
        Ok(())
    }

    fn handle_rt_rsp(&mut self,
                     prefix: Prefix<XorName>,
                     members: BTreeSet<PublicId>,
                     message_id: MessageId)
                     -> Evented<Result<(), RoutingError>> {
        let mut result = Evented::empty();
        if Some(message_id) != self.rt_msg_id {
            return result.with_value(Ok(()));
        }
        let old_prefix = *self.peer_mgr.routing_table().our_prefix();
        for (name, peer_id) in self.peer_mgr.add_prefix(prefix) {
            self.disconnect_peer(&peer_id);
            info!("{:?} Dropped {:?} from the routing table.", self, name);
        }
        let new_prefix = *self.peer_mgr.routing_table().our_prefix();
        if old_prefix.bit_count() < new_prefix.bit_count() {
            result.add_event(Event::SectionSplit(new_prefix));
        } else if old_prefix.bit_count() > new_prefix.bit_count() {
            result.add_event(Event::SectionMerge(new_prefix));
        }
        info!("{:?} Update on RoutingTableResponse completed. Prefixes: {:?}",
              self,
              self.peer_mgr.routing_table().prefixes());
        let src = Authority::ManagedNode(*self.name());
        for member in members {
            if self.peer_mgr.routing_table().need_to_add(member.name()).is_ok() {
                let dst = Authority::ManagedNode(*member.name());
                if let Err(error) = self.send_connection_info_request(member, src, dst)
                    .extract(&mut result) {
                    debug!("{:?} - Failed to send connection info to {:?}: {:?}",
                           self,
                           member,
                           error);
                }
            }
        }
        result.with_value(Ok(()))
    }

    fn handle_section_split(&mut self,
                            prefix: Prefix<XorName>,
                            joining_node: XorName)
                            -> Evented<Result<(), RoutingError>> {
        let mut events = Evented::empty();
        let split_us = prefix == *self.peer_mgr.routing_table().our_prefix();
        // Send SectionSplit notifications if we don't know of the new node yet
        if split_us && !self.peer_mgr.routing_table().has(&joining_node) {
            self.send_section_split(prefix, joining_node);
        }
        // None of the `peers_to_drop` will have been in our section, so no need to notify Routing
        // user about them.
        let (peers_to_drop, our_new_prefix) = self.peer_mgr.split_section(prefix);
        if let Some(new_prefix) = our_new_prefix {
            events.add_event(Event::SectionSplit(new_prefix));
        }

        for (name, peer_id) in peers_to_drop {
            self.disconnect_peer(&peer_id);
            info!("{:?} Dropped {:?} from the routing table.", self, name);
        }
        info!("{:?} Section split for {:?} completed. Prefixes: {:?}",
              self,
              prefix,
              self.peer_mgr.routing_table().prefixes());

        self.merge_if_necessary();

        if split_us {
            self.send_section_update();
        }

        let prefix0 = prefix.pushed(false);
        let prefix1 = prefix.pushed(true);
        self.send_section_list_signature(prefix0, None);
        self.send_section_list_signature(prefix1, None);

        self.reset_rt_timer();

        events.with_value(Ok(()))
    }

    fn handle_own_section_merge(&mut self,
                                sender_prefix: Prefix<XorName>,
                                merge_prefix: Prefix<XorName>,
                                sections: SectionMap)
                                -> Evented<Result<(), RoutingError>> {
        let (merge_state, needed_peers) = self.peer_mgr
            .merge_own_section(sender_prefix, merge_prefix, sections);

        let mut result = Evented::empty();
        match merge_state {
            OwnMergeState::Ongoing |
            OwnMergeState::AlreadyMerged => (),
            OwnMergeState::Completed { targets, merge_details } => {
                // TODO - the event should maybe only fire once all new connections have been made?
                result.add_event(Event::SectionMerge(merge_details.prefix));
                info!("{:?} Own section merge completed. Prefixes: {:?}",
                      self,
                      self.peer_mgr.routing_table().prefixes());
                self.merge_if_necessary();

                if merge_prefix == *self.peer_mgr.routing_table().our_prefix() {
                    self.send_section_update();
                }

                // after the merge, half of our section won't have our signatures -- send them
                for prefix in self.peer_mgr.routing_table().prefixes() {
                    self.send_section_list_signature(prefix, None);
                }
                let src = Authority::Section(self.peer_mgr
                    .routing_table()
                    .our_prefix()
                    .lower_bound());
                self.send_other_section_merge(targets, merge_details, src);
            }
        }

        let own_name = *self.name();
        for needed in &needed_peers {
            debug!("{:?} Sending connection info to {:?} due to merging own section.",
                   self,
                   needed);
            if let Err(error) = self.send_connection_info_request(*needed,
                                              Authority::ManagedNode(own_name),
                                              Authority::ManagedNode(*needed.name()))
                .extract(&mut result) {
                debug!("{:?} - Failed to send connection info to {:?}: {:?}",
                       self,
                       needed,
                       error);
            }
        }
        self.reset_rt_timer();
        result.with_value(Ok(()))
    }

    fn handle_other_section_merge(&mut self,
                                  prefix: Prefix<XorName>,
                                  section: BTreeSet<PublicId>)
                                  -> Evented<Result<(), RoutingError>> {
        let needed_peers = self.peer_mgr.merge_other_section(prefix, section);
        let own_name = *self.name();

        let mut result = Evented::empty();

        for needed in needed_peers {
            debug!("{:?} Sending connection info to {:?} due to merging other section.",
                   self,
                   needed);
            let needed_name = *needed.name();
            if let Err(error) = self.send_connection_info_request(needed,
                                              Authority::ManagedNode(own_name),
                                              Authority::ManagedNode(needed_name))
                .extract(&mut result) {
                debug!("{:?} - Failed to send connection info: {:?}", self, error);
            }
        }
        info!("{:?} Other section merge completed. Prefixes: {:?}",
              self,
              self.peer_mgr.routing_table().prefixes());
        self.merge_if_necessary();
        self.send_section_list_signature(prefix, None);
        self.reset_rt_timer();
        result.with_value(Ok(()))
    }

    fn handle_ack_response(&mut self, ack: Ack) -> Result<(), RoutingError> {
        self.ack_mgr.receive(ack);
        Ok(())
    }

    /// Returns true if the calling node should keep running, false for terminate.
    fn handle_timeout(&mut self, token: u64) -> Evented<bool> {
        if self.get_approval_timer_token == Some(token) {
            return self.handle_approval_timeout();
        }

        let mut events = Evented::empty();
        if self.tick_timer_token == token {
            let tick_period = Duration::from_secs(TICK_TIMEOUT_SECS);
            self.tick_timer_token = self.timer.schedule(tick_period);

            for peer_id in self.peer_mgr.remove_expired_connections() {
                debug!("{:?} Disconnecting from timed out peer {:?}", self, peer_id);
                let _ = self.crust_service.disconnect(peer_id);
            }
            self.merge_if_necessary();

            events.add_event(Event::Tick);
            return events.with_value(true);
        }

        if self.rt_timer_token == Some(token) {
            self.rt_timeout = cmp::min(Duration::from_secs(RT_MAX_TIMEOUT_SECS),
                                       self.rt_timeout * 2);
            self.rt_timer_token = Some(self.timer.schedule(self.rt_timeout));
            if self.send_rt_request().is_err() {
                return events.with_value(true);
            }
        } else if self.candidate_timer_token == Some(token) {
            self.candidate_timer_token = None;
            if self.send_candidate_approval().is_err() {
                return events.with_value(true);
            }
        } else if self.approval_progress_timer_token == Some(token) {
            self.approval_progress_timer_token = Some(self.timer
                .schedule(Duration::from_secs(APPROVAL_PROGRESS_INTERVAL_SECS)));
            let now = Instant::now();
            let duration = if now < self.approval_expiry_time {
                self.approval_expiry_time - now
            } else {
                Duration::from_secs(0)
            };
            info!("{:?} Awaiting approval. {} Continuing to wait for a further {}.",
                  self,
                  self.resource_proof_response_progress().3,
                  Self::format(duration));
        }

        self.resend_unacknowledged_timed_out_msgs(token);

        events.with_value(true)
    }

    // This will be called if `GetNodeNameResponse` times out, or if the subsequent `NodeApproval`
    // times out.
    fn handle_approval_timeout(&mut self) -> Evented<bool> {
        let mut events = Evented::empty();
        if self.resource_proof_response_parts.is_empty() {
            // `GetNodeNameResponse` has timed out.
            info!("{:?} Failed to get relocated name from the network, so restarting.",
                  self);
            events.add_event(Event::RestartRequired);
        } else {
            // `NodeApproval` has timed out.
            let (part_count, completed, incomplete, display_string) =
                self.resource_proof_response_progress();
            let progress = if part_count == 0 {
                100
            } else {
                (((part_count * completed) + incomplete.iter().sum::<usize>()) * 100) /
                (part_count * (completed + incomplete.len()))
            };
            if progress < APPROVAL_RETRY_THRESHOLD {
                info!("{:?} Failed to get approval from the network. {} Approval process only \
                       {}% complete, so terminating node.",
                      self,
                      display_string,
                      progress);
                events.add_event(Event::Terminate);
            } else {
                info!("{:?} Failed to get approval from the network. {} Approval process {}% \
                       complete, so restarting node to retry.",
                      self,
                      display_string,
                      progress);
                events.add_event(Event::RestartRequired);
            }
        }
        events.with_value(false)
    }

    fn send_rt_request(&mut self) -> Result<(), RoutingError> {
        if self.is_approved {
            let msg_id = MessageId::new();
            self.rt_msg_id = Some(msg_id);
            let sections = self.peer_mgr.pub_ids_by_section();
            let digest = sha256::hash(&serialisation::serialise(&sections)?);
            let request_msg = RoutingMessage {
                src: Authority::ManagedNode(*self.name()),
                dst: Authority::PrefixSection(*self.peer_mgr.routing_table().our_prefix()),
                content: MessageContent::RoutingTableRequest(msg_id, digest),
            };
            if let Err(err) = self.send_routing_message(request_msg) {
                debug!("{:?} Failed to send RoutingTableRequest: {:?}.", self, err);
            }
        }
        Ok(())
    }

    fn send_candidate_approval(&mut self) -> Result<(), RoutingError> {
        let (candidate_id, client_auth, sections) = match self.peer_mgr.verified_candidate_info() {
            Err(_) => {
                trace!("{:?} No candidate for which to send CandidateApproval.",
                       self);
                return Err(RoutingError::UnknownCandidate);
            }
            Ok(info) => info,
        };
        let src = Authority::Section(*candidate_id.name());
        let dst = src;
        let response_content = MessageContent::CandidateApproval {
            candidate_id: candidate_id,
            client_auth: client_auth,
            sections: sections,
        };
        let response_msg = RoutingMessage {
            src: src,
            dst: dst,
            content: response_content,
        };
        debug!("{:?} Resource proof duration has passed.  Sending {:?}.",
               self,
               response_msg);
        if let Err(error) = self.send_routing_message(response_msg) {
            debug!("{:?} Failed sending CandidateApproval: {:?}", self, error);
        }
        Ok(())
    }

    fn decrypt_connection_info(&self,
                               encrypted_connection_info: &[u8],
                               nonce: &box_::Nonce,
                               public_id: &PublicId)
                               -> Result<PubConnectionInfo, RoutingError> {
        let decipher_result = box_::open(encrypted_connection_info,
                                         nonce,
                                         public_id.encrypting_public_key(),
                                         self.full_id.encrypting_private_key());

        let serialised_connection_info =
            decipher_result.map_err(|()| RoutingError::AsymmetricDecryptionFailure)?;
        Ok(serialisation::deserialise(&serialised_connection_info)?)
    }

    fn reset_rt_timer(&mut self) {
        self.rt_msg_id = None;
        self.rt_timeout = Duration::from_secs(RT_MIN_TIMEOUT_SECS);
        self.rt_timer_token = Some(self.timer.schedule(self.rt_timeout));
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
            let message = RoutingMessage {
                src: src,
                dst: dst,
                content: part,
            };
            self.send_routing_message(message)?;
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
            self.send_signed_msg_to_peer(signed_msg, target_peer_id, route, new_sent_to.clone())?;
        }
        Ok(())
    }

    fn send_signed_msg_to_peer(&mut self,
                               signed_msg: &SignedMessage,
                               target: PeerId,
                               route: u8,
                               sent_to: BTreeSet<XorName>)
                               -> Result<(), RoutingError> {
        let (peer_id, bytes) = if self.crust_service.is_connected(&target) {
            let serialised = self.to_hop_bytes(signed_msg.clone(), route, sent_to)?;
            (target, serialised)
        } else if let Some(&tunnel_id) = self.tunnels.tunnel_for(&target) {
            let serialised = self.to_tunnel_hop_bytes(signed_msg.clone(), route, sent_to, target)?;
            (tunnel_id, serialised)
        } else {
            trace!("{:?} Not connected or tunnelling to {:?}. Dropping peer.",
                   self,
                   target);
            self.disconnect_peer(&target);
            return Ok(());
        };
        if !self.filter_outgoing_routing_msg(signed_msg.routing_message(), &target, route) {
            self.send_or_drop(&peer_id, bytes, signed_msg.priority());
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
            self.send_or_drop(peer_id, raw_bytes, priority);
            Ok(())
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

    /// Returns the peer that is responsible for collecting signatures to verify a message; this
    /// may be us or another node. If our signature is not required, this returns `None`.
    fn get_signature_target(&self, src: &Authority<XorName>, route: u8) -> Option<XorName> {
        use Authority::*;
        let list: Vec<&XorName> = match *src {
            ClientManager(_) | NaeManager(_) | NodeManager(_) => {
                let mut v = self.peer_mgr
                    .routing_table()
                    .our_section()
                    .iter()
                    .sorted_by(|&lhs, &rhs| src.name().cmp_distance(lhs, rhs));
                v.truncate(self.min_section_size());
                v
            }
            Section(_) => {
                self.peer_mgr
                    .routing_table()
                    .our_section()
                    .iter()
                    .sorted_by(|&lhs, &rhs| src.name().cmp_distance(lhs, rhs))
            }
            PrefixSection(ref pfx) => {
                self.peer_mgr
                    .routing_table()
                    .iter()
                    .filter(|name| pfx.matches(name))
                    .chain(iter::once(self.name()))
                    .sorted_by(|&lhs, &rhs| src.name().cmp_distance(lhs, rhs))
            }
            ManagedNode(_) | Client { .. } => return Some(*self.name()),
        };

        if !list.contains(&self.name()) {
            None
        } else {
            Some(*list[route as usize % list.len()])
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
            MessageContent::ConnectionInfoRequest { pub_id, .. } |
            MessageContent::ConnectionInfoResponse { pub_id, .. } => {
                routing_msg.src.is_client() && pub_id == *self.full_id.public_id()
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
                error!("{:?} Unable to find connection to proxy node in proxy map.",
                       self);
                Err(RoutingError::ProxyConnectionNotFound)
            }
        } else {
            error!("{:?} Source should be client if our state is a Client.",
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
        let direct_message = if self.is_approved {
            DirectMessage::NodeIdentify {
                serialised_public_id: serialised_public_id,
                signature: signature,
            }
        } else {
            DirectMessage::CandidateIdentify {
                serialised_public_id: serialised_public_id,
                signature: signature,
            }
        };

        let result = self.send_direct_message(peer_id, direct_message);
        if let Err(ref error) = result {
            let id_type = if self.is_approved {
                "NodeIdentify"
            } else {
                "CandidateIdentify"
            };
            warn!("{:?} Failed to send {:?} to {:?}: {:?}",
                  self,
                  id_type,
                  peer_id,
                  error);
        }
        result
    }

    fn send_connection_info_request(&mut self,
                                    their_public_id: PublicId,
                                    src: Authority<XorName>,
                                    dst: Authority<XorName>)
                                    -> Evented<Result<(), RoutingError>> {
        let mut result = Evented::empty();
        let their_name = *their_public_id.name();
        if let Some(peer_id) = self.peer_mgr
            .get_proxy_or_client_or_joining_node_peer_id(&their_public_id) {

            try_ev!(self.send_node_identify(peer_id), result);
            self.handle_node_identify(their_public_id, peer_id).extract(&mut result);
            return result.with_value(Ok(()));
        }

        try_ev!(self.peer_mgr.allow_connect(&their_name), result);

        if let Some(token) = self.peer_mgr.get_connection_token(src, dst, their_public_id) {
            self.crust_service.prepare_connection_info(token);
            return result.map(Ok);
        }

        let our_pub_info = if let Some(&PeerState::ConnectionInfoReady(ref our_priv_info)) =
            self.peer_mgr.get_state_by_name(&their_name) {
            our_priv_info.to_pub_connection_info()
        } else {
            trace!("{:?} Not sending connection info request to {:?}",
                   self,
                   their_name);
            return result.map(Ok);
        };
        trace!("{:?} Resending connection info request to {:?}",
               self,
               their_name);
        self.send_connection_info(our_pub_info, their_public_id, src, dst, None);
        result.with_value(Ok(()))
    }

    // Handle dropped peer with the given peer id. Returns true if we should keep running, false if
    // we should terminate.
    fn dropped_peer(&mut self, peer_id: &PeerId) -> Evented<bool> {
        let (peer, removal_result) = match self.peer_mgr.remove_peer(peer_id) {
            Some(result) => result,
            None => return true.to_evented(),
        };

        let mut result = Evented::empty();

        if let Ok(removal_details) = removal_result {
            if !self.dropped_routing_node(peer.pub_id(), removal_details).extract(&mut result) {
                return result.with_value(false);
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

                if self.peer_mgr.routing_table().len() < self.min_section_size() - 1 {
                    result.add_event(Event::Terminate);
                    return result.with_value(false);
                }
            }
            _ => (),
        }

        result.with_value(true)
    }

    // Handle dropped routing peer with the given name and removal details. Returns true if we
    // should keep running, false if we should terminate.
    fn dropped_routing_node(&mut self,
                            pub_id: &PublicId,
                            details: RemovalDetails<XorName>)
                            -> Evented<bool> {
        info!("{:?} Dropped {:?} from the routing table.",
              self,
              details.name);

        let node_lost = Event::NodeLost(details.name, self.peer_mgr.routing_table().clone());
        let mut result = Evented::single(node_lost, ());

        self.merge_if_necessary();

        self.peer_mgr.routing_table().find_section_prefix(&details.name).map_or((), |prefix| {
            self.send_section_list_signature(prefix, None);
        });
        if details.was_in_our_section {
            self.reset_rt_timer();
            self.section_list_sigs
                .remove_signatures_by(*pub_id, self.peer_mgr.routing_table().our_section().len());
        }

        if self.peer_mgr.routing_table().is_empty() {
            debug!("{:?} Lost all routing connections.", self);
            if !self.is_first_node {
                result.add_event(Event::RestartRequired);
                return result.with_value(false);
            }
        }

        result.with_value(true)
    }

    fn send_section_split(&mut self, our_prefix: Prefix<XorName>, joining_node: XorName) {
        for prefix in self.peer_mgr.routing_table().prefixes() {
            let request_msg = RoutingMessage {
                // this way of calculating the source avoids using the joining node as the route
                src: Authority::Section(our_prefix.substituted_in(!joining_node)),
                dst: Authority::PrefixSection(prefix),
                content: MessageContent::SectionSplit(our_prefix, joining_node),
            };
            if let Err(err) = self.send_routing_message(request_msg) {
                debug!("{:?} Failed to send SectionSplit: {:?}.", self, err);
            }
        }
    }

    fn merge_if_necessary(&mut self) {
        if let Some(merge_details) = self.peer_mgr.should_merge() {
            self.send_own_section_merge(merge_details);
        }
    }

    fn send_own_section_merge(&mut self, merge_details: OwnMergeDetails<XorName>) {
        let sections = merge_details.sections
            .into_iter()
            .map(|(prefix, members)| {
                (prefix, self.peer_mgr.get_pub_ids(&members).into_iter().collect())
            })
            .collect();
        let request_content = MessageContent::OwnSectionMerge {
            sender_prefix: merge_details.sender_prefix,
            merge_prefix: merge_details.merge_prefix,
            sections: sections,
        };
        let src_name = self.peer_mgr.routing_table().our_prefix().lower_bound();
        let request_msg = RoutingMessage {
            src: Authority::Section(src_name),
            dst: Authority::PrefixSection(merge_details.merge_prefix),
            content: request_content.clone(),
        };
        if let Err(err) = self.send_routing_message(request_msg) {
            debug!("{:?} Failed to send OwnSectionMerge: {:?}.", self, err);
        }
    }

    fn send_other_section_merge(&mut self,
                                targets: BTreeSet<Prefix<XorName>>,
                                merge_details: OtherMergeDetails<XorName>,
                                src: Authority<XorName>) {
        let section = self.peer_mgr.get_pub_ids(&merge_details.section);
        for target in &targets {
            let request_content = MessageContent::OtherSectionMerge {
                prefix: merge_details.prefix,
                section: section.clone(),
            };
            let request_msg = RoutingMessage {
                src: src,
                dst: Authority::PrefixSection(*target),
                content: request_content,
            };

            if let Err(err) = self.send_routing_message(request_msg) {
                debug!("{:?} Failed to send OtherSectionMerge: {:?}.", self, err);
            }
        }
    }

    fn dropped_tunnel_client(&mut self, peer_id: &PeerId) {
        for other_id in self.tunnels.drop_client(peer_id) {
            let message = DirectMessage::TunnelClosed(*peer_id);
            let _ = self.send_direct_message(other_id, message);
        }
    }

    fn dropped_tunnel_node(&mut self, peer_id: &PeerId) -> Evented<()> {
        let mut result = Evented::empty();
        let peers = self.tunnels
            .remove_tunnel(peer_id)
            .into_iter()
            .filter_map(|dst_id| {
                self.peer_mgr.get_routing_peer(&dst_id).map(|dst_pub_id| (dst_id, *dst_pub_id))
            })
            .collect_vec();
        for (dst_id, pub_id) in peers {
            self.dropped_peer(&dst_id).extract(&mut result);
            debug!("{:?} Lost tunnel for peer {:?} ({:?}). Requesting new tunnel.",
                   self,
                   dst_id,
                   pub_id.name());
            self.find_tunnel_for_peer(dst_id, &pub_id);
        }
        result
    }

    // Proper node is either the first node in the network or a node which has at least one entry
    // in its routing table.
    fn is_proper(&self) -> bool {
        self.is_first_node || self.peer_mgr.routing_table().len() >= 1
    }

    fn send_direct_message(&mut self,
                           dst_id: PeerId,
                           direct_message: DirectMessage)
                           -> Result<(), RoutingError> {
        self.stats().count_direct_message(&direct_message);

        if let Some(&tunnel_id) = self.tunnels.tunnel_for(&dst_id) {
            let message = Message::TunnelDirect {
                content: direct_message,
                src: self.crust_service.id(),
                dst: dst_id,
            };
            self.send_message(&tunnel_id, message)
        } else {
            self.send_message(&dst_id, Message::Direct(direct_message))
        }
    }

    // For the ongoing collection of `ResourceProofResponse` messages, returns a tuple comprising:
    // the `part_count` they all use; the number of fully-completed ones; a vector for the
    // incomplete ones specifying how many parts have been sent to each peer; and a `String`
    // containing this info.
    fn resource_proof_response_progress(&self) -> (usize, usize, Vec<usize>, String) {
        let mut total_parts = 0;
        let mut completed = 0;
        let mut incomplete = vec![];
        for messages in self.resource_proof_response_parts.values() {
            if let Some(next_message) = messages.last() {
                match *next_message {
                    DirectMessage::ResourceProofResponse { part_index, part_count, .. } => {
                        total_parts = part_count;
                        incomplete.push(part_index);
                    }
                    _ => return (1, 0, vec![1], String::new()),  // invalid situation
                }
            } else {
                completed += 1;
            }
        }

        let display_string = if incomplete.is_empty() {
            if self.resource_proof_response_parts.is_empty() {
                "No resource proof challenges received yet; still establishing connections to \
                 peers."
                    .to_string()
            } else {
                format!("All {} resource proof responses fully sent.", completed)
            }
        } else {
            format!("{} resource proof response(s) fully sent.  Remainder have sent \
                     {:?} of {} parts each.",
                    completed,
                    incomplete,
                    total_parts)
        };
        (total_parts, completed, incomplete, display_string)
    }

    fn format(duration: Duration) -> String {
        format!("{}.{:06} seconds",
                duration.as_secs(),
                duration.subsec_nanos() / 1000)
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

    fn close_group(&self, name: XorName, count: usize) -> Option<Vec<XorName>> {
        self.peer_mgr
            .routing_table()
            .closest_names(&name, count)
            .map(|names| names.into_iter().cloned().collect_vec())
    }

    fn handle_lost_peer(&mut self, peer_id: PeerId) -> Evented<Transition> {
        if peer_id == self.crust_service.id() {
            error!("{:?} LostPeer fired with our crust peer ID.", self);
            return Transition::Stay.to_evented();
        }

        debug!("{:?} Received LostPeer - {:?}", self, peer_id);

        let mut result = Evented::empty();

        self.dropped_tunnel_client(&peer_id);
        self.dropped_tunnel_node(&peer_id).extract(&mut result);

        let transition = if self.dropped_peer(&peer_id).extract(&mut result) {
            Transition::Stay
        } else {
            Transition::Terminate
        };

        result.with_value(transition)
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
        self.routing_msg_filter.clear();
        if self.peer_mgr.remove_connecting_peers() {
            self.merge_if_necessary();
        }
    }

    pub fn section_list_signatures(&self,
                                   prefix: Prefix<XorName>)
                                   -> Result<BTreeMap<PublicId, sign::Signature>, RoutingError> {
        if let Some(&(_, ref signatures)) = self.section_list_sigs.get_signatures(prefix) {
            Ok(signatures.iter().map(|(&pub_id, &sig)| (pub_id, sig)).collect())
        } else {
            Err(RoutingError::NotEnoughSignatures)
        }
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

    fn min_section_size(&self) -> usize {
        self.peer_mgr.routing_table().min_section_size()
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
        use routing_table::Authority::*;
        let sending_names = match routing_msg.src {
            ClientManager(_) | NaeManager(_) | NodeManager(_) | ManagedNode(_) => {
                let section = self.peer_mgr
                    .routing_table()
                    .get_section(self.name())
                    .ok_or(RoutingError::RoutingTable(RoutingTableError::NoSuchPeer))?;
                let pub_ids = self.peer_mgr.get_pub_ids(section);
                vec![SectionList::new(*self.peer_mgr.routing_table().our_prefix(), pub_ids)]
            }
            Section(_) => {
                vec![SectionList::new(*self.peer_mgr.routing_table().our_prefix(),
                                      self.peer_mgr
                                          .get_pub_ids(self.peer_mgr
                                              .routing_table()
                                              .our_section()))]
            }
            PrefixSection(ref prefix) => {
                self.peer_mgr
                    .routing_table()
                    .all_sections()
                    .into_iter()
                    .filter_map(|(p, members)| if prefix.is_compatible(&p) {
                        Some(SectionList::new(p, self.peer_mgr.get_pub_ids(&members)))
                    } else {
                        None
                    })
                    .collect()
            }
            Client { .. } => vec![],
        };

        let signed_msg = SignedMessage::new(routing_msg, &self.full_id, sending_names)?;
        if !self.add_to_pending_acks(&signed_msg, route) {
            debug!("{:?} already received an ack for {:?} - so not resending it.",
                   self,
                   signed_msg);
            return Ok(());
        }

        match self.get_signature_target(&signed_msg.routing_message().src, route) {
            None => Ok(()),
            Some(our_name) if our_name == *self.name() => {
                trace!("{:?} Starting message accumulation for {:?}",
                       self,
                       signed_msg);
                let min_section_size = self.min_section_size();
                if let Some((msg, route)) =
                    self.sig_accumulator.add_message(signed_msg, min_section_size, route) {
                    trace!("{:?} Message accumulated - sending: {:?}", self, msg);
                    if self.in_authority(&msg.routing_message().dst) {
                        self.handle_signed_message(msg, route, our_name, &BTreeSet::new())?;
                    } else {
                        self.send_signed_message(&msg, route, &our_name, &BTreeSet::new())?;
                    }
                }
                Ok(())
            }
            Some(target_name) => {
                if let Some(&peer_id) = self.peer_mgr.get_peer_id(&target_name) {
                    let direct_msg = signed_msg.routing_message()
                        .to_signature(self.full_id().signing_private_key())?;
                    trace!("{:?} Sending signature for {:?} to {:?}",
                           self,
                           signed_msg,
                           target_name);
                    self.send_direct_message(peer_id, direct_msg)
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
