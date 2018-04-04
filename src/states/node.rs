// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use super::common::{Base, Bootstrapped, USER_MSG_CACHE_EXPIRY_DURATION_SECS};
use {CrustEvent, PrivConnectionInfo, PubConnectionInfo, QUORUM_DENOMINATOR, QUORUM_NUMERATOR,
     Service};
use ack_manager::{Ack, AckManager};
use action::Action;
use cache::Cache;
use config_handler;
use crust::{ConnectionInfoResult, CrustError, CrustUser};
use cumulative_own_section_merge::CumulativeOwnSectionMerge;
use error::{BootstrapResponseError, InterfaceError, RoutingError};
use event::Event;
#[cfg(feature = "use-mock-crust")]
use fake_clock::FakeClock as Instant;
use id::{FullId, PublicId};
use itertools::Itertools;
use log::Level;
use lru_time_cache::LruCache;
use maidsafe_utilities::serialisation;
use messages::{DEFAULT_PRIORITY, DirectMessage, HopMessage, MAX_PARTS, MAX_PART_LEN, Message,
               MessageContent, RoutingMessage, SectionList, SignedMessage, UserMessage,
               UserMessageCache};
use outbox::{EventBox, EventBuf};
use peer_manager::{ConnectionInfoPreparedResult, Peer, PeerManager, PeerState, ReconnectingPeer,
                   RoutingConnection, SectionMap};
use rand::{self, Rng};
use rate_limiter::RateLimiter;
use resource_prover::{RESOURCE_PROOF_DURATION_SECS, ResourceProver};
use routing_message_filter::{FilteringResult, RoutingMessageFilter};
use routing_table::{Authority, OwnMergeState, Prefix, RemovalDetails, RoutingTable,
                    VersionedPrefix, Xorable};
use routing_table::Error as RoutingTableError;
use rust_sodium::crypto::{box_, sign};
use section_list_cache::SectionListCache;
use sha3::Digest256;
use signature_accumulator::SignatureAccumulator;
use state_machine::Transition;
use stats::Stats;
use std::{cmp, fmt, iter, mem};
use std::collections::{BTreeSet, VecDeque};
#[cfg(feature = "use-mock-crust")]
use std::collections::BTreeMap;
use std::fmt::{Debug, Formatter};
use std::net::IpAddr;
use std::time::Duration;
#[cfg(not(feature = "use-mock-crust"))]
use std::time::Instant;
use timer::Timer;
use tunnels::Tunnels;
use types::{MessageId, RoutingActionSender};
use utils::{self, DisplayDuration};
use xor_name::XorName;

/// Time (in seconds) after which a `Tick` event is sent.
const TICK_TIMEOUT_SECS: u64 = 60;
/// The number of required leading zero bits for the resource proof
const RESOURCE_PROOF_DIFFICULTY: u8 = 0;
/// The total size of the resource proof data.
const RESOURCE_PROOF_TARGET_SIZE: usize = 250 * 1024 * 1024;
/// Initial delay between a routing table change and sending a `SectionUpdate`, in seconds.
const SU_MIN_TIMEOUT_SECS: u64 = 30;
/// Maximal delay between two subsequent `SectionUpdate`s, in seconds.
const SU_MAX_TIMEOUT_SECS: u64 = 300;
/// Interval between displaying info about current candidate, in seconds.
const CANDIDATE_STATUS_INTERVAL_SECS: u64 = 60;
/// Duration for which `OwnSectionMerge` messages are kept in the cache, in seconds.
const MERGE_TIMEOUT_SECS: u64 = 300;
/// Duration for which all clients on a given IP will be blocked from joining this node, in seconds.
const CLIENT_BAN_SECS: u64 = 2 * 60 * 60;
/// Duration for which clients' IDs we disconnected from are retained, in seconds.
const DROPPED_CLIENT_TIMEOUT_SECS: u64 = 2 * 60 * 60;

pub struct Node {
    ack_mgr: AckManager,
    cacheable_user_msg_cache: UserMessageCache,
    crust_service: Service,
    /// ID from before relocating.
    old_full_id: FullId,
    full_id: FullId,
    is_first_node: bool,
    is_approved: bool,
    /// The queue of routing messages addressed to us. These do not themselves need forwarding,
    /// although they may wrap a message which needs forwarding.
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
    next_relocation_dst: Option<XorName>,
    /// Interval used for relocation in mock crust tests.
    next_relocation_interval: Option<(XorName, XorName)>,
    /// The current duration between `RoutingTableRequest`s we send. Doubles with every message.
    su_timeout: Duration,
    /// The timer token for sending the next `RoutingTableRequest`.
    su_timer_token: Option<u64>,
    /// `RoutingMessage`s affecting the routing table that arrived before `NodeApproval`.
    routing_msg_backlog: Vec<RoutingMessage>,
    /// Cache of `OwnSectionMerge` messages we have received, by sender section prefix.
    merge_cache: LruCache<Prefix<XorName>, SectionMap>,
    /// Union of our merged section, deduced from multiple `OwnSectionMerge`.
    our_merged_section: CumulativeOwnSectionMerge,
    /// The timer token for sending a `CandidateApproval` message.
    candidate_timer_token: Option<u64>,
    /// The timer token for displaying the current candidate status.
    candidate_status_token: Option<u64>,
    resource_prover: ResourceProver,
    joining_prefix: Prefix<XorName>,
    /// Limits the rate at which clients can pass messages through this node when it acts as their
    /// proxy.
    clients_rate_limiter: RateLimiter,
    /// IPs of clients which have been temporarily blocked from bootstrapping off this node.
    banned_client_ips: LruCache<IpAddr, ()>,
    /// Recently-disconnected clients.  Clients are added to this when we disconnect from them so we
    /// have a way to know to not handle subsequent hop messages from them (i.e. those which were
    /// already enqueued in the channel or added before Crust handled the disconnect request).  If a
    /// client then re-connects, its ID is removed from here when we add it to the `PeerManager`.
    dropped_clients: LruCache<PublicId, ()>,
    /// Proxy client traffic handled
    proxy_load_amount: u64,
    /// Whether resource proof is disabled.
    disable_resource_proof: bool,
}

impl Node {
    pub fn first(
        action_sender: RoutingActionSender,
        cache: Box<Cache>,
        crust_service: Service,
        full_id: FullId,
        min_section_size: usize,
        timer: Timer,
    ) -> Option<Self> {
        // old_id is useless for first node
        let old_id = FullId::new();
        let mut node = Self::new(
            action_sender,
            cache,
            crust_service,
            true,
            old_id,
            full_id,
            min_section_size,
            Stats::new(),
            timer,
            0,
        );
        if let Err(error) = node.crust_service.start_listening_tcp() {
            error!("{:?} Failed to start listening: {:?}", node, error);
            None
        } else {
            debug!("{:?} State changed to node.", node);
            info!("{:?} Started a new network as a seed node.", node);
            Some(node)
        }
    }

    #[cfg_attr(feature = "cargo-clippy", allow(too_many_arguments))]
    pub fn from_bootstrapping(
        our_section: (Prefix<XorName>, BTreeSet<PublicId>),
        action_sender: RoutingActionSender,
        cache: Box<Cache>,
        crust_service: Service,
        old_full_id: FullId,
        new_full_id: FullId,
        min_section_size: usize,
        proxy_pub_id: PublicId,
        stats: Stats,
        timer: Timer,
    ) -> Self {
        let mut node = Self::new(
            action_sender,
            cache,
            crust_service,
            false,
            old_full_id,
            new_full_id,
            min_section_size,
            stats,
            timer,
            our_section.1.len(),
        );
        node.joining_prefix = our_section.0;
        node.peer_mgr.insert_peer(Peer::new(
            proxy_pub_id,
            PeerState::Proxy,
            false,
            ReconnectingPeer::False,
        ));
        node.join(our_section.1, &proxy_pub_id);
        node
    }

    #[cfg_attr(feature = "cargo-clippy", allow(too_many_arguments))]
    fn new(
        action_sender: RoutingActionSender,
        cache: Box<Cache>,
        crust_service: Service,
        first_node: bool,
        old_full_id: FullId,
        new_full_id: FullId,
        min_section_size: usize,
        stats: Stats,
        timer: Timer,
        challenger_count: usize,
    ) -> Self {
        let dev_config = config_handler::get_config().dev.unwrap_or_default();
        let public_id = *new_full_id.public_id();
        let tick_period = Duration::from_secs(TICK_TIMEOUT_SECS);
        let tick_timer_token = timer.schedule(tick_period);
        let user_msg_cache_duration = Duration::from_secs(USER_MSG_CACHE_EXPIRY_DURATION_SECS);

        Node {
            ack_mgr: AckManager::new(),
            cacheable_user_msg_cache: UserMessageCache::with_expiry_duration(
                user_msg_cache_duration,
            ),
            crust_service: crust_service,
            old_full_id: old_full_id,
            full_id: new_full_id,
            is_first_node: first_node,
            is_approved: first_node,
            msg_queue: VecDeque::new(),
            peer_mgr: PeerManager::new(
                min_section_size,
                public_id,
                dev_config.disable_client_rate_limiter,
            ),
            response_cache: cache,
            routing_msg_filter: RoutingMessageFilter::new(),
            sig_accumulator: Default::default(),
            section_list_sigs: SectionListCache::new(),
            stats: stats,
            tick_timer_token: tick_timer_token,
            timer: timer.clone(),
            tunnels: Default::default(),
            user_msg_cache: UserMessageCache::with_expiry_duration(user_msg_cache_duration),
            next_relocation_dst: None,
            next_relocation_interval: None,
            su_timeout: Duration::from_secs(SU_MIN_TIMEOUT_SECS),
            su_timer_token: None,
            routing_msg_backlog: vec![],
            merge_cache: LruCache::with_expiry_duration(Duration::from_secs(MERGE_TIMEOUT_SECS)),
            our_merged_section: Default::default(),
            candidate_timer_token: None,
            candidate_status_token: None,
            resource_prover: ResourceProver::new(action_sender, timer, challenger_count),
            joining_prefix: Default::default(),
            clients_rate_limiter: RateLimiter::new(dev_config.disable_client_rate_limiter),
            banned_client_ips: LruCache::with_expiry_duration(Duration::from_secs(CLIENT_BAN_SECS)),
            dropped_clients: LruCache::with_expiry_duration(
                Duration::from_secs(DROPPED_CLIENT_TIMEOUT_SECS),
            ),
            proxy_load_amount: 0,
            disable_resource_proof: dev_config.disable_resource_proof,
        }
    }

    /// Called immediately after bootstrapping. Sends `ConnectionInfoRequest`s to all members of
    /// `our_section` to then start the candidate approval process.
    fn join(&mut self, our_section: BTreeSet<PublicId>, proxy_public_id: &PublicId) {
        self.resource_prover.start(self.disable_resource_proof);

        trace!("{:?} Relocation completed.", self);
        info!(
            "{:?} Received relocation section. Establishing connections to {} peers.",
            self,
            our_section.len()
        );

        let src = Authority::Client {
            client_id: *self.full_id.public_id(),
            proxy_node_name: *proxy_public_id.name(),
        };
        // There will be no events raised as a result of these calls, so safe to just use a
        // throwaway `EventBox` here.
        let mut outbox = EventBuf::new();
        for pub_id in &our_section {
            debug!(
                "{:?} Sending connection info to {:?} on Relocation response.",
                self,
                pub_id
            );
            let dst = Authority::ManagedNode(*pub_id.name());
            if let Err(error) = self.send_connection_info_request(
                *pub_id,
                src,
                dst,
                &mut outbox,
                ReconnectingPeer::False,
            )
            {
                debug!(
                    "{:?} - Failed to send connection info to {:?}: {:?}",
                    self,
                    pub_id,
                    error
                );
            }
        }
    }

    fn update_stats(&mut self) {
        let old_client_num = self.stats.cur_client_num;
        self.stats.cur_client_num = self.peer_mgr.client_num();
        if self.stats.cur_client_num != old_client_num {
            if self.stats.cur_client_num > old_client_num {
                self.stats.cumulative_client_num += self.stats.cur_client_num - old_client_num;
            }
            if self.is_approved {
                info!(target: "routing_stats", "{:?} - Connected clients: {}, cumulative: {}",
                  self,
                  self.stats.cur_client_num,
                  self.stats.cumulative_client_num);
            }
        }
        if self.stats.tunnel_connections != self.tunnels.tunnel_count() ||
            self.stats.tunnel_client_pairs != self.tunnels.client_count()
        {
            self.stats.tunnel_connections = self.tunnels.tunnel_count();
            self.stats.tunnel_client_pairs = self.tunnels.client_count();
            if self.is_approved {
                info!(target: "routing_stats",
                      "{:?} - Indirect connections: {}, tunnelling for: {}",
                      self,
                      self.stats.tunnel_connections,
                      self.stats.tunnel_client_pairs);
            }
        }

        if self.stats.cur_routing_table_size != self.routing_table().len() {
            self.stats.cur_routing_table_size = self.routing_table().len();
            if self.is_approved {
                self.print_rt_size();
            }
        }
    }

    fn print_rt_size(&self) {
        const TABLE_LVL: Level = Level::Info;
        if log_enabled!(TABLE_LVL) {
            let status_str = format!(
                "{:?} - Routing Table size: {:3}",
                self,
                self.stats.cur_routing_table_size
            );
            let network_estimate = match self.routing_table().network_size_estimate() {
                (n, true) => format!("Exact network size: {}", n),
                (n, false) => format!("Estimated network size: {}", n),
            };
            let sep_len = cmp::max(status_str.len(), network_estimate.len());
            let sep_str = iter::repeat('-').take(sep_len).collect::<String>();
            log!(target: "routing_stats", TABLE_LVL, " -{}- ", sep_str);
            log!(target: "routing_stats", TABLE_LVL, "| {:<1$} |", status_str, sep_len);
            log!(target: "routing_stats", TABLE_LVL, "| {:<1$} |", network_estimate, sep_len);
            log!(target: "routing_stats", TABLE_LVL, " -{}- ", sep_str);
        }
    }

    pub fn handle_action(&mut self, action: Action, outbox: &mut EventBox) -> Transition {
        match action {
            Action::ClientSendRequest { result_tx, .. } => {
                let _ = result_tx.send(Err(InterfaceError::InvalidState));
            }
            Action::NodeSendMessage {
                src,
                dst,
                content,
                priority,
                result_tx,
            } => {
                let result = match self.send_user_message(src, dst, content, priority) {
                    Err(RoutingError::Interface(err)) => Err(err),
                    Err(_) | Ok(()) => Ok(()),
                };

                let _ = result_tx.send(result);
            }
            Action::Id { result_tx } => {
                let _ = result_tx.send(*self.id());
            }
            Action::Timeout(token) => {
                if let Transition::Terminate = self.handle_timeout(token, outbox) {
                    return Transition::Terminate;
                }
            }
            Action::ResourceProofResult(pub_id, messages) => {
                let msg = self.resource_prover.handle_action_res_proof(
                    pub_id,
                    messages,
                );
                self.send_direct_message(pub_id, msg);
            }
            Action::Terminate => {
                return Transition::Terminate;
            }
        }

        self.handle_routing_messages(outbox);
        self.update_stats();
        Transition::Stay
    }

    pub fn handle_crust_event(
        &mut self,
        crust_event: CrustEvent<PublicId>,
        outbox: &mut EventBox,
    ) -> Transition {
        match crust_event {
            CrustEvent::BootstrapAccept(pub_id, peer_kind) => {
                self.handle_bootstrap_accept(pub_id, peer_kind)
            }
            CrustEvent::BootstrapConnect(pub_id, _) => {
                self.handle_bootstrap_connect(pub_id, outbox)
            }
            CrustEvent::ConnectSuccess(pub_id) => self.handle_connect_success(pub_id, outbox),
            CrustEvent::ConnectFailure(pub_id) => self.handle_connect_failure(pub_id),
            CrustEvent::LostPeer(pub_id) => {
                if let Transition::Terminate = self.handle_lost_peer(pub_id, outbox) {
                    return Transition::Terminate;
                }
            }
            CrustEvent::NewMessage(pub_id, _peer_kind, bytes) => {
                match self.handle_new_message(pub_id, bytes, outbox) {
                    Err(RoutingError::FilterCheckFailed) |
                    Ok(_) => (),
                    Err(err) => debug!("{:?} - {:?}", self, err),
                }
            }
            CrustEvent::ConnectionInfoPrepared(ConnectionInfoResult {
                                                   result_token,
                                                   result,
                                               }) => {
                self.handle_connection_info_prepared(result_token, result)
            }
            CrustEvent::ListenerStarted(port) => {
                trace!("{:?} Listener started on port {}.", self, port);
                // If first node, allow other peers to bootstrap via us
                // else wait until NodeApproval.
                if self.is_first_node {
                    if let Err(err) = self.crust_service.set_accept_bootstrap(true) {
                        warn!(
                            "{:?} Unable to accept bootstrap connections. {:?}",
                            self,
                            err
                        );
                    }
                    self.crust_service.set_service_discovery_listen(true);
                }
                return Transition::Stay;
            }
            CrustEvent::ListenerFailed => {
                error!("{:?} Failed to start listening.", self);
                outbox.send_event(Event::Terminate);
                return Transition::Terminate;
            }
            CrustEvent::WriteMsgSizeProhibitive(pub_id, msg) => {
                error!(
                    "{:?} Failed to send {}-byte message to {:?}. Message too large.",
                    self,
                    msg.len(),
                    pub_id
                );
            }
            _ => {
                debug!("{:?} - Unhandled crust event: {:?}", self, crust_event);
            }
        }

        self.handle_routing_messages(outbox);
        self.update_stats();
        Transition::Stay
    }

    /// Routing table of this node.
    pub fn routing_table(&self) -> &RoutingTable<XorName> {
        self.peer_mgr.routing_table()
    }

    fn handle_routing_messages(&mut self, outbox: &mut EventBox) {
        while let Some(routing_msg) = self.msg_queue.pop_front() {
            if self.in_authority(&routing_msg.dst) {
                if let Err(err) = self.dispatch_routing_message(routing_msg, outbox) {
                    debug!("{:?} Routing message dispatch failed: {:?}", self, err);
                }
            }
        }
    }

    fn handle_bootstrap_accept(&mut self, pub_id: PublicId, peer_kind: CrustUser) {
        trace!(
            "{:?} Received BootstrapAccept from {:?} as {:?}.",
            self,
            pub_id,
            peer_kind
        );
        let ip = if let Ok(ip) = self.crust_service.get_peer_ip_addr(&pub_id) {
            ip
        } else {
            debug!(
                "{:?} Can't get IP address of bootstrapper {:?}.",
                self,
                pub_id
            );
            self.disconnect_peer(&pub_id, None);
            if peer_kind == CrustUser::Client {
                let _ = self.dropped_clients.insert(pub_id, ());
            }
            return;
        };

        if peer_kind == CrustUser::Client && self.banned_client_ips.contains_key(&ip) {
            warn!(
                "{:?} Client {:?} is trying to bootstrap on banned IP {}.",
                self,
                pub_id,
                ip
            );
            self.ban_and_disconnect_peer(&pub_id);
            return;
        }
        self.peer_mgr.insert_peer(Peer::new(
            pub_id,
            PeerState::Bootstrapper { peer_kind, ip },
            false,
            ReconnectingPeer::False,
        ));
    }

    fn handle_bootstrap_connect(&mut self, pub_id: PublicId, outbox: &mut EventBox) {
        // A mature node doesn't need a bootstrap connection
        self.disconnect_peer(&pub_id, Some(outbox))
    }

    fn handle_connect_success(&mut self, pub_id: PublicId, outbox: &mut EventBox) {
        // Remove tunnel connection if we have one for this peer already
        if let Some(tunnel_id) = self.tunnels.remove_tunnel_for(&pub_id) {
            debug!("{:?} Removing unwanted tunnel for {:?}", self, pub_id);
            let message = DirectMessage::TunnelDisconnect(pub_id);
            self.send_direct_message(tunnel_id, message);
        } else if self.peer_mgr.is_routing_peer(&pub_id) {
            warn!(
                "{:?} Received ConnectSuccess from {:?}, but node is already in routing \
                   state in peer_map.",
                self,
                pub_id
            );
            return;
        }

        self.peer_mgr.connected_to(&pub_id);
        debug!("{:?} Received ConnectSuccess from {}.", self, pub_id);
        self.process_connection(pub_id, outbox);
    }

    fn handle_connect_failure(&mut self, pub_id: PublicId) {
        if let Some(&PeerState::CrustConnecting) =
            self.peer_mgr.get_peer(&pub_id).map(Peer::state)
        {
            debug!("{:?} Failed to connect to peer {:?}.", self, pub_id);
            if self.tunnels.tunnel_for(&pub_id).is_none() {
                let valid = self.peer_mgr.get_peer(&pub_id).map_or(
                    false,
                    |peer| peer.valid(),
                );
                self.find_tunnel_for_peer(&pub_id, valid);
            } else {
                debug!("{:?} already has tunnel to peer {}.", self, pub_id);
            }
        }
    }

    fn find_tunnel_for_peer(&mut self, pub_id: &PublicId, valid: bool) {
        for dst_pub_id in self.peer_mgr.set_searching_for_tunnel(*pub_id, valid) {
            trace!(
                "{:?} Asking {} to serve as a tunnel for {:?}.",
                self,
                dst_pub_id,
                pub_id
            );
            let tunnel_request = DirectMessage::TunnelRequest(*pub_id);
            self.send_direct_message(dst_pub_id, tunnel_request);
        }
    }

    fn handle_new_message(
        &mut self,
        pub_id: PublicId,
        bytes: Vec<u8>,
        outbox: &mut EventBox,
    ) -> Result<(), RoutingError> {
        match serialisation::deserialise(&bytes) {
            Ok(Message::Hop(hop_msg)) => self.handle_hop_message(hop_msg, pub_id),
            Ok(Message::Direct(direct_msg)) => {
                self.handle_direct_message(direct_msg, pub_id, outbox)
            }
            Ok(Message::TunnelDirect { content, src, dst }) => {
                if dst == *self.full_id.public_id() {
                    if self.tunnels.tunnel_for(&src) == Some(&pub_id) {
                        self.handle_direct_message(content, src, outbox)
                    } else {
                        debug!(
                            "{:?} Message recd via unregistered tunnel node {} from src {:?}",
                            self,
                            pub_id,
                            src
                        );
                        Err(RoutingError::InvalidDestination)
                    }
                } else if self.tunnels.has_clients(src, dst) {
                    self.send_or_drop(&dst, bytes, content.priority());
                    Ok(())
                } else if !self.peer_mgr.can_tunnel_for(&src, &dst) {
                    debug!(
                        "{:?} Can no longer accept as a tunnel node for {:?} - {:?}",
                        self,
                        src,
                        dst
                    );
                    self.send_direct_message(src, DirectMessage::TunnelClosed(dst));
                    Err(RoutingError::InvalidDestination)
                } else {
                    debug!(
                        "{:?} Invalid TunnelDirect message received via {}: {:?} -> {:?} \
                            {:?}",
                        self,
                        pub_id,
                        src,
                        dst,
                        content
                    );
                    Err(RoutingError::InvalidDestination)
                }
            }
            Ok(Message::TunnelHop { content, src, dst }) => {
                if dst == *self.full_id.public_id() {
                    self.handle_hop_message(content, src)
                } else if self.tunnels.has_clients(src, dst) {
                    self.send_or_drop(&dst, bytes, content.content.priority());
                    Ok(())
                } else {
                    debug!(
                        "{:?} Invalid TunnelHop message received via {}: {:?} -> {:?} {:?}",
                        self,
                        pub_id,
                        src,
                        dst,
                        content
                    );
                    Err(RoutingError::InvalidDestination)
                }
            }
            Err(error) => Err(RoutingError::SerialisationError(error)),
        }
    }

    // Deconstruct a `DirectMessage` and handle or forward as appropriate.
    fn handle_direct_message(
        &mut self,
        direct_message: DirectMessage,
        pub_id: PublicId,
        outbox: &mut EventBox,
    ) -> Result<(), RoutingError> {
        use messages::DirectMessage::*;
        if let Err(error) = self.check_direct_message_sender(&direct_message, &pub_id) {
            match error {
                RoutingError::ClientConnectionNotFound => (),
                _ => self.ban_and_disconnect_peer(&pub_id),
            }
            return Err(error);
        }

        match direct_message {
            MessageSignature(digest, sig) => self.handle_message_signature(digest, sig, pub_id)?,
            SectionListSignature(section_list, sig) => {
                self.handle_section_list_signature(
                    pub_id,
                    section_list,
                    sig,
                )?
            }
            BootstrapRequest(signature) => {
                if let Err(error) = self.handle_bootstrap_request(pub_id, signature, outbox) {
                    warn!(
                        "{:?} Invalid BootstrapRequest received ({:?}), dropping {}.",
                        self,
                        error,
                        pub_id
                    );
                    self.ban_and_disconnect_peer(&pub_id);
                }
            }
            CandidateInfo {
                ref old_public_id,
                ref new_public_id,
                ref signature_using_old,
                ref signature_using_new,
                ref new_client_auth,
            } => {
                if *new_public_id != pub_id {
                    error!(
                        "{:?} CandidateInfo(new_public_id: {}) does not match crust id {}.",
                        self,
                        new_public_id,
                        pub_id
                    );
                    self.disconnect_peer(&pub_id, Some(outbox));
                    return Err(RoutingError::InvalidSource);
                }
                self.handle_candidate_info(
                    old_public_id,
                    &pub_id,
                    signature_using_old,
                    signature_using_new,
                    new_client_auth,
                    outbox,
                );
            }
            TunnelRequest(dst_id) => self.handle_tunnel_request(pub_id, dst_id, outbox),
            TunnelSuccess(dst_id) => self.handle_tunnel_success(pub_id, dst_id, outbox),
            TunnelSelect(dst_id) => self.handle_tunnel_select(pub_id, dst_id),
            TunnelClosed(dst_id) => self.handle_tunnel_closed(pub_id, dst_id, outbox),
            TunnelDisconnect(dst_id) => self.handle_tunnel_disconnect(pub_id, dst_id),
            ResourceProof {
                seed,
                target_size,
                difficulty,
            } => {
                let log_ident = format!("{:?}", self);
                self.resource_prover.handle_request(
                    pub_id,
                    seed,
                    target_size,
                    difficulty,
                    log_ident,
                );
            }
            ResourceProofResponseReceipt => {
                if let Some(msg) = self.resource_prover.handle_receipt(pub_id) {
                    self.send_direct_message(pub_id, msg);
                }
            }
            ResourceProofResponse {
                part_index,
                part_count,
                proof,
                leading_zero_bytes,
            } => {
                self.handle_resource_proof_response(
                    pub_id,
                    part_index,
                    part_count,
                    proof,
                    leading_zero_bytes,
                );
            }
            msg @ BootstrapResponse(_) |
            msg @ ProxyRateLimitExceeded { .. } => {
                debug!("{:?} Unhandled direct message: {:?}", self, msg);
            }
        }
        Ok(())
    }

    /// Returns `Ok` if the peer's state indicates it's allowed to send the given message type.
    fn check_direct_message_sender(
        &self,
        direct_message: &DirectMessage,
        pub_id: &PublicId,
    ) -> Result<(), RoutingError> {
        match self.peer_mgr.get_peer(pub_id).map(Peer::state) {
            Some(&PeerState::Bootstrapper { .. }) => {
                if let DirectMessage::BootstrapRequest(_) = *direct_message {
                    return Ok(());
                }
            }
            Some(&PeerState::Client { .. }) => (),
            None => return Err(RoutingError::ClientConnectionNotFound),
            _ => return Ok(()),
        }

        debug!(
            "{:?} Illegitimate direct message {:?} from {:?}.",
            self,
            direct_message,
            pub_id
        );
        Err(RoutingError::InvalidStateForOperation)
    }

    /// Handles a signature of a `SignedMessage`, and if we have enough to verify the signed
    /// message, handles it.
    fn handle_message_signature(
        &mut self,
        digest: Digest256,
        sig: sign::Signature,
        pub_id: PublicId,
    ) -> Result<(), RoutingError> {
        if !self.peer_mgr.is_routing_peer(&pub_id) {
            debug!(
                "{:?} Received message signature from unknown peer {}",
                self,
                pub_id
            );
            return Err(RoutingError::UnknownConnection(pub_id));
        }

        let min_section_size = self.min_section_size();
        if let Some((signed_msg, route)) =
            self.sig_accumulator.add_signature(
                min_section_size,
                digest,
                sig,
                pub_id,
            )
        {
            let hop = *self.name(); // we accumulated the message, so now we act as the last hop
            self.handle_signed_message(
                signed_msg,
                route,
                hop,
                &BTreeSet::new(),
            )?;
        }
        Ok(())
    }

    fn get_section(&self, prefix: &Prefix<XorName>) -> Result<BTreeSet<XorName>, RoutingError> {
        let section = self.routing_table()
            .get_section(&prefix.lower_bound())
            .ok_or(RoutingError::InvalidSource)?
            .iter()
            .cloned()
            .collect();
        Ok(section)
    }

    fn get_section_list(&self, prefix: &Prefix<XorName>) -> Result<SectionList, RoutingError> {
        Ok(SectionList::new(
            *prefix,
            self.peer_mgr.get_pub_ids(&self.get_section(prefix)?),
        ))
    }

    /// Sends a signature for the list of members of all sections that we haven't signed yet.
    fn send_section_list_signatures(&mut self) {
        for prefix in self.routing_table().prefixes() {
            self.send_section_list_signature(prefix, None);
        }
    }

    /// Sends a signature for the list of members of a section with prefix `prefix` to our whole
    /// section if `dst` is `None`, or to the given node if it is `Some(name)`
    fn send_section_list_signature(&mut self, prefix: Prefix<XorName>, dst: Option<XorName>) {
        if cfg!(not(feature = "use-mock-crust")) {
            return;
        }
        let section = match self.get_section_list(&prefix) {
            Ok(section) => section,
            Err(err) => {
                debug!(
                    "{:?} Error getting section list for {:?}: {:?}",
                    self,
                    prefix,
                    err
                );
                return;
            }
        };
        let sig = if let Some(&sig) = self.section_list_sigs.get_signature_for(
            &prefix,
            self.full_id.public_id(),
            &section,
        )
        {
            sig
        } else {
            let serialised = match serialisation::serialise(&section) {
                Ok(serialised) => serialised,
                Err(err) => {
                    warn!(
                        "{:?} Error serialising section list for {:?}: {:?}",
                        self,
                        prefix,
                        err
                    );
                    return;
                }
            };
            let sig = sign::sign_detached(&serialised, self.full_id.signing_private_key());

            let section_len = self.routing_table().our_section().len();
            let our_id = *self.full_id.public_id();
            self.section_list_sigs.add_signature(
                prefix,
                our_id,
                section.clone(),
                sig,
                section_len,
            );
            sig
        };

        // this defines whom we are sending signature to: our section if dst is None, or given
        // name if it's Some
        let peers = if let Some(dst) = dst {
            self.peer_mgr
                .get_pub_id(&dst)
                .into_iter()
                .cloned()
                .collect_vec()
        } else {
            self.routing_table()
                .our_section()
                .into_iter()
                .filter(|&x| *x != *self.name())    // we don't want to send to ourselves
                .filter_map(|x| self.peer_mgr.get_pub_id(x))
                .cloned()
                .collect_vec()
        };

        for pub_id in peers {
            let msg = DirectMessage::SectionListSignature(section.clone(), sig);
            self.send_direct_message(pub_id, msg);
        }
    }

    fn handle_section_list_signature(
        &mut self,
        pub_id: PublicId,
        section_list: SectionList,
        sig: sign::Signature,
    ) -> Result<(), RoutingError> {
        if !self.peer_mgr.is_routing_peer(&pub_id) {
            return Err(RoutingError::InvalidSource);
        }

        let serialised = serialisation::serialise(&section_list)?;
        if sign::verify_detached(&sig, &serialised, pub_id.signing_public_key()) {
            let section_len = self.routing_table().our_section().len();
            self.section_list_sigs.add_signature(
                section_list.prefix,
                pub_id,
                section_list,
                sig,
                section_len,
            );
            Ok(())
        } else {
            Err(RoutingError::FailedSignature)
        }
    }

    fn handle_hop_message(
        &mut self,
        hop_msg: HopMessage,
        pub_id: PublicId,
    ) -> Result<(), RoutingError> {
        hop_msg.verify(pub_id.signing_public_key())?;
        let mut client_ip = None;
        let mut hop_name_result = match self.peer_mgr.get_peer(&pub_id).map(Peer::state) {
            Some(&PeerState::Bootstrapper { .. }) => {
                warn!(
                    "{:?} Hop message received from bootstrapper {:?}, disconnecting.",
                    self,
                    pub_id
                );
                Err(RoutingError::InvalidStateForOperation)
            }
            Some(&PeerState::Client { ip, .. }) => {
                client_ip = Some(ip);
                Ok(*self.name())
            }
            Some(&PeerState::JoiningNode) => Ok(*self.name()),
            Some(&PeerState::Candidate(_)) |
            Some(&PeerState::Proxy) |
            Some(&PeerState::Routing(_)) => Ok(*pub_id.name()),
            Some(&PeerState::ConnectionInfoPreparing { .. }) |
            Some(&PeerState::ConnectionInfoReady(_)) |
            Some(&PeerState::CrustConnecting) |
            Some(&PeerState::SearchingForTunnel) |
            Some(&PeerState::Connected(_)) |
            None => {
                if self.dropped_clients.contains_key(&pub_id) {
                    debug!(
                        "{:?} Ignoring {:?} from recently-disconnected client {:?}.",
                        self,
                        hop_msg,
                        pub_id
                    );
                    return Ok(());
                } else {
                    Ok(*self.name())
                    // FIXME - confirm we can return with an error here by running soak tests
                    // debug!("{:?} Invalid sender {} of {:?}", self, pub_id, hop_msg);
                    // return Err(RoutingError::InvalidSource);
                }
            }
        };

        if let Some(ip) = client_ip {
            match self.check_valid_client_message(&ip, hop_msg.content.routing_message()) {
                Ok(added_bytes) => {
                    self.proxy_load_amount += added_bytes;
                    self.peer_mgr.add_client_traffic(&pub_id, added_bytes);
                }
                Err(e) => hop_name_result = Err(e),
            }
        }

        match hop_name_result {
            Ok(hop_name) => {
                let HopMessage {
                    content,
                    route,
                    sent_to,
                    ..
                } = hop_msg;
                self.handle_signed_message(content, route, hop_name, &sent_to)
            }
            Err(RoutingError::ExceedsRateLimit(hash)) => {
                trace!(
                    "{:?} Temporarily can't proxy messages from client {:?} (rate-limit hit).",
                    self,
                    pub_id
                );
                self.send_direct_message(
                    pub_id,
                    DirectMessage::ProxyRateLimitExceeded {
                        ack: Ack::compute(hop_msg.content.routing_message())?,
                    },
                );
                Err(RoutingError::ExceedsRateLimit(hash))
            }
            Err(error) => {
                self.ban_and_disconnect_peer(&pub_id);
                Err(error)
            }
        }
    }

    // Verify the message, then, if it is for us, handle the enclosed routing message and swarm it
    // to the rest of our section when destination is targeting multiple; if not, forward it.
    fn handle_signed_message(
        &mut self,
        signed_msg: SignedMessage,
        route: u8,
        hop_name: XorName,
        sent_to: &BTreeSet<XorName>,
    ) -> Result<(), RoutingError> {
        signed_msg.check_integrity(self.min_section_size())?;

        // TODO(MAID-1677): Remove this once messages are fully validated.
        // Expect group/section messages to be sent by at least a quorum of `min_section_size`.
        if self.our_prefix().bit_count() > 0 && signed_msg.routing_message().src.is_multiple() &&
            signed_msg.src_size() * QUORUM_DENOMINATOR <=
                self.min_section_size() * QUORUM_NUMERATOR
        {
            warn!("{:?} Not enough signatures in {:?}.", self, signed_msg);
            return Err(RoutingError::NotEnoughSignatures);
        }

        match self.routing_msg_filter.filter_incoming(
            signed_msg.routing_message(),
            route,
        ) {
            FilteringResult::KnownMessageAndRoute => {
                return Ok(());
            }
            frslt @ FilteringResult::KnownMessage |
            frslt @ FilteringResult::NewMessage => {
                if self.in_authority(&signed_msg.routing_message().dst) {
                    self.send_ack(signed_msg.routing_message(), route);
                    if signed_msg.routing_message().dst.is_multiple() {
                        // Broadcast to the rest of the section.
                        if let Err(error) = self.send_signed_message(
                            &signed_msg,
                            route,
                            &hop_name,
                            sent_to,
                        )
                        {
                            debug!("{:?} Failed to send {:?}: {:?}", self, signed_msg, error);
                        }
                    }
                    if frslt == FilteringResult::NewMessage {
                        // if addressed to us, then we just queue it and return
                        self.msg_queue.push_back(signed_msg.into_routing_message());
                    }
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

    fn dispatch_routing_message(
        &mut self,
        routing_msg: RoutingMessage,
        outbox: &mut EventBox,
    ) -> Result<(), RoutingError> {
        use messages::MessageContent::*;
        use Authority::{Client, ManagedNode, PrefixSection, Section};

        if !self.is_approved {
            match routing_msg.content {
                SectionSplit(..) |
                OwnSectionMerge(..) |
                OtherSectionMerge(..) |
                ExpectCandidate { .. } |
                AcceptAsCandidate { .. } |
                CandidateApproval { .. } |
                SectionUpdate { .. } |
                UserMessagePart { .. } => {
                    // These messages should not be handled before node approval
                    trace!(
                        "{:?} Not approved yet. Delaying message handling: {:?}",
                        self,
                        routing_msg
                    );
                    self.routing_msg_backlog.push(routing_msg);
                    return Ok(());
                }
                ConnectionInfoRequest { .. } => {
                    if !self.joining_prefix.matches(&routing_msg.src.name()) {
                        // Doesn't allow other node connect to us before node approval
                        trace!(
                            "{:?} Not approved yet. Delaying message handling: {:?}",
                            self,
                            routing_msg
                        );
                        self.routing_msg_backlog.push(routing_msg);
                        return Ok(());
                    }
                }
                Relocate { .. } |
                ConnectionInfoResponse { .. } |
                RelocateResponse { .. } |
                Ack(..) |
                NodeApproval { .. } => {
                    // Handle like normal
                }
            }
        }

        match routing_msg.content {
            Ack(..) |
            UserMessagePart { .. } => (),
            _ => trace!("{:?} Got routing message {:?}.", self, routing_msg),
        }

        match (routing_msg.content, routing_msg.src, routing_msg.dst) {
            (Relocate { message_id },
             Client {
                 client_id,
                 proxy_node_name,
             },
             Section(dst_name)) => {
                self.handle_relocate_request(client_id, proxy_node_name, dst_name, message_id)
            }
            (ExpectCandidate {
                 old_public_id,
                 old_client_auth,
                 message_id,
             },
             Section(_),
             relocation_dst @ Section(_)) => {
                self.handle_expect_candidate(
                    old_public_id,
                    old_client_auth,
                    relocation_dst,
                    message_id,
                    outbox,
                )
            }
            (AcceptAsCandidate {
                 old_public_id,
                 old_client_auth,
                 target_interval,
                 message_id,
             },
             Section(_),
             dst @ Section(_)) => {
                self.handle_accept_as_candidate(
                    old_public_id,
                    old_client_auth,
                    dst,
                    target_interval,
                    message_id,
                    outbox,
                )
            }
            (ConnectionInfoRequest {
                 encrypted_conn_info,
                 nonce,
                 pub_id,
                 msg_id,
             },
             src @ Client { .. },
             dst @ ManagedNode(_)) |
            (ConnectionInfoRequest {
                 encrypted_conn_info,
                 nonce,
                 pub_id,
                 msg_id,
             },
             src @ ManagedNode(_),
             dst @ ManagedNode(_)) => {
                self.handle_connection_info_request(
                    encrypted_conn_info,
                    nonce,
                    pub_id,
                    msg_id,
                    src,
                    dst,
                    outbox,
                )
            }
            (ConnectionInfoResponse {
                 encrypted_conn_info,
                 nonce,
                 pub_id,
                 msg_id,
             },
             ManagedNode(src_name),
             dst @ Client { .. }) |
            (ConnectionInfoResponse {
                 encrypted_conn_info,
                 nonce,
                 pub_id,
                 msg_id,
             },
             ManagedNode(src_name),
             dst @ ManagedNode(_)) => {
                self.handle_connection_info_response(
                    encrypted_conn_info,
                    nonce,
                    pub_id,
                    msg_id,
                    src_name,
                    dst,
                )
            }
            (CandidateApproval {
                 new_public_id,
                 new_client_auth,
                 ..
             },
             Section(_),
             Section(_)) => self.handle_candidate_approval(new_public_id, new_client_auth, outbox),
            (NodeApproval { sections }, Section(_), Client { .. }) => {
                self.handle_node_approval(&sections, outbox)
            }
            (SectionUpdate {
                 versioned_prefix,
                 members,
             },
             Section(_),
             PrefixSection(_)) => self.handle_section_update(versioned_prefix, members, outbox),
            (SectionSplit(ver_pfx, joining_node), PrefixSection(_), PrefixSection(_)) => {
                self.handle_section_split(ver_pfx, joining_node, outbox)
            }
            (OwnSectionMerge(sections),
             PrefixSection(sender_prefix),
             PrefixSection(merge_prefix)) => {
                self.handle_own_section_merge(sender_prefix, merge_prefix, sections, outbox)
            }
            (OtherSectionMerge(section, version),
             PrefixSection(merge_prefix),
             PrefixSection(_)) => {
                self.handle_other_section_merge(merge_prefix.with_version(version), section, outbox)
            }
            (Ack(ack, _), _, _) => self.handle_ack_response(ack),
            (UserMessagePart {
                 hash,
                 part_count,
                 part_index,
                 payload,
                 ..
             },
             src,
             dst) => {
                self.stats.increase_user_msg_part();
                if let Some(msg) = self.user_msg_cache.add(
                    hash,
                    part_count,
                    part_index,
                    payload,
                )
                {
                    self.stats().count_user_message(&msg);
                    outbox.send_event(msg.into_event(src, dst));
                }
                Ok(())
            }
            (content, src, dst) => {
                debug!(
                    "{:?} Unhandled routing message {:?} from {:?} to {:?}",
                    self,
                    content,
                    src,
                    dst
                );
                Err(RoutingError::BadAuthority)
            }
        }
    }

    fn handle_candidate_approval(
        &mut self,
        new_pub_id: PublicId,
        new_client_auth: Authority<XorName>,
        outbox: &mut EventBox,
    ) -> Result<(), RoutingError> {
        self.remove_expired_peers(outbox);

        // Once the joining node joined, it may receive the vote regarding itself.
        // Or a node may receive CandidateApproval before connection established.
        // If we are not connected to the candidate, we do not want to add them
        // to our RT.
        // This will flag peer as valid if its found in peer_mgr regardless of their
        // connection status to us.
        let is_connected = match self.peer_mgr.handle_candidate_approval(&new_pub_id) {
            Ok(is_connected) => is_connected.is_some(),
            Err(_) => {
                let src = Authority::ManagedNode(*self.name());
                if let Err(error) = self.send_connection_info_request(
                    new_pub_id,
                    src,
                    new_client_auth,
                    outbox,
                    ReconnectingPeer::False,
                )
                {
                    debug!(
                        "{:?} - Failed to send connection info to {}: {:?}",
                        self,
                        new_pub_id,
                        error
                    );
                }
                false
            }
        };

        info!(
            "{:?} Our section with {:?} has approved candidate {}.",
            self,
            self.our_prefix(),
            new_pub_id
        );
        if self.we_want_to_merge() || self.they_want_to_merge() {
            debug!(
                "{:?} Not sending NodeApproval since our section is currently merging.",
                self
            );
        } else if !self.routing_table().check_invariant(false, false).is_ok() {
            debug!(
                "{:?} Not sending NodeApproval since our routing table isn't valid.",
                self
            );
        } else {
            let src = Authority::Section(*new_pub_id.name());
            // Send the _current_ routing table. If this doesn't accumulate, we expect the candidate
            // to disconnect from us.
            let content = MessageContent::NodeApproval { sections: self.peer_mgr.ideal_rt() };
            if let Err(error) = self.send_routing_message(src, new_client_auth, content) {
                debug!(
                    "{:?} Failed sending NodeApproval to {}: {:?}",
                    self,
                    new_pub_id,
                    error
                );
            }
        }

        if is_connected {
            self.add_to_routing_table(&new_pub_id, outbox);
        }
        Ok(())
    }

    fn handle_node_approval(
        &mut self,
        sections: &SectionMap,
        outbox: &mut EventBox,
    ) -> Result<(), RoutingError> {
        if self.is_approved {
            warn!("{:?} Received duplicate NodeApproval.", self);
            return Ok(());
        }

        let mapped_sections = sections
            .iter()
            .map(|(ver_pfx, section)| {
                let names: BTreeSet<XorName> =
                    section.iter().map(|pub_id| *pub_id.name()).collect();
                (*ver_pfx.prefix(), names)
            })
            .collect();
        if let Err(error) = self.routing_table().check_node_approval_msg(
            mapped_sections,
        )
        {
            info!(
                "{:?} Received invalid sections in NodeApproval: {:?}. Restarting.",
                self,
                error
            );
            outbox.send_event(Event::RestartRequired);
            return Err(From::from(error));
        }

        self.resource_prover.handle_approval();

        if let Err(error) = self.peer_mgr.add_prefixes(
            sections.keys().cloned().collect(),
        )
        {
            info!(
                "{:?} Received invalid prefixes in NodeApproval: {:?}. Restarting.",
                self,
                error
            );
            outbox.send_event(Event::RestartRequired);
            return Err(error);
        }

        self.is_approved = true;
        outbox.send_event(Event::Connected);
        for name in self.routing_table().iter() {
            // TODO: try to remove this as safe_core/safe_vault may not require this notification
            outbox.send_event(Event::NodeAdded(*name, self.routing_table().clone()));
        }

        let our_prefix = *self.our_prefix();
        self.send_section_list_signature(our_prefix, None);

        for section in sections.values() {
            for pub_id in section.iter() {
                if !self.routing_table().has(pub_id.name()) {
                    debug!(
                        "{:?} Sending connection info to {:?} on NodeApproval.",
                        self,
                        pub_id
                    );
                    let src = Authority::ManagedNode(*self.name());
                    let node_auth = Authority::ManagedNode(*pub_id.name());
                    if let Err(error) = self.send_connection_info_request(
                        *pub_id,
                        src,
                        node_auth,
                        outbox,
                        ReconnectingPeer::False,
                    )
                    {
                        debug!(
                            "{:?} - Failed to send connection info to {:?}: {:?}",
                            self,
                            pub_id,
                            error
                        );
                    }
                }
            }
        }

        info!(
            "{:?} Resource proof challenges completed. This node has been approved to join the \
               network!",
            self
        );
        trace!(
            "{:?} Node approval completed. Prefixes: {:?}",
            self,
            self.routing_table().prefixes()
        );

        // Allow other peers to bootstrap via us.
        if let Err(err) = self.crust_service.set_accept_bootstrap(true) {
            warn!(
                "{:?} Unable to accept bootstrap connections. {:?}",
                self,
                err
            );
        }
        self.crust_service.set_service_discovery_listen(true);

        self.print_rt_size();
        self.stats.enable_logging();

        let backlog = mem::replace(&mut self.routing_msg_backlog, vec![]);
        backlog.into_iter().rev().foreach(|msg| {
            self.msg_queue.push_front(msg)
        });
        self.reset_su_timer();
        self.candidate_status_token = Some(self.timer.schedule(Duration::from_secs(
            CANDIDATE_STATUS_INTERVAL_SECS,
        )));
        Ok(())
    }

    fn handle_resource_proof_response(
        &mut self,
        pub_id: PublicId,
        part_index: usize,
        part_count: usize,
        proof: Vec<u8>,
        leading_zero_bytes: u64,
    ) {
        if self.candidate_timer_token.is_none() {
            debug!(
                "{:?} Won't handle resource proof response from {:?} - not currently waiting.",
                self,
                pub_id
            );
            return;
        }

        match self.peer_mgr.verify_candidate(
            &pub_id,
            part_index,
            part_count,
            proof,
            leading_zero_bytes,
        ) {
            Err(error) => {
                debug!(
                    "{:?} Failed to verify candidate {}: {:?}",
                    self,
                    pub_id,
                    error
                );
            }
            Ok(None) => {
                self.send_direct_message(pub_id, DirectMessage::ResourceProofResponseReceipt);
            }
            Ok(Some((target_size, difficulty, elapsed)))
                if difficulty == 0 && target_size < 1000 => {
                // Small tests don't require waiting for synchronisation. Send approval now.
                info!(
                    "{:?} Candidate {} passed our challenge in {}. Sending approval \
                       to our section with {:?}.",
                    self,
                    pub_id,
                    elapsed.display_secs(),
                    self.our_prefix()
                );
                // We set the timer token to None so we do not send another
                // CandidateApproval when the token fires
                self.candidate_timer_token = None;
                self.send_candidate_approval();
            }
            Ok(Some((_, _, elapsed))) => {
                info!(
                    "{:?} Candidate {} passed our challenge in {}. Waiting to send approval to \
                       our section with {:?}.",
                    self,
                    pub_id,
                    elapsed.display_secs(),
                    self.our_prefix()
                );
            }
        }
    }

    /// Returns `Ok` with rate_limiter charged size if client is allowed to send the given message.
    fn check_valid_client_message(
        &mut self,
        ip: &IpAddr,
        msg: &RoutingMessage,
    ) -> Result<u64, RoutingError> {
        match (&msg.src, &msg.content) {
            (&Authority::Client { .. },
             &MessageContent::UserMessagePart {
                 ref hash,
                 ref msg_id,
                 ref part_count,
                 ref part_index,
                 ref priority,
                 ref payload,
                 ..
             })
                if *part_count <= MAX_PARTS && part_index < part_count &&
                       *priority >= DEFAULT_PRIORITY &&
                       payload.len() <= MAX_PART_LEN => {
                self.clients_rate_limiter.add_message(
                    ip,
                    hash,
                    msg_id,
                    *part_count,
                    *part_index,
                    payload,
                )
            }
            _ => {
                debug!(
                    "{:?} Illegitimate client message {:?}. Refusing to relay.",
                    self,
                    msg
                );
                Err(RoutingError::RejectedClientMessage)
            }
        }
    }

    fn correct_rate_limits(&mut self, ip: &IpAddr, msg: &RoutingMessage) -> Option<u64> {
        if let MessageContent::UserMessagePart {
            ref msg_id,
            part_count,
            part_index,
            ref payload,
            ..
        } = msg.content
        {
            self.clients_rate_limiter.apply_refund_for_response(
                ip,
                msg_id,
                part_count,
                part_index,
                payload,
            )
        } else {
            None
        }
    }

    fn respond_from_cache(
        &mut self,
        routing_msg: &RoutingMessage,
        route: u8,
    ) -> Result<bool, RoutingError> {
        if let MessageContent::UserMessagePart {
            hash,
            part_count,
            part_index,
            cacheable,
            ref payload,
            ..
        } = routing_msg.content
        {
            if !cacheable {
                return Ok(false);
            }

            match self.cacheable_user_msg_cache.add(
                hash,
                part_count,
                part_index,
                payload.clone(),
            ) {
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

    // If this returns an error, the peer will be dropped.
    fn handle_bootstrap_request(
        &mut self,
        pub_id: PublicId,
        signature: sign::Signature,
        outbox: &mut EventBox,
    ) -> Result<(), RoutingError> {
        self.remove_expired_peers(outbox);

        let peer_kind = if let Some(peer) = self.peer_mgr.get_peer(&pub_id) {
            match *peer.state() {
                PeerState::Bootstrapper { peer_kind, .. } => peer_kind,
                _ => {
                    return Err(RoutingError::InvalidStateForOperation);
                }
            }
        } else {
            return Err(RoutingError::UnknownConnection(pub_id));
        };

        if peer_kind == CrustUser::Client {
            let ip = self.crust_service.get_peer_ip_addr(&pub_id).map_err(
                |err| {
                    debug!(
                        "{:?} Can't get IP address of bootstrapper {:?} : {:?}",
                        self,
                        pub_id,
                        err
                    );
                    self.disconnect_peer(&pub_id, None);
                    err
                },
            )?;

            if !self.peer_mgr.can_accept_client(ip) {
                debug!(
                    "{:?} Client {:?} rejected: We cannot accept more clients.",
                    self,
                    pub_id
                );
                self.send_direct_message(
                    pub_id,
                    DirectMessage::BootstrapResponse(Err(BootstrapResponseError::ClientLimit)),
                );
                self.disconnect_peer(&pub_id, None);
                return Ok(());
            }
        }

        let ser_pub_id = serialisation::serialise(&pub_id)?;
        if !sign::verify_detached(&signature, &ser_pub_id, pub_id.signing_public_key()) {
            return Err(RoutingError::FailedSignature);
        }

        if !self.is_approved {
            debug!(
                "{:?} Client {:?} rejected: We are not approved as a node yet.",
                self,
                pub_id
            );
            self.send_direct_message(
                pub_id,
                DirectMessage::BootstrapResponse(Err(BootstrapResponseError::NotApproved)),
            );
            self.disconnect_peer(&pub_id, Some(outbox));
            return Ok(());
        }

        if (peer_kind == CrustUser::Client || !self.is_first_node) &&
            self.routing_table().len() < self.min_section_size() - 1
        {
            debug!(
                "{:?} Client {:?} rejected: Routing table has {} entries. {} required.",
                self,
                pub_id,
                self.routing_table().len(),
                self.min_section_size() - 1
            );
            self.send_direct_message(
                pub_id,
                DirectMessage::BootstrapResponse(Err(BootstrapResponseError::TooFewPeers)),
            );
            self.disconnect_peer(&pub_id, Some(outbox));
            return Ok(());
        }

        self.peer_mgr.handle_bootstrap_request(&pub_id);
        let _ = self.dropped_clients.remove(&pub_id);
        self.send_direct_message(pub_id, DirectMessage::BootstrapResponse(Ok(())));
        Ok(())
    }

    #[cfg_attr(feature = "cargo-clippy", allow(too_many_arguments))]
    fn handle_candidate_info(
        &mut self,
        old_pub_id: &PublicId,
        new_pub_id: &PublicId,
        signature_using_old: &sign::Signature,
        signature_using_new: &sign::Signature,
        new_client_auth: &Authority<XorName>,
        outbox: &mut EventBox,
    ) {
        debug!(
            "{:?} Handling CandidateInfo from {}->{}.",
            self,
            old_pub_id,
            new_pub_id
        );
        if !self.is_candidate_info_valid(
            old_pub_id,
            new_pub_id,
            signature_using_old,
            signature_using_new,
        )
        {
            warn!(
                "{:?} Signature check failed in CandidateInfo, so dropping peer {:?}.",
                self,
                new_pub_id
            );
            self.disconnect_peer(new_pub_id, Some(outbox));
        }

        // If this is a valid node in peer_mgr but the Candidate has sent us a CandidateInfo, it
        // might have not yet handled its NodeApproval message. Check and handle accordingly here
        if self.peer_mgr.get_peer(new_pub_id).map_or(
            false,
            |peer| peer.valid(),
        )
        {
            self.process_connection(*new_pub_id, outbox);
            return;
        }

        let (difficulty, target_size) = if self.disable_resource_proof ||
            self.crust_service.is_peer_hard_coded(new_pub_id) ||
            self.peer_mgr.is_joining_node(new_pub_id)
        {
            (0, 1)
        } else {
            (
                RESOURCE_PROOF_DIFFICULTY,
                RESOURCE_PROOF_TARGET_SIZE / (self.routing_table().our_section().len() + 1),
            )
        };
        let seed: Vec<u8> = if cfg!(feature = "use-mock-crust") {
            vec![5u8; 4]
        } else {
            rand::thread_rng().gen_iter().take(10).collect()
        };
        match self.peer_mgr.handle_candidate_info(
            old_pub_id,
            new_pub_id,
            new_client_auth,
            target_size,
            difficulty,
            seed.clone(),
        ) {
            Ok(true) => {
                let direct_message = DirectMessage::ResourceProof {
                    seed: seed,
                    target_size: target_size,
                    difficulty: difficulty,
                };
                info!(
                    "{:?} Sending resource proof challenge to candidate {}->{}",
                    self,
                    old_pub_id,
                    new_pub_id
                );
                self.send_direct_message(*new_pub_id, direct_message);
            }
            Ok(false) => {
                info!(
                    "{:?} Adding candidate {}->{} to routing table without sending resource \
                       proof challenge as section has already approved it.",
                    self,
                    old_pub_id,
                    new_pub_id
                );
                self.add_to_routing_table(new_pub_id, outbox);
            }
            Err(RoutingError::CandidateIsTunnelling) => {
                debug!(
                    "{:?} handling a tunnelling candidate {}->{}",
                    self,
                    old_pub_id,
                    new_pub_id
                );
            }
            Err(error) => {
                debug!(
                    "{:?} Ignore CandidateInfo {}->{}: {:?}.",
                    self,
                    old_pub_id,
                    new_pub_id,
                    error
                );
            }
        }
    }

    fn is_candidate_info_valid(
        &self,
        old_pub_id: &PublicId,
        new_pub_id: &PublicId,
        signature_using_old: &sign::Signature,
        signature_using_new: &sign::Signature,
    ) -> bool {
        let old_and_new_pub_ids = (old_pub_id, new_pub_id);
        let mut signed_data = match serialisation::serialise(&old_and_new_pub_ids) {
            Ok(result) => result,
            Err(error) => {
                error!("Failed to serialise public IDs: {:?}", error);
                return false;
            }
        };
        if !sign::verify_detached(
            signature_using_old,
            &signed_data,
            old_pub_id.signing_public_key(),
        )
        {
            debug!(
                "{:?} CandidateInfo from {}->{} has invalid old signature.",
                self,
                old_pub_id,
                new_pub_id
            );
            return false;
        }
        signed_data.extend_from_slice(&signature_using_old.0);
        if !sign::verify_detached(
            signature_using_new,
            &signed_data,
            new_pub_id.signing_public_key(),
        )
        {
            debug!(
                "{:?} CandidateInfo from {}->{} has invalid new signature.",
                self,
                old_pub_id,
                new_pub_id
            );
            return false;
        }
        true
    }

    fn add_to_routing_table(&mut self, pub_id: &PublicId, outbox: &mut EventBox) {
        match self.peer_mgr.add_to_routing_table(pub_id) {
            Err(RoutingError::RoutingTable(RoutingTableError::AlreadyExists)) => return,
            Err(error) => {
                debug!(
                    "{:?} Peer {:?} was not added to the routing table: {:?}",
                    self,
                    pub_id,
                    error
                );
                self.disconnect_peer(pub_id, Some(outbox));
                return;
            }
            Ok(()) => (),
        }
        if !self.we_want_to_merge() && !self.they_want_to_merge() &&
            self.routing_table().should_split()
        {
            // i.e. the section should split
            let our_ver_pfx = self.routing_table().our_versioned_prefix();
            // In the future we'll look to remove this restriction so we always call
            // `send_section_split()` here and also check whether another round of splitting is
            // required in `handle_section_split()` so splitting becomes recursive like merging.
            if our_ver_pfx.prefix().matches(pub_id.name()) {
                self.send_section_split(our_ver_pfx, *pub_id.name());
            }
        } else {
            self.merge_if_necessary(outbox);
        }

        info!("{:?} Added {} to routing table.", self, pub_id);
        if self.is_first_node && self.routing_table().len() == 1 {
            trace!(
                "{:?} Node approval completed. Prefixes: {:?}",
                self,
                self.routing_table().prefixes()
            );
            outbox.send_event(Event::Connected);
        }

        if self.is_approved {
            outbox.send_event(Event::NodeAdded(
                *pub_id.name(),
                self.routing_table().clone(),
            ));

            if let Some(prefix) = self.routing_table().find_section_prefix(pub_id.name()) {
                self.send_section_list_signature(prefix, None);
                if prefix == *self.our_prefix() {
                    self.send_section_update(None, false);
                    self.reset_su_timer();
                    // if the node joined our section, send signatures for all section lists to it
                    for pfx in self.routing_table().prefixes() {
                        self.send_section_list_signature(pfx, Some(*pub_id.name()));
                    }
                } else {
                    self.send_section_update(Some(prefix), false);
                }
            }
        }

        for dst_id in self.peer_mgr.peers_needing_tunnel() {
            if self.peer_mgr.is_potential_tunnel_node(
                pub_id.name(),
                dst_id.name(),
            )
            {
                trace!(
                    "{:?} Asking {:?} to serve as a tunnel for {:?}",
                    self,
                    pub_id,
                    dst_id
                );
                let tunnel_request = DirectMessage::TunnelRequest(dst_id);
                self.send_direct_message(*pub_id, tunnel_request);
            }
        }
    }

    /// Informs our peers that our section's member list changed. If `dst_prefix` is `Some`, only
    /// tells that section, otherwise tells all connected sections, including our own.
    fn send_section_update(
        &mut self,
        dst_prefix: Option<Prefix<XorName>>,
        allow_small_sections: bool,
    ) {
        if dst_prefix.is_none() &&
            !self.routing_table()
                .check_invariant(allow_small_sections, false)
                .is_ok()
        {
            warn!(
                "{:?} Not sending section update since RT invariant not held.",
                self
            );
            return;
        } else if self.they_want_to_merge() || self.we_want_to_merge() {
            trace!(
                "{:?} Not sending section update since we are in the process of merging.",
                self
            );
            return;
        }

        let members = self.peer_mgr.get_pub_ids(
            self.routing_table().our_section(),
        );

        let content = MessageContent::SectionUpdate {
            versioned_prefix: self.routing_table().our_versioned_prefix(),
            members: members,
        };

        let prefixes = match dst_prefix {
            Some(prefix) => iter::once(prefix).collect(),
            None => self.routing_table().prefixes(),
        };

        trace!("{:?} Sending section update to {:?}", self, prefixes);

        for pfx in prefixes {
            let src = Authority::Section(self.our_prefix().lower_bound());
            let dst = Authority::PrefixSection(pfx);

            if let Err(err) = self.send_routing_message(src, dst, content.clone()) {
                debug!(
                    "{:?} Failed to send section update to {:?}: {:?}",
                    self,
                    pfx,
                    err
                );
            }
        }
    }

    // If `msg_id` is `Some` this is sent as a response, otherwise as a request.
    fn send_connection_info(
        &mut self,
        our_pub_info: PubConnectionInfo,
        their_pub_id: PublicId,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        msg_id: Option<MessageId>,
    ) {
        let encoded_connection_info = match serialisation::serialise(&our_pub_info) {
            Ok(encoded_connection_info) => encoded_connection_info,
            Err(err) => {
                debug!(
                    "{:?} Failed to serialise connection info for {:?}: {:?}.",
                    self,
                    their_pub_id,
                    err
                );
                return;
            }
        };
        let nonce = box_::gen_nonce();
        let encrypted_conn_info = box_::seal(
            &encoded_connection_info,
            &nonce,
            their_pub_id.encrypting_public_key(),
            self.full_id.encrypting_private_key(),
        );
        let msg_content = if let Some(msg_id) = msg_id {
            MessageContent::ConnectionInfoResponse {
                encrypted_conn_info: encrypted_conn_info,
                nonce: nonce.0,
                pub_id: *self.full_id.public_id(),
                msg_id: msg_id,
            }
        } else {
            MessageContent::ConnectionInfoRequest {
                encrypted_conn_info: encrypted_conn_info,
                nonce: nonce.0,
                pub_id: *self.full_id.public_id(),
                msg_id: MessageId::new(),
            }
        };

        if let Err(err) = self.send_routing_message(src, dst, msg_content) {
            debug!(
                "{:?} Failed to send connection info for {:?}: {:?}.",
                self,
                their_pub_id,
                err
            );
        }
    }

    fn handle_connection_info_prepared(
        &mut self,
        result_token: u32,
        result: Result<PrivConnectionInfo, CrustError>,
    ) {
        let our_connection_info = match result {
            Err(err) => {
                error!(
                    "{:?} Failed to prepare connection info: {:?}. Retrying.",
                    self,
                    err
                );
                let new_token = match self.peer_mgr.get_new_connection_info_token(result_token) {
                    Err(error) => {
                        debug!(
                            "{:?} Failed to prepare connection info, but no entry found in \
                               token map: {:?}",
                            self,
                            error
                        );
                        return;
                    }
                    Ok(new_token) => new_token,
                };
                self.crust_service.prepare_connection_info(new_token);
                return;
            }
            Ok(connection_info) => connection_info,
        };

        let our_pub_info = our_connection_info.to_pub_connection_info();
        match self.peer_mgr.connection_info_prepared(
            result_token,
            our_connection_info,
        ) {
            Err(error) => {
                // This usually means we have already connected.
                debug!(
                    "{:?} Prepared connection info, but no entry found in token map: {:?}",
                    self,
                    error
                );
                return;
            }
            Ok(ConnectionInfoPreparedResult {
                   pub_id,
                   src,
                   dst,
                   infos,
               }) => {
                match infos {
                    None => {
                        debug!("{:?} Prepared connection info for {:?}.", self, pub_id);
                        self.send_connection_info(our_pub_info, pub_id, src, dst, None);
                    }
                    Some((our_info, their_info, msg_id)) => {
                        debug!(
                            "{:?} Trying to connect to {:?} as {:?}.",
                            self,
                            their_info.id(),
                            pub_id
                        );
                        self.send_connection_info(our_pub_info, pub_id, src, dst, Some(msg_id));
                        if let Err(error) = self.crust_service.connect(our_info, their_info) {
                            trace!("{:?} Unable to connect to {:?} - {:?}", self, pub_id, error);
                        }
                    }
                }
            }
        }
    }

    #[cfg_attr(feature = "cargo-clippy", allow(too_many_arguments))]
    fn handle_connection_info_request(
        &mut self,
        encrypted_connection_info: Vec<u8>,
        nonce_bytes: [u8; box_::NONCEBYTES],
        pub_id: PublicId,
        message_id: MessageId,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        outbox: &mut EventBox,
    ) -> Result<(), RoutingError> {
        self.peer_mgr.allow_connect(pub_id.name())?;
        let their_connection_info = self.decrypt_connection_info(
            &encrypted_connection_info,
            &box_::Nonce(nonce_bytes),
            &pub_id,
        )?;
        if pub_id != their_connection_info.id() {
            debug!(
                "{:?} PublicId of the sender {} does not match the id mentioned in the message \
                   {}.",
                self,
                pub_id,
                their_connection_info.id()
            );
            return Err(RoutingError::InvalidPeer);
        }

        use peer_manager::ConnectionInfoReceivedResult::*;
        match self.peer_mgr.connection_info_received(
            src,
            dst,
            their_connection_info,
            message_id,
            true,
        ) {
            Ok(Ready(our_info, their_info)) => {
                debug!(
                    "{:?} Already sent a connection info request to {}; resending \
                        our same details as a response.",
                    self,
                    pub_id
                );
                self.send_connection_info(
                    our_info.to_pub_connection_info(),
                    pub_id,
                    dst,
                    src,
                    Some(message_id),
                );
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
                // TODO: we should not be getting conn info req from Proxy/JoiningNode

                log_or_panic!(
                    Level::Error,
                    "{:?} Received ConnectionInfoRequest from peer {} \
                              with invalid state.",
                    self,
                    pub_id
                );
                if self.peer_mgr.get_peer(&pub_id).map_or(false, Peer::valid) {
                    self.process_connection(pub_id, outbox);
                }
            }
            Ok(Waiting) | Ok(IsConnected) | Err(_) => (),
        }
        Ok(())
    }

    fn handle_connection_info_response(
        &mut self,
        encrypted_connection_info: Vec<u8>,
        nonce_bytes: [u8; box_::NONCEBYTES],
        public_id: PublicId,
        message_id: MessageId,
        src: XorName,
        dst: Authority<XorName>,
    ) -> Result<(), RoutingError> {
        self.peer_mgr.allow_connect(&src)?;
        if self.peer_mgr.get_peer(&public_id).is_none() {
            return Err(RoutingError::InvalidDestination);
        }

        let their_connection_info = self.decrypt_connection_info(
            &encrypted_connection_info,
            &box_::Nonce(nonce_bytes),
            &public_id,
        )?;
        if public_id != their_connection_info.id() {
            debug!(
                "{:?} PublicId of the sender {} does not match the id mentioned in the message \
                   {}.",
                self,
                public_id,
                their_connection_info.id()
            );
            return Err(RoutingError::InvalidPeer);
        }

        use peer_manager::ConnectionInfoReceivedResult::*;
        match self.peer_mgr.connection_info_received(
            Authority::ManagedNode(src),
            dst,
            their_connection_info,
            message_id,
            false,
        ) {
            Ok(Ready(our_info, their_info)) => {
                trace!(
                    "{:?} Received connection info response. Trying to connect to {}.",
                    self,
                    public_id
                );
                if let Err(error) = self.crust_service.connect(our_info, their_info) {
                    trace!(
                        "{:?} Unable to connect to {:?} - {:?}",
                        self,
                        public_id,
                        error
                    );
                }
            }
            Ok(Prepare(_)) |
            Ok(IsProxy) |
            Ok(IsClient) |
            Ok(IsJoiningNode) => {
                debug!(
                    "{:?} Received connection info response from {} when we haven't \
                      sent a corresponding request",
                    self,
                    public_id
                );
            }
            Ok(Waiting) | Ok(IsConnected) | Err(_) => (),
        }
        Ok(())
    }

    /// Handles a request by `src_id` to act as a tunnel connecting it with `dst_id`.
    fn handle_tunnel_request(&mut self, srd_id: PublicId, dst_id: PublicId, outbox: &mut EventBox) {
        self.remove_expired_peers(outbox);
        if self.peer_mgr.can_tunnel_for(&srd_id, &dst_id) {
            if let Some((id0, id1)) = self.tunnels.consider_clients(srd_id, dst_id) {
                debug!(
                    "{:?} Accepted tunnel request from {} for {}.",
                    self,
                    srd_id,
                    dst_id
                );
                self.send_direct_message(id0, DirectMessage::TunnelSuccess(id1));
            }
        } else {
            debug!(
                "{:?} Rejected tunnel request from {} for {}.",
                self,
                srd_id,
                dst_id
            );
        }
    }

    /// Handles a `TunnelSuccess` response from `pub_id`: It will act as a tunnel to `dst_id`.
    fn handle_tunnel_success(
        &mut self,
        tunnel_id: PublicId,
        dst_id: PublicId,
        outbox: &mut EventBox,
    ) {
        self.remove_expired_peers(outbox);
        if let Some(current_tunnel_id) = self.tunnels.tunnel_for(&dst_id) {
            if *current_tunnel_id == tunnel_id {
                return; // duplicate `TunnelSuccess`
            }
        };

        let can_tunnel_for = |peer: &Peer| peer.state().can_tunnel_for();
        if self.peer_mgr.get_peer(&tunnel_id).map_or(
            false,
            can_tunnel_for,
        ) && self.tunnels.add(dst_id, tunnel_id) &&
            self.peer_mgr.tunnelling_to(&dst_id)
        {
            debug!(
                "{:?} Adding {:?} as a tunnel node for {:?}.",
                self,
                tunnel_id,
                dst_id
            );
            if self.id() < &dst_id {
                // We need to confirm tunnel selection
                let message = DirectMessage::TunnelSelect(dst_id);
                self.send_direct_message(tunnel_id, message);
            }
            self.process_connection(dst_id, outbox);
        } else {
            debug!(
                "{:?} Rejecting TunnelSuccess from {:?} for peer {:?}",
                self,
                tunnel_id,
                dst_id
            );
            let _ = self.tunnels.remove(dst_id, tunnel_id);
            let message = DirectMessage::TunnelDisconnect(dst_id);
            self.send_direct_message(tunnel_id, message);
        }
    }

    /// Handles a `TunnelSelect` message from `src`: `dst`.
    fn handle_tunnel_select(&mut self, src: PublicId, dst: PublicId) {
        if src < dst && self.peer_mgr.can_tunnel_for(&src, &dst) &&
            self.tunnels.accept_clients(src, dst)
        {
            debug!(
                "{:?} Agreed to act as tunnel node for {:?} - {:?}",
                self,
                src,
                dst
            );
            self.send_direct_message(dst, DirectMessage::TunnelSuccess(src));
        } else {
            debug!("{:?} Rejecting TunnelSelect from {} - {}.", self, src, dst);
            let message = DirectMessage::TunnelClosed(dst);
            self.send_direct_message(src, message);
        }
    }

    /// Handles a `TunnelClosed` message from `src_id`: `dst_id` disconnected.
    fn handle_tunnel_closed(&mut self, src_id: PublicId, dst_id: PublicId, outbox: &mut EventBox) {
        if self.tunnels.remove(dst_id, src_id) {
            debug!("{:?} Tunnel to {} via {} closed.", self, dst_id, src_id);
            if !self.crust_service.is_connected(&dst_id) {
                let _ = self.dropped_peer(&dst_id, outbox, true);
            }
        }
    }

    /// Handles a `TunnelDisconnect` message from `src_id` who wants to disconnect `dst_id`.
    fn handle_tunnel_disconnect(&mut self, src_id: PublicId, dst_id: PublicId) {
        if self.tunnels.drop_client_pair(dst_id, src_id) {
            debug!(
                "{:?} Closing tunnel connecting {} and {}.",
                self,
                dst_id,
                src_id
            );
            self.send_direct_message(dst_id, DirectMessage::TunnelClosed(src_id));
        }
    }

    /// Disconnects from the given peer, via Crust or by dropping the tunnel node, if the peer is
    /// not a proxy, client or routing table entry.
    fn disconnect_peer(&mut self, pub_id: &PublicId, outbox: Option<&mut EventBox>) {
        if self.peer_mgr.is_routing_peer(pub_id) {
            debug!(
                "{:?} Not disconnecting routing table entry {}.",
                self,
                pub_id
            );
        } else if self.peer_mgr.is_proxy(pub_id) {
            debug!("{:?} Not disconnecting proxy node {}.", self, pub_id);
        } else if self.peer_mgr.is_joining_node(pub_id) {
            debug!("{:?} Not disconnecting joining node {:?}.", self, pub_id);
        } else if let Some(tunnel_id) = self.tunnels.remove_tunnel_for(pub_id) {
            debug!("{:?} Disconnecting {:?} (indirect).", self, pub_id);
            let message = DirectMessage::TunnelDisconnect(*pub_id);
            self.send_direct_message(tunnel_id, message);
            let _ = self.peer_mgr.remove_peer(pub_id);
        } else {
            debug!(
                "{:?} Disconnecting {}. Calling crust::Service::disconnect.",
                self,
                pub_id
            );
            let _ = self.crust_service.disconnect(pub_id);
            if let Some((peer, _)) = self.peer_mgr.remove_peer(pub_id) {
                match *peer.state() {
                    PeerState::Bootstrapper { peer_kind, .. } => {
                        if peer_kind == CrustUser::Client {
                            let _ = self.dropped_clients.insert(*pub_id, ());
                        }
                    }
                    PeerState::Client { ip, traffic } => {
                        info!(
                            "{:?} Stats - Client total session traffic from {:?} - {:?}",
                            self,
                            ip,
                            traffic
                        );
                        let _ = self.dropped_clients.insert(*pub_id, ());
                    }
                    PeerState::ConnectionInfoPreparing { .. } |
                    PeerState::ConnectionInfoReady(_) |
                    PeerState::CrustConnecting |
                    PeerState::Connected(_) |
                    PeerState::SearchingForTunnel |
                    PeerState::JoiningNode |
                    PeerState::Routing(_) |
                    PeerState::Candidate(_) |
                    PeerState::Proxy => (),
                }
            }
            self.dropped_tunnel_client(pub_id);
            // FIXME: `outbox` is optional here primarily to avoid passing an `EventBox` through
            //        many of the `send_xxx` functions. We're relying on `purge_invalid_rt_entries`
            //        to clean up any tunnel clients left in the RT which are left with no tunnel
            //        node and hence can't be contacted. There should be a better way to handle
            //        this.
            match outbox {
                Some(event_box) => self.dropped_tunnel_node(pub_id, event_box),
                None => {
                    if self.tunnels.is_tunnel_node(pub_id) {
                        debug!(
                            "{:?} Disconnected from {} which was acting as tunnel node. \
                                Some uncontactable peers will remain until RT purge next runs.",
                            self,
                            pub_id
                        );
                    }
                }
            }
        }
    }

    // Received by X; From A -> X
    fn handle_relocate_request(
        &mut self,
        relocating_node_id: PublicId,
        proxy_name: XorName,
        dst_name: XorName,
        message_id: MessageId,
    ) -> Result<(), RoutingError> {
        // Validate relocating node has contacted the correct Section-X
        if *relocating_node_id.name() != dst_name {
            return Err(RoutingError::InvalidDestination);
        }

        let close_section = match self.routing_table().close_names(&dst_name) {
            Some(close_section) => close_section.into_iter().collect(),
            None => return Err(RoutingError::InvalidDestination),
        };
        let relocation_dst = self.next_relocation_dst.unwrap_or_else(|| {
            utils::calculate_relocation_dst(close_section, &dst_name)
        });

        // From X -> Y; Send to close section of the relocated name
        let request_content = MessageContent::ExpectCandidate {
            old_public_id: relocating_node_id,
            old_client_auth: Authority::Client {
                client_id: relocating_node_id,
                proxy_node_name: proxy_name,
            },
            message_id: message_id,
        };

        let src = Authority::Section(dst_name);
        let dst = Authority::Section(relocation_dst);
        self.send_routing_message(src, dst, request_content)
    }

    // Received by Y; From X -> Y
    // Context: a node is joining our section. Sends `AcceptAsCandidate` to our section. If the
    // network is unbalanced, sends `ExpectCandidate` on to a section with a shorter prefix.
    fn handle_expect_candidate(
        &mut self,
        old_pub_id: PublicId,
        old_client_auth: Authority<XorName>,
        relocation_dst: Authority<XorName>,
        message_id: MessageId,
        outbox: &mut EventBox,
    ) -> Result<(), RoutingError> {
        self.remove_expired_peers(outbox);

        if old_pub_id == *self.full_id.public_id() {
            return Ok(()); // This is a delayed message belonging to our own relocate request.
        }

        // Check that our section is one of the ones with a minimum length prefix, and if it's not,
        // forward it to one that is.
        let min_len_prefix = self.routing_table().min_len_prefix();

        // If we're running in mock-crust mode, and we have relocation interval, don't try to do
        // section balancing, as it will break things.
        let forbid_join_balancing = if cfg!(feature = "use-mock-crust") {
            self.next_relocation_interval.is_some()
        } else {
            false
        };

        if &min_len_prefix != self.our_prefix() && !forbid_join_balancing {
            let request_content = MessageContent::ExpectCandidate {
                old_public_id: old_pub_id,
                old_client_auth: old_client_auth,
                message_id: message_id,
            };
            let src = relocation_dst;
            let dst = Authority::Section(min_len_prefix.substituted_in(relocation_dst.name()));
            return self.send_routing_message(src, dst, request_content);
        }

        let target_interval = self.next_relocation_interval.take().unwrap_or_else(|| {
            utils::calculate_relocation_interval(
                self.our_prefix(),
                self.routing_table().our_section(),
            )
        });

        self.peer_mgr.expect_candidate(old_pub_id)?;

        let response_content = MessageContent::AcceptAsCandidate {
            old_public_id: old_pub_id,
            old_client_auth: old_client_auth,
            target_interval: target_interval,
            message_id: message_id,
        };
        info!(
            "{:?} Expecting candidate with old name {}.",
            self,
            old_pub_id
        );

        self.send_routing_message(relocation_dst, relocation_dst, response_content)
    }

    // Received by Y; From Y -> Y
    // Context: a node is joining our section. Sends the node our section.
    fn handle_accept_as_candidate(
        &mut self,
        old_pub_id: PublicId,
        old_client_auth: Authority<XorName>,
        relocation_dst: Authority<XorName>,
        target_interval: (XorName, XorName),
        message_id: MessageId,
        outbox: &mut EventBox,
    ) -> Result<(), RoutingError> {
        self.remove_expired_peers(outbox);

        if old_pub_id == *self.full_id.public_id() {
            // If we're the joining node: stop
            return Ok(());
        }

        self.candidate_timer_token = Some(self.timer.schedule(
            Duration::from_secs(RESOURCE_PROOF_DURATION_SECS),
        ));

        let own_section = self.peer_mgr.accept_as_candidate(
            old_pub_id,
            target_interval,
        );
        let response_content = MessageContent::RelocateResponse {
            target_interval: target_interval,
            section: own_section,
            message_id: message_id,
        };
        info!(
            "{:?} Our section with {:?} accepted candidate with old name {}.",
            self,
            self.our_prefix(),
            old_pub_id
        );
        trace!(
            "{:?} Sending {:?} to {:?}",
            self,
            response_content,
            old_client_auth
        );

        self.send_routing_message(relocation_dst, old_client_auth, response_content)
    }

    fn handle_section_update(
        &mut self,
        ver_pfx: VersionedPrefix<XorName>,
        members: BTreeSet<PublicId>,
        outbox: &mut EventBox,
    ) -> Result<(), RoutingError> {
        trace!("{:?} Got section update for {:?}", self, ver_pfx);

        let old_prefixes = self.routing_table().prefixes();
        // Perform splits and merges that we missed, according to the section update.
        for pub_id in self.peer_mgr.add_prefix(ver_pfx) {
            self.disconnect_peer(&pub_id, Some(outbox));
        }

        let new_prefixes = self.routing_table().prefixes();
        if old_prefixes != new_prefixes {
            info!(
                "{:?} SectionUpdate handled. Prefixes: {:?}",
                self,
                new_prefixes
            );
            for prefix in new_prefixes.difference(&old_prefixes) {
                self.send_section_list_signature(*prefix, None);
            }
        }
        // Filter list of members to just those we don't know about:
        let members =
            if let Some(section) = self.routing_table().section_with_prefix(ver_pfx.prefix()) {
                members
                    .into_iter()
                    .filter(|id: &PublicId| !section.contains(id.name()))
                    .collect_vec()
            } else {
                debug!(
                    "{:?} Section update received from unknown neighbour {:?}",
                    self,
                    ver_pfx
                );
                return Ok(());
            };
        let members = members
            .into_iter()
            .filter(|id: &PublicId| {
                self.peer_mgr.get_peer(id).map_or(
                    true,
                    |peer| !peer.valid(),
                )
            })
            .collect_vec();

        let own_name = *self.name();
        for pub_id in members {
            if let Err(error) = self.send_connection_info_request(
                pub_id,
                Authority::ManagedNode(own_name),
                Authority::ManagedNode(*pub_id.name()),
                outbox,
                ReconnectingPeer::False,
            )
            {
                debug!(
                    "{:?} - Failed to send connection info to {:?}: {:?}",
                    self,
                    pub_id,
                    error
                );
            }
        }
        Ok(())
    }

    fn handle_section_split(
        &mut self,
        ver_pfx: VersionedPrefix<XorName>,
        joining_node: XorName,
        outbox: &mut EventBox,
    ) -> Result<(), RoutingError> {
        let split_us = ver_pfx.prefix() == self.our_prefix();
        // Send SectionSplit notifications if we don't know of the new node yet
        if split_us && !self.routing_table().has(&joining_node) {
            self.send_section_split(ver_pfx, joining_node);
        }
        // None of the `peers_to_drop` will have been in our section, so no need to notify Routing
        // user about them.
        let (peers_to_drop, our_new_prefix) = self.peer_mgr.split_section(ver_pfx);
        if let Some(new_prefix) = our_new_prefix {
            outbox.send_event(Event::SectionSplit(new_prefix));
        }

        for pub_id in peers_to_drop {
            self.disconnect_peer(&pub_id, Some(outbox));
        }
        info!(
            "{:?} Section split for {:?} completed. Prefixes: {:?}",
            self,
            ver_pfx,
            self.routing_table().prefixes()
        );

        self.merge_if_necessary(outbox);

        self.send_section_update(None, true);
        let prefix0 = ver_pfx.prefix().pushed(false);
        let prefix1 = ver_pfx.prefix().pushed(true);
        self.send_section_list_signature(prefix0, None);
        self.send_section_list_signature(prefix1, None);
        self.reset_su_timer();

        Ok(())
    }

    fn handle_own_section_merge(
        &mut self,
        sender_prefix: Prefix<XorName>,
        merge_prefix: Prefix<XorName>,
        sections: SectionMap,
        outbox: &mut EventBox,
    ) -> Result<(), RoutingError> {
        if let Some(our_merged_section) =
            self.our_merged_section.extend_our_merged_section(
                merge_prefix,
                &sections,
            )
        {
            if merge_prefix == *self.our_prefix() {
                trace!(
                    "{:?} resend OtherSectionMerge on duplicated OwnSectionMerge",
                    self
                );
                let other_prefixes = self.routing_table().other_prefixes();
                let our_ver_pfx = self.routing_table().our_versioned_prefix();
                self.send_other_section_merge(other_prefixes, our_ver_pfx, our_merged_section);
            }
        }
        if !merge_prefix.is_compatible(&sender_prefix) ||
            merge_prefix.bit_count() + 1 != sender_prefix.bit_count() ||
            !merge_prefix.is_compatible(self.our_prefix()) ||
            merge_prefix.bit_count() >= self.our_prefix().bit_count()
        {
            debug!(
                "{:?} Received OwnSectionMerge with merge prefix {:?} from prefix {:?}.",
                self,
                merge_prefix,
                sender_prefix
            );
            return Err(RoutingError::BadAuthority);
        }
        if let Some(previous_sections) = self.merge_cache.insert(sender_prefix, sections) {
            debug!(
                "{:?} Received duplicate OwnSectionMerge from {:?}: {:?}.",
                self,
                sender_prefix,
                previous_sections
            );
        }
        loop {
            let our_prefix = *self.our_prefix();
            let our_sections = match self.merge_cache.remove(&our_prefix) {
                None => break,
                Some(our_sections) => our_sections,
            };
            let their_prefix = our_prefix.sibling();
            let their_sections = match self.merge_cache.remove(&their_prefix) {
                None => {
                    // This is always `None`, because this entry has just been removed.
                    let _none = self.merge_cache.insert(our_prefix, our_sections);
                    break;
                }
                Some(their_sections) => their_sections,
            };
            let mut version = 1;
            let mut our_merged_section = BTreeSet::new();
            for (ver_pfx, peers) in our_sections.iter().chain(&their_sections) {
                if ver_pfx.prefix().is_extension_of(&merge_prefix) {
                    version = cmp::max(version, ver_pfx.version() + 1);
                    our_merged_section.extend(peers.into_iter().map(|peer| *peer.name()));
                }
            }

            if let Some(merged_section) =
                self.our_merged_section.get_our_merged_section(
                    merge_prefix,
                    version,
                )
            {
                our_merged_section = merged_section;
            }

            self.process_own_section_merge(
                their_prefix,
                version,
                their_sections,
                our_merged_section,
                outbox,
            );
            self.our_merged_section.set_send_other_section_merge(
                merge_prefix,
                version,
            );
        }
        self.merge_if_necessary(outbox);
        Ok(())
    }

    fn we_want_to_merge(&self) -> bool {
        self.merge_cache.contains_key(self.our_prefix())
    }

    fn they_want_to_merge(&self) -> bool {
        self.merge_cache.contains_key(&self.our_prefix().sibling())
    }

    fn process_own_section_merge(
        &mut self,
        sender_prefix: Prefix<XorName>,
        merge_version: u64,
        sections: SectionMap,
        our_merged_section: BTreeSet<XorName>,
        outbox: &mut EventBox,
    ) {
        self.remove_expired_peers(outbox);

        match self.peer_mgr.merge_own_section(
            sender_prefix,
            merge_version,
            sections,
        ) {
            (OwnMergeState::AlreadyMerged, _needed_peers) => (),
            (OwnMergeState::Completed {
                 targets,
                 versioned_prefix,
                 ..
             },
             needed_peers) => {
                // TODO - the event should maybe only fire once all new connections have been made?
                outbox.send_event(Event::SectionMerge(*versioned_prefix.prefix()));
                info!(
                    "{:?} Own section merge completed. Prefixes: {:?}",
                    self,
                    self.routing_table().prefixes()
                );

                let own_name = *self.name();
                for needed in &needed_peers {
                    debug!(
                        "{:?} Sending connection info to {:?} due to merging own section.",
                        self,
                        needed
                    );
                    if let Err(error) = self.send_connection_info_request(
                        *needed,
                        Authority::ManagedNode(own_name),
                        Authority::ManagedNode(*needed.name()),
                        outbox,
                        ReconnectingPeer::False,
                    )
                    {
                        debug!(
                            "{:?} - Failed to send connection info to {:?}: {:?}",
                            self,
                            needed,
                            error
                        );
                    }
                }

                // After the merge, half of our section won't have our signatures -- send them
                self.send_section_list_signatures();

                // Send an `OtherSectionMerge` containing just the prefix to ensure accumulation,
                // followed by a second one with the full details of the our section.
                self.send_other_section_merge(targets.clone(), versioned_prefix, BTreeSet::new());
                self.send_other_section_merge(targets, versioned_prefix, our_merged_section);
            }
        }

        self.reset_su_timer();
    }

    fn handle_other_section_merge(
        &mut self,
        merge_ver_pfx: VersionedPrefix<XorName>,
        section: BTreeSet<PublicId>,
        outbox: &mut EventBox,
    ) -> Result<(), RoutingError> {
        self.remove_expired_peers(outbox);

        let needed_peers = self.peer_mgr.merge_other_section(
            merge_ver_pfx,
            section.clone(),
        );
        let own_name = *self.name();

        for needed in needed_peers {
            debug!(
                "{:?} Sending connection info to {:?} due to merging other section.",
                self,
                needed
            );
            let needed_name = *needed.name();
            if let Err(error) = self.send_connection_info_request(
                needed,
                Authority::ManagedNode(own_name),
                Authority::ManagedNode(needed_name),
                outbox,
                ReconnectingPeer::False,
            )
            {
                debug!("{:?} - Failed to send connection info: {:?}", self, error);
            }
        }
        info!(
            "{:?} Other section merge completed. Prefixes: {:?}",
            self,
            self.routing_table().prefixes()
        );

        // This is an optimisation to avoid un-necessary merge in the scenario: the merged section
        // doesn't really contain too few nodes as we just didn't learn about all its members
        // because the included member list was empty.
        if !section.is_empty() {
            self.merge_if_necessary(outbox);
        }

        self.send_section_list_signatures();

        if self.routing_table()
            .section_with_prefix(merge_ver_pfx.prefix())
            .is_some()
        {
            self.reset_su_timer();
            self.send_section_update(Some(*merge_ver_pfx.prefix()), false);
        }
        Ok(())
    }

    fn handle_ack_response(&mut self, ack: Ack) -> Result<(), RoutingError> {
        self.ack_mgr.receive(ack);
        Ok(())
    }

    fn handle_timeout(&mut self, token: u64, outbox: &mut EventBox) -> Transition {
        let log_ident = format!("{:?}", self);
        if let Some(transition) = self.resource_prover.handle_timeout(
            token,
            log_ident,
            outbox,
        )
        {
            return transition;
        }

        if self.tick_timer_token == token {
            let tick_period = Duration::from_secs(TICK_TIMEOUT_SECS);
            self.tick_timer_token = self.timer.schedule(tick_period);
            self.remove_expired_peers(outbox);

            trace!(
                "{:?} Stats - Proxy Load: {} KiB/s",
                self,
                self.proxy_load_amount / (TICK_TIMEOUT_SECS * 1024)
            );
            self.proxy_load_amount = 0;

            let transition = if cfg!(feature = "use-mock-crust") {
                Transition::Stay
            } else {
                self.purge_invalid_rt_entries(outbox)
            };
            self.merge_if_necessary(outbox);
            if self.is_approved {
                outbox.send_event(Event::Tick);
            }
            return transition;
        }

        if self.su_timer_token == Some(token) {
            if cfg!(feature = "use-mock-crust") {
                trace!(
                    "{:?} not to schedule next section update during mock_crust test.",
                    self
                );
            } else {
                self.su_timeout = cmp::min(
                    Duration::from_secs(SU_MAX_TIMEOUT_SECS),
                    self.su_timeout * 2,
                );
                trace!(
                    "{:?} Scheduling next section update for {} seconds from now.",
                    self,
                    self.su_timeout.as_secs()
                );
                self.su_timer_token = Some(self.timer.schedule(self.su_timeout));
                self.send_section_update(None, false);
            }
        } else if self.candidate_timer_token == Some(token) {
            self.candidate_timer_token = None;
            self.send_candidate_approval();
        } else if self.candidate_status_token == Some(token) {
            self.candidate_status_token = Some(self.timer.schedule(Duration::from_secs(
                CANDIDATE_STATUS_INTERVAL_SECS,
            )));
            self.peer_mgr.show_candidate_status();
        } else {
            // Each token has only one purpose, so we only need to call this if none of the above
            // matched:
            self.resend_unacknowledged_timed_out_msgs(token);
        }

        Transition::Stay
    }

    // Drop peers to which we think we have a direct or tunnel connection, but where Crust reports
    // that we're not connected to the peer or tunnel node respectively.
    fn purge_invalid_rt_entries(&mut self, outbox: &mut EventBox) -> Transition {
        let peer_details = self.peer_mgr.get_routing_peer_details();
        for pub_id in peer_details.out_of_sync_peers {
            let _ = self.crust_service.disconnect(&pub_id);
            let _ = self.dropped_peer(&pub_id, outbox, true);
        }
        for removal_detail in peer_details.removal_details {
            let name = removal_detail.name;
            let _ = self.dropped_routing_node(&name, removal_detail, outbox);
        }
        let mut pub_ids_to_drop = vec![];
        for (pub_id, is_tunnel) in peer_details.routing_peer_details {
            if is_tunnel {
                match self.tunnels.tunnel_for(&pub_id) {
                    Some(tunnel_node_id) => {
                        if !self.crust_service.is_connected(tunnel_node_id) {
                            log_or_panic!(
                                Level::Debug,
                                "{:?} Should have a tunnel connection to {} via \
                                          {}, but tunnel node not connected.",
                                self,
                                pub_id,
                                tunnel_node_id
                            );
                            pub_ids_to_drop.push(*tunnel_node_id);
                        }
                    }
                    None => {
                        if self.crust_service.is_connected(&pub_id) {
                            log_or_panic!(
                                Level::Debug,
                                "{:?} Should have a tunnel connection to {}, but \
                                          instead have a direct connection.",
                                self,
                                pub_id
                            );
                            self.peer_mgr.correct_state_to_direct(&pub_id);
                        } else {
                            log_or_panic!(
                                Level::Debug,
                                "{:?} Should have a tunnel connection to {}, but no \
                                          tunnel node or direct connection exists.",
                                self,
                                pub_id
                            );
                            pub_ids_to_drop.push(pub_id);
                        }
                    }
                }
            } else if !self.crust_service.is_connected(&pub_id) {
                log_or_panic!(
                    Level::Error,
                    "{:?} Should have a direct connection to {}, but don't.",
                    self,
                    pub_id
                );
                if self.tunnels.tunnel_for(&pub_id).is_some() {
                    self.peer_mgr.correct_state_to_tunnel(&pub_id);
                }
            }
        }
        let mut transition = Transition::Stay;
        for pub_id in pub_ids_to_drop {
            debug!("{:?} Purging {} from routing table.", self, pub_id);
            if let Transition::Terminate = self.handle_lost_peer(pub_id, outbox) {
                transition = Transition::Terminate;
            }
        }
        transition
    }

    fn send_candidate_approval(&mut self) {
        let (response_content, new_name) = match self.peer_mgr.verified_candidate_info() {
            Err(_) => {
                trace!(
                    "{:?} No candidate for which to send CandidateApproval.",
                    self
                );
                return;
            }
            Ok(result) => result,
        };

        if self.we_want_to_merge() || self.they_want_to_merge() {
            debug!(
                "{:?} Resource proof duration has finished, but not voting to approve \
                   candidate {} since our section is currently merging.",
                self,
                new_name
            );
            return;
        }

        let src = Authority::Section(new_name);
        info!(
            "{:?} Resource proof duration has finished. Voting to approve candidate {}.",
            self,
            new_name
        );
        trace!("{:?} Sending {:?} to {:?}.", self, response_content, src);

        if let Err(error) = self.send_routing_message(src, src, response_content) {
            debug!("{:?} Failed sending CandidateApproval: {:?}", self, error);
        }
    }

    fn decrypt_connection_info(
        &self,
        encrypted_connection_info: &[u8],
        nonce: &box_::Nonce,
        public_id: &PublicId,
    ) -> Result<PubConnectionInfo, RoutingError> {
        let decipher_result = box_::open(
            encrypted_connection_info,
            nonce,
            public_id.encrypting_public_key(),
            self.full_id.encrypting_private_key(),
        );

        let serialised_connection_info =
            decipher_result.map_err(|()| RoutingError::AsymmetricDecryptionFailure)?;
        Ok(serialisation::deserialise(&serialised_connection_info)?)
    }

    fn reset_su_timer(&mut self) {
        trace!(
            "{:?} Scheduling a SectionUpdate for {} seconds from now.",
            self,
            SU_MIN_TIMEOUT_SECS
        );
        self.su_timeout = Duration::from_secs(SU_MIN_TIMEOUT_SECS);
        self.su_timer_token = Some(self.timer.schedule(self.su_timeout));
    }

    // ----- Send Functions -----------------------------------------------------------------------
    fn send_user_message(
        &mut self,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        user_msg: UserMessage,
        priority: u8,
    ) -> Result<(), RoutingError> {
        self.stats.count_user_message(&user_msg);
        for part in user_msg.to_parts(priority)? {
            self.stats.increase_user_msg_part();
            self.send_routing_message(src, dst, part)?;
        }
        Ok(())
    }

    // Send signed_msg on route. Hop is the name of the peer we received this from, or our name if
    // we are the first sender or the proxy for a client or joining node.
    //
    // Don't send to any nodes already sent_to.
    fn send_signed_message(
        &mut self,
        signed_msg: &SignedMessage,
        route: u8,
        hop: &XorName,
        sent_to: &BTreeSet<XorName>,
    ) -> Result<(), RoutingError> {
        let sent_by_us = hop == self.name() && signed_msg.signed_by(self.full_id.public_id());
        if sent_by_us {
            self.stats.count_route(route);
        }

        let dst = signed_msg.routing_message().dst;

        if let Authority::Client { ref client_id, .. } = dst {
            if *self.name() == dst.name() {
                // This is a message for a client we are the proxy of. Relay it.
                return self.relay_to_client(signed_msg, client_id);
            } else if self.in_authority(&dst) {
                return Ok(()); // Message is for us as a client.
            }
        }

        let (new_sent_to, target_pub_ids) = self.get_targets(
            signed_msg.routing_message(),
            route,
            hop,
            sent_to,
        )?;

        for target_pub_id in target_pub_ids {
            self.send_signed_msg_to_peer(
                signed_msg.clone(),
                target_pub_id,
                route,
                new_sent_to.clone(),
            )?;
        }
        Ok(())
    }

    // Filter, then convert the message to a `Hop` or `TunnelHop` `Message` and serialise.
    // Send this byte string.
    fn send_signed_msg_to_peer(
        &mut self,
        signed_msg: SignedMessage,
        target: PublicId,
        route: u8,
        sent_to: BTreeSet<XorName>,
    ) -> Result<(), RoutingError> {
        let priority = signed_msg.priority();
        let routing_msg = signed_msg.routing_message().clone();

        let (pub_id, bytes) = if self.crust_service.is_connected(&target) {
            let serialised = self.to_hop_bytes(signed_msg, route, sent_to)?;
            (target, serialised)
        } else if let Some(&tunnel_id) = self.tunnels.tunnel_for(&target) {
            let serialised = self.to_tunnel_hop_bytes(signed_msg, route, sent_to, target)?;
            (tunnel_id, serialised)
        } else {
            trace!(
                "{:?} Not connected or tunnelling to {:?}. Dropping peer.",
                self,
                target
            );
            self.disconnect_peer(&target, None);
            return Ok(());
        };
        if !self.filter_outgoing_routing_msg(&routing_msg, &target, route) {
            self.send_or_drop(&pub_id, bytes, priority);
        }
        Ok(())
    }

    // Wraps the signed message in a `HopMessage` and sends it on.
    //
    // In the case that the `pub_id` is unknown, an ack is sent and the message dropped.
    fn relay_to_client(
        &mut self,
        signed_msg: &SignedMessage,
        pub_id: &PublicId,
    ) -> Result<(), RoutingError> {
        let priority = signed_msg.priority();
        let is_client = self.peer_mgr.is_client(pub_id);

        let result = if is_client || self.peer_mgr.is_joining_node(pub_id) {
            // If the message being relayed is a data response, update the client's
            // rate limit balance to account for the initial over-counting.
            if let Some(&PeerState::Client { ip, .. }) =
                self.peer_mgr.get_peer(pub_id).map(Peer::state)
            {
                let _ = self.correct_rate_limits(&ip, signed_msg.routing_message());
            }

            if self.filter_outgoing_routing_msg(signed_msg.routing_message(), pub_id, 0) {
                return Ok(());
            }
            let hop_msg = HopMessage::new(
                signed_msg.clone(),
                0,
                BTreeSet::new(),
                self.full_id.signing_private_key(),
            )?;
            let message = Message::Hop(hop_msg);
            let raw_bytes = serialisation::serialise(&message)?;
            self.send_or_drop(pub_id, raw_bytes, priority);
            Ok(())
        } else {
            debug!(
                "{:?} Client connection not found for message {:?}.",
                self,
                signed_msg
            );
            Err(RoutingError::ClientConnectionNotFound)
        };

        // Acknowledge the message so that the sender doesn't retry.
        if is_client || result.is_err() {
            let hop = *self.name();
            self.send_ack_from(signed_msg.routing_message(), 0, Authority::ManagedNode(hop));
        }

        result
    }

    /// Returns the peer that is responsible for collecting signatures to verify a message; this
    /// may be us or another node. If our signature is not required, this returns `None`.
    fn get_signature_target(&self, src: &Authority<XorName>, route: u8) -> Option<XorName> {
        use Authority::*;
        let list: Vec<&XorName> = match *src {
            ClientManager(_) | NaeManager(_) | NodeManager(_) => {
                let mut v = self.routing_table().our_section().iter().sorted_by(
                    |&lhs, &rhs| {
                        src.name().cmp_distance(lhs, rhs)
                    },
                );
                v.truncate(self.min_section_size());
                v
            }
            Section(_) => {
                self.routing_table().our_section().iter().sorted_by(
                    |&lhs, &rhs| {
                        src.name().cmp_distance(lhs, rhs)
                    },
                )
            }
            PrefixSection(ref pfx) => {
                self.routing_table()
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

    /// Returns a list of target IDs for a message sent via route.
    /// Names in exclude and sent_to will be excluded from the result.
    fn get_targets(
        &self,
        routing_msg: &RoutingMessage,
        route: u8,
        exclude: &XorName,
        sent_to: &BTreeSet<XorName>,
    ) -> Result<(BTreeSet<XorName>, Vec<PublicId>), RoutingError> {
        let force_via_proxy = match routing_msg.content {
            MessageContent::ConnectionInfoRequest { pub_id, .. } |
            MessageContent::ConnectionInfoResponse { pub_id, .. } => {
                routing_msg.src.is_client() && pub_id == *self.full_id.public_id()
            }
            _ => false,
        };

        if self.is_proper() && !force_via_proxy {
            let targets: BTreeSet<_> = self.routing_table()
                .targets(&routing_msg.dst, *exclude, route as usize)?
                .into_iter()
                .filter(|target| !sent_to.contains(target))
                .collect();
            let new_sent_to = if self.in_authority(&routing_msg.dst) {
                sent_to
                    .iter()
                    .chain(targets.iter().filter(|target| {
                        match self.peer_mgr.get_peer_by_name(target).map(Peer::state) {
                            Some(&PeerState::Routing(RoutingConnection::Tunnel)) => false,
                            _ => true,
                        }
                    }))
                    .chain(iter::once(self.name()))
                    .cloned()
                    .collect()
            } else {
                BTreeSet::new()
            };
            Ok((
                new_sent_to,
                self.peer_mgr.get_pub_ids(&targets).into_iter().collect(),
            ))
        } else if let Authority::Client { ref proxy_node_name, .. } = routing_msg.src {
            // We don't have any contacts in our routing table yet. Keep using
            // the proxy connection until we do.
            if let Some(pub_id) = self.peer_mgr.get_peer_by_name(proxy_node_name).map(
                Peer::pub_id,
            )
            {
                if self.peer_mgr.is_proxy(pub_id) {
                    Ok((BTreeSet::new(), vec![*pub_id]))
                } else {
                    error!("{:?} Peer found in peer manager but not as proxy.", self);
                    Err(RoutingError::ProxyConnectionNotFound)
                }
            } else {
                error!(
                    "{:?} Unable to find connection to proxy node in proxy map.",
                    self
                );
                Err(RoutingError::ProxyConnectionNotFound)
            }
        } else {
            error!(
                "{:?} Source should be client if our state is a Client. {:?}",
                self,
                routing_msg
            );
            Err(RoutingError::InvalidSource)
        }
    }

    // Wrap the `signed_msg` with a `HopMessage`, then wrap that with `Message::TunnelHop`.
    // Serialise the result to a byte string.
    fn to_tunnel_hop_bytes(
        &self,
        signed_msg: SignedMessage,
        route: u8,
        sent_to: BTreeSet<XorName>,
        dst: PublicId,
    ) -> Result<Vec<u8>, RoutingError> {
        let hop_msg = HopMessage::new(
            signed_msg,
            route,
            sent_to,
            self.full_id.signing_private_key(),
        )?;
        let message = Message::TunnelHop {
            content: hop_msg,
            src: *self.full_id.public_id(),
            dst: dst,
        };

        Ok(serialisation::serialise(&message)?)
    }

    fn process_connection(&mut self, pub_id: PublicId, outbox: &mut EventBox) {
        if self.peer_mgr.get_peer(&pub_id).map_or(
            false,
            |peer| peer.valid(),
        )
        {
            self.add_to_routing_table(&pub_id, outbox);
        }

        if self.is_approved {
            return;
        }

        // If we're not approved yet, we need to identify ourselves with our old and new IDs via
        // `CandidateInfo`. Serialise the old and new `PublicId`s and sign this using the old key.
        let msg = {
            let old_and_new_pub_ids = (self.old_full_id.public_id(), self.full_id.public_id());
            let mut to_sign = match serialisation::serialise(&old_and_new_pub_ids) {
                Ok(result) => result,
                Err(error) => {
                    error!("Failed to serialise public IDs: {:?}", error);
                    return;
                }
            };
            let signature_using_old =
                sign::sign_detached(&to_sign, self.old_full_id.signing_private_key());
            // Append this signature onto the serialised IDs and sign that using the new key.
            to_sign.extend_from_slice(&signature_using_old.0);
            let signature_using_new =
                sign::sign_detached(&to_sign, self.full_id.signing_private_key());
            let proxy_node_name = if let Some(proxy_node_name) = self.peer_mgr.get_proxy_name() {
                *proxy_node_name
            } else {
                warn!(
                    "{:?} No proxy found, so unable to send CandidateInfo.",
                    self
                );
                return;
            };
            let new_client_auth = Authority::Client {
                client_id: *self.full_id.public_id(),
                proxy_node_name: proxy_node_name,
            };

            DirectMessage::CandidateInfo {
                old_public_id: *self.old_full_id.public_id(),
                new_public_id: *self.full_id.public_id(),
                signature_using_old: signature_using_old,
                signature_using_new: signature_using_new,
                new_client_auth: new_client_auth,
            }
        };

        self.send_direct_message(pub_id, msg);
    }

    // Note: This fn assumes `their_public_id` is a valid node in the network
    // Do not call this to respond to ConnectionInfo requests which are not yet validated.
    fn send_connection_info_request(
        &mut self,
        their_public_id: PublicId,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        outbox: &mut EventBox,
        reconnecting: ReconnectingPeer,
    ) -> Result<(), RoutingError> {
        let their_name = *their_public_id.name();
        self.peer_mgr.allow_connect(&their_name)?;

        if self.peer_mgr.is_client(&their_public_id) ||
            self.peer_mgr.is_joining_node(&their_public_id) ||
            self.peer_mgr.is_proxy(&their_public_id)
        {
            // we use peer_name here instead of their_name since the peer can be
            // a joining node with its client name as far as proxy node is concerned
            self.peer_mgr.set_peer_valid(&their_public_id, true);
            self.process_connection(their_public_id, outbox);
            return Ok(());
        }

        // If we are about to send a connection info request to a peer we are already
        // connected to, then set their valid attribute and add them to RT.
        // NOTE: If we do not have this peer in peer_mgr, `get_connection_token`
        // will flag them to `valid`
        self.peer_mgr.set_peer_valid(&their_public_id, true);
        match self.peer_mgr.get_peer(&their_public_id).map(Peer::state) {
            Some(&PeerState::Connected(_)) |
            Some(&PeerState::Candidate(_)) => {
                self.add_to_routing_table(&their_public_id, outbox);
                return Ok(());
            }
            _ => (),
        }

        // This will insert the peer if peer is not in peer_mgr and flag them to `valid`
        if let Some(token) = self.peer_mgr.get_connection_token(
            src,
            dst,
            their_public_id,
            reconnecting,
        )
        {
            self.crust_service.prepare_connection_info(token);
            return Ok(());
        }

        let our_pub_info = match self.peer_mgr.get_peer(&their_public_id).map(Peer::state) {
            Some(&PeerState::ConnectionInfoReady(ref our_priv_info)) => {
                our_priv_info.to_pub_connection_info()
            }
            state => {
                trace!(
                    "{:?} Not sending connection info request to {:?}. State: {:?}",
                    self,
                    their_name,
                    state
                );
                return Ok(());
            }
        };
        trace!(
            "{:?} Resending connection info request to {:?}",
            self,
            their_name
        );
        self.send_connection_info(our_pub_info, their_public_id, src, dst, None);
        Ok(())
    }

    /// Handles dropped peer with the given ID. Returns true if we should keep running, false if
    /// we should terminate.
    fn dropped_peer(
        &mut self,
        pub_id: &PublicId,
        outbox: &mut EventBox,
        mut try_reconnect: bool,
    ) -> bool {
        let (peer, removal_result) = match self.peer_mgr.remove_peer(pub_id) {
            Some(result) => result,
            None => return true,
        };

        if let Ok(removal_details) = removal_result {
            if !self.dropped_routing_node(peer.name(), removal_details, outbox) {
                return false;
            }
        }

        match *peer.state() {
            PeerState::Client { ip, traffic } => {
                debug!("{:?} Client disconnected: {}", self, pub_id);
                info!(
                    "{:?} Stats - Client total session traffic from {:?} - {:?}",
                    self,
                    ip,
                    traffic
                );
                try_reconnect = false;
            }
            PeerState::JoiningNode => {
                debug!("{:?} Joining node {} dropped.", self, pub_id);
                try_reconnect = false;
            }
            PeerState::Proxy => {
                debug!("{:?} Lost bootstrap connection to {:?}.", self, peer);

                if self.routing_table().len() < self.min_section_size() - 1 {
                    outbox.send_event(Event::Terminate);
                    return false;
                }
                try_reconnect = false;
            }
            _ => (),
        }

        if try_reconnect && peer.valid() && self.is_approved {
            debug!(
                "{:?} Sending connection info to {:?} due to dropped peer.",
                self,
                peer.pub_id()
            );
            let own_name = *self.name();
            if let Err(error) = self.send_connection_info_request(
                *peer.pub_id(),
                Authority::ManagedNode(own_name),
                Authority::ManagedNode(*peer.name()),
                outbox,
                ReconnectingPeer::True,
            )
            {
                debug!(
                    "{:?} - Failed to send connection info to {:?}: {:?}",
                    self,
                    peer.pub_id(),
                    error
                );
            }
        }

        true
    }

    /// Handles dropped routing peer with the given name and removal details. Returns true if we
    /// should keep running, false if we should terminate.
    fn dropped_routing_node(
        &mut self,
        name: &XorName,
        details: RemovalDetails<XorName>,
        outbox: &mut EventBox,
    ) -> bool {
        info!(
            "{:?} Dropped {} from the routing table.",
            self,
            details.name
        );

        if self.is_approved {
            outbox.send_event(Event::NodeLost(details.name, self.routing_table().clone()));
        }

        self.merge_if_necessary(outbox);
        self.routing_table()
            .find_section_prefix(&details.name)
            .map_or((), |prefix| {
                self.send_section_list_signature(prefix, None);
            });
        if details.was_in_our_section {
            self.reset_su_timer();
            let section_len = self.routing_table().our_section().len();
            self.section_list_sigs.remove_signatures(name, section_len);
        }

        if self.routing_table().is_empty() {
            debug!("{:?} Lost all routing connections.", self);
            if !self.is_first_node {
                outbox.send_event(Event::RestartRequired);
                return false;
            }
        }

        true
    }

    fn send_section_split(&mut self, our_ver_pfx: VersionedPrefix<XorName>, joining_node: XorName) {
        for prefix in self.routing_table().prefixes() {
            // this way of calculating the source avoids using the joining node as the route
            // src authority is a PrefixSection and not Section to help resend failed messages
            // even if we handle the split and move on.
            let src = Authority::PrefixSection(*our_ver_pfx.prefix());
            let dst = Authority::PrefixSection(prefix);
            let content = MessageContent::SectionSplit(our_ver_pfx, joining_node);
            if let Err(err) = self.send_routing_message(src, dst, content) {
                debug!("{:?} Failed to send SectionSplit: {:?}.", self, err);
            }
        }
    }

    fn merge_if_necessary(&mut self, outbox: &mut EventBox) {
        self.remove_expired_peers(outbox);
        if !self.we_want_to_merge() && (self.they_want_to_merge() || self.peer_mgr.should_merge()) {
            let (sender_prefix, sections) = self.peer_mgr.merge_details();
            let content = MessageContent::OwnSectionMerge(sections);
            let src = Authority::PrefixSection(sender_prefix);
            let dst = Authority::PrefixSection(sender_prefix.popped());
            debug!(
                "{:?} Sending OwnSectionMerge from {:?} to {:?} with content {:?}",
                self,
                src,
                dst,
                content
            );
            if let Err(err) = self.send_routing_message(src, dst, content) {
                debug!("{:?} Failed to send OwnSectionMerge: {:?}.", self, err);
            }
        }
    }

    fn remove_expired_peers(&mut self, outbox: &mut EventBox) {
        for pub_id in self.peer_mgr.remove_expired_peers() {
            debug!("{:?} Disconnecting from timed out peer {:?}", self, pub_id);
            // We've already removed from peer manager but this helps clean out
            // tunnel or direct connection to expired peer
            self.disconnect_peer(&pub_id, Some(outbox));
        }
    }

    fn send_other_section_merge(
        &mut self,
        targets: BTreeSet<Prefix<XorName>>,
        ver_pfx: VersionedPrefix<XorName>,
        section: BTreeSet<XorName>,
    ) {
        let pub_ids = self.peer_mgr.get_pub_ids(&section);
        let version = self.routing_table().our_version();
        let content = MessageContent::OtherSectionMerge(pub_ids, version);
        let src = Authority::PrefixSection(*ver_pfx.prefix());
        for target in &targets {
            let dst = Authority::PrefixSection(*target);
            debug!(
                "{:?} Sending OtherSectionMerge from {:?} to {:?} with content {:?}",
                self,
                src,
                dst,
                content
            );
            if let Err(err) = self.send_routing_message(src, dst, content.clone()) {
                debug!("{:?} Failed to send OtherSectionMerge: {:?}.", self, err);
            }
        }
    }

    fn dropped_tunnel_client(&mut self, pub_id: &PublicId) {
        for other_id in self.tunnels.drop_client(pub_id) {
            trace!(
                "{:?} Closing tunnel client connection between {} and {}",
                self,
                pub_id,
                other_id
            );
            let message = DirectMessage::TunnelClosed(*pub_id);
            self.send_direct_message(other_id, message);
        }
    }

    fn dropped_tunnel_node(&mut self, pub_id: &PublicId, outbox: &mut EventBox) {
        let peers = self.tunnels
            .remove_tunnel(pub_id)
            .into_iter()
            .filter_map(|dst_id| {
                self.peer_mgr.get_peer(&dst_id).map(
                    |peer| (dst_id, peer.valid()),
                )
            })
            .collect_vec();
        for (dst_id, valid) in peers {
            let _ = self.dropped_peer(&dst_id, outbox, false);
            debug!(
                "{:?} Lost tunnel for peer {:?}. Requesting new tunnel.",
                self,
                dst_id
            );
            self.find_tunnel_for_peer(&dst_id, valid);
        }
    }

    // Proper node is either the first node in the network or a node which has at least one entry
    // in its routing table.
    fn is_proper(&self) -> bool {
        self.is_first_node || self.routing_table().len() >= 1
    }

    fn send_direct_message(&mut self, dst_id: PublicId, direct_message: DirectMessage) {
        self.stats().count_direct_message(&direct_message);

        if let Some(&tunnel_id) = self.tunnels.tunnel_for(&dst_id) {
            let message = Message::TunnelDirect {
                content: direct_message,
                src: *self.full_id.public_id(),
                dst: dst_id,
            };
            self.send_message(&tunnel_id, message);
        } else {
            self.send_message(&dst_id, Message::Direct(direct_message));
        }
    }

    fn our_prefix(&self) -> &Prefix<XorName> {
        self.routing_table().our_prefix()
    }

    // While this can theoretically be called as a result of a misbehaving client or node, we're
    // actually only blocking clients from bootstrapping from that IP (see
    // `handle_bootstrap_accept()`). This behaviour will change when we refactor the codebase to
    // handle malicious nodes more fully.
    fn ban_and_disconnect_peer(&mut self, pub_id: &PublicId) {
        if let Ok(ip_addr) = self.crust_service.get_peer_ip_addr(pub_id) {
            let _ = self.banned_client_ips.insert(ip_addr, ());
            debug!("{:?} Banned client {:?} on IP {}", self, pub_id, ip_addr);
        } else {
            warn!("{:?} Can't get IP address of client {:?}.", self, pub_id);
        }
        let _ = self.dropped_clients.insert(*pub_id, ());
        self.disconnect_peer(pub_id, None);
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
        if let Authority::Client { ref client_id, .. } = *auth {
            client_id == self.full_id.public_id()
        } else {
            self.is_proper() && self.routing_table().in_authority(auth)
        }
    }

    fn close_group(&self, name: XorName, count: usize) -> Option<Vec<XorName>> {
        self.routing_table().closest_names(&name, count).map(
            |names| {
                names.into_iter().cloned().collect_vec()
            },
        )
    }

    fn handle_lost_peer(&mut self, pub_id: PublicId, outbox: &mut EventBox) -> Transition {
        if self.peer_mgr.get_peer(&pub_id).is_none() {
            return Transition::Stay;
        }

        debug!("{:?} Received LostPeer - {}", self, pub_id);

        self.dropped_tunnel_client(&pub_id);
        self.dropped_tunnel_node(&pub_id, outbox);

        if self.dropped_peer(&pub_id, outbox, true) {
            Transition::Stay
        } else {
            Transition::Terminate
        }
    }

    fn stats(&mut self) -> &mut Stats {
        &mut self.stats
    }

    fn min_section_size(&self) -> usize {
        self.routing_table().min_section_size()
    }
}

#[cfg(feature = "use-mock-crust")]
impl Node {
    /// Check whether this node acts as a tunnel node between `client_1` and `client_2`.
    pub fn has_tunnel_clients(&self, client_1: PublicId, client_2: PublicId) -> bool {
        self.tunnels.has_clients(client_1, client_2)
    }

    /// Purge invalid routing entries.
    pub fn purge_invalid_rt_entry(&mut self) {
        let _ = self.purge_invalid_rt_entries(&mut EventBuf::new());
    }

    pub fn get_timed_out_tokens(&mut self) -> Vec<u64> {
        self.timer.get_timed_out_tokens()
    }

    pub fn section_list_signatures(
        &self,
        prefix: Prefix<XorName>,
    ) -> Result<BTreeMap<PublicId, sign::Signature>, RoutingError> {
        if let Some(&(_, ref signatures)) = self.section_list_sigs.get_signatures(prefix) {
            Ok(
                signatures
                    .iter()
                    .map(|(&pub_id, &sig)| (pub_id, sig))
                    .collect(),
            )
        } else {
            Err(RoutingError::NotEnoughSignatures)
        }
    }

    pub fn get_banned_client_ips(&self) -> BTreeSet<IpAddr> {
        self.banned_client_ips
            .peek_iter()
            .map(|(ip, _)| *ip)
            .collect()
    }

    pub fn set_next_relocation_dst(&mut self, dst: Option<XorName>) {
        self.next_relocation_dst = dst;
    }

    pub fn set_next_relocation_interval(&mut self, interval: (XorName, XorName)) {
        self.next_relocation_interval = Some(interval);
    }

    pub fn has_unnormalised_routing_conn(&self, excludes: &BTreeSet<XorName>) -> bool {
        self.peer_mgr.has_unnormalised_routing_conn(excludes)
    }

    pub fn get_user_msg_parts_count(&self) -> u64 {
        self.stats.msg_user_parts
    }

    pub fn get_clients_usage(&self) -> BTreeMap<IpAddr, u64> {
        self.clients_rate_limiter.usage_map().clone()
    }
}

impl Bootstrapped for Node {
    fn ack_mgr(&self) -> &AckManager {
        &self.ack_mgr
    }

    fn ack_mgr_mut(&mut self) -> &mut AckManager {
        &mut self.ack_mgr
    }

    // Constructs a signed message, finds the node responsible for accumulation, and either sends
    // this node a signature or tries to accumulate signatures for this message (on success, the
    // accumulator handles or forwards the message).
    fn send_routing_message_via_route(
        &mut self,
        routing_msg: RoutingMessage,
        route: u8,
        expires_at: Option<Instant>,
    ) -> Result<(), RoutingError> {
        if !self.in_authority(&routing_msg.src) {
            trace!(
                "{:?} Not part of the source authority. Not sending message {:?}.",
                self,
                routing_msg
            );
            return Ok(());
        }
        if !self.add_to_pending_acks(&routing_msg, route, expires_at) {
            debug!(
                "{:?} already received an ack for {:?} - so not resending it.",
                self,
                routing_msg
            );
            return Ok(());
        }
        use routing_table::Authority::*;
        let sending_names = match routing_msg.src {
            ClientManager(_) | NaeManager(_) | NodeManager(_) | ManagedNode(_) => {
                let section = self.routing_table().get_section(self.name()).ok_or(
                    RoutingError::RoutingTable(RoutingTableError::NoSuchPeer),
                )?;
                let pub_ids = self.peer_mgr.get_pub_ids(section);
                vec![SectionList::new(*self.our_prefix(), pub_ids)]
            }
            Section(_) => {
                vec![
                    SectionList::new(
                        *self.our_prefix(),
                        self.peer_mgr.get_pub_ids(
                            self.routing_table().our_section(),
                        )
                    ),
                ]
            }
            PrefixSection(ref prefix) => {
                self.routing_table()
                    .all_sections()
                    .into_iter()
                    .filter_map(|(p, (_, members))| if prefix.is_compatible(&p) {
                        Some(SectionList::new(p, self.peer_mgr.get_pub_ids(&members)))
                    } else {
                        None
                    })
                    .collect()
            }
            Client { .. } => vec![],
        };

        let signed_msg = SignedMessage::new(routing_msg, &self.full_id, sending_names)?;

        match self.get_signature_target(&signed_msg.routing_message().src, route) {
            None => Ok(()),
            Some(our_name) if our_name == *self.name() => {
                let min_section_size = self.min_section_size();
                if let Some((msg, route)) =
                    self.sig_accumulator.add_message(
                        signed_msg,
                        min_section_size,
                        route,
                    )
                {
                    if self.in_authority(&msg.routing_message().dst) {
                        self.handle_signed_message(
                            msg,
                            route,
                            our_name,
                            &BTreeSet::new(),
                        )?;
                    } else {
                        self.send_signed_message(
                            &msg,
                            route,
                            &our_name,
                            &BTreeSet::new(),
                        )?;
                    }
                }
                Ok(())
            }
            Some(target_name) => {
                if let Some(&pub_id) = self.peer_mgr.get_pub_id(&target_name) {
                    let direct_msg = signed_msg.routing_message().to_signature(
                        self.full_id
                            .signing_private_key(),
                    )?;
                    self.send_direct_message(pub_id, direct_msg);
                    Ok(())
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
        write!(formatter, "Node({}({:b}))", self.name(), self.our_prefix())
    }
}
