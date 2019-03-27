// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::common::{Base, Bootstrapped, USER_MSG_CACHE_EXPIRY_DURATION_SECS};
use crate::ack_manager::{Ack, AckManager};
use crate::action::Action;
use crate::cache::Cache;
use crate::chain::{
    Chain, GenesisPfxInfo, NetworkEvent, PrefixChangeOutcome, Proof, ProofSet, ProvingSection,
    SectionInfo,
};
use crate::config_handler;
use crate::crust::{ConnectionInfoResult, CrustError, CrustUser};
use crate::error::{BootstrapResponseError, InterfaceError, RoutingError};
use crate::event::Event;
use crate::id::{FullId, PublicId};
use crate::messages::{
    DirectMessage, HopMessage, Message, MessageContent, RoutingMessage, SignedMessage, UserMessage,
    UserMessageCache, DEFAULT_PRIORITY, MAX_PARTS, MAX_PART_LEN,
};
use crate::outbox::{EventBox, EventBuf};
use crate::parsec::{self, Parsec};
use crate::peer_manager::{ConnectionInfoPreparedResult, Peer, PeerManager, PeerState};
use crate::rate_limiter::RateLimiter;
use crate::resource_prover::{ResourceProver, RESOURCE_PROOF_DURATION_SECS};
use crate::routing_message_filter::{FilteringResult, RoutingMessageFilter};
use crate::routing_table::Error as RoutingTableError;
use crate::routing_table::{
    Authority, Prefix, RemovalDetails, RoutingTable, VersionedPrefix, Xorable,
};
use crate::sha3::Digest256;
use crate::signature_accumulator::SignatureAccumulator;
use crate::state_machine::Transition;
use crate::timer::Timer;
use crate::types::{MessageId, RoutingActionSender};
use crate::utils::{self, DisplayDuration};
use crate::xor_name::XorName;
use crate::{CrustEvent, PrivConnectionInfo, PubConnectionInfo, Service};
#[cfg(feature = "mock")]
use fake_clock::FakeClock as Instant;
use itertools::Itertools;
use log::LogLevel;
use lru_time_cache::LruCache;
use maidsafe_utilities::serialisation;
use rand::{self, Rng};
use safe_crypto::{SharedSecretKey, Signature};
use std::collections::BTreeMap;
use std::collections::{BTreeSet, VecDeque};
use std::fmt::{Display, Formatter};
use std::net::IpAddr;
use std::time::Duration;
#[cfg(not(feature = "mock"))]
use std::time::Instant;
use std::{cmp, fmt, iter, mem};

/// Time (in seconds) after which a `Tick` event is sent.
const TICK_TIMEOUT_SECS: u64 = 15;
const POKE_TIMEOUT_SECS: u64 = 60;
const GOSSIP_TIMEOUT_SECS: u64 = 2;
const RECONNECT_PEER_TIMEOUT_SECS: u64 = 20;
//const MAX_IDLE_ROUNDS: u64 = 100;
//const TICK_TIMEOUT_SECS: u64 = 60;
/// The number of required leading zero bits for the resource proof
const RESOURCE_PROOF_DIFFICULTY: u8 = 0;
/// The total size of the resource proof data.
const RESOURCE_PROOF_TARGET_SIZE: usize = 250 * 1024 * 1024;
/// Interval between displaying info about current candidate, in seconds.
const CANDIDATE_STATUS_INTERVAL_SECS: u64 = 60;
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
    /// The queue of routing messages addressed to us. These do not themselves need forwarding,
    /// although they may wrap a message which needs forwarding.
    msg_queue: VecDeque<RoutingMessage>,
    peer_mgr: PeerManager,
    response_cache: Box<Cache>,
    routing_msg_filter: RoutingMessageFilter,
    sig_accumulator: SignatureAccumulator,
    tick_timer_token: u64,
    timer: Timer,
    user_msg_cache: UserMessageCache,
    /// Value which can be set in mock-crust tests to be used as the calculated name for the next
    /// relocation request received by this node.
    next_relocation_dst: Option<XorName>,
    /// Interval used for relocation in mock crust tests.
    next_relocation_interval: Option<(XorName, XorName)>,
    /// `RoutingMessage`s affecting the routing table that arrived before `NodeApproval`.
    routing_msg_backlog: Vec<RoutingMessage>,
    /// The timer token for accepting a new candidate.
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
    parsec_map: BTreeMap<u64, Parsec<NetworkEvent, FullId>>,
    gen_pfx_info: Option<GenesisPfxInfo>,
    poke_timer_token: Option<u64>,
    gossip_timer_token: Option<u64>,
    chain: Chain,
    // Peers we want to try reconnecting to
    reconnect_peers: Vec<PublicId>,
    reconnect_peers_token: u64,
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
            timer,
            0,
        );
        node.peer_mgr.set_established();

        if let Err(error) = node.crust_service.start_listening_tcp() {
            error!("{} Failed to start listening: {:?}", node, error);
            None
        } else {
            debug!("{} State changed to node.", node);
            info!("{} Started a new network as a seed node.", node);
            Some(node)
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_bootstrapping(
        our_section: (Prefix<XorName>, BTreeSet<PublicId>),
        action_sender: RoutingActionSender,
        cache: Box<Cache>,
        crust_service: Service,
        old_full_id: FullId,
        new_full_id: FullId,
        min_section_size: usize,
        proxy_pub_id: PublicId,
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
            timer,
            our_section.1.len(),
        );
        node.joining_prefix = our_section.0;
        node.peer_mgr
            .insert_peer(Peer::new(proxy_pub_id, PeerState::Proxy));
        node.join(our_section.1, &proxy_pub_id);
        node
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        action_sender: RoutingActionSender,
        cache: Box<Cache>,
        crust_service: Service,
        first_node: bool,
        old_full_id: FullId,
        new_full_id: FullId,
        min_section_size: usize,
        timer: Timer,
        challenger_count: usize,
    ) -> Self {
        let dev_config = config_handler::get_config().dev.unwrap_or_default();
        let public_id = *new_full_id.public_id();
        let tick_period = Duration::from_secs(TICK_TIMEOUT_SECS);
        let tick_timer_token = timer.schedule(tick_period);
        let gossip_timer_token = Some(timer.schedule(Duration::from_secs(GOSSIP_TIMEOUT_SECS)));
        let user_msg_cache_duration = Duration::from_secs(USER_MSG_CACHE_EXPIRY_DURATION_SECS);
        let reconnect_peers_token =
            timer.schedule(Duration::from_secs(RECONNECT_PEER_TIMEOUT_SECS));

        Node {
            ack_mgr: AckManager::new(),
            cacheable_user_msg_cache: UserMessageCache::with_expiry_duration(
                user_msg_cache_duration,
            ),
            crust_service: crust_service,
            old_full_id: old_full_id,
            full_id: new_full_id,
            is_first_node: first_node,
            msg_queue: VecDeque::new(),
            peer_mgr: PeerManager::new(
                min_section_size,
                public_id,
                dev_config.disable_client_rate_limiter,
            ),
            response_cache: cache,
            routing_msg_filter: RoutingMessageFilter::new(),
            sig_accumulator: Default::default(),
            tick_timer_token: tick_timer_token,
            timer: timer.clone(),
            user_msg_cache: UserMessageCache::with_expiry_duration(user_msg_cache_duration),
            next_relocation_dst: None,
            next_relocation_interval: None,
            routing_msg_backlog: vec![],
            candidate_timer_token: None,
            candidate_status_token: None,
            resource_prover: ResourceProver::new(action_sender, timer, challenger_count),
            joining_prefix: Default::default(),
            clients_rate_limiter: RateLimiter::new(dev_config.disable_client_rate_limiter),
            banned_client_ips: LruCache::with_expiry_duration(Duration::from_secs(CLIENT_BAN_SECS)),
            dropped_clients: LruCache::with_expiry_duration(Duration::from_secs(
                DROPPED_CLIENT_TIMEOUT_SECS,
            )),
            proxy_load_amount: 0,
            disable_resource_proof: dev_config.disable_resource_proof,
            parsec_map: Default::default(),
            gen_pfx_info: None,
            poke_timer_token: None,
            gossip_timer_token,
            chain: Chain::with_min_sec_size(min_section_size),
            reconnect_peers: Default::default(),
            reconnect_peers_token,
        }
    }

    /// Called immediately after bootstrapping. Sends `ConnectionInfoRequest`s to all members of
    /// `our_section` to then start the candidate approval process.
    fn join(&mut self, our_section: BTreeSet<PublicId>, proxy_public_id: &PublicId) {
        self.resource_prover.start(self.disable_resource_proof);

        trace!("{} Relocation completed.", self);
        info!(
            "{} Received relocation section. Establishing connections to {} peers.",
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
                "{} Sending connection info to {:?} on Relocation response.",
                self, pub_id
            );
            let dst = Authority::ManagedNode(*pub_id.name());
            if let Err(error) = self.send_connection_info_request(*pub_id, src, dst, &mut outbox) {
                debug!(
                    "{} - Failed to send connection info to {:?}: {:?}",
                    self, pub_id, error
                );
            }
        }
    }

    fn print_rt_size(&self) {
        const TABLE_LVL: LogLevel = LogLevel::Info;
        if log_enabled!(TABLE_LVL) {
            let status_str = format!(
                "{} - Routing Table size: {:3}",
                self,
                self.chain.valid_peers(true).len()
            );
            let network_estimate = match self.chain().network_size_estimate() {
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
                let msg = self
                    .resource_prover
                    .handle_action_res_proof(pub_id, messages);
                self.send_direct_message(pub_id, msg);
            }
            Action::Terminate => {
                return Transition::Terminate;
            }
        }

        self.handle_routing_messages(outbox);
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
            CrustEvent::BootstrapConnect(pub_id, _) => self.handle_bootstrap_connect(pub_id),
            CrustEvent::ConnectSuccess(pub_id) => self.handle_connect_success(pub_id, outbox),
            CrustEvent::ConnectFailure(pub_id) => self.handle_connect_failure(pub_id, outbox),
            CrustEvent::LostPeer(pub_id) => {
                if let Transition::Terminate = self.handle_lost_peer(pub_id, outbox) {
                    return Transition::Terminate;
                }
            }
            CrustEvent::NewMessage(pub_id, _peer_kind, bytes) => {
                match self.handle_new_message(pub_id, bytes, outbox) {
                    Err(RoutingError::FilterCheckFailed) | Ok(_) => (),
                    Err(err) => debug!("{} - {:?}", self, err),
                }
            }
            CrustEvent::ConnectionInfoPrepared(ConnectionInfoResult {
                result_token,
                result,
            }) => self.handle_connection_info_prepared(result_token, result),
            CrustEvent::ListenerStarted(port) => {
                trace!("{} Listener started on port {}.", self, port);
                // If first node, allow other peers to bootstrap via us
                // else wait until NodeApproval.
                if self.is_first_node {
                    if let Err(err) = self.crust_service.set_accept_bootstrap(true) {
                        warn!("{} Unable to accept bootstrap connections. {:?}", self, err);
                    }
                    self.crust_service.set_service_discovery_listen(true);
                }
                return Transition::Stay;
            }
            CrustEvent::ListenerFailed => {
                error!("{} Failed to start listening.", self);
                outbox.send_event(Event::Terminate);
                return Transition::Terminate;
            }
            CrustEvent::WriteMsgSizeProhibitive(pub_id, msg) => {
                error!(
                    "{} Failed to send {}-byte message to {:?}. Message too large.",
                    self,
                    msg.len(),
                    pub_id
                );
            }
            _ => {
                debug!("{} - Unhandled crust event: {:?}", self, crust_event);
            }
        }

        self.handle_routing_messages(outbox);
        Transition::Stay
    }

    /// Routing table of this node.
    pub fn routing_table(&self) -> &RoutingTable<XorName> {
        self.peer_mgr.routing_table()
    }

    /// Routing table of this node.
    #[allow(unused)]
    pub fn chain(&self) -> &Chain {
        &self.chain
    }

    fn handle_routing_messages(&mut self, outbox: &mut EventBox) {
        while let Some(routing_msg) = self.msg_queue.pop_front() {
            if self.in_authority(&routing_msg.dst) {
                if let Err(err) = self.dispatch_routing_message(routing_msg, outbox) {
                    debug!("{} Routing message dispatch failed: {:?}", self, err);
                }
            }
        }
    }

    fn handle_bootstrap_accept(&mut self, pub_id: PublicId, peer_kind: CrustUser) {
        trace!(
            "{} Received BootstrapAccept from {:?} as {:?}.",
            self,
            pub_id,
            peer_kind
        );
        let ip = if let Ok(ip) = self.crust_service.get_peer_ip_addr(&pub_id) {
            ip
        } else {
            debug!(
                "{} Can't get IP address of bootstrapper {:?}.",
                self, pub_id
            );
            self.disconnect_peer(&pub_id);
            if peer_kind == CrustUser::Client {
                let _ = self.dropped_clients.insert(pub_id, ());
            }
            return;
        };

        if peer_kind == CrustUser::Client && self.banned_client_ips.contains_key(&ip) {
            warn!(
                "{} Client {:?} is trying to bootstrap on banned IP {}.",
                self, pub_id, ip
            );
            self.ban_and_disconnect_peer(&pub_id);
            return;
        }
        self.peer_mgr
            .insert_peer(Peer::new(pub_id, PeerState::Bootstrapper { peer_kind, ip }));
    }

    fn handle_bootstrap_connect(&mut self, pub_id: PublicId) {
        // A mature node doesn't need a bootstrap connection
        self.disconnect_peer(&pub_id)
    }

    fn handle_connect_success(&mut self, pub_id: PublicId, outbox: &mut EventBox) {
        if self
            .peer_mgr
            .get_peer(&pub_id)
            .map_or(false, Peer::is_routing)
        {
            warn!(
                "{} Received ConnectSuccess from {:?}, but node is already in routing \
                 state in peer_map.",
                self, pub_id
            );
            return;
        }

        self.peer_mgr.connected_to(&pub_id);
        debug!("{} Received ConnectSuccess from {}.", self, pub_id);
        self.process_connection(pub_id, outbox);
    }

    fn handle_connect_failure(&mut self, pub_id: PublicId, outbox: &mut EventBox) {
        if let Some(&PeerState::CrustConnecting) = self.peer_mgr.get_peer(&pub_id).map(Peer::state)
        {
            debug!("{} Failed to connect to peer {:?}.", self, pub_id);
        }
        let _ = self.dropped_peer(&pub_id, outbox, true);
        if self.chain.is_member() && self.chain.our_info().members().contains(&pub_id) {
            self.vote_for_event(NetworkEvent::Offline(pub_id));
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
        use crate::messages::DirectMessage::*;
        if let Err(error) = self.check_direct_message_sender(&direct_message, &pub_id) {
            match error {
                RoutingError::ClientConnectionNotFound => (),
                _ => self.ban_and_disconnect_peer(&pub_id),
            }
            return Err(error);
        }

        match direct_message {
            MessageSignature(digest, sig) => self.handle_message_signature(digest, sig, pub_id)?,
            BootstrapRequest(signature) => {
                if let Err(error) = self.handle_bootstrap_request(pub_id, signature) {
                    warn!(
                        "{} Invalid BootstrapRequest received ({:?}), dropping {}.",
                        self, error, pub_id
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
                        "{} CandidateInfo(new_public_id: {}) does not match crust id {}.",
                        self, new_public_id, pub_id
                    );
                    self.disconnect_peer(&pub_id);
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
            ResourceProof {
                seed,
                target_size,
                difficulty,
            } => {
                let log_ident = format!("{}", self);
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
                    outbox,
                );
            }
            msg @ BootstrapResponse(_) | msg @ ProxyRateLimitExceeded { .. } => {
                debug!("{} Unhandled direct message: {:?}", self, msg);
            }
            ParsecPoke(version) => self.handle_parsec_poke(version, pub_id),
            ParsecRequest(version, par_request) => {
                self.handle_parsec_request(version, par_request, pub_id, outbox)?;
            }
            ParsecResponse(version, par_response) => {
                self.handle_parsec_response(version, par_response, pub_id, outbox)?;
            }
        }
        Ok(())
    }

    fn handle_parsec_poke(&mut self, msg_version: u64, pub_id: PublicId) {
        self.send_parsec_gossip(Some((msg_version, pub_id)))
    }

    fn handle_parsec_request(
        &mut self,
        msg_version: u64,
        par_request: parsec::Request<NetworkEvent, PublicId>,
        pub_id: PublicId,
        outbox: &mut EventBox,
    ) -> Result<(), RoutingError> {
        match self
            .parsec_map
            .get_mut(&msg_version)
            .map(|par| par.handle_request(&pub_id, par_request))
        {
            Some(Ok(rsp)) => {
                let direct_msg = Message::Direct(DirectMessage::ParsecResponse(msg_version, rsp));
                self.send_message(&pub_id, direct_msg);
            }
            Some(Err(err)) => debug!("{} Error handling parsec request: {:?}", self, err),
            None => return Ok(()), // No such parsec version yet.
        }
        if Some(&msg_version) == self.parsec_map.keys().last() {
            self.parsec_poll(outbox)?;
        }
        Ok(())
    }

    fn handle_parsec_response(
        &mut self,
        msg_version: u64,
        par_response: parsec::Response<NetworkEvent, PublicId>,
        pub_id: PublicId,
        outbox: &mut EventBox,
    ) -> Result<(), RoutingError> {
        match self
            .parsec_map
            .get_mut(&msg_version)
            .map(|par| par.handle_response(&pub_id, par_response))
        {
            Some(Ok(_)) => {}
            Some(Err(err)) => trace!("{} Error handling parsec response: {:?}", self, err),
            None => return Ok(()), // No such parsec version yet.
        }
        if Some(&msg_version) == self.parsec_map.keys().last() {
            self.parsec_poll(outbox)?;
        }
        Ok(())
    }

    fn parsec_poll(&mut self, outbox: &mut EventBox) -> Result<(), RoutingError> {
        while let Some(block) = self.parsec_map.values_mut().last().and_then(Parsec::poll) {
            match block.payload() {
                parsec::Observation::Accusation { .. } => {
                    // FIXME: Handle properly
                    unreachable!("...")
                }
                parsec::Observation::Genesis(_) => {
                    // FIXME: Validate with Chain info.
                    continue;
                }
                parsec::Observation::OpaquePayload(event) => {
                    if let Some(proof) = block.proofs().iter().next().map(|p| Proof {
                        pub_id: *p.public_id(),
                        sig: *p.signature(),
                    }) {
                        trace!(
                            "{} Parsec OpaquePayload: {} - {:?}",
                            self,
                            proof.pub_id(),
                            event
                        );
                        self.chain.handle_opaque_event(event, proof)?;
                    }
                }
                parsec::Observation::Add {
                    peer_id,
                    related_info,
                } => {
                    let event =
                        NetworkEvent::Online(*peer_id, serialisation::deserialise(&related_info)?);
                    let to_sig = |p: &parsec::Proof<_>| (*p.public_id(), *p.signature());
                    let sigs = block.proofs().iter().map(to_sig).collect();
                    let proof_set = ProofSet { sigs };
                    trace!("{} Parsec Add: - {}", self, peer_id);
                    self.chain.handle_churn_event(&event, proof_set)?;
                }
                parsec::Observation::Remove { peer_id, .. } => {
                    let event = NetworkEvent::Offline(*peer_id);
                    let to_sig = |p: &parsec::Proof<_>| (*p.public_id(), *p.signature());
                    let sigs = block.proofs().iter().map(to_sig).collect();
                    let proof_set = ProofSet { sigs };
                    trace!("{} Parsec Remove: - {}", self, peer_id);
                    self.chain.handle_churn_event(&event, proof_set)?;
                }
            }

            self.chain_poll(outbox)?;
        }

        Ok(())
    }

    fn chain_poll(&mut self, outbox: &mut EventBox) -> Result<(), RoutingError> {
        let mut our_pfx = *self.chain.our_prefix();
        while let Some(event) = self.chain.poll()? {
            trace!("{} Handle accumulated event: {:?}", self, event);

            match event {
                NetworkEvent::Online(pub_id, client_auth) => {
                    self.handle_online_event(pub_id, client_auth, outbox)?;
                }
                NetworkEvent::Offline(pub_id) => {
                    self.handle_offline_event(pub_id, outbox)?;
                }
                NetworkEvent::OurMerge => self.handle_our_merge_event()?,
                NetworkEvent::NeighbourMerge(_) => self.handle_neighbour_merge_event()?,
                NetworkEvent::SectionInfo(ref sec_info) => {
                    self.handle_section_info_event(sec_info, our_pfx, outbox)?;
                }
                NetworkEvent::ProvingSections(ps, sec_info) => {
                    self.handle_proving_sections_event(ps, sec_info)?;
                }
            }

            our_pfx = *self.chain.our_prefix();
        }

        Ok(())
    }

    /// Handles an accumulated `Online` event.
    fn handle_online_event(
        &mut self,
        new_pub_id: PublicId,
        new_client_auth: Authority<XorName>,
        outbox: &mut EventBox,
    ) -> Result<(), RoutingError> {
        let should_act = self.chain.is_member();
        let to_vote_infos = self.chain.add_member(new_pub_id)?;
        if should_act {
            let _ = self.handle_candidate_approval(new_pub_id, new_client_auth, outbox);
            to_vote_infos
                .into_iter()
                .map(NetworkEvent::SectionInfo)
                .for_each(|sec_info| self.vote_for_event(sec_info));
        }

        Ok(())
    }

    /// Handles an accumulated `Offline` event.
    fn handle_offline_event(
        &mut self,
        pub_id: PublicId,
        outbox: &mut EventBox,
    ) -> Result<(), RoutingError> {
        let should_act = self.chain.is_member();
        let self_info = self.chain.remove_member(pub_id)?;
        if should_act {
            self.vote_for_event(NetworkEvent::SectionInfo(self_info));
            if let Some(&pub_id) = self.peer_mgr.get_pub_id(pub_id.name()) {
                let _ = self.dropped_peer(&pub_id, outbox, false);
                self.disconnect_peer(&pub_id);
            }
        }
        Ok(())
    }

    /// Handles an accumulated `OurMerge` event.
    fn handle_our_merge_event(&mut self) -> Result<(), RoutingError> {
        self.merge_if_necessary()
    }

    /// Handles an accumulated `NeighbourMerge` event.
    fn handle_neighbour_merge_event(&mut self) -> Result<(), RoutingError> {
        self.merge_if_necessary()
    }

    /// Votes for `Merge` if necessary, or for the merged `SectionInfo` if both siblings have
    /// already accumulated `Merge`.
    fn merge_if_necessary(&mut self) -> Result<(), RoutingError> {
        let sibling_pfx = self.our_prefix().sibling();
        if self.chain.is_self_merge_ready() && self.chain.other_prefixes().contains(&sibling_pfx) {
            let payload = *self.chain.our_info().hash();
            let src = Authority::PrefixSection(self.our_prefix());
            let dst = Authority::PrefixSection(sibling_pfx);
            let content = MessageContent::Merge(payload);
            if let Err(err) = self.send_routing_message(src, dst, content) {
                debug!("{} Failed to send Merge: {:?}.", self, err);
            }
        }
        if let Some(merged_info) = self.chain.try_merge()? {
            self.vote_for_event(NetworkEvent::SectionInfo(merged_info));
        } else if self.chain.should_vote_for_merge() && !self.chain.is_self_merge_ready() {
            self.vote_for_event(NetworkEvent::OurMerge);
        }
        Ok(())
    }

    /// Handles an accumulated `SectionInfo` event.
    fn handle_section_info_event(
        &mut self,
        sec_info: &SectionInfo,
        old_pfx: Prefix<XorName>,
        outbox: &mut EventBox,
    ) -> Result<(), RoutingError> {
        if !self.peer_mgr.is_established() && self.chain.is_member() {
            // We have just found a `SectionInfo` block that contains us. Now we can supply our
            // votes for all latest neighbour infos that have accumulated so far.
            let ni_events = self
                .chain
                .neighbour_infos()
                .map(|ni| ni.clone().into_network_event())
                .collect_vec();

            ni_events.into_iter().for_each(|ni_event| {
                self.vote_for_event(ni_event);
            });

            self.node_established(outbox);
        }

        if sec_info.prefix().is_extension_of(&old_pfx) {
            self.finalise_prefix_change()?;
            // FIXME - remove version from being a requirement here
            let our_ver_pfx = self.routing_table().our_versioned_prefix();
            self.handle_section_split(our_ver_pfx, outbox)?;
            self.send_neighbour_infos();
        } else if old_pfx.is_extension_of(sec_info.prefix()) {
            self.finalise_prefix_change()?;
            let _ = self.peer_mgr.add_prefix(sec_info.prefix().with_version(0));
            outbox.send_event(Event::SectionMerge(*sec_info.prefix()));
        }

        let our_name = *self.full_id.public_id().name();
        let self_sec_update = sec_info.prefix().matches(&our_name);
        if !self_sec_update {
            self.handle_section_update(sec_info.prefix().with_version(0));
        }

        if self.chain.is_member() {
            self.update_peer_states(outbox);

            if self_sec_update {
                self.send_neighbour_infos();
            } else {
                // Vote for neighbour update if we haven't done so already.
                // vote_for_event is expected to only generate a new vote if required.
                self.vote_for_event(sec_info.clone().into_network_event());
            }
        }

        let _ = self.merge_if_necessary();

        Ok(())
    }

    /// Handles an accumulated `ProvingSections` event.
    ///
    /// Votes for all sections that it can verify using the the chain of proving sections.
    fn handle_proving_sections_event(
        &mut self,
        proving_secs: Vec<ProvingSection>,
        sec_info: SectionInfo,
    ) -> Result<(), RoutingError> {
        if !self.chain.is_new_neighbour(&sec_info)
            && !proving_secs
                .iter()
                .any(|ps| self.chain.is_new_neighbour(&ps.sec_info))
        {
            return Ok(()); // Nothing new to learn here.
        }
        let validates = |trusted: &Option<ProvingSection>, si: &SectionInfo| {
            trusted.as_ref().map_or(false, |tps| {
                let valid = tps.validate(&si);
                if !valid {
                    log_or_panic!(LogLevel::Info, "Received invalid proving section: {:?}", si);
                }
                valid
            })
        };
        let mut trusted: Option<ProvingSection> = None;
        for ps in proving_secs.into_iter().rev() {
            if validates(&trusted, &ps.sec_info) || self.is_trusted(&ps.sec_info)? {
                let _ = self.add_new_section(&ps.sec_info);
                trusted = Some(ps);
            }
        }
        if validates(&trusted, &sec_info) || self.is_trusted(&sec_info)? {
            let _ = self.add_new_section(&sec_info);
        }
        Ok(())
    }

    // Connected peers which are valid need added to RT
    // Peers no longer required currently connected as PeerState::Routing are disconnected
    // Establish connection to peers missing from peer manager
    fn update_peer_states(&mut self, outbox: &mut EventBox) {
        // If we are not yet established, do not try to update any RT peer states
        if !self.chain.is_member() {
            return;
        }

        let mut peers_to_add = Vec::new();
        let mut peers_to_remove = Vec::new();

        for peer in self.peer_mgr.connected_peers() {
            let pub_id = peer.pub_id();
            if self.chain.is_peer_valid(pub_id) {
                peers_to_add.push(*pub_id);
            } else if peer.is_routing()
                && !self.peer_mgr.is_proxy(pub_id)
                && !self.peer_mgr.is_joining_node(pub_id)
            {
                peers_to_remove.push(*peer.pub_id());
            }
        }
        for pub_id in peers_to_add {
            self.add_to_routing_table(&pub_id, outbox);
        }
        for pub_id in peers_to_remove {
            trace!("{} Removing {:?} from RT.", self, pub_id);
            let _ = self.peer_mgr.remove_peer(&pub_id);
            self.disconnect_peer(&pub_id);
        }

        let peers_to_connect: BTreeSet<PublicId> = self
            .chain
            .valid_peers(true)
            .iter()
            .filter_map(|pub_id| {
                if self.peer_mgr.get_peer(pub_id).is_none() && *pub_id != self.full_id.public_id() {
                    Some(**pub_id)
                } else {
                    None
                }
            })
            .collect();
        for pub_id in peers_to_connect {
            debug!("{} Sending connection info to {:?}.", self, pub_id);
            let src = Authority::ManagedNode(*self.name());
            let node_auth = Authority::ManagedNode(*pub_id.name());
            if let Err(error) = self.send_connection_info_request(pub_id, src, node_auth, outbox) {
                debug!(
                    "{} - Failed to send connection info to {:?}: {:?}",
                    self, pub_id, error
                );
            }
        }
    }

    fn finalise_prefix_change(&mut self) -> Result<(), RoutingError> {
        let drained_obs = if let Some(par) = self.parsec_map.values().last() {
            par.our_unpolled_observations().cloned().collect()
        } else {
            vec![]
        };
        let sibling_pfx = self.chain.our_prefix().sibling();

        let PrefixChangeOutcome {
            gen_pfx_info,
            mut cached_events,
            completed_events,
        } = self.chain.finalise_prefix_change()?;
        self.gen_pfx_info = Some(gen_pfx_info);
        let _ = self.init_parsec()?; // We don't reset the chain on prefix change.

        let neighbour_infos: Vec<_> = self.chain.neighbour_infos().cloned().collect();
        for ni in neighbour_infos {
            if sibling_pfx != *ni.prefix() {
                debug!("{} Committing neighbour section proof for {:?}", self, ni);
                let ps = self.chain.get_proving_sections(&ni, *self.name())?;
                self.vote_for_event(NetworkEvent::ProvingSections(ps, ni.clone()));
            }
            debug!("{} Re-voting for neighbour section {:?}", self, ni);
            self.vote_for_event(ni.into_network_event());
        }

        for obs in drained_obs {
            let event = match obs {
                parsec::Observation::Add {
                    peer_id,
                    related_info,
                } => NetworkEvent::Online(peer_id, serialisation::deserialise(&related_info)?),
                parsec::Observation::Remove { peer_id, .. } => NetworkEvent::Offline(peer_id),
                parsec::Observation::OpaquePayload(event) => event.clone(),
                _ => continue,
            };
            let _ = cached_events.insert(event);
        }
        let our_pfx = *self.chain.our_prefix();
        // filter cached events to SectionInfo where we benefit from additional signatures for
        // neighbours for sec-msg-relay. Online/Offline events we only need to re-vote events which
        // havent yet accumulated in old prefix and that are relevant to our new prefix.
        cached_events
            .iter()
            .filter(|event| match **event {
                // FIXME: once has_unconsensused_observations only considers votes than Obs
                // can enable this similar to Offline event
                NetworkEvent::Online(_pub_id, _) => false,
                NetworkEvent::Offline(pub_id) => {
                    our_pfx.matches(pub_id.name()) && !completed_events.contains(event)
                }
                NetworkEvent::SectionInfo(ref sec_info) => our_pfx.is_neighbour(sec_info.prefix()),
                NetworkEvent::OurMerge => false,
                _ => true,
            })
            .for_each(|event| {
                self.vote_for_event(event.clone());
            });

        Ok(())
    }

    fn send_neighbour_infos(&mut self) {
        self.chain.other_prefixes().iter().for_each(|pfx| {
            let payload = *self.chain.our_info().hash();
            let src = Authority::ManagedNode(*self.full_id.public_id().name());
            let dst = Authority::PrefixSection(*pfx);
            let content = MessageContent::NeighbourInfo(payload);
            if let Err(err) = self.send_routing_message(src, dst, content) {
                debug!("{} Failed to send NeighbourInfo: {:?}.", self, err);
            }
        });
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
            "{} Illegitimate direct message {:?} from {:?}.",
            self, direct_message, pub_id
        );
        Err(RoutingError::InvalidStateForOperation)
    }

    /// Handles a signature of a `SignedMessage`, and if we have enough to verify the signed
    /// message, handles it.
    fn handle_message_signature(
        &mut self,
        digest: Digest256,
        sig: Signature,
        pub_id: PublicId,
    ) -> Result<(), RoutingError> {
        if !self
            .peer_mgr
            .get_peer(&pub_id)
            .map_or(false, Peer::is_routing)
        {
            debug!(
                "{} Received message signature from unknown peer {}",
                self, pub_id
            );
            return Err(RoutingError::UnknownConnection(pub_id));
        }

        let min_section_size = self.min_section_size();
        let proof = Proof { sig, pub_id };
        if let Some((signed_msg, route)) =
            self.sig_accumulator
                .add_proof(min_section_size, digest, proof)
        {
            let hop = *self.name(); // we accumulated the message, so now we act as the last hop
            self.handle_signed_message(signed_msg, route, hop, &BTreeSet::new())?;
        }
        Ok(())
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
                    "{} Hop message received from bootstrapper {:?}, disconnecting.",
                    self, pub_id
                );
                Err(RoutingError::InvalidStateForOperation)
            }
            Some(&PeerState::Client { ip, .. }) => {
                client_ip = Some(ip);
                Ok(*self.name())
            }
            Some(&PeerState::JoiningNode) => Ok(*self.name()),
            Some(&PeerState::Candidate(_))
            | Some(&PeerState::Proxy)
            | Some(&PeerState::Routing(_)) => Ok(*pub_id.name()),
            Some(&PeerState::ConnectionInfoPreparing { .. })
            | Some(&PeerState::ConnectionInfoReady(_))
            | Some(&PeerState::CrustConnecting)
            | Some(&PeerState::Connected)
            | None => {
                if self.dropped_clients.contains_key(&pub_id) {
                    debug!(
                        "{} Ignoring {:?} from recently-disconnected client {:?}.",
                        self, hop_msg, pub_id
                    );
                    return Ok(());
                } else {
                    Ok(*self.name())
                    // FIXME - confirm we can return with an error here by running soak tests
                    // debug!("{} Invalid sender {} of {:?}", self, pub_id, hop_msg);
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
                    "{} Temporarily can't proxy messages from client {:?} (rate-limit hit).",
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
        mut signed_msg: SignedMessage,
        route: u8,
        hop_name: XorName,
        sent_to: &BTreeSet<XorName>,
    ) -> Result<(), RoutingError> {
        signed_msg.check_integrity(self.min_section_size())?;

        if signed_msg.routing_message().src.is_client() {
            if signed_msg.previous_hop().is_some() {
                warn!("{} Unexpected section infos in {:?}", self, signed_msg);
                return Err(RoutingError::InvalidProvingSection);
            }
        } else if self.chain.is_member() {
            // Remove any untrusted trailing section infos.
            // TODO: remove wasted clone. Only useful when msg isnt trusted for log msg.
            let msg_clone = signed_msg.clone();
            while match signed_msg.previous_hop() {
                None => true,
                Some(hop) => !self.is_trusted(hop)?,
            } {
                // We don't know the last hop! Try the one before that.
                if !signed_msg.pop_previous_hop() {
                    debug!("{} Untrusted message: {:?}", self, msg_clone);
                    return Err(RoutingError::NotEnoughSignatures);
                }
            }
            // Now that we validated the sections, inform our peers about any new ones.
            if signed_msg
                .section_infos()
                .any(|si| self.chain.is_new_neighbour(si))
            {
                if let Some(si) = signed_msg.source_section() {
                    // TODO: Why is `add_new_sections` still necessary? The vote should suffice.
                    // TODO: This is enabled for relayed messages only because it considerably
                    //       slows down the tests. Find out why, maybe enable it in more cases.
                    if self.add_new_sections(signed_msg.section_infos())
                        && !self.in_authority(&signed_msg.routing_message().dst)
                    {
                        let ps = signed_msg.proving_sections().clone();
                        self.vote_for_event(NetworkEvent::ProvingSections(ps, si.clone()));
                    }
                }
            }
        }

        let filter_res = self
            .routing_msg_filter
            .filter_incoming(signed_msg.routing_message(), route);
        if filter_res == FilteringResult::KnownMessageAndRoute {
            return Ok(());
        };

        if self.in_authority(&signed_msg.routing_message().dst) {
            self.send_ack(signed_msg.routing_message(), route);
            if signed_msg.routing_message().dst.is_multiple() {
                // Broadcast to the rest of the section.
                if let Err(error) =
                    self.send_signed_message(&mut signed_msg, route, &hop_name, sent_to)
                {
                    debug!("{} Failed to send {:?}: {:?}", self, signed_msg, error);
                }
            }
            if filter_res == FilteringResult::NewMessage {
                // if addressed to us, then we just queue it and return
                self.msg_queue.push_back(signed_msg.into_routing_message());
            }
            return Ok(());
        }

        if self.respond_from_cache(signed_msg.routing_message(), route)? {
            return Ok(());
        }

        if let Err(error) = self.send_signed_message(&mut signed_msg, route, &hop_name, sent_to) {
            debug!("{} Failed to send {:?}: {:?}", self, signed_msg, error);
        }

        Ok(())
    }

    fn dispatch_routing_message(
        &mut self,
        routing_msg: RoutingMessage,
        outbox: &mut EventBox,
    ) -> Result<(), RoutingError> {
        use crate::messages::MessageContent::*;
        use crate::Authority::{Client, ManagedNode, PrefixSection, Section};

        if !self.chain.is_member() && !self.is_first_node {
            match routing_msg.content {
                ExpectCandidate { .. }
                | AcceptAsCandidate { .. }
                | NeighbourInfo(..)
                | NeighbourConfirm(..)
                | Merge(..)
                | UserMessagePart { .. } => {
                    // These messages should not be handled before node approval
                    trace!(
                        "{} Not approved yet. Delaying message handling: {:?}",
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
                            "{} Not approved yet. Delaying message handling: {:?}",
                            self,
                            routing_msg
                        );
                        self.routing_msg_backlog.push(routing_msg);
                        return Ok(());
                    }
                }
                Relocate { .. }
                | ConnectionInfoResponse { .. }
                | RelocateResponse { .. }
                | Ack(..)
                | NodeApproval { .. } => {
                    // Handle like normal
                }
            }
        }

        match routing_msg.content {
            Ack(..) | UserMessagePart { .. } => (),
            _ => trace!("{} Got routing message {:?}.", self, routing_msg),
        }

        match (routing_msg.content, routing_msg.src, routing_msg.dst) {
            (
                Relocate { message_id },
                Client {
                    client_id,
                    proxy_node_name,
                },
                Section(dst_name),
            ) => self.handle_relocate_request(client_id, proxy_node_name, dst_name, message_id),
            (
                ExpectCandidate {
                    old_public_id,
                    old_client_auth,
                    message_id,
                },
                Section(_),
                relocation_dst @ Section(_),
            ) => self.handle_expect_candidate(
                old_public_id,
                old_client_auth,
                relocation_dst,
                message_id,
            ),
            (
                AcceptAsCandidate {
                    old_public_id,
                    old_client_auth,
                    target_interval,
                    message_id,
                },
                Section(_),
                dst @ Section(_),
            ) => self.handle_accept_as_candidate(
                old_public_id,
                old_client_auth,
                dst,
                target_interval,
                message_id,
            ),
            (
                ConnectionInfoRequest {
                    encrypted_conn_info,
                    pub_id,
                    msg_id,
                },
                src @ Client { .. },
                dst @ ManagedNode(_),
            )
            | (
                ConnectionInfoRequest {
                    encrypted_conn_info,
                    pub_id,
                    msg_id,
                },
                src @ ManagedNode(_),
                dst @ ManagedNode(_),
            ) => self.handle_connection_info_request(
                encrypted_conn_info,
                pub_id,
                msg_id,
                src,
                dst,
                outbox,
            ),
            (
                ConnectionInfoResponse {
                    encrypted_conn_info,
                    pub_id,
                    msg_id,
                },
                ManagedNode(src_name),
                dst @ Client { .. },
            )
            | (
                ConnectionInfoResponse {
                    encrypted_conn_info,
                    pub_id,
                    msg_id,
                },
                ManagedNode(src_name),
                dst @ ManagedNode(_),
            ) => self.handle_connection_info_response(
                encrypted_conn_info,
                pub_id,
                msg_id,
                src_name,
                dst,
            ),
            (NodeApproval(gen_info), PrefixSection(_), Client { .. }) => {
                self.handle_node_approval(gen_info, outbox)
            }
            (NeighbourInfo(_digest), ManagedNode(_), PrefixSection(_)) => Ok(()),
            (
                NeighbourConfirm(digest, proofs, sec_infos_and_proofs),
                ManagedNode(_),
                Section(_),
            ) => self.handle_neighbour_confirm(digest, proofs, sec_infos_and_proofs),
            (Merge(digest), PrefixSection(_), PrefixSection(_)) => self.handle_merge(digest),
            (Ack(ack, _), _, _) => self.handle_ack_response(ack),
            (
                UserMessagePart {
                    hash,
                    part_count,
                    part_index,
                    payload,
                    ..
                },
                src,
                dst,
            ) => {
                if let Some(msg) = self
                    .user_msg_cache
                    .add(hash, part_count, part_index, payload)
                {
                    outbox.send_event(msg.into_event(src, dst));
                }
                Ok(())
            }
            (content, src, dst) => {
                debug!(
                    "{} Unhandled routing message {:?} from {:?} to {:?}",
                    self, content, src, dst
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
        self.remove_expired_peers();

        // Once the joining node joined, it may receive the vote regarding itself.
        // Or a node may receive CandidateApproval before connection established.
        // If we are not connected to the candidate, we do not want to add them
        // to our RT.
        // This will flag peer as valid if its found in peer_mgr regardless of their
        // connection status to us.
        let is_connected = match self.peer_mgr.handle_candidate_approval(&new_pub_id) {
            Ok(is_connected) => is_connected,
            Err(_) => {
                let src = Authority::ManagedNode(*self.name());
                if let Err(error) =
                    self.send_connection_info_request(new_pub_id, src, new_client_auth, outbox)
                {
                    debug!(
                        "{} - Failed to send connection info to {}: {:?}",
                        self, new_pub_id, error
                    );
                }
                false
            }
        };

        info!(
            "{} Our section with {:?} has approved candidate {}.",
            self,
            self.our_prefix(),
            new_pub_id
        );

        let mut src = Authority::PrefixSection(Default::default());
        if self.gen_pfx_info.is_none() && self.is_first_node {
            let our_members = vec![*self.full_id.public_id(), new_pub_id]
                .iter()
                .cloned()
                .collect();
            let first_info = SectionInfo::new(our_members, Default::default(), None)?;
            self.gen_pfx_info = Some(GenesisPfxInfo {
                our_info: first_info,
                latest_info: Default::default(),
            });
        }

        if let Some(gen_info) = self.gen_pfx_info.clone() {
            let trimmed_info = GenesisPfxInfo {
                our_info: gen_info.our_info.clone(),
                latest_info: if self.chain.is_member() {
                    self.chain.our_info().clone()
                } else {
                    Default::default()
                },
            };
            if self.chain.is_member() {
                src = Authority::PrefixSection(*trimmed_info.our_info.prefix());
            }
            let content = MessageContent::NodeApproval(trimmed_info);
            if let Err(error) = self.send_routing_message(src, new_client_auth, content) {
                debug!(
                    "{} Failed sending NodeApproval to {}: {:?}",
                    self, new_pub_id, error
                );
            }
        }

        if is_connected {
            if self.init_parsec()? {
                self.init_chain();
            }
            self.add_to_routing_table(&new_pub_id, outbox);
        }
        Ok(())
    }

    fn init_parsec(&mut self) -> Result<bool, RoutingError> {
        let genesis_info = if let Some(ref genesis_info) = self.gen_pfx_info {
            genesis_info.clone()
        } else {
            return Ok(false);
        };

        if self
            .parsec_map
            .get(genesis_info.our_info.version())
            .is_none()
        {
            info!("{}: Init new Parsec, genesis = {:?}", self, genesis_info);

            let full_id = self.full_id.clone();
            let genesis_ver = *genesis_info.our_info.version();
            let consensus_mode = parsec::ConsensusMode::Single;

            #[cfg(not(feature = "mock"))]
            let parsec = if genesis_info.our_info.members().contains(self.id()) {
                Parsec::from_genesis(full_id, &genesis_info.our_info.members(), consensus_mode)
            } else {
                Parsec::from_existing(
                    full_id,
                    &genesis_info.our_info.members(),
                    &genesis_info.latest_info.members(),
                    consensus_mode,
                )
            };

            #[cfg(feature = "mock")]
            let parsec = {
                let section_hash = *genesis_info.our_info.hash();

                if genesis_info.our_info.members().contains(self.id()) {
                    Parsec::from_genesis(
                        section_hash,
                        full_id,
                        &genesis_info.our_info.members(),
                        consensus_mode,
                    )
                } else {
                    Parsec::from_existing(
                        section_hash,
                        full_id,
                        &genesis_info.our_info.members(),
                        &genesis_info.latest_info.members(),
                        consensus_mode,
                    )
                }
            };

            let _ = self.parsec_map.insert(genesis_ver, parsec);

            return Ok(true);
        }
        Ok(false)
    }

    fn init_chain(&mut self) {
        if let Some(ref genesis_info) = self.gen_pfx_info {
            self.chain = Chain::with_gen_info(
                self.chain.min_sec_size(),
                *self.full_id.public_id(),
                genesis_info.clone(),
            );
        }
    }

    fn handle_node_approval(
        &mut self,
        genesis_info: GenesisPfxInfo,
        outbox: &mut EventBox,
    ) -> Result<(), RoutingError> {
        if self.gen_pfx_info.is_some() {
            log_or_panic!(LogLevel::Warn, "{} Received duplicate NodeApproval.", self);
            return Ok(());
        }

        self.resource_prover.handle_approval();
        info!(
            "{} Resource proof challenges completed. This node has been approved to join the \
             network!",
            self
        );

        self.gen_pfx_info = Some(genesis_info.clone());
        if self.init_parsec()? {
            self.init_chain();
        }

        // we shoudnt be having any redundant neighbours at this stage, so ignoring result
        // of add_prefix here
        let _ = self
            .peer_mgr
            .add_prefix(genesis_info.our_info.prefix().with_version(0));

        if !self.is_first_node {
            // consider ourself established if we're the second node
            if genesis_info
                .our_info
                .members()
                .contains(self.full_id.public_id())
            {
                self.node_established(outbox);
            } else {
                self.poke_timer_token =
                    Some(self.timer.schedule(Duration::from_secs(POKE_TIMEOUT_SECS)));
            }
        }

        Ok(())
    }

    // Completes a Node startup process and allows a node to behave as a `ManagedNode`.
    // A given node is considered "established" when it exists in `chain.our_info().members()`
    // first node: this method is skipped entirely as it behaves as a Node from startup.
    // second node: occurs on receipt of `NodeApproval`.
    fn node_established(&mut self, outbox: &mut EventBox) {
        self.peer_mgr.set_established();
        outbox.send_event(Event::Connected);

        trace!(
            "{} Node Established. Prefixes: {:?}",
            self,
            self.chain.prefixes()
        );

        self.update_peer_states(outbox);

        // Allow other peers to bootstrap via us.
        if let Err(err) = self.crust_service.set_accept_bootstrap(true) {
            warn!("{} Unable to accept bootstrap connections. {:?}", self, err);
        }
        self.crust_service.set_service_discovery_listen(true);

        let backlog = mem::replace(&mut self.routing_msg_backlog, vec![]);
        backlog
            .into_iter()
            .rev()
            .foreach(|msg| self.msg_queue.push_front(msg));
        self.candidate_status_token = Some(
            self.timer
                .schedule(Duration::from_secs(CANDIDATE_STATUS_INTERVAL_SECS)),
        );
    }

    fn handle_resource_proof_response(
        &mut self,
        pub_id: PublicId,
        part_index: usize,
        part_count: usize,
        proof: Vec<u8>,
        leading_zero_bytes: u64,
        outbox: &mut EventBox,
    ) {
        if self.candidate_timer_token.is_none() {
            debug!(
                "{} Won't handle resource proof response from {:?} - not currently waiting.",
                self, pub_id
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
                    "{} Failed to verify candidate {}: {:?}",
                    self, pub_id, error
                );
            }
            Ok(None) => {
                self.send_direct_message(pub_id, DirectMessage::ResourceProofResponseReceipt);
            }
            Ok(Some((target_size, difficulty, elapsed)))
                if difficulty == 0 && target_size < 1000 =>
            {
                // Small tests don't require waiting for synchronisation. Send approval now.
                info!(
                    "{} Candidate {} passed our challenge in {}. Sending approval \
                     to our section with {:?}.",
                    self,
                    pub_id,
                    elapsed.display_secs(),
                    self.our_prefix()
                );
                // We set the timer token to None so we do not send another
                // CandidateApproval when the token fires
                self.candidate_timer_token = None;
                self.send_candidate_approval(outbox);
            }
            Ok(Some((_, _, elapsed))) => {
                info!(
                    "{} Candidate {} passed our challenge in {}. Waiting to send approval to \
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
            (
                &Authority::Client { .. },
                &MessageContent::UserMessagePart {
                    ref hash,
                    ref msg_id,
                    ref part_count,
                    ref part_index,
                    ref priority,
                    ref payload,
                    ..
                },
            ) if *part_count <= MAX_PARTS
                && part_index < part_count
                && *priority >= DEFAULT_PRIORITY
                && payload.len() <= MAX_PART_LEN =>
            {
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
                    "{} Illegitimate client message {:?}. Refusing to relay.",
                    self, msg
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
            self.clients_rate_limiter
                .apply_refund_for_response(ip, msg_id, part_count, part_index, payload)
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

            match self
                .cacheable_user_msg_cache
                .add(hash, part_count, part_index, payload.clone())
            {
                Some(UserMessage::Request(request)) => {
                    if let Some(response) = self.response_cache.get(&request) {
                        debug!("{} Found cached response to {:?}", self, request);

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
                    debug!("{} Putting {:?} in cache", self, response);
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
        signature: Signature,
    ) -> Result<(), RoutingError> {
        self.remove_expired_peers();

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
            let ip = self
                .crust_service
                .get_peer_ip_addr(&pub_id)
                .map_err(|err| {
                    debug!(
                        "{} Can't get IP address of bootstrapper {:?} : {:?}",
                        self, pub_id, err
                    );
                    self.disconnect_peer(&pub_id);
                    err
                })?;

            if !self.peer_mgr.can_accept_client(ip) {
                debug!(
                    "{} Client {:?} rejected: We cannot accept more clients.",
                    self, pub_id
                );
                self.send_direct_message(
                    pub_id,
                    DirectMessage::BootstrapResponse(Err(BootstrapResponseError::ClientLimit)),
                );
                self.disconnect_peer(&pub_id);
                return Ok(());
            }
        }

        let ser_pub_id = serialisation::serialise(&pub_id)?;
        if !pub_id
            .signing_public_key()
            .verify_detached(&signature, &ser_pub_id)
        {
            return Err(RoutingError::FailedSignature);
        }

        if !self.chain.is_member() && !self.is_first_node {
            debug!(
                "{} Client {:?} rejected: We are not an established node yet.",
                self, pub_id
            );
            self.send_direct_message(
                pub_id,
                DirectMessage::BootstrapResponse(Err(BootstrapResponseError::NotApproved)),
            );
            self.disconnect_peer(&pub_id);
            return Ok(());
        }

        if (peer_kind == CrustUser::Client || !self.is_first_node)
            && self.chain().len() < self.min_section_size() - 1
        {
            debug!(
                "{} Client {:?} rejected: Routing table has {} entries. {} required.",
                self,
                pub_id,
                self.chain().len(),
                self.min_section_size() - 1
            );
            self.send_direct_message(
                pub_id,
                DirectMessage::BootstrapResponse(Err(BootstrapResponseError::TooFewPeers)),
            );
            self.disconnect_peer(&pub_id);
            return Ok(());
        }

        self.peer_mgr.handle_bootstrap_request(&pub_id);
        let _ = self.dropped_clients.remove(&pub_id);
        self.send_direct_message(pub_id, DirectMessage::BootstrapResponse(Ok(())));
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_candidate_info(
        &mut self,
        old_pub_id: &PublicId,
        new_pub_id: &PublicId,
        signature_using_old: &Signature,
        signature_using_new: &Signature,
        new_client_auth: &Authority<XorName>,
        outbox: &mut EventBox,
    ) {
        debug!(
            "{} Handling CandidateInfo from {}->{}.",
            self, old_pub_id, new_pub_id
        );
        if !self.is_candidate_info_valid(
            old_pub_id,
            new_pub_id,
            signature_using_old,
            signature_using_new,
        ) {
            warn!(
                "{} Signature check failed in CandidateInfo, so dropping peer {:?}.",
                self, new_pub_id
            );
            self.disconnect_peer(new_pub_id);
        }

        // If this is a valid node in peer_mgr but the Candidate has sent us a CandidateInfo, it
        // might have not yet handled its NodeApproval message. Check and handle accordingly here
        if self.peer_mgr.is_connected(new_pub_id) && self.chain.is_peer_valid(new_pub_id) {
            self.process_connection(*new_pub_id, outbox);
            return;
        }

        let (difficulty, target_size) = if self.disable_resource_proof
            || self.crust_service.is_peer_hard_coded(new_pub_id)
            || self.peer_mgr.is_joining_node(new_pub_id)
        {
            (0, 1)
        } else {
            (
                RESOURCE_PROOF_DIFFICULTY,
                RESOURCE_PROOF_TARGET_SIZE / (self.chain().our_section().len() + 1),
            )
        };
        let seed: Vec<u8> = if cfg!(feature = "mock") {
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
                    "{} Sending resource proof challenge to candidate {}->{}",
                    self, old_pub_id, new_pub_id
                );
                self.send_direct_message(*new_pub_id, direct_message);
            }
            Ok(false) => {
                if !self.chain.is_peer_valid(new_pub_id) {
                    debug!(
                        "{} Ignore CandidateInfo from invalid candidate {}->{}.",
                        self, old_pub_id, new_pub_id
                    );
                    return;
                }
                info!(
                    "{} Adding candidate {}->{} to routing table without sending resource \
                     proof challenge as section has already approved it.",
                    self, old_pub_id, new_pub_id
                );
                self.add_to_routing_table(new_pub_id, outbox);
            }
            Err(error) => {
                debug!(
                    "{} Ignore CandidateInfo {}->{}: {:?}.",
                    self, old_pub_id, new_pub_id, error
                );
            }
        }
    }

    fn is_candidate_info_valid(
        &self,
        old_pub_id: &PublicId,
        new_pub_id: &PublicId,
        signature_using_old: &Signature,
        signature_using_new: &Signature,
    ) -> bool {
        let old_and_new_pub_ids = (old_pub_id, new_pub_id);
        let mut signed_data = match serialisation::serialise(&old_and_new_pub_ids) {
            Ok(result) => result,
            Err(error) => {
                error!("Failed to serialise public IDs: {:?}", error);
                return false;
            }
        };
        if !old_pub_id
            .signing_public_key()
            .verify_detached(signature_using_old, &signed_data)
        {
            debug!(
                "{} CandidateInfo from {}->{} has invalid old signature.",
                self, old_pub_id, new_pub_id
            );
            return false;
        }
        signed_data.extend_from_slice(&signature_using_old.into_bytes());
        if !new_pub_id
            .signing_public_key()
            .verify_detached(signature_using_new, &signed_data)
        {
            debug!(
                "{} CandidateInfo from {}->{} has invalid new signature.",
                self, old_pub_id, new_pub_id
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
                    "{} Peer {:?} was not added to the routing table: {:?}",
                    self, pub_id, error
                );
                if !self.chain.is_peer_valid(pub_id) {
                    self.disconnect_peer(pub_id);
                }
                return;
            }
            Ok(()) => (),
        }

        info!("{} Added {} to routing table.", self, pub_id);
        if self.is_first_node && self.routing_table().len() == 1 {
            trace!(
                "{} Node approval completed. Prefixes: {:?}",
                self,
                self.chain.prefixes()
            );
            outbox.send_event(Event::Connected);
        }

        outbox.send_event(Event::NodeAdded(
            *pub_id.name(),
            self.routing_table().clone(),
        ));
        self.print_rt_size();
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
        let shared_secret = self
            .full_id
            .encrypting_private_key()
            .shared_secret(&their_pub_id.encrypting_public_key());
        let encrypted_conn_info = match shared_secret.encrypt(&our_pub_info) {
            Ok(encrypted_conn_info) => encrypted_conn_info,
            Err(err) => {
                debug!(
                    "{} Failed to serialise connection info for {:?}: {:?}.",
                    self, their_pub_id, err
                );
                return;
            }
        };
        let msg_content = if let Some(msg_id) = msg_id {
            MessageContent::ConnectionInfoResponse {
                encrypted_conn_info,
                pub_id: *self.full_id.public_id(),
                msg_id,
            }
        } else {
            MessageContent::ConnectionInfoRequest {
                encrypted_conn_info,
                pub_id: *self.full_id.public_id(),
                msg_id: MessageId::new(),
            }
        };

        if let Err(err) = self.send_routing_message(src, dst, msg_content) {
            debug!(
                "{} Failed to send connection info for {:?}: {:?}.",
                self, their_pub_id, err
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
                    "{} Failed to prepare connection info: {:?}. Retrying.",
                    self, err
                );
                let new_token = match self.peer_mgr.get_new_connection_info_token(result_token) {
                    Err(error) => {
                        debug!(
                            "{} Failed to prepare connection info, but no entry found in \
                             token map: {:?}",
                            self, error
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
        match self
            .peer_mgr
            .connection_info_prepared(result_token, our_connection_info)
        {
            Err(error) => {
                // This usually means we have already connected.
                debug!(
                    "{} Prepared connection info, but no entry found in token map: {:?}",
                    self, error
                );
                return;
            }
            Ok(ConnectionInfoPreparedResult {
                pub_id,
                src,
                dst,
                infos,
            }) => match infos {
                None => {
                    debug!("{} Prepared connection info for {:?}.", self, pub_id);
                    self.send_connection_info(our_pub_info, pub_id, src, dst, None);
                }
                Some((our_info, their_info, msg_id)) => {
                    debug!(
                        "{} Trying to connect to {:?} as {:?}.",
                        self,
                        their_info.id(),
                        pub_id
                    );
                    self.send_connection_info(our_pub_info, pub_id, src, dst, Some(msg_id));
                    if let Err(error) = self.crust_service.connect(our_info, their_info) {
                        trace!("{} Unable to connect to {:?} - {:?}", self, pub_id, error);
                    }
                }
            },
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_connection_info_request(
        &mut self,
        encrypted_connection_info: Vec<u8>,
        pub_id: PublicId,
        message_id: MessageId,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        outbox: &mut EventBox,
    ) -> Result<(), RoutingError> {
        let shared_secret = self
            .full_id
            .encrypting_private_key()
            .shared_secret(&pub_id.encrypting_public_key());
        let their_connection_info =
            self.decrypt_connection_info(&encrypted_connection_info, &shared_secret)?;
        if pub_id != their_connection_info.id() {
            debug!(
                "{} PublicId of the sender {} does not match the id mentioned in the message \
                 {}.",
                self,
                pub_id,
                their_connection_info.id()
            );
            return Err(RoutingError::InvalidPeer);
        }

        use crate::peer_manager::ConnectionInfoReceivedResult::*;
        match self.peer_mgr.connection_info_received(
            src,
            dst,
            their_connection_info,
            message_id,
            true,
        ) {
            Ok(Ready(our_info, their_info)) => {
                debug!(
                    "{} Already sent a connection info request to {}; resending \
                     our same details as a response.",
                    self, pub_id
                );
                self.send_connection_info(
                    our_info.to_pub_connection_info(),
                    pub_id,
                    dst,
                    src,
                    Some(message_id),
                );
                if let Err(error) = self.crust_service.connect(our_info, their_info) {
                    trace!("{} Unable to connect to {:?} - {:?}", self, src, error);
                }
            }
            Ok(Prepare(token)) => {
                self.crust_service.prepare_connection_info(token);
            }
            Ok(IsProxy) | Ok(IsClient) | Ok(IsJoiningNode) => {
                // TODO: we should not be getting conn info req from Proxy/JoiningNode

                log_or_panic!(
                    LogLevel::Error,
                    "{} Received ConnectionInfoRequest from peer {} \
                     with invalid state.",
                    self,
                    pub_id
                );
                if self.peer_mgr.is_connected(&pub_id) {
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
        public_id: PublicId,
        message_id: MessageId,
        src: XorName,
        dst: Authority<XorName>,
    ) -> Result<(), RoutingError> {
        if self.peer_mgr.get_peer(&public_id).is_none() {
            return Err(RoutingError::InvalidDestination);
        }

        let shared_secret = self
            .full_id
            .encrypting_private_key()
            .shared_secret(&public_id.encrypting_public_key());
        let their_connection_info =
            self.decrypt_connection_info(&encrypted_connection_info, &shared_secret)?;
        if public_id != their_connection_info.id() {
            debug!(
                "{} PublicId of the sender {} does not match the id mentioned in the message \
                 {}.",
                self,
                public_id,
                their_connection_info.id()
            );
            return Err(RoutingError::InvalidPeer);
        }

        use crate::peer_manager::ConnectionInfoReceivedResult::*;
        match self.peer_mgr.connection_info_received(
            Authority::ManagedNode(src),
            dst,
            their_connection_info,
            message_id,
            false,
        ) {
            Ok(Ready(our_info, their_info)) => {
                trace!(
                    "{} Received connection info response. Trying to connect to {}.",
                    self,
                    public_id
                );
                if let Err(error) = self.crust_service.connect(our_info, their_info) {
                    trace!(
                        "{} Unable to connect to {:?} - {:?}",
                        self,
                        public_id,
                        error
                    );
                }
            }
            Ok(Prepare(_)) | Ok(IsProxy) | Ok(IsClient) | Ok(IsJoiningNode) => {
                debug!(
                    "{} Received connection info response from {} when we haven't \
                     sent a corresponding request",
                    self, public_id
                );
            }
            Ok(Waiting) | Ok(IsConnected) | Err(_) => (),
        }
        Ok(())
    }

    /// Disconnects if the peer is not a proxy, client or routing table entry.
    fn disconnect_peer(&mut self, pub_id: &PublicId) {
        if self
            .peer_mgr
            .get_peer(pub_id)
            .map_or(false, Peer::is_routing)
        {
            debug!("{} Not disconnecting routing table entry {}.", self, pub_id);
        } else if self.peer_mgr.is_proxy(pub_id) {
            debug!("{} Not disconnecting proxy node {}.", self, pub_id);
        } else if self.peer_mgr.is_joining_node(pub_id) {
            debug!("{} Not disconnecting joining node {:?}.", self, pub_id);
        } else {
            debug!(
                "{} Disconnecting {}. Calling crust::Service::disconnect.",
                self, pub_id
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
                            "{} Stats - Client total session traffic from {:?} - {:?}",
                            self, ip, traffic
                        );
                        let _ = self.dropped_clients.insert(*pub_id, ());
                    }
                    PeerState::ConnectionInfoPreparing { .. }
                    | PeerState::ConnectionInfoReady(_)
                    | PeerState::CrustConnecting
                    | PeerState::Connected
                    | PeerState::JoiningNode
                    | PeerState::Routing(_)
                    | PeerState::Candidate(_)
                    | PeerState::Proxy => (),
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

        let close_section = if self.is_first_node && !self.chain.is_member() {
            iter::once(self.name()).cloned().collect_vec()
        } else {
            match self.chain().close_names(&dst_name) {
                Some(close_section) => close_section.into_iter().collect(),
                None => return Err(RoutingError::InvalidDestination),
            }
        };

        let relocation_dst = self
            .next_relocation_dst
            .unwrap_or_else(|| utils::calculate_relocation_dst(close_section, &dst_name));

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
    ) -> Result<(), RoutingError> {
        self.remove_expired_peers();

        if old_pub_id == *self.full_id.public_id() {
            return Ok(()); // This is a delayed message belonging to our own relocate request.
        }

        // Check that our section is one of the ones with a minimum length prefix, and if it's not,
        // forward it to one that is.
        let min_len_prefix = self.chain().min_len_prefix();

        // If we're running in mock-crust mode, and we have relocation interval, don't try to do
        // section balancing, as it will break things.
        let forbid_join_balancing = if cfg!(feature = "mock") {
            self.next_relocation_interval.is_some()
        } else {
            false
        };

        if min_len_prefix != self.our_prefix() && !forbid_join_balancing {
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
            utils::calculate_relocation_interval(&self.our_prefix(), &self.chain().our_section())
        });

        self.peer_mgr.expect_candidate(old_pub_id)?;

        let response_content = MessageContent::AcceptAsCandidate {
            old_public_id: old_pub_id,
            old_client_auth: old_client_auth,
            target_interval: target_interval,
            message_id: message_id,
        };
        info!("{} Expecting candidate with old name {}.", self, old_pub_id);

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
    ) -> Result<(), RoutingError> {
        self.remove_expired_peers();

        if old_pub_id == *self.full_id.public_id() {
            // If we're the joining node: stop
            return Ok(());
        }

        self.candidate_timer_token = Some(
            self.timer
                .schedule(Duration::from_secs(RESOURCE_PROOF_DURATION_SECS)),
        );

        let own_section = self
            .peer_mgr
            .accept_as_candidate(old_pub_id, target_interval);
        let response_content = MessageContent::RelocateResponse {
            target_interval: target_interval,
            section: own_section,
            message_id: message_id,
        };
        info!(
            "{} Our section with {:?} accepted candidate with old name {}.",
            self,
            self.our_prefix(),
            old_pub_id
        );
        trace!(
            "{} Sending {:?} to {:?}",
            self,
            response_content,
            old_client_auth
        );

        self.send_routing_message(relocation_dst, old_client_auth, response_content)
    }

    fn handle_section_update(&mut self, ver_pfx: VersionedPrefix<XorName>) {
        trace!("{} Got section update for {:?}", self, ver_pfx);

        let old_prefixes = self.chain.prefixes();
        // Perform splits that we missed, according to the section update.
        for pub_id in self.peer_mgr.add_prefix(ver_pfx) {
            self.disconnect_peer(&pub_id);
        }

        let new_prefixes = self.chain.prefixes();
        if old_prefixes != new_prefixes {
            info!(
                "{} section update handled. Prefixes: {:?}",
                self, new_prefixes
            );
        }
    }

    fn handle_section_split(
        &mut self,
        ver_pfx: VersionedPrefix<XorName>,
        outbox: &mut EventBox,
    ) -> Result<(), RoutingError> {
        // None of the `peers_to_drop` will have been in our section, so no need to notify Routing
        // user about them.
        let (peers_to_drop, our_new_prefix) = self.peer_mgr.split_section(ver_pfx);
        if let Some(new_prefix) = our_new_prefix {
            outbox.send_event(Event::SectionSplit(new_prefix));
        }

        for pub_id in peers_to_drop {
            self.disconnect_peer(&pub_id);
        }
        info!(
            "{} Section split for {:?} completed. Prefixes: {:?}",
            self,
            ver_pfx,
            self.chain.prefixes()
        );

        Ok(())
    }

    /// Votes for all of the proving sections that are new to us.
    fn add_new_sections<'a, I>(&mut self, sections: I) -> bool
    where
        I: IntoIterator<Item = &'a SectionInfo>,
    {
        sections
            .into_iter()
            .any(|sec_info| self.add_new_section(sec_info))
    }

    /// Votes for the section if it is new to us.
    fn add_new_section(&mut self, sec_info: &SectionInfo) -> bool {
        if self.chain.is_new_neighbour(sec_info) {
            self.vote_for_event(sec_info.clone().into_network_event());
            true
        } else {
            false
        }
    }

    /// Returns `true` if the `SectionInfo` is known as trusted, or is the predecessor of a trusted
    /// one.
    fn is_trusted(&self, sec_info: &SectionInfo) -> Result<bool, RoutingError> {
        if self.chain.is_trusted(sec_info, true) {
            return Ok(true);
        }
        let is_proof =
            |si: &SectionInfo| si == sec_info || si.prev_hash().contains(sec_info.hash());
        Ok(self
            .parsec_map
            .values()
            .last()
            .ok_or(RoutingError::InvalidStateForOperation)?
            .our_unpolled_observations()
            .filter_map(|obs| match obs {
                parsec::Observation::OpaquePayload(NetworkEvent::SectionInfo(sec_info)) => {
                    Some(sec_info)
                }
                _ => None,
            })
            .any(is_proof))
    }

    fn handle_neighbour_confirm(
        &mut self,
        digest: Digest256,
        proofs: ProofSet,
        sec_infos_and_proofs: Vec<(SectionInfo, ProofSet)>,
    ) -> Result<(), RoutingError> {
        let (pfx, version) = {
            let sec_info = self
                .chain
                .our_info_by_hash(&digest)
                .ok_or(RoutingError::InvalidMessage)?;
            let &(ref neighbour_info, _) = sec_infos_and_proofs
                .last()
                .ok_or(RoutingError::InvalidMessage)?;
            if !neighbour_info.proves(sec_info, &proofs) {
                return Err(RoutingError::InvalidMessage);
            }
            (*neighbour_info.prefix(), *sec_info.version())
        };
        self.chain.update_their_knowledge(pfx, version);
        Ok(())
    }

    fn handle_merge(&mut self, digest: Digest256) -> Result<(), RoutingError> {
        self.vote_for_event(NetworkEvent::NeighbourMerge(digest));
        Ok(())
    }

    fn handle_ack_response(&mut self, ack: Ack) -> Result<(), RoutingError> {
        self.ack_mgr.receive(ack);
        Ok(())
    }

    fn handle_timeout(&mut self, token: u64, outbox: &mut EventBox) -> Transition {
        let log_ident = format!("{}", self);
        if let Some(transition) = self
            .resource_prover
            .handle_timeout(token, log_ident, outbox)
        {
            return transition;
        }

        if self.tick_timer_token == token {
            let tick_period = Duration::from_secs(TICK_TIMEOUT_SECS);
            self.tick_timer_token = self.timer.schedule(tick_period);
            self.remove_expired_peers();
            self.proxy_load_amount = 0;

            let transition = if cfg!(feature = "mock") {
                Transition::Stay
            } else {
                self.purge_invalid_rt_entries(outbox)
            };
            if self.chain.is_member() {
                outbox.send_event(Event::Tick);
            }
            return transition;
        }

        if self.candidate_timer_token == Some(token) {
            self.candidate_timer_token = None;
            self.send_candidate_approval(outbox);
        } else if self.candidate_status_token == Some(token) {
            self.candidate_status_token = Some(
                self.timer
                    .schedule(Duration::from_secs(CANDIDATE_STATUS_INTERVAL_SECS)),
            );
            self.peer_mgr.show_candidate_status();
        } else if self.reconnect_peers_token == token {
            self.reconnect_peers_token = self
                .timer
                .schedule(Duration::from_secs(RECONNECT_PEER_TIMEOUT_SECS));
            self.reconnect_peers(outbox);
        } else if self.poke_timer_token == Some(token) {
            if !self.peer_mgr.is_established() {
                self.send_parsec_poke();
                self.poke_timer_token =
                    Some(self.timer.schedule(Duration::from_secs(POKE_TIMEOUT_SECS)));
            }
        } else if self.gossip_timer_token == Some(token) {
            self.gossip_timer_token = Some(
                self.timer
                    .schedule(Duration::from_secs(GOSSIP_TIMEOUT_SECS)),
            );
            if self.gen_pfx_info.is_some() {
                self.send_parsec_gossip(None);
            }
        } else {
            // Each token has only one purpose, so we only need to call this if none of the above
            // matched:
            self.resend_unacknowledged_timed_out_msgs(token);
        }

        Transition::Stay
    }

    fn send_parsec_gossip(&mut self, target: Option<(u64, PublicId)>) {
        let (version, gossip_target) = match target {
            Some((v, p)) => (v, p),
            None => {
                let (v, mut recipients) = match self.parsec_map.iter().last() {
                    Some((v, par)) => (*v, par.gossip_recipients().collect_vec()),
                    None => return, // We haven't joined a section yet.
                };
                if recipients.is_empty() {
                    return; // Parsec hasn't caught up with the event of us joining yet.
                }
                recipients.retain(|pub_id| self.peer_mgr.is_connected(pub_id));

                if recipients.is_empty() {
                    log_or_panic!(LogLevel::Error, "Not connected to any gossip recipient.");
                    return;
                }

                let rand_index = utils::rand_index(recipients.len());
                (v, *recipients[rand_index])
            }
        };

        let par_req = self
            .parsec_map
            .get_mut(&version)
            .and_then(|par| par.create_gossip(Some(&gossip_target)).ok());
        if let Some(par_req) = par_req {
            self.send_message(
                &gossip_target,
                Message::Direct(DirectMessage::ParsecRequest(version, par_req)),
            );
        }
    }

    // Sends a `ParsecPoke` message to trigger a gossip request from current section members to us.
    //
    // TODO: Should restrict targets to few(counter churn-threshold)/single.
    // Currently this can result in incoming spam of gossip history from everyone.
    // Can also just be a single target once node-ageing makes Offline votes Opaque which should
    // remove invalid test failures for unaccumulated parsec::Remove blocks.
    fn send_parsec_poke(&mut self) {
        let (version, recipients) = if let Some(gen_pfx_info) = self.gen_pfx_info.as_ref() {
            let recipients = gen_pfx_info
                .latest_info
                .members()
                .iter()
                .cloned()
                .collect_vec();
            (*gen_pfx_info.our_info.version(), recipients)
        } else {
            log_or_panic!(
                LogLevel::Error,
                "{} can't send ParsecPoke: not approved yet.",
                self
            );
            return;
        };
        for recipient in recipients {
            self.send_message(
                &recipient,
                Message::Direct(DirectMessage::ParsecPoke(version)),
            );
        }
    }

    // Drop peers to which we think we have a connection, but where Crust reports
    // that we're not connected to the peer.
    fn purge_invalid_rt_entries(&mut self, outbox: &mut EventBox) -> Transition {
        let peer_details = self.peer_mgr.get_routing_peer_details();
        for pub_id in peer_details.out_of_sync_peers {
            let _ = self.crust_service.disconnect(&pub_id);
            let _ = self.dropped_peer(&pub_id, outbox, true);
        }
        for removal_detail in peer_details.removal_details {
            let _ = self.dropped_routing_node(removal_detail, outbox, None);
        }
        for pub_id in peer_details.routing_peer_details {
            if !self.crust_service.is_connected(&pub_id) {
                log_or_panic!(
                    LogLevel::Error,
                    "{} Should have a direct connection to {}, but doesn't.",
                    self,
                    pub_id
                );
            }
        }
        Transition::Stay
    }

    fn send_candidate_approval(&mut self, outbox: &mut EventBox) {
        let (new_id, client_auth) = match self.peer_mgr.verified_candidate_info() {
            Err(_) => {
                trace!("{} No candidate for which to send CandidateApproval.", self);
                return;
            }
            Ok(result) => result,
        };

        info!(
            "{} Resource proof duration has finished. Voting to approve candidate {}.",
            self,
            new_id.name()
        );

        if self.parsec_map.is_empty() {
            let _ = self.handle_candidate_approval(new_id, client_auth, outbox);
        } else {
            let our_pfx = *self.chain.our_prefix();
            if !our_pfx.matches(new_id.name()) {
                log_or_panic!(
                    LogLevel::Error,
                    "{} About to vote for {} which does not match self pfx: {:?}",
                    self,
                    new_id.name(),
                    our_pfx
                );
            }
            self.vote_for_event(NetworkEvent::Online(new_id, client_auth));
        }
    }

    fn vote_for_event(&mut self, event: NetworkEvent) {
        trace!("{} Vote for Event {:?}", self, event);
        let self_disp = format!("{}", self);
        if let Some(ref mut par) = self.parsec_map.values_mut().last() {
            let obs = match event.into_obs() {
                Err(_) => {
                    warn!(
                        "{} Failed to convert NetworkEvent to Parsec Observation.",
                        self_disp
                    );
                    return;
                }
                Ok(obs) => obs,
            };
            if let Err(e) = par.vote_for(obs) {
                trace!("{} Parsec vote error: {:?}", self_disp, e);
            }
        }
    }

    fn decrypt_connection_info(
        &self,
        encrypted_connection_info: &[u8],
        shared_secret: &SharedSecretKey,
    ) -> Result<PubConnectionInfo, RoutingError> {
        shared_secret
            .decrypt(encrypted_connection_info)
            .map_err(RoutingError::Crypto)
    }

    // ----- Send Functions -----------------------------------------------------------------------
    fn send_user_message(
        &mut self,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        user_msg: UserMessage,
        priority: u8,
    ) -> Result<(), RoutingError> {
        for part in user_msg.to_parts(priority)? {
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
        signed_msg: &mut SignedMessage,
        route: u8,
        hop: &XorName,
        sent_to: &BTreeSet<XorName>,
    ) -> Result<(), RoutingError> {
        let dst = signed_msg.routing_message().dst;

        // TODO: Figure out when failure is expected, and in which cases we should still handle the
        // message anyway.
        if let Err(err) = self.chain.extend_proving_sections(signed_msg) {
            debug!("{} Failed to add section infos: {:?}", self, err);
        }

        if let Authority::Client { ref client_id, .. } = dst {
            if *self.name() == dst.name() {
                // This is a message for a client we are the proxy of. Relay it.
                return self.relay_to_client(signed_msg, client_id);
            } else if self.in_authority(&dst) {
                return Ok(()); // Message is for us as a client.
            }
        }

        // Until we're established do not relay any messages.
        let src = signed_msg.routing_message().src;
        if !self.chain.is_member() {
            if let Authority::Client { ref client_id, .. } = src {
                if self.name() != client_id.name() {
                    return Ok(());
                }
            } else {
                return Ok(());
            }
        }

        let (new_sent_to, target_pub_ids) =
            self.get_targets(signed_msg.routing_message(), route, hop, sent_to)?;

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

    // Filter, then convert the message to a `Hop` and serialise.
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
        } else {
            trace!("{} Not connected to {:?}. Dropping peer.", self, target);
            self.disconnect_peer(&target);
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
                "{} Client connection not found for message {:?}.",
                self, signed_msg
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
        use crate::Authority::*;
        let (our_section, valid_peers) = if self.chain().is_member() {
            // FIXME: we're passing false here to valid peers to not include
            // recently accepted peers which would affect quorum calculation.
            // This even when going via RT would have only allowed route-0
            // to succeed as by ack-failure, the new node would have been
            // accepted to the RT. Need a better network startup separation.
            (self.chain().our_section(), self.chain().valid_peers(false))
        } else {
            let our_section: BTreeSet<XorName> = iter::once(self.name()).cloned().collect();
            let valid_peers: BTreeSet<&PublicId> = iter::once(self.id()).collect();
            (our_section, valid_peers)
        };
        let list: Vec<XorName> = match *src {
            ClientManager(_) | NaeManager(_) | NodeManager(_) => {
                let mut v = our_section
                    .into_iter()
                    .sorted_by(|lhs, rhs| src.name().cmp_distance(lhs, rhs));
                v.truncate(self.min_section_size());
                v
            }
            Section(_) => our_section
                .into_iter()
                .sorted_by(|lhs, rhs| src.name().cmp_distance(lhs, rhs)),
            PrefixSection(_) => valid_peers
                .iter()
                .map(|id| id.name())
                .sorted_by(|lhs, rhs| src.name().cmp_distance(lhs, rhs))
                .into_iter()
                .cloned()
                .collect(),
            ManagedNode(_) | Client { .. } => return Some(*self.name()),
        };

        if !list.contains(&self.name()) {
            None
        } else {
            Some(list[route as usize % list.len()])
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
            MessageContent::ConnectionInfoRequest { pub_id, .. }
            | MessageContent::ConnectionInfoResponse { pub_id, .. } => {
                routing_msg.src.is_client() && pub_id == *self.full_id.public_id()
            }
            _ => false,
        };

        if (self.is_first_node || self.chain.is_member()) && !force_via_proxy {
            // TODO: even if having chain reply based on connected_state,
            // we remove self in targets info and can do same by not
            // chaining us to conn_peer list here?
            let conn_peers = self
                .peer_mgr
                .connected_peers()
                .map(Peer::name)
                .chain(iter::once(self.name()))
                .collect_vec();
            let targets: BTreeSet<_> = self
                .chain()
                .targets(&routing_msg.dst, *exclude, route as usize, &conn_peers)?
                .into_iter()
                .filter(|target| !sent_to.contains(target))
                .collect();
            let new_sent_to = if self.in_authority(&routing_msg.dst) {
                sent_to
                    .iter()
                    .chain(&targets)
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
        } else if let Authority::Client {
            ref proxy_node_name,
            ..
        } = routing_msg.src
        {
            // We don't have any contacts in our routing table yet. Keep using
            // the proxy connection until we do.
            if let Some(pub_id) = self
                .peer_mgr
                .get_peer_by_name(proxy_node_name)
                .map(Peer::pub_id)
            {
                if self.peer_mgr.is_proxy(pub_id) {
                    Ok((BTreeSet::new(), vec![*pub_id]))
                } else {
                    error!("{} Peer found in peer manager but not as proxy.", self);
                    Err(RoutingError::ProxyConnectionNotFound)
                }
            } else {
                error!(
                    "{} Unable to find connection to proxy node in proxy map.",
                    self
                );
                Err(RoutingError::ProxyConnectionNotFound)
            }
        } else {
            error!(
                "{} Source should be client if our state is a Client. {:?}",
                self, routing_msg
            );
            Err(RoutingError::InvalidSource)
        }
    }

    /// Adds a newly connected peer to the routing table. Must only be called for connected peers.
    /// If we are the joining node, sends the `CandidateInfo`.
    fn process_connection(&mut self, pub_id: PublicId, outbox: &mut EventBox) {
        if self.chain.is_peer_valid(&pub_id) {
            self.add_to_routing_table(&pub_id, outbox);
        }

        if self.gen_pfx_info.is_some() {
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
            let signature_using_old = self
                .old_full_id
                .signing_private_key()
                .sign_detached(&to_sign);
            // Append this signature onto the serialised IDs and sign that using the new key.
            to_sign.extend_from_slice(&signature_using_old.into_bytes());
            let signature_using_new = self.full_id.signing_private_key().sign_detached(&to_sign);
            let proxy_node_name = if let Some(proxy_node_name) = self.peer_mgr.get_proxy_name() {
                *proxy_node_name
            } else {
                warn!("{} No proxy found, so unable to send CandidateInfo.", self);
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
    ) -> Result<(), RoutingError> {
        let their_name = *their_public_id.name();
        if self.chain.is_member() && !self.chain.is_peer_valid(&their_public_id) {
            trace!(
                "{} Not sending ConnectionInfoRequest to Invalid peer {}.",
                self,
                their_name
            );
            return Err(RoutingError::InvalidPeer);
        }

        if self.peer_mgr.is_client(&their_public_id)
            || self.peer_mgr.is_joining_node(&their_public_id)
            || self.peer_mgr.is_proxy(&their_public_id)
        {
            // we use peer_name here instead of their_name since the peer can be
            // a joining node with its client name as far as proxy node is concerned
            self.process_connection(their_public_id, outbox);
            return Ok(());
        }

        if self.peer_mgr.is_connected(&their_public_id) {
            self.add_to_routing_table(&their_public_id, outbox);
            return Ok(());
        }

        // This will insert the peer if peer is not in peer_mgr and flag them to `valid`
        if let Some(token) = self
            .peer_mgr
            .get_connection_token(src, dst, their_public_id)
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
                    "{} Not sending connection info request to {:?}. State: {:?}",
                    self,
                    their_name,
                    state
                );
                return Ok(());
            }
        };
        trace!(
            "{} Resending connection info request to {:?}",
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
            if !self.dropped_routing_node(removal_details, outbox, Some(*pub_id)) {
                return false;
            }
        }

        match *peer.state() {
            PeerState::Client { ip, traffic } => {
                debug!("{} Client disconnected: {}", self, pub_id);
                info!(
                    "{} Stats - Client total session traffic from {:?} - {:?}",
                    self, ip, traffic
                );
                try_reconnect = false;
            }
            PeerState::JoiningNode => {
                debug!("{} Joining node {} dropped.", self, pub_id);
                try_reconnect = false;
            }
            PeerState::Proxy => {
                debug!("{} Lost bootstrap connection to {:?}.", self, peer);

                if self.chain().len() < self.min_section_size() - 1 {
                    outbox.send_event(Event::Terminate);
                    return false;
                }
                try_reconnect = false;
            }
            _ => (),
        }

        if try_reconnect && self.chain.is_member() && self.chain.is_peer_valid(peer.pub_id()) {
            debug!("{} Caching {:?} to reconnect.", self, peer.pub_id());
            self.reconnect_peers.push(*peer.pub_id());
        }

        true
    }

    // Reconnect to currently cached valid peers that are not connected
    fn reconnect_peers(&mut self, outbox: &mut EventBox) {
        for pub_id in mem::replace(&mut self.reconnect_peers, Default::default()) {
            if self.chain.is_peer_valid(&pub_id) {
                debug!(
                    "{} Sending connection info to {:?} due to dropped peer.",
                    self, pub_id
                );
                let own_name = *self.name();
                if let Err(error) = self.send_connection_info_request(
                    pub_id,
                    Authority::ManagedNode(own_name),
                    Authority::ManagedNode(*pub_id.name()),
                    outbox,
                ) {
                    debug!(
                        "{} - Failed to send connection info to {:?}: {:?}",
                        self, pub_id, error
                    );
                }
            }
        }
    }

    /// Handles dropped routing peer with the given name and removal details. Returns true if we
    /// should keep running, false if we should terminate.
    fn dropped_routing_node(
        &mut self,
        details: RemovalDetails<XorName>,
        outbox: &mut EventBox,
        pub_id_opt: Option<PublicId>,
    ) -> bool {
        info!("{} Dropped {} from the routing table.", self, details.name);

        if self.chain.is_member() {
            outbox.send_event(Event::NodeLost(details.name, self.routing_table().clone()));
        }

        if details.was_in_our_section {
            if let Some(pub_id) = pub_id_opt {
                self.vote_for_event(NetworkEvent::Offline(pub_id));
            }
        }

        if self.routing_table().is_empty() {
            debug!("{} Lost all routing connections.", self);
            if !self.is_first_node {
                outbox.send_event(Event::RestartRequired);
                return false;
            }
        }

        true
    }

    fn remove_expired_peers(&mut self) {
        for pub_id in self.peer_mgr.remove_expired_peers() {
            debug!("{} Disconnecting from timed out peer {:?}", self, pub_id);
            // We've already removed from peer manager but this helps clean out connections to
            // expired peers.
            self.disconnect_peer(&pub_id);
            if self.chain.our_info().members().contains(&pub_id) {
                self.vote_for_event(NetworkEvent::Offline(pub_id));
            }
        }
    }

    fn send_direct_message(&mut self, dst_id: PublicId, direct_message: DirectMessage) {
        self.send_message(&dst_id, Message::Direct(direct_message));
    }

    fn our_prefix(&self) -> Prefix<XorName> {
        self.chain().our_prefix_copy()
    }

    // While this can theoretically be called as a result of a misbehaving client or node, we're
    // actually only blocking clients from bootstrapping from that IP (see
    // `handle_bootstrap_accept()`). This behaviour will change when we refactor the codebase to
    // handle malicious nodes more fully.
    fn ban_and_disconnect_peer(&mut self, pub_id: &PublicId) {
        if let Ok(ip_addr) = self.crust_service.get_peer_ip_addr(pub_id) {
            let _ = self.banned_client_ips.insert(ip_addr, ());
            debug!("{} Banned client {:?} on IP {}", self, pub_id, ip_addr);
        } else {
            warn!("{} Can't get IP address of client {:?}.", self, pub_id);
        }
        let _ = self.dropped_clients.insert(*pub_id, ());
        self.disconnect_peer(pub_id);
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
            let conn_peers = self
                .peer_mgr
                .connected_peers()
                .map(Peer::name)
                .chain(iter::once(self.name()))
                .collect_vec();
            (self.is_first_node || self.chain.is_member())
                && self.chain().in_authority(auth, &conn_peers, self.name())
        }
    }

    fn close_group(&self, name: XorName, count: usize) -> Option<Vec<XorName>> {
        let conn_peers = self
            .peer_mgr
            .connected_peers()
            .map(Peer::name)
            .chain(iter::once(self.name()))
            .collect_vec();
        self.chain().closest_names(&name, count, &conn_peers)
    }

    fn handle_lost_peer(&mut self, pub_id: PublicId, outbox: &mut EventBox) -> Transition {
        if self.peer_mgr.get_peer(&pub_id).is_none() {
            return Transition::Stay;
        }

        debug!("{} Received LostPeer - {}", self, pub_id);

        if self.dropped_peer(&pub_id, outbox, true) {
            Transition::Stay
        } else {
            Transition::Terminate
        }
    }

    fn min_section_size(&self) -> usize {
        self.chain.min_sec_size()
    }
}

#[cfg(feature = "mock")]
impl Node {
    /// Purge invalid routing entries.
    pub fn purge_invalid_rt_entry(&mut self) {
        let _ = self.purge_invalid_rt_entries(&mut EventBuf::new());
    }

    pub fn get_timed_out_tokens(&mut self) -> Vec<u64> {
        self.timer.get_timed_out_tokens()
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

    pub fn set_next_relocation_interval(&mut self, interval: Option<(XorName, XorName)>) {
        self.next_relocation_interval = interval;
    }

    pub fn has_unnormalised_routing_conn(&self, excludes: &BTreeSet<XorName>) -> bool {
        self.peer_mgr.has_unnormalised_routing_conn(excludes)
    }

    pub fn get_clients_usage(&self) -> BTreeMap<IpAddr, u64> {
        self.clients_rate_limiter.usage_map().clone()
    }

    pub fn has_unconsensused_observations(&self) -> bool {
        self.parsec_map
            .values()
            .last()
            .map_or(false, |par| par.has_unconsensused_observations())
    }

    pub fn is_routing_peer(&self, pub_id: &PublicId) -> bool {
        self.peer_mgr
            .get_peer(pub_id)
            .map_or(false, |peer| peer.is_routing())
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
            if route == 0 {
                log_or_panic!(
                    LogLevel::Error,
                    "{} Not part of the source authority. Not sending message {:?}.",
                    self,
                    routing_msg
                );
            }
            return Ok(());
        }
        if !self.add_to_pending_acks(&routing_msg, route, expires_at) {
            debug!(
                "{} already received an ack for {:?} - so not resending it.",
                self, routing_msg
            );
            return Ok(());
        }
        use crate::routing_table::Authority::*;
        let sending_sec = match routing_msg.src {
            ClientManager(_) | NaeManager(_) | NodeManager(_) | ManagedNode(_) | Section(_)
                if self.chain.is_member() =>
            {
                Some(self.chain.our_info().clone())
            }
            PrefixSection(ref pfx) if self.chain.is_member() => {
                let src_section = match self.chain.our_info_for_prefix(pfx) {
                    Some(a) => a.clone(),
                    None => {
                        // Can no longer represent sending Pfx.
                        return Ok(());
                    }
                };
                Some(src_section)
            }
            Client { .. } => None,
            _ if self.is_first_node => {
                // TODO: Remove this special case when PARSEC supports single-node networks.
                let members = iter::once(*self.full_id.public_id()).collect();
                Some(SectionInfo::new(members, Default::default(), None)?)
            }
            _ => {
                // Cannot send routing msgs as a Node until established.
                return Ok(());
            }
        };

        if route > 0 {
            trace!(
                "{} Resending Msg: {:?} via route: {} and src_section: {:?}",
                self,
                routing_msg,
                route,
                sending_sec
            );
        }

        let signed_msg = SignedMessage::new(routing_msg, &self.full_id, sending_sec)?;

        match self.get_signature_target(&signed_msg.routing_message().src, route) {
            None => Ok(()),
            Some(our_name) if our_name == *self.name() => {
                let min_section_size = self.min_section_size();
                if let Some((mut msg, route)) =
                    self.sig_accumulator
                        .add_message(signed_msg, min_section_size, route)
                {
                    if self.in_authority(&msg.routing_message().dst) {
                        self.handle_signed_message(msg, route, our_name, &BTreeSet::new())?;
                    } else {
                        self.send_signed_message(&mut msg, route, &our_name, &BTreeSet::new())?;
                    }
                }
                Ok(())
            }
            Some(target_name) => {
                if let Some(&pub_id) = self.peer_mgr.get_pub_id(&target_name) {
                    let direct_msg = signed_msg
                        .routing_message()
                        .to_signature(self.full_id.signing_private_key())?;
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

impl Display for Node {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "Node({}({:b}))", self.name(), self.our_prefix())
    }
}
