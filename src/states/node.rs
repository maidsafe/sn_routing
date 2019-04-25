// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::common::{Approved, Base, Bootstrapped, Relocated, USER_MSG_CACHE_EXPIRY_DURATION};
use crate::{
    ack_manager::{Ack, AckManager},
    cache::Cache,
    chain::{
        Chain, ChainState, ExpectCandidatePayload, GenesisPfxInfo, NetworkEvent,
        PrefixChangeOutcome, Proof, ProofSet, ProvingSection, SectionInfo,
    },
    config_handler,
    crust::{CrustError, CrustUser, PrivConnectionInfo},
    error::{BootstrapResponseError, InterfaceError, RoutingError},
    event::Event,
    id::{FullId, PublicId},
    messages::{
        DirectMessage, HopMessage, Message, MessageContent, RoutingMessage, SignedMessage,
        UserMessage, UserMessageCache, DEFAULT_PRIORITY, MAX_PARTS, MAX_PART_LEN,
    },
    outbox::EventBox,
    parsec::{self, Block, ParsecMap},
    peer_manager::{Peer, PeerManager, PeerState},
    rate_limiter::RateLimiter,
    resource_prover::RESOURCE_PROOF_DURATION,
    routing_message_filter::{FilteringResult, RoutingMessageFilter},
    routing_table::Error as RoutingTableError,
    routing_table::{Authority, Prefix, Xorable, DEFAULT_PREFIX},
    sha3::Digest256,
    signature_accumulator::SignatureAccumulator,
    state_machine::Transition,
    time::{Duration, Instant},
    timer::Timer,
    types::MessageId,
    utils::{self, DisplayDuration},
    xor_name::XorName,
    Service,
};
use itertools::Itertools;
use log::LogLevel;
use lru_time_cache::LruCache;
use maidsafe_utilities::serialisation;
use rand::{self, Rng};
use safe_crypto::Signature;
#[cfg(feature = "mock_base")]
use std::collections::BTreeMap;
use std::{
    cmp,
    collections::{BTreeSet, VecDeque},
    fmt::{self, Display, Formatter},
    iter, mem,
    net::{IpAddr, SocketAddr},
};

/// Time after which a `Ticked` event is sent.
const TICK_TIMEOUT: Duration = Duration::from_secs(15);
const POKE_TIMEOUT: Duration = Duration::from_secs(60);
const GOSSIP_TIMEOUT: Duration = Duration::from_secs(2);
const RECONNECT_PEER_TIMEOUT: Duration = Duration::from_secs(20);
//const MAX_IDLE_ROUNDS: u64 = 100;
//const TICK_TIMEOUT_SECS: u64 = 60;
/// The number of required leading zero bits for the resource proof
const RESOURCE_PROOF_DIFFICULTY: u8 = 0;
/// The total size of the resource proof data.
const RESOURCE_PROOF_TARGET_SIZE: usize = 250 * 1024 * 1024;
/// Interval between displaying info about current candidate.
const CANDIDATE_STATUS_INTERVAL: Duration = Duration::from_secs(60);
/// Duration for which all clients on a given IP will be blocked from joining this node.
const CLIENT_BAN_DURATION: Duration = Duration::from_secs(2 * 60 * 60);
/// Duration for which clients' IDs we disconnected from are retained.
const DROPPED_CLIENT_TIMEOUT: Duration = Duration::from_secs(2 * 60 * 60);

pub struct Node {
    ack_mgr: AckManager,
    cacheable_user_msg_cache: UserMessageCache,
    crust_service: Service,
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
    parsec_map: ParsecMap,
    gen_pfx_info: GenesisPfxInfo,
    poke_timer_token: u64,
    gossip_timer_token: u64,
    chain: Chain,
    // Peers we want to try reconnecting to
    reconnect_peers: Vec<PublicId>,
    reconnect_peers_token: u64,
    // TODO: notify without local state
    notified_nodes: BTreeSet<PublicId>,
}

impl Node {
    pub fn first(
        cache: Box<Cache>,
        crust_service: Service,
        full_id: FullId,
        min_section_size: usize,
        timer: Timer,
    ) -> Option<Self> {
        let dev_config = config_handler::get_config().dev.unwrap_or_default();

        let public_id = *full_id.public_id();
        let gen_pfx_info = GenesisPfxInfo {
            first_info: create_first_section_info(public_id).ok()?,
            latest_info: SectionInfo::default(),
        };

        let mut node = Self::new(
            AckManager::new(),
            cache,
            crust_service,
            full_id,
            gen_pfx_info,
            true,
            min_section_size,
            Default::default(),
            Default::default(),
            PeerManager::new(public_id, dev_config.disable_client_rate_limiter),
            RoutingMessageFilter::new(),
            timer,
        );

        if let Err(error) = node.crust_service.start_listening_tcp() {
            error!("{} Failed to start listening: {:?}", node, error);
            None
        } else {
            debug!("{} State changed to Node.", node);
            info!("{} Started a new network as a seed node.", node);
            Some(node)
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_proving_node(
        ack_mgr: AckManager,
        cache: Box<Cache>,
        crust_service: Service,
        full_id: FullId,
        gen_pfx_info: GenesisPfxInfo,
        min_section_size: usize,
        msg_queue: VecDeque<RoutingMessage>,
        notified_nodes: BTreeSet<PublicId>,
        peer_mgr: PeerManager,
        routing_msg_filter: RoutingMessageFilter,
        timer: Timer,
    ) -> Self {
        let node = Self::new(
            ack_mgr,
            cache,
            crust_service,
            full_id,
            gen_pfx_info,
            false,
            min_section_size,
            msg_queue,
            notified_nodes,
            peer_mgr,
            routing_msg_filter,
            timer,
        );

        debug!("{} State changed to Node.", node);
        node
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        ack_mgr: AckManager,
        cache: Box<Cache>,
        crust_service: Service,
        full_id: FullId,
        gen_pfx_info: GenesisPfxInfo,
        is_first_node: bool,
        min_section_size: usize,
        msg_queue: VecDeque<RoutingMessage>,
        notified_nodes: BTreeSet<PublicId>,
        peer_mgr: PeerManager,
        routing_msg_filter: RoutingMessageFilter,
        timer: Timer,
    ) -> Self {
        let dev_config = config_handler::get_config().dev.unwrap_or_default();

        let public_id = *full_id.public_id();

        let tick_timer_token = timer.schedule(TICK_TIMEOUT);
        let poke_timer_token = timer.schedule(POKE_TIMEOUT);
        let gossip_timer_token = timer.schedule(GOSSIP_TIMEOUT);
        let reconnect_peers_token = timer.schedule(RECONNECT_PEER_TIMEOUT);

        Self {
            ack_mgr,
            cacheable_user_msg_cache: UserMessageCache::with_expiry_duration(
                USER_MSG_CACHE_EXPIRY_DURATION,
            ),
            crust_service: crust_service,
            full_id: full_id.clone(),
            is_first_node,
            msg_queue,
            peer_mgr,
            response_cache: cache,
            routing_msg_filter,
            sig_accumulator: Default::default(),
            tick_timer_token: tick_timer_token,
            timer: timer,
            user_msg_cache: UserMessageCache::with_expiry_duration(USER_MSG_CACHE_EXPIRY_DURATION),
            next_relocation_dst: None,
            next_relocation_interval: None,
            routing_msg_backlog: vec![],
            candidate_timer_token: None,
            candidate_status_token: None,
            clients_rate_limiter: RateLimiter::new(dev_config.disable_client_rate_limiter),
            banned_client_ips: LruCache::with_expiry_duration(CLIENT_BAN_DURATION),
            dropped_clients: LruCache::with_expiry_duration(DROPPED_CLIENT_TIMEOUT),
            proxy_load_amount: 0,
            disable_resource_proof: dev_config.disable_resource_proof,
            parsec_map: ParsecMap::new(full_id, &gen_pfx_info),
            gen_pfx_info: gen_pfx_info.clone(),
            poke_timer_token,
            gossip_timer_token,
            chain: Chain::new(min_section_size, public_id, gen_pfx_info),
            reconnect_peers: Default::default(),
            reconnect_peers_token,
            notified_nodes,
        }
    }

    fn print_rt_size(&self) {
        const TABLE_LVL: LogLevel = LogLevel::Info;
        if log_enabled!(TABLE_LVL) {
            let status_str = format!(
                "{} - Routing Table size: {:3}",
                self,
                self.chain.valid_peers().len()
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

    // Initialises the first node of the network
    fn init_first_node(&mut self, outbox: &mut EventBox) -> Result<(), RoutingError> {
        outbox.send_event(Event::Connected);

        self.peer_mgr.set_established();
        self.crust_service.set_accept_bootstrap(true)?;
        self.crust_service.set_service_discovery_listen(true);

        Ok(())
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

    fn handle_parsec_poke(&mut self, msg_version: u64, pub_id: PublicId) {
        self.send_parsec_gossip(Some((msg_version, pub_id)))
    }

    fn handle_parsec_request(
        &mut self,
        msg_version: u64,
        par_request: parsec::Request,
        pub_id: PublicId,
        outbox: &mut EventBox,
    ) -> Result<Transition, RoutingError> {
        let log_ident = format!("{}", self);
        let (response, poll) =
            self.parsec_map
                .handle_request(msg_version, par_request, pub_id, &log_ident);

        if let Some(response) = response {
            self.send_message(&pub_id, response);
        }

        if poll {
            self.parsec_poll_all(outbox)
        } else {
            Ok(Transition::Stay)
        }
    }

    fn handle_parsec_response(
        &mut self,
        msg_version: u64,
        par_response: parsec::Response,
        pub_id: PublicId,
        outbox: &mut EventBox,
    ) -> Result<Transition, RoutingError> {
        let log_ident = format!("{}", self);
        if self
            .parsec_map
            .handle_response(msg_version, par_response, pub_id, &log_ident)
        {
            self.parsec_poll_all(outbox)
        } else {
            Ok(Transition::Stay)
        }
    }

    /// Votes for `Merge` if necessary, or for the merged `SectionInfo` if both siblings have
    /// already accumulated `Merge`.
    fn merge_if_necessary(&mut self) -> Result<(), RoutingError> {
        let sibling_pfx = self.our_prefix().sibling();
        if self.chain.is_self_merge_ready() && self.chain.other_prefixes().contains(&sibling_pfx) {
            let payload = *self.chain.our_info().hash();
            let src = Authority::PrefixSection(*self.our_prefix());
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
            } else if peer.is_routing() && self.chain.state() == &ChainState::Normal {
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
            .valid_peers()
            .into_iter()
            .filter(|pub_id| {
                self.peer_mgr.get_peer(pub_id).is_none() && *pub_id != self.full_id.public_id()
            })
            .cloned()
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
        let drained_obs: Vec<_> = self
            .parsec_map
            .our_unpolled_observations()
            .cloned()
            .collect();
        let sibling_pfx = self.chain.our_prefix().sibling();

        let PrefixChangeOutcome {
            gen_pfx_info,
            mut cached_events,
            completed_events,
        } = self.chain.finalise_prefix_change()?;
        self.gen_pfx_info = gen_pfx_info;
        self.init_parsec(); // We don't reset the chain on prefix change.

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

        cached_events
            .iter()
            .filter(|event| match **event {
                // Only re-vote not yet accumulated events and still relevant to our new prefix.
                NetworkEvent::Online(pub_id, _) | NetworkEvent::Offline(pub_id) => {
                    our_pfx.matches(pub_id.name()) && !completed_events.contains(event)
                }

                // Only re-vote not yet accumulated events and still relevant to our new prefix.
                NetworkEvent::ExpectCandidate(ExpectCandidatePayload { ref dst_name, .. }) => {
                    our_pfx.matches(dst_name) && !completed_events.contains(event)
                }

                // Keep: Additional signatures for neighbours for sec-msg-relay.
                NetworkEvent::SectionInfo(ref sec_info) => our_pfx.is_neighbour(sec_info.prefix()),

                // Drop: condition may have changed.
                NetworkEvent::OurMerge => false,

                // Keep: Still relevant after prefix change.
                NetworkEvent::NeighbourMerge(_) | NetworkEvent::ProvingSections(_, _) => true,
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
                        && (!self.in_authority(&signed_msg.routing_message().dst)
                            || signed_msg.routing_message().dst.is_single())
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

        if !self.chain.is_member() {
            match routing_msg.content {
                ExpectCandidate { .. }
                | NeighbourInfo(..)
                | NeighbourConfirm(..)
                | Merge(..)
                | UserMessagePart { .. } => {
                    // These messages should not be handled before node becomes established
                    self.add_routing_message_to_backlog(routing_msg);
                    return Ok(());
                }
                ConnectionInfoRequest { .. } => {
                    if !self.chain.our_prefix().matches(&routing_msg.src.name()) {
                        self.add_routing_message_to_backlog(routing_msg);
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
                Section(dst_name),
            ) => self.handle_expect_candidate(old_public_id, old_client_auth, dst_name, message_id),
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
            )
            | (
                ConnectionInfoRequest {
                    encrypted_conn_info,
                    pub_id,
                    msg_id,
                },
                src @ ManagedNode(_),
                dst @ Client { .. },
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
            (NeighbourInfo(_digest), ManagedNode(_), PrefixSection(_)) => Ok(()),
            (
                NeighbourConfirm(digest, proofs, sec_infos_and_proofs),
                ManagedNode(_),
                Section(_),
            ) => self.handle_neighbour_confirm(digest, proofs, sec_infos_and_proofs),
            (Merge(digest), PrefixSection(_), PrefixSection(_)) => self.handle_merge(digest),
            (Ack(ack, _), _, _) => {
                self.handle_ack_response(ack);
                Ok(())
            }
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

    // Backlog the message to be processed once we are approved.
    fn add_routing_message_to_backlog(&mut self, msg: RoutingMessage) {
        trace!(
            "{} Not approved yet. Delaying message handling: {:?}",
            self,
            msg
        );
        self.routing_msg_backlog.push(msg);
    }

    fn handle_candidate_approval(
        &mut self,
        new_pub_id: PublicId,
        new_client_auth: Authority<XorName>,
        outbox: &mut EventBox,
    ) -> Result<(), RoutingError> {
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

        let trimmed_info = GenesisPfxInfo {
            first_info: self.gen_pfx_info.first_info.clone(),
            latest_info: self.chain.our_info().clone(),
        };

        let src = Authority::PrefixSection(*trimmed_info.first_info.prefix());
        let content = MessageContent::NodeApproval(trimmed_info);
        if let Err(error) = self.send_routing_message(src, new_client_auth, content) {
            debug!(
                "{} Failed sending NodeApproval to {}: {:?}",
                self, new_pub_id, error
            );
        }

        if is_connected {
            self.add_to_routing_table(&new_pub_id, outbox);
        }
        Ok(())
    }

    fn init_parsec(&mut self) {
        let log_ident = format!("{}", self);
        self.parsec_map
            .init(self.full_id.clone(), &self.gen_pfx_info, &log_ident)
    }

    // Completes a Node startup process and allows a node to behave as a `ManagedNode`.
    // A given node is considered "established" when it exists in `chain.our_info().members()`
    // first node: this method is skipped entirely as it behaves as a Node from startup.
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
        self.candidate_status_token = Some(self.timer.schedule(CANDIDATE_STATUS_INTERVAL));
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
                self.send_candidate_approval();
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

        if !self.chain.is_member() {
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
            && self.chain.len() < self.min_section_size() - 1
        {
            debug!(
                "{} Client {:?} rejected: Routing table has {} entries. {} required.",
                self,
                pub_id,
                self.chain.len(),
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
                RESOURCE_PROOF_TARGET_SIZE / (self.chain.our_section().len() + 1),
            )
        };
        let seed: Vec<u8> = if cfg!(feature = "mock_base") {
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

        let close_section = self
            .chain
            .close_names(&dst_name)
            .ok_or(RoutingError::InvalidDestination)?;

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
    // Context: a node is joining our section. Vote `ExpectCandidate`.
    fn handle_expect_candidate(
        &mut self,
        old_public_id: PublicId,
        old_client_auth: Authority<XorName>,
        dst_name: XorName,
        message_id: MessageId,
    ) -> Result<(), RoutingError> {
        if !self.chain.is_member() {
            return Ok(());
        }

        self.vote_for_event(NetworkEvent::ExpectCandidate(ExpectCandidatePayload {
            old_public_id,
            old_client_auth,
            dst_name,
            message_id,
        }));
        Ok(())
    }

    // Return Prefix of section with shorter prefix to resend the `ExpectCandidate` to.
    // Return None if we are the best section.
    fn need_to_forward_expect_candidate_to_prefix(&self) -> Option<Prefix<XorName>> {
        if cfg!(feature = "mock_base") && self.next_relocation_interval.is_some() {
            // Forbid section balancing: It Breaks things in this case.
            return None;
        }

        let min_len_prefix = self.chain().min_len_prefix();
        if min_len_prefix == *self.our_prefix() {
            // Our section is the best destination.
            return None;
        }

        Some(min_len_prefix)
    }

    // Forward ExpectCandidate to section with given prefix.
    fn forward_expect_candidate_to_prefix(
        &mut self,
        vote: ExpectCandidatePayload,
        prefix: Prefix<XorName>,
    ) -> Result<(), RoutingError> {
        let src = Authority::Section(vote.dst_name);
        let dst = Authority::Section(prefix.substituted_in(vote.dst_name));
        let content = MessageContent::ExpectCandidate {
            old_public_id: vote.old_public_id,
            old_client_auth: vote.old_client_auth,
            message_id: vote.message_id,
        };

        self.send_routing_message(src, dst, content)
    }

    // Reject candidate without a response as one is already processed: return None.
    // Otherwise, store the candidate for resource proof: return the target interval.
    // Take next_relocation_interval if available.
    fn accept_candidate_with_interval(
        &mut self,
        vote: &ExpectCandidatePayload,
    ) -> Option<(XorName, XorName)> {
        if self.peer_mgr.has_candidate() {
            return None;
        }

        let target_interval = self.next_relocation_interval.take().unwrap_or_else(|| {
            utils::calculate_relocation_interval(&self.our_prefix(), &self.chain.our_section())
        });
        self.peer_mgr
            .accept_as_candidate(vote.old_public_id, target_interval);

        Some(target_interval)
    }

    // Send RelocateResponse to the candidate using the target_interval.
    fn send_relocate_response(
        &mut self,
        vote: ExpectCandidatePayload,
        target_interval: (XorName, XorName),
    ) -> Result<(), RoutingError> {
        let own_section = if self.chain().is_member() {
            let our_info = self.chain().our_info();
            (*our_info.prefix(), our_info.members().clone())
        } else {
            //FIXME: do this properly
            (
                Default::default(),
                iter::once(*self.full_id().public_id()).collect::<BTreeSet<PublicId>>(),
            )
        };

        let src = Authority::Section(vote.dst_name);
        let dst = vote.old_client_auth;
        let content = MessageContent::RelocateResponse {
            target_interval: target_interval,
            section: own_section,
            message_id: vote.message_id,
        };

        info!(
            "{} Our section with {:?} accepted candidate with old name {}.",
            self,
            self.our_prefix(),
            vote.old_public_id
        );
        trace!("{} Sending {:?} to {:?}", self, content, dst);

        self.send_routing_message(src, dst, content)
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

    fn send_parsec_gossip(&mut self, target: Option<(u64, PublicId)>) {
        let (version, gossip_target) = match target {
            Some((v, p)) => (v, p),
            None => {
                let version = self.parsec_map.last_version();
                let mut recipients = self.parsec_map.gossip_recipients();
                if recipients.is_empty() {
                    // Parsec hasn't caught up with the event of us joining yet.
                    return;
                }

                recipients.retain(|pub_id| self.peer_mgr.is_connected(pub_id));
                if recipients.is_empty() {
                    log_or_panic!(LogLevel::Error, "Not connected to any gossip recipient.");
                    return;
                }

                let rand_index = utils::rand_index(recipients.len());
                (version, *recipients[rand_index])
            }
        };

        if let Some(msg) = self.parsec_map.create_gossip(version, &gossip_target) {
            self.send_message(&gossip_target, msg);
        }
    }

    // Sends a `ParsecPoke` message to trigger a gossip request from current section members to us.
    //
    // TODO: Should restrict targets to few(counter churn-threshold)/single.
    // Currently this can result in incoming spam of gossip history from everyone.
    // Can also just be a single target once node-ageing makes Offline votes Opaque which should
    // remove invalid test failures for unaccumulated parsec::Remove blocks.
    fn send_parsec_poke(&mut self) {
        let version = *self.gen_pfx_info.first_info.version();
        let recipients = self
            .gen_pfx_info
            .latest_info
            .members()
            .iter()
            .cloned()
            .collect_vec();

        for recipient in recipients {
            self.send_message(
                &recipient,
                Message::Direct(DirectMessage::ParsecPoke(version)),
            );
        }
    }

    fn send_candidate_approval(&mut self) {
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

        if !self.our_prefix().matches(new_id.name()) {
            log_or_panic!(
                LogLevel::Error,
                "{} About to vote for {} which does not match self pfx: {:?}",
                self,
                new_id.name(),
                self.our_prefix()
            );
        }
        self.vote_for_event(NetworkEvent::Online(new_id, client_auth));
    }

    fn vote_for_event(&mut self, event: NetworkEvent) {
        trace!("{} Vote for Event {:?}", self, event);
        let log_ident = format!("{}", self);
        self.parsec_map.vote_for(event, &log_ident)
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
            self.send_signed_message_to_peer(
                signed_msg.clone(),
                &target_pub_id,
                route,
                new_sent_to.clone(),
            )?;
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

        let result = if self.peer_mgr.is_connected(pub_id) {
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

            let data = self.to_hop_bytes(signed_msg.clone(), 0, BTreeSet::new())?;
            self.send_or_drop(pub_id, data, priority);
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
        if !self.chain().is_member() {
            return Some(*self.name());
        }
        let list: Vec<XorName> = match *src {
            ClientManager(_) | NaeManager(_) | NodeManager(_) => {
                let mut v = self
                    .chain
                    .our_section()
                    .into_iter()
                    .sorted_by(|lhs, rhs| src.name().cmp_distance(lhs, rhs));
                v.truncate(self.min_section_size());
                v
            }
            Section(_) => self
                .chain
                .our_section()
                .into_iter()
                .sorted_by(|lhs, rhs| src.name().cmp_distance(lhs, rhs)),
            // FIXME: This does not include recently accepted peers which would affect quorum
            // calculation. This even when going via RT would have only allowed route-0 to succeed
            // as by ack-failure, the new node would have been accepted to the RT.
            // Need a better network startup separation.
            PrefixSection(_) => {
                Iterator::flatten(self.chain.all_sections().map(|(_, si)| si.member_names()))
                    .sorted_by(|lhs, rhs| src.name().cmp_distance(lhs, rhs))
            }
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

        if self.chain.is_member() && !force_via_proxy {
            // TODO: even if having chain reply based on connected_state,
            // we remove self in targets info and can do same by not
            // chaining us to conn_peer list here?
            let conn_peers = self.connected_peers();
            let targets: BTreeSet<_> = self
                .chain
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
            if let Some(pub_id) = self
                .peer_mgr
                .get_peer_by_name(proxy_node_name)
                .map(Peer::pub_id)
            {
                if self.peer_mgr.is_connected(pub_id) {
                    Ok((BTreeSet::new(), vec![*pub_id]))
                } else {
                    error!(
                        "{} Unable to find connection to proxy in PeerManager.",
                        self
                    );
                    Err(RoutingError::ProxyConnectionNotFound)
                }
            } else {
                error!("{} Unable to find proxy in PeerManager.", self);
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

    // TODO: Once `Chain::targets` uses the ideal state instead of the actually connected peers,
    // this should be removed.
    /// Returns all peers we are currently connected to, according to the peer manager, including
    /// ourselves.
    fn connected_peers(&self) -> Vec<&XorName> {
        self.peer_mgr
            .connected_peers()
            .map(Peer::name)
            .chain(iter::once(self.name()))
            .collect()
    }

    /// Handles dropped peer with the given ID. Returns true if we should keep running, false if
    /// we should terminate.
    fn dropped_peer(
        &mut self,
        pub_id: &PublicId,
        outbox: &mut EventBox,
        try_reconnect: bool,
    ) -> bool {
        let _ = self.peer_mgr.remove_peer(pub_id);

        if self.chain.is_member() && self.notified_nodes.remove(pub_id) {
            info!("{} Dropped {} from the routing table.", self, pub_id.name());
            outbox.send_event(Event::NodeLost(*pub_id.name()));

            if self.chain.our_info().members().contains(pub_id) {
                self.vote_for_event(NetworkEvent::Offline(*pub_id));
            }
        }

        if self
            .peer_mgr
            .connected_peers()
            .filter(|p| p.is_routing())
            .count()
            == 0
            && self.chain().is_member()
        {
            debug!("{} Lost all routing connections.", self);
            if !self.is_first_node {
                outbox.send_event(Event::RestartRequired);
                return false;
            }
        }

        if try_reconnect && self.chain.is_member() && self.chain.is_peer_valid(pub_id) {
            debug!("{} Caching {:?} to reconnect.", self, pub_id);
            self.reconnect_peers.push(*pub_id);
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

    fn our_prefix(&self) -> &Prefix<XorName> {
        self.chain.our_prefix()
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
            let conn_peers = self.connected_peers();
            self.chain.is_member() && self.chain().in_authority(auth, &conn_peers)
        }
    }

    fn close_group(&self, name: XorName, count: usize) -> Option<Vec<XorName>> {
        let conn_peers = self.connected_peers();
        self.chain.closest_names(&name, count, &conn_peers)
    }

    fn min_section_size(&self) -> usize {
        self.chain.min_sec_size()
    }

    fn handle_node_send_message(
        &mut self,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        content: UserMessage,
        priority: u8,
    ) -> Result<(), InterfaceError> {
        match self.send_user_message(src, dst, content, priority) {
            Err(RoutingError::Interface(err)) => Err(err),
            Err(_) | Ok(()) => Ok(()),
        }
    }

    fn handle_timeout(&mut self, token: u64, outbox: &mut EventBox) -> Transition {
        if self.tick_timer_token == token {
            self.tick_timer_token = self.timer.schedule(TICK_TIMEOUT);
            self.remove_expired_peers();
            self.proxy_load_amount = 0;

            if self.chain.is_member() {
                self.update_peer_states(outbox);
                outbox.send_event(Event::TimerTicked);
            }
        } else if self.candidate_timer_token == Some(token) {
            self.candidate_timer_token = None;
            self.send_candidate_approval();
        } else if self.candidate_status_token == Some(token) {
            self.candidate_status_token = Some(self.timer.schedule(CANDIDATE_STATUS_INTERVAL));
            self.peer_mgr.show_candidate_status();
        } else if self.reconnect_peers_token == token {
            self.reconnect_peers_token = self.timer.schedule(RECONNECT_PEER_TIMEOUT);
            self.reconnect_peers(outbox);
        } else if self.poke_timer_token == token {
            if !self.peer_mgr.is_established() {
                self.send_parsec_poke();
                self.poke_timer_token = self.timer.schedule(POKE_TIMEOUT);
            }
        } else if self.gossip_timer_token == token {
            self.gossip_timer_token = self.timer.schedule(GOSSIP_TIMEOUT);

            // If we're the only node then invoke parsec_poll directly
            if self.chain.is_member() && self.chain.our_info().members().len() == 1 {
                let _ = self.parsec_poll_all(outbox);
            }

            self.send_parsec_gossip(None);
        } else {
            // Each token has only one purpose, so we only need to call this if none of the above
            // matched:
            self.resend_unacknowledged_timed_out_msgs(token);
        }

        Transition::Stay
    }

    fn finish_handle_action(&mut self, outbox: &mut EventBox) -> Transition {
        self.handle_routing_messages(outbox);
        Transition::Stay
    }

    fn handle_bootstrap_accept(&mut self, pub_id: PublicId, peer_kind: CrustUser) -> Transition {
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
            return Transition::Stay;
        };

        if peer_kind == CrustUser::Client && self.banned_client_ips.contains_key(&ip) {
            warn!(
                "{} Client {:?} is trying to bootstrap on banned IP {}.",
                self, pub_id, ip
            );
            self.ban_and_disconnect_peer(&pub_id);
            return Transition::Stay;
        }

        self.peer_mgr
            .insert_peer(Peer::new(pub_id, PeerState::Bootstrapper { peer_kind, ip }));

        Transition::Stay
    }

    fn handle_bootstrap_connect(&mut self, pub_id: PublicId, _: SocketAddr) -> Transition {
        // A mature node doesn't need a bootstrap connection
        self.disconnect_peer(&pub_id);
        Transition::Stay
    }

    fn handle_connect_success(&mut self, pub_id: PublicId, outbox: &mut EventBox) -> Transition {
        Relocated::handle_connect_success(self, pub_id, outbox)
    }

    fn handle_connect_failure(&mut self, pub_id: PublicId, outbox: &mut EventBox) -> Transition {
        self.log_connect_failure(&pub_id);
        let _ = self.dropped_peer(&pub_id, outbox, true);
        if self.chain.is_member() && self.chain.our_info().members().contains(&pub_id) {
            self.vote_for_event(NetworkEvent::Offline(pub_id));
        }

        Transition::Stay
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

    fn handle_connection_info_prepared(
        &mut self,
        result_token: u32,
        result: Result<PrivConnectionInfo<PublicId>, CrustError>,
    ) -> Transition {
        Relocated::handle_connection_info_prepared(self, result_token, result)
    }

    fn handle_listener_started(&mut self, port: u16, outbox: &mut EventBox) -> Transition {
        trace!("{} - Listener started on port {}.", self, port);
        if self.is_first_node && self.init_first_node(outbox).is_err() {
            outbox.send_event(Event::Terminated);
            Transition::Terminate
        } else {
            Transition::Stay
        }
    }

    fn handle_listener_failed(&mut self, outbox: &mut EventBox) -> Transition {
        error!("{} - Failed to start listening.", self);
        outbox.send_event(Event::Terminated);
        Transition::Terminate
    }

    fn finish_handle_crust_event(&mut self, outbox: &mut EventBox) -> Transition {
        self.handle_routing_messages(outbox);
        Transition::Stay
    }

    // Deconstruct a `DirectMessage` and handle or forward as appropriate.
    fn handle_direct_message(
        &mut self,
        direct_message: DirectMessage,
        pub_id: PublicId,
        outbox: &mut EventBox,
    ) -> Result<Transition, RoutingError> {
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
            ParsecPoke(version) => self.handle_parsec_poke(version, pub_id),
            ParsecRequest(version, par_request) => {
                return self.handle_parsec_request(version, par_request, pub_id, outbox);
            }
            ParsecResponse(version, par_response) => {
                return self.handle_parsec_response(version, par_response, pub_id, outbox);
            }
            BootstrapResponse(_)
            | ProxyRateLimitExceeded { .. }
            | ResourceProof { .. }
            | ResourceProofResponseReceipt => {
                debug!("{} Unhandled direct message: {:?}", self, direct_message);
            }
        }

        Ok(Transition::Stay)
    }

    fn handle_hop_message(
        &mut self,
        hop_msg: HopMessage,
        pub_id: PublicId,
        _: &mut EventBox,
    ) -> Result<Transition, RoutingError> {
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
            Some(&PeerState::Candidate) | Some(&PeerState::Proxy) | Some(&PeerState::Routing) => {
                Ok(*pub_id.name())
            }
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
                    return Ok(Transition::Stay);
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
                    .map(|()| Transition::Stay)
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
}

#[cfg(feature = "mock_base")]
impl Node {
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

    pub fn get_clients_usage(&self) -> BTreeMap<IpAddr, u64> {
        self.clients_rate_limiter.usage_map().clone()
    }

    pub fn has_unconsensused_observations(&self, filter_opaque: bool) -> bool {
        self.parsec_map
            .has_unconsensused_observations(filter_opaque)
    }

    pub fn is_routing_peer(&self, pub_id: &PublicId) -> bool {
        self.peer_mgr
            .get_peer(pub_id)
            .map_or(false, Peer::is_routing)
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
        src_section: Option<SectionInfo>,
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

        use crate::routing_table::Authority::*;
        let sending_sec = if route == 0 {
            match routing_msg.src {
                ClientManager(_) | NaeManager(_) | NodeManager(_) | ManagedNode(_) | Section(_)
                | PrefixSection(_)
                    if self.chain.is_member() =>
                {
                    Some(self.chain.our_info().clone())
                }
                Client { .. } => None,
                _ => {
                    // Cannot send routing msgs as a Node until established.
                    return Ok(());
                }
            }
        } else {
            src_section
        };

        if !self.add_to_pending_acks(&routing_msg, sending_sec.clone(), route, expires_at) {
            debug!(
                "{} already received an ack for {:?} - so not resending it.",
                self, routing_msg
            );
            return Ok(());
        }

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

impl Relocated for Node {
    fn peer_mgr(&self) -> &PeerManager {
        &self.peer_mgr
    }

    fn peer_mgr_mut(&mut self) -> &mut PeerManager {
        &mut self.peer_mgr
    }

    /// Adds a newly connected peer to the routing table. Must only be called for connected peers.
    fn process_connection(&mut self, pub_id: PublicId, outbox: &mut EventBox) {
        if self.chain.is_peer_valid(&pub_id) {
            self.add_to_routing_table(&pub_id, outbox);
        }
    }

    fn is_peer_valid(&self, pub_id: &PublicId) -> bool {
        !self.chain.is_member() || self.chain.is_peer_valid(pub_id)
    }

    fn add_to_routing_table_success(&mut self, _: &PublicId) {
        self.print_rt_size();
    }

    fn add_to_routing_table_failure(&mut self, pub_id: &PublicId) {
        if !self.chain.is_peer_valid(pub_id) {
            self.disconnect_peer(pub_id);
        }
    }

    fn add_to_notified_nodes(&mut self, pub_id: PublicId) -> bool {
        self.notified_nodes.insert(pub_id)
    }

    fn remove_from_notified_nodes(&mut self, pub_id: &PublicId) -> bool {
        self.notified_nodes.remove(pub_id)
    }
}

impl Approved for Node {
    fn parsec_poll_one(&mut self) -> Option<Block> {
        self.parsec_map.poll()
    }

    fn chain_mut(&mut self) -> &mut Chain {
        &mut self.chain
    }

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

    fn handle_our_merge_event(&mut self) -> Result<(), RoutingError> {
        self.merge_if_necessary()
    }

    fn handle_neighbour_merge_event(&mut self) -> Result<(), RoutingError> {
        self.merge_if_necessary()
    }

    fn handle_expect_candidate_event(
        &mut self,
        vote: ExpectCandidatePayload,
    ) -> Result<(), RoutingError> {
        if !self.chain.is_member() {
            return Ok(());
        }

        if let Some(prefix) = self.need_to_forward_expect_candidate_to_prefix() {
            return self.forward_expect_candidate_to_prefix(vote, prefix);
        }

        if let Some(target_interval) = self.accept_candidate_with_interval(&vote) {
            self.candidate_timer_token = Some(self.timer.schedule(RESOURCE_PROOF_DURATION));
            return self.send_relocate_response(vote, target_interval);
        }

        // Nothing to do with this event.
        Ok(())
    }

    fn handle_section_info_event(
        &mut self,
        sec_info: SectionInfo,
        old_pfx: Prefix<XorName>,
        outbox: &mut EventBox,
    ) -> Result<Transition, RoutingError> {
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
            outbox.send_event(Event::SectionSplit(*sec_info.prefix()));
            self.send_neighbour_infos();
        } else if old_pfx.is_extension_of(sec_info.prefix()) {
            self.finalise_prefix_change()?;
            outbox.send_event(Event::SectionMerged(*sec_info.prefix()));
        }

        let our_name = *self.full_id.public_id().name();
        let self_sec_update = sec_info.prefix().matches(&our_name);

        if self.chain.is_member() {
            self.update_peer_states(outbox);

            if self_sec_update {
                self.send_neighbour_infos();
            } else {
                // Vote for neighbour update if we haven't done so already.
                // vote_for_event is expected to only generate a new vote if required.
                self.vote_for_event(sec_info.into_network_event());
            }
        }

        let _ = self.merge_if_necessary();

        Ok(Transition::Stay)
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
}

impl Display for Node {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "Node({}({:b}))", self.name(), self.our_prefix())
    }
}

// Create `SectionInfo` for the first node.
fn create_first_section_info(public_id: PublicId) -> Result<SectionInfo, RoutingError> {
    SectionInfo::new(
        iter::once(public_id).collect(),
        *DEFAULT_PREFIX,
        iter::empty(),
    )
    .map_err(|err| {
        error!(
            "FirstNode({:?}) - Failed to create first SectionInfo: {:?}",
            public_id.name(),
            err
        );
        err
    })
}
