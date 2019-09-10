// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#[cfg(all(test, feature = "mock_parsec"))]
mod tests;

use super::common::{Approved, Base, Bootstrapped, Relocated};
#[cfg(feature = "mock_base")]
use crate::messages::Message;
use crate::{
    chain::{
        delivery_group_size, AccumulatingEvent, AckMessagePayload, Chain, ExpectCandidatePayload,
        GenesisPfxInfo, NetworkEvent, OnlinePayload, PrefixChange, PrefixChangeOutcome,
        SectionInfo, SectionInfoSigPayload, SectionKeyInfo, SendAckMessagePayload,
    },
    config_handler,
    error::{BootstrapResponseError, InterfaceError, RoutingError},
    event::Event,
    id::{FullId, PublicId},
    messages::{DirectMessage, HopMessage, MessageContent, RoutingMessage, SignedRoutingMessage},
    outbox::EventBox,
    parsec::{self, ParsecMap},
    peer_manager::{Peer, PeerManager, PeerState},
    peer_map::PeerMap,
    quic_p2p::NodeInfo,
    routing_message_filter::{FilteringResult, RoutingMessageFilter},
    routing_table::Error as RoutingTableError,
    routing_table::{Authority, Prefix, Xorable, DEFAULT_PREFIX},
    sha3::Digest256,
    signature_accumulator::SignatureAccumulator,
    state_machine::Transition,
    time::{Duration, Instant},
    timer::Timer,
    types::MessageId,
    utils::{self, XorTargetInterval},
    xor_name::XorName,
    BlsPublicKeySet, ConnectionInfo, NetworkService,
};
use itertools::Itertools;
use log::LogLevel;
use lru_time_cache::LruCache;
use maidsafe_utilities::serialisation;
use safe_crypto::Signature;
#[cfg(feature = "mock_base")]
use std::net::SocketAddr;
use std::{
    cmp,
    collections::{BTreeSet, VecDeque},
    fmt::{self, Display, Formatter},
    iter, mem,
    net::IpAddr,
};

/// Time after which a `Ticked` event is sent.
const TICK_TIMEOUT: Duration = Duration::from_secs(15);
const GOSSIP_TIMEOUT: Duration = Duration::from_secs(2);
//const MAX_IDLE_ROUNDS: u64 = 100;
//const TICK_TIMEOUT_SECS: u64 = 60;
/// Interval between displaying info about current candidate.
const CANDIDATE_STATUS_INTERVAL: Duration = Duration::from_secs(60);
/// Duration for which all clients on a given IP will be blocked from joining this node.
const CLIENT_BAN_DURATION: Duration = Duration::from_secs(2 * 60 * 60);
/// Duration for which clients' IDs we disconnected from are retained.
const DROPPED_CLIENT_TIMEOUT: Duration = Duration::from_secs(2 * 60 * 60);

pub struct ElderDetails {
    pub chain: Chain,
    pub network_service: NetworkService,
    pub event_backlog: Vec<Event>,
    pub full_id: FullId,
    pub gen_pfx_info: GenesisPfxInfo,
    pub msg_backlog: Vec<RoutingMessage>,
    pub parsec_map: ParsecMap,
    pub peer_map: PeerMap,
    pub peer_mgr: PeerManager,
    pub routing_msg_filter: RoutingMessageFilter,
    pub timer: Timer,
}

pub struct Elder {
    network_service: NetworkService,
    full_id: FullId,
    is_first_node: bool,
    /// The queue of routing messages addressed to us. These do not themselves need forwarding,
    /// although they may wrap a message which needs forwarding.
    msg_queue: VecDeque<RoutingMessage>,
    peer_map: PeerMap,
    peer_mgr: PeerManager,
    routing_msg_filter: RoutingMessageFilter,
    sig_accumulator: SignatureAccumulator,
    tick_timer_token: u64,
    timer: Timer,
    /// Value which can be set in mock-network tests to be used as the calculated name for the next
    /// relocation request received by this node.
    next_relocation_dst: Option<XorName>,
    /// Interval used for relocation in mock network tests.
    next_relocation_interval: Option<XorTargetInterval>,
    /// The timer token for displaying the current candidate status.
    candidate_status_token: u64,
    /// IPs of clients which have been temporarily blocked from bootstrapping off this node.
    banned_client_ips: LruCache<IpAddr, ()>,
    /// Recently-disconnected clients.  Clients are added to this when we disconnect from them so we
    /// have a way to know to not handle subsequent hop messages from them (i.e. those which were
    /// already enqueued in the channel or added before Crust handled the disconnect request).  If a
    /// client then re-connects, its ID is removed from here when we add it to the `PeerManager`.
    dropped_clients: LruCache<PublicId, ()>,
    /// Proxy client traffic handled
    proxy_load_amount: u64,
    parsec_map: ParsecMap,
    gen_pfx_info: GenesisPfxInfo,
    gossip_timer_token: u64,
    chain: Chain,
    #[cfg(feature = "mock_base")]
    ignore_candidate_info_counter: u8,
    pfx_is_successfully_polled: bool,
}

impl Elder {
    pub fn first(
        network_service: NetworkService,
        full_id: FullId,
        min_section_size: usize,
        timer: Timer,
        outbox: &mut dyn EventBox,
    ) -> Result<Self, RoutingError> {
        let dev_config = config_handler::get_config().dev.unwrap_or_default();

        let public_id = *full_id.public_id();
        let gen_pfx_info = GenesisPfxInfo {
            first_info: create_first_section_info(public_id)?,
            first_state_serialized: Vec::new(),
            latest_info: SectionInfo::default(),
        };
        let parsec_map = ParsecMap::new(full_id.clone(), &gen_pfx_info);
        let chain = Chain::new(min_section_size, public_id, gen_pfx_info.clone());
        let peer_map = PeerMap::new();
        let peer_mgr = PeerManager::new(dev_config.disable_client_rate_limiter);

        let details = ElderDetails {
            chain,
            network_service,
            event_backlog: Vec::new(),
            full_id,
            gen_pfx_info,
            msg_backlog: Vec::new(),
            parsec_map,
            peer_map,
            peer_mgr,
            routing_msg_filter: RoutingMessageFilter::new(),
            timer,
        };

        let node = Self::new(details, true);

        debug!("{} - State changed to Node.", node);
        info!("{} - Started a new network as a seed node.", node);

        outbox.send_event(Event::Connected);

        Ok(node)
    }

    pub fn from_adult(
        mut details: ElderDetails,
        sec_info: SectionInfo,
        old_pfx: Prefix<XorName>,
        outbox: &mut dyn EventBox,
    ) -> Result<Self, RoutingError> {
        let event_backlog = mem::replace(&mut details.event_backlog, Vec::new());
        let mut elder = Self::new(details, false);
        elder.init(sec_info, old_pfx, event_backlog, outbox)?;
        Ok(elder)
    }

    fn new(details: ElderDetails, is_first_node: bool) -> Self {
        let timer = details.timer;
        let tick_timer_token = timer.schedule(TICK_TIMEOUT);
        let gossip_timer_token = timer.schedule(GOSSIP_TIMEOUT);
        let candidate_status_token = timer.schedule(CANDIDATE_STATUS_INTERVAL);

        Self {
            network_service: details.network_service,
            full_id: details.full_id.clone(),
            is_first_node,
            msg_queue: details.msg_backlog.into_iter().collect(),
            peer_map: details.peer_map,
            peer_mgr: details.peer_mgr,
            routing_msg_filter: details.routing_msg_filter,
            sig_accumulator: Default::default(),
            tick_timer_token: tick_timer_token,
            timer: timer,
            next_relocation_dst: None,
            next_relocation_interval: None,
            candidate_status_token,
            banned_client_ips: LruCache::with_expiry_duration(CLIENT_BAN_DURATION),
            dropped_clients: LruCache::with_expiry_duration(DROPPED_CLIENT_TIMEOUT),
            proxy_load_amount: 0,
            parsec_map: details.parsec_map,
            gen_pfx_info: details.gen_pfx_info,
            gossip_timer_token,
            chain: details.chain,
            #[cfg(feature = "mock_base")]
            ignore_candidate_info_counter: 0,
            pfx_is_successfully_polled: false,
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
            let network_estimate = match self.chain.network_size_estimate() {
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

    // Initialise regular node
    fn init(
        &mut self,
        sec_info: SectionInfo,
        old_pfx: Prefix<XorName>,
        event_backlog: Vec<Event>,
        outbox: &mut dyn EventBox,
    ) -> Result<(), RoutingError> {
        debug!("{} - State changed to Elder.", self);
        trace!(
            "{} - Node Established. Prefixes: {:?}",
            self,
            self.chain.prefixes()
        );

        // Send `Event::Connected` first and then any backlogged events from previous states.
        for event in iter::once(Event::Connected).chain(event_backlog) {
            self.send_event(event, outbox);
        }

        // Handle the SectionInfo event which triggered us becoming established node.
        let _ = self.handle_section_info_event(sec_info, old_pfx, outbox)?;

        Ok(())
    }

    fn handle_routing_messages(&mut self, outbox: &mut dyn EventBox) {
        while let Some(routing_msg) = self.msg_queue.pop_front() {
            if self.in_authority(&routing_msg.dst) {
                if let Err(err) = self.dispatch_routing_message(routing_msg, outbox) {
                    debug!("{} Routing message dispatch failed: {:?}", self, err);
                }
            }
        }
    }

    fn public_key_set(&self) -> BlsPublicKeySet {
        self.chain.public_key_set()
    }

    fn handle_parsec_poke(&mut self, msg_version: u64, pub_id: PublicId) {
        self.send_parsec_gossip(Some((msg_version, pub_id)))
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
            self.vote_for_section_info(merged_info)?;
        } else if self.chain.should_vote_for_merge() && !self.chain.is_self_merge_ready() {
            self.vote_for_event(AccumulatingEvent::OurMerge);
        }
        Ok(())
    }

    // Connected peers which are valid need added to RT
    // Peers no longer required currently connected as PeerState::Routing are disconnected
    // Establish connection to peers missing from peer manager
    fn update_peer_states(&mut self, outbox: &mut dyn EventBox) {
        let mut peers_to_add = Vec::new();
        let mut peers_to_remove = Vec::new();

        for (pub_id, peer) in self.peer_mgr.connected_peers() {
            if self.is_peer_valid(pub_id) {
                peers_to_add.push(*pub_id);
            } else if peer.is_node() && self.chain.prefix_change() == PrefixChange::None {
                peers_to_remove.push(*pub_id);
            }
        }
        for pub_id in peers_to_add {
            self.add_node(&pub_id, outbox);
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
            let dst = Authority::ManagedNode(*pub_id.name());
            let _ = self.send_connection_request(pub_id, src, dst, outbox);
        }
    }

    fn finalise_prefix_change(&mut self) -> Result<(), RoutingError> {
        // Clear any relocation overrides
        self.next_relocation_dst = None;
        self.next_relocation_interval = None;

        let drained_obs: Vec<_> = self
            .parsec_map
            .our_unpolled_observations()
            .cloned()
            .collect();

        let PrefixChangeOutcome {
            gen_pfx_info,
            mut cached_events,
            completed_events,
        } = self.chain.finalise_prefix_change()?;
        self.gen_pfx_info = gen_pfx_info;
        self.chain.reset_candidate();
        self.peer_mgr.reset_candidate();
        self.init_parsec(); // We don't reset the chain on prefix change.

        for obs in drained_obs {
            let event = match obs {
                parsec::Observation::Remove { peer_id, .. } => {
                    AccumulatingEvent::Offline(peer_id).into_network_event()
                }
                parsec::Observation::OpaquePayload(event) => event.clone(),

                parsec::Observation::Genesis { .. }
                | parsec::Observation::Add { .. }
                | parsec::Observation::Accusation { .. }
                | parsec::Observation::StartDkg(_)
                | parsec::Observation::DkgResult { .. }
                | parsec::Observation::DkgMessage(_) => continue,
            };
            let _ = cached_events.insert(event);
        }
        let our_pfx = *self.chain.our_prefix();

        cached_events
            .iter()
            .filter(|event| match event.payload {
                // Only re-vote not yet accumulated events and still relevant to our new prefix.
                AccumulatingEvent::Offline(pub_id) => {
                    our_pfx.matches(pub_id.name()) && !completed_events.contains(&event.payload)
                }

                // Drop candidates that have not completed:
                // Called peer_manager.remove_candidate reset the candidate so it can be shared by
                // all nodes: Because new node may not have voted for it, Forget the votes in
                // flight as well.
                AccumulatingEvent::AddElder(_, _)
                | AccumulatingEvent::RemoveElder(_)
                | AccumulatingEvent::Online(_)
                | AccumulatingEvent::ExpectCandidate(_)
                | AccumulatingEvent::ParsecPrune
                | AccumulatingEvent::PurgeCandidate(_) => false,

                // Keep: Additional signatures for neighbours for sec-msg-relay.
                AccumulatingEvent::SectionInfo(ref sec_info) => {
                    our_pfx.is_neighbour(sec_info.prefix())
                }

                // Drop: condition may have changed.
                AccumulatingEvent::OurMerge => false,

                // Keep: Still relevant after prefix change.
                AccumulatingEvent::NeighbourMerge(_)
                | AccumulatingEvent::TheirKeyInfo(_)
                | AccumulatingEvent::AckMessage(_)
                | AccumulatingEvent::SendAckMessage(_) => true,
            })
            .for_each(|event| {
                self.vote_for_network_event(event.clone());
            });

        Ok(())
    }

    fn send_neighbour_infos(&mut self) {
        self.chain.other_prefixes().iter().for_each(|pfx| {
            let src = Authority::Section(self.our_prefix().name());
            let dst = Authority::PrefixSection(*pfx);
            let content = MessageContent::NeighbourInfo(self.chain.our_info().clone());
            if let Err(err) = self.send_routing_message(src, dst, content) {
                debug!("{} Failed to send NeighbourInfo: {:?}.", self, err);
            }
        });
    }

    /// Returns `Ok` if the peer's state indicates it's allowed to send the given message type.
    fn check_direct_message_sender(
        &self,
        msg: &DirectMessage,
        pub_id: &PublicId,
    ) -> Result<(), RoutingError> {
        match self.peer_mgr.get_peer(pub_id).map(Peer::state) {
            Some(PeerState::Client { .. }) => {
                if let DirectMessage::BootstrapRequest = *msg {
                    Ok(())
                } else {
                    debug!(
                        "{} Illegitimate direct message {:?} from {:?}.",
                        self, msg, pub_id
                    );
                    Err(RoutingError::InvalidStateForOperation)
                }
            }
            _ => Ok(()),
        }
    }

    /// Handles a signature of a `SignedMessage`, and if we have enough to verify the signed
    /// message, handles it.
    fn handle_message_signature(
        &mut self,
        msg: SignedRoutingMessage,
        pub_id: PublicId,
    ) -> Result<(), RoutingError> {
        if !self.peer_mgr.get_peer(&pub_id).map_or(false, Peer::is_node) {
            debug!(
                "{} Received message signature from unknown peer {}",
                self, pub_id
            );
            return Err(RoutingError::UnknownConnection(pub_id));
        }

        if let Some(signed_msg) = self.sig_accumulator.add_proof(msg.clone()) {
            self.handle_signed_message(signed_msg)?;
        }
        Ok(())
    }

    // If the message is for us, verify it then, handle the enclosed routing message and swarm it
    // to the rest of our section when destination is targeting multiple; if not, forward it.
    fn handle_signed_message(
        &mut self,
        mut signed_msg: SignedRoutingMessage,
    ) -> Result<(), RoutingError> {
        let filter_res = self
            .routing_msg_filter
            .filter_incoming(signed_msg.routing_message());

        if filter_res == FilteringResult::KnownMessage {
            debug!(
                "{} Known message: {:?} - not handling further",
                self,
                signed_msg.routing_message()
            );
            return Ok(());
        }

        if self.in_authority(&signed_msg.routing_message().dst) {
            // The message is addressed to our section. Verify its integrity and trust
            if !signed_msg.check_trust(&self.chain) {
                log_or_panic!(
                    LogLevel::Error,
                    "{} Untrusted SignedRoutingMessage: {:?} --- {:?}",
                    self,
                    signed_msg,
                    self.chain.get_their_keys_info().collect::<Vec<_>>()
                );
                return Err(RoutingError::UntrustedMessage);
            }
            if let Err(err) = signed_msg.check_integrity() {
                log_or_panic!(
                    LogLevel::Error,
                    "{} Invalid integrity ({:?}) SignedRoutingMessage: {:?}",
                    self,
                    err,
                    signed_msg,
                );
                return Err(err);
            }

            self.update_our_knowledge(&signed_msg);

            if signed_msg.routing_message().dst.is_multiple() {
                // Broadcast to the rest of the section.
                if let Err(error) = self.send_signed_message(&mut signed_msg) {
                    debug!("{} Failed to send {:?}: {:?}", self, signed_msg, error);
                }
            }
            if filter_res == FilteringResult::NewMessage {
                // if addressed to us, then we just queue it and return
                self.msg_queue.push_back(signed_msg.into_routing_message());
            }
            return Ok(());
        }

        if let Err(error) = self.send_signed_message(&mut signed_msg) {
            debug!("{} Failed to send {:?}: {:?}", self, signed_msg, error);
        }

        Ok(())
    }

    fn dispatch_routing_message(
        &mut self,
        routing_msg: RoutingMessage,
        outbox: &mut dyn EventBox,
    ) -> Result<(), RoutingError> {
        use crate::messages::MessageContent::*;
        use crate::Authority::{Client, ManagedNode, PrefixSection, Section};

        match routing_msg.content {
            UserMessage { .. } => (),
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
                ConnectionRequest {
                    encrypted_conn_info,
                    pub_id,
                    ..
                },
                src @ Client { .. },
                dst @ ManagedNode(_),
            )
            | (
                ConnectionRequest {
                    encrypted_conn_info,
                    pub_id,
                    ..
                },
                src @ ManagedNode(_),
                dst @ ManagedNode(_),
            ) => self.handle_connection_request(&encrypted_conn_info, pub_id, src, dst, outbox),
            (NeighbourInfo(sec_info), Section(_), PrefixSection(_)) => {
                self.handle_neighbour_info(sec_info)
            }
            (Merge(digest), PrefixSection(_), PrefixSection(_)) => self.handle_merge(digest),
            (UserMessage(content), src, dst) => {
                outbox.send_event(Event::MessageReceived { content, src, dst });
                Ok(())
            }
            (
                AckMessage {
                    src_prefix,
                    ack_version,
                },
                Section(src),
                Section(dst),
            ) => self.handle_ack_message(src_prefix, ack_version, src, dst),
            (content, src, dst) => {
                debug!(
                    "{} Unhandled routing message {:?} from {:?} to {:?}",
                    self, content, src, dst
                );
                Err(RoutingError::BadAuthority)
            }
        }
    }

    fn handle_ack_message(
        &mut self,
        src_prefix: Prefix<XorName>,
        ack_version: u64,
        _src: XorName,
        _dst: XorName,
    ) -> Result<(), RoutingError> {
        // Prefix doesn't need to match, as we may get an ack for the section where we were before
        // splitting.
        self.vote_for_event(AccumulatingEvent::AckMessage(AckMessagePayload {
            src_prefix,
            ack_version,
        }));
        Ok(())
    }

    fn vote_send_section_info_ack(&mut self, ack_payload: SendAckMessagePayload) {
        let has_their_keys = self.chain.get_their_keys_info().any(|(_, info)| {
            *info.prefix() == ack_payload.ack_prefix && *info.version() == ack_payload.ack_version
        });

        if has_their_keys {
            self.vote_for_event(AccumulatingEvent::SendAckMessage(ack_payload));
        }
    }

    // Send NodeApproval to the current candidate which promotes them to Adult and allows them to
    // passively participate in parsec consensus (that is, they can receive gossip and poll
    // consensused blocks out of parsec, but they can't vote yet)
    fn handle_candidate_approval(
        &mut self,
        new_pub_id: PublicId,
        new_client_auth: Authority<XorName>,
        outbox: &mut dyn EventBox,
    ) {
        info!(
            "{} Our section with {:?} has approved candidate {}.",
            self,
            self.our_prefix(),
            new_pub_id
        );

        // Make sure we are connected to the candidate
        if self.peer_mgr.get_peer(&new_pub_id).is_none() {
            trace!(
                "{} - Not yet connected to {} - sending connection request.",
                self,
                new_pub_id
            );

            let src = Authority::ManagedNode(*self.name());
            let _ = self.send_connection_request(new_pub_id, src, new_client_auth, outbox);
        };

        self.peer_mgr.reset_candidate();

        let trimmed_info = GenesisPfxInfo {
            first_info: self.gen_pfx_info.first_info.clone(),
            first_state_serialized: self.gen_pfx_info.first_state_serialized.clone(),
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
    }

    fn init_parsec(&mut self) {
        self.set_pfx_successfully_polled(false);
        self.parsec_map
            .init(self.full_id.clone(), &self.gen_pfx_info, &self.log_ident())
    }

    // If this returns an error, the peer will be dropped.
    fn handle_bootstrap_request(&mut self, pub_id: PublicId) -> Result<(), RoutingError> {
        let conn_info = match self.peer_map().get_connection_info(&pub_id) {
            Some(conn_info) => conn_info.clone(),
            None => {
                log_or_panic!(
                    LogLevel::Error,
                    "Not connected to the sender of BootstrapRequest."
                );
                return Err(RoutingError::UnknownConnection(pub_id));
            }
        };

        let (peer_type, client_ip) = match conn_info {
            ConnectionInfo::Client { peer_addr } => ("client", Some(peer_addr.ip())),
            ConnectionInfo::Node { .. } => ("node", None),
        };

        trace!(
            "{} - Received BootstrapRequest from {:?} as {}.",
            self,
            pub_id,
            peer_type
        );

        if let Some(ip) = client_ip {
            // Check banned IPs.
            if self.banned_client_ips.contains_key(&ip) {
                warn!(
                    "{} - Client {:?} is trying to bootstrap on banned IP {}.",
                    self, pub_id, ip
                );
                self.ban_and_disconnect_peer(&pub_id);
                return Ok(());
            }

            // Check the client limit.
            if !self.peer_mgr.can_accept_client(&ip) {
                debug!(
                    "{} - Client {:?} rejected: We cannot accept more clients.",
                    self, pub_id
                );
                self.send_direct_message(
                    &pub_id,
                    DirectMessage::BootstrapResponse(Err(BootstrapResponseError::ClientLimit)),
                );
                self.disconnect_peer(&pub_id);
                return Ok(());
            }
        }

        // Check min section size.
        if (client_ip.is_some() || !self.is_first_node)
            && self.chain.len() < self.min_section_size() - 1
        {
            debug!(
                "{} - Peer {:?} rejected: Routing table has {} entries. {} required.",
                self,
                pub_id,
                self.chain.len(),
                self.min_section_size() - 1
            );
            self.send_direct_message(
                &pub_id,
                DirectMessage::BootstrapResponse(Err(BootstrapResponseError::TooFewPeers)),
            );
            self.disconnect_peer(&pub_id);
            return Ok(());
        }

        self.peer_mgr.handle_bootstrap_request(pub_id, &conn_info);
        let _ = self.dropped_clients.remove(&pub_id);

        self.send_direct_message(&pub_id, DirectMessage::BootstrapResponse(Ok(())));

        Ok(())
    }

    fn handle_connection_response(&mut self, pub_id: PublicId, outbox: &mut dyn EventBox) {
        self.peer_mgr_mut().set_connected(pub_id);
        self.process_connection(pub_id, outbox);
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_candidate_info(
        &mut self,
        old_pub_id: PublicId,
        new_pub_id: PublicId,
        signature_using_old: Signature,
        new_client_auth: Authority<XorName>,
        outbox: &mut dyn EventBox,
    ) {
        #[cfg(feature = "mock_base")]
        {
            if self.ignore_candidate_info_counter > 0 {
                self.ignore_candidate_info_counter -= 1;
                return;
            }
        }
        debug!(
            "{} - Handling CandidateInfo from {}->{}.",
            self, old_pub_id, new_pub_id
        );

        if !self.is_candidate_info_valid(&old_pub_id, &new_pub_id, &signature_using_old) {
            warn!(
                "{} - Signature check failed in CandidateInfo, so dropping peer {:?}.",
                self, new_pub_id
            );
            self.disconnect_peer(&new_pub_id);
            return;
        }

        // If this is a valid node in peer_mgr but the Candidate has sent us a CandidateInfo, it
        // might have not yet handled its NodeApproval message. Check and handle accordingly here
        if self.peer_mgr.is_connected(&new_pub_id) && self.is_peer_valid(&new_pub_id) {
            self.process_connection(new_pub_id, outbox);
            return;
        }

        let target_interval =
            if let Some(interval) = self.chain.matching_candidate_target_interval(&old_pub_id) {
                interval
            } else {
                debug!(
                    "{} - Ignore CandidateInfo: we are not waiting for candidate {}->{}.",
                    self, old_pub_id, new_pub_id
                );
                return;
            };

        if !target_interval.contains(new_pub_id.name()) {
            debug!(
                "{} - Ignore CandidateInfo: new ID {} is not within the required target range.",
                self, new_pub_id
            );
            return;
        }

        self.vote_for_event(AccumulatingEvent::Online(OnlinePayload {
            old_public_id: old_pub_id,
            new_public_id: new_pub_id,
            client_auth: new_client_auth,
        }));
    }

    fn is_candidate_info_valid(
        &self,
        old_pub_id: &PublicId,
        new_pub_id: &PublicId,
        signature_using_old: &Signature,
    ) -> bool {
        let both_ids = (*old_pub_id, *new_pub_id);
        let both_ids_serialised = match serialisation::serialise(&both_ids) {
            Ok(result) => result,
            Err(error) => {
                error!("{} - Failed to serialise public IDs: {:?}", self, error);
                return false;
            }
        };
        if !old_pub_id
            .signing_public_key()
            .verify_detached(signature_using_old, &both_ids_serialised)
        {
            debug!(
                "{} CandidateInfo from {}->{} has invalid old signature.",
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
            error!(
                "{} Invalid destination in a relocate request! Node name: {:?}, destination: {:?}",
                self,
                relocating_node_id.name(),
                dst_name
            );
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
        self.vote_for_event(AccumulatingEvent::ExpectCandidate(ExpectCandidatePayload {
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

        let min_len_prefix = self.chain.min_len_prefix();
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
    ) -> Option<XorTargetInterval> {
        if self.chain.has_candidate() {
            return None;
        }

        let target_interval = self.next_relocation_interval.take().unwrap_or_else(|| {
            utils::calculate_relocation_interval(&self.our_prefix(), &self.chain.our_section())
        });

        self.chain
            .accept_as_candidate(vote.old_public_id, target_interval.clone());
        self.peer_mgr.accept_as_candidate();

        Some(target_interval)
    }

    // Send RelocateResponse to the candidate using the target_interval.
    fn send_relocate_response(
        &mut self,
        vote: ExpectCandidatePayload,
        target_interval: XorTargetInterval,
    ) -> Result<(), RoutingError> {
        let own_section = {
            let our_info = self.chain.our_info();
            (*our_info.prefix(), our_info.members().clone())
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

    fn update_our_knowledge(&mut self, signed_msg: &SignedRoutingMessage) {
        if signed_msg.routing_message().src.is_client() {
            return;
        }

        let key_info = if let Some(key_info) = signed_msg.source_section_key_info() {
            key_info
        } else {
            return;
        };

        let new_key_info = self.chain.get_their_keys_info().any(|(_, info)| {
            *info.version() < *key_info.version() && info.prefix().is_compatible(key_info.prefix())
        });

        if new_key_info {
            self.vote_for_event(AccumulatingEvent::TheirKeyInfo(key_info.clone()));
        }
    }

    fn handle_neighbour_info(&mut self, sec_info: SectionInfo) -> Result<(), RoutingError> {
        if self.chain.is_new_neighbour(&sec_info) {
            self.vote_for_section_info(sec_info)?;
        }
        Ok(())
    }

    fn handle_merge(&mut self, digest: Digest256) -> Result<(), RoutingError> {
        self.vote_for_event(AccumulatingEvent::NeighbourMerge(digest));
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
            self.send_direct_message(&gossip_target, msg);
        }
    }

    fn vote_for_event(&mut self, event: AccumulatingEvent) {
        self.vote_for_network_event(event.into_network_event())
    }

    fn vote_for_section_info(&mut self, info: SectionInfo) -> Result<(), RoutingError> {
        let signature_payload = SectionInfoSigPayload::new(&info, &self.full_id)?;
        self.vote_for_network_event(info.into_network_event_with(Some(signature_payload)));
        Ok(())
    }

    fn vote_for_network_event(&mut self, event: NetworkEvent) {
        trace!("{} Vote for Event {:?}", self, event);
        self.parsec_map.vote_for(event, &self.log_ident())
    }

    // ----- Send Functions -----------------------------------------------------------------------
    fn send_user_message(
        &mut self,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        content: Vec<u8>,
    ) -> Result<(), RoutingError> {
        self.send_routing_message(src, dst, MessageContent::UserMessage(content))
    }

    // Send signed_msg on route. Hop is the name of the peer we received this from, or our name if
    // we are the first sender or the proxy for a client or joining node.
    fn send_signed_message(
        &mut self,
        signed_msg: &mut SignedRoutingMessage,
    ) -> Result<(), RoutingError> {
        let dst = signed_msg.routing_message().dst;

        if let Authority::Client { ref client_id, .. } = dst {
            if *self.name() == dst.name() {
                // This is a message for a client we are the proxy of. Relay it.
                return self.relay_to_client(signed_msg, client_id);
            } else if self.in_authority(&dst) {
                return Ok(()); // Message is for us as a client.
            }
        }

        let (target_pub_ids, dg_size) = self.get_targets(signed_msg.routing_message())?;

        debug!(
            "{}: Sending message {:?} via targets {:?}",
            self, signed_msg, target_pub_ids
        );

        let targets: Vec<_> = target_pub_ids
            .into_iter()
            .filter(|pub_id| {
                !self.filter_outgoing_routing_msg(signed_msg.routing_message(), pub_id)
            })
            .collect();

        let message = self.to_hop_message(signed_msg.clone())?;

        self.send_message_to_targets(&targets, dg_size, message);

        // we've seen this message - don't handle it again if someone else sends it to us
        let _ = self
            .routing_msg_filter
            .filter_incoming(signed_msg.routing_message());

        Ok(())
    }

    // Wraps the signed message in a `HopMessage` and sends it on.
    //
    // In the case that the `pub_id` is unknown, an ack is sent and the message dropped.
    fn relay_to_client(
        &mut self,
        signed_msg: &SignedRoutingMessage,
        pub_id: &PublicId,
    ) -> Result<(), RoutingError> {
        if self.peer_mgr.is_connected(pub_id) {
            if self.filter_outgoing_routing_msg(signed_msg.routing_message(), pub_id) {
                return Ok(());
            }

            let message = self.to_hop_message(signed_msg.clone())?;
            self.send_message(pub_id, message);
            Ok(())
        } else {
            debug!(
                "{} Client connection not found for message {:?}.",
                self, signed_msg
            );
            Err(RoutingError::ClientConnectionNotFound)
        }
    }

    /// Returns the set of peers that are responsible for collecting signatures to verify a message;
    /// this may contain us or only other nodes. If our signature is not required, this returns
    /// `None`.
    fn get_signature_targets(&self, src: &Authority<XorName>) -> Option<BTreeSet<XorName>> {
        use crate::Authority::*;

        let list: Vec<XorName> = match *src {
            ClientManager(_) | NaeManager(_) | NodeManager(_) | Section(_) => self
                .chain
                .our_section()
                .into_iter()
                .sorted_by(|lhs, rhs| src.name().cmp_distance(lhs, rhs)),
            // FIXME: This does not include recently accepted peers which would affect quorum
            // calculation. This even when going via RT would have only allowed route-0 to succeed
            // as by ack-failure, the new node would have been accepted to the RT.
            // Need a better network startup separation.
            PrefixSection(pfx) => {
                Iterator::flatten(self.chain.all_sections().map(|(_, si)| si.member_names()))
                    .filter(|name| pfx.matches(name))
                    .sorted_by(|lhs, rhs| src.name().cmp_distance(lhs, rhs))
            }
            ManagedNode(_) | Client { .. } => {
                let mut result = BTreeSet::new();
                let _ = result.insert(*self.name());
                return Some(result);
            }
        };

        if !list.contains(&self.name()) {
            None
        } else {
            let len = list.len();
            Some(list.into_iter().take(delivery_group_size(len)).collect())
        }
    }

    /// Returns a list of target IDs for a message sent via route.
    /// Name in exclude will be excluded from the result.
    fn get_targets(
        &self,
        routing_msg: &RoutingMessage,
    ) -> Result<(Vec<PublicId>, usize), RoutingError> {
        let force_via_proxy = match routing_msg.content {
            MessageContent::ConnectionRequest { pub_id, .. } => {
                routing_msg.src.is_client() && pub_id == *self.full_id.public_id()
            }
            _ => false,
        };

        if !force_via_proxy {
            // TODO: even if having chain reply based on connected_state,
            // we remove self in targets info and can do same by not
            // chaining us to conn_peer list here?
            let conn_peers = self
                .peer_map()
                .connected_ids()
                .map(|pub_id| pub_id.name())
                .chain(iter::once(self.name()))
                .collect_vec();
            let (targets, dg_size) = self.chain.targets(&routing_msg.dst, &conn_peers)?;
            Ok((
                targets
                    .into_iter()
                    .filter_map(|name| self.peer_mgr.get_pub_id(&name))
                    .cloned()
                    .collect(),
                dg_size,
            ))
        } else if let Authority::Client {
            ref proxy_node_name,
            ..
        } = routing_msg.src
        {
            if let Some(pub_id) = self.peer_mgr.get_pub_id(proxy_node_name) {
                if self.peer_mgr.is_connected(pub_id) {
                    Ok((vec![*pub_id], 1))
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
            .map(|(pub_id, _)| pub_id.name())
            .chain(iter::once(self.name()))
            .collect()
    }

    /// Handles dropped peer with the given ID. Returns true if we should keep running, false if
    /// we should terminate.
    fn dropped_peer(
        &mut self,
        pub_id: PublicId,
        outbox: &mut dyn EventBox,
        try_reconnect: bool,
    ) -> bool {
        if self.peer_mgr.remove_peer_no_joining_checks(&pub_id) {
            info!("{} Dropped {} from the routing table.", self, pub_id.name());
            outbox.send_event(Event::NodeLost(*pub_id.name()));

            if self.chain.our_info().members().contains(&pub_id) {
                self.vote_for_event(AccumulatingEvent::Offline(pub_id));
            }
        }

        if self
            .peer_mgr
            .connected_peers()
            .filter(|(_, p)| p.is_node())
            .count()
            == 0
        {
            debug!("{} Lost all routing connections.", self);
            // Except network startup, restart in other cases.
            if *self.chain.our_info().version() > 0 {
                outbox.send_event(Event::RestartRequired);
                return false;
            }
        }

        if try_reconnect && self.is_peer_valid(&pub_id) {
            debug!(
                "{} - Sending connection info to {:?} due to dropped peer.",
                self, pub_id
            );

            let our_name = *self.name();
            let _ = self.send_connection_request(
                pub_id,
                Authority::ManagedNode(our_name),
                Authority::ManagedNode(*pub_id.name()),
                outbox,
            );
        }

        true
    }

    fn remove_expired_peers(&mut self) {
        if self.peer_mgr.expire_candidate_once() {
            if let Some(expired_id) = self.chain.candidate_old_public_id().cloned() {
                self.vote_for_event(AccumulatingEvent::PurgeCandidate(expired_id));
            }
        }

        for pub_id in self.peer_mgr.remove_expired_peers() {
            debug!("{} Disconnecting from timed out peer {:?}", self, pub_id);
            // We've already removed from peer manager but this helps clean out connections to
            // expired peers.
            self.disconnect_peer(&pub_id);
            if self.chain.our_info().members().contains(&pub_id) {
                self.vote_for_event(AccumulatingEvent::Offline(pub_id));
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
        let ip = match self.peer_map().get_connection_info(pub_id) {
            Some(ConnectionInfo::Client { peer_addr }) => peer_addr.ip(),
            Some(ConnectionInfo::Node { .. }) => {
                warn!(
                    "{} - Can't ban IP address of {:?} - not a client.",
                    self, pub_id
                );
                return;
            }
            None => {
                warn!(
                    "{} - Can't ban IP address of {:?} - unknown IP address.",
                    self, pub_id
                );
                return;
            }
        };

        debug!("{} - Banned client {:?} on IP {}.", self, pub_id, ip);

        let _ = self.banned_client_ips.insert(ip, ());
        let _ = self.dropped_clients.insert(*pub_id, ());
        self.disconnect_peer(pub_id);
    }
}

impl Base for Elder {
    fn network_service(&self) -> &NetworkService {
        &self.network_service
    }

    fn network_service_mut(&mut self) -> &mut NetworkService {
        &mut self.network_service
    }

    fn full_id(&self) -> &FullId {
        &self.full_id
    }

    fn in_authority(&self, auth: &Authority<XorName>) -> bool {
        if let Authority::Client { ref client_id, .. } = *auth {
            client_id == self.full_id.public_id()
        } else {
            self.chain.in_authority(auth)
        }
    }

    fn close_group(&self, name: XorName, count: usize) -> Option<Vec<XorName>> {
        let conn_peers = self.connected_peers();
        self.chain.closest_names(&name, count, &conn_peers)
    }

    fn min_section_size(&self) -> usize {
        self.chain.min_sec_size()
    }

    fn peer_map(&self) -> &PeerMap {
        &self.peer_map
    }

    fn peer_map_mut(&mut self) -> &mut PeerMap {
        &mut self.peer_map
    }

    fn handle_send_message(
        &mut self,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        content: Vec<u8>,
    ) -> Result<(), InterfaceError> {
        match self.send_user_message(src, dst, content) {
            Err(RoutingError::Interface(err)) => Err(err),
            Err(_) | Ok(()) => Ok(()),
        }
    }

    fn handle_timeout(&mut self, token: u64, outbox: &mut dyn EventBox) -> Transition {
        if self.tick_timer_token == token {
            self.tick_timer_token = self.timer.schedule(TICK_TIMEOUT);
            self.remove_expired_peers();
            self.proxy_load_amount = 0;
            self.update_peer_states(outbox);
            outbox.send_event(Event::TimerTicked);
        } else if self.candidate_status_token == token {
            self.candidate_status_token = self.timer.schedule(CANDIDATE_STATUS_INTERVAL);
            self.chain.show_candidate_status(&self.log_ident());
        } else if self.gossip_timer_token == token {
            self.gossip_timer_token = self.timer.schedule(GOSSIP_TIMEOUT);

            // If we're the only node then invoke parsec_poll_all directly
            if self.chain.our_info().members().len() == 1 {
                let _ = self.parsec_poll(outbox);
            }

            self.send_parsec_gossip(None);
        }

        Transition::Stay
    }

    fn finish_handle_action(&mut self, outbox: &mut dyn EventBox) -> Transition {
        self.handle_routing_messages(outbox);
        Transition::Stay
    }

    fn handle_bootstrapped_to(&mut self, node_info: NodeInfo) -> Transition {
        // A mature node doesn't need a bootstrap connection
        self.network_service
            .service_mut()
            .disconnect_from(node_info.peer_addr);
        Transition::Stay
    }

    fn handle_peer_lost(&mut self, pub_id: PublicId, outbox: &mut dyn EventBox) -> Transition {
        debug!("{} - Lost peer {}", self, pub_id);

        if self.peer_mgr.get_peer(&pub_id).is_none() {
            return Transition::Stay;
        }

        if self.dropped_peer(pub_id, outbox, true) {
            Transition::Stay
        } else {
            Transition::Terminate
        }
    }

    fn finish_handle_network_event(&mut self, outbox: &mut dyn EventBox) -> Transition {
        self.handle_routing_messages(outbox);
        Transition::Stay
    }

    // Deconstruct a `DirectMessage` and handle or forward as appropriate.
    fn handle_direct_message(
        &mut self,
        msg: DirectMessage,
        pub_id: PublicId,
        outbox: &mut dyn EventBox,
    ) -> Result<Transition, RoutingError> {
        self.check_direct_message_sender(&msg, &pub_id)?;

        use crate::messages::DirectMessage::*;
        match msg {
            MessageSignature(msg) => self.handle_message_signature(msg, pub_id)?,
            BootstrapRequest => {
                if let Err(error) = self.handle_bootstrap_request(pub_id) {
                    warn!(
                        "{} Invalid BootstrapRequest received ({:?}), dropping {}.",
                        self, error, pub_id
                    );
                    self.ban_and_disconnect_peer(&pub_id);
                }
            }
            ConnectionResponse => self.handle_connection_response(pub_id, outbox),
            CandidateInfo {
                old_public_id,
                signature_using_old,
                new_client_auth,
            } => {
                self.handle_candidate_info(
                    old_public_id,
                    pub_id,
                    signature_using_old,
                    new_client_auth,
                    outbox,
                );
            }
            ParsecPoke(version) => self.handle_parsec_poke(version, pub_id),
            ParsecRequest(version, par_request) => {
                return self.handle_parsec_request(version, par_request, pub_id, outbox);
            }
            ParsecResponse(version, par_response) => {
                return self.handle_parsec_response(version, par_response, pub_id, outbox);
            }
            BootstrapResponse(_) => {
                debug!("{} Unhandled direct message: {:?}", self, msg);
            }
        }
        Ok(Transition::Stay)
    }

    fn handle_hop_message(
        &mut self,
        msg: HopMessage,
        _: &mut dyn EventBox,
    ) -> Result<Transition, RoutingError> {
        let HopMessage { content, .. } = msg;
        self.handle_signed_message(content)
            .map(|()| Transition::Stay)
    }
}

#[cfg(feature = "mock_base")]
impl Elder {
    pub fn chain(&self) -> &Chain {
        &self.chain
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

    pub fn set_next_relocation_interval(&mut self, interval: Option<XorTargetInterval>) {
        self.next_relocation_interval = interval;
    }

    pub fn has_unpolled_observations(&self) -> bool {
        self.parsec_map.has_unpolled_observations()
    }

    pub fn is_node_peer(&self, pub_id: &PublicId) -> bool {
        self.peer_mgr.get_peer(pub_id).map_or(false, Peer::is_node)
    }

    pub fn has_candidate(&self) -> bool {
        self.chain.has_candidate()
    }

    pub fn set_ignore_candidate_info_counter(&mut self, counter: u8) {
        self.ignore_candidate_info_counter = counter;
    }

    pub fn get_peer(&self, pub_id: &PublicId) -> Option<&Peer> {
        self.peer_mgr.get_peer(pub_id)
    }

    pub fn identify_connection(&mut self, pub_id: PublicId, peer_addr: SocketAddr) {
        self.peer_map.identify(pub_id, peer_addr)
    }

    pub fn send_msg_to_targets(
        &mut self,
        dst_targets: &[PublicId],
        dg_size: usize,
        message: Message,
    ) {
        self.send_message_to_targets(dst_targets, dg_size, message)
    }
}

impl Bootstrapped for Elder {
    // Constructs a signed message, finds the nodes responsible for accumulation, and either sends
    // these nodes a signature or tries to accumulate signatures for this message (on success, the
    // accumulator handles or forwards the message).
    fn send_routing_message_impl(
        &mut self,
        routing_msg: RoutingMessage,
        _expires_at: Option<Instant>,
    ) -> Result<(), RoutingError> {
        if !self.in_authority(&routing_msg.src) {
            log_or_panic!(
                LogLevel::Error,
                "{} Not part of the source authority. Not sending message {:?}.",
                self,
                routing_msg
            );
            return Ok(());
        }

        // If the source is single, we don't even need to send signatures, so let's cut this short
        if !routing_msg.src.is_multiple() {
            let mut msg = SignedRoutingMessage::single_source(routing_msg, &self.full_id)?;
            if self.in_authority(&msg.routing_message().dst) {
                self.handle_signed_message(msg)?;
            } else {
                self.send_signed_message(&mut msg)?;
            }
            return Ok(());
        }

        let proof = self.chain.prove(&routing_msg.dst);
        let pk_set = self.public_key_set();
        let signed_msg = SignedRoutingMessage::new(routing_msg, &self.full_id, pk_set, proof)?;

        for target in Iterator::flatten(
            self.get_signature_targets(&signed_msg.routing_message().src)
                .into_iter(),
        ) {
            if target == *self.name() {
                if let Some(mut msg) = self.sig_accumulator.add_proof(signed_msg.clone()) {
                    if self.in_authority(&msg.routing_message().dst) {
                        self.handle_signed_message(msg)?;
                    } else {
                        self.send_signed_message(&mut msg)?;
                    }
                }
            } else if let Some(&pub_id) = self.peer_mgr.get_pub_id(&target) {
                trace!(
                    "{} Sending a signature for message {:?} to {:?}",
                    self,
                    signed_msg.routing_message(),
                    target
                );
                self.send_direct_message(
                    &pub_id,
                    DirectMessage::MessageSignature(signed_msg.clone()),
                );
            } else {
                error!(
                    "{} Failed to resolve signature target {:?} for message {:?}",
                    self,
                    target,
                    signed_msg.routing_message()
                );
                return Err(RoutingError::RoutingTable(RoutingTableError::NoSuchPeer));
            }
        }
        Ok(())
    }

    fn routing_msg_filter(&mut self) -> &mut RoutingMessageFilter {
        &mut self.routing_msg_filter
    }

    fn timer(&mut self) -> &mut Timer {
        &mut self.timer
    }
}

impl Relocated for Elder {
    fn peer_mgr(&self) -> &PeerManager {
        &self.peer_mgr
    }

    fn peer_mgr_mut(&mut self) -> &mut PeerManager {
        &mut self.peer_mgr
    }

    fn process_connection(&mut self, pub_id: PublicId, outbox: &mut dyn EventBox) {
        if self.is_peer_valid(&pub_id) {
            self.add_node(&pub_id, outbox);
        }
    }

    fn is_peer_valid(&self, pub_id: &PublicId) -> bool {
        self.chain.is_peer_valid(pub_id)
    }

    fn add_node_success(&mut self, _: &PublicId) {
        self.print_rt_size();
    }

    fn add_node_failure(&mut self, pub_id: &PublicId) {
        if !self.is_peer_valid(pub_id) {
            self.disconnect_peer(pub_id);
        }
    }

    fn send_event(&mut self, event: Event, outbox: &mut dyn EventBox) {
        outbox.send_event(event);
    }
}

impl Approved for Elder {
    fn parsec_map_mut(&mut self) -> &mut ParsecMap {
        &mut self.parsec_map
    }

    fn chain_mut(&mut self) -> &mut Chain {
        &mut self.chain
    }

    fn set_pfx_successfully_polled(&mut self, val: bool) {
        self.pfx_is_successfully_polled = val;
    }

    fn is_pfx_successfully_polled(&self) -> bool {
        self.pfx_is_successfully_polled
    }

    fn handle_add_elder_event(
        &mut self,
        new_pub_id: PublicId,
        _new_client_auth: Authority<XorName>,
        outbox: &mut dyn EventBox,
    ) -> Result<(), RoutingError> {
        let to_vote_infos = self.chain.add_member(new_pub_id)?;

        // If we are connected to the new elder, mark it as a full node already. Otherwise the
        // connection request to them should have been already sent and we mark them as full node
        // when we receive the response.
        if self.peer_mgr.get_peer(&new_pub_id).is_some() {
            self.add_node(&new_pub_id, outbox);
        };

        for sec_info in to_vote_infos.into_iter() {
            self.vote_for_section_info(sec_info)?;
        }

        Ok(())
    }

    fn handle_remove_elder_event(
        &mut self,
        pub_id: PublicId,
        outbox: &mut dyn EventBox,
    ) -> Result<(), RoutingError> {
        let self_info = self.chain.remove_member(pub_id)?;
        self.vote_for_section_info(self_info)?;
        if let Some(&pub_id) = self.peer_mgr.get_pub_id(pub_id.name()) {
            let _ = self.dropped_peer(pub_id, outbox, false);
            self.disconnect_peer(&pub_id);
        }

        Ok(())
    }

    fn handle_online_event(
        &mut self,
        online_payload: OnlinePayload,
        outbox: &mut dyn EventBox,
    ) -> Result<(), RoutingError> {
        if self.chain.try_approve_candidate(&online_payload) {
            let OnlinePayload {
                new_public_id,
                client_auth,
                ..
            } = online_payload;

            self.handle_candidate_approval(new_public_id, client_auth, outbox);

            // TODO: vote for StartDkg and only when that gets consensused, vote for AddElder.

            self.vote_for_event(AccumulatingEvent::AddElder(
                online_payload.new_public_id,
                online_payload.client_auth,
            ));
        }
        Ok(())
    }

    fn handle_offline_event(&mut self, pub_id: PublicId) -> Result<(), RoutingError> {
        self.vote_for_event(AccumulatingEvent::RemoveElder(pub_id));
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
        if let Some(prefix) = self.need_to_forward_expect_candidate_to_prefix() {
            return self.forward_expect_candidate_to_prefix(vote, prefix);
        }

        if let Some(target_interval) = self.accept_candidate_with_interval(&vote) {
            return self.send_relocate_response(vote, target_interval);
        }

        // Nothing to do with this event.
        Ok(())
    }

    fn handle_purge_candidate_event(
        &mut self,
        old_public_id: PublicId,
    ) -> Result<(), RoutingError> {
        if self
            .chain
            .matching_candidate_target_interval(&old_public_id)
            .is_some()
        {
            self.chain.reset_candidate();
            self.peer_mgr.reset_candidate();
        }
        Ok(())
    }

    fn handle_section_info_event(
        &mut self,
        sec_info: SectionInfo,
        old_pfx: Prefix<XorName>,
        outbox: &mut dyn EventBox,
    ) -> Result<Transition, RoutingError> {
        if sec_info.prefix().is_extension_of(&old_pfx) {
            self.finalise_prefix_change()?;
            self.send_event(Event::SectionSplit(*sec_info.prefix()), outbox);
            // After a section split, the normal `send_neighbour_infos` action for the neighbouring
            // section will be triggered here (and only here).  Meanwhile own section's sending
            // action will be triggered at the other place later on (`self_sec_update` is true).
            if !sec_info.prefix().matches(self.name()) {
                self.send_neighbour_infos();
            }
        } else if old_pfx.is_extension_of(sec_info.prefix()) {
            self.finalise_prefix_change()?;
            self.send_event(Event::SectionMerged(*sec_info.prefix()), outbox);
        }

        let self_sec_update = sec_info.prefix().matches(self.name());

        self.update_peer_states(outbox);

        if self_sec_update {
            self.chain.reset_candidate_if_member_of(sec_info.members());

            // Vote to update our self messages proof
            self.vote_send_section_info_ack(SendAckMessagePayload {
                ack_prefix: *sec_info.prefix(),
                ack_version: *sec_info.version(),
            });

            self.send_neighbour_infos();
        }

        let _ = self.merge_if_necessary();

        Ok(Transition::Stay)
    }

    fn handle_their_key_info_event(
        &mut self,
        key_info: SectionKeyInfo,
    ) -> Result<(), RoutingError> {
        self.vote_send_section_info_ack(SendAckMessagePayload {
            ack_prefix: *key_info.prefix(),
            ack_version: *key_info.version(),
        });
        Ok(())
    }

    fn handle_send_ack_message_event(
        &mut self,
        ack_payload: SendAckMessagePayload,
    ) -> Result<(), RoutingError> {
        let src = Authority::Section(self.our_prefix().name());
        let dst = Authority::Section(ack_payload.ack_prefix.name());
        let content = MessageContent::AckMessage {
            src_prefix: *self.our_prefix(),
            ack_version: ack_payload.ack_version,
        };

        self.send_routing_message(src, dst, content)
    }
}

impl Display for Elder {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "Elder({}({:b}))", self.name(), self.our_prefix())
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
