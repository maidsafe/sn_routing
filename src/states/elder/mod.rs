// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#[cfg(all(test, feature = "mock"))]
mod tests;

use super::{
    adult::AdultDetails,
    common::{Approved, Base},
    Adult,
};
use crate::{
    chain::{
        delivery_group_size, AccumulatingEvent, AckMessagePayload, Chain, EldersChange, EldersInfo,
        EventSigPayload, GenesisPfxInfo, IntoAccumulatingEvent, NetworkEvent, NetworkParams,
        OnlinePayload, ParsecResetData, SectionKeyInfo, SendAckMessagePayload, MIN_AGE,
        MIN_AGE_COUNTER,
    },
    error::{InterfaceError, RoutingError},
    event::{Connected, Event},
    id::{FullId, P2pNode, PublicId},
    location::Location,
    messages::{
        BootstrapResponse, DirectMessage, HopMessageWithSerializedMessage, JoinRequest,
        MemberKnowledge, MessageContent, RoutingMessage, SecurityMetadata, SignedRoutingMessage,
    },
    network_service::NetworkService,
    outbox::EventBox,
    parsec::{self, generate_first_dkg_result, DkgResultWrapper, ParsecMap},
    pause::PausedState,
    peer_map::PeerMap,
    relocation::{RelocateDetails, SignedRelocateDetails},
    rng::{self, MainRng},
    routing_message_filter::RoutingMessageFilter,
    signature_accumulator::SignatureAccumulator,
    state_machine::{State, Transition},
    time::Duration,
    timer::Timer,
    xor_space::{Prefix, XorName, Xorable},
    ConnectionInfo,
};
use itertools::Itertools;
use log::LogLevel;
use serde::Serialize;
use std::{
    cmp,
    collections::{BTreeMap, BTreeSet, HashSet, VecDeque},
    fmt::{self, Display, Formatter},
    iter, mem,
    net::SocketAddr,
};

#[cfg(feature = "mock_base")]
use crate::{messages::Message, states::common::to_network_bytes};

/// Time after which an Elder should send a new Gossip.
const GOSSIP_TIMEOUT: Duration = Duration::from_secs(2);
/// Number of RelocatePrepare to consensus before actually relocating a node.
/// This helps avoid relocated node receiving message they need to process from previous section.
const INITIAL_RELOCATE_COOL_DOWN_COUNT_DOWN: i32 = 10;

struct CompleteParsecReset {
    /// The new genesis prefix info.
    pub gen_pfx_info: GenesisPfxInfo,
    /// The cached events that should be revoted. Not shared state: only the ones we voted for.
    /// Also contains our votes that never reached consensus.
    pub to_vote_again: BTreeSet<NetworkEvent>,
    /// The events to process. Not shared state: only the ones we voted for.
    /// Also contains our votes that never reached consensus.
    pub to_process: BTreeSet<NetworkEvent>,
    /// Event to send on completion.
    pub event_to_send: Option<Event>,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
enum PendingMessageKey {
    NeighbourInfo {
        version: u64,
        prefix: Prefix<XorName>,
    },
}

pub struct ElderDetails {
    pub chain: Chain,
    pub network_service: NetworkService,
    pub event_backlog: Vec<Event>,
    pub full_id: FullId,
    pub gen_pfx_info: GenesisPfxInfo,
    pub routing_msg_queue: VecDeque<SignedRoutingMessage>,
    pub routing_msg_backlog: Vec<SignedRoutingMessage>,
    pub direct_msg_backlog: Vec<(P2pNode, DirectMessage)>,
    pub sig_accumulator: SignatureAccumulator,
    pub parsec_map: ParsecMap,
    pub routing_msg_filter: RoutingMessageFilter,
    pub timer: Timer,
    pub rng: MainRng,
}

pub struct Elder {
    network_service: NetworkService,
    full_id: FullId,
    // The queue of routing messages addressed to us. These do not themselves need forwarding,
    // although they may wrap a message which needs forwarding.
    routing_msg_queue: VecDeque<SignedRoutingMessage>,
    routing_msg_backlog: Vec<SignedRoutingMessage>,
    direct_msg_backlog: Vec<(P2pNode, DirectMessage)>,
    routing_msg_filter: RoutingMessageFilter,
    sig_accumulator: SignatureAccumulator,
    timer: Timer,
    parsec_map: ParsecMap,
    gen_pfx_info: GenesisPfxInfo,
    gossip_timer_token: u64,
    chain: Chain,
    pfx_is_successfully_polled: bool,
    // DKG cache
    dkg_cache: BTreeMap<BTreeSet<PublicId>, EldersInfo>,
    // Messages we received but not accumulated yet, so may need to re-swarm.
    pending_voted_msgs: BTreeMap<PendingMessageKey, SignedRoutingMessage>,
    /// The knowledge of the non-elder members about our section.
    members_knowledge: BTreeMap<XorName, MemberKnowledge>,
    rng: MainRng,
}

impl Elder {
    pub fn first(
        mut network_service: NetworkService,
        full_id: FullId,
        network_cfg: NetworkParams,
        timer: Timer,
        mut rng: MainRng,
        outbox: &mut dyn EventBox,
    ) -> Result<Self, RoutingError> {
        let public_id = *full_id.public_id();
        let connection_info = network_service.our_connection_info()?;
        let p2p_node = P2pNode::new(public_id, connection_info);
        let mut first_ages = BTreeMap::new();
        let _ = first_ages.insert(public_id, MIN_AGE_COUNTER);
        let first_dkg_result = generate_first_dkg_result(&mut rng);
        let gen_pfx_info = GenesisPfxInfo {
            first_info: create_first_elders_info(p2p_node)?,
            first_bls_keys: first_dkg_result.public_key_set,
            first_state_serialized: Vec::new(),
            first_ages,
            latest_info: EldersInfo::default(),
            parsec_version: 0,
        };
        let parsec_map = ParsecMap::default().with_init(&mut rng, full_id.clone(), &gen_pfx_info);
        let chain = Chain::new(
            network_cfg,
            public_id,
            gen_pfx_info.clone(),
            first_dkg_result.secret_key_share,
        );

        let details = ElderDetails {
            chain,
            network_service,
            event_backlog: Vec::new(),
            full_id,
            gen_pfx_info,
            routing_msg_queue: Default::default(),
            routing_msg_backlog: Default::default(),
            direct_msg_backlog: Default::default(),
            sig_accumulator: Default::default(),
            parsec_map,
            routing_msg_filter: RoutingMessageFilter::new(),
            timer,
            rng,
        };

        let node = Self::new(details);

        debug!("{} - State changed to Node.", node);
        info!("{} - Started a new network as a seed node.", node);

        outbox.send_event(Event::Connected(Connected::First));

        Ok(node)
    }

    pub fn from_adult(
        mut details: ElderDetails,
        old_pfx: Prefix<XorName>,
        outbox: &mut dyn EventBox,
    ) -> Result<Self, RoutingError> {
        let event_backlog = mem::replace(&mut details.event_backlog, Vec::new());
        let mut elder = Self::new(details);
        elder.init(old_pfx, event_backlog, outbox)?;
        Ok(elder)
    }

    pub fn demote(
        self,
        gen_pfx_info: GenesisPfxInfo,
        outbox: &mut dyn EventBox,
    ) -> Result<State, RoutingError> {
        let details = AdultDetails {
            network_service: self.network_service,
            event_backlog: Vec::new(),
            direct_msg_backlog: self.direct_msg_backlog,
            routing_msg_backlog: self.routing_msg_backlog,
            full_id: self.full_id,
            gen_pfx_info,
            sig_accumulator: self.sig_accumulator,
            routing_msg_filter: self.routing_msg_filter,
            timer: self.timer,
            network_cfg: self.chain.network_cfg(),
            rng: self.rng,
        };
        Adult::new(details, self.parsec_map, outbox).map(State::Adult)
    }

    pub fn pause(self) -> Result<PausedState, RoutingError> {
        Ok(PausedState {
            chain: self.chain,
            full_id: self.full_id,
            gen_pfx_info: self.gen_pfx_info,
            routing_msg_filter: self.routing_msg_filter,
            routing_msg_queue: self.routing_msg_queue,
            routing_msg_backlog: self.routing_msg_backlog,
            direct_msg_backlog: self.direct_msg_backlog,
            network_service: self.network_service,
            network_rx: None,
            sig_accumulator: self.sig_accumulator,
            parsec_map: self.parsec_map,
        })
    }

    pub fn resume(state: PausedState, timer: Timer) -> Self {
        Self::new(ElderDetails {
            chain: state.chain,
            network_service: state.network_service,
            event_backlog: Vec::new(),
            full_id: state.full_id,
            gen_pfx_info: state.gen_pfx_info,
            routing_msg_queue: state.routing_msg_queue,
            routing_msg_backlog: state.routing_msg_backlog,
            direct_msg_backlog: state.direct_msg_backlog,
            sig_accumulator: state.sig_accumulator,
            parsec_map: state.parsec_map,
            routing_msg_filter: state.routing_msg_filter,
            timer,
            rng: rng::new(),
        })
    }

    pub fn our_elders(&self) -> impl Iterator<Item = &P2pNode> {
        self.chain.our_elders()
    }

    pub fn our_prefix(&self) -> &Prefix<XorName> {
        self.chain.our_prefix()
    }

    pub fn closest_known_elders_to(&self, name: &XorName) -> impl Iterator<Item = &P2pNode> {
        self.chain.closest_section_info(*name).1.member_nodes()
    }

    fn new(details: ElderDetails) -> Self {
        let timer = details.timer;
        let gossip_timer_token = timer.schedule(GOSSIP_TIMEOUT);

        Self {
            network_service: details.network_service,
            full_id: details.full_id.clone(),
            routing_msg_queue: details.routing_msg_queue,
            routing_msg_backlog: details.routing_msg_backlog,
            direct_msg_backlog: details.direct_msg_backlog,
            routing_msg_filter: details.routing_msg_filter,
            sig_accumulator: details.sig_accumulator,
            timer,
            parsec_map: details.parsec_map,
            gen_pfx_info: details.gen_pfx_info,
            gossip_timer_token,
            chain: details.chain,
            pfx_is_successfully_polled: false,
            dkg_cache: Default::default(),
            pending_voted_msgs: Default::default(),
            members_knowledge: Default::default(),
            rng: details.rng,
        }
    }

    fn print_rt_size(&self) {
        const TABLE_LVL: LogLevel = LogLevel::Info;
        if log_enabled!(TABLE_LVL) {
            let status_str = format!(
                "{} - Routing Table size: {:3}",
                self,
                self.chain.elders().count()
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

        for event in event_backlog {
            self.send_event(event, outbox);
        }

        // Handle the SectionInfo event which triggered us becoming established node.
        let change = EldersChange {
            neighbour_added: self.chain.neighbour_elder_nodes().cloned().collect(),
            neighbour_removed: Default::default(),
        };
        let _ = self.handle_section_info_event(old_pfx, change, outbox)?;

        Ok(())
    }

    fn handle_routing_messages(&mut self, outbox: &mut dyn EventBox) -> Transition {
        while let Some(msg) = self.routing_msg_queue.pop_front() {
            if self.in_location(&msg.routing_message().dst) {
                match self.dispatch_routing_message(msg, outbox) {
                    Ok(Transition::Stay) => (),
                    Ok(transition) => return transition,
                    Err(err) => debug!("{} Routing message dispatch failed: {:?}", self, err),
                }
            }
        }

        Transition::Stay
    }

    fn our_section_bls_keys(&self) -> &bls::PublicKeySet {
        self.chain.our_section_bls_keys()
    }

    fn handle_member_knowledge(&mut self, p2p_node: P2pNode, payload: MemberKnowledge) {
        trace!("{} - Received {:?} from {:?}", self, payload, p2p_node);

        if self.chain.is_peer_our_active_member(p2p_node.public_id()) {
            self.members_knowledge
                .entry(*p2p_node.name())
                .or_default()
                .update(payload);
        }

        self.send_parsec_gossip(Some((payload.parsec_version, p2p_node)))
    }

    // Connect to all elders from our section or neighbour sections that we are not yet connected
    // to and disconnect from peers that are no longer elders of neighbour sections.
    fn update_peer_connections(&mut self, change: &EldersChange) {
        if !self.chain.split_in_progress() {
            let our_needed_connections: HashSet<_> = self
                .chain
                .known_nodes()
                .map(|node| *node.peer_addr())
                .collect();

            for p2p_node in &change.neighbour_removed {
                // The peer might have been relocated from a neighbour to us - in that case do not
                // disconnect from them.
                if our_needed_connections.contains(p2p_node.peer_addr()) {
                    continue;
                }

                self.disconnect(p2p_node.peer_addr());
            }
        }

        for p2p_node in &change.neighbour_added {
            if !self.peer_map().has(p2p_node.peer_addr()) {
                self.establish_connection(p2p_node)
            }
        }

        let to_connect: Vec<_> = self
            .chain
            .our_joined_members()
            .filter(|p2p_node| {
                p2p_node.public_id() != self.id() && !self.peer_map().has(p2p_node.peer_addr())
            })
            .cloned()
            .collect();

        for p2p_node in to_connect {
            self.establish_connection(&p2p_node)
        }
    }

    fn establish_connection(&mut self, node: &P2pNode) {
        self.send_direct_message(node.connection_info(), DirectMessage::ConnectionResponse);
    }

    fn complete_parsec_reset_data(&mut self, reset_data: ParsecResetData) -> CompleteParsecReset {
        let ParsecResetData {
            gen_pfx_info,
            cached_events,
            completed_events,
        } = reset_data;

        let cached_events: BTreeSet<_> = cached_events
            .into_iter()
            .chain(
                self.parsec_map
                    .our_unpolled_observations()
                    .filter_map(|obs| match obs {
                        parsec::Observation::OpaquePayload(event) => Some(event),

                        parsec::Observation::Genesis { .. }
                        | parsec::Observation::Add { .. }
                        | parsec::Observation::Remove { .. }
                        | parsec::Observation::Accusation { .. }
                        | parsec::Observation::StartDkg(_)
                        | parsec::Observation::DkgResult { .. }
                        | parsec::Observation::DkgMessage(_) => None,
                    })
                    .cloned(),
            )
            .filter(|event| !completed_events.contains(&event.payload))
            .collect();

        let our_pfx = *self.our_prefix();

        let to_process = cached_events
            .iter()
            .filter(|event| match &event.payload {
                // Events to re-process
                AccumulatingEvent::Online(_) => true,
                // Events to re-insert
                AccumulatingEvent::Offline(_)
                | AccumulatingEvent::AckMessage(_)
                | AccumulatingEvent::StartDkg(_)
                | AccumulatingEvent::ParsecPrune
                | AccumulatingEvent::Relocate(_)
                | AccumulatingEvent::RelocatePrepare(_, _)
                | AccumulatingEvent::SectionInfo(_, _)
                | AccumulatingEvent::NeighbourInfo(_)
                | AccumulatingEvent::TheirKeyInfo(_)
                | AccumulatingEvent::SendAckMessage(_)
                | AccumulatingEvent::User(_) => false,
            })
            .cloned()
            .collect();

        let to_vote_again = cached_events
            .into_iter()
            .filter(|event| {
                match event.payload {
                    // Only re-vote if still relevant to our new prefix.
                    AccumulatingEvent::Online(ref payload) => {
                        our_pfx.matches(payload.p2p_node.name())
                    }
                    AccumulatingEvent::Offline(pub_id) => our_pfx.matches(pub_id.name()),
                    AccumulatingEvent::AckMessage(ref payload) => {
                        our_pfx.matches(&payload.dst_name)
                    }
                    AccumulatingEvent::Relocate(ref details)
                    | AccumulatingEvent::RelocatePrepare(ref details, _) => {
                        our_pfx.matches(details.pub_id.name())
                    }
                    // Drop: no longer relevant after prefix change.
                    AccumulatingEvent::StartDkg(_) | AccumulatingEvent::ParsecPrune => false,

                    // Keep: Additional signatures for neighbours for sec-msg-relay.
                    AccumulatingEvent::SectionInfo(ref elders_info, _)
                    | AccumulatingEvent::NeighbourInfo(ref elders_info) => {
                        our_pfx.is_neighbour(elders_info.prefix())
                    }

                    // Keep: Still relevant after prefix change.
                    AccumulatingEvent::TheirKeyInfo(_)
                    | AccumulatingEvent::SendAckMessage(_)
                    | AccumulatingEvent::User(_) => true,
                }
            })
            .collect();

        CompleteParsecReset {
            gen_pfx_info,
            to_vote_again,
            to_process,
            event_to_send: None,
        }
    }

    fn process_post_reset_events(
        &mut self,
        old_pfx: Prefix<XorName>,
        to_process: BTreeSet<NetworkEvent>,
    ) {
        to_process.iter().for_each(|event| match &event.payload {
            evt @ AccumulatingEvent::Offline(_)
            | evt @ AccumulatingEvent::AckMessage(_)
            | evt @ AccumulatingEvent::StartDkg(_)
            | evt @ AccumulatingEvent::ParsecPrune
            | evt @ AccumulatingEvent::Relocate(_)
            | evt @ AccumulatingEvent::RelocatePrepare(_, _)
            | evt @ AccumulatingEvent::SectionInfo(_, _)
            | evt @ AccumulatingEvent::NeighbourInfo(_)
            | evt @ AccumulatingEvent::TheirKeyInfo(_)
            | evt @ AccumulatingEvent::SendAckMessage(_)
            | evt @ AccumulatingEvent::User(_) => {
                log_or_panic!(LogLevel::Error, "unexpected event {:?}", evt);
            }
            AccumulatingEvent::Online(payload) => {
                self.resend_bootstrap_response_join(&payload.p2p_node);
            }
        });

        self.resend_pending_voted_messages(old_pfx);
    }

    // Resend the response with ours or our sibling's info in case of split.
    fn resend_bootstrap_response_join(&mut self, p2p_node: &P2pNode) {
        let our_info = self.chain.our_info();

        let response_section = Some(our_info)
            .filter(|info| info.prefix().matches(p2p_node.name()))
            .or_else(|| self.chain.get_neighbour_info(&our_info.prefix().sibling()))
            .filter(|info| info.prefix().matches(p2p_node.name()))
            .cloned();

        if let Some(response_section) = response_section {
            trace!(
                "{} - Resend Join to {} with version {}",
                self,
                p2p_node,
                response_section.version()
            );
            self.send_direct_message(
                p2p_node.connection_info(),
                DirectMessage::BootstrapResponse(BootstrapResponse::Join(response_section)),
            );
        }
    }

    // After parsec reset, resend any unaccumulated voted messages to everyone that needs
    // them but possibly did not receive them already.
    fn resend_pending_voted_messages(&mut self, _old_pfx: Prefix<XorName>) {
        for (_, msg) in mem::replace(&mut self.pending_voted_msgs, Default::default()) {
            let msg = match HopMessageWithSerializedMessage::new(msg) {
                Ok(msg) => msg,
                Err(err) => {
                    error!("Failed to make message {:?}", err);
                    continue;
                }
            };
            let routing_message = msg.signed_routing_message().routing_message();
            match self.send_signed_message(&msg) {
                Ok(()) => trace!("{} - Resend {:?}", self, routing_message),
                Err(error) => debug!(
                    "{} - Failed to resend {:?}: {:?}",
                    self, routing_message, error
                ),
            }
        }
    }

    fn reset_parsec_with_data(
        &mut self,
        gen_pfx_info: GenesisPfxInfo,
        to_vote_again: BTreeSet<NetworkEvent>,
    ) -> Result<(), RoutingError> {
        self.gen_pfx_info = gen_pfx_info;
        self.init_parsec(); // We don't reset the chain on prefix change.

        to_vote_again.iter().for_each(|event| {
            self.vote_for_network_event(event.clone());
        });

        Ok(())
    }

    fn prepare_reset_parsec(&mut self) -> Result<CompleteParsecReset, RoutingError> {
        let reset_data = self
            .chain
            .prepare_parsec_reset(self.parsec_map.last_version().saturating_add(1))?;
        let complete_data = self.complete_parsec_reset_data(reset_data);
        Ok(complete_data)
    }

    fn prepare_finalise_split(&mut self) -> Result<CompleteParsecReset, RoutingError> {
        let reset_data = self
            .chain
            .finalise_prefix_change(self.parsec_map.last_version().saturating_add(1))?;
        let mut complete_data = self.complete_parsec_reset_data(reset_data);
        complete_data.event_to_send = Some(Event::SectionSplit(*self.our_prefix()));
        Ok(complete_data)
    }

    fn send_neighbour_infos(&mut self) {
        self.chain.other_prefixes().iter().for_each(|pfx| {
            let src = Location::Section(self.our_prefix().name());
            let dst = Location::PrefixSection(*pfx);
            let content = MessageContent::NeighbourInfo(self.chain.our_info().clone());

            if let Err(err) = self.send_routing_message(RoutingMessage { src, dst, content }) {
                debug!("{} Failed to send NeighbourInfo: {:?}.", self, err);
            }
        });
    }

    // Send `GenesisUpdate` message to all non-elders.
    fn send_genesis_updates(&mut self) {
        for (recipient, msg) in self.create_genesis_updates() {
            trace!(
                "{} - Send GenesisUpdate({:?}) to {}",
                self,
                self.gen_pfx_info,
                recipient
            );

            self.send_direct_message(
                recipient.connection_info(),
                DirectMessage::MessageSignature(Box::new(msg)),
            );
        }
    }

    fn create_genesis_updates(&self) -> Vec<(P2pNode, SignedRoutingMessage)> {
        let src = Location::PrefixSection(*self.our_prefix());
        self.chain
            .adults_and_infants_p2p_nodes()
            .cloned()
            .filter_map(|recipient| {
                let msg = RoutingMessage {
                    src,
                    dst: Location::Node(*recipient.name()),
                    content: MessageContent::GenesisUpdate(self.gen_pfx_info.clone()),
                };

                let version = self
                    .members_knowledge
                    .get(recipient.name())
                    .map(|knowledge| knowledge.elders_version)
                    .unwrap_or(0);

                match self.to_signed_routing_message(msg, Some(version)) {
                    Ok(msg) => Some((recipient, msg)),
                    Err(error) => {
                        error!("{} - Failed to create signed message: {:?}", self, error);
                        None
                    }
                }
            })
            .collect()
    }

    /// Handles a signature of a `SignedMessage`, and if we have enough to verify the signed
    /// message, handles it.
    fn handle_message_signature(
        &mut self,
        msg: SignedRoutingMessage,
        pub_id: PublicId,
    ) -> Result<(), RoutingError> {
        if !self.chain.is_peer_elder(&pub_id) {
            debug!(
                "{} - Received message signature from invalid peer {}, {:?}",
                self, pub_id, msg
            );
            return Err(RoutingError::InvalidSource);
        }

        if let Some(signed_msg) = self.sig_accumulator.add_proof(msg) {
            let signed_msg = HopMessageWithSerializedMessage::new(signed_msg)?;
            self.handle_signed_message(signed_msg)?;
        }
        Ok(())
    }

    // If the message is for us, verify it then, handle the enclosed routing message and swarm it
    // to the rest of our section when destination is targeting multiple; if not, forward it.
    fn handle_signed_message(
        &mut self,
        msg: HopMessageWithSerializedMessage,
    ) -> Result<(), RoutingError> {
        let signed_msg = msg.signed_routing_message();
        if !self
            .routing_msg_filter
            .filter_incoming(signed_msg.routing_message())
            .is_new()
        {
            trace!(
                "{} Known message: {:?} - not handling further",
                self,
                signed_msg.routing_message()
            );
            return Ok(());
        }

        self.handle_filtered_signed_message(msg)
    }

    fn handle_filtered_signed_message(
        &mut self,
        msg: HopMessageWithSerializedMessage,
    ) -> Result<(), RoutingError> {
        let signed_msg = msg.signed_routing_message();
        trace!(
            "{} - Handle signed message: {:?}",
            self,
            signed_msg.routing_message()
        );

        if self.in_location(&signed_msg.routing_message().dst) {
            self.check_signed_message_trust(signed_msg)?;
            self.check_signed_message_integrity(signed_msg)?;
            self.update_our_knowledge(signed_msg);

            if signed_msg.routing_message().dst.is_multiple() {
                // Broadcast to the rest of the section.
                if let Err(error) = self.send_signed_message(&msg) {
                    debug!("{} Failed to send {:?}: {:?}", self, signed_msg, error);
                }
            }
            // if addressed to us, then we just queue it and return
            self.routing_msg_queue
                .push_back(msg.into_signed_routing_message());
        } else if let Err(error) = self.send_signed_message(&msg) {
            debug!("{} Failed to send {:?}: {:?}", self, signed_msg, error);
        }

        Ok(())
    }

    fn handle_backloged_filtered_signed_message(
        &mut self,
        signed_msg: SignedRoutingMessage,
    ) -> Result<(), RoutingError> {
        trace!(
            "{} - Handle backlogged signed message: {:?}",
            self,
            signed_msg.routing_message()
        );

        if self.in_location(&signed_msg.routing_message().dst)
            && signed_msg.check_trust(&self.chain)
        {
            // If message still for us and we still trust it, then it must not be stale.
            self.check_signed_message_integrity(&signed_msg)?;
            self.update_our_knowledge(&signed_msg);
            self.routing_msg_queue.push_back(signed_msg);
        }

        Ok(())
    }

    fn dispatch_routing_message(
        &mut self,
        signed_msg: SignedRoutingMessage,
        outbox: &mut dyn EventBox,
    ) -> Result<Transition, RoutingError> {
        use crate::messages::MessageContent::*;

        let (msg, security_metadata) = signed_msg.into_parts();

        match msg.content {
            UserMessage { .. } => (),
            _ => trace!("{} Got routing message {:?}.", self, msg),
        }

        match (msg.content, msg.src, msg.dst) {
            (
                NeighbourInfo(elders_info),
                src @ Location::Section(_),
                dst @ Location::PrefixSection(_),
            ) => {
                self.handle_neighbour_info(elders_info, src, dst, security_metadata)?;
                Ok(Transition::Stay)
            }
            (UserMessage(content), src, dst) => {
                outbox.send_event(Event::MessageReceived { content, src, dst });
                Ok(Transition::Stay)
            }
            (
                AckMessage {
                    src_prefix,
                    ack_version,
                },
                Location::Section(src),
                Location::Section(dst),
            ) => {
                self.handle_ack_message(src_prefix, ack_version, src, dst)?;
                Ok(Transition::Stay)
            }
            (content @ GenesisUpdate(_), src, dst) => {
                debug!(
                    "{} Unhandled routing message {:?} from {:?} to {:?}, adding to backlog",
                    self, content, src, dst
                );
                self.routing_msg_backlog
                    .push(SignedRoutingMessage::from_parts(
                        RoutingMessage { content, src, dst },
                        security_metadata,
                    ));
                Ok(Transition::Stay)
            }
            (content, src, dst) => {
                debug!(
                    "{} Unhandled routing message {:?} from {:?} to {:?}, ignoring",
                    self, content, src, dst
                );
                Err(RoutingError::BadLocation)
            }
        }
    }

    fn handle_ack_message(
        &mut self,
        src_prefix: Prefix<XorName>,
        ack_version: u64,
        _src: XorName,
        dst: XorName,
    ) -> Result<(), RoutingError> {
        // Prefix doesn't need to match, as we may get an ack for the section where we were before
        // splitting.
        self.vote_for_event(AccumulatingEvent::AckMessage(AckMessagePayload {
            dst_name: dst,
            src_prefix,
            ack_version,
        }));
        Ok(())
    }

    fn vote_send_section_info_ack(&mut self, ack_payload: SendAckMessagePayload) {
        let has_their_keys = self.chain.get_their_keys_info().any(|(_, info)| {
            *info.prefix() == ack_payload.ack_prefix && info.version() == ack_payload.ack_version
        });

        if has_their_keys {
            self.vote_for_event(AccumulatingEvent::SendAckMessage(ack_payload));
        }
    }

    // Send NodeApproval to the current candidate which promotes them to Adult and allows them to
    // passively participate in parsec consensus (that is, they can receive gossip and poll
    // consensused blocks out of parsec, but they can't vote yet)
    fn handle_candidate_approval(&mut self, p2p_node: P2pNode, _outbox: &mut dyn EventBox) {
        info!(
            "{} Our section with {:?} has approved candidate {}.",
            self,
            self.our_prefix(),
            p2p_node
        );

        let pub_id = *p2p_node.public_id();
        let dst = Location::Node(*pub_id.name());

        // Make sure we are connected to the candidate
        if !self.peer_map().has(p2p_node.peer_addr()) {
            trace!(
                "{} - Not yet connected to {} - use p2p_node.",
                self,
                p2p_node
            );
            self.send_direct_message(
                p2p_node.connection_info(),
                DirectMessage::ConnectionResponse,
            );
        };

        let trimmed_info = GenesisPfxInfo {
            first_info: self.gen_pfx_info.first_info.clone(),
            first_bls_keys: self.gen_pfx_info.first_bls_keys.clone(),
            first_state_serialized: Default::default(),
            first_ages: self.gen_pfx_info.first_ages.clone(),
            latest_info: self.chain.our_info().clone(),
            parsec_version: self.gen_pfx_info.parsec_version,
        };

        let src = Location::PrefixSection(*trimmed_info.first_info.prefix());
        let content = MessageContent::NodeApproval(trimmed_info);
        if let Err(error) = self.send_routing_message(RoutingMessage { src, dst, content }) {
            debug!(
                "{} Failed sending NodeApproval to {}: {:?}",
                self, pub_id, error
            );
        }
    }

    fn init_parsec(&mut self) {
        let log_ident = self.log_ident();

        self.set_pfx_successfully_polled(false);
        self.parsec_map.init(
            &mut self.rng,
            self.full_id.clone(),
            &self.gen_pfx_info,
            &log_ident,
        )
    }

    // If this returns an error, the peer will be dropped.
    fn handle_bootstrap_request(&mut self, p2p_node: P2pNode, name: XorName) {
        debug!(
            "{} - Received BootstrapRequest to section at {} from {:?}.",
            self, name, p2p_node
        );

        self.respond_to_bootstrap_request(&p2p_node, &name);
    }

    fn respond_to_bootstrap_request(&mut self, p2p_node: &P2pNode, name: &XorName) {
        let response = if self.our_prefix().matches(name) {
            let our_info = self.chain.our_info().clone();
            debug!(
                "{} - Sending BootstrapResponse::Join to {:?} ({:?})",
                self, p2p_node, our_info
            );
            BootstrapResponse::Join(our_info)
        } else {
            let conn_infos: Vec<_> = self
                .closest_known_elders_to(name)
                .map(|p2p_node| p2p_node.connection_info().clone())
                .collect();
            debug!(
                "{} - Sending BootstrapResponse::Rebootstrap to {}",
                self, p2p_node
            );
            BootstrapResponse::Rebootstrap(conn_infos)
        };
        self.send_direct_message(
            p2p_node.connection_info(),
            DirectMessage::BootstrapResponse(response),
        );
    }

    fn handle_connection_response(&mut self, pub_id: PublicId, _: &mut dyn EventBox) {
        debug!("{} - Received connection response from {}", self, pub_id);
    }

    fn handle_join_request(&mut self, p2p_node: P2pNode, join_request: JoinRequest) {
        debug!(
            "{} - Received JoinRequest from {} for v{}",
            self, p2p_node, join_request.elders_version
        );

        if join_request.elders_version < self.chain.our_info().version() {
            self.resend_bootstrap_response_join(&p2p_node);
        }

        let pub_id = *p2p_node.public_id();
        if !self.our_prefix().matches(pub_id.name()) {
            debug!(
                "{} - Ignoring JoinRequest from {} - name doesn't match our prefix {:?}.",
                self,
                pub_id,
                self.our_prefix()
            );
            return;
        }

        if self.chain.is_peer_our_member(&pub_id) {
            debug!(
                "{} - Ignoring JoinRequest from {} - already member of our section.",
                self, pub_id
            );
            return;
        }

        if self.chain.is_in_online_backlog(&pub_id) {
            debug!(
                "{} - Ignoring JoinRequest from {} - already in backlog.",
                self, pub_id
            );
            return;
        }

        // This joining node is being relocated to us.
        let age = if let Some(payload) = join_request.relocate_payload {
            if !payload.verify_identity(&pub_id) {
                debug!(
                    "{} - Ignoring relocation JoinRequest from {} - invalid signature.",
                    self, pub_id
                );
                return;
            }

            let details = payload.details;

            if !self.our_prefix().matches(&details.content().destination) {
                debug!(
                    "{} - Ignoring relocation JoinRequest from {} - destination {} doesn't match \
                     our prefix {:?}.",
                    self,
                    pub_id,
                    details.content().destination,
                    self.our_prefix()
                );
                return;
            }

            if !self.check_signed_relocation_details(&details) {
                return;
            }

            details.content().age
        } else {
            MIN_AGE
        };

        self.send_direct_message(
            p2p_node.connection_info(),
            DirectMessage::ConnectionResponse,
        );
        self.vote_for_event(AccumulatingEvent::Online(OnlinePayload { p2p_node, age }))
    }

    fn update_our_knowledge(&mut self, signed_msg: &SignedRoutingMessage) {
        let key_info = if let Some(key_info) = signed_msg.source_section_key_info() {
            key_info
        } else {
            return;
        };

        let new_key_info = self
            .chain
            .get_their_keys_info()
            .find(|(prefix, _)| prefix.is_compatible(key_info.prefix()))
            .map_or(false, |(_, info)| info.version() < key_info.version());

        if new_key_info {
            self.vote_for_event(AccumulatingEvent::TheirKeyInfo(key_info.clone()));
        }
    }

    fn handle_neighbour_info(
        &mut self,
        elders_info: EldersInfo,
        src: Location<XorName>,
        dst: Location<XorName>,
        security_metadata: SecurityMetadata,
    ) -> Result<(), RoutingError> {
        if self.chain.is_new_neighbour(&elders_info) {
            let _ = self
                .pending_voted_msgs
                .entry(PendingMessageKey::NeighbourInfo {
                    version: elders_info.version(),
                    prefix: *elders_info.prefix(),
                })
                .or_insert_with(|| {
                    SignedRoutingMessage::from_parts(
                        RoutingMessage {
                            src,
                            dst,
                            content: MessageContent::NeighbourInfo(elders_info.clone()),
                        },
                        security_metadata,
                    )
                });

            self.vote_for_event(AccumulatingEvent::NeighbourInfo(elders_info));
        } else {
            trace!(
                "{} Ignore not new neighbour neighbour_info: {:?}",
                self,
                elders_info
            );
        }
        Ok(())
    }

    fn maintain_parsec(&mut self) {
        if self.parsec_map.needs_pruning() {
            self.vote_for_event(AccumulatingEvent::ParsecPrune);
            self.parsec_map_mut().set_pruning_voted_for();
        }
    }

    fn vote_for_event(&mut self, event: AccumulatingEvent) {
        self.vote_for_network_event(event.into_network_event())
    }

    fn vote_for_relocate(&mut self, details: RelocateDetails) -> Result<(), RoutingError> {
        self.vote_for_signed_event(details)
    }

    fn vote_for_relocate_prepare(&mut self, details: RelocateDetails, count_down: i32) {
        self.vote_for_network_event(
            AccumulatingEvent::RelocatePrepare(details, count_down).into_network_event(),
        );
    }

    fn vote_for_section_info(
        &mut self,
        elders_info: EldersInfo,
        section_key: bls::PublicKey,
    ) -> Result<(), RoutingError> {
        let key_info = SectionKeyInfo::from_elders_info(&elders_info, section_key);
        let signature_payload = EventSigPayload::new_for_section_key_info(
            &self.chain.our_section_bls_secret_key_share()?.key,
            &key_info,
        )?;
        let acc_event = AccumulatingEvent::SectionInfo(elders_info, key_info);

        let event = acc_event.into_network_event_with(Some(signature_payload));
        self.vote_for_network_event(event);
        Ok(())
    }

    fn vote_for_signed_event<T: IntoAccumulatingEvent + Serialize>(
        &mut self,
        payload: T,
    ) -> Result<(), RoutingError> {
        let signature_payload = EventSigPayload::new(
            &self.chain.our_section_bls_secret_key_share()?.key,
            &payload,
        )?;

        let event = payload
            .into_accumulating_event()
            .into_network_event_with(Some(signature_payload));
        self.vote_for_network_event(event);
        Ok(())
    }

    fn vote_for_network_event(&mut self, event: NetworkEvent) {
        trace!("{} Vote for Event {:?}", self, event);
        self.parsec_map.vote_for(event, &self.log_ident())
    }

    // ----- Send Functions -----------------------------------------------------------------------
    fn send_user_message(
        &mut self,
        src: Location<XorName>,
        dst: Location<XorName>,
        content: Vec<u8>,
    ) -> Result<(), RoutingError> {
        self.send_routing_message(RoutingMessage {
            src,
            dst,
            content: MessageContent::UserMessage(content),
        })
    }

    // Constructs a signed message, finds the nodes responsible for accumulation, and either sends
    // these nodes a signature or tries to accumulate signatures for this message (on success, the
    // accumulator handles or forwards the message).
    fn send_routing_message(&mut self, routing_msg: RoutingMessage) -> Result<(), RoutingError> {
        if !self.in_location(&routing_msg.src) {
            log_or_panic!(
                LogLevel::Error,
                "{} Not part of the source location. Not sending message {:?}.",
                self,
                routing_msg
            );
            return Ok(());
        }

        // If the source is single, we don't even need to send signatures, so let's cut this short
        if !routing_msg.src.is_multiple() {
            let msg = SignedRoutingMessage::single_source(routing_msg, &self.full_id)?;
            let msg = HopMessageWithSerializedMessage::new(msg)?;
            if self.in_location(&msg.signed_routing_message().routing_message().dst) {
                self.handle_signed_message(msg)?;
            } else {
                self.send_signed_message(&msg)?;
            }
            return Ok(());
        }

        let signed_msg = self.to_signed_routing_message(routing_msg, None)?;

        for target in Iterator::flatten(
            self.get_signature_targets(&signed_msg.routing_message().src)
                .into_iter(),
        ) {
            if target == *self.name() {
                if let Some(msg) = self.sig_accumulator.add_proof(signed_msg.clone()) {
                    let msg = HopMessageWithSerializedMessage::new(msg)?;
                    if self.in_location(&msg.signed_routing_message().routing_message().dst) {
                        self.handle_signed_message(msg)?;
                    } else {
                        self.send_signed_message(&msg)?;
                    }
                }
            } else if let Some(p2p_node) = self.chain.get_p2p_node(&target) {
                trace!(
                    "{} Sending a signature for message {:?} to {:?}",
                    self,
                    signed_msg.routing_message(),
                    target
                );
                let conn_info = p2p_node.connection_info().clone();
                self.send_direct_message(
                    &conn_info,
                    DirectMessage::MessageSignature(Box::new(signed_msg.clone())),
                );
            } else {
                error!(
                    "{} Failed to resolve signature target {:?} for message {:?}",
                    self,
                    target,
                    signed_msg.routing_message()
                );
            }
        }

        Ok(())
    }

    // Send signed_msg on route. Hop is the name of the peer we received this from, or our name if
    // we are the first sender or the proxy for a client or joining node.
    fn send_signed_message(
        &mut self,
        msg: &HopMessageWithSerializedMessage,
    ) -> Result<(), RoutingError> {
        let signed_msg = msg.signed_routing_message();
        let dst = msg.message_dst();

        // If the message is to a single node and we have the connection info for this node, don't
        // go through the routing table
        let single_target = if let Location::Node(node_name) = dst {
            self.chain.get_p2p_node(node_name)
        } else {
            None
        };

        let (target_p2p_nodes, dg_size) = if let Some(target) = single_target {
            (vec![target.clone()], 1)
        } else {
            self.get_targets(dst)?
        };

        trace!(
            "{}: Sending message {:?} via targets {:?}",
            self,
            signed_msg,
            target_p2p_nodes
        );

        let targets: Vec<_> = target_p2p_nodes
            .into_iter()
            .filter(|p2p_node| {
                self.routing_msg_filter
                    .filter_outgoing(signed_msg.routing_message(), p2p_node.public_id())
                    .is_new()
            })
            .map(|node| node.connection_info().clone())
            .collect();

        self.send_message_to_targets(&targets, dg_size, msg.serialized_message().clone());

        // we've seen this message - don't handle it again if someone else sends it to us
        let _ = self
            .routing_msg_filter
            .filter_incoming(signed_msg.routing_message());

        Ok(())
    }

    /// Vote for a user-defined event.
    pub fn vote_for_user_event(&mut self, event: Vec<u8>) {
        self.vote_for_event(AccumulatingEvent::User(event));
    }

    /// Returns the set of peers that are responsible for collecting signatures to verify a message;
    /// this may contain us or only other nodes. If our signature is not required, this returns
    /// `None`.
    fn get_signature_targets(&self, src: &Location<XorName>) -> Option<BTreeSet<XorName>> {
        let list: Vec<XorName> = match *src {
            Location::Section(_) => self
                .chain
                .our_elders()
                .map(|p2p_node| p2p_node.name())
                .copied()
                .sorted_by(|lhs, rhs| src.name().cmp_distance(lhs, rhs)),
            Location::PrefixSection(pfx) => self
                .chain
                .all_sections()
                .flat_map(|(_, si)| si.member_names())
                .filter(|name| pfx.matches(name))
                .copied()
                .sorted_by(|lhs, rhs| src.name().cmp_distance(lhs, rhs)),
            Location::Node(_) => {
                let mut result = BTreeSet::new();
                let _ = result.insert(*self.name());
                return Some(result);
            }
        };

        if !list.contains(self.name()) {
            None
        } else {
            let len = list.len();
            Some(list.into_iter().take(delivery_group_size(len)).collect())
        }
    }

    /// Returns a list of target IDs for a message sent via route.
    /// Name in exclude will be excluded from the result.
    fn get_targets(&self, dst: &Location<XorName>) -> Result<(Vec<P2pNode>, usize), RoutingError> {
        let (targets, dg_size) = self.chain.targets(dst)?;
        Ok((targets.into_iter().cloned().collect(), dg_size))
    }

    // Check whether we are connected to any elders. If this node loses all elder connections,
    // it must be restarted.
    fn check_elder_connections(&self, outbox: &mut dyn EventBox) -> bool {
        let our_name = self.name();
        if self
            .our_elders()
            .any(|node| node.name() != our_name && self.peer_map().has(node.peer_addr()))
        {
            true
        } else {
            debug!("{} - Lost all elder connections.", self);

            // Except network startup, restart in other cases.
            if self.chain.our_info().version() > 0 {
                outbox.send_event(Event::RestartRequired);
                false
            } else {
                true
            }
        }
    }

    // Signs and proves the given `RoutingMessage` and wraps it in `SignedRoutingMessage`.
    fn to_signed_routing_message(
        &self,
        msg: RoutingMessage,
        node_knowledge_override: Option<u64>,
    ) -> Result<SignedRoutingMessage, RoutingError> {
        let proof = self.chain.prove(&msg.dst, node_knowledge_override);
        let pk_set = self.our_section_bls_keys().clone();
        let secret_key = self.chain.our_section_bls_secret_key_share()?;

        SignedRoutingMessage::new(msg, secret_key, pk_set, proof)
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

    fn in_location(&self, auth: &Location<XorName>) -> bool {
        self.chain.in_location(auth)
    }

    fn close_group(&self, name: XorName, count: usize) -> Option<Vec<XorName>> {
        let mut conn_peers: Vec<_> = self.chain.elders().map(P2pNode::name).collect();
        conn_peers.sort_unstable();
        conn_peers.dedup();
        self.chain.closest_names(&name, count, &conn_peers)
    }

    fn peer_map(&self) -> &PeerMap {
        &self.network_service().peer_map
    }

    fn peer_map_mut(&mut self) -> &mut PeerMap {
        &mut self.network_service_mut().peer_map
    }

    fn timer(&mut self) -> &mut Timer {
        &mut self.timer
    }

    fn rng(&mut self) -> &mut MainRng {
        &mut self.rng
    }

    fn finish_handle_transition(&mut self, outbox: &mut dyn EventBox) -> Transition {
        debug!("{} - State change to Elder finished.", self);

        let mut transition = Transition::Stay;
        for (pub_id, msg) in mem::replace(&mut self.direct_msg_backlog, Default::default()) {
            if let Transition::Stay = &transition {
                match self.handle_direct_message(msg, pub_id, outbox) {
                    Ok(new_transition) => transition = new_transition,
                    Err(err) => debug!("{} - {:?}", self, err),
                }
            } else {
                self.direct_msg_backlog.push((pub_id, msg));
            }
        }

        if let Transition::Stay = &transition {
            for msg in mem::replace(&mut self.routing_msg_backlog, Default::default()) {
                if let Err(err) = self.handle_backloged_filtered_signed_message(msg) {
                    debug!("{} - {:?}", self, err);
                }
            }
        }

        transition
    }

    fn handle_send_message(
        &mut self,
        src: Location<XorName>,
        dst: Location<XorName>,
        content: Vec<u8>,
    ) -> Result<(), InterfaceError> {
        match self.send_user_message(src, dst, content) {
            Err(RoutingError::Interface(err)) => Err(err),
            Err(_) | Ok(()) => Ok(()),
        }
    }

    fn handle_timeout(&mut self, token: u64, outbox: &mut dyn EventBox) -> Transition {
        if self.gossip_timer_token == token {
            self.gossip_timer_token = self.timer.schedule(GOSSIP_TIMEOUT);

            // If we're the only node then invoke parsec_poll directly
            if self.chain.our_info().len() == 1 {
                let _ = self.parsec_poll(outbox);
            }

            self.send_parsec_gossip(None);
            self.maintain_parsec();
        }

        Transition::Stay
    }

    fn finish_handle_action(&mut self, outbox: &mut dyn EventBox) -> Transition {
        self.handle_routing_messages(outbox)
    }

    fn handle_bootstrapped_to(&mut self, conn_info: ConnectionInfo) -> Transition {
        // A mature node doesn't need a bootstrap connection
        self.network_service
            .service_mut()
            .disconnect_from(conn_info.peer_addr);
        Transition::Stay
    }

    fn handle_peer_lost(&mut self, peer_addr: SocketAddr, outbox: &mut dyn EventBox) -> Transition {
        debug!("{} - Lost peer {}", self, peer_addr);

        let pub_id = if let Some(node) = self.chain.find_p2p_node_from_addr(&peer_addr) {
            *node.public_id()
        } else {
            info!(
                "{} - Lost connection to a peer we don't know: {}",
                self, peer_addr
            );
            return Transition::Stay;
        };

        // If we lost an elder, check whether we still have sufficient number of remaining elder
        // connections.
        if self.chain.is_peer_our_elder(&pub_id) && !self.check_elder_connections(outbox) {
            return Transition::Terminate;
        }

        if self.chain.is_peer_our_member(&pub_id) {
            self.vote_for_event(AccumulatingEvent::Offline(pub_id));
        }

        Transition::Stay
    }

    fn finish_handle_network_event(&mut self, outbox: &mut dyn EventBox) -> Transition {
        self.handle_routing_messages(outbox)
    }

    // Deconstruct a `DirectMessage` and handle or forward as appropriate.
    fn handle_direct_message(
        &mut self,
        msg: DirectMessage,
        p2p_node: P2pNode,
        outbox: &mut dyn EventBox,
    ) -> Result<Transition, RoutingError> {
        use crate::messages::DirectMessage::*;

        let pub_id = *p2p_node.public_id();

        match msg {
            MessageSignature(msg) => self.handle_message_signature(*msg, pub_id)?,
            BootstrapRequest(name) => self.handle_bootstrap_request(p2p_node, name),
            ConnectionResponse => self.handle_connection_response(pub_id, outbox),
            JoinRequest(join_request) => self.handle_join_request(p2p_node, *join_request),
            MemberKnowledge(payload) => self.handle_member_knowledge(p2p_node, payload),
            ParsecRequest(version, par_request) => {
                return self.handle_parsec_request(version, par_request, p2p_node, outbox);
            }
            ParsecResponse(version, par_response) => {
                return self.handle_parsec_response(version, par_response, pub_id, outbox);
            }
            BootstrapResponse(_) => {
                debug!("{} Unhandled direct message: {:?}", self, msg);
            }
            msg @ Relocate(_) => {
                debug!(
                    "{} Unhandled Elder direct message from {}, adding to backlog: {:?}",
                    self,
                    p2p_node.public_id(),
                    msg
                );
                self.direct_msg_backlog.push((p2p_node, msg));
            }
        }
        Ok(Transition::Stay)
    }

    fn handle_hop_message(
        &mut self,
        msg: HopMessageWithSerializedMessage,
        _: &mut dyn EventBox,
    ) -> Result<Transition, RoutingError> {
        self.handle_signed_message(msg).map(|()| Transition::Stay)
    }
}

#[cfg(feature = "mock_base")]
impl Elder {
    pub fn chain(&self) -> &Chain {
        &self.chain
    }

    pub fn process_timers(&mut self) {
        self.timer.process_timers()
    }

    pub fn has_unpolled_observations(&self) -> bool {
        if !self.chain.is_self_elder() {
            return false;
        }
        self.parsec_map.has_unpolled_observations()
    }

    pub fn unpolled_observations_string(&self) -> String {
        self.parsec_map.unpolled_observations_string()
    }

    pub fn is_peer_our_elder(&self, pub_id: &PublicId) -> bool {
        self.chain.is_peer_our_elder(pub_id)
    }

    pub fn send_msg_to_targets(
        &mut self,
        dst_targets: &[ConnectionInfo],
        dg_size: usize,
        message: Message,
    ) -> Result<(), RoutingError> {
        let message = to_network_bytes(&message)?;

        self.send_message_to_targets(dst_targets, dg_size, message);
        Ok(())
    }

    pub fn parsec_last_version(&self) -> u64 {
        self.parsec_map.last_version()
    }
}

impl Approved for Elder {
    fn send_event(&mut self, event: Event, outbox: &mut dyn EventBox) {
        outbox.send_event(event);
    }

    fn parsec_map(&self) -> &ParsecMap {
        &self.parsec_map
    }

    fn parsec_map_mut(&mut self) -> &mut ParsecMap {
        &mut self.parsec_map
    }

    fn chain(&self) -> &Chain {
        &self.chain
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

    fn handle_relocate_polled(&mut self, details: RelocateDetails) -> Result<(), RoutingError> {
        self.vote_for_relocate_prepare(details, INITIAL_RELOCATE_COOL_DOWN_COUNT_DOWN);
        Ok(())
    }

    fn handle_promote_and_demote_elders(
        &mut self,
        new_infos: Vec<EldersInfo>,
    ) -> Result<(), RoutingError> {
        for info in new_infos {
            let participants: BTreeSet<_> = info.member_ids().copied().collect();
            let _ = self.dkg_cache.insert(participants.clone(), info);
            self.vote_for_event(AccumulatingEvent::StartDkg(participants));
        }

        Ok(())
    }

    fn handle_member_added(
        &mut self,
        payload: OnlinePayload,
        outbox: &mut dyn EventBox,
    ) -> Result<(), RoutingError> {
        self.handle_candidate_approval(payload.p2p_node, outbox);
        self.print_rt_size();
        Ok(())
    }

    fn handle_member_removed(
        &mut self,
        pub_id: PublicId,
        _outbox: &mut dyn EventBox,
    ) -> Result<(), RoutingError> {
        let _ = self.members_knowledge.remove(pub_id.name());
        Ok(())
    }

    fn handle_member_relocated(
        &mut self,
        details: RelocateDetails,
        signature: bls::Signature,
        node_knowledge: u64,
        _outbox: &mut dyn EventBox,
    ) {
        let _ = self.members_knowledge.remove(details.pub_id.name());

        if &details.pub_id == self.id() {
            // Do not send the message to ourselves.
            return;
        }

        // We need proof that is valid for both the relocating node and the target section. To
        // construct such proof, we create one proof for the relocating node and one for the target
        // section and then take the longer of the two. This works because the longer proof is a
        // superset of the shorter one. We need to do this because in rare cases, the relocating
        // node might be lagging behind the target section in the knowledge of the source section.
        let proof = {
            let proof_for_source = self.chain.prove(
                &Location::Node(*details.pub_id.name()),
                Some(node_knowledge),
            );
            let proof_for_target = self
                .chain
                .prove(&Location::Section(details.destination), None);

            if proof_for_source.blocks_len() > proof_for_target.blocks_len() {
                proof_for_source
            } else {
                proof_for_target
            }
        };

        if let Some(conn_info) = self
            .chain
            .get_member_connection_info(&details.pub_id)
            .cloned()
        {
            let message = DirectMessage::Relocate(Box::new(SignedRelocateDetails::new(
                details, proof, signature,
            )));
            self.send_direct_message(&conn_info, message);
        }
    }

    fn handle_dkg_result_event(
        &mut self,
        participants: &BTreeSet<PublicId>,
        dkg_result: &DkgResultWrapper,
    ) -> Result<(), RoutingError> {
        if let Some(info) = self.dkg_cache.remove(participants) {
            info!("{} - handle DkgResult: {:?}", self, participants);
            self.vote_for_section_info(info, dkg_result.0.public_key_set.public_key())?;
        } else {
            log_or_panic!(
                LogLevel::Error,
                "{} DKG for an unexpected info {:?} (expected: {{{:?}}})",
                self,
                participants,
                self.dkg_cache.keys().format(", ")
            );
        }
        Ok(())
    }

    fn handle_prune_event(&mut self) -> Result<(), RoutingError> {
        if self.chain.split_in_progress() {
            log_or_panic!(
                LogLevel::Warn,
                "{} Tring to prune parsec during prefix change.",
                self
            );
            return Ok(());
        }
        if self.chain.churn_in_progress() {
            trace!("{} - ignore ParsecPrune - churn in progress.", self);
            return Ok(());
        }

        info!("{} - handle ParsecPrune", self);
        let complete_data = self.prepare_reset_parsec()?;
        self.reset_parsec_with_data(complete_data.gen_pfx_info, complete_data.to_vote_again)?;
        self.send_genesis_updates();
        self.send_member_knowledge();
        Ok(())
    }

    fn handle_section_info_event(
        &mut self,
        old_pfx: Prefix<XorName>,
        elders_change: EldersChange,
        outbox: &mut dyn EventBox,
    ) -> Result<Transition, RoutingError> {
        let elders_info = self.chain.our_info();
        let info_prefix = *elders_info.prefix();
        let info_version = elders_info.version();
        let is_member = elders_info.is_member(self.full_id.public_id());

        info!("{} - handle SectionInfo: {:?}.", self, elders_info);

        let complete_data = if info_prefix.is_extension_of(&old_pfx) {
            self.prepare_finalise_split()?
        } else if old_pfx.is_extension_of(&info_prefix) {
            panic!(
                "{} - Merge not supported: {:?} -> {:?}",
                self, old_pfx, info_prefix,
            );
        } else {
            self.prepare_reset_parsec()?
        };

        if !is_member {
            // Demote after the parsec reset, i.e genesis prefix info is for the new parsec,
            // i.e the one that would be received with NodeApproval.
            self.process_post_reset_events(old_pfx, complete_data.to_process);
            return Ok(Transition::Demote {
                gen_pfx_info: complete_data.gen_pfx_info,
            });
        }

        self.reset_parsec_with_data(complete_data.gen_pfx_info, complete_data.to_vote_again)?;
        self.process_post_reset_events(old_pfx, complete_data.to_process);

        self.update_peer_connections(&elders_change);
        self.send_neighbour_infos();
        self.send_genesis_updates();
        self.send_member_knowledge();

        // Vote to update our self messages proof
        self.vote_send_section_info_ack(SendAckMessagePayload {
            ack_prefix: info_prefix,
            ack_version: info_version,
        });

        self.print_rt_size();
        if let Some(to_send) = complete_data.event_to_send {
            self.send_event(to_send, outbox);
        }

        Ok(Transition::Stay)
    }

    fn handle_neighbour_info_event(
        &mut self,
        elders_info: EldersInfo,
        neighbour_change: EldersChange,
    ) -> Result<(), RoutingError> {
        info!("{} - handle NeighbourInfo: {:?}.", self, elders_info);
        let _ = self
            .pending_voted_msgs
            .remove(&PendingMessageKey::NeighbourInfo {
                version: elders_info.version(),
                prefix: *elders_info.prefix(),
            });
        self.update_peer_connections(&neighbour_change);
        Ok(())
    }

    fn handle_their_key_info_event(
        &mut self,
        key_info: SectionKeyInfo,
    ) -> Result<(), RoutingError> {
        self.vote_send_section_info_ack(SendAckMessagePayload {
            ack_prefix: *key_info.prefix(),
            ack_version: key_info.version(),
        });
        Ok(())
    }

    fn handle_send_ack_message_event(
        &mut self,
        ack_payload: SendAckMessagePayload,
    ) -> Result<(), RoutingError> {
        let src = Location::Section(self.our_prefix().name());
        let dst = Location::Section(ack_payload.ack_prefix.name());
        let content = MessageContent::AckMessage {
            src_prefix: *self.our_prefix(),
            ack_version: ack_payload.ack_version,
        };

        self.send_routing_message(RoutingMessage { src, dst, content })
    }

    fn handle_relocate_prepare_event(
        &mut self,
        payload: RelocateDetails,
        count_down: i32,
        _outbox: &mut dyn EventBox,
    ) -> Result<(), RoutingError> {
        if count_down > 0 {
            self.vote_for_relocate_prepare(payload, count_down - 1);
        } else {
            self.vote_for_relocate(payload)?;
        }
        Ok(())
    }
}

impl Display for Elder {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "Elder({}({:b}))", self.name(), self.our_prefix())
    }
}

// Create `EldersInfo` for the first node.
fn create_first_elders_info(p2p_node: P2pNode) -> Result<EldersInfo, RoutingError> {
    let name = *p2p_node.name();
    let node = (name, p2p_node);
    EldersInfo::new(iter::once(node).collect(), Prefix::default(), iter::empty()).map_err(|err| {
        error!(
            "FirstNode({:?}) - Failed to create first EldersInfo: {:?}",
            name, err
        );
        err
    })
}
