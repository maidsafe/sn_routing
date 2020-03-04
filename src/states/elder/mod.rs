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
    error::{Result, RoutingError},
    event::{Connected, Event},
    id::{FullId, P2pNode, PublicId},
    location::{DstLocation, SrcLocation},
    message_filter::MessageFilter,
    messages::{
        AccumulatingMessage, BootstrapResponse, JoinRequest, MemberKnowledge, Message,
        MessageWithBytes, PlainMessage, QueuedMessage, SrcAuthority, Variant, VerifyStatus,
    },
    network_service::NetworkService,
    outbox::EventBox,
    parsec::{self, generate_first_dkg_result, DkgResultWrapper, ParsecMap},
    pause::PausedState,
    relocation::RelocateDetails,
    rng::{self, MainRng},
    signature_accumulator::SignatureAccumulator,
    state_machine::{State, Transition},
    timer::Timer,
    xor_space::{Prefix, XorName, Xorable},
};
use hex_fmt::HexFmt;
use itertools::Itertools;
use std::{
    cmp,
    collections::{BTreeMap, BTreeSet, HashSet, VecDeque},
    fmt::{self, Display, Formatter},
    iter, mem,
    net::SocketAddr,
};

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
    pub msg_queue: VecDeque<QueuedMessage>,
    pub msg_backlog: Vec<QueuedMessage>,
    pub sig_accumulator: SignatureAccumulator,
    pub parsec_map: ParsecMap,
    pub msg_filter: MessageFilter,
    pub timer: Timer,
    pub rng: MainRng,
}

pub struct Elder {
    network_service: NetworkService,
    full_id: FullId,
    // The queue of routing messages addressed to us. These do not themselves need forwarding,
    // although they may wrap a message which needs forwarding.
    msg_queue: VecDeque<QueuedMessage>,
    msg_backlog: Vec<QueuedMessage>,
    msg_filter: MessageFilter,
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
    pending_voted_msgs: BTreeMap<PendingMessageKey, Message>,
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
            msg_queue: Default::default(),
            msg_backlog: Default::default(),
            sig_accumulator: Default::default(),
            parsec_map,
            msg_filter: MessageFilter::new(),
            timer,
            rng,
        };

        let node = Self::new(details);

        debug!("{} - State changed to Node.", node);
        info!("{} - Started a new network as a seed node.", node);

        outbox.send_event(Event::Connected(Connected::First));
        outbox.send_event(Event::Promoted);

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

        outbox.send_event(Event::Promoted);

        Ok(elder)
    }

    pub fn demote(
        self,
        gen_pfx_info: GenesisPfxInfo,
        outbox: &mut dyn EventBox,
    ) -> Result<State, RoutingError> {
        outbox.send_event(Event::Demoted);

        let details = AdultDetails {
            network_service: self.network_service,
            event_backlog: Vec::new(),
            msg_backlog: self.msg_backlog,
            full_id: self.full_id,
            gen_pfx_info,
            sig_accumulator: self.sig_accumulator,
            msg_filter: self.msg_filter,
            timer: self.timer,
            network_cfg: self.chain.network_cfg(),
            rng: self.rng,
        };
        Adult::new(details, self.parsec_map, outbox).map(State::Adult)
    }

    pub fn pause(self) -> PausedState {
        PausedState {
            chain: self.chain,
            full_id: self.full_id,
            gen_pfx_info: self.gen_pfx_info,
            msg_filter: self.msg_filter,
            msg_queue: self.msg_queue,
            msg_backlog: self.msg_backlog,
            network_service: self.network_service,
            network_rx: None,
            sig_accumulator: self.sig_accumulator,
            parsec_map: self.parsec_map,
        }
    }

    pub fn resume(state: PausedState, timer: Timer) -> Self {
        Self::new(ElderDetails {
            chain: state.chain,
            network_service: state.network_service,
            event_backlog: Vec::new(),
            full_id: state.full_id,
            gen_pfx_info: state.gen_pfx_info,
            msg_queue: state.msg_queue,
            msg_backlog: state.msg_backlog,
            sig_accumulator: state.sig_accumulator,
            parsec_map: state.parsec_map,
            msg_filter: state.msg_filter,
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
        let parsec_map = details.parsec_map;

        let gossip_timer_token = timer.schedule(parsec_map.gossip_period());

        Self {
            network_service: details.network_service,
            full_id: details.full_id.clone(),
            msg_queue: details.msg_queue,
            msg_backlog: details.msg_backlog,
            msg_filter: details.msg_filter,
            sig_accumulator: details.sig_accumulator,
            timer,
            parsec_map,
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
        const TABLE_LVL: log::Level = log::Level::Info;
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

    fn handle_messages(&mut self, outbox: &mut dyn EventBox) -> Transition {
        while let Some(QueuedMessage { message, sender }) = self.msg_queue.pop_front() {
            if self.in_dst_location(&message.dst) {
                match self.dispatch_message(sender, message, outbox) {
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

                self.network_service.disconnect(*p2p_node.peer_addr());
            }
        }
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
                log_or_panic!(log::Level::Error, "unexpected event {:?}", evt);
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
                p2p_node.peer_addr(),
                Variant::BootstrapResponse(BootstrapResponse::Join(response_section)),
            );
        }
    }

    // After parsec reset, resend any unaccumulated voted messages to everyone that needs
    // them but possibly did not receive them already.
    fn resend_pending_voted_messages(&mut self, _old_pfx: Prefix<XorName>) {
        for (_, msg) in mem::take(&mut self.pending_voted_msgs) {
            let msg = match MessageWithBytes::new(msg, &self.log_ident()) {
                Ok(msg) => msg,
                Err(err) => {
                    error!("Failed to make message {:?}", err);
                    continue;
                }
            };
            match self.send_signed_message(&msg) {
                Ok(()) => trace!("{} - Resend {}", self, HexFmt(msg.full_crypto_hash())),
                Err(error) => debug!(
                    "{} - Failed to resend {}: {:?}",
                    self,
                    HexFmt(msg.full_crypto_hash()),
                    error
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
            let src = SrcLocation::Section(*self.our_prefix());
            let dst = DstLocation::Prefix(*pfx);
            let variant = Variant::NeighbourInfo(self.chain.our_info().clone());

            if let Err(err) = self.send_routing_message(src, dst, variant, None) {
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
                recipient.peer_addr(),
                Variant::MessageSignature(Box::new(msg)),
            );
        }
    }

    fn create_genesis_updates(&self) -> Vec<(P2pNode, AccumulatingMessage)> {
        self.chain
            .adults_and_infants_p2p_nodes()
            .cloned()
            .filter_map(|recipient| {
                let variant = Variant::GenesisUpdate(Box::new(self.gen_pfx_info.clone()));
                let dst = DstLocation::Node(*recipient.name());
                let version = self
                    .members_knowledge
                    .get(recipient.name())
                    .map(|knowledge| knowledge.elders_version)
                    .unwrap_or(0);

                match self.to_accumulating_message(dst, variant, Some(version)) {
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
        msg: AccumulatingMessage,
        src: PublicId,
        _outbox: &mut dyn EventBox,
    ) -> Result<Transition> {
        if !self.chain.is_peer_elder(&src) {
            debug!(
                "{} - Received message signature from not known elder (still use it) {}, {:?}",
                self, src, msg
            );
            // FIXME: currently accepting signatures from unknown senders to cater to lagging nodes.
            // Need to verify whether there are any security implications with doing this.
        }

        if let Some(msg) = self.sig_accumulator.add_proof(msg, &self.log_ident()) {
            self.handle_accumulated_message(msg)?
        }

        Ok(Transition::Stay)
    }

    fn handle_accumulated_message(&mut self, mut msg: MessageWithBytes) -> Result<()> {
        // FIXME: this is almost the same as `Base::try_handle__message` - find a way
        // to avoid the duplication.

        if !self.filter_incoming_message(&msg) {
            trace!(
                "{} Known message: {} - not handling further",
                self,
                HexFmt(msg.full_crypto_hash())
            );

            return Ok(());
        }

        self.try_relay_message(&msg)?;

        if !self.in_dst_location(msg.message_dst()) {
            return Ok(());
        }

        let msg = msg.take_or_deserialize_message()?;

        if self.should_handle_message(&msg) && self.verify_message(&msg)? {
            self.msg_queue.push_back(msg.into_queued(None));
        }

        Ok(())
    }

    fn handle_backlogged_message(
        &mut self,
        sender: Option<SocketAddr>,
        msg: Message,
    ) -> Result<(), RoutingError> {
        trace!("{} - Handle backlogged message: {:?}", self, msg);

        if !self.in_dst_location(&msg.dst) {
            return Ok(());
        }

        if self.should_handle_message(&msg) && self.verify_message_quiet(&msg).unwrap_or(false) {
            // If message still for us and we still trust it, then it must not be stale.
            self.update_our_knowledge(&msg);
            self.msg_queue.push_back(msg.into_queued(sender));
        }

        Ok(())
    }

    fn dispatch_message(
        &mut self,
        sender: Option<SocketAddr>,
        msg: Message,
        outbox: &mut dyn EventBox,
    ) -> Result<Transition, RoutingError> {
        match msg.variant {
            Variant::UserMessage { .. } => (),
            _ => trace!("{} Got {:?}.", self, msg),
        }

        match msg.variant {
            Variant::NeighbourInfo(elders_info) => {
                // Ensure the src and dst are what we expect.
                let _: &Prefix<_> = msg.src.as_section()?;
                let _: &Prefix<_> = msg.dst.as_prefix()?;

                self.handle_neighbour_info(elders_info, msg.src, msg.dst)?;
            }
            Variant::UserMessage(content) => {
                outbox.send_event(Event::MessageReceived {
                    content,
                    src: msg.src.location(),
                    dst: msg.dst,
                });
            }
            Variant::AckMessage {
                src_prefix,
                ack_version,
            } => {
                self.handle_ack_message(
                    src_prefix,
                    ack_version,
                    *msg.src.as_section()?,
                    *msg.dst.as_section()?,
                )?;
            }
            Variant::MessageSignature(accumulating_msg) => {
                return self.handle_message_signature(
                    *accumulating_msg,
                    *msg.src.as_node()?,
                    outbox,
                );
            }
            Variant::BootstrapRequest(name) => {
                self.handle_bootstrap_request(msg.src.to_sender_node(sender)?, name)
            }
            Variant::JoinRequest(join_request) => {
                self.handle_join_request(msg.src.to_sender_node(sender)?, *join_request)
            }
            Variant::MemberKnowledge(payload) => {
                self.handle_member_knowledge(msg.src.to_sender_node(sender)?, payload)
            }
            Variant::ParsecRequest(version, request) => {
                return self.handle_parsec_request(
                    version,
                    request,
                    msg.src.to_sender_node(sender)?,
                    outbox,
                );
            }
            Variant::ParsecResponse(version, response) => {
                return self.handle_parsec_response(version, response, *msg.src.as_node()?, outbox);
            }
            _ => unreachable!(),
        }

        Ok(Transition::Stay)
    }

    fn handle_ack_message(
        &mut self,
        src_prefix: Prefix<XorName>,
        ack_version: u64,
        _src: Prefix<XorName>,
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
        let has_their_keys = self.chain.get_their_key_infos().any(|(_, info)| {
            *info.prefix() == ack_payload.ack_prefix && info.version() == ack_payload.ack_version
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
        p2p_node: P2pNode,
        their_knowledge: Option<u64>,
        _outbox: &mut dyn EventBox,
    ) {
        info!(
            "{} Our section with {:?} has approved candidate {}.",
            self,
            self.our_prefix(),
            p2p_node
        );

        let pub_id = *p2p_node.public_id();
        let dst = DstLocation::Node(*pub_id.name());

        let trimmed_info = GenesisPfxInfo {
            first_info: self.gen_pfx_info.first_info.clone(),
            first_bls_keys: self.gen_pfx_info.first_bls_keys.clone(),
            first_state_serialized: Default::default(),
            first_ages: self.gen_pfx_info.first_ages.clone(),
            latest_info: self.chain.our_info().clone(),
            parsec_version: self.gen_pfx_info.parsec_version,
        };

        let src = SrcLocation::Section(*trimmed_info.first_info.prefix());
        let variant = Variant::NodeApproval(Box::new(trimmed_info));
        if let Err(error) = self.send_routing_message(src, dst, variant, their_knowledge) {
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
                .map(|p2p_node| *p2p_node.peer_addr())
                .collect();
            debug!(
                "{} - Sending BootstrapResponse::Rebootstrap to {}",
                self, p2p_node
            );
            BootstrapResponse::Rebootstrap(conn_infos)
        };
        self.send_direct_message(p2p_node.peer_addr(), Variant::BootstrapResponse(response));
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
        let (age, their_knowledge) = if let Some(payload) = join_request.relocate_payload {
            if !payload.verify_identity(&pub_id) {
                debug!(
                    "{} - Ignoring relocation JoinRequest from {} - invalid signature.",
                    self, pub_id
                );
                return;
            }

            let details = payload.relocate_details();

            if !self.our_prefix().matches(&details.destination) {
                debug!(
                    "{} - Ignoring relocation JoinRequest from {} - destination {} doesn't match \
                     our prefix {:?}.",
                    self,
                    pub_id,
                    details.destination,
                    self.our_prefix()
                );
                return;
            }

            if !self.check_signed_relocation_details(&payload.details) {
                return;
            }

            (details.age, Some(details.destination_key_info.version()))
        } else {
            (MIN_AGE, None)
        };

        self.vote_for_event(AccumulatingEvent::Online(OnlinePayload {
            p2p_node,
            age,
            their_knowledge,
        }))
    }

    fn update_our_knowledge(&mut self, msg: &Message) {
        let key_info = if let Some(key_info) = msg.source_section_key_info() {
            key_info
        } else {
            return;
        };

        let new_key_info = self
            .chain
            .get_their_key_infos()
            .find(|(prefix, _)| prefix.is_compatible(key_info.prefix()))
            .map_or(false, |(_, info)| info.version() < key_info.version());

        if new_key_info {
            self.vote_for_event(AccumulatingEvent::TheirKeyInfo(key_info.clone()));
        }
    }

    fn handle_neighbour_info(
        &mut self,
        elders_info: EldersInfo,
        src: SrcAuthority,
        dst: DstLocation,
    ) -> Result<()> {
        if self.chain.is_new_neighbour(&elders_info) {
            let _ = self
                .pending_voted_msgs
                .entry(PendingMessageKey::NeighbourInfo {
                    version: elders_info.version(),
                    prefix: *elders_info.prefix(),
                })
                .or_insert_with(|| Message {
                    src,
                    dst,
                    variant: Variant::NeighbourInfo(elders_info.clone()),
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

    fn vote_for_relocate(&mut self, details: RelocateDetails) {
        self.vote_for_network_event(details.into_accumulating_event().into_network_event())
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

    fn vote_for_network_event(&mut self, event: NetworkEvent) {
        trace!("{} Vote for Event {:?}", self, event);
        self.parsec_map.vote_for(event, &self.log_ident());
    }

    // Constructs a message, finds the nodes responsible for accumulation, and either sends
    // these nodes a signature or tries to accumulate signatures for this message (on success, the
    // accumulator handles or forwards the message).
    //
    // If `node_knowledge_override` is set and the destination is a single node, it will be used as
    // the starting index of the proof. Otherwise the index is calculated using the knowledge
    // stored in the shared state.
    fn send_routing_message(
        &mut self,
        src: SrcLocation,
        dst: DstLocation,
        variant: Variant,
        node_knowledge_override: Option<u64>,
    ) -> Result<()> {
        if !self.in_src_location(&src) {
            log_or_panic!(
                log::Level::Error,
                "{} Not part of the source location. Not sending message {:?} -> {:?}: {:?}.",
                self,
                src,
                dst,
                variant
            );
            return Ok(());
        }

        let log_ident = self.log_ident();

        // If the source is single, we don't even need to send signatures, so let's cut this short
        if src.is_single() {
            let msg = Message::single_src(&self.full_id, dst, variant)?;
            let msg = MessageWithBytes::new(msg, &log_ident)?;
            return self.handle_accumulated_message(msg);
        }

        let accumulating_msg =
            self.to_accumulating_message(dst, variant, node_knowledge_override)?;

        for target in self.get_signature_targets(&dst) {
            if target.name() == self.name() {
                if let Some(msg) = self
                    .sig_accumulator
                    .add_proof(accumulating_msg.clone(), &log_ident)
                {
                    self.handle_accumulated_message(msg)?;
                }
            } else {
                trace!(
                    "{} Sending a signature for {:?} to {:?}",
                    self,
                    accumulating_msg.content,
                    target,
                );
                self.send_direct_message(
                    target.peer_addr(),
                    Variant::MessageSignature(Box::new(accumulating_msg.clone())),
                );
            }
        }

        Ok(())
    }

    // Send message over the network.
    fn send_signed_message(&mut self, msg: &MessageWithBytes) -> Result<(), RoutingError> {
        let dst = msg.message_dst();

        // If the message is to a single node and we have the connection info for this node, don't
        // go through the routing table
        let single_target = if let DstLocation::Node(node_name) = dst {
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
            "{}: Sending message {} via targets {:?}",
            self,
            HexFmt(msg.full_crypto_hash()),
            target_p2p_nodes
        );

        let targets: Vec<_> = target_p2p_nodes
            .into_iter()
            .filter(|p2p_node| {
                self.msg_filter
                    .filter_outgoing(msg, p2p_node.public_id())
                    .is_new()
            })
            .map(|node| *node.peer_addr())
            .collect();

        let cheap_bytes_clone = msg.full_bytes().clone();
        self.send_message_to_targets(&targets, dg_size, cheap_bytes_clone);

        Ok(())
    }

    /// Vote for a user-defined event.
    pub fn vote_for_user_event(&mut self, event: Vec<u8>) {
        self.vote_for_event(AccumulatingEvent::User(event));
    }

    /// Returns the set of peers that are responsible for collecting signatures to verify a message;
    /// this may contain us or only other nodes. If our signature is not required, this returns
    /// `None`.
    fn get_signature_targets(&self, dst: &DstLocation) -> Vec<P2pNode> {
        let dst_name = match dst {
            DstLocation::Node(name) => *name,
            DstLocation::Section(name) => *name,
            DstLocation::Prefix(prefix) => prefix.name(),
            DstLocation::Direct => {
                log_or_panic!(
                    log::Level::Error,
                    "{} - Invalid destination for signature targets: {:?}",
                    self,
                    dst
                );
                return vec![];
            }
        };

        let mut list = self
            .chain
            .our_elders()
            .cloned()
            .sorted_by(|lhs, rhs| dst_name.cmp_distance(lhs.name(), rhs.name()));
        list.truncate(delivery_group_size(list.len()));
        list
    }

    /// Returns a list of target IDs for a message sent via route.
    fn get_targets(&self, dst: &DstLocation) -> Result<(Vec<P2pNode>, usize), RoutingError> {
        let (targets, dg_size) = self.chain.targets(dst)?;
        Ok((targets.into_iter().cloned().collect(), dg_size))
    }

    // Signs and proves the given `RoutingMessage` and wraps it in `SignedRoutingMessage`.
    fn to_accumulating_message(
        &self,
        dst: DstLocation,
        variant: Variant,
        node_knowledge_override: Option<u64>,
    ) -> Result<AccumulatingMessage> {
        let proof = self.chain.prove(&dst, node_knowledge_override);
        let pk_set = self.our_section_bls_keys().clone();
        let secret_key = self.chain.our_section_bls_secret_key_share()?;

        let content = PlainMessage {
            src: *self.our_prefix(),
            dst,
            variant,
        };

        AccumulatingMessage::new(content, secret_key, pk_set, proof)
    }

    pub fn in_src_location(&self, src: &SrcLocation) -> bool {
        self.chain.in_src_location(src)
    }

    // Verifies message but doesn't log anything on failure, only returns result.
    fn verify_message_quiet(&self, msg: &Message) -> Result<bool, RoutingError> {
        match msg.verify(self.chain.get_their_key_infos()) {
            Ok(VerifyStatus::Full) => Ok(true),
            Ok(VerifyStatus::ProofTooNew) if msg.dst.is_multiple() => {
                // Proof is too new which can only happen if we've been already demoted but are
                // lagging behind (or the sender is faulty/malicious). We can't handle the
                // message ourselves but the other elders likely can.
                Ok(false)
            }
            Ok(VerifyStatus::ProofTooNew) => Err(RoutingError::UntrustedMessage),
            Err(error) => Err(error),
        }
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

    fn in_dst_location(&self, dst: &DstLocation) -> bool {
        self.chain.in_dst_location(dst)
    }

    fn close_group(&self, name: XorName, count: usize) -> Option<Vec<XorName>> {
        let mut conn_peers: Vec<_> = self.chain.elders().map(P2pNode::name).collect();
        conn_peers.sort_unstable();
        conn_peers.dedup();
        self.chain.closest_names(&name, count, &conn_peers)
    }

    fn timer(&self) -> &Timer {
        &self.timer
    }

    fn rng(&mut self) -> &mut MainRng {
        &mut self.rng
    }

    fn finish_handle_transition(&mut self, _outbox: &mut dyn EventBox) -> Transition {
        debug!("{} - State change to Elder finished.", self);

        for QueuedMessage { message, sender } in mem::take(&mut self.msg_backlog) {
            match self.handle_backlogged_message(sender, message) {
                Ok(()) => (),
                Err(err) => debug!("{} - {:?}", self, err),
            }
        }

        Transition::Stay
    }

    fn handle_send_message(
        &mut self,
        src: SrcLocation,
        dst: DstLocation,
        content: Vec<u8>,
    ) -> Result<(), RoutingError> {
        if let DstLocation::Direct = dst {
            return Err(RoutingError::BadLocation);
        }

        self.send_routing_message(src, dst, Variant::UserMessage(content), None)
    }

    fn handle_timeout(&mut self, token: u64, _outbox: &mut dyn EventBox) -> Transition {
        if self.gossip_timer_token == token {
            self.gossip_timer_token = self.timer.schedule(self.parsec_map.gossip_period());
            self.parsec_map.reset_gossip_period();
        }

        Transition::Stay
    }

    fn finish_handle_input(&mut self, outbox: &mut dyn EventBox) -> Transition {
        match self.handle_messages(outbox) {
            Transition::Stay => (),
            transition => return transition,
        }

        let transition = if self.chain.our_info().len() == 1 {
            // If we're the only node then invoke parsec_poll directly
            match self.parsec_poll(outbox) {
                Ok(transition) => transition,
                Err(error) => {
                    error!("{} - Parsec poll failed: {:?}", self, error);
                    Transition::Stay
                }
            }
        } else {
            Transition::Stay
        };

        self.maintain_parsec();
        self.send_parsec_gossip(None);

        transition
    }

    fn handle_bootstrapped_to(&mut self, addr: SocketAddr) -> Transition {
        // A mature node doesn't need a bootstrap connection
        self.network_service.service_mut().disconnect_from(addr);
        Transition::Stay
    }

    fn handle_connection_failure(
        &mut self,
        addr: SocketAddr,
        _outbox: &mut dyn EventBox,
    ) -> Transition {
        let node = self
            .chain
            .our_active_members()
            .find(|node| *node.peer_addr() == addr);

        if let Some(node) = node {
            trace!("{} - ConnectionFailure from member {}", self, node);

            // Ping the peer to trigger lost peer detection.
            let addr = *node.peer_addr();
            self.send_direct_message(&addr, Variant::Ping);
        } else {
            trace!("{} - ConnectionFailure from non-member {}", self, addr);
        }

        Transition::Stay
    }

    fn handle_peer_lost(
        &mut self,
        peer_addr: SocketAddr,
        _outbox: &mut dyn EventBox,
    ) -> Transition {
        let pub_id = if let Some(node) = self.chain.find_p2p_node_from_addr(&peer_addr) {
            debug!("{} - Lost known peer {}", self, node);
            *node.public_id()
        } else {
            trace!("{} - Lost unknown peer {}", self, peer_addr);
            return Transition::Stay;
        };

        if self.chain.is_peer_our_member(&pub_id) {
            self.vote_for_event(AccumulatingEvent::Offline(pub_id));
        }

        Transition::Stay
    }

    fn handle_message(
        &mut self,
        sender: Option<SocketAddr>,
        msg: Message,
        _outbox: &mut dyn EventBox,
    ) -> Result<Transition> {
        self.update_our_knowledge(&msg);
        self.msg_queue.push_back(msg.into_queued(sender));
        Ok(Transition::Stay)
    }

    fn unhandled_message(&mut self, sender: Option<SocketAddr>, msg: Message) {
        match msg.variant {
            Variant::GenesisUpdate(_) | Variant::Relocate(_) => {
                debug!("{} Unhandled message, adding to backlog: {:?}", self, msg);
                self.msg_backlog.push(msg.into_queued(sender));
            }
            Variant::BootstrapResponse(_) | Variant::NodeApproval(_) | Variant::Ping => {
                debug!("{} Unhandled message, ignoring: {:?}", self, msg);
            }
            _ => unreachable!(),
        }
    }

    fn filter_incoming_message(&mut self, message: &MessageWithBytes) -> bool {
        self.msg_filter.filter_incoming(message).is_new()
    }

    fn relay_message(&mut self, message: &MessageWithBytes) -> Result<()> {
        self.send_signed_message(message)
    }

    fn should_handle_message(&self, msg: &Message) -> bool {
        match msg.variant {
            Variant::NeighbourInfo(_)
            | Variant::UserMessage(_)
            | Variant::AckMessage { .. }
            | Variant::MessageSignature(_)
            | Variant::BootstrapRequest(_)
            | Variant::JoinRequest(_)
            | Variant::MemberKnowledge(_)
            | Variant::ParsecRequest(..)
            | Variant::ParsecResponse(..) => true,

            Variant::GenesisUpdate(_)
            | Variant::Relocate(_)
            | Variant::BootstrapResponse(_)
            | Variant::NodeApproval(_)
            | Variant::Ping => false,
        }
    }

    fn verify_message(&self, msg: &Message) -> Result<bool, RoutingError> {
        self.verify_message_quiet(msg).map_err(|error| {
            self.log_verify_failure(msg, &error, self.chain.get_their_key_infos());
            error
        })
    }
}

#[cfg(feature = "mock_base")]
impl Elder {
    pub fn chain(&self) -> &Chain {
        &self.chain
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
        dst_targets: &[SocketAddr],
        dg_size: usize,
        message: Message,
    ) -> Result<(), RoutingError> {
        let message = message.to_bytes()?;
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
        self.handle_candidate_approval(payload.p2p_node, payload.their_knowledge, outbox);
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
        node_knowledge: u64,
        _outbox: &mut dyn EventBox,
    ) -> Result<(), RoutingError> {
        let _ = self.members_knowledge.remove(details.pub_id.name());

        if &details.pub_id == self.id() {
            // Do not send the message to ourselves.
            return Ok(());
        }

        // We need proof that is valid for both the relocating node and the target section. To
        // construct such proof, we create one proof for the relocating node and one for the target
        // section and then take the longer of the two. This works because the longer proof is a
        // superset of the shorter one. We need to do this because in rare cases, the relocating
        // node might be lagging behind the target section in the knowledge of the source section.
        let knowledge_index = cmp::min(
            node_knowledge,
            self.chain
                .knowledge_index(&DstLocation::Section(details.destination), None),
        );

        let src = SrcLocation::Section(*self.our_prefix());
        let dst = DstLocation::Node(*details.pub_id.name());
        let content = Variant::Relocate(Box::new(details));

        self.send_routing_message(src, dst, content, Some(knowledge_index))
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
                log::Level::Error,
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
                log::Level::Warn,
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
        let src = SrcLocation::Section(*self.our_prefix());
        let dst = DstLocation::Section(ack_payload.ack_prefix.name());
        let variant = Variant::AckMessage {
            src_prefix: *self.our_prefix(),
            ack_version: ack_payload.ack_version,
        };

        self.send_routing_message(src, dst, variant, None)
    }

    fn handle_relocate_prepare_event(
        &mut self,
        payload: RelocateDetails,
        count_down: i32,
        _outbox: &mut dyn EventBox,
    ) {
        if count_down > 0 {
            self.vote_for_relocate_prepare(payload, count_down - 1);
        } else {
            self.vote_for_relocate(payload);
        }
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
