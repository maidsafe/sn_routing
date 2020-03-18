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
    common::{Base, Core, BOUNCE_RESEND_DELAY},
    JoiningPeer,
};
use crate::{
    chain::{
        delivery_group_size, AccumulatedEvent, AccumulatingEvent, AckMessagePayload, Chain,
        EldersChange, EldersInfo, EventSigPayload, GenesisPfxInfo, IntoAccumulatingEvent,
        MemberState, NetworkEvent, NetworkParams, OnlinePayload, ParsecResetData, PollAccumulated,
        Proof, SectionKeyInfo, SendAckMessagePayload, MIN_AGE, MIN_AGE_COUNTER,
    },
    error::{Result, RoutingError},
    event::{Connected, Event},
    id::{FullId, P2pNode, PublicId},
    location::{DstLocation, SrcLocation},
    log_utils,
    message_filter::MessageFilter,
    messages::{
        self, AccumulatingMessage, BootstrapResponse, JoinRequest, MemberKnowledge, Message,
        MessageHash, MessageWithBytes, PlainMessage, QueuedMessage, SrcAuthority, Variant,
        VerifyStatus,
    },
    network_service::NetworkService,
    outbox::EventBox,
    parsec::{self, generate_first_dkg_result, DkgResultWrapper, Observation, ParsecMap},
    pause::PausedState,
    relocation::{RelocateDetails, SignedRelocateDetails},
    rng::{self, MainRng},
    signature_accumulator::SignatureAccumulator,
    state_machine::{State, Transition},
    time::Duration,
    timer::Timer,
    xor_space::{Prefix, XorName, Xorable},
};
use bytes::Bytes;
use itertools::Itertools;
use rand::Rng;
use std::{
    cmp,
    collections::{BTreeMap, BTreeSet, HashSet, VecDeque},
    iter, mem,
    net::SocketAddr,
};

// Send our knowledge in a similar speed as GOSSIP_TIMEOUT
const KNOWLEDGE_TIMEOUT: Duration = Duration::from_secs(2);

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
    pub full_id: FullId,
    pub gen_pfx_info: GenesisPfxInfo,
    pub msg_queue: VecDeque<QueuedMessage>,
    pub sig_accumulator: SignatureAccumulator,
    pub parsec_map: ParsecMap,
    pub msg_filter: MessageFilter,
    pub timer: Timer,
    pub rng: MainRng,
}

pub struct ApprovedPeer {
    core: Core,
    // The queue of routing messages addressed to us. These do not themselves need forwarding,
    // although they may wrap a message which needs forwarding.
    msg_queue: VecDeque<QueuedMessage>,
    sig_accumulator: SignatureAccumulator,
    parsec_map: ParsecMap,
    gen_pfx_info: GenesisPfxInfo,
    timer_token: u64,
    chain: Chain,
    pfx_is_successfully_polled: bool,
    // DKG cache
    dkg_cache: BTreeMap<BTreeSet<PublicId>, EldersInfo>,
    // Messages we received but not accumulated yet, so may need to re-swarm.
    pending_voted_msgs: BTreeMap<PendingMessageKey, Message>,
    /// The knowledge of the non-elder members about our section.
    members_knowledge: BTreeMap<XorName, MemberKnowledge>,
}

impl ApprovedPeer {
    ////////////////////////////////////////////////////////////////////////////
    // Construction and transition
    ////////////////////////////////////////////////////////////////////////////

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
        let mut ages = BTreeMap::new();
        let _ = ages.insert(public_id, MIN_AGE_COUNTER);
        let first_dkg_result = generate_first_dkg_result(&mut rng);
        let gen_pfx_info = GenesisPfxInfo {
            elders_info: create_first_elders_info(p2p_node)?,
            public_keys: first_dkg_result.public_key_set,
            state_serialized: Vec::new(),
            ages,
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
            full_id,
            gen_pfx_info,
            msg_queue: Default::default(),
            sig_accumulator: Default::default(),
            parsec_map,
            msg_filter: MessageFilter::new(),
            timer,
            rng,
        };

        let node = Self::new(details);

        info!("{} Started a new network as a seed node.", node.name());

        outbox.send_event(Event::Connected(Connected::First));
        outbox.send_event(Event::Promoted);

        Ok(node)
    }

    pub fn from_joining_peer(
        details: ElderDetails,
        connect_type: Connected,
        outbox: &mut dyn EventBox,
    ) -> Self {
        let node = Self::new(details);

        debug!("{} State changed to Elder.", node.name());
        outbox.send_event(Event::Connected(connect_type));

        node
    }

    pub fn relocate(
        self,
        conn_infos: Vec<SocketAddr>,
        details: SignedRelocateDetails,
    ) -> Result<State, RoutingError> {
        Ok(State::JoiningPeer(JoiningPeer::relocate(
            self.core,
            self.chain.network_cfg(),
            conn_infos,
            details,
        )))
    }

    pub fn pause(self) -> PausedState {
        PausedState {
            chain: self.chain,
            full_id: self.core.full_id,
            gen_pfx_info: self.gen_pfx_info,
            msg_filter: self.core.msg_filter,
            msg_queue: self.msg_queue,
            network_service: self.core.network_service,
            network_rx: None,
            sig_accumulator: self.sig_accumulator,
            parsec_map: self.parsec_map,
        }
    }

    pub fn resume(state: PausedState, timer: Timer) -> Self {
        Self::new(ElderDetails {
            chain: state.chain,
            network_service: state.network_service,
            full_id: state.full_id,
            gen_pfx_info: state.gen_pfx_info,
            msg_queue: state.msg_queue,
            sig_accumulator: state.sig_accumulator,
            parsec_map: state.parsec_map,
            msg_filter: state.msg_filter,
            timer,
            rng: rng::new(),
        })
    }

    fn new(details: ElderDetails) -> Self {
        let timer = details.timer;
        let parsec_map = details.parsec_map;

        let timer_token = if details.chain.is_self_elder() {
            timer.schedule(parsec_map.gossip_period())
        } else {
            timer.schedule(KNOWLEDGE_TIMEOUT)
        };

        Self {
            core: Core {
                full_id: details.full_id.clone(),
                network_service: details.network_service,
                msg_filter: details.msg_filter,
                timer,
                rng: details.rng,
            },
            sig_accumulator: details.sig_accumulator,
            msg_queue: details.msg_queue,
            parsec_map,
            gen_pfx_info: details.gen_pfx_info,
            timer_token,
            chain: details.chain,
            pfx_is_successfully_polled: false,
            dkg_cache: Default::default(),
            pending_voted_msgs: Default::default(),
            members_knowledge: Default::default(),
        }
    }

    ////////////////////////////////////////////////////////////////////////////
    // Public API
    ////////////////////////////////////////////////////////////////////////////

    pub fn our_prefix(&self) -> &Prefix<XorName> {
        self.chain.our_prefix()
    }

    pub fn our_elders(&self) -> impl Iterator<Item = &P2pNode> {
        self.chain.our_elders()
    }

    pub fn closest_known_elders_to(&self, name: &XorName) -> impl Iterator<Item = &P2pNode> {
        self.chain.closest_section_info(*name).1.member_nodes()
    }

    /// Vote for a user-defined event.
    pub fn vote_for_user_event(&mut self, event: Vec<u8>) {
        self.vote_for_event(AccumulatingEvent::User(event));
    }

    pub fn in_src_location(&self, src: &SrcLocation) -> bool {
        self.chain.in_src_location(src)
    }

    ////////////////////////////////////////////////////////////////////////////
    // Message handling
    ////////////////////////////////////////////////////////////////////////////

    fn handle_accumulated_message(&mut self, mut msg_with_bytes: MessageWithBytes) -> Result<()> {
        // TODO: this is almost the same as `Base::try_handle_message` - find a way
        // to avoid the duplication.
        self.try_relay_message(None, &msg_with_bytes)?;

        if !self.in_dst_location(msg_with_bytes.message_dst()) {
            return Ok(());
        }

        if self.core.msg_filter.contains_incoming(&msg_with_bytes) {
            trace!(
                "not handling message - already handled: {:?}",
                msg_with_bytes
            );
            return Ok(());
        }

        let msg = msg_with_bytes.take_or_deserialize_message()?;

        if self.should_handle_message(&msg) && self.verify_message(&msg)? {
            self.core.msg_filter.insert_incoming(&msg_with_bytes);
            self.msg_queue.push_back(msg.into_queued(None));
        } else {
            self.unhandled_message(None, msg, msg_with_bytes.full_bytes().clone());
        }

        Ok(())
    }

    fn handle_messages(&mut self, outbox: &mut dyn EventBox) -> Transition {
        while let Some(QueuedMessage { message, sender }) = self.msg_queue.pop_front() {
            if self.in_dst_location(&message.dst) {
                match self.dispatch_message(sender, message, outbox) {
                    Ok(Transition::Stay) => (),
                    Ok(transition) => return transition,
                    Err(err) => debug!("Routing message dispatch failed: {:?}", err),
                }
            }
        }

        Transition::Stay
    }

    fn dispatch_message(
        &mut self,
        sender: Option<SocketAddr>,
        msg: Message,
        outbox: &mut dyn EventBox,
    ) -> Result<Transition, RoutingError> {
        match msg.variant {
            Variant::UserMessage { .. } => (),
            _ => trace!("Got {:?}", msg),
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
            Variant::GenesisUpdate(info) => {
                let _: &Prefix<_> = msg.src.as_section()?;
                self.handle_genesis_update(*info)?;
            }
            Variant::Relocate(_) => {
                let _: &Prefix<_> = msg.src.as_section()?;
                let signed_relocate = SignedRelocateDetails::new(msg)?;
                return self.handle_relocate(signed_relocate);
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
            Variant::Bounce {
                elders_version,
                message,
            } => self.handle_bounce(msg.src.to_sender_node(sender)?, elders_version, message),
            _ => unreachable!(),
        }

        Ok(Transition::Stay)
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
            trace!("Ignore not new neighbour neighbour_info: {:?}", elders_info);
        }
        Ok(())
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

    fn handle_genesis_update(&mut self, gen_pfx_info: GenesisPfxInfo) -> Result<()> {
        info!("Received GenesisUpdate: {:?}", gen_pfx_info);

        if !self.is_genesis_update_new(&gen_pfx_info) {
            return Ok(());
        }

        self.gen_pfx_info = gen_pfx_info.clone();
        self.parsec_map.init(
            &mut self.core.rng,
            self.core.full_id.clone(),
            &self.gen_pfx_info,
        );
        self.chain = Chain::new(self.chain.network_cfg(), *self.id(), gen_pfx_info, None);

        Ok(())
    }

    fn handle_relocate(
        &mut self,
        signed_msg: SignedRelocateDetails,
    ) -> Result<Transition, RoutingError> {
        if signed_msg.relocate_details().pub_id != *self.id() {
            // This `Relocate` message is not for us - it's most likely a duplicate of a previous
            // message that we already handled.
            return Ok(Transition::Stay);
        }

        debug!(
            "Received Relocate message to join the section at {}.",
            signed_msg.relocate_details().destination
        );

        if !self.check_signed_relocation_details(&signed_msg) {
            return Ok(Transition::Stay);
        }

        let conn_infos: Vec<_> = self
            .chain
            .our_elders()
            .map(|p2p_node| *p2p_node.peer_addr())
            .collect();

        // Disconnect from everyone we know.
        for addr in self.chain.known_nodes().map(|node| *node.peer_addr()) {
            self.core.network_service.disconnect(addr);
        }

        Ok(Transition::Relocate {
            details: signed_msg,
            conn_infos,
        })
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
                "Received message signature from not known elder (still use it) {}, {:?}",
                src, msg
            );
            // FIXME: currently accepting signatures from unknown senders to cater to lagging nodes.
            // Need to verify whether there are any security implications with doing this.
        }

        if let Some(msg) = self.sig_accumulator.add_proof(msg) {
            self.handle_accumulated_message(msg)?
        }

        Ok(Transition::Stay)
    }

    // Note: As an adult, we should only give info about our section elders and they would
    // further guide the joining node. However this lead to a loop if the Adult is the new Elder so
    // we use the same code as for Elder and return Join in some cases.
    fn handle_bootstrap_request(&mut self, p2p_node: P2pNode, destination: XorName) {
        debug!(
            "Received BootstrapRequest to section at {} from {:?}.",
            destination, p2p_node
        );

        let response = if self.chain.our_prefix().matches(&destination) {
            let our_info = self.chain.our_info().clone();
            debug!(
                "Sending BootstrapResponse::Join to {:?} ({:?})",
                p2p_node, our_info
            );
            BootstrapResponse::Join(our_info)
        } else {
            let conn_infos: Vec<_> = self
                .chain
                .closest_section_info(destination)
                .1
                .member_nodes()
                .map(|p2p_node| *p2p_node.peer_addr())
                .collect();
            debug!("Sending BootstrapResponse::Rebootstrap to {}", p2p_node);
            BootstrapResponse::Rebootstrap(conn_infos)
        };
        self.core
            .send_direct_message(p2p_node.peer_addr(), Variant::BootstrapResponse(response));
    }

    fn handle_join_request(&mut self, p2p_node: P2pNode, join_request: JoinRequest) {
        debug!(
            "Received JoinRequest from {} for v{}",
            p2p_node, join_request.elders_version
        );

        if join_request.elders_version < self.chain.our_info().version() {
            self.resend_bootstrap_response_join(&p2p_node);
        }

        let pub_id = *p2p_node.public_id();
        if !self.our_prefix().matches(pub_id.name()) {
            debug!(
                "Ignoring JoinRequest from {} - name doesn't match our prefix {:?}.",
                pub_id,
                self.our_prefix()
            );
            return;
        }

        if self.chain.is_peer_our_member(&pub_id) {
            debug!(
                "Ignoring JoinRequest from {} - already member of our section.",
                pub_id
            );
            return;
        }

        if self.chain.is_in_online_backlog(&pub_id) {
            debug!("Ignoring JoinRequest from {} - already in backlog.", pub_id);
            return;
        }

        // This joining node is being relocated to us.
        let (age, their_knowledge) = if let Some(payload) = join_request.relocate_payload {
            if !payload.verify_identity(&pub_id) {
                debug!(
                    "Ignoring relocation JoinRequest from {} - invalid signature.",
                    pub_id
                );
                return;
            }

            let details = payload.relocate_details();

            if !self.our_prefix().matches(&details.destination) {
                debug!(
                    "Ignoring relocation JoinRequest from {} - destination {} doesn't match \
                     our prefix {:?}.",
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

    fn handle_member_knowledge(&mut self, p2p_node: P2pNode, payload: MemberKnowledge) {
        trace!("Received {:?} from {:?}", payload, p2p_node);

        if self.chain.is_peer_our_active_member(p2p_node.public_id()) {
            self.members_knowledge
                .entry(*p2p_node.name())
                .or_default()
                .update(payload);
        }

        self.send_parsec_gossip(Some((payload.parsec_version, p2p_node)))
    }

    fn handle_parsec_request(
        &mut self,
        msg_version: u64,
        par_request: parsec::Request,
        p2p_node: P2pNode,
        outbox: &mut dyn EventBox,
    ) -> Result<Transition> {
        trace!(
            "handle parsec request v{} from {} (last: v{})",
            msg_version,
            p2p_node.public_id(),
            self.parsec_map.last_version(),
        );

        let response =
            self.parsec_map
                .handle_request(msg_version, par_request, *p2p_node.public_id());

        if let Some(response) = response {
            trace!("send parsec response v{} to {:?}", msg_version, p2p_node,);
            self.core
                .send_direct_message(p2p_node.peer_addr(), response);
        }

        if msg_version == self.parsec_map.last_version() {
            self.parsec_poll(outbox)
        } else {
            Ok(Transition::Stay)
        }
    }

    fn handle_parsec_response(
        &mut self,
        msg_version: u64,
        par_response: parsec::Response,
        pub_id: PublicId,
        outbox: &mut dyn EventBox,
    ) -> Result<Transition> {
        trace!("handle parsec response v{} from {}", msg_version, pub_id);

        self.parsec_map
            .handle_response(msg_version, par_response, pub_id);

        if msg_version == self.parsec_map.last_version() {
            self.parsec_poll(outbox)
        } else {
            Ok(Transition::Stay)
        }
    }

    fn handle_bounce(&mut self, sender: P2pNode, sender_version: Option<u64>, msg_bytes: Bytes) {
        if let Some((_, version)) = self.chain.find_section_by_member(sender.public_id()) {
            if sender_version
                .map(|sender_version| sender_version < version)
                .unwrap_or(true)
            {
                trace!(
                    "Received Bounce of {:?} from {}. Peer is lagging behind, resending in {:?}",
                    MessageHash::from_bytes(&msg_bytes),
                    sender,
                    BOUNCE_RESEND_DELAY
                );
                self.core.send_message_to_target_later(
                    sender.peer_addr(),
                    msg_bytes,
                    BOUNCE_RESEND_DELAY,
                );
            } else {
                trace!(
                    "Received Bounce of {:?} from {}. Peer has moved on, not resending",
                    MessageHash::from_bytes(&msg_bytes),
                    sender
                );
            }
        } else {
            trace!(
                "Received Bounce of {:?} from {}. Peer not known, not resending",
                MessageHash::from_bytes(&msg_bytes),
                sender
            );
        }
    }

    ////////////////////////////////////////////////////////////////////////////
    // Accumulated events handling
    ////////////////////////////////////////////////////////////////////////////

    fn parsec_poll(&mut self, outbox: &mut dyn EventBox) -> Result<Transition, RoutingError> {
        while let Some(block) = self.parsec_map.poll() {
            let parsec_version = self.parsec_map.last_version();
            match block.payload() {
                Observation::Accusation { .. } => {
                    // FIXME: Handle properly
                    unreachable!("...")
                }
                Observation::Genesis {
                    group,
                    related_info,
                } => {
                    // FIXME: Validate with Chain info.

                    trace!(
                        "Parsec Genesis {}: group {:?} - related_info {}",
                        parsec_version,
                        group,
                        related_info.len()
                    );

                    self.chain.handle_genesis_event(group, related_info)?;
                    self.pfx_is_successfully_polled = true;

                    continue;
                }
                Observation::OpaquePayload(event) => {
                    if let Some(proof) = block.proofs().iter().next().map(|p| Proof {
                        pub_id: *p.public_id(),
                        sig: *p.signature(),
                    }) {
                        trace!(
                            "Parsec OpaquePayload {}: {} - {:?}",
                            parsec_version,
                            proof.pub_id(),
                            event
                        );
                        self.chain.handle_opaque_event(event, proof)?;
                    }
                }
                Observation::Add { peer_id, .. } => {
                    log_or_panic!(
                        log::Level::Error,
                        "Unexpected Parsec Add {}: - {}",
                        parsec_version,
                        peer_id
                    );
                }
                Observation::Remove { peer_id, .. } => {
                    log_or_panic!(
                        log::Level::Error,
                        "Unexpected Parsec Remove {}: - {}",
                        parsec_version,
                        peer_id
                    );
                }
                obs @ Observation::StartDkg(_) | obs @ Observation::DkgMessage(_) => {
                    log_or_panic!(
                        log::Level::Error,
                        "parsec_poll polled internal Observation {}: {:?}",
                        parsec_version,
                        obs
                    );
                }
                Observation::DkgResult {
                    participants,
                    dkg_result,
                } => {
                    self.chain
                        .handle_dkg_result_event(participants, dkg_result)?;
                    self.handle_dkg_result_event(participants, dkg_result)?;
                }
            }

            match self.chain_poll(outbox)? {
                Transition::Stay => (),
                transition => return Ok(transition),
            }
        }

        self.check_voting_status();

        Ok(Transition::Stay)
    }

    fn chain_poll(&mut self, outbox: &mut dyn EventBox) -> Result<Transition, RoutingError> {
        let mut old_pfx = *self.chain.our_prefix();
        let mut was_elder = self.chain.is_self_elder();

        while let Some(event) = self.chain.poll_accumulated()? {
            match event {
                PollAccumulated::AccumulatedEvent(event) => {
                    match self.handle_accumulated_event(event, old_pfx, was_elder, outbox)? {
                        Transition::Stay => (),
                        transition => return Ok(transition),
                    }
                }
                PollAccumulated::RelocateDetails(details) => {
                    self.handle_relocate_polled(details)?;
                }
                PollAccumulated::PromoteDemoteElders(new_infos) => {
                    self.handle_promote_and_demote_elders(new_infos)?;
                }
            }

            old_pfx = *self.chain.our_prefix();
            was_elder = self.chain.is_self_elder();
        }

        Ok(Transition::Stay)
    }

    fn handle_accumulated_event(
        &mut self,
        event: AccumulatedEvent,
        old_pfx: Prefix<XorName>,
        was_elder: bool,
        outbox: &mut dyn EventBox,
    ) -> Result<Transition, RoutingError> {
        trace!("Handle accumulated event: {:?}", event);

        match event.content {
            AccumulatingEvent::StartDkg(_) => {
                log_or_panic!(
                    log::Level::Error,
                    "StartDkg came out of Parsec - this shouldn't happen"
                );
            }
            AccumulatingEvent::Online(payload) => {
                self.handle_online_event(payload, outbox)?;
            }
            AccumulatingEvent::Offline(pub_id) => {
                self.handle_offline_event(pub_id, outbox)?;
            }
            AccumulatingEvent::SectionInfo(_, _) => {
                return self.handle_section_info_event(
                    old_pfx,
                    was_elder,
                    event.elders_change,
                    outbox,
                );
            }
            AccumulatingEvent::NeighbourInfo(elders_info) => {
                self.handle_neighbour_info_event(elders_info, event.elders_change)?;
            }
            AccumulatingEvent::TheirKeyInfo(key_info) => {
                self.handle_their_key_info_event(key_info)?
            }
            AccumulatingEvent::AckMessage(_payload) => {
                // Update their_knowledge is handled within the chain.
            }
            AccumulatingEvent::SendAckMessage(payload) => {
                self.handle_send_ack_message_event(payload)?
            }
            AccumulatingEvent::ParsecPrune => self.handle_prune_event()?,
            AccumulatingEvent::Relocate(payload) => self.handle_relocate_event(payload, outbox)?,
            AccumulatingEvent::RelocatePrepare(pub_id, count) => {
                self.handle_relocate_prepare_event(pub_id, count, outbox);
            }
            AccumulatingEvent::User(payload) => self.handle_user_event(payload, outbox)?,
        }

        Ok(Transition::Stay)
    }

    fn handle_relocate_polled(&mut self, details: RelocateDetails) -> Result<(), RoutingError> {
        if !self.chain.is_self_elder() {
            return Ok(());
        }

        self.vote_for_relocate_prepare(details, INITIAL_RELOCATE_COOL_DOWN_COUNT_DOWN);

        Ok(())
    }

    fn handle_promote_and_demote_elders(
        &mut self,
        new_infos: Vec<EldersInfo>,
    ) -> Result<(), RoutingError> {
        if !self.chain.is_self_elder() {
            return Ok(());
        }

        for info in new_infos {
            let participants: BTreeSet<_> = info.member_ids().copied().collect();
            let _ = self.dkg_cache.insert(participants.clone(), info);
            self.vote_for_event(AccumulatingEvent::StartDkg(participants));
        }

        Ok(())
    }

    fn handle_online_event(
        &mut self,
        payload: OnlinePayload,
        outbox: &mut dyn EventBox,
    ) -> Result<(), RoutingError> {
        if !self.chain.can_add_member(payload.p2p_node.public_id()) {
            info!("ignore Online: {:?}.", payload);
        } else {
            info!("handle Online: {:?}.", payload);

            let pub_id = *payload.p2p_node.public_id();
            self.chain.add_member(payload.p2p_node.clone(), payload.age);
            self.chain.increment_age_counters(&pub_id);

            if self.chain.is_self_elder() {
                self.send_node_approval(payload.p2p_node, payload.their_knowledge, outbox);
                self.print_rt_size();
            }
        }

        Ok(())
    }

    fn handle_relocate_prepare_event(
        &mut self,
        payload: RelocateDetails,
        count_down: i32,
        _outbox: &mut dyn EventBox,
    ) {
        if !self.chain.is_self_elder() {
            return;
        }

        if count_down > 0 {
            self.vote_for_relocate_prepare(payload, count_down - 1);
        } else {
            self.vote_for_relocate(payload);
        }
    }

    fn handle_relocate_event(
        &mut self,
        details: RelocateDetails,
        _outbox: &mut dyn EventBox,
    ) -> Result<(), RoutingError> {
        if !self.chain.can_remove_member(&details.pub_id) {
            info!("ignore Relocate: {:?} - not a member", details);
            return Ok(());
        }

        info!("handle Relocate: {:?}", details);

        let node_knowledge = match self.chain.remove_member(&details.pub_id) {
            MemberState::Relocating { node_knowledge } => node_knowledge,
            state => {
                log_or_panic!(
                    log::Level::Error,
                    "Expected the state of {} to be Relocating, but was {:?}",
                    details.pub_id,
                    state,
                );
                return Ok(());
            }
        };

        let _ = self.members_knowledge.remove(details.pub_id.name());

        if !self.chain.is_self_elder() {
            return Ok(());
        }

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

    fn handle_offline_event(
        &mut self,
        pub_id: PublicId,
        _outbox: &mut dyn EventBox,
    ) -> Result<(), RoutingError> {
        if !self.chain.can_remove_member(&pub_id) {
            info!("ignore Offline: {}", pub_id);
        } else {
            info!("handle Offline: {}", pub_id);

            self.chain.increment_age_counters(&pub_id);
            let _ = self.chain.remove_member(&pub_id);
            self.disconnect_by_id_lookup(&pub_id);
            let _ = self.members_knowledge.remove(pub_id.name());
        }

        Ok(())
    }

    fn handle_dkg_result_event(
        &mut self,
        participants: &BTreeSet<PublicId>,
        dkg_result: &DkgResultWrapper,
    ) -> Result<(), RoutingError> {
        if !self.chain.is_self_elder() {
            return Ok(());
        }

        if let Some(info) = self.dkg_cache.remove(participants) {
            info!("handle DkgResult: {:?}", participants);
            self.vote_for_section_info(info, dkg_result.0.public_key_set.public_key())?;
        } else {
            log_or_panic!(
                log::Level::Error,
                "DKG for an unexpected info {:?} (expected: {{{:?}}})",
                participants,
                self.dkg_cache.keys().format(", ")
            );
        }
        Ok(())
    }

    fn handle_section_info_event(
        &mut self,
        old_pfx: Prefix<XorName>,
        was_elder: bool,
        elders_change: EldersChange,
        outbox: &mut dyn EventBox,
    ) -> Result<Transition, RoutingError> {
        let elders_info = self.chain.our_info();
        let info_prefix = *elders_info.prefix();
        let info_version = elders_info.version();
        let is_elder = elders_info.is_member(self.core.full_id.public_id());

        if was_elder || is_elder {
            info!("handle SectionInfo: {:?}", elders_info);
        } else {
            trace!("unhandled SectionInfo");
            return Ok(Transition::Stay);
        }

        let complete_data = if info_prefix.is_extension_of(&old_pfx) {
            self.prepare_finalise_split()?
        } else if old_pfx.is_extension_of(&info_prefix) {
            panic!("Merge not supported: {:?} -> {:?}", old_pfx, info_prefix,);
        } else {
            self.prepare_reset_parsec()?
        };

        if !is_elder {
            // Demote after the parsec reset, i.e genesis prefix info is for the new parsec,
            // i.e the one that would be received with NodeApproval.
            self.process_post_reset_events(old_pfx, complete_data.to_process);
            self.demote(complete_data.gen_pfx_info);

            info!("Demoted");
            outbox.send_event(Event::Demoted);

            return Ok(Transition::Stay);
        }

        self.reset_parsec_with_data(complete_data.gen_pfx_info, complete_data.to_vote_again)?;
        self.process_post_reset_events(old_pfx, complete_data.to_process);

        self.update_peer_connections(&elders_change);
        self.send_neighbour_infos();
        self.send_genesis_updates();
        self.send_member_knowledge();

        // Vote to update our self messages proof
        self.vote_for_send_ack_message(SendAckMessagePayload {
            ack_prefix: info_prefix,
            ack_version: info_version,
        });

        self.print_rt_size();
        if let Some(to_send) = complete_data.event_to_send {
            outbox.send_event(to_send);
        }

        if !was_elder {
            info!("Promoted");
            outbox.send_event(Event::Promoted);
        }

        Ok(Transition::Stay)
    }

    fn handle_neighbour_info_event(
        &mut self,
        elders_info: EldersInfo,
        neighbour_change: EldersChange,
    ) -> Result<(), RoutingError> {
        info!("handle NeighbourInfo: {:?}", elders_info);

        if !self.chain.is_self_elder() {
            return Ok(());
        }

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
        if !self.chain.is_self_elder() {
            return Ok(());
        }

        self.vote_for_send_ack_message(SendAckMessagePayload {
            ack_prefix: *key_info.prefix(),
            ack_version: key_info.version(),
        });
        Ok(())
    }

    fn handle_send_ack_message_event(
        &mut self,
        ack_payload: SendAckMessagePayload,
    ) -> Result<(), RoutingError> {
        if !self.chain.is_self_elder() {
            return Ok(());
        }

        let src = SrcLocation::Section(*self.our_prefix());
        let dst = DstLocation::Section(ack_payload.ack_prefix.name());
        let variant = Variant::AckMessage {
            src_prefix: *self.our_prefix(),
            ack_version: ack_payload.ack_version,
        };

        self.send_routing_message(src, dst, variant, None)
    }

    fn handle_prune_event(&mut self) -> Result<(), RoutingError> {
        if !self.chain.is_self_elder() {
            debug!("Unhandled ParsecPrune event");
            return Ok(());
        }

        if self.chain.split_in_progress() {
            log_or_panic!(
                log::Level::Warn,
                "Tring to prune parsec during prefix change.",
            );
            return Ok(());
        }
        if self.chain.churn_in_progress() {
            trace!("ignore ParsecPrune - churn in progress.");
            return Ok(());
        }

        info!("handle ParsecPrune");
        let complete_data = self.prepare_reset_parsec()?;
        self.reset_parsec_with_data(complete_data.gen_pfx_info, complete_data.to_vote_again)?;
        self.send_genesis_updates();
        self.send_member_knowledge();
        Ok(())
    }

    /// Handle an accumulated `User` event
    fn handle_user_event(
        &mut self,
        payload: Vec<u8>,
        outbox: &mut dyn EventBox,
    ) -> Result<(), RoutingError> {
        outbox.send_event(Event::Consensus(payload));
        Ok(())
    }

    ////////////////////////////////////////////////////////////////////////////
    // Parsec and Chain management
    ////////////////////////////////////////////////////////////////////////////

    fn init_parsec(&mut self) {
        self.pfx_is_successfully_polled = false;
        self.parsec_map.init(
            &mut self.core.rng,
            self.core.full_id.clone(),
            &self.gen_pfx_info,
        )
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

    fn demote(&mut self, gen_pfx_info: GenesisPfxInfo) {
        self.gen_pfx_info = gen_pfx_info.clone();
        self.init_parsec();
        self.chain = Chain::new(
            self.chain.network_cfg(),
            *self.core.full_id.public_id(),
            gen_pfx_info,
            None,
        );
    }

    fn maintain_parsec(&mut self) {
        if self.parsec_map.needs_pruning() {
            self.vote_for_event(AccumulatingEvent::ParsecPrune);
            self.parsec_map.set_pruning_voted_for();
        }
    }

    // Checking members vote status and vote to remove those non-resposive nodes.
    fn check_voting_status(&mut self) {
        let unresponsive_nodes = self.chain.check_vote_status();
        for pub_id in &unresponsive_nodes {
            info!("Voting for unresponsive node {:?}", pub_id);
            self.parsec_map
                .vote_for(AccumulatingEvent::Offline(*pub_id).into_network_event());
        }
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

    fn vote_for_send_ack_message(&mut self, ack_payload: SendAckMessagePayload) {
        let has_their_keys = self.chain.get_their_key_infos().any(|(_, info)| {
            *info.prefix() == ack_payload.ack_prefix && info.version() == ack_payload.ack_version
        });

        if has_their_keys {
            self.vote_for_event(AccumulatingEvent::SendAckMessage(ack_payload));
        }
    }

    fn vote_for_event(&mut self, event: AccumulatingEvent) {
        self.vote_for_network_event(event.into_network_event())
    }

    fn vote_for_network_event(&mut self, event: NetworkEvent) {
        trace!("Vote for Event {:?}", event);
        self.parsec_map.vote_for(event);
    }

    ////////////////////////////////////////////////////////////////////////////
    // Message sending
    ////////////////////////////////////////////////////////////////////////////

    fn send_neighbour_infos(&mut self) {
        self.chain.other_prefixes().iter().for_each(|pfx| {
            let src = SrcLocation::Section(*self.our_prefix());
            let dst = DstLocation::Prefix(*pfx);
            let variant = Variant::NeighbourInfo(self.chain.our_info().clone());

            if let Err(err) = self.send_routing_message(src, dst, variant, None) {
                debug!("Failed to send NeighbourInfo: {:?}", err);
            }
        });
    }

    // Send `GenesisUpdate` message to all non-elders.
    fn send_genesis_updates(&mut self) {
        for (recipient, msg) in self.create_genesis_updates() {
            trace!(
                "Send GenesisUpdate({:?}) to {}",
                self.gen_pfx_info,
                recipient
            );

            self.core.send_direct_message(
                recipient.peer_addr(),
                Variant::MessageSignature(Box::new(msg)),
            );
        }
    }

    fn create_genesis_updates(&self) -> Vec<(P2pNode, AccumulatingMessage)> {
        let payload = self.gen_pfx_info.trimmed();

        self.chain
            .adults_and_infants_p2p_nodes()
            .cloned()
            .filter_map(|recipient| {
                let variant = Variant::GenesisUpdate(Box::new(payload.clone()));
                let dst = DstLocation::Node(*recipient.name());
                let version = self
                    .members_knowledge
                    .get(recipient.name())
                    .map(|knowledge| knowledge.elders_version)
                    .unwrap_or(0);

                match self.to_accumulating_message(dst, variant, Some(version)) {
                    Ok(msg) => Some((recipient, msg)),
                    Err(error) => {
                        error!("Failed to create signed message: {:?}", error);
                        None
                    }
                }
            })
            .collect()
    }

    fn send_member_knowledge(&mut self) {
        let payload = MemberKnowledge {
            elders_version: self.chain.our_info().version(),
            parsec_version: self.parsec_map.last_version(),
        };

        for recipient in self.chain.our_info().member_nodes() {
            if recipient.public_id() == self.id() {
                continue;
            }

            trace!("Send {:?} to {:?}", payload, recipient);
            self.core
                .send_direct_message(recipient.peer_addr(), Variant::MemberKnowledge(payload))
        }
    }

    // Send NodeApproval to the current candidate which makes them a section member and allows them
    // to passively participate in parsec consensus (that is, they can receive gossip and poll
    // consensused blocks out of parsec, but they can't vote yet)
    fn send_node_approval(
        &mut self,
        p2p_node: P2pNode,
        their_knowledge: Option<u64>,
        _outbox: &mut dyn EventBox,
    ) {
        info!(
            "Our section with {:?} has approved candidate {}.",
            self.our_prefix(),
            p2p_node
        );

        let trimmed_info = self.gen_pfx_info.trimmed();
        let src = SrcLocation::Section(*trimmed_info.elders_info.prefix());
        let dst = DstLocation::Node(*p2p_node.name());

        let variant = Variant::NodeApproval(Box::new(trimmed_info));
        if let Err(error) = self.send_routing_message(src, dst, variant, their_knowledge) {
            debug!("Failed sending NodeApproval to {}: {:?}", p2p_node, error);
        }
    }

    fn send_parsec_gossip(&mut self, target: Option<(u64, P2pNode)>) {
        let (version, gossip_target) = match target {
            Some((v, p)) => (v, p),
            None => {
                if !self.parsec_map.should_send_gossip() {
                    return;
                }

                if let Some(recipient) = self.choose_gossip_recipient() {
                    let version = self.parsec_map.last_version();
                    (version, recipient)
                } else {
                    return;
                }
            }
        };

        match self
            .parsec_map
            .create_gossip(version, gossip_target.public_id())
        {
            Ok(msg) => {
                trace!("send parsec request v{} to {:?}", version, gossip_target,);
                self.core
                    .send_direct_message(gossip_target.peer_addr(), msg);
            }
            Err(error) => {
                trace!(
                    "failed to send parsec request v{} to {:?}: {:?}",
                    version,
                    gossip_target,
                    error
                );
            }
        }
    }

    fn choose_gossip_recipient(&mut self) -> Option<P2pNode> {
        let recipients = self.parsec_map.gossip_recipients();
        if recipients.is_empty() {
            trace!("not sending parsec request: no recipients");
            return None;
        }

        let mut p2p_recipients: Vec<_> = recipients
            .into_iter()
            .filter_map(|pub_id| self.chain.get_member_p2p_node(pub_id.name()))
            .cloned()
            .collect();

        if p2p_recipients.is_empty() {
            log_or_panic!(
                log::Level::Error,
                "not sending parsec request: not connected to any gossip recipient.",
            );
            return None;
        }

        let rand_index = self.core.rng.gen_range(0, p2p_recipients.len());
        Some(p2p_recipients.swap_remove(rand_index))
    }

    fn send_bounce(&mut self, recipient: &SocketAddr, msg_bytes: Bytes) {
        let variant = Variant::Bounce {
            elders_version: Some(self.chain.our_info().version()),
            message: msg_bytes,
        };

        self.core.send_direct_message(recipient, variant)
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
                "Resend Join to {} with version {}",
                p2p_node,
                response_section.version()
            );
            self.core.send_direct_message(
                p2p_node.peer_addr(),
                Variant::BootstrapResponse(BootstrapResponse::Join(response_section)),
            );
        }
    }

    // After parsec reset, resend any unaccumulated voted messages to everyone that needs
    // them but possibly did not receive them already.
    fn resend_pending_voted_messages(&mut self, _old_pfx: Prefix<XorName>) {
        for (_, msg) in mem::take(&mut self.pending_voted_msgs) {
            let msg = match MessageWithBytes::new(msg) {
                Ok(msg) => msg,
                Err(err) => {
                    error!("Failed to make message {:?}", err);
                    continue;
                }
            };
            match self.send_signed_message(&msg) {
                Ok(()) => trace!("Resend {:?}", msg),
                Err(error) => debug!("Failed to resend {:?}: {:?}", msg, error),
            }
        }
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
                "Not part of the source location. Not sending message {:?} -> {:?}: {:?}.",
                src,
                dst,
                variant
            );
            return Ok(());
        }

        // If the source is single, we don't even need to send signatures, so let's cut this short
        if src.is_single() {
            let msg = Message::single_src(&self.core.full_id, dst, variant)?;
            let msg = MessageWithBytes::new(msg)?;
            return self.handle_accumulated_message(msg);
        }

        let accumulating_msg =
            self.to_accumulating_message(dst, variant, node_knowledge_override)?;

        for target in self.get_signature_targets(&dst) {
            if target.name() == self.name() {
                if let Some(msg) = self.sig_accumulator.add_proof(accumulating_msg.clone()) {
                    self.handle_accumulated_message(msg)?;
                }
            } else {
                trace!(
                    "Sending a signature for {:?} to {:?}",
                    accumulating_msg.content,
                    target,
                );
                self.core.send_direct_message(
                    target.peer_addr(),
                    Variant::MessageSignature(Box::new(accumulating_msg.clone())),
                );
            }
        }

        Ok(())
    }

    // Signs and proves the given `RoutingMessage` and wraps it in `SignedRoutingMessage`.
    fn to_accumulating_message(
        &self,
        dst: DstLocation,
        variant: Variant,
        node_knowledge_override: Option<u64>,
    ) -> Result<AccumulatingMessage> {
        let proof = self.chain.prove(&dst, node_knowledge_override);
        let pk_set = self.chain.our_section_bls_keys().clone();
        let secret_key = self.chain.our_section_bls_secret_key_share()?;

        let content = PlainMessage {
            src: *self.our_prefix(),
            dst,
            variant,
        };

        AccumulatingMessage::new(content, secret_key, pk_set, proof)
    }

    // Returns the set of peers that are responsible for collecting signatures to verify a message;
    // this may contain us or only other nodes.
    fn get_signature_targets(&self, dst: &DstLocation) -> Vec<P2pNode> {
        let dst_name = match dst {
            DstLocation::Node(name) => *name,
            DstLocation::Section(name) => *name,
            DstLocation::Prefix(prefix) => prefix.name(),
            DstLocation::Direct => {
                log_or_panic!(
                    log::Level::Error,
                    "Invalid destination for signature targets: {:?}",
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

    // Send message over the network.
    fn send_signed_message(&mut self, msg: &MessageWithBytes) -> Result<()> {
        let (targets, dg_size) = self.chain.targets(msg.message_dst())?;

        trace!("Sending {:?} via targets {:?}", msg, targets);

        let targets: Vec<_> = targets
            .into_iter()
            .filter(|p2p_node| {
                self.core
                    .msg_filter
                    .filter_outgoing(msg, p2p_node.public_id())
                    .is_new()
            })
            .map(|node| *node.peer_addr())
            .collect();

        let cheap_bytes_clone = msg.full_bytes().clone();
        self.core
            .send_message_to_targets(&targets, dg_size, cheap_bytes_clone);

        Ok(())
    }

    ////////////////////////////////////////////////////////////////////////////
    // Miscellaneous
    ////////////////////////////////////////////////////////////////////////////

    fn print_rt_size(&self) {
        const TABLE_LVL: log::Level = log::Level::Info;
        if log::log_enabled!(TABLE_LVL) {
            let status_str = format!("Routing Table size: {:3}", self.chain.elders().count());
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

    // Ignore stale GenesisUpdates
    fn is_genesis_update_new(&self, gen_pfx_info: &GenesisPfxInfo) -> bool {
        gen_pfx_info.parsec_version > self.gen_pfx_info.parsec_version
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

                self.core.network_service.disconnect(*p2p_node.peer_addr());
            }
        }
    }

    fn disconnect_by_id_lookup(&mut self, pub_id: &PublicId) {
        if let Some(node) = self.chain.get_p2p_node(pub_id.name()) {
            let peer_addr = *node.peer_addr();
            self.core.network_service.disconnect(peer_addr);
        } else {
            log_or_panic!(
                log::Level::Error,
                "Can't disconnect from node we can't lookup in Chain: {}.",
                pub_id
            );
        };
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

    fn check_signed_relocation_details(&self, msg: &SignedRelocateDetails) -> bool {
        msg.signed_msg()
            .verify(self.chain.get_their_key_infos())
            .and_then(VerifyStatus::require_full)
            .map_err(|error| {
                messages::log_verify_failure(
                    msg.signed_msg(),
                    &error,
                    self.chain.get_their_key_infos(),
                );
                error
            })
            .is_ok()
    }
}

impl Base for ApprovedPeer {
    fn core(&self) -> &Core {
        &self.core
    }

    fn core_mut(&mut self) -> &mut Core {
        &mut self.core
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

    fn set_log_ident(&self) -> log_utils::Guard {
        use std::fmt::Write;
        log_utils::set_ident(|buffer| {
            write!(
                buffer,
                "{}({}({:b})) ",
                if self.chain.is_self_elder() {
                    "Elder"
                } else {
                    "Adult"
                },
                self.name(),
                self.our_prefix()
            )
        })
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
        if self.timer_token == token {
            if self.chain.is_self_elder() {
                self.timer_token = self.core.timer.schedule(self.parsec_map.gossip_period());
                self.parsec_map.reset_gossip_period();
            } else {
                // TODO: send this only when the knowledge changes, not periodically.
                self.send_member_knowledge();
                self.timer_token = self.core.timer.schedule(KNOWLEDGE_TIMEOUT);
            }
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
                    error!("Parsec poll failed: {:?}", error);
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
        self.core
            .network_service
            .service_mut()
            .disconnect_from(addr);
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
            trace!("ConnectionFailure from member {}", node);

            // Ping the peer to trigger lost peer detection.
            let addr = *node.peer_addr();
            self.core.send_direct_message(&addr, Variant::Ping);
        } else {
            trace!("ConnectionFailure from non-member {}", addr);
        }

        Transition::Stay
    }

    fn handle_peer_lost(
        &mut self,
        peer_addr: SocketAddr,
        _outbox: &mut dyn EventBox,
    ) -> Transition {
        let pub_id = if let Some(node) = self.chain.find_p2p_node_from_addr(&peer_addr) {
            debug!("Lost known peer {}", node);
            *node.public_id()
        } else {
            trace!("Lost unknown peer {}", peer_addr);
            return Transition::Stay;
        };

        if self.chain.is_self_elder() && self.chain.is_peer_our_member(&pub_id) {
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

    fn unhandled_message(&mut self, sender: Option<SocketAddr>, msg: Message, msg_bytes: Bytes) {
        let bounce = match msg.variant {
            Variant::MessageSignature(_) => true,
            Variant::Relocate(_) if self.chain.is_self_elder() => true,
            Variant::JoinRequest(_)
            | Variant::NeighbourInfo(_)
            | Variant::UserMessage(_)
            | Variant::AckMessage { .. }
                if !self.chain.is_self_elder() =>
            {
                true
            }
            Variant::GenesisUpdate(_) => self.chain.is_self_elder(),
            Variant::BootstrapResponse(_) | Variant::NodeApproval(_) | Variant::Ping => false,
            Variant::MemberKnowledge(_) if !self.chain.is_self_elder() => false,

            _ => unreachable!("unexpected unhandled message: {:?}", msg),
        };

        if bounce {
            if let Some(sender) = sender {
                debug!(
                    "Unhandled message - bouncing: {:?}, hash: {:?}",
                    msg,
                    MessageHash::from_bytes(&msg_bytes)
                );

                self.send_bounce(&sender, msg_bytes);
            } else {
                trace!("Unhandled accumulated message, discarding: {:?}", msg);
            }
        } else {
            debug!("Unhandled message from {:?}, discarding: {:?}", sender, msg);
        }
    }

    fn relay_message(
        &mut self,
        _sender: Option<SocketAddr>,
        message: &MessageWithBytes,
    ) -> Result<()> {
        self.send_signed_message(message)
    }

    fn should_handle_message(&self, msg: &Message) -> bool {
        match &msg.variant {
            Variant::BootstrapRequest(_)
            | Variant::ParsecRequest(..)
            | Variant::ParsecResponse(..)
            | Variant::Bounce { .. } => true,

            Variant::NeighbourInfo(_)
            | Variant::UserMessage(_)
            | Variant::AckMessage { .. }
            | Variant::JoinRequest(_)
            | Variant::MemberKnowledge(_) => self.chain.is_self_elder(),

            Variant::GenesisUpdate(info) => {
                !self.chain.is_self_elder() && self.is_genesis_update_new(info)
            }
            Variant::Relocate(_) => !self.chain.is_self_elder(),

            Variant::MessageSignature(accumulating_msg) => {
                match &accumulating_msg.content.variant {
                    Variant::NeighbourInfo(_)
                    | Variant::UserMessage(_)
                    | Variant::NodeApproval(_)
                    | Variant::AckMessage { .. }
                    | Variant::Relocate(_) => true,

                    Variant::GenesisUpdate(info) => {
                        !self.chain.is_self_elder() && self.is_genesis_update_new(info)
                    }

                    // These variants are not be signature-accumulated
                    Variant::MessageSignature(_)
                    | Variant::BootstrapRequest(_)
                    | Variant::BootstrapResponse(_)
                    | Variant::JoinRequest(_)
                    | Variant::MemberKnowledge(_)
                    | Variant::ParsecRequest(..)
                    | Variant::ParsecResponse(..)
                    | Variant::Ping
                    | Variant::Bounce { .. } => false,
                }
            }

            Variant::BootstrapResponse(_) | Variant::NodeApproval(_) | Variant::Ping => false,
        }
    }

    fn verify_message(&self, msg: &Message) -> Result<bool, RoutingError> {
        self.verify_message_quiet(msg).map_err(|error| {
            messages::log_verify_failure(msg, &error, self.chain.get_their_key_infos());
            error
        })
    }
}

#[cfg(feature = "mock_base")]
impl ApprovedPeer {
    pub fn chain(&self) -> &Chain {
        &self.chain
    }

    pub fn has_unpolled_observations(&self) -> bool {
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
        self.core
            .send_message_to_targets(dst_targets, dg_size, message);
        Ok(())
    }

    pub fn parsec_last_version(&self) -> u64 {
        self.parsec_map.last_version()
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
