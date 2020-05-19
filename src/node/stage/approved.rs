// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    consensus::{
        self, AccumulatingEvent, AccumulatingProof, ConsensusEngine, DkgResultWrapper,
        EventSigPayload, GenesisPrefixInfo, IntoAccumulatingEvent, NeighbourEldersRemoved,
        NetworkEvent, OnlinePayload, ParsecRequest, ParsecResponse,
    },
    core::Core,
    error::{Result, RoutingError},
    event::Event,
    id::{P2pNode, PublicId},
    location::{DstLocation, SrcLocation},
    messages::{
        self, AccumulatingMessage, BootstrapResponse, JoinRequest, MemberKnowledge, Message,
        MessageAction, MessageHash, MessageWithBytes, PlainMessage, Variant, VerifyStatus,
    },
    pause::PausedState,
    relocation::{RelocateDetails, SignedRelocateDetails},
    rng::MainRng,
    routing_table,
    section::{
        EldersInfo, IndexedSecretKeyShare, MemberState, SectionKeysProvider, SharedState,
        SplitCache, MIN_AGE, MIN_AGE_COUNTER,
    },
    signature_accumulator::SignatureAccumulator,
    time::Duration,
    xor_space::{Prefix, XorName},
};
use bytes::Bytes;
use crossbeam_channel::Sender;
use itertools::Itertools;
use rand::Rng;
use std::{
    cmp::{self, Ordering},
    collections::{BTreeMap, BTreeSet},
    iter,
    net::SocketAddr,
};

// Send our knowledge in a similar speed as GOSSIP_TIMEOUT
const KNOWLEDGE_TIMEOUT: Duration = Duration::from_secs(2);

/// Number of RelocatePrepare to consensus before actually relocating a node.
/// This helps avoid relocated node receiving message they need to process from previous section.
const RELOCATE_COOL_DOWN_STEPS: i32 = 10;

// The approved stage - node is a full member of a section and is performing its duties according
// to its persona (infant, adult or elder).
pub struct Approved {
    pub consensus_engine: ConsensusEngine,
    pub shared_state: SharedState,
    section_keys_provider: SectionKeysProvider,
    sig_accumulator: SignatureAccumulator,
    genesis_prefix_info: GenesisPrefixInfo,
    timer_token: u64,
    // DKG cache
    dkg_cache: BTreeMap<BTreeSet<PublicId>, EldersInfo>,
    // The accumulated info during a split.
    split_cache: Option<SplitCache>,
    // Marker indicating we are processing churn event
    churn_in_progress: bool,
    // Flag indicating that our section members changed (a node joined or left) and we might need
    // to change our elders.
    members_changed: bool,
    /// The knowledge of the non-elder members about our section.
    members_knowledge: BTreeMap<XorName, MemberKnowledge>,
}

impl Approved {
    // Create the approved stage for the first node in the network.
    pub fn first(core: &mut Core) -> Result<Self> {
        let connection_info = core.transport.our_connection_info()?;
        let p2p_node = P2pNode::new(*core.id(), connection_info);
        let mut ages = BTreeMap::new();
        let _ = ages.insert(*p2p_node.name(), MIN_AGE_COUNTER);
        let first_dkg_result = consensus::generate_first_dkg_result(&mut core.rng);
        let genesis_prefix_info = GenesisPrefixInfo {
            elders_info: create_first_elders_info(p2p_node),
            public_keys: first_dkg_result.public_key_set,
            ages,
            parsec_version: 0,
        };

        Ok(Self::new(
            core,
            genesis_prefix_info,
            first_dkg_result.secret_key_share,
        ))
    }

    // Create the approved stage for a regular node.
    pub fn new(
        core: &mut Core,
        genesis_prefix_info: GenesisPrefixInfo,
        secret_key_share: Option<bls::SecretKeyShare>,
    ) -> Self {
        let timer_token = core.timer.schedule(KNOWLEDGE_TIMEOUT);

        let section_keys_provider = SectionKeysProvider::new(
            genesis_prefix_info.public_keys.clone(),
            secret_key_share.and_then(|key| {
                IndexedSecretKeyShare::new(key, core.name(), &genesis_prefix_info.elders_info)
            }),
        );

        let consensus_engine = ConsensusEngine::new(
            &mut core.rng,
            core.full_id.clone(),
            &genesis_prefix_info.elders_info,
            vec![],
            genesis_prefix_info.parsec_version,
        );
        let shared_state = SharedState::new(
            genesis_prefix_info.elders_info.clone(),
            genesis_prefix_info.public_keys.public_key(),
            genesis_prefix_info.ages.clone(),
        );

        Self {
            consensus_engine,
            shared_state,
            section_keys_provider,
            sig_accumulator: Default::default(),
            genesis_prefix_info,
            timer_token,
            dkg_cache: Default::default(),
            split_cache: None,
            churn_in_progress: false,
            members_changed: false,
            members_knowledge: Default::default(),
        }
    }

    pub fn pause(self, core: Core) -> PausedState {
        PausedState {
            network_params: core.network_params,
            consensus_engine: self.consensus_engine,
            shared_state: self.shared_state,
            section_keys_provider: self.section_keys_provider,
            full_id: core.full_id,
            genesis_prefix_info: self.genesis_prefix_info,
            msg_filter: core.msg_filter,
            msg_queue: core.msg_queue,
            transport: core.transport,
            transport_rx: None,
            sig_accumulator: self.sig_accumulator,
            split_cache: self.split_cache,
        }
    }

    // Create the approved stage by resuming a paused node.
    pub fn resume(
        state: PausedState,
        timer_tx: Sender<u64>,
        user_event_tx: Sender<Event>,
    ) -> (Self, Core) {
        let core = Core::resume(
            state.network_params,
            state.full_id,
            state.transport,
            state.msg_filter,
            state.msg_queue,
            timer_tx,
            user_event_tx,
        );

        let is_self_elder = state
            .shared_state
            .sections
            .our()
            .elders
            .contains_key(core.name());
        let timer_token = if is_self_elder {
            core.timer.schedule(state.consensus_engine.gossip_period())
        } else {
            core.timer.schedule(KNOWLEDGE_TIMEOUT)
        };

        let stage = Self {
            consensus_engine: state.consensus_engine,
            shared_state: state.shared_state,
            section_keys_provider: state.section_keys_provider,
            sig_accumulator: state.sig_accumulator,
            genesis_prefix_info: state.genesis_prefix_info,
            timer_token,
            split_cache: state.split_cache,
            // TODO: these fields should come from PausedState too
            dkg_cache: Default::default(),
            churn_in_progress: false,
            members_changed: false,
            members_knowledge: Default::default(),
        };

        (stage, core)
    }

    pub fn vote_for_event(&mut self, event: AccumulatingEvent) {
        self.consensus_engine.vote_for(event.into_network_event())
    }

    pub fn handle_connection_failure(&mut self, core: &mut Core, addr: SocketAddr) {
        let node = self
            .shared_state
            .our_members
            .active()
            .map(|info| &info.p2p_node)
            .find(|node| *node.peer_addr() == addr);

        if let Some(node) = node {
            trace!("ConnectionFailure from member {}", node);

            // Ping the peer to trigger lost peer detection.
            let addr = *node.peer_addr();
            core.send_direct_message(&addr, Variant::Ping);
        } else {
            trace!("ConnectionFailure from non-member {}", addr);
        }
    }

    pub fn handle_peer_lost(&mut self, core: &Core, peer_addr: SocketAddr) {
        let pub_id = if let Some(node) = self.shared_state.find_p2p_node_from_addr(&peer_addr) {
            debug!("Lost known peer {}", node);
            *node.public_id()
        } else {
            trace!("Lost unknown peer {}", peer_addr);
            return;
        };

        if self.is_our_elder(core.id()) && self.shared_state.our_members.contains(pub_id.name()) {
            self.vote_for_event(AccumulatingEvent::Offline(pub_id));
        }
    }

    pub fn handle_timeout(&mut self, core: &mut Core, token: u64) {
        if self.timer_token == token {
            if self.is_our_elder(core.id()) {
                self.timer_token = core.timer.schedule(self.consensus_engine.gossip_period());
                self.consensus_engine.reset_gossip_period();
            } else {
                // TODO: send this only when the knowledge changes, not periodically.
                self.send_member_knowledge(core);
                self.timer_token = core.timer.schedule(KNOWLEDGE_TIMEOUT);
            }
        }
    }

    pub fn finish_handle_input(&mut self, core: &mut Core) {
        if self.shared_state.our_info().elders.len() == 1 {
            // If we're the only node then invoke poll_all directly
            if let Err(error) = self.poll_all(core) {
                error!("poll failed: {:?}", error);
            }
        }

        self.consensus_engine.prune_if_needed();
        self.send_parsec_gossip(core, None);
    }

    /// Vote for a user-defined event.
    pub fn vote_for_user_event(&mut self, event: Vec<u8>) {
        self.vote_for_event(AccumulatingEvent::User(event));
    }

    /// Is the node with the given id an elder in our section?
    pub fn is_our_elder(&self, id: &PublicId) -> bool {
        self.shared_state
            .sections
            .our()
            .elders
            .contains_key(id.name())
    }

    /// Returns the current BLS public key set
    pub fn public_key_set(&self) -> &bls::PublicKeySet {
        self.section_keys_provider.public_key_set()
    }

    /// Returns the current BLS secret key share, if any
    pub fn secret_key_share(&self) -> Option<&bls::SecretKeyShare> {
        self.section_keys_provider
            .secret_key_share()
            .ok()
            .map(|share| &share.key)
    }

    ////////////////////////////////////////////////////////////////////////////
    // Message handling
    ////////////////////////////////////////////////////////////////////////////

    pub fn decide_message_action(&self, our_id: &PublicId, msg: &Message) -> Result<MessageAction> {
        let is_self_elder = self.is_our_elder(our_id);

        match &msg.variant {
            Variant::NeighbourInfo { .. } => {
                if is_self_elder && self.verify_message(msg)? {
                    Ok(MessageAction::Handle)
                } else {
                    Ok(MessageAction::Bounce)
                }
            }
            Variant::UserMessage(_) => {
                if self.should_handle_user_message(our_id, &msg.dst) && self.verify_message(msg)? {
                    Ok(MessageAction::Handle)
                } else {
                    Ok(MessageAction::Bounce)
                }
            }
            Variant::NodeApproval(_) => Ok(MessageAction::Discard),
            Variant::GenesisUpdate(info) => {
                if !self.should_handle_genesis_update(our_id, info) {
                    return Ok(MessageAction::Discard);
                }

                if self.verify_message(msg)? {
                    Ok(MessageAction::Handle)
                } else {
                    Ok(MessageAction::Bounce)
                }
            }
            Variant::Relocate(_) => {
                if self.verify_message(msg)? {
                    Ok(MessageAction::Handle)
                } else {
                    Ok(MessageAction::Bounce)
                }
            }
            Variant::MessageSignature(accumulating_msg) => {
                if !self.verify_message(msg)? {
                    return Ok(MessageAction::Discard);
                }

                match &accumulating_msg.content.variant {
                    Variant::NeighbourInfo { .. }
                    | Variant::UserMessage(_)
                    | Variant::NodeApproval(_)
                    | Variant::Relocate(_) => Ok(MessageAction::Handle),

                    Variant::GenesisUpdate(info) => {
                        if self.should_handle_genesis_update(our_id, info) {
                            Ok(MessageAction::Handle)
                        } else if is_self_elder {
                            Ok(MessageAction::Bounce)
                        } else {
                            Ok(MessageAction::Discard)
                        }
                    }

                    // These variants are not to be signature-accumulated
                    Variant::MessageSignature(_)
                    | Variant::BootstrapRequest(_)
                    | Variant::BootstrapResponse(_)
                    | Variant::JoinRequest(_)
                    | Variant::MemberKnowledge(_)
                    | Variant::ParsecRequest(..)
                    | Variant::ParsecResponse(..)
                    | Variant::Ping
                    | Variant::Bounce { .. } => Ok(MessageAction::Discard),
                }
            }
            Variant::JoinRequest(req) => {
                if !self.should_handle_join_request(our_id, req) {
                    return Ok(MessageAction::Bounce);
                }

                if !self.verify_message(msg)? {
                    return Ok(MessageAction::Discard);
                }

                Ok(MessageAction::Handle)
            }
            Variant::BootstrapResponse(_) => Ok(MessageAction::Discard),
            Variant::BootstrapRequest(_)
            | Variant::MemberKnowledge(_)
            | Variant::ParsecRequest(..)
            | Variant::ParsecResponse(..)
            | Variant::Bounce { .. } => {
                if self.verify_message(msg)? {
                    Ok(MessageAction::Handle)
                } else {
                    Ok(MessageAction::Discard)
                }
            }
            Variant::Ping => Ok(MessageAction::Discard),
        }
    }

    pub fn verify_message(&self, msg: &Message) -> Result<bool> {
        self.verify_message_quiet(msg).map_err(|error| {
            messages::log_verify_failure(msg, &error, self.shared_state.sections.keys());
            error
        })
    }

    pub fn handle_neighbour_info(
        &mut self,
        elders_info: EldersInfo,
        src_key: bls::PublicKey,
    ) -> Result<()> {
        if self.shared_state.sections.is_new_neighbour(&elders_info) {
            self.vote_for_event(AccumulatingEvent::NeighbourInfo(elders_info, src_key));
        } else {
            trace!("Ignore not new neighbour neighbour_info: {:?}", elders_info);
        }
        Ok(())
    }

    pub fn handle_genesis_update(
        &mut self,
        core: &mut Core,
        genesis_prefix_info: GenesisPrefixInfo,
    ) -> Result<()> {
        info!("Received GenesisUpdate: {:?}", genesis_prefix_info);

        core.msg_filter.reset();
        self.handle_elders_update(core, genesis_prefix_info);
        Ok(())
    }

    pub fn handle_relocate(
        &mut self,
        core: &mut Core,
        signed_msg: SignedRelocateDetails,
    ) -> Option<RelocateParams> {
        if signed_msg.relocate_details().pub_id != *core.id() {
            // This `Relocate` message is not for us - it's most likely a duplicate of a previous
            // message that we already handled.
            return None;
        }

        debug!(
            "Received Relocate message to join the section at {}.",
            signed_msg.relocate_details().destination
        );

        if !self.check_signed_relocation_details(&signed_msg) {
            return None;
        }

        let conn_infos: Vec<_> = self
            .shared_state
            .sections
            .our_elders()
            .map(|p2p_node| *p2p_node.peer_addr())
            .collect();

        // Disconnect from everyone we know.
        for addr in self
            .shared_state
            .known_nodes()
            .map(|node| *node.peer_addr())
        {
            core.transport.disconnect(addr);
        }

        Some(RelocateParams {
            details: signed_msg,
            conn_infos,
        })
    }

    /// Handles a signature of a `SignedMessage`, and if we have enough to verify the signed
    /// message, handles it.
    pub fn handle_message_signature(
        &mut self,
        core: &mut Core,
        msg: AccumulatingMessage,
        src: PublicId,
    ) -> Result<()> {
        if !self.shared_state.is_peer_elder(src.name()) {
            debug!(
                "Received message signature from not known elder (still use it) {}, {:?}",
                src, msg
            );
            // FIXME: currently accepting signatures from unknown senders to cater to lagging nodes.
            // Need to verify whether there are any security implications with doing this.
        }

        if let Some(msg) = self.sig_accumulator.add_proof(msg) {
            self.handle_accumulated_message(core, msg)?
        }

        Ok(())
    }

    // Note: As an adult, we should only give info about our section elders and they would
    // further guide the joining node. However this lead to a loop if the Adult is the new Elder so
    // we use the same code as for Elder and return Join in some cases.
    pub fn handle_bootstrap_request(
        &mut self,
        core: &mut Core,
        p2p_node: P2pNode,
        destination: XorName,
    ) {
        debug!(
            "Received BootstrapRequest to section at {} from {:?}.",
            destination, p2p_node
        );

        let response = if self.shared_state.our_prefix().matches(&destination) {
            let our_info = self.shared_state.our_info().clone();
            debug!(
                "Sending BootstrapResponse::Join to {:?} ({:?})",
                p2p_node, our_info
            );
            BootstrapResponse::Join(our_info)
        } else {
            let conn_infos: Vec<_> = self
                .shared_state
                .sections
                .closest(&destination)
                .1
                .elders
                .values()
                .map(|p2p_node| *p2p_node.peer_addr())
                .collect();
            debug!("Sending BootstrapResponse::Rebootstrap to {}", p2p_node);
            BootstrapResponse::Rebootstrap(conn_infos)
        };
        core.send_direct_message(p2p_node.peer_addr(), Variant::BootstrapResponse(response));
    }

    pub fn handle_join_request(
        &mut self,
        core: &mut Core,
        p2p_node: P2pNode,
        join_request: JoinRequest,
    ) {
        debug!(
            "Received JoinRequest from {} for v{}",
            p2p_node, join_request.elders_version
        );

        if join_request.elders_version < self.shared_state.our_info().version {
            self.resend_bootstrap_response_join(core, &p2p_node);
            return;
        }

        let pub_id = *p2p_node.public_id();
        if !self.shared_state.our_prefix().matches(pub_id.name()) {
            debug!(
                "Ignoring JoinRequest from {} - name doesn't match our prefix {:?}.",
                pub_id,
                self.shared_state.our_prefix()
            );
            return;
        }

        if self.shared_state.our_members.contains(pub_id.name()) {
            debug!(
                "Ignoring JoinRequest from {} - already member of our section.",
                pub_id
            );
            return;
        }

        if self.shared_state.is_in_online_backlog(&pub_id) {
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

            if !self.shared_state.our_prefix().matches(&details.destination) {
                debug!(
                    "Ignoring relocation JoinRequest from {} - destination {} doesn't match \
                     our prefix {:?}.",
                    pub_id,
                    details.destination,
                    self.shared_state.our_prefix()
                );
                return;
            }

            if !self.check_signed_relocation_details(&payload.details) {
                return;
            }

            (details.age, Some(details.destination_key))
        } else {
            (MIN_AGE, None)
        };

        self.vote_for_event(AccumulatingEvent::Online(OnlinePayload {
            p2p_node,
            age,
            their_knowledge,
        }))
    }

    pub fn handle_member_knowledge(
        &mut self,
        core: &mut Core,
        p2p_node: P2pNode,
        payload: MemberKnowledge,
    ) {
        trace!("Received {:?} from {:?}", payload, p2p_node);

        if self.shared_state.our_members.is_active(p2p_node.name()) {
            let _ = self
                .members_knowledge
                .entry(*p2p_node.name())
                .and_modify(|old| old.update(&payload))
                .or_insert(payload);
        }

        let version = payload
            .parsec_version
            .min(self.consensus_engine.parsec_version());
        self.send_parsec_gossip(core, Some((version, p2p_node)))
    }

    pub fn handle_parsec_request(
        &mut self,
        core: &mut Core,
        msg_version: u64,
        parsec_request: ParsecRequest,
        p2p_node: P2pNode,
    ) -> Result<()> {
        trace!(
            "handle parsec request v{} from {} (last: v{})",
            msg_version,
            p2p_node.public_id(),
            self.consensus_engine.parsec_version(),
        );

        let response = self.consensus_engine.handle_parsec_request(
            msg_version,
            parsec_request,
            *p2p_node.public_id(),
        );

        if let Some(response) = response {
            trace!("send parsec response v{} to {:?}", msg_version, p2p_node,);
            core.send_direct_message(p2p_node.peer_addr(), response);
        }

        match msg_version.cmp(&self.consensus_engine.parsec_version()) {
            Ordering::Equal => self.poll_all(core),
            Ordering::Greater => {
                // We are lagging behind. Send a request whose response might help us catch up.
                self.send_parsec_gossip(
                    core,
                    Some((self.consensus_engine.parsec_version(), p2p_node)),
                );
                Ok(())
            }
            Ordering::Less => Ok(()),
        }
    }

    pub fn handle_parsec_response(
        &mut self,
        core: &mut Core,
        msg_version: u64,
        parsec_response: ParsecResponse,
        pub_id: PublicId,
    ) -> Result<()> {
        trace!("handle parsec response v{} from {}", msg_version, pub_id);

        self.consensus_engine
            .handle_parsec_response(msg_version, parsec_response, pub_id);

        if msg_version == self.consensus_engine.parsec_version() {
            self.poll_all(core)
        } else {
            Ok(())
        }
    }

    fn try_relay_message(&mut self, core: &mut Core, msg: &MessageWithBytes) -> Result<()> {
        if !msg
            .message_dst()
            .contains(core.name(), self.shared_state.our_prefix())
            || msg.message_dst().is_multiple()
        {
            // Relay closer to the destination or broadcast to the rest of our section.
            self.send_signed_message(core, msg)
        } else {
            Ok(())
        }
    }

    fn handle_accumulated_message(
        &mut self,
        core: &mut Core,
        mut msg_with_bytes: MessageWithBytes,
    ) -> Result<()> {
        trace!("accumulated message {:?}", msg_with_bytes);

        // TODO: this is almost the same as `Node::try_handle_message` - find a way
        // to avoid the duplication.
        self.try_relay_message(core, &msg_with_bytes)?;

        if !msg_with_bytes
            .message_dst()
            .contains(core.name(), self.shared_state.our_prefix())
        {
            return Ok(());
        }

        if core.msg_filter.contains_incoming(&msg_with_bytes) {
            trace!(
                "not handling message - already handled: {:?}",
                msg_with_bytes
            );
            return Ok(());
        }

        let msg = msg_with_bytes.take_or_deserialize_message()?;

        match self.decide_message_action(core.id(), &msg)? {
            MessageAction::Handle => {
                core.msg_filter.insert_incoming(&msg_with_bytes);
                core.msg_queue.push_back(msg.into_queued(None));
            }
            MessageAction::Bounce | MessageAction::Discard => {
                // We can't bounce accumulated messages because we don't have access to the sender
                // anymore - discarding instead.
                trace!("Unhandled accumulated message, discarding: {:?}", msg);
            }
        }

        Ok(())
    }

    ////////////////////////////////////////////////////////////////////////////
    // Accumulated events handling
    ////////////////////////////////////////////////////////////////////////////

    // Polls and processes all accumulated events.
    fn poll_all(&mut self, core: &mut Core) -> Result<()> {
        while self.poll_one(core)? {}
        self.vote_for_remove_unresponsive_peers();

        Ok(())
    }

    // Polls and processes the next accumulated event. Returns whether any event was processed.
    //
    // If the event is a `SectionInfo` or `NeighbourInfo`, it also updates the corresponding
    // containers.
    fn poll_one(&mut self, core: &mut Core) -> Result<bool> {
        if self.poll_churn_event_backlog(core)? {
            return Ok(true);
        }

        // Note: it's important that `promote_and_demote_elders` happens before `poll_relocation`,
        // otherwise we might relocate a node that we still need.
        if self.promote_and_demote_elders(core) {
            return Ok(true);
        }

        if self.poll_relocation(core.id()) {
            return Ok(true);
        }

        let (event, proof) = match self.consensus_engine.poll(self.shared_state.sections.our()) {
            None => return Ok(false),
            Some((event, proof)) => (event, proof),
        };

        if self.should_backlog_event(&event) {
            self.backlog_event(event);
            Ok(false)
        } else {
            self.handle_accumulated_event(core, event, proof)?;
            Ok(true)
        }
    }

    // Can we perform an action right now that can result in churn?
    fn is_ready_to_churn(&self) -> bool {
        self.shared_state.handled_genesis_event && !self.churn_in_progress
    }

    // Polls and processes a backlogged churn event, if any.
    fn poll_churn_event_backlog(&mut self, core: &mut Core) -> Result<bool> {
        if !self.is_ready_to_churn() {
            return Ok(false);
        }

        if let Some(event) = self.shared_state.churn_event_backlog.pop_back() {
            trace!(
                "churn backlog poll {:?}, Others: {:?}",
                event,
                self.shared_state.churn_event_backlog
            );

            self.handle_accumulated_event(core, event, AccumulatingProof::default())?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn should_backlog_event(&self, event: &AccumulatingEvent) -> bool {
        let is_churn_trigger = match event {
            AccumulatingEvent::Online(_)
            | AccumulatingEvent::Offline(_)
            | AccumulatingEvent::Relocate(_) => true,
            _ => false,
        };

        is_churn_trigger && !self.is_ready_to_churn()
    }

    fn backlog_event(&mut self, event: AccumulatingEvent) {
        trace!(
            "churn backlog {:?}, Other: {:?}",
            event,
            self.shared_state.churn_event_backlog
        );
        self.shared_state.churn_event_backlog.push_front(event);
    }

    // Generate a new section info based on the current set of members and vote for it if it
    // changed.
    fn promote_and_demote_elders(&mut self, core: &Core) -> bool {
        if !self.members_changed || !self.is_ready_to_churn() {
            // Nothing changed that could impact elder set, or we cannot process it yet.
            return false;
        }

        self.members_changed = false;

        let new_infos = if let Some(new_infos) = self
            .shared_state
            .promote_and_demote_elders(&core.network_params, core.name())
        {
            self.churn_in_progress = true;
            new_infos
        } else {
            self.churn_in_progress = false;
            return false;
        };

        if !self.is_our_elder(core.id()) {
            return true;
        }

        for info in new_infos {
            let participants: BTreeSet<_> = info.elder_ids().copied().collect();
            let _ = self.dkg_cache.insert(participants.clone(), info);
            self.vote_for_event(AccumulatingEvent::StartDkg(participants));
        }

        true
    }

    /// Polls and handles the next scheduled relocation, if any.
    fn poll_relocation(&mut self, our_id: &PublicId) -> bool {
        // Delay relocation until no additional churn is in progress.
        if !self.is_ready_to_churn() {
            return false;
        }

        if let Some(details) = self.shared_state.poll_relocation() {
            if self.is_our_elder(our_id) {
                self.vote_for_relocate_prepare(details, RELOCATE_COOL_DOWN_STEPS);
            }

            return true;
        }

        false
    }

    fn handle_accumulated_event(
        &mut self,
        core: &mut Core,
        event: AccumulatingEvent,
        proof: AccumulatingProof,
    ) -> Result<()> {
        trace!("Handle accumulated event: {:?}", event);

        match event {
            AccumulatingEvent::Genesis {
                group,
                related_info,
            } => self.handle_genesis_event(&group, &related_info)?,
            AccumulatingEvent::StartDkg(_) => {
                log_or_panic!(
                    log::Level::Error,
                    "unexpected accumulated event: {:?}",
                    event
                );
            }
            AccumulatingEvent::DkgResult {
                participants,
                dkg_result,
            } => self.handle_dkg_result_event(core, &participants, &dkg_result)?,
            AccumulatingEvent::Online(payload) => self.handle_online_event(core, payload),
            AccumulatingEvent::Offline(pub_id) => self.handle_offline_event(core, pub_id),
            AccumulatingEvent::SectionInfo(elders_info, key) => {
                self.handle_section_info_event(core, elders_info, key, proof)?
            }
            AccumulatingEvent::NeighbourInfo(elders_info, key) => {
                self.handle_neighbour_info_event(core, elders_info, key)?
            }
            AccumulatingEvent::SendNeighbourInfo { dst, nonce } => {
                self.handle_send_neighbour_info_event(core, dst, nonce)?
            }
            AccumulatingEvent::TheirKeyInfo { prefix, key } => {
                self.handle_their_key_info_event(prefix, key)
            }
            AccumulatingEvent::TheirKnowledge { prefix, knowledge } => {
                self.handle_their_knowledge_event(prefix, knowledge)
            }
            AccumulatingEvent::ParsecPrune => self.handle_prune_event(core)?,
            AccumulatingEvent::Relocate(payload) => self.handle_relocate_event(core, payload)?,
            AccumulatingEvent::RelocatePrepare(pub_id, count) => {
                self.handle_relocate_prepare_event(core, pub_id, count);
            }
            AccumulatingEvent::User(payload) => self.handle_user_event(core, payload)?,
        }

        Ok(())
    }

    // Handles an accumulated parsec Observation for genesis.
    //
    // The related_info is the serialized shared state that will be the starting
    // point when processing parsec data.
    fn handle_genesis_event(
        &mut self,
        _group: &BTreeSet<PublicId>,
        related_info: &[u8],
    ) -> Result<()> {
        // `related_info` is empty only if this is the `first` node.
        let new_state = if !related_info.is_empty() {
            Some(bincode::deserialize(related_info)?)
        } else {
            None
        };

        // On split membership may need to be checked again.
        self.members_changed = true;
        self.shared_state.update(new_state);

        Ok(())
    }

    fn handle_online_event(&mut self, core: &mut Core, payload: OnlinePayload) {
        if self.churn_in_progress {
            log_or_panic!(
                log::Level::Error,
                "can't handle Online when churn is in progress"
            );
            return;
        }

        if self.shared_state.add_member(
            payload.p2p_node.clone(),
            payload.age,
            core.network_params.recommended_section_size,
        ) {
            info!("handle Online: {:?}.", payload);

            self.members_changed = true;

            if self.is_our_elder(core.id()) {
                core.send_event(Event::MemberJoined {
                    name: *payload.p2p_node.name(),
                    age: payload.age,
                });
                self.send_node_approval(core, payload.p2p_node, payload.their_knowledge);
                self.print_network_stats();
            }
        } else {
            info!("ignore Online: {:?}.", payload);
        }
    }

    fn handle_offline_event(&mut self, core: &mut Core, pub_id: PublicId) {
        if self.churn_in_progress {
            log_or_panic!(
                log::Level::Error,
                "can't handle Offline when churn is in progress"
            );
            return;
        }

        if let Some(info) = self
            .shared_state
            .remove_member(&pub_id, core.network_params.recommended_section_size)
        {
            info!("handle Offline: {}", pub_id);

            self.members_changed = true;

            core.transport.disconnect(*info.p2p_node.peer_addr());
            let _ = self.members_knowledge.remove(pub_id.name());

            if self.is_our_elder(core.id()) {
                core.send_event(Event::MemberLeft {
                    name: *pub_id.name(),
                    age: info.age(),
                });
            }
        } else {
            info!("ignore Offline: {}", pub_id);
        }
    }

    fn handle_relocate_prepare_event(
        &mut self,
        core: &Core,
        payload: RelocateDetails,
        count_down: i32,
    ) {
        if !self.is_our_elder(core.id()) {
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
        core: &mut Core,
        details: RelocateDetails,
    ) -> Result<(), RoutingError> {
        let node_knowledge = match self
            .shared_state
            .remove_member(
                &details.pub_id,
                core.network_params.recommended_section_size,
            )
            .map(|info| info.state)
        {
            Some(MemberState::Relocating { node_knowledge }) => {
                info!("handle Relocate: {:?}", details);
                node_knowledge
            }
            Some(MemberState::Left) | None => {
                info!("ignore Relocate: {:?} - not a member", details);
                return Ok(());
            }
            Some(MemberState::Joined) => {
                log_or_panic!(
                    log::Level::Error,
                    "Expected the state of {} to be Relocating, but was Joined",
                    details.pub_id,
                );
                return Ok(());
            }
        };

        self.members_changed = true;
        let _ = self.members_knowledge.remove(details.pub_id.name());

        if !self.is_our_elder(core.id()) {
            return Ok(());
        }

        if &details.pub_id == core.id() {
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
            self.shared_state
                .sections
                .knowledge_by_location(&DstLocation::Section(details.destination)),
        );

        let src = SrcLocation::Section(*self.shared_state.our_prefix());
        let dst = DstLocation::Node(*details.pub_id.name());
        let content = Variant::Relocate(Box::new(details));

        self.send_routing_message(core, src, dst, content, Some(knowledge_index))
    }

    fn handle_dkg_result_event(
        &mut self,
        core: &Core,
        participants: &BTreeSet<PublicId>,
        dkg_result: &DkgResultWrapper,
    ) -> Result<(), RoutingError> {
        self.section_keys_provider
            .handle_dkg_result_event(participants, dkg_result)?;

        if !self.is_our_elder(core.id()) {
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
        core: &mut Core,
        elders_info: EldersInfo,
        section_key: bls::PublicKey,
        proof: AccumulatingProof,
    ) -> Result<()> {
        let old_prefix = *self.shared_state.our_prefix();
        let was_elder = self.is_our_elder(core.id());

        let neighbour_elders_removed = NeighbourEldersRemoved::builder(&self.shared_state.sections);
        let neighbour_elders_removed =
            if self.add_new_elders_info(core.name(), elders_info, section_key, proof)? {
                neighbour_elders_removed.build(&self.shared_state.sections)
            } else {
                return Ok(());
            };

        let elders_info = self.shared_state.our_info();
        let info_prefix = elders_info.prefix;
        let is_elder = elders_info.elders.contains_key(core.name());

        core.msg_filter.reset();

        if was_elder || is_elder {
            info!("handle SectionInfo: {:?}", elders_info);
        } else {
            trace!("unhandled SectionInfo");
            return Ok(());
        }

        if info_prefix.is_extension_of(&old_prefix) {
            info!("Split");
        } else if old_prefix.is_extension_of(&info_prefix) {
            panic!("Merge not supported: {:?} -> {:?}", old_prefix, info_prefix);
        }

        let complete_data = self.prepare_parsec_reset(core.id())?;

        if !is_elder {
            // Demote after the parsec reset, i.e genesis prefix info is for the new parsec,
            // i.e the one that would be received with NodeApproval.
            self.process_post_reset_events(core, complete_data.to_process);
            self.handle_elders_update(core, complete_data.genesis_prefix_info);

            info!("Demoted");
            core.send_event(Event::Demoted);

            return Ok(());
        }

        self.finalise_parsec_reset(
            core,
            complete_data.genesis_prefix_info,
            complete_data.to_vote_again,
        )?;
        self.process_post_reset_events(core, complete_data.to_process);

        self.prune_neighbour_connections(core, &neighbour_elders_removed);
        self.send_genesis_updates(core);
        self.send_member_knowledge(core);

        self.print_network_stats();

        if !was_elder {
            info!("Promoted");
            core.send_event(Event::Promoted);
        }

        core.send_event(Event::EldersChanged {
            prefix: *self.shared_state.our_prefix(),
            key: *self.shared_state.our_history.last_key(),
            elders: self
                .shared_state
                .our_info()
                .elders
                .keys()
                .copied()
                .collect(),
        });

        Ok(())
    }

    // Handles our own section info, or the section info of our sibling directly after a split.
    // Returns whether the event should be handled by the caller.
    fn add_new_elders_info(
        &mut self,
        our_name: &XorName,
        elders_info: EldersInfo,
        section_key: bls::PublicKey,
        proofs: AccumulatingProof,
    ) -> Result<bool> {
        // Split handling alone. wouldn't cater to merge
        if elders_info
            .prefix
            .is_extension_of(self.shared_state.our_prefix())
        {
            match self.split_cache.take() {
                None => {
                    self.split_cache = Some(SplitCache {
                        elders_info,
                        section_key,
                        proofs,
                    });
                    Ok(false)
                }
                Some(cached) => {
                    let cached_prefix = cached.elders_info.prefix;

                    // Add our_info first so when we add sibling info, its a valid neighbour prefix
                    // which does not get immediately purged.
                    if cached_prefix.matches(our_name) {
                        self.add_our_elders_info(
                            our_name,
                            cached.elders_info,
                            cached.section_key,
                            cached.proofs,
                        )?;
                        self.add_sibling_elders_info(elders_info, section_key);
                    } else {
                        self.add_our_elders_info(our_name, elders_info, section_key, proofs)?;
                        self.add_sibling_elders_info(cached.elders_info, cached.section_key);
                    }
                    Ok(true)
                }
            }
        } else {
            self.add_our_elders_info(our_name, elders_info, section_key, proofs)?;
            Ok(true)
        }
    }

    fn add_our_elders_info(
        &mut self,
        our_name: &XorName,
        elders_info: EldersInfo,
        section_key: bls::PublicKey,
        proofs: AccumulatingProof,
    ) -> Result<(), RoutingError> {
        let signature = self.section_keys_provider.check_and_combine_signatures(
            self.shared_state.sections.our(),
            &section_key,
            proofs,
        )?;
        self.section_keys_provider
            .finalise_dkg(our_name, &elders_info)?;
        self.shared_state
            .update_our_section(elders_info, section_key, signature);
        self.churn_in_progress = false;
        Ok(())
    }

    fn add_sibling_elders_info(&mut self, elders_info: EldersInfo, section_key: bls::PublicKey) {
        let prefix = elders_info.prefix;
        self.shared_state.sections.add_neighbour(elders_info);
        self.shared_state.sections.update_keys(prefix, section_key);

        // We can update their knowledge already because we know they also reached consensus on
        // our `SectionInfo` so they know our latest key.
        self.shared_state
            .sections
            .update_knowledge(prefix, self.shared_state.our_history.last_key_index());
    }

    fn handle_neighbour_info_event(
        &mut self,
        core: &mut Core,
        elders_info: EldersInfo,
        key: bls::PublicKey,
    ) -> Result<()> {
        info!("handle NeighbourInfo: {:?}", elders_info);

        let neighbour_elders_removed = NeighbourEldersRemoved::builder(&self.shared_state.sections);
        self.shared_state
            .sections
            .update_keys(elders_info.prefix, key);
        self.shared_state.sections.add_neighbour(elders_info);
        let neighbour_elders_removed = neighbour_elders_removed.build(&self.shared_state.sections);

        if !self.is_our_elder(core.id()) {
            return Ok(());
        }

        self.prune_neighbour_connections(core, &neighbour_elders_removed);
        Ok(())
    }

    fn handle_send_neighbour_info_event(
        &mut self,
        core: &mut Core,
        dst: XorName,
        nonce: MessageHash,
    ) -> Result<()> {
        if !self.is_our_elder(core.id()) {
            return Ok(());
        }

        self.send_routing_message(
            core,
            SrcLocation::Section(*self.shared_state.our_prefix()),
            DstLocation::Section(dst),
            Variant::NeighbourInfo {
                elders_info: self.shared_state.our_info().clone(),
                nonce,
            },
            None,
        )
    }

    fn handle_their_key_info_event(&mut self, prefix: Prefix<XorName>, key: bls::PublicKey) {
        self.shared_state.sections.update_keys(prefix, key);
    }

    fn handle_their_knowledge_event(&mut self, prefix: Prefix<XorName>, knowledge: u64) {
        self.shared_state
            .sections
            .update_knowledge(prefix, knowledge)
    }

    fn handle_prune_event(&mut self, core: &mut Core) -> Result<(), RoutingError> {
        if !self.is_our_elder(core.id()) {
            debug!("ignore ParsecPrune event - not elder");
            return Ok(());
        }

        if self.churn_in_progress {
            debug!("ignore ParsecPrune event - churn in progress");
            return Ok(());
        }

        info!("handle ParsecPrune");
        let complete_data = self.prepare_parsec_reset(core.id())?;
        self.finalise_parsec_reset(
            core,
            complete_data.genesis_prefix_info,
            complete_data.to_vote_again,
        )?;
        self.send_genesis_updates(core);
        self.send_member_knowledge(core);
        Ok(())
    }

    /// Handle an accumulated `User` event
    fn handle_user_event(&mut self, core: &mut Core, payload: Vec<u8>) -> Result<(), RoutingError> {
        core.send_event(Event::Consensus(payload));
        Ok(())
    }

    ////////////////////////////////////////////////////////////////////////////
    // Parsec and Chain management
    ////////////////////////////////////////////////////////////////////////////

    /// Gets the data needed to initialise a new Parsec instance
    fn prepare_parsec_reset(&mut self, our_id: &PublicId) -> Result<ParsecResetData> {
        self.shared_state.handled_genesis_event = false;
        let cached_events = self.consensus_engine.prepare_reset(our_id);

        let genesis_prefix_info = GenesisPrefixInfo {
            elders_info: self.shared_state.our_info().clone(),
            public_keys: self.section_keys_provider.public_key_set().clone(),
            ages: self.shared_state.our_members.get_age_counters(),
            parsec_version: self.consensus_engine.parsec_version() + 1,
        };

        let our_prefix = *self.shared_state.our_prefix();

        let to_process = cached_events
            .iter()
            .filter(|event| match &event.payload {
                // Events to re-process
                AccumulatingEvent::Online(_) => true,
                // Events to re-insert
                AccumulatingEvent::Genesis { .. }
                | AccumulatingEvent::Offline(_)
                | AccumulatingEvent::StartDkg(_)
                | AccumulatingEvent::DkgResult { .. }
                | AccumulatingEvent::ParsecPrune
                | AccumulatingEvent::Relocate(_)
                | AccumulatingEvent::RelocatePrepare(_, _)
                | AccumulatingEvent::SectionInfo(_, _)
                | AccumulatingEvent::NeighbourInfo { .. }
                | AccumulatingEvent::SendNeighbourInfo { .. }
                | AccumulatingEvent::TheirKeyInfo { .. }
                | AccumulatingEvent::TheirKnowledge { .. }
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
                        our_prefix.matches(payload.p2p_node.name())
                    }
                    AccumulatingEvent::Offline(pub_id) => our_prefix.matches(pub_id.name()),
                    AccumulatingEvent::Relocate(ref details)
                    | AccumulatingEvent::RelocatePrepare(ref details, _) => {
                        our_prefix.matches(details.pub_id.name())
                    }
                    // Drop: no longer relevant after prefix change.
                    AccumulatingEvent::Genesis { .. }
                    | AccumulatingEvent::StartDkg(_)
                    | AccumulatingEvent::DkgResult { .. }
                    | AccumulatingEvent::ParsecPrune => false,

                    // Keep: Additional signatures for neighbours for sec-msg-relay.
                    AccumulatingEvent::SectionInfo(ref elders_info, _)
                    | AccumulatingEvent::NeighbourInfo(ref elders_info, _) => {
                        our_prefix.is_neighbour(&elders_info.prefix)
                    }

                    // Only revote if the recipient is still our neighbour
                    AccumulatingEvent::SendNeighbourInfo { ref dst, .. } => {
                        self.shared_state.sections.is_in_neighbour(dst)
                    }

                    // Keep: Still relevant after prefix change.
                    AccumulatingEvent::TheirKeyInfo { .. }
                    | AccumulatingEvent::TheirKnowledge { .. }
                    | AccumulatingEvent::User(_) => true,
                }
            })
            .collect();

        Ok(ParsecResetData {
            genesis_prefix_info,
            to_vote_again,
            to_process,
        })
    }

    fn process_post_reset_events(&mut self, core: &mut Core, to_process: BTreeSet<NetworkEvent>) {
        to_process.iter().for_each(|event| match &event.payload {
            AccumulatingEvent::Genesis { .. }
            | AccumulatingEvent::Offline(_)
            | AccumulatingEvent::StartDkg(_)
            | AccumulatingEvent::DkgResult { .. }
            | AccumulatingEvent::ParsecPrune
            | AccumulatingEvent::Relocate(_)
            | AccumulatingEvent::RelocatePrepare(_, _)
            | AccumulatingEvent::SectionInfo(_, _)
            | AccumulatingEvent::NeighbourInfo { .. }
            | AccumulatingEvent::SendNeighbourInfo { .. }
            | AccumulatingEvent::TheirKeyInfo { .. }
            | AccumulatingEvent::TheirKnowledge { .. }
            | AccumulatingEvent::User(_) => {
                log_or_panic!(log::Level::Error, "unexpected event {:?}", event.payload);
            }
            AccumulatingEvent::Online(payload) => {
                self.resend_bootstrap_response_join(core, &payload.p2p_node);
            }
        });
    }

    // Finalise parsec reset and revotes for all previously unaccumulated events.
    fn finalise_parsec_reset(
        &mut self,
        core: &mut Core,
        genesis_prefix_info: GenesisPrefixInfo,
        to_vote_again: BTreeSet<NetworkEvent>,
    ) -> Result<()> {
        let serialised_state = bincode::serialize(&self.shared_state)?;

        self.genesis_prefix_info = genesis_prefix_info;
        self.consensus_engine.finalise_reset(
            &mut core.rng,
            core.full_id.clone(),
            &self.genesis_prefix_info.elders_info,
            serialised_state,
            self.genesis_prefix_info.parsec_version,
        );

        to_vote_again.iter().for_each(|event| {
            self.consensus_engine.vote_for(event.clone());
        });

        Ok(())
    }

    // Handles change to the section elders as non-elder.
    fn handle_elders_update(&mut self, core: &mut Core, genesis_prefix_info: GenesisPrefixInfo) {
        self.section_keys_provider =
            SectionKeysProvider::new(genesis_prefix_info.public_keys.clone(), None);
        self.consensus_engine.finalise_reset(
            &mut core.rng,
            core.full_id.clone(),
            &genesis_prefix_info.elders_info,
            vec![],
            genesis_prefix_info.parsec_version,
        );
        self.shared_state = SharedState::new(
            genesis_prefix_info.elders_info.clone(),
            genesis_prefix_info.public_keys.public_key(),
            genesis_prefix_info.ages.clone(),
        );
        self.genesis_prefix_info = genesis_prefix_info;
    }

    // Detect non-responsive peers and vote them out.
    fn vote_for_remove_unresponsive_peers(&mut self) {
        let members = self.shared_state.our_info().elder_ids();
        let unresponsive_nodes = self.consensus_engine.detect_unresponsive(members);
        for pub_id in &unresponsive_nodes {
            info!("Voting for unresponsive node {:?}", pub_id);
            self.consensus_engine
                .vote_for(AccumulatingEvent::Offline(*pub_id).into_network_event());
        }
    }

    fn vote_for_relocate(&mut self, details: RelocateDetails) {
        self.consensus_engine
            .vote_for(details.into_accumulating_event().into_network_event())
    }

    fn vote_for_relocate_prepare(&mut self, details: RelocateDetails, count_down: i32) {
        self.consensus_engine
            .vote_for(AccumulatingEvent::RelocatePrepare(details, count_down).into_network_event());
    }

    fn vote_for_section_info(
        &mut self,
        elders_info: EldersInfo,
        section_key: bls::PublicKey,
    ) -> Result<(), RoutingError> {
        let signature_payload = EventSigPayload::new(
            &self.section_keys_provider.secret_key_share()?.key,
            &section_key,
        );
        let event = AccumulatingEvent::SectionInfo(elders_info, section_key);
        let event = event.into_network_event_with(Some(signature_payload));
        self.consensus_engine.vote_for(event);
        Ok(())
    }

    ////////////////////////////////////////////////////////////////////////////
    // Message sending
    ////////////////////////////////////////////////////////////////////////////

    // Send NodeApproval to the current candidate which makes them a section member and allows them
    // to passively participate in parsec consensus (that is, they can receive gossip and poll
    // consensused blocks out of parsec, but they can't vote yet)
    fn send_node_approval(
        &mut self,
        core: &mut Core,
        p2p_node: P2pNode,
        their_knowledge: Option<bls::PublicKey>,
    ) {
        info!(
            "Our section with {:?} has approved candidate {}.",
            self.shared_state.our_prefix(),
            p2p_node
        );

        let src = SrcLocation::Section(self.genesis_prefix_info.elders_info.prefix);
        let dst = DstLocation::Node(*p2p_node.name());

        let variant = Variant::NodeApproval(Box::new(self.genesis_prefix_info.clone()));
        let their_knowledge =
            their_knowledge.and_then(|key| self.shared_state.our_history.index_of(&key));

        if let Err(error) = self.send_routing_message(core, src, dst, variant, their_knowledge) {
            debug!("Failed sending NodeApproval to {}: {:?}", p2p_node, error);
        }
    }

    // Send `GenesisUpdate` message to all non-elders.
    fn send_genesis_updates(&mut self, core: &mut Core) {
        for (recipient, msg) in self.create_genesis_updates() {
            trace!(
                "Send GenesisUpdate({:?}) to {}",
                self.genesis_prefix_info,
                recipient
            );

            core.send_direct_message(
                recipient.peer_addr(),
                Variant::MessageSignature(Box::new(msg)),
            );
        }
    }

    // TODO: make non-pub
    pub fn create_genesis_updates(&self) -> Vec<(P2pNode, AccumulatingMessage)> {
        self.shared_state
            .adults_and_infants_p2p_nodes()
            .cloned()
            .filter_map(|recipient| {
                let variant = Variant::GenesisUpdate(Box::new(self.genesis_prefix_info.clone()));
                let dst = DstLocation::Node(*recipient.name());
                let index = self
                    .members_knowledge
                    .get(recipient.name())
                    .and_then(|knowledge| {
                        self.shared_state
                            .our_history
                            .index_of(&knowledge.section_key)
                    })
                    .unwrap_or(0);

                match self.to_accumulating_message(dst, variant, Some(index)) {
                    Ok(msg) => Some((recipient, msg)),
                    Err(error) => {
                        error!("Failed to create signed message: {:?}", error);
                        None
                    }
                }
            })
            .collect()
    }

    fn send_parsec_gossip(&mut self, core: &mut Core, target: Option<(u64, P2pNode)>) {
        let (version, gossip_target) = match target {
            Some((v, p)) => (v, p),
            None => {
                if !self.consensus_engine.should_send_gossip() {
                    return;
                }

                if let Some(recipient) = self.choose_gossip_recipient(&mut core.rng) {
                    let version = self.consensus_engine.parsec_version();
                    (version, recipient)
                } else {
                    return;
                }
            }
        };

        match self
            .consensus_engine
            .create_gossip(version, gossip_target.public_id())
        {
            Ok(msg) => {
                trace!("send parsec request v{} to {:?}", version, gossip_target,);
                core.send_direct_message(gossip_target.peer_addr(), msg);
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

    fn choose_gossip_recipient(&mut self, rng: &mut MainRng) -> Option<P2pNode> {
        let recipients = self.consensus_engine.gossip_recipients();
        if recipients.is_empty() {
            trace!("not sending parsec request: no recipients");
            return None;
        }

        let mut p2p_recipients: Vec<_> = recipients
            .into_iter()
            .filter_map(|pub_id| self.shared_state.our_members.get_p2p_node(pub_id.name()))
            .cloned()
            .collect();

        if p2p_recipients.is_empty() {
            log_or_panic!(
                log::Level::Error,
                "not sending parsec request: not connected to any gossip recipient.",
            );
            return None;
        }

        let rand_index = rng.gen_range(0, p2p_recipients.len());
        Some(p2p_recipients.swap_remove(rand_index))
    }

    fn send_member_knowledge(&mut self, core: &mut Core) {
        let payload = MemberKnowledge {
            section_key: *self.shared_state.our_history.last_key(),
            parsec_version: self.consensus_engine.parsec_version(),
        };

        for recipient in self.shared_state.sections.our_elders() {
            if recipient.public_id() == core.id() {
                continue;
            }

            trace!("Send {:?} to {:?}", payload, recipient);
            core.send_direct_message(recipient.peer_addr(), Variant::MemberKnowledge(payload))
        }
    }

    pub fn create_bounce(&self, msg_bytes: Bytes) -> Variant {
        Variant::Bounce {
            elders_version: Some(self.shared_state.our_info().version),
            message: msg_bytes,
        }
    }

    // Resend the response with ours or our sibling's info in case of split.
    fn resend_bootstrap_response_join(&mut self, core: &mut Core, p2p_node: &P2pNode) {
        let our_info = self.shared_state.our_info();

        let response_section = Some(our_info)
            .filter(|info| info.prefix.matches(p2p_node.name()))
            .or_else(|| self.shared_state.sections.get(&our_info.prefix.sibling()))
            .filter(|info| info.prefix.matches(p2p_node.name()))
            .cloned();

        if let Some(response_section) = response_section {
            trace!(
                "Resend Join to {} with version {}",
                p2p_node,
                response_section.version
            );
            core.send_direct_message(
                p2p_node.peer_addr(),
                Variant::BootstrapResponse(BootstrapResponse::Join(response_section)),
            );
        }
    }

    // Send message over the network.
    pub fn send_signed_message(&mut self, core: &mut Core, msg: &MessageWithBytes) -> Result<()> {
        let (targets, dg_size) = routing_table::delivery_targets(
            msg.message_dst(),
            core.id(),
            &self.shared_state.our_members,
            &self.shared_state.sections,
        )?;

        let targets: Vec<_> = targets
            .into_iter()
            .filter(|p2p_node| {
                core.msg_filter
                    .filter_outgoing(msg, p2p_node.public_id())
                    .is_new()
            })
            .collect();

        if targets.is_empty() {
            return Ok(());
        }

        trace!("Sending {:?} via targets {:?}", msg, targets);

        let targets: Vec<_> = targets.into_iter().map(|node| *node.peer_addr()).collect();
        let cheap_bytes_clone = msg.full_bytes().clone();
        core.send_message_to_targets(&targets, dg_size, cheap_bytes_clone);

        Ok(())
    }

    // Constructs a message, finds the nodes responsible for accumulation, and either sends
    // these nodes a signature or tries to accumulate signatures for this message (on success, the
    // accumulator handles or forwards the message).
    //
    // If `proof_start_index_override` is set it will be used as the starting index of the proof.
    // Otherwise the index is calculated using the knowledge stored in the section map.
    pub fn send_routing_message(
        &mut self,
        core: &mut Core,
        src: SrcLocation,
        dst: DstLocation,
        variant: Variant,
        proof_start_index_override: Option<u64>,
    ) -> Result<()> {
        if !src.contains(core.name()) {
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
            let msg = Message::single_src(&core.full_id, dst, variant)?;
            let msg = MessageWithBytes::new(msg)?;
            return self.handle_accumulated_message(core, msg);
        }

        let accumulating_msg =
            self.to_accumulating_message(dst, variant, proof_start_index_override)?;

        let targets = routing_table::signature_targets(
            &dst,
            self.shared_state.sections.our_elders().cloned(),
        );

        trace!(
            "Sending signatures for {:?} to {:?}",
            accumulating_msg.content,
            targets,
        );

        for target in targets {
            if target.name() == core.name() {
                if let Some(msg) = self.sig_accumulator.add_proof(accumulating_msg.clone()) {
                    self.handle_accumulated_message(core, msg)?;
                }
            } else {
                core.send_direct_message(
                    target.peer_addr(),
                    Variant::MessageSignature(Box::new(accumulating_msg.clone())),
                );
            }
        }

        Ok(())
    }

    // Signs and proves the given message and wraps it in `AccumulatingMessage`.
    fn to_accumulating_message(
        &self,
        dst: DstLocation,
        variant: Variant,
        proof_start_index_override: Option<u64>,
    ) -> Result<AccumulatingMessage> {
        let proof = self.shared_state.prove(&dst, proof_start_index_override);
        let pk_set = self.section_keys_provider.public_key_set().clone();
        let sk_share = self.section_keys_provider.secret_key_share()?;

        let dst_key = *self
            .shared_state
            .sections
            .key_by_location(&dst)
            .unwrap_or_else(|| self.shared_state.our_history.first_key());

        let content = PlainMessage {
            src: *self.shared_state.our_prefix(),
            dst,
            dst_key,
            variant,
        };

        AccumulatingMessage::new(content, sk_share, pk_set, proof)
    }

    ////////////////////////////////////////////////////////////////////////////
    // Miscellaneous
    ////////////////////////////////////////////////////////////////////////////

    // Ignore stale GenesisUpdates
    fn should_handle_genesis_update(
        &self,
        our_id: &PublicId,
        genesis_prefix_info: &GenesisPrefixInfo,
    ) -> bool {
        !self.is_our_elder(our_id)
            && genesis_prefix_info.parsec_version > self.genesis_prefix_info.parsec_version
    }

    // Ignore `JoinRequest` if we are not elder unless the join request is outdated in which case we
    // reply with `BootstrapResponse::Join` with the up-to-date info (see `handle_join_request`).
    fn should_handle_join_request(&self, our_id: &PublicId, req: &JoinRequest) -> bool {
        self.is_our_elder(our_id) || req.elders_version < self.shared_state.our_info().version
    }

    // If elder, always handle UserMessage, otherwise handle it only if addressed directly to us
    // as a node.
    fn should_handle_user_message(&self, our_id: &PublicId, dst: &DstLocation) -> bool {
        self.is_our_elder(our_id) || dst.as_node().ok() == Some(our_id.name())
    }

    // Disconnect from peers that are no longer elders of neighbour sections.
    fn prune_neighbour_connections(
        &mut self,
        core: &mut Core,
        neighbour_elders_removed: &NeighbourEldersRemoved,
    ) {
        for p2p_node in &neighbour_elders_removed.0 {
            // The peer might have been relocated from a neighbour to us - in that case do not
            // disconnect from them.
            if self.shared_state.is_known_peer(p2p_node.name()) {
                continue;
            }

            core.transport.disconnect(*p2p_node.peer_addr());
        }
    }

    // Update our knowledge of their (sender's) section and their knowledge of our section.
    pub fn update_section_knowledge(&mut self, msg: &Message, msg_hash: &MessageHash) {
        let events =
            self.shared_state
                .update_section_knowledge(&msg.src, msg.dst_key.as_ref(), msg_hash);

        for event in events {
            self.vote_for_event(event)
        }
    }

    // Verifies message but doesn't log anything on failure, only returns result.
    fn verify_message_quiet(&self, msg: &Message) -> Result<bool> {
        match msg.verify(self.shared_state.sections.keys()) {
            Ok(VerifyStatus::Full) => Ok(true),
            Ok(VerifyStatus::Unknown) if msg.dst.is_multiple() => {
                // Proof is too new which can only happen if we've been already demoted but are
                // lagging behind (or the sender is faulty/malicious). We can't handle the
                // message ourselves but the other elders likely can.
                Ok(false)
            }
            Ok(VerifyStatus::Unknown) => Err(RoutingError::UntrustedMessage),
            Err(error) => Err(error),
        }
    }

    fn check_signed_relocation_details(&self, msg: &SignedRelocateDetails) -> bool {
        msg.signed_msg()
            .verify(self.shared_state.sections.keys())
            .and_then(VerifyStatus::require_full)
            .map_err(|error| {
                messages::log_verify_failure(
                    msg.signed_msg(),
                    &error,
                    self.shared_state.sections.keys(),
                );
                error
            })
            .is_ok()
    }

    fn print_network_stats(&self) {
        self.shared_state.sections.network_stats().print()
    }
}

// Data needed to finalise parsec reset.
struct ParsecResetData {
    // The new genesis prefix info.
    genesis_prefix_info: GenesisPrefixInfo,
    // The cached events that should be revoted. Not shared state: only the ones we voted for.
    // Also contains our votes that never reached consensus.
    to_vote_again: BTreeSet<NetworkEvent>,
    // The events to process. Not shared state: only the ones we voted for.
    // Also contains our votes that never reached consensus.
    to_process: BTreeSet<NetworkEvent>,
}

pub struct RelocateParams {
    pub conn_infos: Vec<SocketAddr>,
    pub details: SignedRelocateDetails,
}

// Create `EldersInfo` for the first node.
fn create_first_elders_info(p2p_node: P2pNode) -> EldersInfo {
    let name = *p2p_node.name();
    let node = (name, p2p_node);
    EldersInfo::new(iter::once(node).collect(), Prefix::default(), 0)
}
