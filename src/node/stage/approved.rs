// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    consensus::{
        self, AccumulatingEvent, ConsensusEngine, DkgResultWrapper, GenesisPrefixInfo,
        NetworkEvent, ParsecRequest, ParsecResponse, Proof, Proven,
    },
    core::Core,
    delivery_group,
    error::{Result, RoutingError},
    event::Event,
    id::{P2pNode, PublicId},
    location::{DstLocation, SrcLocation},
    messages::{
        self, AccumulatingMessage, BootstrapResponse, JoinRequest, Message, MessageAccumulator,
        MessageHash, MessageStatus, PlainMessage, Variant, VerifyStatus,
    },
    pause::PausedState,
    relocation::{RelocateDetails, SignedRelocateDetails},
    rng::MainRng,
    section::{
        member_info, EldersInfo, MemberState, NeighbourEldersRemoved, SectionKeyShare,
        SectionKeysProvider, SectionUpdateBarrier, SectionUpdateDetails, SharedState, MIN_AGE,
    },
    time::Duration,
};
use bytes::Bytes;
use crossbeam_channel::Sender;
use itertools::Itertools;
use rand::Rng;
use serde::Serialize;
use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    iter,
    net::SocketAddr,
};
use xor_name::{Prefix, XorName};

// Send our knowledge in a similar speed as GOSSIP_TIMEOUT
const KNOWLEDGE_TIMEOUT: Duration = Duration::from_secs(2);

// The approved stage - node is a full member of a section and is performing its duties according
// to its persona (infant, adult or elder).
pub struct Approved {
    pub consensus_engine: ConsensusEngine,
    pub shared_state: SharedState,
    section_keys_provider: SectionKeysProvider,
    message_accumulator: MessageAccumulator,
    timer_token: u64,
    // DKG cache
    dkg_cache: BTreeMap<BTreeSet<PublicId>, EldersInfo>,
    section_update_barrier: SectionUpdateBarrier,
    // Marker indicating we are processing churn event
    churn_in_progress: bool,
    // Flag indicating that our section members changed (a node joined or left) and we might need
    // to change our elders.
    members_changed: bool,
}

impl Approved {
    // Create the approved stage for the first node in the network.
    pub fn first(core: &mut Core) -> Result<Self> {
        let connection_info = core.transport.our_connection_info()?;
        let p2p_node = P2pNode::new(*core.id(), connection_info);

        let secret_key_set = consensus::generate_secret_key_set(&mut core.rng, 1);
        let public_key_set = secret_key_set.public_keys();
        let secret_key_share = secret_key_set.secret_key_share(0);

        // Note: `ElderInfo` is normally signed with the previous key, but as we are the first node
        // of the network there is no previous key. Sign with the current key instead.
        let elders_info = create_first_elders_info(&public_key_set, &secret_key_share, p2p_node)?;
        let shared_state =
            create_first_shared_state(&public_key_set, &secret_key_share, elders_info)?;

        let section_key_share = SectionKeyShare {
            public_key_set,
            index: 0,
            secret_key_share,
        };

        Self::new(core, shared_state, 0, Some(section_key_share))
    }

    // Create the approved stage for a regular node.
    pub fn new(
        core: &mut Core,
        shared_state: SharedState,
        parsec_version: u64,
        section_key_share: Option<SectionKeyShare>,
    ) -> Result<Self> {
        let serialised_state = bincode::serialize(&shared_state)?;
        let consensus_engine = ConsensusEngine::new(
            &mut core.rng,
            core.full_id.clone(),
            shared_state.sections.our(),
            serialised_state,
            parsec_version,
        );

        let section_keys_provider = SectionKeysProvider::new(section_key_share);
        let timer_token = core.timer.schedule(KNOWLEDGE_TIMEOUT);

        Ok(Self {
            consensus_engine,
            shared_state,
            section_keys_provider,
            message_accumulator: Default::default(),
            timer_token,
            dkg_cache: Default::default(),
            section_update_barrier: Default::default(),
            churn_in_progress: false,
            members_changed: false,
        })
    }

    pub fn pause(self, core: Core) -> PausedState {
        PausedState {
            network_params: core.network_params,
            consensus_engine: self.consensus_engine,
            shared_state: self.shared_state,
            section_keys_provider: self.section_keys_provider,
            full_id: core.full_id,
            msg_filter: core.msg_filter,
            msg_queue: core.msg_queue,
            transport: core.transport,
            transport_rx: None,
            msg_accumulator: self.message_accumulator,
            section_update_barrier: self.section_update_barrier,
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
            message_accumulator: state.msg_accumulator,
            timer_token,
            section_update_barrier: state.section_update_barrier,
            // TODO: these fields should come from PausedState too
            dkg_cache: Default::default(),
            churn_in_progress: false,
            members_changed: false,
        };

        (stage, core)
    }

    pub fn vote_for_event(&mut self, event: AccumulatingEvent) {
        match self
            .section_keys_provider
            .key_share()
            .and_then(|share| event.into_signed_network_event(share))
        {
            Ok(event) => self.consensus_engine.vote_for(event),
            Err(error) => log_or_panic!(
                log::Level::Error,
                "Failed to create NetworkEvent: {}",
                error
            ),
        }
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
        let name = if let Some(node) = self.shared_state.find_p2p_node_from_addr(&peer_addr) {
            debug!("Lost known peer {}", node);
            *node.name()
        } else {
            trace!("Lost unknown peer {}", peer_addr);
            return;
        };

        if self.is_our_elder(core.id()) && self.shared_state.our_members.contains(&name) {
            self.vote_for_event(AccumulatingEvent::Offline(name))
        }
    }

    pub fn handle_timeout(&mut self, core: &mut Core, token: u64) {
        if self.timer_token == token {
            if self.is_our_elder(core.id()) {
                self.timer_token = core.timer.schedule(self.consensus_engine.gossip_period());
                self.consensus_engine.reset_gossip_period();
            } else {
                // TODO: send this only when the knowledge changes, not periodically.
                self.send_parsec_poke(core);
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

        if self.is_our_elder(core.id()) && self.consensus_engine.needs_pruning() {
            self.vote_for_event(AccumulatingEvent::ParsecPrune);
        }

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
    pub fn section_key_share(&self) -> Option<&SectionKeyShare> {
        self.section_keys_provider.key_share().ok()
    }

    ////////////////////////////////////////////////////////////////////////////
    // Message handling
    ////////////////////////////////////////////////////////////////////////////

    pub fn decide_message_status(&self, our_id: &PublicId, msg: &Message) -> Result<MessageStatus> {
        match msg.variant() {
            Variant::NeighbourInfo { .. } => {
                if !self.is_our_elder(our_id) {
                    return Ok(MessageStatus::Unknown);
                }
            }
            Variant::UserMessage(_) => {
                if !self.should_handle_user_message(our_id, msg.dst()) {
                    return Ok(MessageStatus::Unknown);
                }
            }
            Variant::GenesisUpdate(info) => {
                if !self.should_handle_genesis_update(our_id, info) {
                    return Ok(MessageStatus::Useless);
                }
            }
            Variant::JoinRequest(req) => {
                if !self.should_handle_join_request(our_id, req) {
                    // Note: We don't bounce this message because the current bounce-resend
                    // mechanism wouldn't preserve the original SocketAddr which is needed for
                    // properly handling this message.
                    // This is OK because in the worst case the join request just timeouts and the
                    // joining node sends it again.
                    return Ok(MessageStatus::Useless);
                }
            }
            Variant::NodeApproval(_) | Variant::BootstrapResponse(_) | Variant::Ping => {
                return Ok(MessageStatus::Useless)
            }
            Variant::Relocate(_)
            | Variant::MessageSignature(_)
            | Variant::BootstrapRequest(_)
            | Variant::ParsecPoke(_)
            | Variant::ParsecRequest(..)
            | Variant::ParsecResponse(..)
            | Variant::BouncedUntrustedMessage(_)
            | Variant::BouncedUnknownMessage { .. } => {}
        }

        if self.verify_message(msg)? {
            Ok(MessageStatus::Useful)
        } else if msg.src().is_section() {
            Ok(MessageStatus::Untrusted)
        } else {
            Ok(MessageStatus::Useless)
        }
    }

    // Ignore stale GenesisUpdates
    fn should_handle_genesis_update(
        &self,
        our_id: &PublicId,
        genesis_prefix_info: &GenesisPrefixInfo,
    ) -> bool {
        !self.is_our_elder(our_id)
            && genesis_prefix_info.parsec_version > self.consensus_engine.parsec_version()
    }

    // Ignore `JoinRequest` if we are not elder unless the join request is outdated in which case we
    // reply with `BootstrapResponse::Join` with the up-to-date info (see `handle_join_request`).
    fn should_handle_join_request(&self, our_id: &PublicId, req: &JoinRequest) -> bool {
        self.is_our_elder(our_id) || req.section_key != *self.shared_state.our_history.last_key()
    }

    // If elder, always handle UserMessage, otherwise handle it only if addressed directly to us
    // as a node.
    fn should_handle_user_message(&self, our_id: &PublicId, dst: &DstLocation) -> bool {
        self.is_our_elder(our_id) || dst.as_node().ok() == Some(our_id.name())
    }

    fn verify_message(&self, msg: &Message) -> Result<bool> {
        match msg.verify(self.shared_state.section_keys()) {
            Ok(VerifyStatus::Full) => Ok(true),
            Ok(VerifyStatus::Unknown) => Ok(false),
            Err(error) => {
                messages::log_verify_failure(msg, &error, self.shared_state.sections.keys());
                Err(error)
            }
        }
    }

    /// Handle message whose trust we can't establish because its proof contains only keys we don't
    /// know.
    pub fn handle_untrusted_message(
        &self,
        core: &mut Core,
        sender: Option<SocketAddr>,
        msg: Message,
    ) -> Result<()> {
        let src = msg.src().src_location();
        let bounce_dst = src.to_dst();
        let bounce_dst_key = *self.shared_state.section_key_by_location(&bounce_dst);

        let bounce_msg = Message::single_src(
            &core.full_id,
            bounce_dst,
            Some(bounce_dst_key),
            Variant::BouncedUntrustedMessage(Box::new(msg)),
        )?;
        let bounce_msg = bounce_msg.to_bytes();

        if let Some(sender) = sender {
            core.send_message_to_target(&sender, bounce_msg)
        } else {
            self.send_message_to_our_elders(core, bounce_msg)
        }

        Ok(())
    }

    /// Handle message that is "unknown" because we are not in the correct state (e.g. we are adult
    /// and the message is for elders). We bounce the message to our elders who have more
    /// information to decide what to do with it.
    pub fn handle_unknown_message(
        &self,
        core: &mut Core,
        sender: Option<SocketAddr>,
        msg_bytes: Bytes,
    ) -> Result<()> {
        let bounce_msg = Message::single_src(
            &core.full_id,
            DstLocation::Direct,
            None,
            Variant::BouncedUnknownMessage {
                message: msg_bytes,
                parsec_version: self.consensus_engine.parsec_version(),
            },
        )?;
        let bounce_msg = bounce_msg.to_bytes();

        // If the message came from one of our elders then bounce it only to them to avoid message
        // explosion.
        let our_elder_sender = sender.filter(|sender| {
            self.shared_state
                .sections
                .our_elders()
                .any(|p2p_node| p2p_node.peer_addr() == sender)
        });
        if let Some(sender) = our_elder_sender {
            core.send_message_to_target(&sender, bounce_msg)
        } else {
            self.send_message_to_our_elders(core, bounce_msg)
        }

        Ok(())
    }

    pub fn handle_bounced_untrusted_message(
        &mut self,
        core: &mut Core,
        dst_key: Option<bls::PublicKey>,
        bounced_msg: Message,
    ) -> Result<()> {
        let dst_key = if let Some(dst_key) = dst_key {
            dst_key
        } else {
            trace!(
                "Received BouncedUntrustedMessage({:?}) - missing dst key, discarding",
                bounced_msg,
            );
            return Ok(());
        };

        if let Err(error) = bounced_msg
            .src()
            .clone()
            .extend_proof_chain(&dst_key, &self.shared_state.our_history)
        {
            trace!(
                "Received BouncedUntrustedMessage({:?}) - extending proof failed, \
                 discarding: {:?}",
                bounced_msg,
                error,
            );
            return Ok(());
        }

        trace!(
            "Received BouncedUntrustedMessage({:?}) - resending with extended proof",
            bounced_msg
        );

        self.relay_message(core, &bounced_msg)
    }

    pub fn handle_bounced_unknown_message(
        &mut self,
        core: &mut Core,
        sender: P2pNode,
        bounced_msg_bytes: Bytes,
        sender_parsec_version: u64,
    ) {
        if sender_parsec_version >= self.consensus_engine.parsec_version() {
            trace!(
                "Received BouncedUnknownMessage({:?}) from {} \
                 - peer is up to date or ahead of us, discarding",
                MessageHash::from_bytes(&bounced_msg_bytes),
                sender
            );
            return;
        }

        trace!(
            "Received BouncedUnknownMessage({:?}) from {} \
             - peer is lagging behind, resending with parsec gossip",
            MessageHash::from_bytes(&bounced_msg_bytes),
            sender,
        );

        // First send parsec gossip to update the peer, then resend the message itself. If the
        // messages arrive in the same order they were sent, the gossip should update the peer so
        // they will then be able to handle the resent message. If not, the peer will bounce the
        // message again.

        self.send_parsec_gossip(core, Some((sender_parsec_version, sender.clone())));
        core.send_message_to_target(sender.peer_addr(), bounced_msg_bytes)
    }

    pub fn handle_neighbour_info(&mut self, elders_info: EldersInfo, src_key: bls::PublicKey) {
        if !self.shared_state.sections.has_key(&src_key) {
            self.vote_for_event(AccumulatingEvent::TheirKey {
                prefix: elders_info.prefix,
                key: src_key,
            });
        } else {
            trace!(
                "Ignore not new section key of {:?}: {:?}",
                elders_info,
                src_key
            );
            return;
        }

        if elders_info
            .prefix
            .is_neighbour(self.shared_state.our_prefix())
        {
            self.vote_for_event(AccumulatingEvent::SectionInfo(elders_info));
        }
    }

    pub fn handle_genesis_update(
        &mut self,
        core: &mut Core,
        genesis_prefix_info: GenesisPrefixInfo,
        section_key: bls::PublicKey,
    ) -> Result<()> {
        info!("Received GenesisUpdate: {:?}", genesis_prefix_info);

        core.msg_filter.reset();

        self.shared_state = SharedState::new(genesis_prefix_info.elders_info, section_key);
        self.section_keys_provider = SectionKeysProvider::new(None);
        self.reset_parsec(core, genesis_prefix_info.parsec_version)
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

        if let Some(msg) = self.message_accumulator.add(msg) {
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
            BootstrapResponse::Join {
                elders_info: self.shared_state.our_info().clone(),
                section_key: *self.shared_state.our_history.last_key(),
            }
        } else {
            let conn_infos: Vec<_> = self
                .shared_state
                .sections
                .closest(&destination)
                .elders
                .values()
                .map(|p2p_node| *p2p_node.peer_addr())
                .collect();
            BootstrapResponse::Rebootstrap(conn_infos)
        };

        debug!("Sending BootstrapResponse {:?} to {}", response, p2p_node);
        core.send_direct_message(p2p_node.peer_addr(), Variant::BootstrapResponse(response));
    }

    pub fn handle_join_request(
        &mut self,
        core: &mut Core,
        p2p_node: P2pNode,
        join_request: JoinRequest,
    ) {
        debug!("Received {:?} from {}", join_request, p2p_node);

        if join_request.section_key != *self.shared_state.our_history.last_key() {
            let response = BootstrapResponse::Join {
                elders_info: self.shared_state.our_info().clone(),
                section_key: *self.shared_state.our_history.last_key(),
            };
            trace!("Resending BootstrapResponse {:?} to {}", response, p2p_node,);
            core.send_direct_message(p2p_node.peer_addr(), Variant::BootstrapResponse(response));
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

            if !self
                .verify_message(payload.details.signed_msg())
                .unwrap_or(false)
            {
                debug!(
                    "Ignoring relocation JoinRequest from {} - untrusted.",
                    pub_id
                );
                return;
            }

            (details.age, Some(details.destination_key))
        } else {
            (MIN_AGE, None)
        };

        self.vote_for_event(AccumulatingEvent::Online {
            p2p_node,
            age,
            their_knowledge,
        })
    }

    pub fn handle_parsec_poke(&mut self, core: &mut Core, p2p_node: P2pNode, version: u64) {
        trace!("Received parsec poke v{} from {}", version, p2p_node);

        let version = version.min(self.consensus_engine.parsec_version());
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

    fn try_relay_message(&mut self, core: &mut Core, msg: &Message) -> Result<()> {
        if !msg
            .dst()
            .contains(core.name(), self.shared_state.our_prefix())
            || msg.dst().is_section()
        {
            // Relay closer to the destination or broadcast to the rest of our section.
            self.relay_message(core, msg)
        } else {
            Ok(())
        }
    }

    fn handle_accumulated_message(&mut self, core: &mut Core, msg: Message) -> Result<()> {
        trace!("accumulated message {:?}", msg);

        // TODO: this is almost the same as `Node::try_handle_message` - find a way
        // to avoid the duplication.
        self.try_relay_message(core, &msg)?;

        if !msg
            .dst()
            .contains(core.name(), self.shared_state.our_prefix())
        {
            return Ok(());
        }

        if core.msg_filter.contains_incoming(&msg) {
            trace!("not handling message - already handled: {:?}", msg);
            return Ok(());
        }

        match self.decide_message_status(core.id(), &msg)? {
            MessageStatus::Useful => {
                core.msg_filter.insert_incoming(&msg);
                core.msg_queue.push_back(msg.into_queued(None));
                Ok(())
            }
            MessageStatus::Untrusted => {
                trace!("Untrusted accumulated message: {:?}", msg);
                self.handle_untrusted_message(core, None, msg)
            }
            MessageStatus::Unknown => {
                trace!("Unknown accumulated message: {:?}", msg);
                self.handle_unknown_message(core, None, msg.to_bytes())
            }
            MessageStatus::Useless => {
                trace!("Useless accumulated message: {:?}", msg);
                Ok(())
            }
        }
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

        self.handle_accumulated_event(core, event, proof)?;

        Ok(true)
    }

    // Can we perform an action right now that can result in churn?
    fn is_ready_to_churn(&self) -> bool {
        self.shared_state.handled_genesis_event && !self.churn_in_progress
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
            self.consensus_engine.vote_for(NetworkEvent {
                payload: AccumulatingEvent::StartDkg(participants),
                proof_share: None,
            });
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
                self.vote_for_event(AccumulatingEvent::Relocate(details));
            }

            return true;
        }

        false
    }

    fn handle_accumulated_event(
        &mut self,
        core: &mut Core,
        event: AccumulatingEvent,
        proof: Option<Proof>,
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
            AccumulatingEvent::Online {
                p2p_node,
                age,
                their_knowledge,
            } => self.handle_online_event(
                core,
                p2p_node,
                age,
                their_knowledge,
                proof.expect("missing proof for Online"),
            ),
            AccumulatingEvent::Offline(name) => {
                self.handle_offline_event(core, name, proof.expect("missing proof for Offline"))
            }
            AccumulatingEvent::SectionInfo(elders_info) => self.handle_section_info_event(
                core,
                elders_info,
                proof.expect("missing proof for SectionInfo"),
            )?,
            AccumulatingEvent::SendNeighbourInfo { dst, nonce } => {
                self.handle_send_neighbour_info_event(core, dst, nonce)?
            }
            AccumulatingEvent::OurKey { prefix, key } => self.handle_our_key_event(
                core,
                prefix,
                key,
                proof.expect("missing proof for OurKey"),
            )?,
            AccumulatingEvent::TheirKey { prefix, key } => self.handle_their_key_event(
                core,
                prefix,
                key,
                proof.expect("missing proof for TheirKey"),
            )?,
            AccumulatingEvent::TheirKnowledge { prefix, knowledge } => self
                .handle_their_knowledge_event(
                    prefix,
                    knowledge,
                    proof.expect("missing proof for TheirKnowledge"),
                ),
            AccumulatingEvent::ParsecPrune => self.handle_prune_event(core)?,
            AccumulatingEvent::Relocate(payload) => self.handle_relocate_event(
                core,
                payload,
                proof.expect("missing proof for Relocate"),
            )?,
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
        let new_state = bincode::deserialize(related_info)?;

        // On split membership may need to be checked again.
        self.members_changed = true;
        self.shared_state.update(new_state);

        Ok(())
    }

    fn handle_online_event(
        &mut self,
        core: &mut Core,
        p2p_node: P2pNode,
        age: u8,
        their_knowledge: Option<bls::PublicKey>,
        proof: Proof,
    ) {
        if self.shared_state.add_member(
            p2p_node.clone(),
            age,
            proof,
            core.network_params.recommended_section_size,
        ) {
            info!("handle Online: {} (age: {})", p2p_node, age);

            self.members_changed = true;

            if self.is_our_elder(core.id()) {
                core.send_event(Event::MemberJoined {
                    name: *p2p_node.name(),
                    age,
                });
                self.send_node_approval(core, p2p_node, their_knowledge);
                self.print_network_stats();
            }
        } else {
            info!("ignore Online: {}", p2p_node);
        }
    }

    fn handle_offline_event(&mut self, core: &mut Core, name: XorName, proof: Proof) {
        if let Some(info) = self.shared_state.remove_member(
            &name,
            proof,
            core.network_params.recommended_section_size,
        ) {
            info!("handle Offline: {}", name);

            self.members_changed = true;

            core.transport.disconnect(*info.p2p_node.peer_addr());

            if self.is_our_elder(core.id()) {
                core.send_event(Event::MemberLeft {
                    name,
                    age: info.age(),
                });
            }
        } else {
            info!("ignore Offline: {}", name);
        }
    }

    fn handle_relocate_event(
        &mut self,
        core: &mut Core,
        details: RelocateDetails,
        proof: Proof,
    ) -> Result<(), RoutingError> {
        match self
            .shared_state
            .remove_member(
                details.pub_id.name(),
                proof,
                core.network_params.recommended_section_size,
            )
            .map(|info| info.state)
        {
            Some(MemberState::Relocating) => {
                info!("handle Relocate: {:?}", details);
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

        if !self.is_our_elder(core.id()) {
            return Ok(());
        }

        if &details.pub_id == core.id() {
            // Do not send the message to ourselves.
            return Ok(());
        }

        // We need to construct a proof that would be trusted by the destination section.
        let knowledge_index = self
            .shared_state
            .sections
            .knowledge_by_location(&DstLocation::Section(details.destination));

        let src = SrcLocation::Section(*self.shared_state.our_prefix());
        let dst = DstLocation::Node(*details.pub_id.name());
        let content = Variant::Relocate(details);

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

            let key = dkg_result.0.public_key_set.public_key();

            self.vote_for_event(AccumulatingEvent::OurKey {
                prefix: info.prefix,
                key,
            });

            if info.prefix.is_extension_of(self.shared_state.our_prefix()) {
                self.vote_for_event(AccumulatingEvent::TheirKey {
                    prefix: info.prefix,
                    key,
                });
            }

            self.vote_for_event(AccumulatingEvent::SectionInfo(info));
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
        proof: Proof,
    ) -> Result<()> {
        let elders_info = Proven::new(elders_info, proof);

        if elders_info.value.prefix == *self.shared_state.our_prefix()
            || elders_info
                .value
                .prefix
                .is_extension_of(self.shared_state.our_prefix())
        {
            // Our section
            if let Some(details) = self.section_update_barrier.handle_info(
                core.name(),
                self.shared_state.our_prefix(),
                elders_info,
            ) {
                self.update_our_section(core, details)?
            }
        } else {
            // Other section
            self.update_neighbour_info(core, elders_info)
        }

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

    fn handle_our_key_event(
        &mut self,
        core: &mut Core,
        prefix: Prefix,
        key: bls::PublicKey,
        proof: Proof,
    ) -> Result<()> {
        if !prefix.matches(core.name()) {
            return Ok(());
        }

        let key = Proven::new(key, proof);

        if let Some(details) = self
            .section_update_barrier
            .handle_our_key(self.shared_state.our_prefix(), key)
        {
            self.update_our_section(core, details)
        } else {
            Ok(())
        }
    }

    fn handle_their_key_event(
        &mut self,
        core: &mut Core,
        prefix: Prefix,
        key: bls::PublicKey,
        proof: Proof,
    ) -> Result<()> {
        if prefix.matches(core.name()) {
            return Ok(());
        }

        let key = Proven::new((prefix, key), proof);

        if key.value.0.is_extension_of(self.shared_state.our_prefix()) {
            if let Some(details) = self
                .section_update_barrier
                .handle_their_key(self.shared_state.our_prefix(), key)
            {
                self.update_our_section(core, details)?
            }
        } else {
            self.shared_state.sections.update_keys(key)
        }

        Ok(())
    }

    fn handle_their_knowledge_event(&mut self, prefix: Prefix, knowledge: u64, proof: Proof) {
        let knowledge = Proven::new((prefix, knowledge), proof);
        self.shared_state.sections.update_knowledge(knowledge)
    }

    fn handle_prune_event(&mut self, core: &mut Core) -> Result<()> {
        if !self.is_our_elder(core.id()) {
            debug!("ignore ParsecPrune event - not elder");
            return Ok(());
        }

        if self.churn_in_progress {
            debug!("ignore ParsecPrune event - churn in progress");
            return Ok(());
        }

        info!("handle ParsecPrune");

        self.reset_parsec(core, self.consensus_engine.parsec_version() + 1)?;
        self.send_genesis_updates(core);
        self.send_parsec_poke(core);
        Ok(())
    }

    /// Handle an accumulated `User` event
    fn handle_user_event(&mut self, core: &mut Core, payload: Vec<u8>) -> Result<(), RoutingError> {
        core.send_event(Event::Consensus(payload));
        Ok(())
    }

    fn update_our_section(&mut self, core: &mut Core, details: SectionUpdateDetails) -> Result<()> {
        let old_prefix = *self.shared_state.our_prefix();
        let was_elder = self.is_our_elder(core.id());
        let sibling_prefix = details.sibling.as_ref().map(|sibling| sibling.key.value.0);

        self.update_our_key_and_info(core, details.our.key, details.our.info)?;

        if let Some(sibling) = details.sibling {
            self.shared_state.sections.update_keys(sibling.key);
            self.update_neighbour_info(core, sibling.info);
        }

        let elders_info = self.shared_state.our_info();
        let new_prefix = elders_info.prefix;
        let is_elder = elders_info.elders.contains_key(core.name());

        core.msg_filter.reset();

        if was_elder || is_elder {
            info!("handle SectionInfo: {:?}", elders_info);
        } else {
            trace!("unhandled SectionInfo");
            return Ok(());
        }

        if new_prefix.is_extension_of(&old_prefix) {
            info!("Split");
        } else if old_prefix.is_extension_of(&new_prefix) {
            panic!("Merge not supported: {:?} -> {:?}", old_prefix, new_prefix);
        }

        self.reset_parsec(core, self.consensus_engine.parsec_version() + 1)?;

        if !is_elder {
            info!("Demoted");
            self.shared_state.demote();
            core.send_event(Event::Demoted);
            return Ok(());
        }

        // We can update the sibling knowledge already because we know they also reached consensus
        // on our `OurKey` so they know our latest key. Need to vote for it first though, to
        // accumulate the signatures.
        if let Some(prefix) = sibling_prefix {
            self.vote_for_event(AccumulatingEvent::TheirKnowledge {
                prefix,
                knowledge: self.shared_state.our_history.last_key_index(),
            })
        }

        self.send_genesis_updates(core);
        self.send_parsec_poke(core);

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

    fn update_our_key_and_info(
        &mut self,
        core: &mut Core,
        section_key: Proven<bls::PublicKey>,
        elders_info: Proven<EldersInfo>,
    ) -> Result<(), RoutingError> {
        self.section_keys_provider
            .finalise_dkg(core.name(), &elders_info.value)?;

        let neighbour_elders_removed = NeighbourEldersRemoved::builder(&self.shared_state.sections);
        self.shared_state
            .update_our_section(elders_info, section_key);
        let neighbour_elders_removed = neighbour_elders_removed.build(&self.shared_state.sections);
        self.prune_neighbour_connections(core, &neighbour_elders_removed);

        self.churn_in_progress = false;

        Ok(())
    }

    fn update_neighbour_info(&mut self, core: &mut Core, elders_info: Proven<EldersInfo>) {
        let neighbour_elders_removed = NeighbourEldersRemoved::builder(&self.shared_state.sections);
        self.shared_state.sections.add_neighbour(elders_info);
        let neighbour_elders_removed = neighbour_elders_removed.build(&self.shared_state.sections);
        self.prune_neighbour_connections(core, &neighbour_elders_removed);
    }

    ////////////////////////////////////////////////////////////////////////////
    // Parsec and Chain management
    ////////////////////////////////////////////////////////////////////////////

    fn reset_parsec(&mut self, core: &mut Core, new_parsec_version: u64) -> Result<()> {
        let is_elder = self.is_our_elder(core.id());

        let events = self.consensus_engine.prepare_reset(core.name());
        let events = self.filter_events_to_revote(events);

        let serialised_state = if is_elder {
            bincode::serialize(&self.shared_state)?
        } else {
            vec![]
        };

        self.consensus_engine.finalise_reset(
            &mut core.rng,
            core.full_id.clone(),
            self.shared_state.our_info(),
            serialised_state,
            new_parsec_version,
        );

        if is_elder {
            self.shared_state.handled_genesis_event = false;

            for event in events {
                self.vote_for_event(event);
            }
        }

        Ok(())
    }

    fn filter_events_to_revote(
        &self,
        mut events: Vec<AccumulatingEvent>,
    ) -> Vec<AccumulatingEvent> {
        let our_prefix = *self.shared_state.our_prefix();

        events.retain(|event| match &event {
            // Only re-vote if still relevant to our new prefix.
            AccumulatingEvent::Online { p2p_node, .. } => our_prefix.matches(p2p_node.name()),
            AccumulatingEvent::Offline(name) => our_prefix.matches(name),
            AccumulatingEvent::Relocate(details) => our_prefix.matches(details.pub_id.name()),
            // Drop: no longer relevant after prefix change.
            AccumulatingEvent::Genesis { .. }
            | AccumulatingEvent::StartDkg(_)
            | AccumulatingEvent::DkgResult { .. }
            | AccumulatingEvent::ParsecPrune
            | AccumulatingEvent::OurKey { .. } => false,

            // Keep: Additional signatures for neighbours for sec-msg-relay.
            AccumulatingEvent::SectionInfo(elders_info) => {
                our_prefix.is_neighbour(&elders_info.prefix)
            }

            // Only revote if the recipient is still our neighbour
            AccumulatingEvent::SendNeighbourInfo { dst, .. } => {
                self.shared_state.sections.is_in_neighbour(dst)
            }

            // Keep: Still relevant after prefix change.
            AccumulatingEvent::TheirKey { .. }
            | AccumulatingEvent::TheirKnowledge { .. }
            | AccumulatingEvent::User(_) => true,
        });
        events
    }

    fn create_genesis_prefix_info(&self) -> GenesisPrefixInfo {
        GenesisPrefixInfo {
            elders_info: self.shared_state.sections.proven_our().clone(),
            parsec_version: self.consensus_engine.parsec_version(),
        }
    }

    // Detect non-responsive peers and vote them out.
    fn vote_for_remove_unresponsive_peers(&mut self) {
        let unresponsive_nodes = self
            .consensus_engine
            .detect_unresponsive(self.shared_state.our_info());
        for pub_id in &unresponsive_nodes {
            info!("Voting for unresponsive node {:?}", pub_id);
            self.vote_for_event(AccumulatingEvent::Offline(*pub_id.name()));
        }
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

        let genesis_prefix_info = self.create_genesis_prefix_info();

        let src = SrcLocation::Section(genesis_prefix_info.elders_info.value.prefix);
        let dst = DstLocation::Node(*p2p_node.name());

        let variant = Variant::NodeApproval(genesis_prefix_info);
        let their_knowledge =
            their_knowledge.and_then(|key| self.shared_state.our_history.index_of(&key));

        if let Err(error) = self.send_routing_message(core, src, dst, variant, their_knowledge) {
            debug!("Failed sending NodeApproval to {}: {:?}", p2p_node, error);
        }
    }

    // Send `GenesisUpdate` message to all non-elders.
    fn send_genesis_updates(&mut self, core: &mut Core) {
        for (recipient, msg) in self.create_genesis_updates() {
            trace!("Send {:?} to {}", msg.content, recipient);

            core.send_direct_message(
                recipient.peer_addr(),
                Variant::MessageSignature(Box::new(msg)),
            );
        }
    }

    // TODO: make non-pub
    pub fn create_genesis_updates(&self) -> Vec<(P2pNode, AccumulatingMessage)> {
        let genesis_prefix_info = self.create_genesis_prefix_info();

        self.shared_state
            .adults_and_infants_p2p_nodes()
            .cloned()
            .filter_map(|recipient| {
                let variant = Variant::GenesisUpdate(genesis_prefix_info.clone());
                let dst = DstLocation::Node(*recipient.name());
                let proof_start_index = self
                    .shared_state
                    .our_history
                    .last_key_index()
                    .saturating_sub(1);

                match self.to_accumulating_message(dst, variant, Some(proof_start_index)) {
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
            .filter_map(|pub_id| self.shared_state.get_p2p_node(pub_id.name()))
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

    fn send_parsec_poke(&mut self, core: &mut Core) {
        let version = self.consensus_engine.parsec_version();

        for recipient in self.shared_state.sections.our_elders() {
            if recipient.public_id() == core.id() {
                continue;
            }

            trace!("send parsec poke v{} to {}", version, recipient);
            core.send_direct_message(recipient.peer_addr(), Variant::ParsecPoke(version))
        }
    }

    // Send message over the network.
    pub fn relay_message(&mut self, core: &mut Core, msg: &Message) -> Result<()> {
        let (targets, dg_size) = delivery_group::delivery_targets(
            msg.dst(),
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

        let targets: Vec<_> = targets.into_iter().map(|node| *node.peer_addr()).collect();
        core.send_message_to_targets(&targets, dg_size, msg.to_bytes());

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

        // If the source is a single node, we don't even need to send signatures, so let's cut this
        // short
        if !src.is_section() {
            let msg = Message::single_src(&core.full_id, dst, None, variant)?;
            return self.handle_accumulated_message(core, msg);
        }

        let accumulating_msg =
            self.to_accumulating_message(dst, variant, proof_start_index_override)?;

        let targets = delivery_group::signature_targets(
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
                if let Some(msg) = self.message_accumulator.add(accumulating_msg.clone()) {
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
        let proof_chain = self.shared_state.prove(&dst, proof_start_index_override);
        let key_share = self.section_keys_provider.key_share()?;
        let dst_key = *self.shared_state.section_key_by_location(&dst);

        let content = PlainMessage {
            src: *self.shared_state.our_prefix(),
            dst,
            dst_key,
            variant,
        };

        let proof_share = content.prove(
            key_share.public_key_set.clone(),
            key_share.index,
            &key_share.secret_key_share,
        )?;

        Ok(AccumulatingMessage::new(content, proof_chain, proof_share))
    }

    // TODO: consider changing this so it sends only to a subset of the elders
    // (say 1/3 of the ones closest to our name or so)
    fn send_message_to_our_elders(&self, core: &mut Core, msg_bytes: Bytes) {
        let targets: Vec<_> = self
            .shared_state
            .sections
            .our_elders()
            .map(P2pNode::peer_addr)
            .copied()
            .collect();
        core.send_message_to_targets(&targets, targets.len(), msg_bytes)
    }

    ////////////////////////////////////////////////////////////////////////////
    // Miscellaneous
    ////////////////////////////////////////////////////////////////////////////

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
    pub fn update_section_knowledge(&mut self, our_name: &XorName, msg: &Message) {
        let hash = msg.hash();
        let events = self.shared_state.update_section_knowledge(
            our_name,
            msg.src(),
            msg.dst_key().as_ref(),
            hash,
        );

        for event in events {
            self.vote_for_event(event)
        }
    }

    fn print_network_stats(&self) {
        self.shared_state.sections.network_stats().print()
    }
}

pub struct RelocateParams {
    pub conn_infos: Vec<SocketAddr>,
    pub details: SignedRelocateDetails,
}

// Create `EldersInfo` for the first node.
fn create_first_elders_info(
    pk_set: &bls::PublicKeySet,
    sk_share: &bls::SecretKeyShare,
    p2p_node: P2pNode,
) -> Result<Proven<EldersInfo>> {
    let name = *p2p_node.name();
    let node = (name, p2p_node);
    let elders_info = EldersInfo::new(iter::once(node).collect(), Prefix::default());
    let proof = create_first_proof(pk_set, sk_share, &elders_info)?;
    Ok(Proven::new(elders_info, proof))
}

fn create_first_shared_state(
    pk_set: &bls::PublicKeySet,
    sk_share: &bls::SecretKeyShare,
    elders_info: Proven<EldersInfo>,
) -> Result<SharedState> {
    let mut shared_state = SharedState::new(elders_info, pk_set.public_key());

    for p2p_node in shared_state.sections.our().elders.values() {
        let proof = create_first_proof(
            pk_set,
            sk_share,
            &member_info::to_sign(p2p_node.name(), MemberState::Joined),
        )?;
        shared_state
            .our_members
            .add(p2p_node.clone(), MIN_AGE, proof);
    }

    Ok(shared_state)
}

fn create_first_proof<T: Serialize>(
    pk_set: &bls::PublicKeySet,
    sk_share: &bls::SecretKeyShare,
    payload: &T,
) -> Result<Proof> {
    let bytes = bincode::serialize(payload)?;
    let signature_share = sk_share.sign(&bytes);
    let signature = pk_set
        .combine_signatures(iter::once((0, &signature_share)))
        .map_err(|_| RoutingError::InvalidSignatureShares)?;

    Ok(Proof {
        public_key: pk_set.public_key(),
        signature,
    })
}
