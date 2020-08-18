// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    consensus::{
        self, threshold_count, AccumulatingEvent, AccumulationError, ConsensusEngine, DkgResult,
        DkgVoter, ParsecRequest, ParsecResponse, Proof, ProofShare, Proven, Vote, VoteAccumulator,
    },
    core::Core,
    delivery_group,
    error::{Result, RoutingError},
    event::Event,
    id::{P2pNode, PublicId},
    location::{DstLocation, SrcLocation},
    messages::{
        self, AccumulatingMessage, BootstrapResponse, EldersUpdate, JoinRequest, Message,
        MessageAccumulator, MessageHash, MessageStatus, PlainMessage, Variant, VerifyStatus,
    },
    pause::PausedState,
    relocation::{RelocateDetails, SignedRelocateDetails},
    rng::MainRng,
    section::{
        EldersInfo, MemberInfo, NeighbourEldersRemoved, SectionKeyShare, SectionKeysProvider,
        SectionUpdateBarrier, SectionUpdateDetails, SharedState, MIN_AGE,
    },
    time::Duration,
};
use bls_dkg::key_gen::message::Message as DkgMessage;
use bytes::Bytes;
use crossbeam_channel::Sender;
use itertools::Itertools;
use rand::Rng;
use serde::Serialize;
use std::{cmp::Ordering, collections::BTreeSet, iter, net::SocketAddr};
use xor_name::{Prefix, XorName};

// Interval to progress DKG timed phase
const DKG_PROGRESS_INTERVAL: Duration = Duration::from_secs(30);

// The approved stage - node is a full member of a section and is performing its duties according
// to its persona (infant, adult or elder).
pub(crate) struct Approved {
    pub consensus_engine: ConsensusEngine,
    pub shared_state: SharedState,
    section_keys_provider: SectionKeysProvider,
    message_accumulator: MessageAccumulator,
    vote_accumulator: VoteAccumulator,
    gossip_timer_token: Option<u64>,
    section_update_barrier: SectionUpdateBarrier,
    // Marker indicating we are processing churn event
    churn_in_progress: bool,
    // Flag indicating that our section members changed (a node joined or left) and we might need
    // to change our elders.
    members_changed: bool,
    // Voter for DKG
    dkg_voter: DkgVoter,
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
        let consensus_engine = ConsensusEngine::new(
            &mut core.rng,
            core.full_id.clone(),
            shared_state.sections.our(),
            parsec_version,
        );

        let section_keys_provider = SectionKeysProvider::new(section_key_share);

        let gossip_timer_token = if shared_state.our_info().elders.contains_key(core.name()) {
            Some(core.timer.schedule(consensus_engine.gossip_period()))
        } else {
            None
        };

        Ok(Self {
            consensus_engine,
            shared_state,
            section_keys_provider,
            message_accumulator: Default::default(),
            vote_accumulator: Default::default(),
            gossip_timer_token,
            section_update_barrier: Default::default(),
            churn_in_progress: false,
            members_changed: false,
            dkg_voter: Default::default(),
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
            vote_accumulator: self.vote_accumulator,
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

        let gossip_timer_token = if is_self_elder {
            Some(core.timer.schedule(state.consensus_engine.gossip_period()))
        } else {
            None
        };

        let stage = Self {
            consensus_engine: state.consensus_engine,
            shared_state: state.shared_state,
            section_keys_provider: state.section_keys_provider,
            message_accumulator: state.msg_accumulator,
            vote_accumulator: state.vote_accumulator,
            gossip_timer_token,
            section_update_barrier: state.section_update_barrier,
            // TODO: these fields should come from PausedState too
            churn_in_progress: false,
            members_changed: false,
            dkg_voter: Default::default(),
        };

        (stage, core)
    }

    // Cast a vote for totally ordered event via parsec.
    pub fn cast_ordered_vote(&mut self, event: AccumulatingEvent) {
        match self
            .section_keys_provider
            .key_share()
            .and_then(|share| event.clone().into_network_event(share))
        {
            Ok(event) => self.consensus_engine.vote_for(event),
            Err(error) => log_or_panic!(
                log::Level::Error,
                "Failed to create NetworkEvent {:?}: {}",
                event,
                error,
            ),
        }
    }

    // Cast a vote that doesn't need total order, only section consensus.
    pub fn cast_unordered_vote(&mut self, core: &mut Core, vote: Vote) -> Result<()> {
        trace!("Vote for {:?}", vote);

        let key_share = self.section_keys_provider.key_share()?;
        let proof_share = vote.prove(
            key_share.public_key_set.clone(),
            key_share.index,
            &key_share.secret_key_share,
        )?;

        // Broadcast the vote to the rest of the section elders.
        let variant = Variant::Vote {
            content: vote.clone(),
            proof_share: proof_share.clone(),
        };
        let proof_chain = self.shared_state.create_proof_chain_for_our_info(None);
        let message = Message::single_src(
            &core.full_id,
            DstLocation::Section(*core.name()),
            variant,
            Some(proof_chain),
            Some(*self.shared_state.our_history.last_key()),
        )?;
        self.relay_message(core, &message)?;

        self.handle_unordered_vote(core, vote, proof_share)
    }

    // Insert the vote into the vote accumulator and handle it if accumulated.
    pub fn handle_unordered_vote(
        &mut self,
        core: &mut Core,
        vote: Vote,
        proof_share: ProofShare,
    ) -> Result<()> {
        match self.vote_accumulator.add(vote, proof_share) {
            Ok((vote, proof)) => self.handle_unordered_consensus(core, vote, proof),
            Err(AccumulationError::NotEnoughShares)
            | Err(AccumulationError::AlreadyAccumulated) => Ok(()),
            Err(error) => {
                error!("Failed to add vote: {}", error);
                Err(RoutingError::InvalidSignatureShare)
            }
        }
    }

    pub fn check_lagging(&mut self, core: &mut Core, peer: &SocketAddr, proof_share: &ProofShare) {
        let public_key = proof_share.public_key_set.public_key();

        if self.shared_state.our_history.has_key(&public_key)
            && public_key != *self.shared_state.our_history.last_key()
        {
            // The key is recognized as non-last, indicating the peer is lagging.
            core.send_direct_message(
                peer,
                Variant::NotifyLagging {
                    shared_state: self.shared_state.clone(),
                    parsec_version: self.consensus_engine.parsec_version(),
                },
            );
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

        if !self.is_our_elder(core.id()) {
            return;
        }

        if let Some(info) = self.shared_state.our_members.get(&name) {
            let info = info.clone().leave();
            self.cast_ordered_vote(AccumulatingEvent::Offline(info))
        }
    }

    pub fn handle_timeout(&mut self, core: &mut Core, token: u64) {
        if self.gossip_timer_token == Some(token) {
            if self.is_our_elder(core.id()) {
                self.gossip_timer_token =
                    Some(core.timer.schedule(self.consensus_engine.gossip_period()));
                self.consensus_engine.reset_gossip_period();
            }
        } else if self.dkg_voter.timer_token() == token {
            self.dkg_voter
                .set_timer_token(core.timer.schedule(DKG_PROGRESS_INTERVAL));
            self.progress_dkg(core);
        }
    }

    fn check_dkg(&mut self, core: &mut Core) {
        let (completed, mut backlog_votes) = self.dkg_voter.check_dkg();

        for (dkg_key, dkg_result) in completed {
            debug!("Completed DKG {:?}", dkg_key);
            self.notify_old_elders(
                core,
                &dkg_key.0,
                dkg_key.1,
                dkg_result.public_key_set.clone(),
            );
            if let Err(err) = self.handle_dkg_result_event(core, &dkg_key.0, dkg_key.1, &dkg_result)
            {
                debug!("Failed handle DKG result of {:?} - {:?}", dkg_key, err);
            } else {
                self.dkg_voter.remove_voter(dkg_key.1);
            }
        }

        // To avoid the case that DKG was completed after received certain accumulated votes.
        while let Some((vote, proof)) = backlog_votes.pop_back() {
            trace!("handle cached accumulated vote {:?}", vote);
            // In case of error, vote got cached inside `handle_unordered_consensus`.
            if let Err(err) = self.handle_unordered_consensus(core, vote.clone(), proof) {
                debug!("Failed ({:?}) handle cached event {:?}", err, vote);
            }
        }
    }

    fn progress_dkg(&mut self, core: &mut Core) {
        for (dkg_key, message) in self.dkg_voter.progress_dkg(&mut core.rng) {
            let _ = self.broadcast_dkg_message(core, dkg_key.0, dkg_key.1, message);
        }

        self.check_dkg(core);
    }

    pub fn finish_handle_input(&mut self, core: &mut Core) {
        if self.shared_state.our_info().elders.len() == 1 {
            // If we're the only node then invoke poll_all directly
            if let Err(error) = self.poll_all(core) {
                error!("poll failed: {:?}", error);
            }
        }

        if self.section_keys_provider.key_share().is_ok()
            && self.is_our_elder(core.id())
            && self.consensus_engine.needs_pruning()
        {
            self.cast_ordered_vote(AccumulatingEvent::ParsecPrune);
        }

        self.send_parsec_gossip(core, None);
    }

    /// Vote for a user-defined event.
    pub fn vote_for_user_event(&mut self, event: Vec<u8>) {
        self.cast_ordered_vote(AccumulatingEvent::User(event));
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
            Variant::EldersUpdate(payload) => {
                if self.is_our_elder(our_id)
                    || payload.parsec_version <= self.consensus_engine.parsec_version()
                {
                    return Ok(MessageStatus::Useless);
                }
            }
            Variant::Promote { shared_state, .. } => {
                if self.is_our_elder(our_id) {
                    return Ok(MessageStatus::Useless);
                }
                // DKG not completed yet.
                if !self
                    .section_keys_provider
                    .has_key_or_candidate(shared_state.our_info())
                {
                    return Ok(MessageStatus::Unknown);
                }
            }
            Variant::NotifyLagging { .. } => {
                // Adult shall be updated by EldersUpdate, or Promote if is going to be promoted.
                if !self.is_our_elder(our_id) {
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
            Variant::DKGMessage { participants, .. }
            | Variant::DKGOldElders { participants, .. } => {
                if self.is_our_elder(our_id) || participants.contains(our_id) {
                    return Ok(MessageStatus::Useful);
                } else {
                    return Ok(MessageStatus::Unknown);
                }
            }
            Variant::ParsecRequest(..) | Variant::ParsecResponse(..) => {
                if !self.is_our_elder(our_id) {
                    return Ok(MessageStatus::Useless);
                }
            }
            Variant::NodeApproval(_) | Variant::BootstrapResponse(_) | Variant::Ping => {
                return Ok(MessageStatus::Useless)
            }
            Variant::Vote { proof_share, .. } => {
                if !self.should_handle_vote(proof_share) {
                    // Message will be bounced if we are lagging (not known of the signing key).
                    return Ok(MessageStatus::Unknown);
                }
            }
            Variant::MessageSignature(accumulating_msg) => {
                if !self.should_handle_vote(&accumulating_msg.proof_share) {
                    // Message will be bounced if we are lagging (not known of the signing key).
                    return Ok(MessageStatus::Unknown);
                }
            }
            Variant::Relocate(_)
            | Variant::BootstrapRequest(_)
            | Variant::BouncedUntrustedMessage(_)
            | Variant::BouncedUnknownMessage { .. } => (),
        }

        if self.verify_message(msg)? {
            Ok(MessageStatus::Useful)
        } else {
            Ok(MessageStatus::Untrusted)
        }
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

    // Handle `Vote` message only if signed with known key, otherwise bounce.
    fn should_handle_vote(&self, proof_share: &ProofShare) -> bool {
        self.shared_state
            .our_history
            .has_key(&proof_share.public_key_set.public_key())
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
            Variant::BouncedUntrustedMessage(Box::new(msg)),
            None,
            Some(bounce_dst_key),
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
            Variant::BouncedUnknownMessage {
                src_key: *self.shared_state.our_history.last_key(),
                message: msg_bytes,
            },
            None,
            None,
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
        sender: P2pNode,
        dst_key: Option<bls::PublicKey>,
        bounced_msg: Message,
    ) {
        trace!(
            "Received BouncedUntrustedMessage({:?}) from {}...",
            bounced_msg,
            sender
        );

        let dst_key = if let Some(dst_key) = dst_key {
            dst_key
        } else {
            trace!("    ...missing dst key, discarding");
            return;
        };

        let resend_msg =
            match bounced_msg.extend_proof_chain(&dst_key, &self.shared_state.our_history) {
                Ok(msg) => msg,
                Err(error) => {
                    trace!("    ...extending proof failed, discarding: {:?}", error);
                    return;
                }
            };

        trace!("    ...resending with extended proof");
        core.send_message_to_target(sender.peer_addr(), resend_msg.to_bytes())
    }

    pub fn handle_bounced_unknown_message(
        &mut self,
        core: &mut Core,
        sender: P2pNode,
        bounced_msg_bytes: Bytes,
        sender_last_key: &bls::PublicKey,
    ) {
        if !self.shared_state.our_history.has_key(sender_last_key)
            || sender_last_key == self.shared_state.our_history.last_key()
        {
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
             - peer is lagging behind, resending with NotifyLagging",
            MessageHash::from_bytes(&bounced_msg_bytes),
            sender,
        );
        // First send NotifyLagging to update the peer, then resend the message itself. If the
        // messages arrive in the same order they were sent, the notification should update the peer
        // so it will then be able to handle the resent message. If not, the peer will bounce the
        // message again.
        core.send_direct_message(
            sender.peer_addr(),
            Variant::NotifyLagging {
                shared_state: self.shared_state.clone(),
                parsec_version: self.consensus_engine.parsec_version(),
            },
        );
        core.send_message_to_target(sender.peer_addr(), bounced_msg_bytes)
    }

    pub fn handle_neighbour_info(
        &mut self,
        core: &mut Core,
        elders_info: EldersInfo,
        src_key: bls::PublicKey,
    ) -> Result<()> {
        if !self.shared_state.sections.has_key(&src_key) {
            self.cast_unordered_vote(
                core,
                Vote::TheirKey {
                    prefix: elders_info.prefix,
                    key: src_key,
                },
            )?;
        } else {
            trace!(
                "Ignore not new section key of {:?}: {:?}",
                elders_info,
                src_key
            );
            return Ok(());
        }

        if elders_info
            .prefix
            .is_neighbour(self.shared_state.our_prefix())
        {
            self.cast_unordered_vote(core, Vote::SectionInfo(elders_info))
        } else {
            Ok(())
        }
    }

    pub fn handle_elders_update(
        &mut self,
        core: &mut Core,
        section_key: bls::PublicKey,
        payload: EldersUpdate,
    ) -> Result<()> {
        info!("Received {:?}", payload);

        // Receiving an old EldersUpdate or we are going to be promoted soon.
        if payload.elders_info.value.position(core.name()).is_some()
            || self
                .section_keys_provider
                .has_key_or_candidate(&payload.elders_info.value)
        {
            debug!("ignore EldersUpdate - actually promoted");
            return Ok(());
        }

        core.msg_filter.reset();

        self.shared_state = SharedState::new(section_key, payload.elders_info);
        self.section_keys_provider = SectionKeysProvider::new(None);
        self.reset_parsec(core, payload.parsec_version)
    }

    pub fn handle_promote(
        &mut self,
        core: &mut Core,
        shared_state: SharedState,
        parsec_version: u64,
    ) -> Result<()> {
        // On sender side, the check has already been carried out once.
        // Doing the check again here just to prevent malicious case.
        if !shared_state.our_info().elders.contains_key(core.name()) {
            debug!("ignore Promote - not actually promoted");
            return Ok(());
        }

        info!("Promoted to Elder");
        info!("update our section: {:?}", shared_state.our_info());

        let old_prefix = self.shared_state.our_info().prefix;

        core.msg_filter.reset();

        // TODO: verify `shared_state` !
        self.shared_state.update(shared_state)?;

        self.reset_parsec(core, parsec_version)?;
        self.gossip_timer_token = Some(core.timer.schedule(self.consensus_engine.gossip_period()));

        match self
            .section_keys_provider
            .finalise_dkg(core.name(), self.shared_state.our_info())
        {
            Ok(()) => (),
            Err(RoutingError::InvalidElderDkgResult) => {
                // Ignore `InvalidElderDkgResult` because it just means the DKG hasn't completed
                // for us yet.
                // TODO: check that we have an ongoing DKG instance corresponding to the latest
                // EldersInfo.
            }
            Err(error) => return Err(error),
        }

        self.send_elders_update(core)?;

        // Only need to vote during split and for sibling section, to accumulate enough votes.
        if old_prefix != self.shared_state.our_info().prefix {
            let prefix = self.shared_state.our_info().prefix.sibling();
            let key_index = self.shared_state.our_history.last_key_index();
            self.cast_unordered_vote(core, Vote::TheirKnowledge { prefix, key_index })?;
        }

        core.send_event(Event::PromotedToElder);
        self.send_elders_changed_event(core);

        self.print_network_stats();

        Ok(())
    }

    pub fn handle_lagging(
        &mut self,
        core: &mut Core,
        shared_state: SharedState,
        parsec_version: u64,
    ) -> Result<()> {
        if !shared_state.our_prefix().matches(core.name()) {
            debug!("ignore lagging notification - not our section");
            return Ok(());
        }

        if self
            .shared_state
            .our_history
            .has_key(shared_state.our_history.last_key())
        {
            debug!("ignore lagging notification - already updated");
            return Ok(());
        }

        if !shared_state
            .our_history
            .has_key(self.shared_state.our_history.last_key())
        {
            debug!("ignore lagging notification - our key is ahead");
            return Ok(());
        }

        trace!("Handle NotifyLagging");
        let old_prefix = self.shared_state.our_info().prefix;

        // TODO: verify `shared_state` !
        self.shared_state.update(shared_state)?;

        self.reset_parsec(core, parsec_version)?;

        match self
            .section_keys_provider
            .finalise_dkg(core.name(), self.shared_state.our_info())
        {
            Ok(()) => (),
            Err(error) => return Err(error),
        }

        self.send_elders_update(core)?;
        // Only need to vote during split and for sibling section, to accumulate enough votes.
        if old_prefix != self.shared_state.our_info().prefix {
            let prefix = self.shared_state.our_info().prefix.sibling();
            let key_index = self.shared_state.our_history.last_key_index();
            self.cast_unordered_vote(core, Vote::TheirKnowledge { prefix, key_index })?;
        }

        self.print_network_stats();

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

        if self.shared_state.our_members.is_joined(pub_id.name()) {
            debug!(
                "Ignoring JoinRequest from {} - already member of our section.",
                pub_id
            );
            return;
        }

        // This joining node is being relocated to us.
        let (age, previous_name, their_knowledge) =
            if let Some(payload) = join_request.relocate_payload {
                if !payload.verify_identity(&pub_id) {
                    debug!(
                        "Ignoring relocation JoinRequest from {} - invalid signature.",
                        pub_id
                    );
                    return;
                }

                // FIXME: this might panic if the payload is malformed.
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

                (
                    details.age,
                    Some(*details.pub_id.name()),
                    Some(details.destination_key),
                )
            } else {
                (MIN_AGE, None, None)
            };

        self.cast_ordered_vote(AccumulatingEvent::Online {
            member_info: MemberInfo::joined(p2p_node, age),
            previous_name,
            their_knowledge,
        })
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

    pub fn handle_dkg_old_elders(
        &mut self,
        core: &mut Core,
        participants: BTreeSet<PublicId>,
        section_key_index: u64,
        public_key_set: bls::PublicKeySet,
        src_id: PublicId,
    ) -> Result<()> {
        debug!(
            "notified by DKG participants {:?} to vote for SectionInfo",
            participants
        );

        // Accumulate quorum notifications then carry out the further process.
        if !self
            .dkg_voter
            .add_old_elders_notification(&participants, &src_id)
        {
            return Ok(());
        }

        let dkg_result = DkgResult::new(public_key_set, None);
        if self.dkg_voter.has_info(
            &(participants.clone(), section_key_index),
            &dkg_result,
            self.shared_state.our_history.last_key_index(),
        ) {
            self.handle_dkg_result_event(core, &participants, section_key_index, &dkg_result)
        } else {
            Ok(())
        }
    }

    pub fn handle_dkg_message(
        &mut self,
        core: &mut Core,
        participants: BTreeSet<PublicId>,
        section_key_index: u64,
        message_bytes: Bytes,
        sender: PublicId,
    ) -> Result<()> {
        trace!(
            "handle dkg message of p{:?}-{:?} from {}",
            participants,
            section_key_index,
            sender
        );

        if participants.contains(core.id()) {
            self.init_dkg_gen(core, participants.clone(), section_key_index);
        } else {
            // During split, a non-participant Elder could be picked as a relayer to forward DKG
            // messages, when the new elders of one sub-section are currently all non-elders.
            self.try_forward_dkg_message_to_non_elder(
                core,
                participants,
                section_key_index,
                message_bytes,
                &sender,
            );
            return Ok(());
        }

        let msg_parsed = bincode::deserialize(&message_bytes[..])?;

        trace!("processing dkg message {:?}", msg_parsed);

        let responses = self.dkg_voter.process_dkg_message(
            &mut core.rng,
            &(participants.clone(), section_key_index),
            msg_parsed,
        );

        // Only a valid DkgMessage, which results in some responses, shall reset the ticker.
        if !responses.is_empty() {
            self.dkg_voter
                .set_timer_token(core.timer.schedule(DKG_PROGRESS_INTERVAL));
        }

        for response in responses {
            let _ =
                self.broadcast_dkg_message(core, participants.clone(), section_key_index, response);
        }

        self.try_forward_dkg_message_to_non_elder(
            core,
            participants,
            section_key_index,
            message_bytes,
            &sender,
        );

        self.check_dkg(core);
        Ok(())
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

        let (event, proof) = match self.consensus_engine.poll(self.shared_state.sections.our()) {
            None => return Ok(false),
            Some((event, proof)) => (event, proof),
        };

        self.handle_ordered_consensus(core, event, proof)?;

        Ok(true)
    }

    // Can we perform an action right now that can result in churn?
    fn is_ready_to_churn(&self) -> bool {
        !self.churn_in_progress
    }

    // Generate a new section info based on the current set of members and vote for it if it
    // changed.
    fn promote_and_demote_elders(&mut self, core: &mut Core) -> bool {
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

        if new_infos.len() > 1 {
            debug!("splitting with new_infos {:?}", new_infos);
        }

        for info in new_infos {
            let participants: BTreeSet<_> = info.elder_ids().copied().collect();
            let section_key_index = self.shared_state.our_history.last_key_index();
            let dkg_key = (participants.clone(), section_key_index);

            if let Some(dkg_result) = self.dkg_voter.push_info(&dkg_key, info) {
                // Got notified of the DKG result, happen during split or demote.
                if let Err(err) = self.handle_dkg_result_event(
                    core,
                    &participants,
                    section_key_index,
                    &dkg_result,
                ) {
                    debug!(
                        "Failed handle notified dkg_result {:?} - {:?}",
                        dkg_key, err
                    );
                    self.dkg_voter
                        .insert_old_elders_dkg_result(dkg_key, dkg_result);
                }
                continue;
            }

            // In case all the current elders split into one side of the sub-section, and to avoid
            // malicious elders within one side don't carry out vote, triggering the sibling
            // section's DKG process by send them an Initial DKG message.
            if !participants.contains(core.id()) {
                trace!(
                    "Triggering DKG process for sibling section during splitting {:?}",
                    participants
                );

                let threshold = threshold_count(participants.len());
                let message = DkgMessage::Initialization {
                    // FIXME: will be counted as an extra vote
                    key_gen_id: 0,
                    m: threshold,
                    n: participants.len(),
                    member_list: participants.clone(),
                };
                let _ = self.broadcast_dkg_message(core, participants, section_key_index, message);
            } else {
                self.init_dkg_gen(core, participants, section_key_index);
            }
        }

        true
    }

    fn init_dkg_gen(
        &mut self,
        core: &mut Core,
        participants: BTreeSet<PublicId>,
        section_key_index: u64,
    ) {
        if section_key_index < self.shared_state.our_history.last_key_index()
            || self.section_keys_provider.has_dkg(&participants)
        {
            trace!(
                "Already has DKG of {:?} - {:?}",
                participants,
                section_key_index
            );
            return;
        }
        for message in self
            .dkg_voter
            .init_dkg_gen(&core.full_id, &(participants.clone(), section_key_index))
        {
            let _ =
                self.broadcast_dkg_message(core, participants.clone(), section_key_index, message);
            self.dkg_voter
                .set_timer_token(core.timer.schedule(DKG_PROGRESS_INTERVAL));
        }
    }

    // As an Elder, forwarding DKG message for Adult participants.
    fn try_forward_dkg_message_to_non_elder(
        &mut self,
        core: &mut Core,
        participants: BTreeSet<PublicId>,
        section_key_index: u64,
        message_bytes: Bytes,
        sender: &PublicId,
    ) {
        if self.is_our_elder(core.id()) && !self.is_our_elder(sender) {
            let variant = Variant::DKGMessage {
                participants: participants.clone(),
                section_key_index,
                message: message_bytes,
            };

            for pub_id in participants.iter() {
                if self.is_our_elder(pub_id) {
                    continue;
                }
                if let Some(target) = self.shared_state.get_p2p_node(pub_id.name()) {
                    trace!("Sending DKG to {:?} - {:?}", pub_id.name(), variant);
                    core.send_direct_message(target.peer_addr(), variant.clone());
                }
            }
        }
    }

    fn broadcast_dkg_message(
        &mut self,
        core: &mut Core,
        participants: BTreeSet<PublicId>,
        section_key_index: u64,
        dkg_message: DkgMessage<PublicId>,
    ) -> Result<()> {
        trace!("broadcasting DKG message {:?}", dkg_message);
        let message: Bytes = bincode::serialize(&dkg_message)?.into();
        let variant = Variant::DKGMessage {
            participants: participants.clone(),
            section_key_index,
            message: message.clone(),
        };

        for pub_id in participants.iter() {
            if pub_id == core.id() {
                continue;
            }
            if let Some(target) = self.shared_state.get_p2p_node(pub_id.name()) {
                trace!("Sending DKG to {:?} - {:?}", pub_id.name(), variant);
                core.send_direct_message(target.peer_addr(), variant.clone());
            }
        }

        // In case all the participants are non-elders (could happen during split), existing elders
        // have to be used as relayer to forward DKG messages.
        if !participants.iter().any(|pub_id| self.is_our_elder(pub_id)) {
            // Sending to all elders to prevent some of them got dropped or mis-behaved.
            // TODO: consider sending to 1/3 ?
            let targets: Vec<_> = self.shared_state.sections.our_elders().collect();
            for target in targets {
                trace!("Sending DKG to {:?} - {:?}", target.name(), variant);
                core.send_direct_message(target.peer_addr(), variant.clone());
            }
        }

        self.handle_dkg_message(core, participants, section_key_index, message, *core.id())
    }

    fn increment_ages(
        &mut self,
        core: &mut Core,
        churn_name: &XorName,
        churn_signature: &bls::Signature,
    ) -> Result<()> {
        if self.is_in_startup_phase(core) {
            // We are in the startup phase - don't relocate, just increment everyones ages
            // (excluding the new node).
            let votes: Vec<_> = self
                .shared_state
                .our_members
                .joined()
                .filter(|info| info.p2p_node.name() != churn_name)
                .map(|info| Vote::ChangeAge(info.clone().increment_age()))
                .collect();

            for vote in votes {
                self.cast_unordered_vote(core, vote)?;
            }

            return Ok(());
        }

        // As a measure against sybil attacks, don't relocate on infant churn.
        if !self.shared_state.is_peer_adult_or_elder(churn_name) {
            trace!("Skip relocation on infant churn");
            return Ok(());
        }

        let relocations = self.shared_state.compute_relocations(
            churn_name,
            churn_signature,
            core.network_params.elder_size,
        );

        for (info, details) in relocations {
            debug!(
                "Relocating {} to {} (on churn of {})",
                info.p2p_node, details.destination, churn_name
            );

            core.send_event(Event::RelocationInitiated {
                name: *info.p2p_node.name(),
                destination: details.destination,
            });

            self.send_relocate(core, details)?;
            self.cast_ordered_vote(AccumulatingEvent::Offline(info.leave()));
        }

        Ok(())
    }

    // Are we in the startup phase? Startup phase is when the network consists of only one section
    // and it has no more than `recommended_section_size` members.
    fn is_in_startup_phase(&self, core: &Core) -> bool {
        self.shared_state.our_prefix().is_empty()
            && self.shared_state.our_members.joined().count()
                <= core.network_params.recommended_section_size
    }

    fn handle_ordered_consensus(
        &mut self,
        core: &mut Core,
        event: AccumulatingEvent,
        proof: Proof,
    ) -> Result<()> {
        debug!("Handle consensus on {:?}", event);

        match event {
            AccumulatingEvent::Online {
                member_info,
                previous_name,
                their_knowledge,
            } => {
                self.handle_online_event(core, member_info, previous_name, their_knowledge, proof)?
            }
            AccumulatingEvent::Offline(member_info) => {
                self.handle_offline_event(core, member_info, proof)?
            }
            AccumulatingEvent::ParsecPrune => self.handle_prune_event(core)?,
            AccumulatingEvent::User(payload) => self.handle_user_event(core, payload)?,
        }

        Ok(())
    }

    fn handle_unordered_consensus(
        &mut self,
        core: &mut Core,
        vote: Vote,
        proof: Proof,
    ) -> Result<()> {
        debug!("Handle consensus on {:?}", vote);

        match vote {
            Vote::SectionInfo(elders_info) => {
                match self.handle_section_info_event(core, elders_info.clone(), proof.clone()) {
                    Ok(()) => Ok(()),
                    // Could receive the accumulated SectionInfo before complete the DKG process.
                    Err(RoutingError::InvalidElderDkgResult) => {
                        trace!(
                            "caching SectionInfo({:?}) as invalid DKG result",
                            elders_info
                        );
                        self.dkg_voter
                            .push_vote(Vote::SectionInfo(elders_info), proof);
                        Ok(())
                    }
                    Err(error) => Err(error),
                }
            }
            Vote::OurKey { prefix, key } => {
                match self.handle_our_key_event(core, prefix, key, proof.clone()) {
                    Ok(()) => Ok(()),
                    Err(RoutingError::InvalidElderDkgResult) => {
                        trace!(
                            "caching OurKey {{ prefix: {:?}, key: {:?} }} as invalid DKG result",
                            prefix,
                            key
                        );
                        self.dkg_voter
                            .push_vote(Vote::OurKey { prefix, key }, proof);
                        Ok(())
                    }
                    Err(error) => Err(error),
                }
            }
            Vote::TheirKey { prefix, key } => {
                match self.handle_their_key_event(core, prefix, key, proof.clone()) {
                    Ok(()) => Ok(()),
                    Err(RoutingError::InvalidElderDkgResult) => {
                        trace!(
                            "caching TheirKey {{ prefix: {:?}, key: {:?} }} as invalid DKG result",
                            prefix,
                            key
                        );
                        self.dkg_voter
                            .push_vote(Vote::TheirKey { prefix, key }, proof);
                        Ok(())
                    }
                    Err(error) => Err(error),
                }
            }
            Vote::TheirKnowledge { prefix, key_index } => {
                self.handle_their_knowledge_event(prefix, key_index, proof);
                Ok(())
            }
            Vote::ChangeAge(member_info) => {
                self.handle_change_age_event(member_info, proof);
                Ok(())
            }
        }
    }

    fn handle_online_event(
        &mut self,
        core: &mut Core,
        member_info: MemberInfo,
        previous_name: Option<XorName>,
        their_knowledge: Option<bls::PublicKey>,
        proof: Proof,
    ) -> Result<()> {
        let p2p_node = member_info.p2p_node.clone();
        let age = member_info.age;
        let signature = proof.signature.clone();

        if !self.shared_state.update_member(member_info, proof) {
            info!("ignore Online: {}", p2p_node);
            return Ok(());
        }

        info!("handle Online: {} (age: {})", p2p_node, age);

        self.members_changed = true;
        self.increment_ages(core, p2p_node.name(), &signature)?;
        self.send_node_approval(core, &p2p_node, their_knowledge)?;
        self.print_network_stats();

        if let Some(previous_name) = previous_name {
            core.send_event(Event::MemberJoined {
                name: *p2p_node.name(),
                previous_name,
                age,
            });
        } else {
            core.send_event(Event::InfantJoined {
                name: *p2p_node.name(),
                age,
            });
        }

        Ok(())
    }

    fn handle_offline_event(
        &mut self,
        core: &mut Core,
        member_info: MemberInfo,
        proof: Proof,
    ) -> Result<()> {
        let p2p_node = member_info.p2p_node.clone();
        let age = member_info.age;
        let signature = proof.signature.clone();

        if !self.shared_state.update_member(member_info, proof) {
            info!("ignore Offline: {}", p2p_node);
            return Ok(());
        }

        info!("handle Offline: {}", p2p_node);

        self.members_changed = true;
        self.increment_ages(core, p2p_node.name(), &signature)?;
        core.transport.disconnect(*p2p_node.peer_addr());

        core.send_event(Event::MemberLeft {
            name: *p2p_node.name(),
            age,
        });

        Ok(())
    }

    fn notify_old_elders(
        &mut self,
        core: &mut Core,
        participants: &BTreeSet<PublicId>,
        section_key_index: u64,
        public_key_set: bls::PublicKeySet,
    ) {
        let src = SrcLocation::Node(*core.id().name());
        let variant = Variant::DKGOldElders {
            participants: participants.clone(),
            section_key_index,
            public_key_set,
        };
        let elder_ids: Vec<PublicId> = self.shared_state.our_info().elder_ids().copied().collect();

        for elder_id in elder_ids {
            if !participants.contains(&elder_id) {
                trace!(
                    "notify {:?} for the completion of DKG {:?}",
                    elder_id,
                    participants
                );
                let dst = DstLocation::Node(*elder_id.name());
                let _ = self.send_routing_message(core, src, dst, variant.clone(), None);
            }
        }
    }

    pub fn handle_dkg_result_event(
        &mut self,
        core: &mut Core,
        participants: &BTreeSet<PublicId>,
        section_key_index: u64,
        dkg_result: &DkgResult,
    ) -> Result<()> {
        if self.is_our_elder(core.id()) {
            if self.section_keys_provider.key_share().is_err() {
                // We've just been promoted and already received the `Promote` message.
                self.section_keys_provider
                    .handle_dkg_result_event(participants, dkg_result)?;
                self.section_keys_provider
                    .finalise_dkg(core.name(), self.shared_state.our_info())?;
                return Ok(());
            }
        } else {
            // We are about to get promoted, but have not received the `Promote` message yet.
            return self
                .section_keys_provider
                .handle_dkg_result_event(participants, dkg_result);
        }

        let dkg_key = (participants.clone(), section_key_index);

        if let Some(info) = self.dkg_voter.take_info(&dkg_key) {
            info!("handle DkgResult: {:?}", dkg_key);

            let key = dkg_result.public_key_set.public_key();

            // Casting unordered_votes will check consensus and handle accumulated immediately.
            let result = self
                .section_keys_provider
                .handle_dkg_result_event(&dkg_key.0, dkg_result);

            self.cast_unordered_vote(
                core,
                Vote::OurKey {
                    prefix: info.prefix,
                    key,
                },
            )?;

            if info.prefix.is_extension_of(self.shared_state.our_prefix()) {
                self.cast_unordered_vote(
                    core,
                    Vote::TheirKey {
                        prefix: info.prefix,
                        key,
                    },
                )?;
            }

            self.cast_unordered_vote(core, Vote::SectionInfo(info))?;

            result
        } else {
            // The latest participant was just following vote, which doesn't have the info to
            // vote for a section_info. Or the DKG process completed before receiving the
            // correspondent AccumulatedEvent.
            debug!(
                "DKG for an unexpected info {:?} (expected: {{{:?}}})",
                dkg_key,
                self.dkg_voter.info_keys().format(", ")
            );
            Err(RoutingError::InvalidState)
        }
    }

    fn handle_section_info_event(
        &mut self,
        core: &mut Core,
        elders_info: EldersInfo,
        proof: Proof,
    ) -> Result<()> {
        if elders_info == *self.shared_state.our_info() {
            trace!("ignore SectionInfo {:?}, already updated", elders_info);
            return Ok(());
        }
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

    fn handle_our_key_event(
        &mut self,
        core: &mut Core,
        prefix: Prefix,
        key: bls::PublicKey,
        proof: Proof,
    ) -> Result<()> {
        if self.section_keys_provider.public_key() == Some(key) {
            trace!("Ignore OurKeyEvent {:?}, as already promoted", key);
            return Ok(());
        }

        let key = Proven::new(key, proof);

        let details = if !prefix.matches(core.name()) {
            if prefix.popped() == *self.shared_state.our_prefix() {
                self.section_update_barrier
                    .handle_sibling_our_key(self.shared_state.our_prefix(), key)
            } else {
                None
            }
        } else {
            self.section_update_barrier
                .handle_our_key(self.shared_state.our_prefix(), key)
        };

        if let Some(details) = details {
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
        let key = Proven::new((prefix, key), proof);

        let details = if prefix.matches(core.name()) {
            if prefix.popped() == *self.shared_state.our_prefix() {
                self.section_update_barrier
                    .handle_sibling_their_key(self.shared_state.our_prefix(), key)
            } else {
                None
            }
        } else if key.value.0.is_extension_of(self.shared_state.our_prefix()) {
            self.section_update_barrier
                .handle_their_key(self.shared_state.our_prefix(), key)
        } else {
            self.shared_state.sections.update_keys(key);
            None
        };

        if let Some(details) = details {
            self.update_our_section(core, details)
        } else {
            Ok(())
        }
    }

    fn handle_their_knowledge_event(&mut self, prefix: Prefix, knowledge: u64, proof: Proof) {
        let knowledge = Proven::new((prefix, knowledge), proof);
        self.shared_state.sections.update_knowledge(knowledge)
    }

    fn handle_change_age_event(&mut self, member_info: MemberInfo, proof: Proof) {
        let _ = self.shared_state.update_member(member_info, proof);
    }

    fn handle_prune_event(&mut self, core: &mut Core) -> Result<()> {
        if self.churn_in_progress {
            debug!("ignore ParsecPrune event - churn in progress");
            return Ok(());
        }

        info!("handle ParsecPrune");

        self.reset_parsec(core, self.consensus_engine.parsec_version() + 1)?;
        self.send_elders_update(core)?;

        Ok(())
    }

    /// Handle an accumulated `User` event
    fn handle_user_event(&mut self, core: &mut Core, payload: Vec<u8>) -> Result<(), RoutingError> {
        core.send_event(Event::Consensus(payload));
        Ok(())
    }

    fn update_our_section(&mut self, core: &mut Core, details: SectionUpdateDetails) -> Result<()> {
        info!("update our section: {:?}", details.our.info.value);

        let old_prefix = *self.shared_state.our_prefix();
        let sibling_prefix = details.sibling.as_ref().map(|sibling| sibling.key.value.0);

        let mut old_shared_state = self.shared_state.clone();

        let promoted_nodes: Vec<_> = details
            .all_elders()
            .filter(|p2p_node| {
                !self
                    .shared_state
                    .our_info()
                    .elders
                    .contains_key(p2p_node.name())
            })
            .cloned()
            .collect();

        self.update_our_key_and_info(core, details.our.key, details.our.info.clone())?;

        if let Some(sibling) = details.sibling {
            self.shared_state.sections.update_keys(sibling.key);
            self.update_neighbour_info(core, sibling.info.clone());

            old_shared_state.update_our_section(sibling.info, sibling.sibling_our_key);
            old_shared_state.sections.add_neighbour(details.our.info);
            old_shared_state
                .sections
                .update_keys(sibling.sibling_their_key);
        }

        let new_prefix = &self.shared_state.our_info().prefix;
        if new_prefix.is_extension_of(&old_prefix) {
            info!("Split");

            self.send_promote(
                core,
                old_shared_state,
                self.consensus_engine.parsec_version() + 1,
                promoted_nodes.clone(),
            )?;
        } else if old_prefix.is_extension_of(new_prefix) {
            panic!("Merge not supported: {:?} -> {:?}", old_prefix, new_prefix);
        }

        core.msg_filter.reset();
        self.section_update_barrier = Default::default();
        self.reset_parsec(core, self.consensus_engine.parsec_version() + 1)?;

        self.send_promote(
            core,
            self.shared_state.clone(),
            self.consensus_engine.parsec_version(),
            promoted_nodes,
        )?;
        self.send_elders_update(core)?;

        if !self.is_our_elder(core.id()) {
            info!("Demoted");
            self.shared_state.demote();
            core.send_event(Event::Demoted);
            return Ok(());
        }

        // We can update the sibling knowledge already because we know they also reached consensus
        // on our `OurKey` so they know our latest key. Need to vote for it first though, to
        // accumulate the signatures.
        if let Some(prefix) = sibling_prefix {
            self.cast_unordered_vote(
                core,
                Vote::TheirKnowledge {
                    prefix,
                    key_index: self.shared_state.our_history.last_key_index(),
                },
            )?;
        }

        self.send_elders_changed_event(core);
        self.print_network_stats();

        Ok(())
    }

    fn send_elders_changed_event(&self, core: &mut Core) {
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
        })
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
    // Parsec management
    ////////////////////////////////////////////////////////////////////////////

    fn reset_parsec(&mut self, core: &mut Core, new_parsec_version: u64) -> Result<()> {
        let is_elder = self.is_our_elder(core.id());

        let events = self.consensus_engine.prepare_reset(core.name());
        let events = self.filter_events_to_revote(events);

        self.consensus_engine.finalise_reset(
            &mut core.rng,
            core.full_id.clone(),
            self.shared_state.our_info(),
            new_parsec_version,
        );

        if is_elder {
            for event in events {
                self.cast_ordered_vote(event);
            }
        }

        // FIXME: this should not be necessary because elder membership should always be up to date
        // after parsec reset. But without this almost all the tests fail. Figure out why.
        self.members_changed = true;

        Ok(())
    }

    fn filter_events_to_revote(
        &self,
        mut events: Vec<AccumulatingEvent>,
    ) -> Vec<AccumulatingEvent> {
        let our_prefix = *self.shared_state.our_prefix();

        events.retain(|event| match &event {
            // Only re-vote if still relevant to our new prefix.
            AccumulatingEvent::Online { member_info, .. } => {
                our_prefix.matches(member_info.p2p_node.name())
            }
            AccumulatingEvent::Offline(member_info) => {
                our_prefix.matches(member_info.p2p_node.name())
            }
            // Drop: no longer relevant after prefix change.
            AccumulatingEvent::ParsecPrune => false,

            // Always revote
            AccumulatingEvent::User(_) => true,
        });
        events
    }

    // Detect non-responsive peers and vote them out.
    fn vote_for_remove_unresponsive_peers(&mut self) {
        let unresponsive_nodes: Vec<_> = self
            .consensus_engine
            .detect_unresponsive(self.shared_state.our_info())
            .into_iter()
            .filter_map(|id| self.shared_state.our_members.get(id.name()))
            .map(|info| info.clone().leave())
            .collect();

        for info in unresponsive_nodes {
            info!("Voting for unresponsive node {}", info.p2p_node);
            self.cast_ordered_vote(AccumulatingEvent::Offline(info));
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
        p2p_node: &P2pNode,
        their_knowledge: Option<bls::PublicKey>,
    ) -> Result<()> {
        info!(
            "Our section with {:?} has approved candidate {}.",
            self.shared_state.our_prefix(),
            p2p_node
        );

        let their_knowledge =
            their_knowledge.and_then(|key| self.shared_state.our_history.index_of(&key));
        let proof_chain = self
            .shared_state
            .create_proof_chain_for_our_info(their_knowledge);

        let elders_update = self.create_elders_update();
        let variant = Variant::NodeApproval(elders_update);

        trace!("Send {:?} to {:?}", variant, p2p_node);
        let message = Message::single_src(
            &core.full_id,
            DstLocation::Direct,
            variant,
            Some(proof_chain),
            None,
        )?;
        core.send_message_to_target(p2p_node.peer_addr(), message.to_bytes());

        Ok(())
    }

    fn send_elders_update(&mut self, core: &mut Core) -> Result<()> {
        let proof_chain = self.shared_state.create_proof_chain_for_our_info(None);
        let elders_update = self.create_elders_update();
        let variant = Variant::EldersUpdate(elders_update);
        let message = Message::single_src(
            &core.full_id,
            DstLocation::Direct,
            variant.clone(),
            Some(proof_chain),
            None,
        )?;

        for p2p_node in self.shared_state.adults_and_infants_p2p_nodes() {
            trace!("Send {:?} to {:?}", variant, p2p_node);

            core.send_message_to_target(p2p_node.peer_addr(), message.to_bytes());
        }

        Ok(())
    }

    fn create_elders_update(&self) -> EldersUpdate {
        EldersUpdate {
            elders_info: self.shared_state.sections.proven_our().clone(),
            parsec_version: self.consensus_engine.parsec_version(),
        }
    }

    fn send_promote(
        &self,
        core: &mut Core,
        shared_state: SharedState,
        parsec_version: u64,
        new_elders: Vec<P2pNode>,
    ) -> Result<()> {
        let variant = Variant::Promote {
            shared_state: shared_state.clone(),
            parsec_version,
        };

        for p2p_node in new_elders {
            if !shared_state.our_info().elders.contains_key(p2p_node.name()) {
                continue;
            }
            trace!("Send {:?} to {:?}", variant, p2p_node);
            let message = Message::single_src(
                &core.full_id,
                DstLocation::Direct,
                variant.clone(),
                None,
                None,
            )?;
            core.send_message_to_target(p2p_node.peer_addr(), message.to_bytes());
        }

        Ok(())
    }

    fn send_relocate(&mut self, core: &mut Core, details: RelocateDetails) -> Result<()> {
        // We need to construct a proof that would be trusted by the destination section.
        let knowledge_index = self
            .shared_state
            .sections
            .knowledge_by_location(&DstLocation::Section(details.destination));

        let src = SrcLocation::Section(*self.shared_state.our_prefix());
        let dst = DstLocation::Node(*details.pub_id.name());
        let variant = Variant::Relocate(details);

        self.send_routing_message(core, src, dst, variant, Some(knowledge_index))
    }

    fn send_parsec_gossip(&mut self, core: &mut Core, target: Option<(u64, P2pNode)>) {
        let (version, gossip_target) = match target {
            Some((v, p)) => (v, p),
            None => {
                if !self.consensus_engine.should_send_gossip() {
                    trace!("shall not carry out a gossip");
                    return;
                }

                if let Some(recipient) = self.choose_gossip_recipient(&mut core.rng) {
                    let version = self.consensus_engine.parsec_version();
                    (version, recipient)
                } else {
                    trace!("can't pick a recipient for gossip");
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

    // Send message over the network.
    pub fn relay_message(&self, core: &mut Core, msg: &Message) -> Result<()> {
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
            let msg = Message::single_src(&core.full_id, dst, variant, None, None)?;
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
    pub fn update_section_knowledge(&mut self, core: &mut Core, msg: &Message) -> Result<()> {
        use crate::section::UpdateSectionKnowledgeAction::*;

        let src_prefix = if let Ok(prefix) = msg.src().as_section_prefix() {
            prefix
        } else {
            return Ok(());
        };

        let src_key = if let Ok(key) = msg.proof_chain_last_key() {
            key
        } else {
            return Ok(());
        };

        let hash = msg.hash();
        let actions = self.shared_state.update_section_knowledge(
            core.name(),
            src_prefix,
            src_key,
            msg.dst_key().as_ref(),
            hash,
        );

        for action in actions {
            match action {
                VoteTheirKey { prefix, key } => {
                    self.cast_unordered_vote(core, Vote::TheirKey { prefix, key })?
                }
                VoteTheirKnowledge { prefix, key_index } => {
                    self.cast_unordered_vote(core, Vote::TheirKnowledge { prefix, key_index })?
                }
                SendNeighbourInfo { dst, nonce } => self.send_neighbour_info(
                    core,
                    dst,
                    nonce,
                    self.shared_state.sections.key_by_name(&dst.name()).cloned(),
                )?,
            }
        }

        Ok(())
    }

    fn send_neighbour_info(
        &mut self,
        core: &mut Core,
        dst: Prefix,
        nonce: MessageHash,
        dst_key: Option<bls::PublicKey>,
    ) -> Result<()> {
        let proof_chain = self.shared_state.create_proof_chain_for_our_info(Some(
            self.shared_state.sections.knowledge_by_section(&dst),
        ));
        let variant = Variant::NeighbourInfo {
            elders_info: self.shared_state.sections.proven_our().clone(),
            nonce,
        };
        trace!("sending NeighbourInfo {:?}", variant);
        let msg = Message::single_src(
            &core.full_id,
            DstLocation::Section(dst.name()),
            variant,
            Some(proof_chain),
            dst_key,
        )?;

        self.try_relay_message(core, &msg)
    }

    #[cfg(feature = "mock_base")]
    // Returns whether node has completed the full joining process
    pub fn is_ready(&self, core: &Core) -> bool {
        // TODO: This is mainly to prevent bootstrapping a new node too quickly when the previous
        //       node is expected to become an elder, which will carry out DKG voting process.
        //       However, this may hide issue for the tests such as `simultaneous_joining_nodes`.
        //       Consider using `poll_until_minimal_elder_count` in the testing code to avoid carry
        //       out internal check here.
        if self
            .shared_state
            .our_members
            .elder_candidates(core.network_params.elder_size, self.shared_state.our_info())
            .contains_key(core.id().name())
        {
            self.is_our_elder(core.id())
        } else {
            true
        }
    }

    fn print_network_stats(&self) {
        self.shared_state.sections.network_stats().print()
    }
}

pub(crate) struct RelocateParams {
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
    let mut shared_state = SharedState::new(elders_info.proof.public_key, elders_info);

    for p2p_node in shared_state.sections.our().elders.values() {
        let member_info = MemberInfo::joined(p2p_node.clone(), MIN_AGE);
        let proof = create_first_proof(pk_set, sk_share, &member_info)?;
        let _ = shared_state
            .our_members
            .update(member_info, proof, &shared_state.our_history);
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
        .map_err(|_| RoutingError::InvalidSignatureShare)?;

    Ok(Proof {
        public_key: pk_set.public_key(),
        signature,
    })
}
