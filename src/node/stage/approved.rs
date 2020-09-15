// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    consensus::{
        self, AccumulationError, DkgKey, DkgVoter, Proof, ProofShare, Proven, Vote, VoteAccumulator,
    },
    core::Core,
    delivery_group,
    error::{Error, Result},
    event::Event,
    id::{P2pNode, PublicId},
    location::{DstLocation, SrcLocation},
    messages::{
        self, AccumulatingMessage, BootstrapResponse, JoinRequest, Message, MessageAccumulator,
        MessageHash, MessageStatus, PlainMessage, Variant, VerifyStatus,
    },
    pause::PausedState,
    relocation::{RelocateAction, RelocateDetails, RelocatePromise, SignedRelocateDetails},
    section::{
        EldersInfo, MemberInfo, NeighbourEldersRemoved, SectionKeyShare, SectionKeysProvider,
        SectionProofChain, SectionUpdateBarrier, SharedState, MIN_AGE,
    },
    time::Duration,
};
use bls_dkg::key_gen::message::Message as DkgMessage;
use bytes::Bytes;
use crossbeam_channel::Sender;
use itertools::Itertools;
use serde::Serialize;
use std::{iter, net::SocketAddr};
use xor_name::{Prefix, XorName};

// Interval to progress DKG timed phase
const DKG_PROGRESS_INTERVAL: Duration = Duration::from_secs(30);

// The approved stage - node is a full member of a section and is performing its duties according
// to its persona (infant, adult or elder).
pub(crate) struct Approved {
    pub shared_state: SharedState,
    section_keys_provider: SectionKeysProvider,
    message_accumulator: MessageAccumulator,
    vote_accumulator: VoteAccumulator,
    section_update_barrier: SectionUpdateBarrier,
    // Voter for DKG
    dkg_voter: DkgVoter,
    // Serialized `RelocatePromise` message that we received from our section. To be sent back to
    // them after we are demoted.
    relocate_promise: Option<Bytes>,
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
        // TODO: consider signing it with a throwaway key instead, to avoid having to special-case
        // this in some places.
        let elders_info = create_first_elders_info(&public_key_set, &secret_key_share, p2p_node)?;
        let shared_state =
            create_first_shared_state(&public_key_set, &secret_key_share, elders_info)?;

        let section_key_share = SectionKeyShare {
            public_key_set,
            index: 0,
            secret_key_share,
        };

        Self::new(shared_state, Some(section_key_share))
    }

    // Create the approved stage for a regular node.
    pub fn new(
        shared_state: SharedState,
        section_key_share: Option<SectionKeyShare>,
    ) -> Result<Self> {
        let section_keys_provider = SectionKeysProvider::new(section_key_share);

        Ok(Self {
            shared_state,
            section_keys_provider,
            message_accumulator: Default::default(),
            vote_accumulator: Default::default(),
            section_update_barrier: Default::default(),
            dkg_voter: Default::default(),
            relocate_promise: None,
        })
    }

    pub fn pause(self, core: Core) -> PausedState {
        PausedState {
            network_params: core.network_params,
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
            relocate_promise: self.relocate_promise,
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

        let stage = Self {
            shared_state: state.shared_state,
            section_keys_provider: state.section_keys_provider,
            message_accumulator: state.msg_accumulator,
            vote_accumulator: state.vote_accumulator,
            section_update_barrier: state.section_update_barrier,
            // TODO: these fields should come from PausedState too
            dkg_voter: Default::default(),
            relocate_promise: state.relocate_promise,
        };

        (stage, core)
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
            DstLocation::Direct,
            variant,
            Some(proof_chain),
            Some(*self.shared_state.our_history.last_key()),
        )?;
        let recipients: Vec<_> = self
            .shared_state
            .our_info()
            .elders
            .values()
            .filter(|p2p_node| p2p_node.name() != core.name())
            .map(P2pNode::peer_addr)
            .copied()
            .collect();
        core.send_message_to_targets(&recipients, recipients.len(), message.to_bytes());

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
            Err(AccumulationError::NotEnoughShares) => Ok(()),
            Err(error) => {
                error!("Failed to add vote: {}", error);
                Err(Error::InvalidSignatureShare)
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
                // TODO: consider sending only those parts of the shared state that are new
                // since `public_key` was the latest key.
                Variant::Sync(self.shared_state.clone()),
            );
        }
    }

    pub fn handle_connection_failure(&mut self, core: &mut Core, addr: SocketAddr) {
        let node = self
            .shared_state
            .our_members
            .joined()
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

    pub fn handle_peer_lost(&mut self, core: &mut Core, peer_addr: SocketAddr) -> Result<()> {
        let name = if let Some(node) = self.shared_state.find_p2p_node_from_addr(&peer_addr) {
            debug!("Lost known peer {}", node);
            *node.name()
        } else {
            trace!("Lost unknown peer {}", peer_addr);
            return Ok(());
        };

        if !self.is_our_elder(core.id()) {
            return Ok(());
        }

        if let Some(info) = self.shared_state.our_members.get(&name) {
            let info = info.clone().leave();
            self.cast_unordered_vote(core, Vote::Offline(info))?;
        }

        Ok(())
    }

    pub fn handle_timeout(&mut self, core: &mut Core, token: u64) {
        if self.dkg_voter.timer_token() == Some(token) {
            self.dkg_voter
                .set_timer_token(core.timer.schedule(DKG_PROGRESS_INTERVAL));

            if let Err(error) = self.progress_dkg(core) {
                error!("failed to progress DKG: {}", error);
            }
        }
    }

    fn check_dkg(&mut self, core: &mut Core) -> Result<()> {
        match self.dkg_voter.check_dkg() {
            Some(Ok((elders_info, outcome))) => {
                let public_key = outcome.public_key_set.public_key();
                self.section_keys_provider
                    .insert_dkg_outcome(core.name(), &elders_info, outcome);
                self.handle_dkg_result(core, elders_info, Ok(public_key), *core.id())
            }
            Some(Err(elders_info)) => {
                self.handle_dkg_result(core, elders_info, Err(()), *core.id())
            }
            None => Ok(()),
        }
    }

    fn progress_dkg(&mut self, core: &mut Core) -> Result<()> {
        match self.dkg_voter.progress_dkg(&mut core.rng) {
            Some(Ok((dkg_key, messages))) => {
                for message in messages {
                    self.broadcast_dkg_message(core, dkg_key, message)?;
                }
                self.check_dkg(core)
            }
            Some(Err(elders_info)) => {
                self.handle_dkg_result(core, elders_info, Err(()), *core.id())
            }
            None => Ok(()),
        }
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
            Variant::DKGResult { .. } => {
                if !self.is_our_elder(our_id) {
                    return Ok(MessageStatus::Unknown);
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
            Variant::RelocatePromise(promise) => {
                if promise.name != *our_id.name() {
                    if !self.is_our_elder(our_id) {
                        return Ok(MessageStatus::Useless);
                    }

                    if self.shared_state.is_peer_our_elder(&promise.name) {
                        // If the peer is honest and is still elder then we probably haven't yet
                        // processed its demotion. Bounce the message back and try again on resend.
                        return Ok(MessageStatus::Unknown);
                    }
                }
            }
            Variant::Sync { .. }
            | Variant::Relocate(_)
            | Variant::BootstrapRequest(_)
            | Variant::BouncedUntrustedMessage(_)
            | Variant::BouncedUnknownMessage { .. }
            | Variant::DKGStart(_)
            | Variant::DKGMessage { .. } => (),
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
             - peer is lagging behind, resending with Sync",
            MessageHash::from_bytes(&bounced_msg_bytes),
            sender,
        );
        // First send Sync to update the peer, then resend the message itself. If the messages
        // arrive in the same order they were sent, the Sync should update the peer so it will then
        // be able to handle the resent message. If not, the peer will bounce the message again.
        core.send_direct_message(sender.peer_addr(), Variant::Sync(self.shared_state.clone()));
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

    pub fn handle_sync(&mut self, core: &mut Core, shared_state: SharedState) -> Result<()> {
        if !shared_state.our_prefix().matches(core.name()) {
            trace!("ignore Sync - not our section");
            return Ok(());
        }

        self.update_shared_state(core, shared_state)
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

        if self.relocate_promise.is_none() {
            core.send_event(Event::RelocationStarted);
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

    pub fn handle_relocate_promise(
        &mut self,
        core: &mut Core,
        promise: RelocatePromise,
        msg_bytes: Bytes,
    ) -> Result<()> {
        if promise.name == *core.name() {
            // Store the `RelocatePromise` message and send it back after we are demoted.
            // Keep it around even if we are not elder anymore, in case we need to resend it.
            if self.relocate_promise.is_none() {
                self.relocate_promise = Some(msg_bytes.clone());
                core.send_event(Event::RelocationStarted);
            } else {
                trace!("ignore RelocatePromise - already have one");
            }

            // We are no longer elder. Send the promise back already.
            if !self.is_our_elder(core.id()) {
                self.send_message_to_our_elders(core, msg_bytes);
            }

            return Ok(());
        }

        if self.shared_state.is_peer_our_elder(&promise.name) {
            error!(
                "ignore returned RelocatePromise from {} - node is still elder",
                promise.name
            );
            return Ok(());
        }

        if let Some(info) = self.shared_state.our_members.get(&promise.name) {
            let details = self
                .shared_state
                .create_relocation_details(info, promise.destination);
            let addr = *info.p2p_node.peer_addr();

            self.send_relocate(core, addr, details)
        } else {
            error!(
                "ignore returned RelocatePromise from {} - unknown node",
                promise.name
            );
            Ok(())
        }
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
    ) -> Result<()> {
        debug!("Received {:?} from {}", join_request, p2p_node);

        if join_request.section_key != *self.shared_state.our_history.last_key() {
            let response = BootstrapResponse::Join {
                elders_info: self.shared_state.our_info().clone(),
                section_key: *self.shared_state.our_history.last_key(),
            };
            trace!("Resending BootstrapResponse {:?} to {}", response, p2p_node,);
            core.send_direct_message(p2p_node.peer_addr(), Variant::BootstrapResponse(response));
            return Ok(());
        }

        let pub_id = *p2p_node.public_id();
        if !self.shared_state.our_prefix().matches(pub_id.name()) {
            debug!(
                "Ignoring JoinRequest from {} - name doesn't match our prefix {:?}.",
                pub_id,
                self.shared_state.our_prefix()
            );
            return Ok(());
        }

        if self.shared_state.our_members.is_joined(pub_id.name()) {
            debug!(
                "Ignoring JoinRequest from {} - already member of our section.",
                pub_id
            );
            return Ok(());
        }

        // This joining node is being relocated to us.
        let (age, previous_name, their_knowledge) =
            if let Some(payload) = join_request.relocate_payload {
                if !payload.verify_identity(&pub_id) {
                    debug!(
                        "Ignoring relocation JoinRequest from {} - invalid signature.",
                        pub_id
                    );
                    return Ok(());
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
                    return Ok(());
                }

                if !self
                    .verify_message(payload.details.signed_msg())
                    .unwrap_or(false)
                {
                    debug!(
                        "Ignoring relocation JoinRequest from {} - untrusted.",
                        pub_id
                    );
                    return Ok(());
                }

                (
                    details.age,
                    Some(*details.pub_id.name()),
                    Some(details.destination_key),
                )
            } else {
                (MIN_AGE, None, None)
            };

        self.cast_unordered_vote(
            core,
            Vote::Online {
                member_info: MemberInfo::joined(p2p_node, age),
                previous_name,
                their_knowledge,
            },
        )
    }

    pub fn handle_dkg_start(&mut self, core: &mut Core, new_elders_info: EldersInfo) -> Result<()> {
        trace!("Received DKGStart({:?})", new_elders_info);

        if new_elders_info.elders.contains_key(core.name()) {
            // Participant
            if let Some((dkg_key, message)) = self
                .dkg_voter
                .start_participating(&core.full_id, new_elders_info.clone())
            {
                self.dkg_voter
                    .set_timer_token(core.timer.schedule(DKG_PROGRESS_INTERVAL));
                self.broadcast_dkg_message(core, dkg_key, message)?
            }
        }

        if self.is_our_elder(core.id()) {
            // Observer
            self.dkg_voter.start_observing(new_elders_info);
        }

        Ok(())
    }

    pub fn handle_dkg_result(
        &mut self,
        core: &mut Core,
        elders_info: EldersInfo,
        result: Result<bls::PublicKey, ()>,
        sender: PublicId,
    ) -> Result<()> {
        if sender == *core.id() {
            self.send_dkg_result(core, elders_info.clone(), result)?;
        }

        if !self.is_our_elder(core.id()) {
            return Ok(());
        }

        let result =
            if let Some(result) = self.dkg_voter.observe_result(&elders_info, result, sender) {
                result
            } else {
                return Ok(());
            };

        trace!("accumulated DKG result for {}: {:?}", elders_info, result);

        for info in self
            .shared_state
            .promote_and_demote_elders(&core.network_params, core.name())
        {
            // Check whether the result still corresponds to the current elder candidates.
            if info == elders_info {
                debug!("handle DKG result for {}: {:?}", info, result);

                if let Ok(public_key) = result {
                    self.vote_for_section_update(core, public_key, info)?
                } else {
                    self.send_dkg_start(core, info)?
                }
            } else if info.prefix == elders_info.prefix
                || info.prefix.is_extension_of(&elders_info.prefix)
            {
                trace!(
                    "ignore DKG result for {}: {:?} - outdated",
                    elders_info,
                    result
                );
                self.send_dkg_start(core, info)?
            }
        }

        Ok(())
    }

    pub fn handle_dkg_message(
        &mut self,
        core: &mut Core,
        dkg_key: DkgKey,
        message_bytes: Bytes,
        sender: PublicId,
    ) -> Result<()> {
        let message = bincode::deserialize(&message_bytes[..])?;

        trace!("handle DKG message {:?} from {}", message, sender);

        let responses = self
            .dkg_voter
            .process_dkg_message(&mut core.rng, &dkg_key, message);

        // Only a valid DkgMessage, which results in some responses, shall reset the ticker.
        if !responses.is_empty() {
            self.dkg_voter
                .set_timer_token(core.timer.schedule(DKG_PROGRESS_INTERVAL));
        }

        for response in responses {
            let _ = self.broadcast_dkg_message(core, dkg_key, response);
        }

        self.check_dkg(core)
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

    // Generate a new section info based on the current set of members and vote for it if it
    // changed.
    fn promote_and_demote_elders(&mut self, core: &mut Core) -> Result<()> {
        for info in self
            .shared_state
            .promote_and_demote_elders(&core.network_params, core.name())
        {
            self.send_dkg_start(core, info)?;
        }

        Ok(())
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

        let relocations = self
            .shared_state
            .compute_relocations(churn_name, churn_signature);

        for (info, action) in relocations {
            debug!(
                "Relocating {} to {} (on churn of {})",
                info.p2p_node,
                action.destination(),
                churn_name
            );

            let addr = *info.p2p_node.peer_addr();

            self.cast_unordered_vote(core, Vote::Offline(info.relocate(*action.destination())))?;

            match action {
                RelocateAction::Instant(details) => self.send_relocate(core, addr, details)?,
                RelocateAction::Delayed(promise) => {
                    self.send_relocate_promise(core, addr, promise)?
                }
            }
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

    fn handle_unordered_consensus(
        &mut self,
        core: &mut Core,
        vote: Vote,
        proof: Proof,
    ) -> Result<()> {
        debug!("handle consensus on {:?}", vote);

        match vote {
            Vote::Online {
                member_info,
                previous_name,
                their_knowledge,
            } => self.handle_online_event(core, member_info, previous_name, their_knowledge, proof),
            Vote::Offline(member_info) => self.handle_offline_event(core, member_info, proof),
            Vote::SectionInfo(elders_info) => {
                self.handle_section_info_event(core, elders_info, proof)
            }
            Vote::OurKey { prefix, key } => self.handle_our_key_event(core, prefix, key, proof),
            Vote::TheirKey { prefix, key } => self.handle_their_key_event(core, prefix, key, proof),
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

        self.promote_and_demote_elders(core)
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

        self.increment_ages(core, p2p_node.name(), &signature)?;
        core.transport.disconnect(*p2p_node.peer_addr());

        core.send_event(Event::MemberLeft {
            name: *p2p_node.name(),
            age,
        });

        self.promote_and_demote_elders(core)
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
            self.section_update_barrier.handle_section_info(
                &self.shared_state,
                core.name(),
                elders_info,
            );
            self.try_update_our_section(core)
        } else {
            // Other section
            self.update_neighbour_info(core, elders_info);
            Ok(())
        }
    }

    fn handle_our_key_event(
        &mut self,
        core: &mut Core,
        prefix: Prefix,
        key: bls::PublicKey,
        proof: Proof,
    ) -> Result<()> {
        let key = Proven::new(key, proof);

        self.section_update_barrier
            .handle_our_key(&self.shared_state, core.name(), &prefix, key);
        self.try_update_our_section(core)
    }

    fn handle_their_key_event(
        &mut self,
        core: &mut Core,
        prefix: Prefix,
        key: bls::PublicKey,
        proof: Proof,
    ) -> Result<()> {
        let key = Proven::new((prefix, key), proof);

        if key.value.0.is_extension_of(self.shared_state.our_prefix()) {
            self.section_update_barrier
                .handle_their_key(&self.shared_state, core.name(), key);
            self.try_update_our_section(core)
        } else {
            let _ = self.shared_state.update_their_key(key);
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

    fn vote_for_section_update(
        &mut self,
        core: &mut Core,
        public_key: bls::PublicKey,
        elders_info: EldersInfo,
    ) -> Result<()> {
        if self.shared_state.our_history.has_key(&public_key) {
            // Our shared state is already up to date, so no need to vote. Just finalize the DKG so
            // we can start using the new secret key share.
            self.section_keys_provider.finalise_dkg();
            return Ok(());
        }

        // Casting unordered_votes will check consensus and handle accumulated immediately.
        self.cast_unordered_vote(
            core,
            Vote::OurKey {
                prefix: elders_info.prefix,
                key: public_key,
            },
        )?;

        if elders_info
            .prefix
            .is_extension_of(self.shared_state.our_prefix())
        {
            self.cast_unordered_vote(
                core,
                Vote::TheirKey {
                    prefix: elders_info.prefix,
                    key: public_key,
                },
            )?;
        }

        self.cast_unordered_vote(core, Vote::SectionInfo(elders_info))
    }

    fn try_update_our_section(&mut self, core: &mut Core) -> Result<()> {
        let (our, sibling) = self
            .section_update_barrier
            .take(self.shared_state.our_prefix());

        if let Some(our) = our {
            trace!("update our section: {:?}", our.our_info());
            self.update_shared_state(core, our)?;
        }

        if let Some(sibling) = sibling {
            trace!("update sibling section: {:?}", sibling.our_info());

            // We can update the sibling knowledge already because we know they also reached consensus
            // on our `OurKey` so they know our latest key. Need to vote for it first though, to
            // accumulate the signatures.
            self.cast_unordered_vote(
                core,
                Vote::TheirKnowledge {
                    prefix: *sibling.our_prefix(),
                    key_index: self.shared_state.our_history.last_key_index(),
                },
            )?;

            self.send_sync(core, sibling)?;
        }

        Ok(())
    }

    fn update_shared_state(&mut self, core: &mut Core, update: SharedState) -> Result<()> {
        let old_is_elder = self.is_our_elder(core.id());
        let old_last_key_index = self.shared_state.our_history.last_key_index();
        let old_prefix = *self.shared_state.our_prefix();

        let neighbour_elders_removed = NeighbourEldersRemoved::builder(&self.shared_state.sections);

        self.shared_state.merge(update)?;

        let neighbour_elders_removed = neighbour_elders_removed.build(&self.shared_state.sections);
        self.prune_neighbour_connections(core, &neighbour_elders_removed);

        self.section_keys_provider.finalise_dkg();

        let new_is_elder = self.is_our_elder(core.id());
        let new_last_key_index = self.shared_state.our_history.last_key_index();
        let new_prefix = *self.shared_state.our_prefix();

        if new_prefix != old_prefix {
            info!("Split");

            if new_is_elder {
                // We can update the sibling knowledge already because we know they also reached
                // consensus on our `OurKey` so they know our latest key. Need to vote for it first
                // though, to accumulate the signatures.
                self.cast_unordered_vote(
                    core,
                    Vote::TheirKnowledge {
                        prefix: new_prefix.sibling(),
                        key_index: new_last_key_index,
                    },
                )?;
            }
        }

        if new_last_key_index != old_last_key_index {
            core.msg_filter.reset();

            if new_is_elder {
                info!(
                    "Section updated: prefix: ({:b}), key: {:?}, elders: {}",
                    self.shared_state.our_prefix(),
                    self.shared_state.our_history.last_key(),
                    self.shared_state.our_info().elders.values().format(", ")
                );

                self.print_network_stats();
            }

            if new_is_elder || old_is_elder {
                self.send_sync(core, self.shared_state.clone())?;
            }

            self.send_elders_changed_event(core);
        }

        if !old_is_elder && new_is_elder {
            info!("Promoted to elder");
            core.send_event(Event::PromotedToElder);

            // Ping all members to detect recent lost nodes for which the section might need
            // our Offline vote.
            for p2p_node in self.shared_state.active_members() {
                core.send_direct_message(p2p_node.peer_addr(), Variant::Ping);
            }
        }

        if old_is_elder && !new_is_elder {
            info!("Demoted");
            self.shared_state.demote();
            self.section_keys_provider = SectionKeysProvider::new(None);
            core.send_event(Event::Demoted);
        }

        if !new_is_elder {
            self.return_relocate_promise(core);
        }

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

    fn update_neighbour_info(&mut self, core: &mut Core, elders_info: Proven<EldersInfo>) {
        let neighbour_elders_removed = NeighbourEldersRemoved::builder(&self.shared_state.sections);
        let _ = self.shared_state.update_neighbour_info(elders_info);
        let neighbour_elders_removed = neighbour_elders_removed.build(&self.shared_state.sections);
        self.prune_neighbour_connections(core, &neighbour_elders_removed);
    }

    /* FIXME: bring back unresponsiveness detection
    // Detect non-responsive peers and vote them out.
    fn vote_for_remove_unresponsive_peers(&mut self, core: &mut Core) -> Result<()> {
        let unresponsive_nodes: Vec<_> = self
            .consensus_engine
            .detect_unresponsive(self.shared_state.our_info())
            .into_iter()
            .filter_map(|id| self.shared_state.our_members.get(id.name()))
            .map(|info| info.clone().leave())
            .collect();

        for info in unresponsive_nodes {
            info!("Voting for unresponsive node {}", info.p2p_node);
            self.cast_unordered_vote(core, Vote::Offline(info))?;
        }

        Ok(())
    }
    */

    ////////////////////////////////////////////////////////////////////////////
    // Message sending
    ////////////////////////////////////////////////////////////////////////////

    // Send NodeApproval to the current candidate which makes them a section member
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

        let variant = Variant::NodeApproval(self.shared_state.sections.proven_our().clone());

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

    fn send_sync(&self, core: &mut Core, shared_state: SharedState) -> Result<()> {
        for p2p_node in shared_state.active_members() {
            if p2p_node.name() == core.name() {
                continue;
            }

            let shared_state = if shared_state.is_peer_our_elder(p2p_node.name()) {
                shared_state.clone()
            } else {
                shared_state.to_minimal()
            };
            let variant = Variant::Sync(shared_state);

            trace!("Send {:?} to {:?}", variant, p2p_node);
            let message =
                Message::single_src(&core.full_id, DstLocation::Direct, variant, None, None)?;
            core.send_message_to_target(p2p_node.peer_addr(), message.to_bytes());
        }

        Ok(())
    }

    fn send_relocate(
        &mut self,
        core: &mut Core,
        recipient: SocketAddr,
        details: RelocateDetails,
    ) -> Result<()> {
        // We need to construct a proof that would be trusted by the destination section.
        let knowledge_index = self
            .shared_state
            .sections
            .knowledge_by_location(&DstLocation::Section(details.destination));

        let dst = DstLocation::Node(*details.pub_id.name());
        let variant = Variant::Relocate(details);

        trace!("Send {:?} -> {:?}", variant, dst);

        // Message accumulated at destination.
        let message = self.to_accumulating_message(dst, variant, Some(knowledge_index))?;
        core.send_direct_message(&recipient, Variant::MessageSignature(Box::new(message)));

        Ok(())
    }

    fn send_relocate_promise(
        &mut self,
        core: &mut Core,
        recipient: SocketAddr,
        promise: RelocatePromise,
    ) -> Result<()> {
        // Note: this message is first sent to a single node who then sends it back to the section
        // where it needs to be handled by all the elders. This is why the destination is
        // `Section`, not `Node`.
        let dst = DstLocation::Section(promise.name);
        let variant = Variant::RelocatePromise(promise);

        // Message accumulated at destination
        let message = self.to_accumulating_message(dst, variant, None)?;
        core.send_direct_message(&recipient, Variant::MessageSignature(Box::new(message)));

        Ok(())
    }

    fn return_relocate_promise(&mut self, core: &mut Core) {
        // TODO: keep sending this periodically until we get relocated.
        if let Some(bytes) = self.relocate_promise.as_ref().cloned() {
            self.send_message_to_our_elders(core, bytes)
        }
    }

    fn send_dkg_start(&self, core: &mut Core, new_elders_info: EldersInfo) -> Result<()> {
        trace!("Send DKGStart({:?})", new_elders_info);

        // Send to all participants and observers.
        let recipients: Vec<_> = new_elders_info
            .elders
            .values()
            .chain(self.shared_state.our_info().elders.values())
            .map(|p2p_node| *p2p_node.peer_addr())
            .unique()
            .collect();

        let variant = Variant::DKGStart(new_elders_info);
        let message = self.to_accumulating_message(DstLocation::Direct, variant, None)?;
        let message = Message::single_src(
            &core.full_id,
            DstLocation::Direct,
            Variant::MessageSignature(Box::new(message)),
            None,
            None,
        )?;

        core.send_message_to_targets(&recipients, recipients.len(), message.to_bytes());

        Ok(())
    }

    fn send_dkg_result(
        &self,
        core: &mut Core,
        elders_info: EldersInfo,
        result: Result<bls::PublicKey, ()>,
    ) -> Result<()> {
        let variant = Variant::DKGResult {
            elders_info,
            result,
        };

        let recipients = self
            .shared_state
            .our_info()
            .elders
            .values()
            .filter(|p2p_node| p2p_node.name() != core.name());

        trace!("Send {:?} to {}", variant, recipients.clone().format(", "));

        let recipients: Vec<_> = recipients.map(P2pNode::peer_addr).copied().collect();
        let message = Message::single_src(&core.full_id, DstLocation::Direct, variant, None, None)?;
        core.send_message_to_targets(&recipients, recipients.len(), message.to_bytes());

        Ok(())
    }

    fn broadcast_dkg_message(
        &mut self,
        core: &mut Core,
        dkg_key: DkgKey,
        dkg_message: DkgMessage<PublicId>,
    ) -> Result<()> {
        trace!("broadcasting DKG message {:?}", dkg_message);
        let dkg_message_bytes: Bytes = bincode::serialize(&dkg_message)?.into();
        let variant = Variant::DKGMessage {
            dkg_key,
            message: dkg_message_bytes.clone(),
        };
        let message = Message::single_src(&core.full_id, DstLocation::Direct, variant, None, None)?;

        let recipients: Vec<_> = self
            .dkg_voter
            .participants()
            .filter(|p2p_node| p2p_node.public_id() != core.id())
            .map(P2pNode::peer_addr)
            .copied()
            .collect();

        core.send_message_to_targets(&recipients, recipients.len(), message.to_bytes());

        self.handle_dkg_message(core, dkg_key, dkg_message_bytes, *core.id())
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

        trace!("relay {:?} to {:?}", msg, targets);

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
        let key_share = self.section_keys_provider.key_share()?;

        let first_index = proof_start_index_override
            .unwrap_or_else(|| self.shared_state.sections.knowledge_by_location(&dst));
        let last_key = key_share.public_key_set.public_key();
        let last_index = self
            .shared_state
            .our_history
            .index_of(&last_key)
            .unwrap_or_else(|| self.shared_state.our_history.last_key_index());
        let proof_chain = self
            .shared_state
            .our_history
            .slice(first_index..=last_index);

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

        if !self.is_our_elder(core.id()) {
            return Ok(());
        }

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

    #[cfg(feature = "mock")]
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

    // Simulate DKG completion for unit tests.
    #[cfg(all(test, feature = "mock"))]
    pub(crate) fn complete_dkg(
        &mut self,
        core: &mut Core,
        elders_info: EldersInfo,
        public_key_set: bls::PublicKeySet,
        secret_key_share: Option<bls::SecretKeyShare>,
    ) -> Result<()> {
        use bls_dkg::key_gen::outcome::Outcome;

        let public_key = public_key_set.public_key();

        if let Some(secret_key_share) = secret_key_share {
            self.section_keys_provider.insert_dkg_outcome(
                core.name(),
                &elders_info,
                Outcome {
                    public_key_set,
                    secret_key_share,
                },
            )
        }

        self.handle_dkg_result(core, elders_info, Ok(public_key), *core.id())?;

        Ok(())
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
    let mut shared_state = SharedState::new(
        SectionProofChain::new(elders_info.proof.public_key),
        elders_info,
    );

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
        .map_err(|_| Error::InvalidSignatureShare)?;

    Ok(Proof {
        public_key: pk_set.public_key(),
        signature,
    })
}
