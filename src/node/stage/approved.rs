// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{bootstrapping::Bootstrapping, comm::Comm, NodeInfo};
use crate::{
    consensus::{
        AccumulationError, DkgKey, DkgVoter, Proof, ProofShare, Proven, Vote, VoteAccumulator,
    },
    delivery_group,
    error::{Error, Result},
    event::Event,
    location::{DstLocation, SrcLocation},
    message_filter::MessageFilter,
    messages::{
        BootstrapResponse, JoinRequest, Message, MessageHash, MessageStatus, PlainMessage, Variant,
        VerifyStatus,
    },
    peer::Peer,
    relocation::{RelocateAction, RelocateDetails, RelocatePromise, SignedRelocateDetails},
    section::{
        EldersInfo, MemberInfo, SectionKeyShare, SectionKeysProvider, SectionProofChain,
        SectionUpdateBarrier, SharedState, MIN_AGE,
    },
    timer::Timer,
};
use async_recursion::async_recursion;
use bls_dkg::key_gen::message::Message as DkgMessage;
use bytes::Bytes;
use itertools::Itertools;
use std::{net::SocketAddr, slice, time::Duration};
use xor_name::{Prefix, XorName};

// Interval to progress DKG timed phase
const DKG_PROGRESS_INTERVAL: Duration = Duration::from_secs(30);

// The approved stage - node is a full member of a section and is performing its duties according
// to its persona (infant, adult or elder).
pub(crate) struct Approved {
    pub node_info: NodeInfo,
    pub shared_state: SharedState,
    section_keys_provider: SectionKeysProvider,
    vote_accumulator: VoteAccumulator,
    section_update_barrier: SectionUpdateBarrier,
    // Voter for DKG
    dkg_voter: DkgVoter,
    // Serialized `RelocatePromise` message that we received from our section. To be sent back to
    // them after we are demoted.
    relocate_promise: Option<Bytes>,
    comm: Comm,
    msg_filter: MessageFilter,
    timer: Timer,
}

impl Approved {
    // Create the approved stage for a regular node.
    pub fn new(
        comm: Comm,
        shared_state: SharedState,
        section_key_share: Option<SectionKeyShare>,
        node_info: NodeInfo,
        timer: Timer,
    ) -> Result<Self> {
        let section_keys_provider = SectionKeysProvider::new(section_key_share);

        Ok(Self {
            node_info,
            shared_state,
            section_keys_provider,
            vote_accumulator: Default::default(),
            section_update_barrier: Default::default(),
            dkg_voter: Default::default(),
            relocate_promise: None,
            comm,
            msg_filter: MessageFilter::new(),
            timer,
        })
    }

    pub async fn process_message(
        &mut self,
        sender: SocketAddr,
        msg: Message,
    ) -> Result<Option<Bootstrapping>> {
        // Filter messages which were already handled
        if self.msg_filter.contains_incoming(&msg) {
            trace!("not handling message - already handled: {:?}", msg);
            return Ok(None);
        }

        match self.decide_message_status(&msg)? {
            MessageStatus::Useful => {
                trace!("Useful message from {}: {:?}", sender, msg);
                self.update_section_knowledge(&msg).await?;
                self.handle_useful_message(Some(sender), msg).await
            }
            MessageStatus::Untrusted => {
                debug!("Untrusted message from {}: {:?} ", sender, msg);
                self.handle_untrusted_message(Some(sender), msg).await?;
                Ok(None)
            }
            MessageStatus::Unknown => {
                debug!("Unknown message from {}: {:?} ", sender, msg);
                self.handle_unknown_message(Some(sender), msg.to_bytes())
                    .await?;
                Ok(None)
            }
            MessageStatus::Useless => {
                debug!("Useless message from {}: {:?}", sender, msg);
                Ok(None)
            }
        }
    }

    pub async fn process_timeout(&mut self, token: u64) -> Result<()> {
        if self.dkg_voter.timer_token() == Some(token) {
            self.dkg_voter
                .set_timer_token(self.timer.schedule(DKG_PROGRESS_INTERVAL).await);

            if let Err(error) = self.progress_dkg().await {
                error!("failed to progress DKG: {}", error);
            }
        }

        Ok(())
    }

    // Send vote to all our elders.
    async fn vote(&mut self, vote: Vote) -> Result<()> {
        let elders: Vec<_> = self
            .shared_state
            .our_info()
            .elders
            .values()
            .copied()
            .collect();
        self.send_vote(&elders, vote).await
    }

    // Send `vote` to `recipients`.
    #[async_recursion]
    async fn send_vote(&mut self, recipients: &[Peer], vote: Vote) -> Result<()> {
        let key_share = self.section_keys_provider.key_share()?;

        trace!(
            "Vote for {:?} (using {:?})",
            vote,
            key_share.public_key_set.public_key()
        );

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
            &self.node_info.keypair,
            self.age(),
            DstLocation::Direct,
            variant,
            Some(proof_chain),
            Some(*self.shared_state.our_history.last_key()),
        )?;

        let mut others = Vec::new();
        let mut handle = false;

        for recipient in recipients {
            if recipient.name() == &self.node_info.name() {
                handle = true;
            } else {
                others.push(*recipient.addr());
            }
        }

        self.send_message_to_targets(&others, others.len(), message.to_bytes())
            .await?;

        if handle {
            self.handle_vote(vote, proof_share).await?;
        }

        Ok(())
    }

    // Insert the vote into the vote accumulator and handle it if accumulated.
    async fn handle_vote(&mut self, vote: Vote, proof_share: ProofShare) -> Result<()> {
        match self.vote_accumulator.add(vote, proof_share) {
            Ok((vote, proof)) => self.handle_consensus(vote, proof).await,
            Err(AccumulationError::NotEnoughShares) => Ok(()),
            Err(error) => {
                error!("Failed to add vote: {}", error);
                Err(Error::InvalidSignatureShare)
            }
        }
    }

    async fn check_lagging(&mut self, peer: &SocketAddr, proof_share: &ProofShare) -> Result<()> {
        let public_key = proof_share.public_key_set.public_key();

        if self.shared_state.our_history.has_key(&public_key)
            && public_key != *self.shared_state.our_history.last_key()
        {
            // The key is recognized as non-last, indicating the peer is lagging.
            self.send_direct_message(
                peer,
                // TODO: consider sending only those parts of the shared state that are new
                // since `public_key` was the latest key.
                Variant::Sync(self.shared_state.clone()),
            )
            .await?;
        }

        Ok(())
    }

    async fn handle_peer_lost(&mut self, peer_addr: &SocketAddr) -> Result<()> {
        let name = if let Some(node) = self.shared_state.find_peer_from_addr(peer_addr) {
            debug!("Lost known peer {:?}", node);
            *node.name()
        } else {
            trace!("Lost unknown peer {}", peer_addr);
            return Ok(());
        };

        if !self.is_our_elder(&self.node_info.name()) {
            return Ok(());
        }

        if let Some(info) = self.shared_state.our_members.get(&name) {
            let info = info.clone().leave();
            self.vote(Vote::Offline(info)).await?;
        }

        Ok(())
    }

    async fn check_dkg(&mut self, dkg_key: DkgKey) -> Result<()> {
        match self.dkg_voter.check_dkg() {
            Some(Ok((elders_info, outcome))) => {
                let public_key = outcome.public_key_set.public_key();
                self.section_keys_provider.insert_dkg_outcome(
                    &self.node_info.name(),
                    &elders_info,
                    outcome,
                );
                self.handle_dkg_result(dkg_key, Ok(public_key), self.node_info.name())
                    .await
            }
            Some(Err(())) => {
                self.handle_dkg_result(dkg_key, Err(()), self.node_info.name())
                    .await
            }
            None => Ok(()),
        }
    }

    async fn progress_dkg(&mut self) -> Result<()> {
        match self.dkg_voter.progress_dkg() {
            Some((dkg_key, Ok(messages))) => {
                for message in messages {
                    self.broadcast_dkg_message(dkg_key, message).await?;
                }
                self.check_dkg(dkg_key).await
            }
            Some((dkg_key, Err(()))) => {
                self.handle_dkg_result(dkg_key, Err(()), self.node_info.name())
                    .await
            }
            None => Ok(()),
        }
    }

    /// Is the node with the given id an elder in our section?
    pub fn is_our_elder(&self, id: &XorName) -> bool {
        self.shared_state.sections.our().elders.contains_key(id)
    }

    /// Returns the current BLS public key set
    pub fn section_key_share(&self) -> Option<&SectionKeyShare> {
        self.section_keys_provider.key_share().ok()
    }

    ////////////////////////////////////////////////////////////////////////////
    // Message handling
    ////////////////////////////////////////////////////////////////////////////

    fn decide_message_status(&self, msg: &Message) -> Result<MessageStatus> {
        let our_id = self.node_info.name();

        match msg.variant() {
            Variant::NeighbourInfo { .. } => {
                if !self.is_our_elder(&our_id) {
                    return Ok(MessageStatus::Unknown);
                }
            }
            Variant::UserMessage(_) => {
                if !self.should_handle_user_message(&our_id, msg.dst()) {
                    return Ok(MessageStatus::Unknown);
                }
            }
            Variant::JoinRequest(req) => {
                if !self.should_handle_join_request(&our_id, req) {
                    // Note: We don't bounce this message because the current bounce-resend
                    // mechanism wouldn't preserve the original SocketAddr which is needed for
                    // properly handling this message.
                    // This is OK because in the worst case the join request just timeouts and the
                    // joining node sends it again.
                    return Ok(MessageStatus::Useless);
                }
            }
            Variant::DKGStart { elders_info, .. } => {
                if !elders_info.elders.contains_key(&our_id) {
                    return Ok(MessageStatus::Useless);
                }
            }
            Variant::DKGResult { .. } => {
                if !self.is_our_elder(&our_id) {
                    return Ok(MessageStatus::Unknown);
                }
            }
            Variant::NodeApproval(_) | Variant::BootstrapResponse(_) => {
                return Ok(MessageStatus::Useless)
            }
            Variant::Vote { proof_share, .. } => {
                if !self.should_handle_vote(proof_share) {
                    // Message will be bounced if we are lagging (not known of the signing key).
                    return Ok(MessageStatus::Unknown);
                }
            }
            Variant::RelocatePromise(promise) => {
                if promise.name != our_id {
                    if !self.is_our_elder(&our_id) {
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
            | Variant::DKGMessage { .. } => (),
        }

        if self.verify_message(msg)? {
            Ok(MessageStatus::Useful)
        } else {
            Ok(MessageStatus::Untrusted)
        }
    }

    async fn handle_useful_message(
        &mut self,
        sender: Option<SocketAddr>,
        msg: Message,
    ) -> Result<Option<Bootstrapping>> {
        self.msg_filter.insert_incoming(&msg);
        match msg.variant() {
            Variant::NeighbourInfo { elders_info, .. } => {
                msg.dst().check_is_section()?;
                self.handle_neighbour_info(elders_info.value.clone(), *msg.proof_chain_last_key()?)
                    .await?;

                Ok(None)
            }
            Variant::Sync(shared_state) => {
                self.handle_sync(shared_state.clone()).await?;
                Ok(None)
            }
            Variant::Relocate(_) => {
                msg.src().check_is_section()?;
                let signed_relocate = SignedRelocateDetails::new(msg)?;
                match self.handle_relocate(signed_relocate).await {
                    Some(RelocateParams {
                        conn_infos,
                        details,
                    }) => {
                        // Transition from Approved to Bootstrapping on relocation
                        let bootstrapping = Bootstrapping::new(
                            Some(details),
                            conn_infos,
                            self.comm.clone(),
                            self.node_info.clone(),
                            self.timer.clone(),
                        )
                        .await?;

                        Ok(Some(bootstrapping))
                    }
                    None => Ok(None),
                }
            }
            Variant::RelocatePromise(promise) => {
                self.handle_relocate_promise(*promise, msg.to_bytes())
                    .await?;
                Ok(None)
            }
            Variant::BootstrapRequest(name) => {
                self.handle_bootstrap_request(msg.src().to_sender_node(sender)?, *name)
                    .await?;
                Ok(None)
            }
            Variant::JoinRequest(join_request) => {
                self.handle_join_request(msg.src().to_sender_node(sender)?, *join_request.clone())
                    .await?;
                Ok(None)
            }
            Variant::UserMessage(content) => {
                self.handle_user_message(msg.src().src_location(), *msg.dst(), content.clone());
                Ok(None)
            }
            Variant::BouncedUntrustedMessage(message) => {
                self.handle_bounced_untrusted_message(
                    msg.src().to_sender_node(sender)?,
                    *msg.dst_key(),
                    *message.clone(),
                )
                .await?;

                Ok(None)
            }
            Variant::BouncedUnknownMessage { src_key, message } => {
                self.handle_bounced_unknown_message(
                    msg.src().to_sender_node(sender)?,
                    message.clone(),
                    src_key,
                )
                .await?;
                Ok(None)
            }
            Variant::DKGStart {
                dkg_key,
                elders_info,
            } => {
                self.handle_dkg_start(*dkg_key, elders_info.clone()).await?;
                Ok(None)
            }
            Variant::DKGMessage { dkg_key, message } => {
                self.handle_dkg_message(*dkg_key, message.clone(), msg.src().as_node()?.0)
                    .await?;
                Ok(None)
            }
            Variant::DKGResult { dkg_key, result } => {
                self.handle_dkg_result(*dkg_key, *result, msg.src().as_node()?.0)
                    .await?;

                Ok(None)
            }
            Variant::Vote {
                content,
                proof_share,
            } => {
                let result = self.handle_vote(content.clone(), proof_share.clone()).await;
                if let Some(addr) = sender {
                    self.check_lagging(&addr, proof_share).await?;
                }

                result?;

                Ok(None)
            }
            Variant::NodeApproval(_) | Variant::BootstrapResponse(_) => unreachable!(),
        }
    }

    // Ignore `JoinRequest` if we are not elder unless the join request is outdated in which case we
    // reply with `BootstrapResponse::Join` with the up-to-date info (see `handle_join_request`).
    fn should_handle_join_request(&self, our_id: &XorName, req: &JoinRequest) -> bool {
        self.is_our_elder(our_id) || req.section_key != *self.shared_state.our_history.last_key()
    }

    // If elder, always handle UserMessage, otherwise handle it only if addressed directly to us
    // as a node.
    fn should_handle_user_message(&self, our_id: &XorName, dst: &DstLocation) -> bool {
        self.is_our_elder(our_id) || dst.as_node().ok() == Some(our_id)
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
                warn!("Verification of {:?} failed: {}", msg, error);
                Err(error)
            }
        }
    }

    /// Handle message whose trust we can't establish because its proof contains only keys we don't
    /// know.
    async fn handle_untrusted_message(
        &mut self,
        sender: Option<SocketAddr>,
        msg: Message,
    ) -> Result<()> {
        let src = msg.src().src_location();
        let bounce_dst = src.to_dst();
        let bounce_dst_key = *self.shared_state.section_key_by_location(&bounce_dst);

        let bounce_msg = Message::single_src(
            &self.node_info.keypair,
            self.age(),
            bounce_dst,
            Variant::BouncedUntrustedMessage(Box::new(msg)),
            None,
            Some(bounce_dst_key),
        )?;
        let bounce_msg = bounce_msg.to_bytes();

        if let Some(sender) = sender {
            self.send_message_to_target(&sender, bounce_msg).await
        } else {
            self.send_message_to_our_elders(bounce_msg).await
        }
    }

    /// Handle message that is "unknown" because we are not in the correct state (e.g. we are adult
    /// and the message is for elders). We bounce the message to our elders who have more
    /// information to decide what to do with it.
    async fn handle_unknown_message(
        &mut self,
        sender: Option<SocketAddr>,
        msg_bytes: Bytes,
    ) -> Result<()> {
        let bounce_msg = Message::single_src(
            &self.node_info.keypair,
            self.age(),
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
                .any(|peer| peer.addr() == sender)
        });
        if let Some(sender) = our_elder_sender {
            self.send_message_to_target(&sender, bounce_msg).await
        } else {
            self.send_message_to_our_elders(bounce_msg).await
        }
    }

    async fn handle_bounced_untrusted_message(
        &mut self,
        sender: Peer,
        dst_key: Option<bls::PublicKey>,
        bounced_msg: Message,
    ) -> Result<()> {
        trace!(
            "Received BouncedUntrustedMessage({:?}) from {:?}...",
            bounced_msg,
            sender
        );

        if let Some(dst_key) = dst_key {
            let resend_msg =
                match bounced_msg.extend_proof_chain(&dst_key, &self.shared_state.our_history) {
                    Ok(msg) => msg,
                    Err(err) => {
                        trace!("...extending proof failed, discarding: {:?}", err);
                        return Ok(());
                    }
                };

            trace!("    ...resending with extended proof");
            self.send_message_to_target(sender.addr(), resend_msg.to_bytes())
                .await
        } else {
            trace!("    ...missing dst key, discarding");
            Ok(())
        }
    }

    async fn handle_bounced_unknown_message(
        &mut self,
        sender: Peer,
        bounced_msg_bytes: Bytes,
        sender_last_key: &bls::PublicKey,
    ) -> Result<()> {
        if !self.shared_state.our_history.has_key(sender_last_key)
            || sender_last_key == self.shared_state.our_history.last_key()
        {
            trace!(
                "Received BouncedUnknownMessage({:?}) from {:?} \
                 - peer is up to date or ahead of us, discarding",
                MessageHash::from_bytes(&bounced_msg_bytes),
                sender
            );
            return Ok(());
        }

        trace!(
            "Received BouncedUnknownMessage({:?}) from {:?} \
             - peer is lagging behind, resending with Sync",
            MessageHash::from_bytes(&bounced_msg_bytes),
            sender,
        );
        // First send Sync to update the peer, then resend the message itself. If the messages
        // arrive in the same order they were sent, the Sync should update the peer so it will then
        // be able to handle the resent message. If not, the peer will bounce the message again.
        self.send_direct_message(sender.addr(), Variant::Sync(self.shared_state.clone()))
            .await?;
        self.send_message_to_target(sender.addr(), bounced_msg_bytes)
            .await
    }

    async fn handle_neighbour_info(
        &mut self,
        elders_info: EldersInfo,
        src_key: bls::PublicKey,
    ) -> Result<()> {
        if !self.shared_state.sections.has_key(&src_key) {
            self.vote(Vote::TheirKey {
                prefix: elders_info.prefix,
                key: src_key,
            })
            .await?;
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
            self.vote(Vote::SectionInfo(elders_info)).await
        } else {
            Ok(())
        }
    }

    fn handle_user_message(&mut self, src: SrcLocation, dst: DstLocation, content: Bytes) {
        self.node_info
            .send_event(Event::MessageReceived { content, src, dst })
    }

    async fn handle_sync(&mut self, shared_state: SharedState) -> Result<()> {
        if !shared_state.our_prefix().matches(&self.node_info.name()) {
            trace!("ignore Sync - not our section");
            return Ok(());
        }

        self.update_shared_state(shared_state).await
    }

    async fn handle_relocate(
        &mut self,
        signed_msg: SignedRelocateDetails,
    ) -> Option<RelocateParams> {
        if signed_msg.relocate_details().pub_id != self.node_info.name() {
            // This `Relocate` message is not for us - it's most likely a duplicate of a previous
            // message that we already handled.
            return None;
        }

        debug!(
            "Received Relocate message to join the section at {}.",
            signed_msg.relocate_details().destination
        );

        if self.relocate_promise.is_none() {
            self.node_info.send_event(Event::RelocationStarted {
                previous_name: self.node_info.name(),
            });
        }

        let conn_infos: Vec<_> = self
            .shared_state
            .sections
            .our_elders()
            .map(Peer::addr)
            .copied()
            .collect();

        Some(RelocateParams {
            details: signed_msg,
            conn_infos,
        })
    }

    async fn handle_relocate_promise(
        &mut self,
        promise: RelocatePromise,
        msg_bytes: Bytes,
    ) -> Result<()> {
        if promise.name == self.node_info.name() {
            // Store the `RelocatePromise` message and send it back after we are demoted.
            // Keep it around even if we are not elder anymore, in case we need to resend it.
            if self.relocate_promise.is_none() {
                self.relocate_promise = Some(msg_bytes.clone());
                self.node_info.send_event(Event::RelocationStarted {
                    previous_name: self.node_info.name(),
                });
            } else {
                trace!("ignore RelocatePromise - already have one");
            }

            // We are no longer elder. Send the promise back already.
            if !self.is_our_elder(&self.node_info.name()) {
                self.send_message_to_our_elders(msg_bytes).await?;
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
            let peer = info.peer;
            self.send_relocate(&peer, details).await
        } else {
            error!(
                "ignore returned RelocatePromise from {} - unknown node",
                promise.name
            );
            Ok(())
        }
    }

    // Note: As an adult, we should only give info about our section elders and they would
    // further guide the joining node. However this lead to a loop if the Adult is the new Elder so
    // we use the same code as for Elder and return Join in some cases.
    async fn handle_bootstrap_request(&mut self, peer: Peer, destination: XorName) -> Result<()> {
        debug!(
            "Received BootstrapRequest to section at {} from {:?}.",
            destination, peer
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
                .map(|peer| *peer.addr())
                .collect();
            BootstrapResponse::Rebootstrap(conn_infos)
        };

        debug!("Sending BootstrapResponse {:?} to {:?}", response, peer);
        self.send_direct_message(peer.addr(), Variant::BootstrapResponse(response))
            .await
    }

    async fn handle_join_request(&mut self, peer: Peer, join_request: JoinRequest) -> Result<()> {
        debug!("Received {:?} from {:?}", join_request, peer);

        if join_request.section_key != *self.shared_state.our_history.last_key() {
            let response = BootstrapResponse::Join {
                elders_info: self.shared_state.our_info().clone(),
                section_key: *self.shared_state.our_history.last_key(),
            };
            trace!("Resending BootstrapResponse {:?} to {:?}", response, peer,);
            return self
                .send_direct_message(peer.addr(), Variant::BootstrapResponse(response))
                .await;
        }

        let pub_id = *peer.name();
        if !self.shared_state.our_prefix().matches(&pub_id) {
            debug!(
                "Ignoring JoinRequest from {} - name doesn't match our prefix {:?}.",
                pub_id,
                self.shared_state.our_prefix()
            );
            return Ok(());
        }

        if self.shared_state.our_members.is_joined(&pub_id) {
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
                    Some(details.pub_id),
                    Some(details.destination_key),
                )
            } else {
                (MIN_AGE, None, None)
            };

        self.vote(Vote::Online {
            member_info: MemberInfo::joined(peer.with_age(age)),
            previous_name,
            their_knowledge,
        })
        .await
    }

    pub async fn handle_dkg_start(
        &mut self,
        dkg_key: DkgKey,
        new_elders_info: EldersInfo,
    ) -> Result<()> {
        trace!("Received DKGStart for {}", new_elders_info);

        if let Some(message) =
            self.dkg_voter
                .start_participating(self.node_info.name(), dkg_key, new_elders_info)
        {
            // TODO ??
            //self.dkg_voter
            //    .set_timer_token(core.timer.schedule(DKG_PROGRESS_INTERVAL));
            self.broadcast_dkg_message(dkg_key, message).await?
        }

        Ok(())
    }

    pub async fn handle_dkg_result(
        &mut self,
        dkg_key: DkgKey,
        result: Result<bls::PublicKey, ()>,
        sender: XorName,
    ) -> Result<()> {
        if sender == self.node_info.name() {
            self.send_dkg_result(dkg_key, result).await?;
        }

        if !self.is_our_elder(&self.node_info.name()) {
            return Ok(());
        }

        let (elders_info, result) =
            if let Some(output) = self.dkg_voter.observe_result(&dkg_key, result, sender) {
                output
            } else {
                return Ok(());
            };

        trace!("accumulated DKG result for {}: {:?}", elders_info, result);

        for info in self
            .shared_state
            .promote_and_demote_elders(&self.node_info.network_params, &self.node_info.name())
        {
            // Check whether the result still corresponds to the current elder candidates.
            if info == elders_info {
                debug!("handle DKG result for {}: {:?}", info, result);

                if let Ok(public_key) = result {
                    self.vote_for_section_update(public_key, info).await?
                } else {
                    self.send_dkg_start(info).await?;
                }
            } else if info.prefix == elders_info.prefix
                || info.prefix.is_extension_of(&elders_info.prefix)
            {
                trace!(
                    "ignore DKG result for {}: {:?} - outdated",
                    elders_info,
                    result
                );
                self.send_dkg_start(info).await?;
            }
        }

        Ok(())
    }

    pub async fn handle_dkg_message(
        &mut self,
        dkg_key: DkgKey,
        message_bytes: Bytes,
        sender: XorName,
    ) -> Result<()> {
        let message = bincode::deserialize(&message_bytes[..])?;

        trace!("handle DKG message {:?} from {}", message, sender);

        let responses = self.dkg_voter.process_dkg_message(&dkg_key, message);

        // Only a valid DkgMessage, which results in some responses, shall reset the ticker.
        if !responses.is_empty() {
            self.dkg_voter
                .set_timer_token(self.timer.schedule(DKG_PROGRESS_INTERVAL).await);
        }

        for response in responses {
            let _ = self.broadcast_dkg_message(dkg_key, response).await;
        }

        self.check_dkg(dkg_key).await
    }

    async fn try_relay_message(&mut self, msg: &Message) -> Result<()> {
        if !msg
            .dst()
            .contains(&self.node_info.name(), self.shared_state.our_prefix())
            || msg.dst().is_section()
        {
            // Relay closer to the destination or broadcast to the rest of our section.
            self.relay_message(msg).await
        } else {
            Ok(())
        }
    }

    #[async_recursion]
    async fn handle_accumulated_message(&mut self, msg: Message) -> Result<()> {
        trace!("accumulated message {:?}", msg);

        // TODO: this is almost the same as `Node::try_handle_message` - find a way
        // to avoid the duplication.
        self.try_relay_message(&msg).await?;

        if !msg
            .dst()
            .contains(&self.node_info.name(), self.shared_state.our_prefix())
        {
            return Ok(());
        }

        if self.msg_filter.contains_incoming(&msg) {
            trace!("not handling message - already handled: {:?}", msg);
            return Ok(());
        }

        match self.decide_message_status(&msg)? {
            MessageStatus::Useful => {
                self.msg_filter.insert_incoming(&msg);
                let _ = self.handle_useful_message(None, msg).await?;
                Ok(())
            }
            MessageStatus::Untrusted => {
                trace!("Untrusted accumulated message: {:?}", msg);
                self.handle_untrusted_message(None, msg).await
            }
            MessageStatus::Unknown => {
                trace!("Unknown accumulated message: {:?}", msg);
                self.handle_unknown_message(None, msg.to_bytes()).await
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
    async fn promote_and_demote_elders(&mut self) -> Result<()> {
        for info in self
            .shared_state
            .promote_and_demote_elders(&self.node_info.network_params, &self.node_info.name())
        {
            self.send_dkg_start(info).await?;
        }

        Ok(())
    }

    async fn increment_ages(
        &mut self,
        churn_name: &XorName,
        churn_signature: &bls::Signature,
    ) -> Result<()> {
        if self.is_in_startup_phase() {
            // We are in the startup phase - don't relocate, just increment everyones ages
            // (excluding the new node).
            let votes: Vec<_> = self
                .shared_state
                .our_members
                .joined()
                .filter(|info| info.peer.name() != churn_name)
                .map(|info| Vote::ChangeAge(info.clone().increment_age()))
                .collect();

            for vote in votes {
                self.vote(vote).await?;
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
                "Relocating {:?} to {} (on churn of {})",
                info.peer,
                action.destination(),
                churn_name
            );

            let peer = info.peer;

            self.vote(Vote::Offline(info.relocate(*action.destination())))
                .await?;

            match action {
                RelocateAction::Instant(details) => self.send_relocate(&peer, details).await?,
                RelocateAction::Delayed(promise) => {
                    self.send_relocate_promise(&peer, promise).await?
                }
            }
        }

        Ok(())
    }

    // Are we in the startup phase? Startup phase is when the network consists of only one section
    // and it has no more than `recommended_section_size` members.
    fn is_in_startup_phase(&self) -> bool {
        self.shared_state.our_prefix().is_empty()
            && self.shared_state.our_members.joined().count()
                <= self.node_info.network_params.recommended_section_size
    }

    async fn handle_consensus(&mut self, vote: Vote, proof: Proof) -> Result<()> {
        debug!("handle consensus on {:?}", vote);

        match vote {
            Vote::Online {
                member_info,
                previous_name,
                their_knowledge,
            } => {
                self.handle_online_event(member_info, previous_name, their_knowledge, proof)
                    .await
            }
            Vote::Offline(member_info) => self.handle_offline_event(member_info, proof).await,
            Vote::SectionInfo(elders_info) => {
                self.handle_section_info_event(elders_info, proof).await
            }
            Vote::OurKey { prefix, key } => self.handle_our_key_event(prefix, key, proof).await,
            Vote::TheirKey { prefix, key } => self.handle_their_key_event(prefix, key, proof).await,
            Vote::TheirKnowledge { prefix, key_index } => {
                self.handle_their_knowledge_event(prefix, key_index, proof);
                Ok(())
            }
            Vote::ChangeAge(member_info) => {
                self.handle_change_age_event(member_info, proof);
                Ok(())
            }
            Vote::SendMessage {
                message,
                proof_chain,
            } => {
                self.handle_send_message_event(*message, proof_chain, proof)
                    .await
            }
        }
    }

    async fn handle_online_event(
        &mut self,
        member_info: MemberInfo,
        previous_name: Option<XorName>,
        their_knowledge: Option<bls::PublicKey>,
        proof: Proof,
    ) -> Result<()> {
        let peer = member_info.peer;
        let age = peer.age();
        let signature = proof.signature.clone();

        if !self.shared_state.update_member(member_info, proof) {
            info!("ignore Online: {:?}", peer);
            return Ok(());
        }

        info!("handle Online: {:?} (age: {})", peer, age);

        self.increment_ages(peer.name(), &signature).await?;
        self.send_node_approval(&peer, their_knowledge).await?;
        self.print_network_stats();

        if let Some(previous_name) = previous_name {
            self.node_info.send_event(Event::MemberJoined {
                name: *peer.name(),
                previous_name,
                age,
            });
        } else {
            self.node_info.send_event(Event::InfantJoined {
                name: *peer.name(),
                age,
            });
        }

        self.promote_and_demote_elders().await
    }

    async fn handle_offline_event(&mut self, member_info: MemberInfo, proof: Proof) -> Result<()> {
        let peer = member_info.peer;
        let age = peer.age();
        let signature = proof.signature.clone();

        if !self.shared_state.update_member(member_info, proof) {
            info!("ignore Offline: {:?}", peer);
            return Ok(());
        }

        info!("handle Offline: {:?}", peer);

        self.increment_ages(peer.name(), &signature).await?;

        self.node_info.send_event(Event::MemberLeft {
            name: *peer.name(),
            age,
        });

        self.promote_and_demote_elders().await
    }

    async fn handle_section_info_event(
        &mut self,
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
                &self.node_info.name(),
                elders_info,
            );
            self.try_update_our_section().await
        } else {
            // Other section
            let _ = self.shared_state.update_neighbour_info(elders_info);
            Ok(())
        }
    }

    async fn handle_our_key_event(
        &mut self,
        prefix: Prefix,
        key: bls::PublicKey,
        proof: Proof,
    ) -> Result<()> {
        let key = Proven::new(key, proof);

        self.section_update_barrier.handle_our_key(
            &self.shared_state,
            &self.node_info.name(),
            &prefix,
            key,
        );
        self.try_update_our_section().await
    }

    async fn handle_their_key_event(
        &mut self,
        prefix: Prefix,
        key: bls::PublicKey,
        proof: Proof,
    ) -> Result<()> {
        let key = Proven::new((prefix, key), proof);

        if key.value.0.is_extension_of(self.shared_state.our_prefix()) {
            self.section_update_barrier.handle_their_key(
                &self.shared_state,
                &self.node_info.name(),
                key,
            );
            self.try_update_our_section().await
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

    async fn handle_send_message_event(
        &mut self,
        message: PlainMessage,
        proof_chain: SectionProofChain,
        proof: Proof,
    ) -> Result<()> {
        let message = Message::section_src(
            message.src,
            proof.signature,
            message.dst,
            message.variant,
            proof_chain,
            message.dst_key,
        )?;

        self.handle_accumulated_message(message).await
    }

    async fn vote_for_section_update(
        &mut self,
        public_key: bls::PublicKey,
        elders_info: EldersInfo,
    ) -> Result<()> {
        if self.shared_state.our_history.has_key(&public_key) {
            // Our shared state is already up to date, so no need to vote. Just finalize the DKG so
            // we can start using the new secret key share.
            self.section_keys_provider.finalise_dkg(&public_key);
            return Ok(());
        }

        if !self.section_update_barrier.start_update(elders_info.prefix) {
            trace!(
                "section update of {:?} already in progress",
                elders_info.prefix
            );
            return Ok(());
        }

        // Casting unordered_votes will check consensus and handle accumulated immediately.
        self.vote(Vote::OurKey {
            prefix: elders_info.prefix,
            key: public_key,
        })
        .await?;

        if elders_info
            .prefix
            .is_extension_of(self.shared_state.our_prefix())
        {
            self.vote(Vote::TheirKey {
                prefix: elders_info.prefix,
                key: public_key,
            })
            .await?;
        }

        self.vote(Vote::SectionInfo(elders_info)).await
    }

    async fn try_update_our_section(&mut self) -> Result<()> {
        let (our, sibling) = self
            .section_update_barrier
            .take(self.shared_state.our_prefix());

        if let Some(our) = our {
            trace!("update our section: {:?}", our.our_info());
            self.update_shared_state(our).await?;
        }

        if let Some(sibling) = sibling {
            trace!("update sibling section: {:?}", sibling.our_info());

            // We can update the sibling knowledge already because we know they also reached consensus
            // on our `OurKey` so they know our latest key. Need to vote for it first though, to
            // accumulate the signatures.
            self.vote(Vote::TheirKnowledge {
                prefix: *sibling.our_prefix(),
                key_index: self.shared_state.our_history.last_key_index(),
            })
            .await?;

            self.send_sync(sibling).await?;
        }

        Ok(())
    }

    async fn update_shared_state(&mut self, update: SharedState) -> Result<()> {
        let old_is_elder = self.is_our_elder(&self.node_info.name());
        let old_last_key_index = self.shared_state.our_history.last_key_index();
        let old_prefix = *self.shared_state.our_prefix();

        self.shared_state.merge(update)?;

        self.section_keys_provider
            .finalise_dkg(self.shared_state.our_history.last_key());
        self.dkg_voter
            .stop_observing(self.shared_state.our_history.last_key_index());

        let new_is_elder = self.is_our_elder(&self.node_info.name());
        let new_last_key_index = self.shared_state.our_history.last_key_index();
        let new_prefix = *self.shared_state.our_prefix();

        if new_prefix != old_prefix {
            info!("Split");

            if new_is_elder {
                // We can update the sibling knowledge already because we know they also reached
                // consensus on our `OurKey` so they know our latest key. Need to vote for it first
                // though, to accumulate the signatures.
                self.vote(Vote::TheirKnowledge {
                    prefix: new_prefix.sibling(),
                    key_index: new_last_key_index,
                })
                .await?;
            }
        }

        if new_last_key_index != old_last_key_index {
            self.msg_filter.reset();

            if new_is_elder {
                info!(
                    "Section updated: prefix: ({:b}), key: {:?}, elders: {:?}",
                    self.shared_state.our_prefix(),
                    self.shared_state.our_history.last_key(),
                    self.shared_state.our_info().elders.values().format(", ")
                );

                self.promote_and_demote_elders().await?;
                self.print_network_stats();
            }

            if new_is_elder || old_is_elder {
                self.send_sync(self.shared_state.clone()).await?;
            }

            self.node_info.send_event(Event::EldersChanged {
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
        }

        if !old_is_elder && new_is_elder {
            info!("Promoted to elder");
            self.node_info.send_event(Event::PromotedToElder);
        }

        if old_is_elder && !new_is_elder {
            info!("Demoted");
            self.shared_state.demote();
            self.section_keys_provider = SectionKeysProvider::new(None);
            self.node_info.send_event(Event::Demoted);
        }

        if !new_is_elder {
            self.return_relocate_promise().await?;
        }

        Ok(())
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
            info!("Voting for unresponsive node {}", info.peer);
            self.cast_unordered_vote(core, Vote::Offline(info))?;
        }

        Ok(())
    }
    */

    ////////////////////////////////////////////////////////////////////////////
    // Message sending
    ////////////////////////////////////////////////////////////////////////////

    // Send NodeApproval to the current candidate which makes them a section member
    async fn send_node_approval(
        &mut self,
        peer: &Peer,
        their_knowledge: Option<bls::PublicKey>,
    ) -> Result<()> {
        info!(
            "Our section with {:?} has approved candidate {:?}.",
            self.shared_state.our_prefix(),
            peer
        );

        let their_knowledge =
            their_knowledge.and_then(|key| self.shared_state.our_history.index_of(&key));
        let proof_chain = self
            .shared_state
            .create_proof_chain_for_our_info(their_knowledge);

        let variant = Variant::NodeApproval(self.shared_state.sections.proven_our().clone());

        trace!("Send {:?} to {:?}", variant, peer);
        let message = Message::single_src(
            &self.node_info.keypair,
            self.age(),
            DstLocation::Direct,
            variant,
            Some(proof_chain),
            None,
        )?;
        self.send_message_to_target(peer.addr(), message.to_bytes())
            .await?;
        Ok(())
    }

    async fn send_sync(&mut self, shared_state: SharedState) -> Result<()> {
        for peer in shared_state.active_members() {
            if peer.name() == &self.node_info.name() {
                continue;
            }

            let shared_state = if shared_state.is_peer_our_elder(peer.name()) {
                shared_state.clone()
            } else {
                shared_state.to_minimal()
            };
            let variant = Variant::Sync(shared_state);

            trace!("Send {:?} to {:?}", variant, peer);
            let message = Message::single_src(
                &self.node_info.keypair,
                self.age(),
                DstLocation::Direct,
                variant,
                None,
                None,
            )?;
            self.send_message_to_target(peer.addr(), message.to_bytes())
                .await?;
        }

        Ok(())
    }

    async fn send_relocate(&mut self, recipient: &Peer, details: RelocateDetails) -> Result<()> {
        // We need to construct a proof that would be trusted by the destination section.
        let knowledge_index = self
            .shared_state
            .sections
            .knowledge_by_location(&DstLocation::Section(details.destination));

        let dst = DstLocation::Node(details.pub_id);
        let variant = Variant::Relocate(details);

        trace!("Send {:?} -> {:?}", variant, dst);

        // Vote accumulated at destination.
        let vote = self.create_send_message_vote(dst, variant, Some(knowledge_index))?;
        self.send_vote(slice::from_ref(recipient), vote).await
    }

    async fn send_relocate_promise(
        &mut self,
        recipient: &Peer,
        promise: RelocatePromise,
    ) -> Result<()> {
        // Note: this message is first sent to a single node who then sends it back to the section
        // where it needs to be handled by all the elders. This is why the destination is
        // `Section`, not `Node`.
        let dst = DstLocation::Section(promise.name);
        let variant = Variant::RelocatePromise(promise);

        // Vote accumulated at destination
        let vote = self.create_send_message_vote(dst, variant, None)?;
        self.send_vote(slice::from_ref(recipient), vote).await
    }

    async fn return_relocate_promise(&mut self) -> Result<()> {
        // TODO: keep sending this periodically until we get relocated.
        if let Some(bytes) = self.relocate_promise.as_ref().cloned() {
            self.send_message_to_our_elders(bytes).await?;
        }
        Ok(())
    }

    async fn send_dkg_start(&mut self, new_elders_info: EldersInfo) -> Result<()> {
        trace!("Send DKGStart for {}", new_elders_info);

        let dkg_key = DkgKey::new(&new_elders_info);

        // Send to all participants.
        let recipients: Vec<_> = new_elders_info.elders.values().copied().collect();
        let variant = Variant::DKGStart {
            dkg_key,
            elders_info: new_elders_info.clone(),
        };
        let vote = self.create_send_message_vote(DstLocation::Direct, variant, None)?;
        self.send_vote(&recipients, vote).await?;

        self.dkg_voter.start_observing(
            dkg_key,
            new_elders_info,
            self.shared_state.our_history.last_key_index(),
        );

        Ok(())
    }

    async fn send_dkg_result(
        &mut self,
        dkg_key: DkgKey,
        result: Result<bls::PublicKey, ()>,
    ) -> Result<()> {
        let variant = Variant::DKGResult { dkg_key, result };

        let recipients = self
            .shared_state
            .our_info()
            .elders
            .values()
            .filter(|peer| peer.name() != &self.node_info.name());

        trace!(
            "Send {:?} to {:?}",
            variant,
            recipients.clone().format(", ")
        );

        let recipients: Vec<_> = recipients.map(Peer::addr).copied().collect();
        let message = Message::single_src(
            &self.node_info.keypair,
            self.age(),
            DstLocation::Direct,
            variant,
            None,
            None,
        )?;
        self.send_message_to_targets(&recipients, recipients.len(), message.to_bytes())
            .await?;

        Ok(())
    }

    #[async_recursion]
    async fn broadcast_dkg_message(
        &mut self,
        dkg_key: DkgKey,
        dkg_message: DkgMessage,
    ) -> Result<()> {
        trace!("broadcasting DKG message {:?}", dkg_message);
        let dkg_message_bytes: Bytes = bincode::serialize(&dkg_message)?.into();
        let variant = Variant::DKGMessage {
            dkg_key,
            message: dkg_message_bytes.clone(),
        };
        let message = Message::single_src(
            &self.node_info.keypair,
            self.age(),
            DstLocation::Direct,
            variant,
            None,
            None,
        )?;

        let recipients: Vec<_> = self
            .dkg_voter
            .participants()
            .filter(|peer| peer.name() != &self.node_info.name())
            .map(Peer::addr)
            .copied()
            .collect();

        self.send_message_to_targets(&recipients, recipients.len(), message.to_bytes())
            .await?;

        // TODO: remove the recursion caused by this call.
        self.handle_dkg_message(dkg_key, dkg_message_bytes, self.node_info.name())
            .await
    }

    // Send message over the network.
    pub async fn relay_message(&mut self, msg: &Message) -> Result<()> {
        let (targets, dg_size) = delivery_group::delivery_targets(
            msg.dst(),
            &self.node_info.name(),
            &self.shared_state.our_members,
            &self.shared_state.sections,
        )?;

        let targets: Vec<_> = targets
            .into_iter()
            .filter(|peer| self.msg_filter.filter_outgoing(msg, peer.name()).is_new())
            .collect();

        if targets.is_empty() {
            return Ok(());
        }

        trace!("relay {:?} to {:?}", msg, targets);

        let targets: Vec<_> = targets.into_iter().map(|node| *node.addr()).collect();
        self.send_message_to_targets(&targets, dg_size, msg.to_bytes())
            .await?;

        Ok(())
    }

    pub async fn send_user_message(
        &mut self,
        src: SrcLocation,
        dst: DstLocation,
        content: Bytes,
    ) -> Result<()> {
        if !src.contains(&self.node_info.name()) {
            error!(
                "Not sending user message {:?} -> {:?}: not part of the source location",
                src, dst
            );
            return Err(Error::BadLocation);
        }

        if matches!(dst, DstLocation::Direct) {
            error!(
                "Not sending user message {:?} -> {:?}: direct dst not supported",
                src, dst
            );
            return Err(Error::BadLocation);
        }

        let variant = Variant::UserMessage(content);

        match src {
            SrcLocation::Node(_) => {
                // If the source is a single node, we don't even need to vote, so let's cut this short.
                let msg = Message::single_src(
                    &self.node_info.keypair,
                    self.age(),
                    dst,
                    variant,
                    None,
                    None,
                )?;
                self.relay_message(&msg).await
            }
            SrcLocation::Section(_) => {
                let vote = self.create_send_message_vote(dst, variant, None)?;

                let recipients = delivery_group::signature_targets(
                    &dst,
                    self.shared_state.our_info().elders.values().copied(),
                );
                self.send_vote(&recipients, vote).await
            }
        }
    }

    fn create_send_message_vote(
        &self,
        dst: DstLocation,
        variant: Variant,
        proof_chain_first_index: Option<u64>,
    ) -> Result<Vote> {
        let proof_chain = self.create_proof_chain(&dst, proof_chain_first_index)?;
        let dst_key = *self.shared_state.section_key_by_location(&dst);
        let message = PlainMessage {
            src: *self.shared_state.our_prefix(),
            dst,
            dst_key,
            variant,
        };

        Ok(Vote::SendMessage {
            message: Box::new(message),
            proof_chain,
        })
    }

    fn create_proof_chain(
        &self,
        dst: &DstLocation,
        first_index: Option<u64>,
    ) -> Result<SectionProofChain> {
        let first_index =
            first_index.unwrap_or_else(|| self.shared_state.sections.knowledge_by_location(dst));

        let last_key = self
            .section_keys_provider
            .key_share()?
            .public_key_set
            .public_key();
        let last_index = self
            .shared_state
            .our_history
            .index_of(&last_key)
            .unwrap_or_else(|| self.shared_state.our_history.last_key_index());

        Ok(self
            .shared_state
            .our_history
            .slice(first_index..=last_index))
    }

    pub async fn send_direct_message(
        &mut self,
        recipient: &SocketAddr,
        variant: Variant,
    ) -> Result<()> {
        let message = Message::single_src(
            &self.node_info.keypair,
            self.age(),
            DstLocation::Direct,
            variant,
            None,
            None,
        )?;
        self.send_message_to_target(recipient, message.to_bytes())
            .await
    }

    // TODO: consider changing this so it sends only to a subset of the elders
    // (say 1/3 of the ones closest to our name or so)
    async fn send_message_to_our_elders(&mut self, msg_bytes: Bytes) -> Result<()> {
        let targets: Vec<_> = self
            .shared_state
            .sections
            .our_elders()
            .map(Peer::addr)
            .copied()
            .collect();
        self.send_message_to_targets(&targets, targets.len(), msg_bytes)
            .await
    }

    async fn send_message_to_targets(
        &mut self,
        recipients: &[SocketAddr],
        delivery_group_size: usize,
        msg: Bytes,
    ) -> Result<()> {
        match self
            .comm
            .send_message_to_targets(recipients, delivery_group_size, msg)
            .await
        {
            Ok(()) => Ok(()),
            Err(error) => {
                for addr in &error.failed_recipients {
                    self.handle_peer_lost(addr).await?;
                }

                Err(error.into())
            }
        }
    }

    async fn send_message_to_target(&mut self, recipient: &SocketAddr, msg: Bytes) -> Result<()> {
        self.send_message_to_targets(slice::from_ref(recipient), 1, msg)
            .await
    }

    ////////////////////////////////////////////////////////////////////////////
    // Miscellaneous
    ////////////////////////////////////////////////////////////////////////////

    // Update our knowledge of their (sender's) section and their knowledge of our section.
    async fn update_section_knowledge(&mut self, msg: &Message) -> Result<()> {
        use crate::section::UpdateSectionKnowledgeAction::*;

        if !self.is_our_elder(&self.node_info.name()) {
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
            &self.node_info.name(),
            src_prefix,
            src_key,
            msg.dst_key().as_ref(),
            hash,
        );

        for action in actions {
            match action {
                VoteTheirKey { prefix, key } => {
                    self.vote(Vote::TheirKey { prefix, key }).await?;
                }
                VoteTheirKnowledge { prefix, key_index } => {
                    self.vote(Vote::TheirKnowledge { prefix, key_index })
                        .await?;
                }
                SendNeighbourInfo { dst, nonce } => {
                    self.send_neighbour_info(
                        dst,
                        nonce,
                        self.shared_state.sections.key_by_name(&dst.name()).cloned(),
                    )
                    .await?
                }
            }
        }

        Ok(())
    }

    async fn send_neighbour_info(
        &mut self,
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
            &self.node_info.keypair,
            self.age(),
            DstLocation::Section(dst.name()),
            variant,
            Some(proof_chain),
            dst_key,
        )?;

        self.try_relay_message(&msg).await
    }

    fn print_network_stats(&self) {
        self.shared_state.sections.network_stats().print()
    }

    fn age(&self) -> u8 {
        self.shared_state
            .find_age_for_peer(&self.node_info.name())
            .unwrap_or(MIN_AGE)
    }
}

pub(crate) struct RelocateParams {
    pub conn_infos: Vec<SocketAddr>,
    pub details: SignedRelocateDetails,
}
