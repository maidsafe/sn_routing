// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{Command, UpdateBarrier};
use crate::{
    consensus::{
        AccumulationError, DkgCommands, DkgKey, DkgVoter, Proof, ProofShare, Proven, Vote,
        VoteAccumulator,
    },
    delivery_group,
    error::{Error, Result},
    event::Event,
    location::{DstLocation, SrcLocation},
    message_filter::MessageFilter,
    messages::{
        BootstrapResponse, JoinRequest, Message, MessageHash, MessageStatus, PlainMessage, Variant,
        VerifyStatus, PING,
    },
    network::Network,
    node::Node,
    peer::Peer,
    relocation::{
        self, RelocateAction, RelocateDetails, RelocatePromise, RelocateState,
        SignedRelocateDetails,
    },
    section::{
        EldersInfo, MemberInfo, PeerState, Section, SectionKeyShare, SectionKeysProvider,
        SectionProofChain, MIN_AGE,
    },
    RECOMMENDED_SECTION_SIZE,
};
use bls_dkg::key_gen::{message::Message as DkgMessage, outcome::Outcome as DkgOutcome};
use bytes::Bytes;
use itertools::Itertools;
use std::{cmp, net::SocketAddr, slice};
use tokio::sync::mpsc;
use xor_name::{Prefix, XorName};

// The approved stage - node is a full member of a section and is performing its duties according
// to its persona (infant, adult or elder).
pub(crate) struct Approved {
    node: Node,
    section: Section,
    network: Network,
    section_keys_provider: SectionKeysProvider,
    vote_accumulator: VoteAccumulator,
    update_barrier: UpdateBarrier,
    // Voter for DKG
    dkg_voter: DkgVoter,
    relocate_state: Option<RelocateState>,
    msg_filter: MessageFilter,
    pub(super) event_tx: mpsc::UnboundedSender<Event>,
}

impl Approved {
    // Creates the approved state for the first node in the network
    pub fn first_node(node: Node, event_tx: mpsc::UnboundedSender<Event>) -> Result<Self> {
        let (section, section_key_share) = Section::first_node(node.peer())?;
        Ok(Self::new(node, section, Some(section_key_share), event_tx))
    }

    // Creates the approved state for a regular node.
    pub fn new(
        node: Node,
        section: Section,
        section_key_share: Option<SectionKeyShare>,
        event_tx: mpsc::UnboundedSender<Event>,
    ) -> Self {
        let section_keys_provider = SectionKeysProvider::new(section_key_share);

        Self {
            node,
            section,
            network: Network::new(),
            section_keys_provider,
            vote_accumulator: Default::default(),
            update_barrier: Default::default(),
            dkg_voter: Default::default(),
            relocate_state: None,
            msg_filter: MessageFilter::new(),
            event_tx,
        }
    }

    pub fn node(&self) -> &Node {
        &self.node
    }

    pub fn section(&self) -> &Section {
        &self.section
    }

    pub fn network(&self) -> &Network {
        &self.network
    }

    pub fn send_event(&self, event: Event) {
        // Note: cloning the sender to avoid mutable access. Should have negligible cost.
        if self.event_tx.clone().send(event).is_err() {
            error!("Event receiver has been closed");
        }
    }

    pub async fn handle_message(
        &mut self,
        sender: Option<SocketAddr>,
        msg: Message,
    ) -> Result<Vec<Command>> {
        let mut commands = vec![];

        // Check if the message is for us.
        let in_dst_location = msg.dst().contains(&self.node.name(), self.section.prefix());
        if !in_dst_location || msg.dst().is_section() {
            // Relay closer to the destination or
            // broadcast to the rest of our section.
            commands.extend(self.relay_message(&msg)?);
        }
        if !in_dst_location {
            // Message not for us.
            return Ok(commands);
        }

        // Filter messages which were already handled
        if self.msg_filter.contains_incoming(&msg) {
            trace!("not handling message - already handled: {:?}", msg);
            return Ok(commands);
        }

        match self.decide_message_status(&msg)? {
            MessageStatus::Useful => {
                trace!("Useful message from {:?}: {:?}", sender, msg);
                commands.extend(self.update_section_knowledge(&msg)?);
                commands.extend(self.handle_useful_message(sender, msg).await?);
            }
            MessageStatus::Untrusted => {
                debug!("Untrusted message from {:?}: {:?} ", sender, msg);
                commands.push(self.handle_untrusted_message(sender, msg)?);
            }
            MessageStatus::Unknown => {
                debug!("Unknown message from {:?}: {:?} ", sender, msg);
                commands.push(self.handle_unknown_message(sender, msg.to_bytes())?);
            }
            MessageStatus::Useless => {
                debug!("Useless message from {:?}: {:?}", sender, msg);
            }
        }

        Ok(commands)
    }

    pub fn handle_timeout(&mut self, token: u64) -> Result<Vec<Command>> {
        self.dkg_voter
            .handle_timeout(&self.node.name(), token)
            .into_commands(&self.node)
    }

    // Insert the vote into the vote accumulator and handle it if accumulated.
    pub fn handle_vote(&mut self, vote: Vote, proof_share: ProofShare) -> Result<Vec<Command>> {
        match self.vote_accumulator.add(vote, proof_share) {
            Ok((vote, proof)) => Ok(vec![Command::HandleConsensus { vote, proof }]),
            Err(AccumulationError::NotEnoughShares) => Ok(vec![]),
            Err(error) => {
                error!("Failed to add vote: {}", error);
                Err(Error::InvalidSignatureShare)
            }
        }
    }

    pub fn handle_consensus(&mut self, vote: Vote, proof: Proof) -> Result<Vec<Command>> {
        debug!("handle consensus on {:?}", vote);

        match vote {
            Vote::Online {
                member_info,
                previous_name,
                their_knowledge,
            } => self.handle_online_event(member_info, previous_name, their_knowledge, proof),
            Vote::Offline(member_info) => self.handle_offline_event(member_info, proof),
            Vote::SectionInfo(elders_info) => self.handle_section_info_event(elders_info, proof),
            Vote::OurKey { prefix, key } => self.handle_our_key_event(prefix, key, proof),
            Vote::TheirKey { prefix, key } => self.handle_their_key_event(prefix, key, proof),
            Vote::TheirKnowledge { prefix, key_index } => {
                self.handle_their_knowledge_event(prefix, key_index, proof);
                Ok(vec![])
            }
            Vote::SendMessage {
                message,
                proof_chain,
            } => Ok(vec![self.handle_send_message_event(
                *message,
                proof_chain,
                proof,
            )?]),
        }
    }

    pub fn handle_connection_lost(&self, addr: &SocketAddr) -> Option<Command> {
        if !self.is_elder() {
            return None;
        }

        if let Some(peer) = self.section.find_joined_member_by_addr(addr) {
            trace!("Lost connection to {}", peer);
        } else {
            return None;
        }

        // Try to send a "ping" message to probe the peer connection. If it succeeds, the
        // connection loss was just temporary. Otherwise the peer is assumed lost and we will vote
        // it offline.
        Some(Command::send_message_to_target(
            addr,
            Bytes::from_static(PING),
        ))
    }

    pub fn handle_peer_lost(&self, addr: &SocketAddr) -> Result<Vec<Command>> {
        let name = if let Some(peer) = self.section.find_joined_member_by_addr(addr) {
            debug!("Lost known peer {}", peer);
            *peer.name()
        } else {
            trace!("Lost unknown peer {}", addr);
            return Ok(vec![]);
        };

        if !self.is_elder() {
            return Ok(vec![]);
        }

        if let Some(info) = self.section.members().get(&name) {
            let info = info.clone().leave()?;
            self.vote(Vote::Offline(info))
        } else {
            Ok(vec![])
        }
    }

    pub fn handle_dkg_participation_result(
        &mut self,
        dkg_key: DkgKey,
        elders_info: EldersInfo,
        result: Result<DkgOutcome, ()>,
    ) -> Result<Vec<Command>> {
        let key = if let Ok(outcome) = result {
            let key = outcome.public_key_set.public_key();
            self.section_keys_provider
                .insert_dkg_outcome(&self.node.name(), &elders_info, outcome);

            if self.section.chain().has_key(&key) {
                self.section_keys_provider.finalise_dkg(&key)
            }

            Ok(key)
        } else {
            Err(())
        };

        let mut commands = vec![];
        commands.push(self.send_dkg_result(dkg_key, key)?);
        commands.extend(self.handle_dkg_result(dkg_key, key, self.node.name())?);

        Ok(commands)
    }

    pub fn handle_dkg_observation_result(
        &mut self,
        dkg_elders_info: EldersInfo,
        result: Result<bls::PublicKey, ()>,
    ) -> Result<Vec<Command>> {
        trace!(
            "accumulated DKG result for {}: {:?}",
            dkg_elders_info,
            result
        );

        let mut commands = vec![];

        for new_elders_info in self.section.promote_and_demote_elders(&self.node.name()) {
            // Check whether the result still corresponds to the current elder candidates.
            if new_elders_info == dkg_elders_info {
                debug!("handle DKG result for {}: {:?}", new_elders_info, result);

                if let Ok(public_key) = result {
                    commands.extend(self.vote_for_section_update(public_key, new_elders_info)?);
                } else {
                    commands.extend(self.send_dkg_start(new_elders_info)?);
                }
            } else if new_elders_info.prefix == dkg_elders_info.prefix
                || new_elders_info
                    .prefix
                    .is_extension_of(&dkg_elders_info.prefix)
            {
                trace!(
                    "ignore DKG result for {}: {:?} - outdated",
                    dkg_elders_info,
                    result
                );
                commands.extend(self.send_dkg_start(new_elders_info)?);
            }
        }

        Ok(commands)
    }

    // Send vote to all our elders.
    fn vote(&self, vote: Vote) -> Result<Vec<Command>> {
        let elders: Vec<_> = self.section.elders_info().peers().copied().collect();
        self.send_vote(&elders, vote)
    }

    // Send `vote` to `recipients`.
    fn send_vote(&self, recipients: &[Peer], vote: Vote) -> Result<Vec<Command>> {
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
        let proof_chain = self.section.create_proof_chain_for_our_info(None);
        let message = Message::single_src(
            &self.node,
            DstLocation::Direct,
            variant,
            Some(proof_chain),
            Some(*self.section.chain().last_key()),
        )?;

        let mut others = Vec::new();
        let mut handle = false;

        for recipient in recipients {
            if recipient.name() == &self.node.name() {
                handle = true;
            } else {
                others.push(*recipient.addr());
            }
        }

        let mut commands = vec![];

        if !others.is_empty() {
            commands.push(Command::send_message_to_targets(
                &others,
                others.len(),
                message.to_bytes(),
            ));
        }

        if handle {
            commands.push(Command::HandleVote { vote, proof_share });
        }

        Ok(commands)
    }

    fn check_lagging(
        &self,
        peer: &SocketAddr,
        proof_share: &ProofShare,
    ) -> Result<Option<Command>> {
        let public_key = proof_share.public_key_set.public_key();

        if self.section.chain().has_key(&public_key)
            && public_key != *self.section.chain().last_key()
        {
            // The key is recognized as non-last, indicating the peer is lagging.
            Ok(Some(self.send_direct_message(
                peer,
                // TODO: consider sending only those parts of section that are new
                // since `public_key` was the latest key.
                Variant::Sync {
                    section: self.section.clone(),
                    network: self.network.clone(),
                },
            )?))
        } else {
            Ok(None)
        }
    }

    /// Is this node an elder?
    pub fn is_elder(&self) -> bool {
        self.section.is_elder(&self.node.name())
    }

    /// Returns the current BLS public key set
    pub fn section_key_share(&self) -> Option<&SectionKeyShare> {
        self.section_keys_provider.key_share().ok()
    }

    ////////////////////////////////////////////////////////////////////////////
    // Message handling
    ////////////////////////////////////////////////////////////////////////////

    fn decide_message_status(&self, msg: &Message) -> Result<MessageStatus> {
        match msg.variant() {
            Variant::NeighbourInfo { .. } => {
                if !self.is_elder() {
                    return Ok(MessageStatus::Unknown);
                }
            }
            Variant::UserMessage(_) => {
                if !self.should_handle_user_message(msg.dst()) {
                    return Ok(MessageStatus::Unknown);
                }
            }
            Variant::JoinRequest(req) => {
                if !self.should_handle_join_request(req) {
                    // Note: We don't bounce this message because the current bounce-resend
                    // mechanism wouldn't preserve the original SocketAddr which is needed for
                    // properly handling this message.
                    // This is OK because in the worst case the join request just timeouts and the
                    // joining node sends it again.
                    return Ok(MessageStatus::Useless);
                }
            }
            Variant::DKGStart { elders_info, .. } => {
                if !elders_info.elders.contains_key(&self.node.name()) {
                    return Ok(MessageStatus::Useless);
                }
            }
            Variant::DKGResult { .. } => {
                if !self.is_elder() {
                    return Ok(MessageStatus::Unknown);
                }
            }
            Variant::NodeApproval(_) | Variant::BootstrapResponse(_) => {
                // Skip validation of these. We will validate them inside the bootstrap task.
                return Ok(MessageStatus::Useful);
            }
            Variant::Vote { proof_share, .. } => {
                if !self.should_handle_vote(proof_share) {
                    // Message will be bounced if we are lagging (not known of the signing key).
                    return Ok(MessageStatus::Unknown);
                }
            }
            Variant::RelocatePromise(promise) => {
                if promise.name != self.node.name() {
                    if !self.is_elder() {
                        return Ok(MessageStatus::Useless);
                    }

                    if self.section.is_elder(&promise.name) {
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
            | Variant::DKGMessage { .. } => {}
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
    ) -> Result<Vec<Command>> {
        self.msg_filter.insert_incoming(&msg);
        match msg.variant() {
            Variant::NeighbourInfo { elders_info, .. } => {
                msg.dst().check_is_section()?;
                self.handle_neighbour_info(elders_info.value.clone(), *msg.proof_chain_last_key()?)
            }
            Variant::Sync { section, network } => {
                self.handle_sync(section.clone(), network.clone())
            }
            Variant::Relocate(_) => {
                msg.src().check_is_section()?;
                let signed_relocate = SignedRelocateDetails::new(msg)?;
                Ok(self.handle_relocate(signed_relocate).into_iter().collect())
            }
            Variant::RelocatePromise(promise) => {
                self.handle_relocate_promise(*promise, msg.to_bytes())
            }
            Variant::BootstrapRequest(name) => {
                let sender = sender.ok_or(Error::InvalidSource)?;
                Ok(vec![self.handle_bootstrap_request(
                    msg.src().to_node_peer(sender)?,
                    *name,
                )?])
            }

            Variant::JoinRequest(join_request) => {
                let sender = sender.ok_or(Error::InvalidSource)?;
                self.handle_join_request(msg.src().to_node_peer(sender)?, *join_request.clone())
            }
            Variant::UserMessage(content) => {
                self.handle_user_message(msg.src().src_location(), *msg.dst(), content.clone());
                Ok(vec![])
            }
            Variant::BouncedUntrustedMessage(message) => {
                let sender = sender.ok_or(Error::InvalidSource)?;
                Ok(self
                    .handle_bounced_untrusted_message(
                        msg.src().to_node_peer(sender)?,
                        *msg.dst_key(),
                        *message.clone(),
                    )
                    .into_iter()
                    .collect())
            }
            Variant::BouncedUnknownMessage { src_key, message } => {
                let sender = sender.ok_or(Error::InvalidSource)?;
                self.handle_bounced_unknown_message(
                    msg.src().to_node_peer(sender)?,
                    message.clone(),
                    src_key,
                )
            }
            Variant::DKGStart {
                dkg_key,
                elders_info,
            } => self.handle_dkg_start(*dkg_key, elders_info.clone()),
            Variant::DKGMessage { dkg_key, message } => {
                self.handle_dkg_message(*dkg_key, message.clone(), msg.src().to_node_name()?)
            }
            Variant::DKGResult { dkg_key, result } => Ok(self
                .handle_dkg_result(*dkg_key, *result, msg.src().to_node_name()?)?
                .into_iter()
                .collect()),
            Variant::Vote {
                content,
                proof_share,
            } => {
                let mut commands = vec![];
                let result = self.handle_vote(content.clone(), proof_share.clone());

                if let Some(addr) = sender {
                    commands.extend(self.check_lagging(&addr, proof_share)?);
                }

                commands.extend(result?);
                Ok(commands)
            }
            Variant::NodeApproval(_) | Variant::BootstrapResponse(_) => {
                if let Some(RelocateState::InProgress(message_tx)) = &mut self.relocate_state {
                    if let Some(sender) = sender {
                        trace!("Forwarding {:?} to the bootstrap task", msg);
                        let _ = message_tx.send((msg, sender)).await;
                    } else {
                        error!("Missig sender of {:?}", msg);
                    }
                }

                Ok(vec![])
            }
        }
    }

    // Ignore `JoinRequest` if we are not elder unless the join request is outdated in which case we
    // reply with `BootstrapResponse::Join` with the up-to-date info (see `handle_join_request`).
    fn should_handle_join_request(&self, req: &JoinRequest) -> bool {
        self.is_elder() || req.section_key != *self.section.chain().last_key()
    }

    // If elder, always handle UserMessage, otherwise handle it only if addressed directly to us
    // as a node.
    fn should_handle_user_message(&self, dst: &DstLocation) -> bool {
        self.is_elder() || dst.as_node().ok() == Some(&self.node.name())
    }

    // Handle `Vote` message only if signed with known key, otherwise bounce.
    fn should_handle_vote(&self, proof_share: &ProofShare) -> bool {
        self.section
            .chain()
            .has_key(&proof_share.public_key_set.public_key())
    }

    fn verify_message(&self, msg: &Message) -> Result<bool> {
        let known_keys = self
            .section
            .chain()
            .keys()
            .map(move |key| (self.section.prefix(), key))
            .chain(self.network.keys());

        match msg.verify(known_keys) {
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
    fn handle_untrusted_message(
        &self,
        sender: Option<SocketAddr>,
        msg: Message,
    ) -> Result<Command> {
        let src = msg.src().src_location();
        let src_name = match src {
            SrcLocation::Node(name) => name,
            SrcLocation::Section(prefix) => prefix.name(),
        };

        let bounce_dst_key = *self.section_key_by_name(&src_name);
        let bounce_dst = if src.is_section() {
            DstLocation::Section(src_name)
        } else {
            DstLocation::Node(src_name)
        };

        let bounce_msg = Message::single_src(
            &self.node,
            bounce_dst,
            Variant::BouncedUntrustedMessage(Box::new(msg)),
            None,
            Some(bounce_dst_key),
        )?;
        let bounce_msg = bounce_msg.to_bytes();

        if let Some(sender) = sender {
            Ok(Command::send_message_to_target(&sender, bounce_msg))
        } else {
            Ok(self.send_message_to_our_elders(bounce_msg))
        }
    }

    /// Handle message that is "unknown" because we are not in the correct state (e.g. we are adult
    /// and the message is for elders). We bounce the message to our elders who have more
    /// information to decide what to do with it.
    fn handle_unknown_message(
        &self,
        sender: Option<SocketAddr>,
        msg_bytes: Bytes,
    ) -> Result<Command> {
        let bounce_msg = Message::single_src(
            &self.node,
            DstLocation::Direct,
            Variant::BouncedUnknownMessage {
                src_key: *self.section.chain().last_key(),
                message: msg_bytes,
            },
            None,
            None,
        )?;
        let bounce_msg = bounce_msg.to_bytes();

        // If the message came from one of our elders then bounce it only to them to avoid message
        // explosion.
        let our_elder_sender = sender.filter(|sender| {
            self.section
                .elders_info()
                .peers()
                .any(|peer| peer.addr() == sender)
        });

        if let Some(sender) = our_elder_sender {
            Ok(Command::send_message_to_target(&sender, bounce_msg))
        } else {
            Ok(self.send_message_to_our_elders(bounce_msg))
        }
    }

    fn handle_bounced_untrusted_message(
        &self,
        sender: Peer,
        dst_key: Option<bls::PublicKey>,
        bounced_msg: Message,
    ) -> Option<Command> {
        trace!(
            "Received BouncedUntrustedMessage({:?}) from {:?}...",
            bounced_msg,
            sender
        );

        if let Some(dst_key) = dst_key {
            let resend_msg = match bounced_msg.extend_proof_chain(&dst_key, self.section.chain()) {
                Ok(msg) => msg,
                Err(err) => {
                    trace!("...extending proof failed, discarding: {:?}", err);
                    return None;
                }
            };

            trace!("    ...resending with extended proof");
            Some(Command::send_message_to_target(
                sender.addr(),
                resend_msg.to_bytes(),
            ))
        } else {
            trace!("    ...missing dst key, discarding");
            None
        }
    }

    fn handle_bounced_unknown_message(
        &self,
        sender: Peer,
        bounced_msg_bytes: Bytes,
        sender_last_key: &bls::PublicKey,
    ) -> Result<Vec<Command>> {
        if !self.section.chain().has_key(sender_last_key)
            || sender_last_key == self.section.chain().last_key()
        {
            trace!(
                "Received BouncedUnknownMessage({:?}) from {:?} \
                 - peer is up to date or ahead of us, discarding",
                MessageHash::from_bytes(&bounced_msg_bytes),
                sender
            );
            return Ok(vec![]);
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
        Ok(vec![
            self.send_direct_message(
                sender.addr(),
                Variant::Sync {
                    section: self.section.clone(),
                    network: self.network.clone(),
                },
            )?,
            Command::send_message_to_target(sender.addr(), bounced_msg_bytes),
        ])
    }

    fn handle_neighbour_info(
        &self,
        elders_info: EldersInfo,
        src_key: bls::PublicKey,
    ) -> Result<Vec<Command>> {
        let mut commands = vec![];

        if !self.network.has_key(&src_key) {
            commands.extend(self.vote(Vote::TheirKey {
                prefix: elders_info.prefix,
                key: src_key,
            })?);
        } else {
            trace!(
                "Ignore not new section key of {:?}: {:?}",
                elders_info,
                src_key
            );
            return Ok(commands);
        }

        if elders_info.prefix.is_neighbour(self.section.prefix()) {
            commands.extend(self.vote(Vote::SectionInfo(elders_info))?);
        }

        Ok(commands)
    }

    fn handle_user_message(&self, src: SrcLocation, dst: DstLocation, content: Bytes) {
        self.send_event(Event::MessageReceived { content, src, dst })
    }

    fn handle_sync(&mut self, section: Section, network: Network) -> Result<Vec<Command>> {
        if !section.prefix().matches(&self.node.name()) {
            trace!("ignore Sync - not our section");
            return Ok(vec![]);
        }

        self.update_state(section, network)
    }

    fn handle_relocate(&mut self, details: SignedRelocateDetails) -> Option<Command> {
        if details.relocate_details().pub_id != self.node.name() {
            // This `Relocate` message is not for us - it's most likely a duplicate of a previous
            // message that we already handled.
            return None;
        }

        debug!(
            "Received Relocate message to join the section at {}.",
            details.relocate_details().destination
        );

        if self.relocate_state.is_none() {
            self.send_event(Event::RelocationStarted {
                previous_name: self.node.name(),
            });
        }

        let (message_tx, message_rx) = mpsc::channel(1);
        self.relocate_state = Some(RelocateState::InProgress(message_tx));

        let bootstrap_addrs: Vec<_> = self
            .section
            .elders_info()
            .peers()
            .map(Peer::addr)
            .copied()
            .collect();

        Some(Command::Relocate {
            bootstrap_addrs,
            details,
            message_rx,
        })
    }

    fn handle_relocate_promise(
        &mut self,
        promise: RelocatePromise,
        msg_bytes: Bytes,
    ) -> Result<Vec<Command>> {
        let mut commands = vec![];

        if promise.name == self.node.name() {
            // Store the `RelocatePromise` message and send it back after we are demoted.
            // Keep it around even if we are not elder anymore, in case we need to resend it.
            match self.relocate_state {
                None => {
                    self.relocate_state = Some(RelocateState::Delayed(msg_bytes.clone()));
                    self.send_event(Event::RelocationStarted {
                        previous_name: self.node.name(),
                    });
                }
                Some(RelocateState::InProgress(_)) => {
                    trace!("ignore RelocatePromise - relocation already in progress");
                }
                Some(RelocateState::Delayed(_)) => {
                    trace!("ignore RelocatePromise - already have one");
                }
            }

            // We are no longer elder. Send the promise back already.
            if !self.is_elder() {
                commands.push(self.send_message_to_our_elders(msg_bytes));
            }

            return Ok(commands);
        }

        if self.section.is_elder(&promise.name) {
            error!(
                "ignore returned RelocatePromise from {} - node is still elder",
                promise.name
            );
            return Ok(commands);
        }

        if let Some(info) = self.section.members().get(&promise.name) {
            let details = RelocateDetails::new(
                &self.section,
                &self.network,
                &info.peer,
                promise.destination,
            );
            commands.extend(self.send_relocate(&info.peer, details)?);
        } else {
            error!(
                "ignore returned RelocatePromise from {} - unknown node",
                promise.name
            );
        }

        Ok(commands)
    }

    // Note: As an adult, we should only give info about our section elders and they would
    // further guide the joining node. However this lead to a loop if the Adult is the new Elder so
    // we use the same code as for Elder and return Join in some cases.
    fn handle_bootstrap_request(&self, peer: Peer, destination: XorName) -> Result<Command> {
        debug!(
            "Received BootstrapRequest to section at {} from {:?}.",
            destination, peer
        );

        let response = if self.section.prefix().matches(&destination) {
            BootstrapResponse::Join {
                elders_info: self.section.elders_info().clone(),
                section_key: *self.section.chain().last_key(),
            }
        } else if let Some(section) = self.network.closest(&destination) {
            let conn_infos = section.peers().map(Peer::addr).copied().collect();
            BootstrapResponse::Rebootstrap(conn_infos)
        } else {
            return Err(Error::InvalidDestination);
        };

        debug!("Sending BootstrapResponse {:?} to {}", response, peer);
        self.send_direct_message(peer.addr(), Variant::BootstrapResponse(response))
    }

    fn handle_join_request(&self, peer: Peer, join_request: JoinRequest) -> Result<Vec<Command>> {
        debug!("Received {:?} from {}", join_request, peer);

        if join_request.section_key != *self.section.chain().last_key() {
            let response = BootstrapResponse::Join {
                elders_info: self.section.elders_info().clone(),
                section_key: *self.section.chain().last_key(),
            };
            trace!("Resending BootstrapResponse {:?} to {}", response, peer,);
            return Ok(vec![self.send_direct_message(
                peer.addr(),
                Variant::BootstrapResponse(response),
            )?]);
        }

        let pub_id = *peer.name();
        if !self.section.prefix().matches(&pub_id) {
            debug!(
                "Ignoring JoinRequest from {} - name doesn't match our prefix {:?}.",
                pub_id,
                self.section.prefix()
            );
            return Ok(vec![]);
        }

        if self.section.members().is_joined(&pub_id) {
            debug!(
                "Ignoring JoinRequest from {} - already member of our section.",
                pub_id
            );
            return Ok(vec![]);
        }

        // This joining node is being relocated to us.
        let (age, previous_name, their_knowledge) =
            if let Some(payload) = join_request.relocate_payload {
                if !payload.verify_identity(&pub_id) {
                    debug!(
                        "Ignoring relocation JoinRequest from {} - invalid signature.",
                        pub_id
                    );
                    return Ok(vec![]);
                }

                // FIXME: this might panic if the payload is malformed.
                let details = payload.relocate_details();

                if !self.section.prefix().matches(&details.destination) {
                    debug!(
                        "Ignoring relocation JoinRequest from {} - destination {} doesn't match \
                         our prefix {:?}.",
                        pub_id,
                        details.destination,
                        self.section.prefix()
                    );
                    return Ok(vec![]);
                }

                if !self
                    .verify_message(payload.details.signed_msg())
                    .unwrap_or(false)
                {
                    debug!(
                        "Ignoring relocation JoinRequest from {} - untrusted.",
                        pub_id
                    );
                    return Ok(vec![]);
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
    }

    fn handle_dkg_start(
        &mut self,
        dkg_key: DkgKey,
        new_elders_info: EldersInfo,
    ) -> Result<Vec<Command>> {
        trace!("Received DKGStart for {}", new_elders_info);
        self.dkg_voter
            .start_participating(self.node.name(), dkg_key, new_elders_info)
            .into_commands(&self.node)
    }

    fn handle_dkg_result(
        &mut self,
        dkg_key: DkgKey,
        result: Result<bls::PublicKey, ()>,
        sender: XorName,
    ) -> Result<Vec<Command>> {
        self.dkg_voter
            .observe_result(&dkg_key, result, sender)
            .into_commands(&self.node)
    }

    fn handle_dkg_message(
        &mut self,
        dkg_key: DkgKey,
        message: DkgMessage,
        sender: XorName,
    ) -> Result<Vec<Command>> {
        trace!("handle DKG message {:?} from {}", message, sender);

        self.dkg_voter
            .process_message(&self.node.name(), dkg_key, message)
            .into_commands(&self.node)
    }

    // Generate a new section info based on the current set of members and vote for it if it
    // changed.
    fn promote_and_demote_elders(&mut self) -> Result<Vec<Command>> {
        let mut commands = vec![];

        for info in self.section.promote_and_demote_elders(&self.node.name()) {
            commands.extend(self.send_dkg_start(info)?);
        }

        Ok(commands)
    }

    fn relocate_peers(
        &self,
        churn_name: &XorName,
        churn_signature: &bls::Signature,
    ) -> Result<Vec<Command>> {
        let mut commands = vec![];

        // As a measure against sybil attacks, don't relocate on infant churn.
        if !self.section.is_adult_or_elder(churn_name) {
            trace!("Skip relocation on infant churn");
            return Ok(commands);
        }

        let relocations =
            relocation::actions(&self.section, &self.network, churn_name, churn_signature);

        for (info, action) in relocations {
            debug!(
                "Relocating {:?} to {} (on churn of {})",
                info.peer,
                action.destination(),
                churn_name
            );

            let peer = info.peer;

            commands.extend(self.vote(Vote::Offline(info.relocate(*action.destination())))?);

            match action {
                RelocateAction::Instant(details) => {
                    commands.extend(self.send_relocate(&peer, details)?)
                }
                RelocateAction::Delayed(promise) => {
                    commands.extend(self.send_relocate_promise(&peer, promise)?)
                }
            }
        }

        Ok(commands)
    }

    fn relocate_peer_in_startup_phase(
        &self,
        peer: Peer,
        signature: &bls::Signature,
    ) -> Result<Vec<Command>> {
        let age = relocation::startup_phase_age(signature);
        let details =
            RelocateDetails::with_age(&self.section, &self.network, &peer, *peer.name(), age);

        trace!(
            "Relocating {:?} to {} with age {} in startup phase",
            peer,
            details.destination,
            details.age
        );

        self.send_relocate(&peer, details)
    }

    fn relocate_rejoining_peer(&self, peer: Peer, age: u8) -> Result<Vec<Command>> {
        let details =
            RelocateDetails::with_age(&self.section, &self.network, &peer, *peer.name(), age);

        trace!(
            "Relocating {:?} to {} with age {} due to rejoin",
            peer,
            details.destination,
            details.age
        );

        self.send_relocate(&peer, details)
    }

    // Are we in the startup phase? Startup phase is when the network consists of only one section
    // and it has no more than `recommended_section_size` members.
    fn is_in_startup_phase(&self) -> bool {
        self.section.prefix().is_empty()
            && self.section.members().joined().count() <= RECOMMENDED_SECTION_SIZE
    }

    fn handle_online_event(
        &mut self,
        member_info: MemberInfo,
        previous_name: Option<XorName>,
        their_knowledge: Option<bls::PublicKey>,
        proof: Proof,
    ) -> Result<Vec<Command>> {
        let peer = member_info.peer;
        let signature = proof.signature.clone();

        let mut commands = vec![];

        let is_startup_phase = self.is_in_startup_phase();

        if let Some(info) = self.section.members().get(peer.name()) {
            // This node is rejoin with same name.

            if info.state != PeerState::Left {
                debug!(
                    "Ignoring Online node {} - {:?} not Left.",
                    peer.name(),
                    info.state,
                );
                return Ok(commands);
            }
            // To avoid during startup_phase, a rejoin node being given a randmly higher age,
            // force it to be halved.
            if is_startup_phase || info.peer.age() / 2 > MIN_AGE {
                // TODO: consider handling the relocation inside the bootstrap phase, to avoid having
                // to send this `NodeApproval`.
                commands.push(self.send_node_approval(&peer, their_knowledge)?);
                commands.extend(
                    self.relocate_rejoining_peer(peer, cmp::max(MIN_AGE, info.peer.age() / 2))?,
                );
                return Ok(commands);
            }
        }

        if is_startup_phase && peer.age() <= MIN_AGE {
            // In startup phase, instantly relocate the joining peer in order to promote it to
            // adult.

            if self.section.members().is_known(peer.name()) {
                info!("ignore Online: {:?}", peer);
                return Ok(vec![]);
            }

            // TODO: consider handling the relocation inside the bootstrap phase, to avoid having
            // to send this `NodeApproval`.
            commands.push(self.send_node_approval(&peer, their_knowledge)?);
            commands.extend(self.relocate_peer_in_startup_phase(peer, &signature)?);
        } else {
            // Post startup phase, add the new peer normally.

            if !self.section.update_member(Proven {
                value: member_info,
                proof,
            }) {
                info!("ignore Online: {:?}", peer);
                return Ok(vec![]);
            }

            info!("handle Online: {:?}", peer);

            commands.push(self.send_node_approval(&peer, their_knowledge)?);
            commands.extend(self.relocate_peers(peer.name(), &signature)?);
            commands.extend(self.promote_and_demote_elders()?);

            self.send_event(Event::MemberJoined {
                name: *peer.name(),
                previous_name,
                age: peer.age(),
                startup_relocation: is_startup_phase,
            });

            self.print_network_stats();
        }

        Ok(commands)
    }

    fn handle_offline_event(
        &mut self,
        member_info: MemberInfo,
        proof: Proof,
    ) -> Result<Vec<Command>> {
        let mut commands = vec![];

        let peer = member_info.peer;
        let age = peer.age();
        let signature = proof.signature.clone();

        if !self.section.update_member(Proven {
            value: member_info,
            proof,
        }) {
            info!("ignore Offline: {:?}", peer);
            return Ok(commands);
        }

        info!("handle Offline: {:?}", peer);

        commands.extend(self.relocate_peers(peer.name(), &signature)?);
        commands.extend(self.promote_and_demote_elders()?);

        self.send_event(Event::MemberLeft {
            name: *peer.name(),
            age,
        });

        Ok(commands)
    }

    fn handle_section_info_event(
        &mut self,
        elders_info: EldersInfo,
        proof: Proof,
    ) -> Result<Vec<Command>> {
        let elders_info = Proven::new(elders_info, proof);

        if elders_info.value.prefix == *self.section.prefix()
            || elders_info
                .value
                .prefix
                .is_extension_of(self.section.prefix())
        {
            self.update_barrier.handle_section_info(
                &self.node.name(),
                &self.section,
                &self.network,
                elders_info,
            );
            self.try_update_state()
        } else {
            // Other section
            if self.network.update_neighbour_info(elders_info) {
                self.network.prune_neighbours(self.section.prefix());
            }
            Ok(vec![])
        }
    }

    fn handle_our_key_event(
        &mut self,
        prefix: Prefix,
        key: bls::PublicKey,
        proof: Proof,
    ) -> Result<Vec<Command>> {
        let key = Proven::new(key, proof);

        self.update_barrier.handle_our_key(
            &self.node.name(),
            &self.section,
            &self.network,
            &prefix,
            key,
        );
        self.try_update_state()
    }

    fn handle_their_key_event(
        &mut self,
        prefix: Prefix,
        key: bls::PublicKey,
        proof: Proof,
    ) -> Result<Vec<Command>> {
        let key = Proven::new((prefix, key), proof);

        if key.value.0.is_extension_of(self.section.prefix()) {
            self.update_barrier.handle_their_key(
                &self.node.name(),
                &self.section,
                &self.network,
                key,
            );
            self.try_update_state()
        } else if key.value.0 != *self.section.prefix() {
            let _ = self.network.update_their_key(key);
            Ok(vec![])
        } else {
            // Ignore our key. Should be updated using `OurKey` instead.
            Err(Error::InvalidVote)
        }
    }

    fn handle_their_knowledge_event(&mut self, prefix: Prefix, knowledge: u64, proof: Proof) {
        let knowledge = Proven::new((prefix, knowledge), proof);
        self.network.update_knowledge(knowledge)
    }

    fn handle_send_message_event(
        &self,
        message: PlainMessage,
        proof_chain: SectionProofChain,
        proof: Proof,
    ) -> Result<Command> {
        let message = Message::section_src(message, proof.signature, proof_chain)?;

        Ok(Command::HandleMessage {
            message,
            sender: None,
        })
    }

    fn vote_for_section_update(
        &mut self,
        public_key: bls::PublicKey,
        elders_info: EldersInfo,
    ) -> Result<Vec<Command>> {
        let mut commands = vec![];

        if self.section.chain().has_key(&public_key) {
            // Our section state is already up to date, so no need to vote.
            return Ok(commands);
        }

        if !self.update_barrier.start_update(elders_info.prefix) {
            trace!(
                "section update of {:?} already in progress",
                elders_info.prefix
            );
            return Ok(commands);
        }

        // Casting unordered_votes will check consensus and handle accumulated immediately.
        commands.extend(self.vote(Vote::OurKey {
            prefix: elders_info.prefix,
            key: public_key,
        })?);

        if elders_info.prefix.is_extension_of(self.section.prefix()) {
            commands.extend(self.vote(Vote::TheirKey {
                prefix: elders_info.prefix,
                key: public_key,
            })?);
        }

        commands.extend(self.vote(Vote::SectionInfo(elders_info))?);

        Ok(commands)
    }

    fn try_update_state(&mut self) -> Result<Vec<Command>> {
        let mut commands = vec![];

        let (our, sibling) = self.update_barrier.take(self.section.prefix());

        if let Some(our) = our {
            trace!("update our section: {:?}", our.section.elders_info());
            commands.extend(self.update_state(our.section, our.network)?);
        }

        if let Some(sibling) = sibling {
            trace!(
                "update sibling section: {:?}",
                sibling.section.elders_info()
            );

            // We can update the sibling knowledge already because we know they also reached consensus
            // on our `OurKey` so they know our latest key. Need to vote for it first though, to
            // accumulate the signatures.
            commands.extend(self.vote(Vote::TheirKnowledge {
                prefix: *sibling.section.prefix(),
                key_index: self.section.chain().last_key_index(),
            })?);
            commands.extend(self.send_sync(sibling.section, sibling.network)?);
        }

        Ok(commands)
    }

    fn update_state(&mut self, section: Section, network: Network) -> Result<Vec<Command>> {
        let mut commands = vec![];

        let old_is_elder = self.is_elder();
        let old_last_key_index = self.section.chain().last_key_index();
        let old_prefix = *self.section.prefix();

        self.section.merge(section)?;
        self.network.merge(network, self.section.chain());

        self.section_keys_provider
            .finalise_dkg(self.section.chain().last_key());
        self.dkg_voter
            .stop_observing(self.section.chain().last_key_index());

        let new_is_elder = self.is_elder();
        let new_last_key_index = self.section.chain().last_key_index();
        let new_prefix = *self.section.prefix();

        if new_prefix != old_prefix {
            info!("Split");

            if new_is_elder {
                // We can update the sibling knowledge already because we know they also reached
                // consensus on our `OurKey` so they know our latest key. Need to vote for it first
                // though, to accumulate the signatures.
                commands.extend(self.vote(Vote::TheirKnowledge {
                    prefix: new_prefix.sibling(),
                    key_index: new_last_key_index,
                })?);
            }
        }

        if new_last_key_index != old_last_key_index {
            self.msg_filter.reset();

            if new_is_elder {
                info!(
                    "Section updated: prefix: ({:b}), key: {:?}, elders: {}",
                    self.section.prefix(),
                    self.section.chain().last_key(),
                    self.section.elders_info().peers().format(", ")
                );

                commands.extend(self.promote_and_demote_elders()?);
                self.print_network_stats();
            }

            if new_is_elder || old_is_elder {
                commands.extend(self.send_sync(self.section.clone(), self.network.clone())?);
            }

            self.send_event(Event::EldersChanged {
                prefix: *self.section.prefix(),
                key: *self.section.chain().last_key(),
                elders: self.section.elders_info().elders.keys().copied().collect(),
            });
        }

        if !old_is_elder && new_is_elder {
            info!("Promoted to elder");
            self.send_event(Event::PromotedToElder);
        }

        if old_is_elder && !new_is_elder {
            info!("Demoted");
            self.section = self.section.to_minimal();
            self.network = Network::new();
            self.section_keys_provider = SectionKeysProvider::new(None);
            self.send_event(Event::Demoted);
        }

        if !new_is_elder {
            commands.extend(self.return_relocate_promise());
        }

        Ok(commands)
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
    fn send_node_approval(
        &self,
        peer: &Peer,
        their_knowledge: Option<bls::PublicKey>,
    ) -> Result<Command> {
        info!(
            "Our section with {:?} has approved candidate {:?}.",
            self.section.prefix(),
            peer
        );

        let their_knowledge = their_knowledge.and_then(|key| self.section.chain().index_of(&key));
        let proof_chain = self
            .section
            .create_proof_chain_for_our_info(their_knowledge);

        let variant = Variant::NodeApproval(self.section.proven_elders_info().clone());

        trace!("Send {:?} to {:?}", variant, peer);
        let message = Message::single_src(
            &self.node,
            DstLocation::Direct,
            variant,
            Some(proof_chain),
            None,
        )?;

        Ok(Command::send_message_to_target(
            peer.addr(),
            message.to_bytes(),
        ))
    }

    fn send_sync(&mut self, section: Section, network: Network) -> Result<Vec<Command>> {
        let mut commands = vec![];

        for peer in section.active_members() {
            if peer.name() == &self.node.name() {
                continue;
            }

            let variant = if section.is_elder(peer.name()) {
                Variant::Sync {
                    section: section.clone(),
                    network: network.clone(),
                }
            } else {
                Variant::Sync {
                    section: section.to_minimal(),
                    network: Network::new(),
                }
            };

            trace!("Send {:?} to {:?}", variant, peer);
            let message =
                Message::single_src(&self.node, DstLocation::Direct, variant, None, None)?;
            commands.push(Command::send_message_to_target(
                peer.addr(),
                message.to_bytes(),
            ))
        }

        Ok(commands)
    }

    fn send_relocate(&self, recipient: &Peer, details: RelocateDetails) -> Result<Vec<Command>> {
        // We need to construct a proof that would be trusted by the destination section.
        let knowledge_index = self
            .network
            .knowledge_by_location(&DstLocation::Section(details.destination));

        let dst = DstLocation::Node(details.pub_id);
        let variant = Variant::Relocate(details);

        trace!("Send {:?} -> {:?}", variant, dst);

        // Vote accumulated at destination.
        let vote = self.create_send_message_vote(dst, variant, Some(knowledge_index))?;
        self.send_vote(slice::from_ref(recipient), vote)
    }

    fn send_relocate_promise(
        &self,
        recipient: &Peer,
        promise: RelocatePromise,
    ) -> Result<Vec<Command>> {
        // Note: this message is first sent to a single node who then sends it back to the section
        // where it needs to be handled by all the elders. This is why the destination is
        // `Section`, not `Node`.
        let dst = DstLocation::Section(promise.name);
        let variant = Variant::RelocatePromise(promise);

        // Vote accumulated at destination
        let vote = self.create_send_message_vote(dst, variant, None)?;
        self.send_vote(slice::from_ref(recipient), vote)
    }

    fn return_relocate_promise(&self) -> Option<Command> {
        // TODO: keep sending this periodically until we get relocated.
        if let Some(RelocateState::Delayed(bytes)) = &self.relocate_state {
            Some(self.send_message_to_our_elders(bytes.clone()))
        } else {
            None
        }
    }

    fn send_neighbour_info(
        &mut self,
        dst: Prefix,
        nonce: MessageHash,
        dst_key: Option<bls::PublicKey>,
    ) -> Result<Option<Command>> {
        let proof_chain = self
            .section
            .create_proof_chain_for_our_info(Some(self.network.knowledge_by_section(&dst)));
        let variant = Variant::NeighbourInfo {
            elders_info: self.section.proven_elders_info().clone(),
            nonce,
        };
        trace!("sending NeighbourInfo {:?}", variant);
        let msg = Message::single_src(
            &self.node,
            DstLocation::Section(dst.name()),
            variant,
            Some(proof_chain),
            dst_key,
        )?;

        self.relay_message(&msg)
    }

    fn send_dkg_start(&mut self, new_elders_info: EldersInfo) -> Result<Vec<Command>> {
        trace!("Send DKGStart for {}", new_elders_info);

        let dkg_key = DkgKey::new(&new_elders_info);

        // Send to all participants.
        let recipients: Vec<_> = new_elders_info.elders.values().copied().collect();
        let variant = Variant::DKGStart {
            dkg_key,
            elders_info: new_elders_info.clone(),
        };
        let vote = self.create_send_message_vote(DstLocation::Direct, variant, None)?;
        let commands = self.send_vote(&recipients, vote)?;

        self.dkg_voter.start_observing(
            dkg_key,
            new_elders_info,
            self.section.chain().last_key_index(),
        );

        Ok(commands)
    }

    fn send_dkg_result(
        &self,
        dkg_key: DkgKey,
        result: Result<bls::PublicKey, ()>,
    ) -> Result<Command> {
        let variant = Variant::DKGResult { dkg_key, result };

        let recipients = self
            .section
            .elders_info()
            .peers()
            .filter(|peer| peer.name() != &self.node.name());

        trace!(
            "Send {:?} to {:?}",
            variant,
            recipients.clone().format(", ")
        );

        let recipients: Vec<_> = recipients.map(Peer::addr).copied().collect();
        let message = Message::single_src(&self.node, DstLocation::Direct, variant, None, None)?;

        Ok(Command::send_message_to_targets(
            &recipients,
            recipients.len(),
            message.to_bytes(),
        ))
    }

    // Send message over the network.
    pub fn relay_message(&mut self, msg: &Message) -> Result<Option<Command>> {
        let (targets, dg_size) = delivery_group::delivery_targets(
            msg.dst(),
            &self.node.name(),
            &self.section,
            &self.network,
        )?;

        let targets: Vec<_> = targets
            .into_iter()
            .filter(|peer| self.msg_filter.filter_outgoing(msg, peer.name()).is_new())
            .collect();

        if targets.is_empty() {
            return Ok(None);
        }

        trace!("relay {:?} to {:?}", msg, targets);

        let targets: Vec<_> = targets.into_iter().map(|node| *node.addr()).collect();
        let command = Command::send_message_to_targets(&targets, dg_size, msg.to_bytes());

        Ok(Some(command))
    }

    pub fn send_user_message(
        &mut self,
        src: SrcLocation,
        dst: DstLocation,
        content: Bytes,
    ) -> Result<Vec<Command>> {
        if !src.contains(&self.node.name()) {
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
                let msg = Message::single_src(&self.node, dst, variant, None, None)?;
                Ok(self.relay_message(&msg)?.into_iter().collect())
            }
            SrcLocation::Section(_) => {
                let vote = self.create_send_message_vote(dst, variant, None)?;
                let recipients = delivery_group::signature_targets(
                    &dst,
                    self.section.elders_info().peers().copied(),
                );
                self.send_vote(&recipients, vote)
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
        let dst_key = if let Some(name) = dst.name() {
            *self.section_key_by_name(name)
        } else {
            // NOTE: `dst` is `Direct`. We use this when we want the message to accumulate at the
            // destination and also be handled only there. We only do this if the recipient is in
            // our section, so it's OK to use our latest key as the `dst_key`.
            *self.section.chain().last_key()
        };

        let message = PlainMessage {
            src: *self.section.prefix(),
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
        let first_index = first_index.unwrap_or_else(|| self.network.knowledge_by_location(dst));

        let last_key = self
            .section_keys_provider
            .key_share()?
            .public_key_set
            .public_key();
        let last_index = self
            .section
            .chain()
            .index_of(&last_key)
            .unwrap_or_else(|| self.section.chain().last_key_index());

        Ok(self.section.chain().slice(first_index..=last_index))
    }

    fn send_direct_message(&self, recipient: &SocketAddr, variant: Variant) -> Result<Command> {
        let message = Message::single_src(&self.node, DstLocation::Direct, variant, None, None)?;
        Ok(Command::send_message_to_target(
            recipient,
            message.to_bytes(),
        ))
    }

    // TODO: consider changing this so it sends only to a subset of the elders
    // (say 1/3 of the ones closest to our name or so)
    fn send_message_to_our_elders(&self, msg_bytes: Bytes) -> Command {
        let targets: Vec<_> = self
            .section
            .elders_info()
            .peers()
            .map(Peer::addr)
            .copied()
            .collect();
        Command::send_message_to_targets(&targets, targets.len(), msg_bytes)
    }

    ////////////////////////////////////////////////////////////////////////////
    // Miscellaneous
    ////////////////////////////////////////////////////////////////////////////

    // Update our knowledge of their (sender's) section and their knowledge of our section.
    fn update_section_knowledge(&mut self, msg: &Message) -> Result<Vec<Command>> {
        if !self.is_elder() {
            return Ok(vec![]);
        }

        let src_prefix = if let Ok(prefix) = msg.src().as_section_prefix() {
            prefix
        } else {
            return Ok(vec![]);
        };

        let src_key = if let Ok(key) = msg.proof_chain_last_key() {
            key
        } else {
            return Ok(vec![]);
        };

        let is_neighbour = self.section.prefix().is_neighbour(src_prefix);

        let mut commands = Vec::new();
        let mut vote_send_neighbour_info = false;

        if !src_prefix.matches(&self.node.name()) && !self.network.has_key(src_key) {
            // Only vote `TheirKeyInfo` for non-neighbours. For neighbours, we update the keys
            // via `NeighbourInfo`.
            if is_neighbour {
                vote_send_neighbour_info = true;
            } else {
                commands.extend(self.vote(Vote::TheirKey {
                    prefix: *src_prefix,
                    key: *src_key,
                })?);
            }
        }

        if let Some(dst_key) = msg.dst_key() {
            let old = self.network.knowledge_by_section(src_prefix);
            let new = self.section.chain().index_of(dst_key).unwrap_or(0);

            if new > old {
                commands.extend(self.vote(Vote::TheirKnowledge {
                    prefix: *src_prefix,
                    key_index: new,
                })?);
            }

            if is_neighbour && new < self.section.chain().last_key_index() {
                vote_send_neighbour_info = true;
            }
        }

        if vote_send_neighbour_info {
            // TODO: if src has split, consider sending to all child prefixes that are still our
            // neighbours.
            let dst_key = self.network.key_by_name(&src_prefix.name()).cloned();

            commands.extend(self.send_neighbour_info(*src_prefix, *msg.hash(), dst_key)?)
        }

        Ok(commands)
    }

    fn section_key_by_name(&self, name: &XorName) -> &bls::PublicKey {
        if self.section.prefix().matches(name) {
            self.section.chain().last_key()
        } else {
            self.network
                .key_by_name(name)
                .unwrap_or_else(|| self.section.chain().first_key())
        }
    }

    fn print_network_stats(&self) {
        self.network
            .network_stats(self.section.elders_info())
            .print()
    }
}
