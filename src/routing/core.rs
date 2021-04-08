// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    enduser_registry::{EndUserRegistry, SocketId},
    lazy_messaging,
    split_barrier::SplitBarrier,
    Command,
};
use crate::{
    agreement::{
        DkgCommands, DkgFailureProof, DkgFailureProofSet, DkgKey, DkgVoter, Proof, ProofShare,
        Proposal, ProposalAggregationError, ProposalAggregator, Proven,
    },
    crypto, delivery_group,
    error::{Error, Result},
    event::{Event, NodeElderChange},
    message_filter::MessageFilter,
    messages::{
        JoinRequest, Message, MessageHash, MessageStatus, PlainMessage, ResourceProofResponse,
        SrcAuthority, Variant, VerifyStatus,
    },
    network::Network,
    node::Node,
    peer::Peer,
    relocation::{
        self, RelocateAction, RelocateDetails, RelocatePromise, RelocateState,
        SignedRelocateDetails,
    },
    section::{
        EldersInfo, MemberInfo, PeerState, Section, SectionChain, SectionKeyShare,
        SectionKeysProvider, FIRST_SECTION_MAX_AGE, FIRST_SECTION_MIN_AGE, MIN_ADULT_AGE, MIN_AGE,
    },
    ELDER_SIZE,
};
use bls_dkg::key_gen::message::Message as DkgMessage;
use bls_signature_aggregator::{Error as AggregatorError, SignatureAggregator};
use bytes::Bytes;
use ed25519_dalek::Verifier;
use itertools::Itertools;
use resource_proof::ResourceProof;
use sn_data_types::PublicKey as EndUserPK;
use sn_messaging::{
    client::Message as ClientMessage,
    node::NodeMessage,
    section_info::{
        Error as TargetSectionError, GetSectionResponse, Message as SectionInfoMsg, SectionInfo,
    },
    DstLocation, EndUser, Itinerary, MessageType, SrcLocation,
};
use std::{
    cmp::{self, Ordering},
    iter,
    net::SocketAddr,
    slice,
};
use tokio::sync::mpsc;
use xor_name::{Prefix, XorName};

pub(crate) const RESOURCE_PROOF_DATA_SIZE: usize = 64;
pub(crate) const RESOURCE_PROOF_DIFFICULTY: u8 = 2;
const KEY_CACHE_SIZE: u8 = 5;

// State + logic of a routing node.
pub(crate) struct Core {
    node: Node,
    section: Section,
    network: Network,
    section_keys_provider: SectionKeysProvider,
    message_aggregator: SignatureAggregator,
    proposal_aggregator: ProposalAggregator,
    split_barrier: SplitBarrier,
    // Voter for Dkg
    dkg_voter: DkgVoter,
    relocate_state: Option<RelocateState>,
    msg_filter: MessageFilter,
    pub(super) event_tx: mpsc::UnboundedSender<Event>,
    joins_allowed: bool,
    resource_proof: ResourceProof,
    end_users: EndUserRegistry,
}

impl Core {
    // Creates `Core` for the first node in the network
    pub fn first_node(node: Node, event_tx: mpsc::UnboundedSender<Event>) -> Result<Self> {
        let (section, section_key_share) = Section::first_node(node.peer())?;
        Ok(Self::new(node, section, Some(section_key_share), event_tx))
    }

    // Creates `Core` for a regular node.
    pub fn new(
        node: Node,
        section: Section,
        section_key_share: Option<SectionKeyShare>,
        event_tx: mpsc::UnboundedSender<Event>,
    ) -> Self {
        let section_keys_provider = SectionKeysProvider::new(KEY_CACHE_SIZE, section_key_share);

        Self {
            node,
            section,
            network: Network::new(),
            section_keys_provider,
            proposal_aggregator: Default::default(),
            split_barrier: SplitBarrier::new(),
            message_aggregator: Default::default(),
            dkg_voter: Default::default(),
            relocate_state: None,
            msg_filter: MessageFilter::new(),
            event_tx,
            joins_allowed: true,
            resource_proof: ResourceProof::new(RESOURCE_PROOF_DATA_SIZE, RESOURCE_PROOF_DIFFICULTY),
            end_users: EndUserRegistry::new(),
        }
    }

    pub fn get_enduser_by_addr(&self, sender: &SocketAddr) -> Option<&EndUser> {
        self.end_users.get_enduser_by_addr(sender)
    }

    pub fn get_socket_addr(&self, id: SocketId) -> Option<&SocketAddr> {
        self.end_users.get_socket_addr(id)
    }

    pub fn get_all_socket_addr<'a>(
        &'a self,
        end_user: &'a EndUserPK,
    ) -> impl Iterator<Item = &'a SocketAddr> {
        self.end_users.get_all_socket_addr(end_user)
    }

    pub fn node(&self) -> &Node {
        &self.node
    }

    pub fn section(&self) -> &Section {
        &self.section
    }

    pub fn section_chain(&self) -> &SectionChain {
        self.section.chain()
    }

    pub fn network(&self) -> &Network {
        &self.network
    }

    /// Is this node an elder?
    pub fn is_elder(&self) -> bool {
        self.section.is_elder(&self.node.name())
    }

    /// Tries to sign with the secret corresponding to the provided BLS public key
    pub fn sign_with_section_key_share(
        &self,
        data: &[u8],
        public_key: &bls::PublicKey,
    ) -> Result<bls::SignatureShare> {
        self.section_keys_provider.sign_with(data, public_key)
    }

    /// Returns the current BLS public key set
    pub fn public_key_set(&self) -> Result<bls::PublicKeySet> {
        Ok(self
            .section_keys_provider
            .key_share()?
            .public_key_set
            .clone())
    }

    /// Returns the latest known public key of the section with `prefix`.
    pub fn section_key(&self, prefix: &Prefix) -> Option<&bls::PublicKey> {
        if prefix == self.section.prefix() || prefix.is_extension_of(self.section.prefix()) {
            Some(self.section.chain().last_key())
        } else {
            self.network.key_by_prefix(prefix).or_else(|| {
                if self.is_elder() {
                    // We are elder - the first key is the genesis key
                    Some(self.section.chain().root_key())
                } else {
                    // We are not elder - the chain might be truncated so the first key is not
                    // necessarily the genesis key.
                    None
                }
            })
        }
    }

    /// Returns the info about the section matching the name.
    pub fn matching_section(
        &self,
        name: &XorName,
    ) -> (Option<&bls::PublicKey>, Option<&EldersInfo>) {
        if self.section.prefix().matches(name) {
            (
                Some(self.section.chain().last_key()),
                Some(self.section.elders_info()),
            )
        } else {
            self.network.section_by_name(name)
        }
    }

    /// Returns our index in the current BLS group if this node is a member of one, or
    /// `Error::MissingSecretKeyShare` otherwise.
    pub fn our_index(&self) -> Result<usize> {
        Ok(self.section_keys_provider.key_share()?.index)
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

    pub async fn handle_section_info_msg(
        &mut self,
        sender: SocketAddr,
        message: SectionInfoMsg,
    ) -> Vec<Command> {
        match message {
            SectionInfoMsg::GetSectionQuery(name) => {
                debug!("Received GetSectionQuery({}) from {}", name, sender);

                let response = if let (true, Ok(pk_set)) =
                    (self.section.prefix().matches(&name), self.public_key_set())
                {
                    GetSectionResponse::Success(SectionInfo {
                        prefix: self.section.elders_info().prefix,
                        pk_set,
                        elders: self
                            .section
                            .elders_info()
                            .peers()
                            .map(|peer| (*peer.name(), *peer.addr()))
                            .collect(),
                    })
                } else {
                    // If we are elder, we should know a section that is closer to `name` that us.
                    // Otherwise redirect to our elders.
                    let section = self
                        .network
                        .closest(&name)
                        .unwrap_or_else(|| self.section.elders_info());
                    let addrs = section.peers().map(Peer::addr).copied().collect();
                    GetSectionResponse::Redirect(addrs)
                };

                let response = SectionInfoMsg::GetSectionResponse(response);
                debug!("Sending {:?} to {}", response, sender);

                vec![Command::SendMessage {
                    recipients: vec![sender],
                    delivery_group_size: 1,
                    message: MessageType::SectionInfo(response),
                }]
            }
            SectionInfoMsg::RegisterEndUserCmd {
                end_user,
                socketaddr_sig,
            } => {
                if self
                    .end_users
                    .try_add(sender, end_user, socketaddr_sig)
                    .is_ok()
                {
                    return vec![];
                }

                let response =
                    SectionInfoMsg::RegisterEndUserError(TargetSectionError::InvalidBootstrap(
                        format!("Failed to add enduser {} from {}", end_user, sender),
                    ));
                debug!("Sending {:?} to {}", response, sender);

                vec![Command::SendMessage {
                    recipients: vec![sender],
                    delivery_group_size: 1,
                    message: MessageType::SectionInfo(response),
                }]
            }
            SectionInfoMsg::GetSectionResponse(_) => {
                if let Some(RelocateState::InProgress(tx)) = &mut self.relocate_state {
                    trace!("Forwarding {:?} to the bootstrap task", message);
                    let _ = tx.send((MessageType::SectionInfo(message), sender)).await;
                }
                vec![]
            }
            SectionInfoMsg::RegisterEndUserError(error) => {
                error!("RegisterEndUserError received: {:?}", error);
                vec![]
            }
            SectionInfoMsg::SectionInfoUpdate(error) => {
                error!("SectionInfoUpdate received: {:?}", error);
                vec![]
            }
        }
    }

    pub fn handle_timeout(&mut self, token: u64) -> Result<Vec<Command>> {
        self.dkg_voter
            .handle_timeout(&self.node.keypair, token)
            .into_commands(&self.node)
    }

    // Insert the proposal into the proposal aggregator and handle it if aggregated.
    pub fn handle_proposal(
        &mut self,
        proposal: Proposal,
        proof_share: ProofShare,
    ) -> Result<Vec<Command>> {
        match self.proposal_aggregator.add(proposal, proof_share) {
            Ok((proposal, proof)) => Ok(vec![Command::HandleAgreement { proposal, proof }]),
            Err(ProposalAggregationError::Aggregation(
                bls_signature_aggregator::Error::NotEnoughShares,
            )) => Ok(vec![]),
            Err(error) => {
                error!("Failed to add proposal: {}", error);
                Err(Error::InvalidSignatureShare)
            }
        }
    }

    pub fn handle_agreement(&mut self, proposal: Proposal, proof: Proof) -> Result<Vec<Command>> {
        debug!("handle agreement on {:?}", proposal);

        match proposal {
            Proposal::Online {
                member_info,
                previous_name,
                their_knowledge,
            } => self.handle_online_agreement(member_info, previous_name, their_knowledge, proof),
            Proposal::Offline(member_info) => self.handle_offline_agreement(member_info, proof),
            Proposal::SectionInfo(elders_info) => {
                self.handle_section_info_agreement(elders_info, proof)
            }
            Proposal::OurElders(elders_info) => {
                self.handle_our_elders_agreement(elders_info, proof)
            }
            Proposal::TheirKey { prefix, key } => {
                self.handle_their_key_agreement(prefix, key, proof);
                Ok(vec![])
            }
            Proposal::TheirKnowledge { prefix, key } => {
                self.handle_their_knowledge_agreement(prefix, key, proof);
                Ok(vec![])
            }
            Proposal::AccumulateAtSrc {
                message,
                proof_chain,
            } => Ok(vec![self.handle_accumulate_at_src_agreement(
                *message,
                proof_chain,
                proof,
            )?]),
            Proposal::JoinsAllowed(joins_allowed) => {
                self.joins_allowed = joins_allowed;
                Ok(vec![])
            }
        }
    }

    pub fn handle_connection_lost(&self, addr: SocketAddr) -> Option<Command> {
        if !self.is_elder() {
            return None;
        }

        if let Some(peer) = self.section.find_joined_member_by_addr(&addr) {
            trace!("Lost connection to {}", peer);
        } else {
            return None;
        }

        // Try to send a "ping" message to probe the peer connection. If it succeeds, the
        // connection loss was just temporary. Otherwise the peer is assumed lost and we will
        // propose it offline.
        Some(Command::SendMessage {
            recipients: vec![addr],
            delivery_group_size: 1,
            message: MessageType::Ping,
        })
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

            // Don't send the `Offline` proposal to the peer being lost as that send would fail,
            // triggering a chain of further `Offline` proposals.
            let elders: Vec<_> = self
                .section
                .elders_info()
                .peers()
                .filter(|peer| peer.name() != info.peer.name())
                .copied()
                .collect();

            self.send_proposal(&elders, Proposal::Offline(info))
        } else {
            Ok(vec![])
        }
    }

    pub fn handle_dkg_outcome(
        &mut self,
        elders_info: EldersInfo,
        key_share: SectionKeyShare,
    ) -> Result<Vec<Command>> {
        let proposal = Proposal::SectionInfo(elders_info);
        let recipients: Vec<_> = self.section.elders_info().peers().copied().collect();
        let result = self.send_proposal_with(&recipients, proposal, &key_share);

        let public_key = key_share.public_key_set.public_key();

        self.section_keys_provider.insert_dkg_outcome(key_share);

        if self.section.chain().has_key(&public_key) {
            self.section_keys_provider.finalise_dkg(&public_key)
        }

        result
    }

    pub fn handle_dkg_failure(&mut self, proofs: DkgFailureProofSet) -> Result<Command> {
        let variant = Variant::DkgFailureAgreement(proofs);
        let message = Message::single_src(&self.node, DstLocation::Direct, variant, None, None)?;
        Ok(self.send_message_to_our_elders(message.to_bytes()))
    }

    // Send proposal to all our elders.
    fn propose(&self, proposal: Proposal) -> Result<Vec<Command>> {
        let elders: Vec<_> = self.section.elders_info().peers().copied().collect();
        self.send_proposal(&elders, proposal)
    }

    // Send `proposal` to `recipients`.
    fn send_proposal(&self, recipients: &[Peer], proposal: Proposal) -> Result<Vec<Command>> {
        let key_share = self.section_keys_provider.key_share().map_err(|err| {
            trace!("Can't propose {:?}: {}", proposal, err);
            err
        })?;
        self.send_proposal_with(recipients, proposal, key_share)
    }

    fn send_proposal_with(
        &self,
        recipients: &[Peer],
        proposal: Proposal,
        key_share: &SectionKeyShare,
    ) -> Result<Vec<Command>> {
        trace!(
            "Propose {:?}, key_share: {:?}, aggregators: {:?}",
            proposal,
            key_share,
            recipients,
        );

        let proof_share = proposal.prove(
            key_share.public_key_set.clone(),
            key_share.index,
            &key_share.secret_key_share,
        )?;

        // Broadcast the proposal to the rest of the section elders.
        let variant = Variant::Propose {
            content: proposal,
            proof_share,
        };
        let message = Message::single_src(&self.node, DstLocation::Direct, variant, None, None)?;

        Ok(self.send_or_handle(message, recipients))
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

    ////////////////////////////////////////////////////////////////////////////
    // Message handling
    ////////////////////////////////////////////////////////////////////////////

    fn decide_message_status(&self, msg: &Message) -> Result<MessageStatus> {
        match msg.variant() {
            Variant::OtherSection { .. } => {
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
            Variant::DkgStart { elders_info, .. } => {
                if !elders_info.elders.contains_key(&self.node.name()) {
                    return Ok(MessageStatus::Useless);
                }
            }
            Variant::NodeApproval { .. } | Variant::JoinRetry { .. } => {
                // Skip validation of these. We will validate them inside the bootstrap task.
                return Ok(MessageStatus::Useful);
            }
            Variant::Sync { section, .. } => {
                // Ignore `Sync` not for our section.
                if !section.prefix().matches(&self.node.name()) {
                    return Ok(MessageStatus::Useless);
                }
            }
            Variant::Propose {
                content,
                proof_share,
                ..
            } => {
                if let Some(status) =
                    self.decide_propose_status(&msg.src().name(), content, proof_share)
                {
                    return Ok(status);
                }
            }
            Variant::RelocatePromise(promise) => {
                if let Some(status) = self.decide_relocate_promise_status(promise) {
                    return Ok(status);
                }
            }
            Variant::Relocate(_)
            | Variant::BouncedUntrustedMessage(_)
            | Variant::BouncedUnknownMessage { .. }
            | Variant::DkgMessage { .. }
            | Variant::DkgFailureObservation { .. }
            | Variant::DkgFailureAgreement { .. }
            | Variant::ResourceChallenge { .. } => {}
        }

        if self.verify_message(msg)? {
            Ok(MessageStatus::Useful)
        } else {
            Ok(MessageStatus::Untrusted)
        }
    }

    fn aggregate_message(&mut self, msg: Message) -> Result<Option<Message>> {
        let proof_share = if let SrcAuthority::BlsShare { proof_share, .. } = msg.src() {
            proof_share
        } else {
            // Not an aggregating message, return unchanged.
            return Ok(Some(msg));
        };

        let signed_bytes = bincode::serialize(&msg.signable_view())?;
        match self
            .message_aggregator
            .add(&signed_bytes, proof_share.clone())
        {
            Ok(proof) => {
                trace!("Successfully accumulated signatures for message: {:?}", msg);
                Ok(Some(msg.into_dst_accumulated(proof)?))
            }
            Err(AggregatorError::NotEnoughShares) => Ok(None),
            Err(err) => {
                error!("Error accumulating message at destination: {:?}", err);
                Err(Error::InvalidSignatureShare)
            }
        }
    }

    async fn handle_useful_message(
        &mut self,
        sender: Option<SocketAddr>,
        msg: Message,
    ) -> Result<Vec<Command>> {
        self.msg_filter.insert_incoming(&msg);

        let msg = if let Some(msg) = self.aggregate_message(msg)? {
            msg
        } else {
            return Ok(vec![]);
        };

        match msg.variant() {
            Variant::OtherSection { elders_info, .. } => {
                self.handle_other_section(elders_info.value.clone(), *msg.proof_chain_last_key()?)
            }
            Variant::Sync { section, network } => {
                self.handle_sync(section.clone(), network.clone())
            }
            Variant::Relocate(_) => {
                if msg.src().is_section() {
                    let signed_relocate = SignedRelocateDetails::new(msg)?;
                    Ok(self.handle_relocate(signed_relocate)?.into_iter().collect())
                } else {
                    Err(Error::InvalidSrcLocation)
                }
            }
            Variant::RelocatePromise(promise) => {
                self.handle_relocate_promise(*promise, msg.to_bytes())
            }
            Variant::JoinRequest(join_request) => {
                let sender = sender.ok_or(Error::InvalidSrcLocation)?;
                self.handle_join_request(msg.src().peer(sender)?, *join_request.clone())
            }
            Variant::UserMessage(content) => self.handle_user_message(&msg, content.clone()),
            Variant::BouncedUntrustedMessage(message) => {
                let sender = sender.ok_or(Error::InvalidSrcLocation)?;
                Ok(vec![self.handle_bounced_untrusted_message(
                    msg.src().peer(sender)?,
                    msg.dst_key().copied(),
                    *message.clone(),
                )?])
            }
            Variant::BouncedUnknownMessage { src_key, message } => {
                let sender = sender.ok_or(Error::InvalidSrcLocation)?;
                self.handle_bounced_unknown_message(
                    msg.src().peer(sender)?,
                    message.clone(),
                    src_key,
                )
            }
            Variant::DkgStart {
                dkg_key,
                elders_info,
            } => self.handle_dkg_start(*dkg_key, elders_info.clone()),
            Variant::DkgMessage { dkg_key, message } => {
                self.handle_dkg_message(*dkg_key, message.clone(), msg.src().name())
            }
            Variant::DkgFailureObservation { dkg_key, proof } => {
                self.handle_dkg_failure_observation(*dkg_key, *proof)
            }
            Variant::DkgFailureAgreement(proofs) => {
                self.handle_dkg_failure_agreement(&msg.src().name(), proofs)
            }
            Variant::Propose {
                content,
                proof_share,
            } => {
                let mut commands = vec![];
                let result = self.handle_proposal(content.clone(), proof_share.clone());

                if let Some(addr) = sender {
                    commands.extend(self.check_lagging(&addr, proof_share)?);
                }

                commands.extend(result?);
                Ok(commands)
            }
            Variant::NodeApproval { .. }
            | Variant::JoinRetry { .. }
            | Variant::ResourceChallenge { .. } => {
                if let Some(RelocateState::InProgress(message_tx)) = &mut self.relocate_state {
                    if let Some(sender) = sender {
                        trace!("Forwarding {:?} to the bootstrap task", msg);
                        let node_msg = NodeMessage::new(msg.to_bytes());
                        let _ = message_tx
                            .send((MessageType::NodeMessage(node_msg), sender))
                            .await;
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
        self.is_elder() || dst == &DstLocation::Node(self.node.name())
    }

    // Decide how to handle a `Propose` message.
    fn decide_propose_status(
        &self,
        sender: &XorName,
        proposal: &Proposal,
        proof_share: &ProofShare,
    ) -> Option<MessageStatus> {
        match proposal {
            Proposal::SectionInfo(elders_info)
                if elders_info.prefix == *self.section.prefix()
                    || elders_info.prefix.is_extension_of(self.section.prefix()) =>
            {
                // This `SectionInfo` is proposed by the DKG participants and is signed by the new
                // key created by the DKG so we don't know it yet. We only require the sender of the
                // proposal to be one of the DKG participants.
                if elders_info.elders.contains_key(sender) {
                    None
                } else {
                    Some(MessageStatus::Useless)
                }
            }
            _ => {
                // Any other proposal needs to be signed by a known key.
                if self
                    .section
                    .chain()
                    .has_key(&proof_share.public_key_set.public_key())
                {
                    None
                } else {
                    Some(MessageStatus::Unknown)
                }
            }
        }
    }

    // Decide how to handle a `RelocatePromise` message.
    fn decide_relocate_promise_status(&self, promise: &RelocatePromise) -> Option<MessageStatus> {
        if promise.name == self.node.name() {
            // Promise to relocate us.
            if self.relocate_state.is_some() {
                // Already received a promise or already relocating. discard.
                return Some(MessageStatus::Useless);
            }
        } else {
            // Promise returned from a node to be relocated, to be exchanged for the actual
            // `Relocate` message.
            if !self.is_elder() || self.section.is_elder(&promise.name) {
                // If we are not elder, maybe we just haven't processed our promotion yet.
                // If they are still elder, maybe we just haven't processed their demotion yet.
                //
                // In both cases, bounce the message and try again on resend (if any).
                return Some(MessageStatus::Unknown);
            }
        }

        None
    }

    fn verify_message(&self, msg: &Message) -> Result<bool> {
        let known_keys = self
            .section
            .chain()
            .keys()
            .chain(self.network.keys().map(|(_, key)| key))
            .chain(iter::once(self.section.genesis_key()));

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
        let src_name = msg.src().name();
        let bounce_dst_key = *self.section_key_by_name(&src_name);
        let bounce_msg = Message::single_src(
            &self.node,
            DstLocation::Direct,
            Variant::BouncedUntrustedMessage(Box::new(msg)),
            None,
            Some(bounce_dst_key),
        )?;
        let bounce_msg = bounce_msg.to_bytes();

        if let Some(sender) = sender {
            Ok(Command::send_message_to_node(&sender, bounce_msg))
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
            Ok(Command::send_message_to_node(&sender, bounce_msg))
        } else {
            Ok(self.send_message_to_our_elders(bounce_msg))
        }
    }

    fn handle_bounced_untrusted_message(
        &self,
        sender: Peer,
        dst_key: Option<bls::PublicKey>,
        bounced_msg: Message,
    ) -> Result<Command> {
        let span = trace_span!("Received BouncedUntrustedMessage", ?bounced_msg, %sender);
        let _span_guard = span.enter();

        let dst_key = dst_key.ok_or_else(|| {
            error!("missing dst key");
            Error::InvalidMessage
        })?;

        let resend_msg = match bounced_msg.variant() {
            Variant::Sync { section, network } => {
                // `Sync` messages are handled specially, because they don't carry a proof chain.
                // Instead we use the section chain that's part of the included `Section` struct.
                // Problem is we can't extend that chain as it would invalidate the signature. We
                // must construct a new message instead.
                let section = section
                    .extend_chain(&dst_key, self.section.chain())
                    .map_err(|err| {
                        error!("extending section chain failed: {:?}", err);
                        Error::InvalidMessage // TODO: more specific error
                    })?;

                Message::single_src(
                    &self.node,
                    DstLocation::Direct,
                    Variant::Sync {
                        section,
                        network: network.clone(),
                    },
                    None,
                    None,
                )?
            }
            _ => bounced_msg
                .extend_proof_chain(&dst_key, self.section.chain())
                .map_err(|err| {
                    error!("extending proof chain failed: {:?}", err);
                    Error::InvalidMessage // TODO: more specific error
                })?,
        };

        trace!("resending with extended proof");
        Ok(Command::send_message_to_node(
            sender.addr(),
            resend_msg.to_bytes(),
        ))
    }

    fn handle_bounced_unknown_message(
        &self,
        sender: Peer,
        bounced_msg_bytes: Bytes,
        sender_last_key: &bls::PublicKey,
    ) -> Result<Vec<Command>> {
        let span = trace_span!(
            "Received BouncedUnknownMessage",
            bounced_msg_hash=?MessageHash::from_bytes(&bounced_msg_bytes),
            %sender
        );
        let _span_guard = span.enter();

        if !self.section.prefix().matches(sender.name()) {
            trace!("peer is not from our section, discarding");
            return Ok(vec![]);
        }

        if !self.section.chain().has_key(sender_last_key)
            || sender_last_key == self.section.chain().last_key()
        {
            trace!("peer is up to date or ahead of us, discarding");
            return Ok(vec![]);
        }

        trace!("peer is lagging behind, resending with Sync",);
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
            Command::send_message_to_node(sender.addr(), bounced_msg_bytes),
        ])
    }

    fn handle_other_section(
        &self,
        elders_info: EldersInfo,
        src_key: bls::PublicKey,
    ) -> Result<Vec<Command>> {
        let mut commands = vec![];

        if !self.network.has_key(&src_key) {
            commands.extend(self.propose(Proposal::TheirKey {
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

        commands.extend(self.propose(Proposal::SectionInfo(elders_info))?);

        Ok(commands)
    }

    fn handle_user_message(&mut self, msg: &Message, content: Bytes) -> Result<Vec<Command>> {
        if let DstLocation::EndUser(end_user) = msg.dst() {
            let recipients = match end_user {
                EndUser::AllClients(public_key) => {
                    self.get_all_socket_addr(public_key).copied().collect()
                }
                EndUser::Client { socket_id, .. } => {
                    if let Some(socket_addr) = self.get_socket_addr(*socket_id).copied() {
                        vec![socket_addr]
                    } else {
                        vec![]
                    }
                }
            };
            if recipients.is_empty() {
                return Err(Error::CannotRoute);
            };
            return Ok(vec![Command::SendMessage {
                recipients,
                delivery_group_size: 1,
                message: MessageType::ClientMessage(ClientMessage::from(content)?),
            }]);
        }

        self.send_event(Event::MessageReceived {
            content,
            src: msg.src().src_location(),
            dst: *msg.dst(),
            proof_chain: msg.proof_chain().ok().cloned(),
        });
        Ok(vec![])
    }

    fn handle_sync(&mut self, section: Section, network: Network) -> Result<Vec<Command>> {
        if !section.prefix().matches(&self.node.name()) {
            trace!("ignore Sync - not our section");
            return Ok(vec![]);
        }

        let snapshot = self.state_snapshot();
        self.section.merge(section)?;
        self.network.merge(network, self.section.chain());
        self.update_state(snapshot)
    }

    fn handle_relocate(&mut self, details: SignedRelocateDetails) -> Result<Option<Command>> {
        if details.relocate_details()?.pub_id != self.node.name() {
            // This `Relocate` message is not for us - it's most likely a duplicate of a previous
            // message that we already handled.
            return Ok(None);
        }

        debug!(
            "Received Relocate message to join the section at {}",
            details.relocate_details()?.destination
        );

        match self.relocate_state {
            Some(RelocateState::InProgress(_)) => {
                trace!("Ignore Relocate - relocation already in progress");
                return Ok(None);
            }
            Some(RelocateState::Delayed(_)) => (),
            None => {
                self.send_event(Event::RelocationStarted {
                    previous_name: self.node.name(),
                });
            }
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

        Ok(Some(Command::Relocate {
            bootstrap_addrs,
            details,
            message_rx,
        }))
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
                    trace!(
                        "Received RelocatePromise to section at {}",
                        promise.destination
                    );
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

    fn handle_join_request(
        &mut self,
        peer: Peer,
        join_request: JoinRequest,
    ) -> Result<Vec<Command>> {
        debug!("Received {:?} from {}", join_request, peer);

        if !self.section.prefix().matches(peer.name()) {
            debug!(
                "Ignoring JoinRequest from {} - name doesn't match our prefix {:?}.",
                peer,
                self.section.prefix()
            );
            return Ok(vec![]);
        }

        if join_request.section_key != *self.section.chain().last_key() {
            let variant = Variant::JoinRetry {
                elders_info: self.section.elders_info().clone(),
                section_key: *self.section.chain().last_key(),
            };
            trace!("Sending {:?} to {}", variant, peer);
            return Ok(vec![self.send_direct_message(peer.addr(), variant)?]);
        }

        if self.section.members().is_joined(peer.name()) {
            debug!(
                "Ignoring JoinRequest from {} - already member of our section.",
                peer
            );
            return Ok(vec![]);
        }

        // This joining node is being relocated to us.
        let (mut age, previous_name, their_knowledge) =
            if let Some(ref payload) = join_request.relocate_payload {
                if !payload.verify_identity(peer.name()) {
                    debug!(
                        "Ignoring relocation JoinRequest from {} - invalid signature.",
                        peer
                    );
                    return Ok(vec![]);
                }

                let details = payload.relocate_details()?;

                if !self.section.prefix().matches(&details.destination) {
                    debug!(
                        "Ignoring relocation JoinRequest from {} - destination {} doesn't match \
                         our prefix {:?}.",
                        peer,
                        details.destination,
                        self.section.prefix()
                    );
                    return Ok(vec![]);
                }

                if !self
                    .verify_message(payload.details.signed_msg())
                    .unwrap_or(false)
                {
                    debug!("Ignoring relocation JoinRequest from {} - untrusted.", peer);
                    return Ok(vec![]);
                }

                (
                    details.age,
                    Some(details.pub_id),
                    Some(details.destination_key),
                )
            } else if !self.joins_allowed {
                debug!(
                    "Ignoring JoinRequest from {} - new node not acceptable.",
                    peer,
                );
                return Ok(vec![]);
            } else {
                // Start as Adult as long as passed resource proofing.
                (MIN_ADULT_AGE, None, None)
            };

        // Age differentiate only applies to the new node.
        if join_request.relocate_payload.is_none() {
            // During the first section, node shall use ranged age to avoid too many nodes got
            // relocated at the same time. After the first section got split, later on nodes shall
            // only start with age of MIN_ADULT_AGE
            if self.section.prefix().is_empty() {
                if peer.age() < FIRST_SECTION_MIN_AGE || peer.age() > FIRST_SECTION_MAX_AGE {
                    debug!(
                        "Ignoring JoinRequest from {} - first-section node having wrong age {:?}",
                        peer,
                        peer.age(),
                    );
                    return Ok(vec![]);
                } else {
                    age = peer.age();
                }
            } else if peer.age() != MIN_ADULT_AGE {
                // After section split, new node has to join with age of MIN_ADULT_AGE.
                debug!(
                    "Ignoring JoinRequest from {} - non-first-section node having wrong age {:?}",
                    peer,
                    peer.age(),
                );
                return Ok(vec![]);
            }
        }

        // Requires the node name matches the age.
        if age != peer.age() {
            debug!(
                "Ignoring JoinRequest from {} - required age {:?} not presented.",
                peer, age,
            );
            return Ok(vec![]);
        }

        // Require resource proof only if joining as a new node.
        if previous_name.is_none() {
            if let Some(response) = join_request.resource_proof_response {
                if !self.validate_resource_proof_response(peer.name(), response) {
                    debug!(
                        "Ignoring JoinRequest from {} - invalid resource proof response",
                        peer
                    );
                    return Ok(vec![]);
                }
            } else {
                return Ok(vec![self.send_resource_proof_challenge(&peer)?]);
            }
        }

        self.propose(Proposal::Online {
            member_info: MemberInfo::joined(peer),
            previous_name,
            their_knowledge,
        })
    }

    fn validate_resource_proof_response(
        &self,
        peer_name: &XorName,
        response: ResourceProofResponse,
    ) -> bool {
        let serialized = if let Ok(serialized) = bincode::serialize(&(peer_name, &response.nonce)) {
            serialized
        } else {
            return false;
        };

        if self
            .node
            .keypair
            .public
            .verify(&serialized, &response.nonce_signature)
            .is_err()
        {
            return false;
        }

        self.resource_proof
            .validate_all(&response.nonce, &response.data, response.solution)
    }

    fn send_resource_proof_challenge(&self, peer: &Peer) -> Result<Command> {
        let nonce: [u8; 32] = rand::random();
        let serialized = bincode::serialize(&(peer.name(), &nonce))?;
        let response = Variant::ResourceChallenge {
            data_size: RESOURCE_PROOF_DATA_SIZE,
            difficulty: RESOURCE_PROOF_DIFFICULTY,
            nonce,
            nonce_signature: crypto::sign(&serialized, &self.node.keypair),
        };

        self.send_direct_message(peer.addr(), response)
    }

    fn handle_dkg_start(
        &mut self,
        dkg_key: DkgKey,
        new_elders_info: EldersInfo,
    ) -> Result<Vec<Command>> {
        trace!("Received DkgStart for {}", new_elders_info);
        self.dkg_voter
            .start(&self.node.keypair, dkg_key, new_elders_info)
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
            .process_message(&self.node.keypair, &dkg_key, message)
            .into_commands(&self.node)
    }

    fn handle_dkg_failure_observation(
        &mut self,
        dkg_key: DkgKey,
        proof: DkgFailureProof,
    ) -> Result<Vec<Command>> {
        self.dkg_voter
            .process_failure(&dkg_key, proof)
            .into_commands(&self.node)
    }

    fn handle_dkg_failure_agreement(
        &self,
        sender: &XorName,
        proofs: &DkgFailureProofSet,
    ) -> Result<Vec<Command>> {
        let sender = &self
            .section
            .members()
            .get(sender)
            .ok_or(Error::InvalidSrcLocation)?
            .peer;

        let generation = self.section.chain().main_branch_len() as u64;
        let elders_info = self
            .section
            .promote_and_demote_elders(&self.node.name())
            .into_iter()
            .find(|elders_info| proofs.verify(elders_info, generation));
        let elders_info = if let Some(elders_info) = elders_info {
            elders_info
        } else {
            trace!("Ignore DKG failure agreement with invalid proofs or outdated participants",);
            return Ok(vec![]);
        };

        trace!(
            "Received DKG failure agreement - restarting: {}",
            elders_info
        );

        self.send_dkg_start_to(elders_info, slice::from_ref(sender))
    }

    // Generate a new section info based on the current set of members and if it differs from the
    // current elders, trigger a DKG.
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

        // Do not carry out relocation when there is not enough elder nodes.
        if self.section.elders_info().elders.len() < ELDER_SIZE {
            return Ok(commands);
        }

        // Consider: Set <= 4, as to not carry out relocations in first 16 sections.
        // TEMP: Do not carry out relocations in the first section
        if self.section.prefix().bit_count() < 1 {
            return Ok(commands);
        }

        let relocations =
            relocation::actions(&self.section, &self.network, churn_name, churn_signature);

        for (info, action) in relocations {
            let peer = info.peer;

            // The newly joined node is not being relocated immediately.
            if peer.name() == churn_name {
                continue;
            }

            debug!(
                "Relocating {:?} to {} (on churn of {})",
                peer,
                action.destination(),
                churn_name
            );

            commands.extend(self.propose(Proposal::Offline(info.relocate(*action.destination())))?);

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

    fn relocate_rejoining_peer(&self, peer: &Peer, age: u8) -> Result<Vec<Command>> {
        let details =
            RelocateDetails::with_age(&self.section, &self.network, peer, *peer.name(), age);

        trace!(
            "Relocating {:?} to {} with age {} due to rejoin",
            peer,
            details.destination,
            details.age
        );

        self.send_relocate(peer, details)
    }

    fn handle_online_agreement(
        &mut self,
        new_info: MemberInfo,
        previous_name: Option<XorName>,
        their_knowledge: Option<bls::PublicKey>,
        proof: Proof,
    ) -> Result<Vec<Command>> {
        let mut commands = vec![];

        if let Some(old_info) = self.section.members().get_proven(new_info.peer.name()) {
            // This node is rejoin with same name.

            if old_info.value.state != PeerState::Left {
                debug!(
                    "Ignoring Online node {} - {:?} not Left.",
                    new_info.peer.name(),
                    old_info.value.state,
                );

                return Ok(commands);
            }

            let new_age = cmp::max(MIN_AGE, old_info.value.peer.age() / 2);

            if new_age > MIN_AGE {
                // TODO: consider handling the relocation inside the bootstrap phase, to avoid
                // having to send this `NodeApproval`.
                commands.push(self.send_node_approval(old_info.clone(), their_knowledge)?);
                commands.extend(self.relocate_rejoining_peer(&old_info.value.peer, new_age)?);

                return Ok(commands);
            }
        }

        let new_info = Proven {
            value: new_info,
            proof,
        };

        if !self.section.update_member(new_info.clone()) {
            info!("ignore Online: {:?}", new_info.value.peer);
            return Ok(vec![]);
        }

        info!("handle Online: {:?}", new_info.value.peer);

        self.send_event(Event::MemberJoined {
            name: *new_info.value.peer.name(),
            previous_name,
            age: new_info.value.peer.age(),
        });

        commands
            .extend(self.relocate_peers(new_info.value.peer.name(), &new_info.proof.signature)?);
        commands.extend(self.promote_and_demote_elders()?);
        commands.push(self.send_node_approval(new_info, their_knowledge)?);

        self.print_network_stats();

        Ok(commands)
    }

    fn handle_offline_agreement(
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

    fn handle_section_info_agreement(
        &mut self,
        elders_info: EldersInfo,
        proof: Proof,
    ) -> Result<Vec<Command>> {
        let mut commands = vec![];

        let equal_or_extension = elders_info.prefix == *self.section.prefix()
            || elders_info.prefix.is_extension_of(self.section.prefix());
        let elders_info = Proven::new(elders_info, proof);

        if equal_or_extension {
            // Our section of sub-section

            let infos = self.section.promote_and_demote_elders(&self.node.name());
            if !infos.contains(&elders_info.value) {
                // SectionInfo out of date, ignore.
                return Ok(commands);
            }

            // Send a `Sync` message to all the to-be-promoted members so they have the full
            // section and network data.
            let sync_recipients: Vec<_> = infos
                .iter()
                .flat_map(|info| info.peers())
                .filter(|peer| !self.section.is_elder(peer.name()))
                .map(Peer::addr)
                .copied()
                .collect();
            if !sync_recipients.is_empty() {
                let sync_message = Message::single_src(
                    &self.node,
                    DstLocation::Direct,
                    Variant::Sync {
                        section: self.section.clone(),
                        network: self.network.clone(),
                    },
                    None,
                    None,
                )?;
                commands.push(Command::send_message_to_nodes(
                    &sync_recipients,
                    sync_recipients.len(),
                    sync_message.to_bytes(),
                ));
            }

            // Send the `OurElder` proposal to all of the to-be-elders so it's aggregated by them.
            let our_elders_recipients: Vec<_> = infos
                .iter()
                .flat_map(|info| info.peers())
                .copied()
                .collect();
            commands.extend(
                self.send_proposal(&our_elders_recipients, Proposal::OurElders(elders_info))?,
            );
        } else {
            // Other section

            let _ = self
                .network
                .update_section(elders_info, None, self.section.chain());
        }

        Ok(commands)
    }

    fn handle_our_elders_agreement(
        &mut self,
        elders_info: Proven<EldersInfo>,
        key_proof: Proof,
    ) -> Result<Vec<Command>> {
        let updates = self
            .split_barrier
            .process(self.section.prefix(), elders_info, key_proof);
        if updates.is_empty() {
            return Ok(vec![]);
        }

        let snapshot = self.state_snapshot();

        for (elders_info, key_proof) in updates {
            if elders_info.value.prefix.matches(&self.node.name()) {
                let _ = self.section.update_elders(elders_info, key_proof);
            } else {
                let _ =
                    self.network
                        .update_section(elders_info, Some(key_proof), self.section.chain());
            }
        }

        self.update_state(snapshot)
    }

    fn handle_their_key_agreement(&mut self, prefix: Prefix, key: bls::PublicKey, proof: Proof) {
        let key = Proven::new((prefix, key), proof);
        let _ = self.network.update_their_key(key);
    }

    fn handle_their_knowledge_agreement(
        &mut self,
        prefix: Prefix,
        knowledge: bls::PublicKey,
        proof: Proof,
    ) {
        let knowledge = Proven::new((prefix, knowledge), proof);
        self.network.update_knowledge(knowledge)
    }

    fn handle_accumulate_at_src_agreement(
        &self,
        message: PlainMessage,
        proof_chain: SectionChain,
        proof: Proof,
    ) -> Result<Command> {
        let message = Message::section_src(message, proof.signature, proof_chain)?;

        Ok(Command::HandleMessage {
            message,
            sender: None,
        })
    }

    fn state_snapshot(&self) -> StateSnapshot {
        StateSnapshot {
            is_elder: self.is_elder(),
            last_key: *self.section.chain().last_key(),
            prefix: *self.section.prefix(),
        }
    }

    fn update_state(&mut self, old: StateSnapshot) -> Result<Vec<Command>> {
        let mut commands = vec![];
        let new = self.state_snapshot();

        self.section_keys_provider
            .finalise_dkg(self.section.chain().last_key());

        if new.prefix != old.prefix {
            info!("Split");
        }

        if new.last_key != old.last_key {
            self.msg_filter.reset();

            if new.is_elder {
                info!(
                    "Section updated: prefix: ({:b}), key: {:?}, elders: {}",
                    new.prefix,
                    new.last_key,
                    self.section.elders_info().peers().format(", ")
                );

                if self.section_keys_provider.has_key_share() {
                    commands.extend(self.promote_and_demote_elders()?);
                    // Whenever there is an elders change, casting a round of joins_allowed
                    // proposals to sync.
                    commands.extend(self.propose(Proposal::JoinsAllowed(self.joins_allowed))?);
                }

                self.print_network_stats();
            }

            if new.is_elder || old.is_elder {
                commands.extend(self.send_sync(self.section.clone(), self.network.clone())?);
            }

            let sibling_key = if new.prefix != old.prefix {
                self.section_key(&new.prefix.sibling()).copied()
            } else {
                None
            };

            let self_status_change = if !old.is_elder && new.is_elder {
                info!("Promoted to elder");
                NodeElderChange::Promoted
            } else if old.is_elder && !new.is_elder {
                info!("Demoted");
                self.section = self.section.trimmed(1);
                self.network = Network::new();
                self.section_keys_provider = SectionKeysProvider::new(KEY_CACHE_SIZE, None);
                NodeElderChange::Demoted
            } else {
                NodeElderChange::None
            };

            self.send_event(Event::EldersChanged {
                prefix: new.prefix,
                key: new.last_key,
                sibling_key,
                elders: self.section.elders_info().elders.keys().copied().collect(),
                self_status_change,
            });
        }

        if !new.is_elder {
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

    // Send NodeApproval to a joining node which makes them a section member
    fn send_node_approval(
        &self,
        member_info: Proven<MemberInfo>,
        their_knowledge: Option<bls::PublicKey>,
    ) -> Result<Command> {
        info!(
            "Our section with {:?} has approved peer {:?}.",
            self.section.prefix(),
            member_info.value.peer
        );

        let addr = *member_info.value.peer.addr();

        // Attach proof chain that includes the key the approved node knows (if any), the key its
        // `MemberInfo` is signed with and the last key of our section chain.
        let proof_chain = self.section.chain().minimize(
            iter::once(self.section.chain().last_key())
                .chain(their_knowledge.as_ref())
                .chain(iter::once(&member_info.proof.public_key)),
        )?;

        let variant = Variant::NodeApproval {
            genesis_key: *self.section.genesis_key(),
            elders_info: self.section.proven_elders_info().clone(),
            member_info,
        };

        let message = Message::single_src(
            &self.node,
            DstLocation::Direct,
            variant,
            Some(proof_chain),
            None,
        )?;

        Ok(Command::send_message_to_node(&addr, message.to_bytes()))
    }

    fn send_sync(&mut self, section: Section, network: Network) -> Result<Vec<Command>> {
        let send = |variant, recipients: Vec<_>| -> Result<_> {
            trace!("Send {:?} to {:?}", variant, recipients);

            let message =
                Message::single_src(&self.node, DstLocation::Direct, variant, None, None)?;
            let recipients: Vec<_> = recipients.iter().map(Peer::addr).copied().collect();

            Ok(Command::send_message_to_nodes(
                &recipients,
                recipients.len(),
                message.to_bytes(),
            ))
        };

        let mut commands = vec![];

        let (elders, non_elders): (Vec<_>, _) = section
            .active_members()
            .filter(|peer| peer.name() != &self.node.name())
            .copied()
            .partition(|peer| section.is_elder(peer.name()));

        // Send the trimmed state to non-elders. The trimmed state contains only the latest
        // section key and one key before that which is the key the recipients should know so they
        // will be able to trust it.
        let variant = Variant::Sync {
            section: section.trimmed(2),
            network: Network::new(),
        };
        commands.push(send(variant, non_elders)?);

        // Send the full state to elders.
        // The full state contains the whole section chain.
        let variant = Variant::Sync { section, network };
        commands.push(send(variant, elders)?);

        Ok(commands)
    }

    fn send_relocate(&self, recipient: &Peer, details: RelocateDetails) -> Result<Vec<Command>> {
        // We need to construct a proof that would be trusted by the destination section.
        let known_key = self
            .network
            .knowledge_by_name(&details.destination)
            .unwrap_or_else(|| self.section.chain().root_key());

        let src = details.pub_id;
        let dst = DstLocation::Node(details.pub_id);
        let variant = Variant::Relocate(details);

        self.send_message_for_dst_accumulation(
            src,
            dst,
            variant,
            Some(known_key),
            slice::from_ref(recipient),
        )
    }

    fn send_relocate_promise(
        &self,
        recipient: &Peer,
        promise: RelocatePromise,
    ) -> Result<Vec<Command>> {
        // Note: this message is first sent to a single node who then sends it back to the section
        // where it needs to be handled by all the elders. This is why the destination is
        // `Section`, not `Node`.
        let src = promise.name;
        let dst = DstLocation::Section(promise.name);
        let variant = Variant::RelocatePromise(promise);

        self.send_message_for_dst_accumulation(src, dst, variant, None, slice::from_ref(recipient))
    }

    fn return_relocate_promise(&self) -> Option<Command> {
        // TODO: keep sending this periodically until we get relocated.
        if let Some(RelocateState::Delayed(bytes)) = &self.relocate_state {
            Some(self.send_message_to_our_elders(bytes.clone()))
        } else {
            None
        }
    }

    fn send_dkg_start(&self, elders_info: EldersInfo) -> Result<Vec<Command>> {
        // Send to all participants.
        let recipients: Vec<_> = elders_info.elders.values().copied().collect();
        self.send_dkg_start_to(elders_info, &recipients)
    }

    fn send_dkg_start_to(
        &self,
        elders_info: EldersInfo,
        recipients: &[Peer],
    ) -> Result<Vec<Command>> {
        let src_prefix = elders_info.prefix;
        let generation = self.section.chain().main_branch_len() as u64;
        let dkg_key = DkgKey::new(&elders_info, generation);

        trace!(
            "Send DkgStart for {} with {:?} to {:?}",
            elders_info,
            dkg_key,
            recipients
        );

        let variant = Variant::DkgStart {
            dkg_key,
            elders_info,
        };

        self.send_message_for_dst_accumulation(
            src_prefix.name(),
            DstLocation::Direct,
            variant,
            None,
            recipients,
        )
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

        trace!(
            "relay {:?} to {:?} (proof_chain: {:?})",
            msg,
            targets,
            msg.proof_chain().ok()
        );

        let targets: Vec<_> = targets.into_iter().map(|node| *node.addr()).collect();
        let command = Command::send_message_to_nodes(&targets, dg_size, msg.to_bytes());

        Ok(Some(command))
    }

    pub fn check_key_status(&self, bls_pk: &bls::PublicKey) -> Result<(), TargetSectionError> {
        // Whenever there is EldersInfo change candidate, it is considered as having ongoing DKG.
        if !self
            .section
            .promote_and_demote_elders(&self.node.name())
            .is_empty()
        {
            return Err(TargetSectionError::DkgInProgress);
        }
        if !self.section.chain().has_key(bls_pk) {
            return Err(TargetSectionError::UnrecognizedSectionKey);
        }
        if bls_pk != self.section.chain().last_key() {
            if let Ok(public_key_set) = self.public_key_set() {
                return Err(TargetSectionError::TargetSectionInfoOutdated(SectionInfo {
                    prefix: *self.section.prefix(),
                    pk_set: public_key_set,
                    elders: self
                        .section
                        .elders_info()
                        .peers()
                        .map(|peer| (*peer.name(), *peer.addr()))
                        .collect(),
                }));
            } else {
                return Err(TargetSectionError::DkgInProgress);
            }
        }
        Ok(())
    }

    // Setting the JoinsAllowed triggers a round Proposal::SetJoinsAllowed to update the flag.
    pub fn set_joins_allowed(&mut self, joins_allowed: bool) -> Result<Vec<Command>> {
        let mut commands = Vec::new();
        if self.is_elder() && joins_allowed != self.joins_allowed {
            commands.extend(self.propose(Proposal::JoinsAllowed(joins_allowed))?);
        }
        Ok(commands)
    }

    pub fn send_user_message(
        &mut self,
        itinerary: Itinerary,
        content: Bytes,
        additional_proof_chain_key: Option<&bls::PublicKey>,
    ) -> Result<Vec<Command>> {
        let are_we_src = itinerary.src.equals(&self.node.name())
            || itinerary.src.equals(&self.section().prefix().name());
        if !are_we_src {
            error!(
                "Not sending user message {:?} -> {:?}: we are not the source location",
                itinerary.src, itinerary.dst
            );
            return Err(Error::InvalidSrcLocation);
        }
        if matches!(itinerary.src, SrcLocation::EndUser(_)) {
            return Err(Error::InvalidSrcLocation);
        }
        if matches!(itinerary.dst, DstLocation::Direct) {
            error!(
                "Not sending user message {:?} -> {:?}: direct dst not supported",
                itinerary.src, itinerary.dst
            );
            return Err(Error::InvalidDstLocation);
        }

        let variant = Variant::UserMessage(content);

        // If the msg is to be aggregated at dst, we don't vote among our peers, we simply send the
        // msg as our vote to the dst.
        let msg = if itinerary.aggregate_at_dst() {
            let proof_chain =
                self.create_proof_chain(&itinerary.dst, additional_proof_chain_key)?;
            Message::for_dst_accumulation(
                self.section_keys_provider.key_share()?,
                itinerary.src.name(),
                itinerary.dst,
                variant,
                proof_chain,
                None,
            )?
        } else {
            Message::single_src(&self.node, itinerary.dst, variant, None, None)?
        };
        let mut commands = vec![];

        // TODO: consider removing this, we are getting duplciate msgs by it
        if itinerary
            .dst
            .contains(&self.node.name(), self.section.prefix())
        {
            commands.push(Command::HandleMessage {
                sender: Some(self.node.addr),
                message: msg.clone(),
            });
        }

        commands.extend(self.relay_message(&msg)?);

        Ok(commands)
    }

    fn send_message_for_dst_accumulation(
        &self,
        src: XorName,
        dst: DstLocation,
        variant: Variant,
        additional_proof_chain_key: Option<&bls::PublicKey>,
        recipients: &[Peer],
    ) -> Result<Vec<Command>> {
        let proof_chain = self.create_proof_chain(&dst, additional_proof_chain_key)?;
        let dst_key = if let Some(name) = dst.name() {
            *self.section_key_by_name(&name)
        } else {
            // NOTE: `dst` is `Direct`. We use this only if the recipient is in our section, so
            // it's OK to use our latest key as the `dst_key`.
            *self.section.chain().last_key()
        };

        let key_share = self.section_keys_provider.key_share().map_err(|err| {
            trace!(
                "Can't create message {:?} for accumulation at dst {:?}: {}",
                variant,
                dst,
                err
            );
            err
        })?;
        let message = Message::for_dst_accumulation(
            key_share,
            src,
            dst,
            variant,
            proof_chain,
            Some(dst_key),
        )?;

        trace!(
            "Send {:?} for accumulation at dst to {:?}",
            message,
            recipients
        );

        Ok(self.send_or_handle(message, recipients))
    }

    // Send the message to all `recipients`. If one of the recipients is us, don't send it over the
    // network but handle it directly.
    fn send_or_handle(&self, message: Message, recipients: &[Peer]) -> Vec<Command> {
        let mut commands = vec![];
        let mut others = Vec::new();
        let mut handle = false;

        trace!("Send {:?} to {:?}", message, recipients);

        for recipient in recipients {
            if recipient.name() == &self.node.name() {
                handle = true;
            } else {
                others.push(*recipient.addr());
            }
        }

        if !others.is_empty() {
            commands.push(Command::send_message_to_nodes(
                &others,
                others.len(),
                message.to_bytes(),
            ));
        }

        if handle {
            commands.push(Command::HandleMessage {
                sender: Some(self.node.addr),
                message,
            });
        }

        commands
    }

    fn create_proof_chain(
        &self,
        dst: &DstLocation,
        additional_key: Option<&bls::PublicKey>,
    ) -> Result<SectionChain> {
        // The last key of the proof chain is the last section key for which we also have the
        // secret key share. Ideally this is our current section key unless we haven't observed the
        // DKG completion yet.
        let last_key = self
            .section_keys_provider
            .key_share()?
            .public_key_set
            .public_key();

        // Only include `additional_key` if it is older than `last_key` because `last_key` must be
        // the actual last key of the resulting proof chain because it's the key that will be used
        // to sign the message.
        let additional_key = additional_key
            .or_else(|| self.network.knowledge_by_name(&dst.name()?))
            .filter(|key| self.section.chain().cmp_by_position(key, &last_key) == Ordering::Less);

        Ok(self
            .section
            .chain()
            .minimize(iter::once(&last_key).chain(additional_key))?)
    }

    fn send_direct_message(&self, recipient: &SocketAddr, variant: Variant) -> Result<Command> {
        let message = Message::single_src(&self.node, DstLocation::Direct, variant, None, None)?;
        Ok(Command::send_message_to_node(recipient, message.to_bytes()))
    }

    // TODO: consider changing this so it sends only to a subset of the elders
    // (say 1/3 of the ones closest to our name or so)
    fn send_message_to_our_elders(&self, msg: Bytes) -> Command {
        let targets: Vec<_> = self
            .section
            .elders_info()
            .peers()
            .map(Peer::addr)
            .copied()
            .collect();
        Command::send_message_to_nodes(&targets, targets.len(), msg)
    }

    ////////////////////////////////////////////////////////////////////////////
    // Miscellaneous
    ////////////////////////////////////////////////////////////////////////////

    // Update our knowledge of their (sender's) section and their knowledge of our section.
    fn update_section_knowledge(&mut self, msg: &Message) -> Result<Vec<Command>> {
        if !self.is_elder() {
            return Ok(vec![]);
        }

        let actions = lazy_messaging::process(&self.node, &self.section, &self.network, msg)?;
        let mut commands = vec![];

        if let Some(msg) = actions.send {
            commands.extend(self.relay_message(&msg)?);
        }

        if let Some(proposal) = actions.propose {
            commands.extend(self.propose(proposal)?);
        }

        Ok(commands)
    }

    fn section_key_by_name(&self, name: &XorName) -> &bls::PublicKey {
        if self.section.prefix().matches(name) {
            self.section.chain().last_key()
        } else if let Some(key) = self.network.key_by_name(name) {
            key
        } else if self.section.prefix().sibling().matches(name) {
            // For sibling with unknown key, use the previous key in our chain under the assumption
            // that it's the last key before the split and therefore the last key of theirs we know.
            // In case this assumption is not correct (because we already progressed more than one
            // key since the split) then this key would be unknown to them and they would send
            // us back their whole section chain. However, this situation should be rare.
            self.section.chain().prev_key()
        } else {
            self.section.chain().root_key()
        }
    }

    fn print_network_stats(&self) {
        self.network
            .network_stats(self.section.elders_info())
            .print()
    }
}

struct StateSnapshot {
    is_elder: bool,
    last_key: bls::PublicKey,
    prefix: Prefix,
}
