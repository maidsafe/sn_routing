// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{Command, SplitBarrier};
use crate::{
    consensus::{
        DkgCommands, DkgFailureProof, DkgFailureProofSet, DkgKey, DkgVoter, Proof, ProofShare,
        Proven, Vote, VoteAccumulationError, VoteAccumulator,
    },
    crypto, delivery_group,
    error::{Error, Result},
    event::{Event, NodeElderChange},
    message_filter::MessageFilter,
    messages::{
        JoinRequest, Message, MessageHash, MessageStatus, PlainMessage, ResourceProofResponse,
        Variant, VerifyStatus,
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
    ELDER_SIZE, RECOMMENDED_SECTION_SIZE,
};
use bls_dkg::key_gen::message::Message as DkgMessage;
use bytes::Bytes;
use ed25519_dalek::Verifier;
use itertools::Itertools;
use resource_proof::ResourceProof;
use sn_data_types::{PublicKey as EndUserPK, Signature as EndUserSig};
use sn_messaging::{
    node::NodeMessage,
    section_info::{
        Error as TargetSectionError, GetSectionResponse, Message as SectionInfoMsg, SectionInfo,
    },
    DstLocation, EndUser, MessageType, SrcLocation,
};
use std::{
    cmp,
    collections::{btree_map::Entry, BTreeMap},
    net::SocketAddr,
    slice, unimplemented,
};
use tokio::sync::mpsc;
use xor_name::{Prefix, XorName};

pub(crate) const RESOURCE_PROOF_DATA_SIZE: usize = 64;
pub(crate) const RESOURCE_PROOF_DIFFICULTY: u8 = 2;
const KEY_CACHE_SIZE: u8 = 5;

type SocketId = XorName;

struct EndUserRegistry {
    clients: BTreeMap<SocketAddr, EndUser>,
    socket_id_mapping: BTreeMap<SocketId, SocketAddr>,
}

impl EndUserRegistry {
    pub fn new() -> Self {
        Self {
            clients: BTreeMap::default(),
            socket_id_mapping: BTreeMap::default(),
        }
    }

    pub fn get_enduser_by_addr(&self, socketaddr: &SocketAddr) -> Option<EndUser> {
        self.clients.get(socketaddr).copied()
    }

    pub fn get_socket_addr(&self, socket_id: &SocketId) -> Option<&SocketAddr> {
        self.socket_id_mapping.get(socket_id)
    }

    pub fn try_add(
        &mut self,
        sender: SocketAddr,
        end_user_pk: EndUserPK,
        socketaddr_sig: EndUserSig,
    ) -> Result<()> {
        if let Ok(data) = &bincode::serialize(&sender) {
            end_user_pk
                .verify(&socketaddr_sig, data)
                .map_err(|_e| Error::InvalidState)?;
        } else {
            return Err(Error::InvalidState);
        }
        let socket_id = if let Ok(socket_id_src) = &bincode::serialize(&socketaddr_sig) {
            XorName::from_content(&[socket_id_src])
        } else {
            return Err(Error::InvalidState);
        };
        let end_user = EndUser::Client {
            public_key: end_user_pk,
            socket_id,
        };
        match self.socket_id_mapping.entry(socket_id) {
            Entry::Vacant(_) => {
                let _ = self.clients.insert(sender, end_user);
                let _ = self.socket_id_mapping.insert(socket_id, sender);
            }
            Entry::Occupied(_) => (),
        }
        Ok(())
    }
}

// The approved stage - node is a full member of a section and is performing its duties according
// to its persona (adult or elder).
pub(crate) struct Approved {
    node: Node,
    section: Section,
    network: Network,
    section_keys_provider: SectionKeysProvider,
    vote_accumulator: VoteAccumulator,
    split_barrier: SplitBarrier,
    // Voter for DKG
    dkg_voter: DkgVoter,
    relocate_state: Option<RelocateState>,
    msg_filter: MessageFilter,
    pub(super) event_tx: mpsc::UnboundedSender<Event>,
    joins_allowed: bool,
    resource_proof: ResourceProof,
    end_users: EndUserRegistry,
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
        let section_keys_provider = SectionKeysProvider::new(KEY_CACHE_SIZE, section_key_share);

        Self {
            node,
            section,
            network: Network::new(),
            section_keys_provider,
            vote_accumulator: Default::default(),
            split_barrier: Default::default(),
            dkg_voter: Default::default(),
            relocate_state: None,
            msg_filter: MessageFilter::new(),
            event_tx,
            joins_allowed: true,
            resource_proof: ResourceProof::new(RESOURCE_PROOF_DATA_SIZE, RESOURCE_PROOF_DIFFICULTY),
            end_users: EndUserRegistry::new(),
        }
    }

    pub fn get_enduser_by_addr(&self, sender: &SocketAddr) -> Option<EndUser> {
        self.end_users.get_enduser_by_addr(sender)
    }

    pub fn get_socket_addr(&self, id: &SocketId) -> Option<&SocketAddr> {
        self.end_users.get_socket_addr(id)
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

    pub async fn handle_sectioninfo_msg(
        &mut self,
        sender: SocketAddr,
        message: SectionInfoMsg,
    ) -> Vec<Command> {
        match message {
            SectionInfoMsg::GetSectionQuery(name) => {
                debug!("Received GetSectionQuery({}) from {}", name, sender);

                let response = if self.section.prefix().matches(&name) {
                    if let Ok(pk_set) = self.public_key_set() {
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
                        GetSectionResponse::SectionInfoUpdate(TargetSectionError::NoSectionPkSet)
                    }
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

    // Insert the vote into the vote accumulator and handle it if accumulated.
    pub fn handle_vote(&mut self, vote: Vote, proof_share: ProofShare) -> Result<Vec<Command>> {
        match self.vote_accumulator.add(vote, proof_share) {
            Ok((vote, proof)) => Ok(vec![Command::HandleConsensus { vote, proof }]),
            Err(VoteAccumulationError::Aggregation(
                bls_signature_aggregator::Error::NotEnoughShares,
            )) => Ok(vec![]),
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
            Vote::OurElders(elders_info) => self.handle_our_elders_event(elders_info, proof),
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
            Vote::JoinsAllowed(joins_allowed) => {
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
        // connection loss was just temporary. Otherwise the peer is assumed lost and we will vote
        // it offline.
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
            self.vote(Vote::Offline(info))
        } else {
            Ok(vec![])
        }
    }

    pub fn handle_dkg_outcome(
        &mut self,
        elders_info: EldersInfo,
        key_share: SectionKeyShare,
    ) -> Result<Vec<Command>> {
        let vote = Vote::SectionInfo(elders_info);
        let recipients: Vec<_> = self.section.elders_info().peers().copied().collect();
        let result = self.send_vote_with(&recipients, vote, &key_share);

        let public_key = key_share.public_key_set.public_key();

        self.section_keys_provider.insert_dkg_outcome(key_share);

        if self.section.chain().has_key(&public_key) {
            self.section_keys_provider.finalise_dkg(&public_key)
        }

        result
    }

    pub fn handle_dkg_failure(
        &mut self,
        elders_info: EldersInfo,
        proofs: DkgFailureProofSet,
    ) -> Result<Command> {
        let variant = Variant::DKGFailureAgreement {
            elders_info,
            proofs,
        };
        let message = Message::single_src(&self.node, DstLocation::Direct, variant, None, None)?;
        Ok(self.send_message_to_our_elders(message.to_bytes()))
    }

    // Send vote to all our elders.
    fn vote(&self, vote: Vote) -> Result<Vec<Command>> {
        let mut elders: Vec<_> = self.section.elders_info().peers().copied().collect();
        // Exclude the offline elder from the recipients.
        if let Vote::Offline(ref info) = vote {
            elders.retain(|elder| elder.name() != info.peer.name());
        }
        self.send_vote(&elders, vote)
    }

    // Send `vote` to `recipients`.
    fn send_vote(&self, recipients: &[Peer], vote: Vote) -> Result<Vec<Command>> {
        let key_share = self.section_keys_provider.key_share()?;
        self.send_vote_with(recipients, vote, key_share)
    }

    fn send_vote_with(
        &self,
        recipients: &[Peer],
        vote: Vote,
        key_share: &SectionKeyShare,
    ) -> Result<Vec<Command>> {
        trace!(
            "Vote for {:?} (public_key: {:?}, voters: {:?})",
            vote,
            key_share.public_key_set.public_key(),
            recipients,
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
            commands.push(Command::send_message_to_nodes(
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
            Variant::NodeApproval { .. } | Variant::JoinRetry { .. } => {
                // Skip validation of these. We will validate them inside the bootstrap task.
                return Ok(MessageStatus::Useful);
            }
            Variant::Vote {
                content,
                proof_share,
                ..
            } => {
                if let Some(status) =
                    self.decide_vote_status(&msg.src().to_node_name()?, content, proof_share)
                {
                    return Ok(status);
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
            | Variant::BouncedUntrustedMessage(_)
            | Variant::BouncedUnknownMessage { .. }
            | Variant::DKGMessage { .. }
            | Variant::DKGFailureObservation { .. }
            | Variant::DKGFailureAgreement { .. }
            | Variant::ResourceChallenge { .. } => {}
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
                if msg.dst().is_section() {
                    self.handle_neighbour_info(
                        elders_info.value.clone(),
                        *msg.proof_chain_last_key()?,
                    )
                } else {
                    Err(Error::InvalidDstLocation)
                }
            }
            Variant::Sync { section, network } => {
                self.handle_sync(section.clone(), network.clone())
            }
            Variant::Relocate(_) => {
                if msg.src().is_section() {
                    let signed_relocate = SignedRelocateDetails::new(msg)?;
                    Ok(self.handle_relocate(signed_relocate).into_iter().collect())
                } else {
                    Err(Error::InvalidSrcLocation)
                }
            }
            Variant::RelocatePromise(promise) => {
                self.handle_relocate_promise(*promise, msg.to_bytes())
            }
            Variant::JoinRequest(join_request) => {
                let sender = sender.ok_or(Error::InvalidSrcLocation)?;
                self.handle_join_request(msg.src().to_node_peer(sender)?, *join_request.clone())
            }
            Variant::UserMessage(content) => {
                self.handle_user_message(msg.src().src_location(), *msg.dst(), content.clone());
                Ok(vec![])
            }
            Variant::BouncedUntrustedMessage(message) => {
                let sender = sender.ok_or(Error::InvalidSrcLocation)?;
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
                let sender = sender.ok_or(Error::InvalidSrcLocation)?;
                self.handle_bounced_unknown_message(
                    msg.src().to_node_peer(sender)?,
                    message.clone(),
                    src_key,
                )
            }
            Variant::DKGStart {
                dkg_key,
                elders_info,
                key_index,
            } => self.handle_dkg_start(*dkg_key, elders_info.clone(), *key_index),
            Variant::DKGMessage { dkg_key, message } => {
                self.handle_dkg_message(*dkg_key, message.clone(), msg.src().to_node_name()?)
            }
            Variant::DKGFailureObservation { dkg_key, proof } => {
                self.handle_dkg_failure_observation(*dkg_key, *proof)
            }
            Variant::DKGFailureAgreement {
                elders_info,
                proofs,
            } => self.handle_dkg_failure_agreement(
                &msg.src().to_node_name()?,
                elders_info.clone(),
                proofs,
            ),
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
        let is_elder = self.is_elder();
        let are_we_dst = if let DstLocation::Node(name) = dst {
            name == &self.node.name()
        } else {
            false
        };
        is_elder || are_we_dst
    }

    // Decide how to handle a `Vote` message.
    fn decide_vote_status(
        &self,
        sender: &XorName,
        vote: &Vote,
        proof_share: &ProofShare,
    ) -> Option<MessageStatus> {
        match vote {
            Vote::SectionInfo(elders_info)
                if elders_info.prefix == *self.section.prefix()
                    || elders_info.prefix.is_extension_of(self.section.prefix()) =>
            {
                // This `SectionInfo` is voted by the DKG participants and is signed by the new key
                // created by the DKG so we don't know it yet. We only require the sender of the
                // vote to be one of the DKG participants.
                if elders_info.elders.contains_key(sender) {
                    None
                } else {
                    Some(MessageStatus::Useless)
                }
            }
            _ => {
                // Any other vote needs to be signed by a known key.
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
            _ => unimplemented!(),
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
            Some(Command::send_message_to_node(
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
            Command::send_message_to_node(sender.addr(), bounced_msg_bytes),
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
            "Received Relocate message to join the section at {}",
            details.relocate_details().destination
        );

        match self.relocate_state {
            Some(RelocateState::InProgress(_)) => {
                trace!("Ignore Relocate - relocation already in progress");
                return None;
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
        let (age, previous_name, their_knowledge) =
            if let Some(payload) = join_request.relocate_payload {
                if !payload.verify_identity(peer.name()) {
                    debug!(
                        "Ignoring relocation JoinRequest from {} - invalid signature.",
                        peer
                    );
                    return Ok(vec![]);
                }

                // FIXME: this might panic if the payload is malformed.
                let details = payload.relocate_details();

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
                (MIN_AGE + 1, None, None)
            };

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

        self.vote(Vote::Online {
            member_info: MemberInfo::joined(peer.with_age(age)),
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
        key_index: u64,
    ) -> Result<Vec<Command>> {
        trace!("Received DKGStart for {}", new_elders_info);
        self.dkg_voter
            .start(&self.node.keypair, dkg_key, new_elders_info, key_index)
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
        elders_info: EldersInfo,
        proofs: &DkgFailureProofSet,
    ) -> Result<Vec<Command>> {
        let sender = &self
            .section
            .members()
            .get(sender)
            .ok_or(Error::InvalidSrcLocation)?
            .peer;

        if !proofs.verify(&elders_info) {
            error!(
                "Ignore DKG failure agreement with invalid proofs: {}",
                elders_info
            );
            return Ok(vec![]);
        }

        if !self
            .section
            .promote_and_demote_elders(&self.node.name())
            .contains(&elders_info)
        {
            trace!(
                "Ignore DKG failure agreement for outdated participants: {}",
                elders_info
            );
            return Ok(vec![]);
        }

        trace!(
            "Received DKG failure agreement - restarting: {}",
            elders_info
        );

        self.send_dkg_start_to(elders_info, slice::from_ref(sender))
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

        // Do not carry out relocation when there is not enough elder nodes.
        if self.section.elders_info().elders.len() < ELDER_SIZE {
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

    // Are we in the startup phase? Startup phase is when the network consists of only one section
    // and it has no more than `recommended_section_size` members.
    fn is_in_startup_phase(&self) -> bool {
        self.section.prefix().is_empty()
            && self.section.members().joined().count() <= RECOMMENDED_SECTION_SIZE
    }

    fn handle_online_event(
        &mut self,
        new_info: MemberInfo,
        previous_name: Option<XorName>,
        their_knowledge: Option<bls::PublicKey>,
        proof: Proof,
    ) -> Result<Vec<Command>> {
        let mut commands = vec![];

        let is_startup_phase = self.is_in_startup_phase();

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
            startup_relocation: is_startup_phase,
        });

        commands
            .extend(self.relocate_peers(new_info.value.peer.name(), &new_info.proof.signature)?);
        commands.extend(self.promote_and_demote_elders()?);
        commands.push(self.send_node_approval(new_info, their_knowledge)?);

        self.print_network_stats();

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
        let mut commands = vec![];

        let prefix_is_equal = elders_info.prefix == *self.section.prefix();
        let prefix_is_extension = elders_info.prefix.is_extension_of(self.section.prefix());

        let elders_info = Proven::new(elders_info, proof);

        if prefix_is_equal || prefix_is_extension {
            // Our section
            if self
                .section
                .promote_and_demote_elders(&self.node.name())
                .contains(&elders_info.value)
            {
                if prefix_is_extension {
                    commands.extend(self.vote(Vote::TheirKey {
                        prefix: elders_info.value.prefix,
                        key: elders_info.proof.public_key,
                    })?);
                }

                commands.extend(self.vote(Vote::OurElders(elders_info))?);
            }
        } else if self.network.update_neighbour_info(elders_info) {
            // Other section
            self.network.prune_neighbours(self.section.prefix());
        }

        Ok(commands)
    }

    fn handle_our_elders_event(
        &mut self,
        elders_info: Proven<EldersInfo>,
        key_proof: Proof,
    ) -> Result<Vec<Command>> {
        self.split_barrier.handle_our_section(
            &self.node.name(),
            &self.section,
            &self.network,
            elders_info,
            key_proof,
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
            self.split_barrier.handle_their_key(
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

    fn try_update_state(&mut self) -> Result<Vec<Command>> {
        let mut commands = vec![];

        let (our, sibling) = self.split_barrier.take(self.section.prefix());

        if let Some(our) = our {
            trace!("update our section: {:?}", our.section.elders_info());
            commands.extend(self.update_state(our.section, our.network)?);
        }

        if let Some(sibling) = sibling {
            trace!(
                "update sibling section: {:?}",
                sibling.section.elders_info()
            );

            if self.section_keys_provider.has_key_share() {
                // We can update the sibling knowledge already because we know they also reached
                // consensus on our `OurKey` so they know our latest key. Need to vote for it first
                // though, to accumulate the signatures.
                commands.extend(self.vote(Vote::TheirKnowledge {
                    prefix: *sibling.section.prefix(),
                    key_index: self.section.chain().last_key_index(),
                })?);
            }

            commands.extend(self.send_sync(sibling.section, sibling.network)?);
        }

        Ok(commands)
    }

    fn update_state(&mut self, section: Section, network: Network) -> Result<Vec<Command>> {
        let mut commands = vec![];

        let old_is_elder = self.is_elder();
        let old_last_key = *self.section.chain().last_key();
        let old_prefix = *self.section.prefix();

        self.section.merge(section)?;
        self.network.merge(network, self.section.chain());

        self.section_keys_provider
            .finalise_dkg(self.section.chain().last_key());

        let new_is_elder = self.is_elder();
        let new_last_key = *self.section.chain().last_key();
        let new_prefix = *self.section.prefix();

        if new_prefix != old_prefix {
            info!("Split");

            if new_is_elder && self.section_keys_provider.has_key_share() {
                // We can update the sibling knowledge already because we know they also reached
                // consensus on our `OurKey` so they know our latest key. Need to vote for it first
                // though, to accumulate the signatures.
                commands.extend(self.vote(Vote::TheirKnowledge {
                    prefix: new_prefix.sibling(),
                    key_index: self.section.chain().last_key_index(),
                })?);
            }
        }

        if new_last_key != old_last_key {
            self.msg_filter.reset();

            if new_is_elder {
                info!(
                    "Section updated: prefix: ({:b}), key: {:?}, elders: {}",
                    self.section.prefix(),
                    self.section.chain().last_key(),
                    self.section.elders_info().peers().format(", ")
                );

                if self.section_keys_provider.has_key_share() {
                    commands.extend(self.promote_and_demote_elders()?);
                    // Whenever there is an elders change, casting a round of joins_allowed vote to sync.
                    commands.extend(self.vote(Vote::JoinsAllowed(self.joins_allowed))?);
                }

                self.print_network_stats();
            }

            if new_is_elder || old_is_elder {
                commands.extend(self.send_sync(self.section.clone(), self.network.clone())?);
            }

            let self_status_change = if !old_is_elder && new_is_elder {
                info!("Promoted to elder");
                NodeElderChange::Promoted
            } else if old_is_elder && !new_is_elder {
                info!("Demoted");
                self.section = self.section.trimmed(1);
                self.network = Network::new();
                self.section_keys_provider = SectionKeysProvider::new(KEY_CACHE_SIZE, None);
                NodeElderChange::Demoted
            } else {
                NodeElderChange::None
            };

            self.send_event(Event::EldersChanged {
                prefix: *self.section.prefix(),
                key: *self.section.chain().last_key(),
                elders: self.section.elders_info().elders.keys().copied().collect(),
                self_status_change,
            });
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
        let last_index = self.section.chain().last_key_index();
        let their_knowledge_index = their_knowledge
            .and_then(|key| self.section.chain().index_of(&key))
            .unwrap_or(last_index);
        let member_info_key_index = self
            .section
            .chain()
            .index_of(&member_info.proof.public_key)
            .unwrap_or(last_index);
        let start_index = their_knowledge_index.min(member_info_key_index);
        let proof_chain = self.section.chain().slice(start_index..);

        let variant = Variant::NodeApproval {
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
        trace!("Send DKGStart for {} to {:?}", elders_info, recipients);

        let dkg_key = DkgKey::new(&elders_info);
        let variant = Variant::DKGStart {
            dkg_key,
            elders_info,
            key_index: self.section.chain().last_key_index() + 1,
        };
        let vote = self.create_send_message_vote(DstLocation::Direct, variant, None)?;
        self.send_vote(recipients, vote)
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

    // Setting the JoinsAllowed triggers a round Vote::SetJoinsAllowed to update the flag.
    pub fn set_joins_allowed(&mut self, joins_allowed: bool) -> Result<Vec<Command>> {
        let mut commands = Vec::new();
        if self.is_elder() && joins_allowed != self.joins_allowed {
            commands.extend(self.vote(Vote::JoinsAllowed(joins_allowed))?);
        }
        Ok(commands)
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
            return Err(Error::InvalidSrcLocation);
        }

        if matches!(dst, DstLocation::Direct) {
            error!(
                "Not sending user message {:?} -> {:?}: direct dst not supported",
                src, dst
            );
            return Err(Error::InvalidDstLocation);
        }

        let variant = Variant::UserMessage(content);

        match src {
            SrcLocation::Node(_) => {
                // If the source is a single node, we don't even need to vote, so let's cut this short.
                let msg = Message::single_src(&self.node, dst, variant, None, None)?;
                let mut commands = vec![];

                if dst.contains(&self.node.name(), self.section.prefix()) {
                    commands.push(Command::HandleMessage {
                        sender: Some(self.node.addr),
                        message: msg.clone(),
                    });
                }

                commands.extend(self.relay_message(&msg)?);

                Ok(commands)
            }
            SrcLocation::Section(_) => {
                let vote = self.create_send_message_vote(dst, variant, None)?;
                let recipients = delivery_group::signature_targets(
                    &dst,
                    self.section.elders_info().peers().copied(),
                );
                self.send_vote(&recipients, vote)
            }
            SrcLocation::EndUser(_) => Err(Error::InvalidSrcLocation),
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
            *self.section_key_by_name(&name)
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
