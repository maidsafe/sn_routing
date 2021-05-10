// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod agreement;
mod bad_msgs;
mod decisions;
mod relocation;
mod resource_proof;

use super::super::Core;
use crate::{
    agreement::{DkgCommands, DkgFailureProofSet, ProofShare, Proposal, ProposalError},
    error::{Error, Result},
    event::Event,
    messages::{JoinRequest, Message, MessageStatus, SrcAuthority, Variant, VerifyStatus},
    network::Network,
    peer::Peer,
    relocation::{RelocateState, SignedRelocateDetails},
    routing::command::Command,
    section::{
        Section, SectionAuthorityProvider, SectionKeyShare, FIRST_SECTION_MAX_AGE,
        FIRST_SECTION_MIN_AGE, MIN_ADULT_AGE,
    },
};
use bls_signature_aggregator::Error as AggregatorError;
use bytes::Bytes;
use sn_messaging::{
    client::Message as ClientMessage,
    node::NodeMessage,
    section_info::Error as TargetSectionError,
    section_info::{GetSectionResponse, Message as SectionInfoMsg, SectionInfo},
    DstLocation, EndUser, MessageType,
};
use std::{collections::BTreeSet, iter, net::SocketAddr};

// Message handling
impl Core {
    pub(crate) async fn handle_message(
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
            MessageStatus::Useless => {
                debug!("Useless message from {:?}: {:?}", sender, msg);
            }
        }

        Ok(commands)
    }

    pub(crate) async fn handle_section_info_msg(
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
                        prefix: self.section.authority_provider().prefix,
                        pk_set,
                        elders: self
                            .section
                            .authority_provider()
                            .peers()
                            .map(|peer| (*peer.name(), *peer.addr()))
                            .collect(),
                        joins_allowed: self.joins_allowed,
                    })
                } else {
                    // If we are elder, we should know a section that is closer to `name` that us.
                    // Otherwise redirect to our elders.
                    let section = self
                        .network
                        .closest(&name)
                        .unwrap_or_else(|| self.section.authority_provider());
                    let addrs = section.elders.values().copied().collect();
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
                trace!("Try adding enduser {} from {}", end_user, sender);
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

    pub(crate) fn handle_timeout(&mut self, token: u64) -> Result<Vec<Command>> {
        self.dkg_voter
            .handle_timeout(&self.node.keypair, token)
            .into_commands(&self.node)
    }

    // Insert the proposal into the proposal aggregator and handle it if aggregated.
    pub(crate) fn handle_proposal(
        &mut self,
        proposal: Proposal,
        proof_share: ProofShare,
    ) -> Result<Vec<Command>> {
        match self.proposal_aggregator.add(proposal, proof_share) {
            Ok((proposal, proof)) => Ok(vec![Command::HandleAgreement { proposal, proof }]),
            Err(ProposalError::Aggregation(bls_signature_aggregator::Error::NotEnoughShares)) => {
                Ok(vec![])
            }
            Err(error) => {
                error!("Failed to add proposal: {}", error);
                Err(Error::InvalidSignatureShare)
            }
        }
    }

    pub(crate) fn handle_dkg_outcome(
        &mut self,
        section_auth: SectionAuthorityProvider,
        key_share: SectionKeyShare,
    ) -> Result<Vec<Command>> {
        let proposal = Proposal::SectionInfo(section_auth);
        let recipients: Vec<_> = self.section.authority_provider().peers().collect();
        let result = self.send_proposal_with(&recipients, proposal, &key_share);

        let public_key = key_share.public_key_set.public_key();

        self.section_keys_provider.insert_dkg_outcome(key_share);

        if self.section.chain().has_key(&public_key) {
            self.section_keys_provider.finalise_dkg(&public_key)
        }

        result
    }

    pub(crate) fn handle_dkg_failure(&mut self, proofs: DkgFailureProofSet) -> Result<Command> {
        let variant = Variant::DkgFailureAgreement(proofs);
        let message = Message::single_src(&self.node, DstLocation::Direct, variant, None, None)?;
        Ok(self.send_message_to_our_elders(message.to_bytes()))
    }

    pub(crate) fn aggregate_message(&mut self, msg: Message) -> Result<Option<Message>> {
        let proof_share = if let SrcAuthority::BlsShare { proof_share, .. } = msg.src() {
            proof_share
        } else {
            // Not an aggregating message, return unchanged.
            return Ok(Some(msg));
        };

        let signed_bytes =
            bincode::serialize(&msg.signable_view()).map_err(|_| Error::InvalidMessage)?;
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

    pub(crate) async fn handle_useful_message(
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
            Variant::OtherSection { section_auth, .. } => {
                self.handle_other_section(section_auth.value.clone(), *msg.proof_chain_last_key()?)
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
            Variant::DkgStart {
                dkg_key,
                section_auth,
            } => self.handle_dkg_start(*dkg_key, section_auth.clone()),
            Variant::DkgMessage { dkg_key, message } => {
                self.handle_dkg_message(*dkg_key, message.clone(), msg.src().name())
            }
            Variant::DkgFailureObservation {
                dkg_key,
                proof,
                non_participants,
            } => self.handle_dkg_failure_observation(*dkg_key, non_participants, *proof),
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
            Variant::ConnectivityComplaint(elder_name) => {
                self.handle_connectivity_complaint(msg.src().name(), *elder_name)
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

    pub(crate) fn verify_message(&self, msg: &Message) -> Result<bool> {
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

    pub(crate) fn handle_other_section(
        &self,
        section_auth: SectionAuthorityProvider,
        src_key: bls::PublicKey,
    ) -> Result<Vec<Command>> {
        let mut commands = vec![];

        if !self.network.has_key(&src_key) {
            commands.extend(self.propose(Proposal::TheirKey {
                prefix: section_auth.prefix,
                key: src_key,
            })?);
        } else {
            trace!(
                "Ignore not new section key of {:?}: {:?}",
                section_auth,
                src_key
            );
            return Ok(commands);
        }

        commands.extend(self.propose(Proposal::SectionInfo(section_auth))?);

        Ok(commands)
    }

    pub(crate) fn handle_user_message(
        &mut self,
        msg: &Message,
        content: Bytes,
    ) -> Result<Vec<Command>> {
        trace!("handle user message {:?}", msg);
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
                trace!("Cannot route user message, recipient list empty: {:?}", msg);
                return Err(Error::EmptyRecipientList);
            };
            trace!("sending user message {:?} to client {:?}", msg, recipients);
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
            proof: msg.proof(),
            proof_chain: msg.proof_chain().ok().cloned(),
        });
        Ok(vec![])
    }

    pub(crate) fn handle_sync(
        &mut self,
        section: Section,
        network: Network,
    ) -> Result<Vec<Command>> {
        if !section.prefix().matches(&self.node.name()) {
            trace!("ignore Sync - not our section");
            return Ok(vec![]);
        }

        let old_adults: BTreeSet<_> = self
            .section
            .live_adults()
            .map(|p| p.name())
            .copied()
            .collect();

        let snapshot = self.state_snapshot();
        trace!(
            "Updating knowledge of own section \n    elders: {:?} \n    members: {:?}",
            section.authority_provider(),
            section.members()
        );
        self.section.merge(section)?;
        self.network.merge(network, self.section.chain());

        if !self.is_elder() {
            let current_adults: BTreeSet<_> = self
                .section
                .live_adults()
                .map(|p| p.name())
                .copied()
                .collect();
            let added: BTreeSet<_> = current_adults.difference(&old_adults).copied().collect();
            let removed: BTreeSet<_> = old_adults.difference(&current_adults).copied().collect();

            if !added.is_empty() || !removed.is_empty() {
                self.send_event(Event::AdultsChanged {
                    remaining: old_adults.intersection(&current_adults).copied().collect(),
                    added,
                    removed,
                });
            }
        }

        self.update_state(snapshot)
    }

    pub(crate) fn handle_join_request(
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
                section_auth: self.section.authority_provider().clone(),
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

        Ok(vec![Command::TestConnectivity {
            peer,
            previous_name,
            their_knowledge,
        }])
    }

    // Generate a new section info based on the current set of members and if it differs from the
    // current elders, trigger a DKG.
    pub(crate) fn promote_and_demote_elders(&mut self) -> Result<Vec<Command>> {
        let mut commands = vec![];

        for info in self.section.promote_and_demote_elders(&self.node.name()) {
            commands.extend(self.send_dkg_start(info)?);
        }

        Ok(commands)
    }

    /* FIXME: bring back unresponsiveness detection
    // Detect non-responsive peers and vote them out.
    pub(crate) fn vote_for_remove_unresponsive_peers(&mut self, core: &mut Core) -> Result<()> {
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
}
