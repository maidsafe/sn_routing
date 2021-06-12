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
    dkg::{DkgCommands, ProposalError, SignedShare},
    error::{Error, Result},
    event::Event,
    messages::{MessageStatus, RoutingMsgUtils, SrcAuthorityUtils, VerifyStatus},
    network::NetworkUtils,
    peer::PeerUtils,
    relocation::{RelocatePayloadUtils, RelocateState, SignedRelocateDetailsUtils},
    routing::command::Command,
    section::{
        SectionAuthorityProviderUtils, SectionKeyShare, SectionPeersUtils, SectionUtils,
        FIRST_SECTION_MAX_AGE, FIRST_SECTION_MIN_AGE, MIN_ADULT_AGE,
    },
};
use bytes::Bytes;
use sn_messaging::node::Error as AggregatorError;
use sn_messaging::{
    client::ClientMsg,
    node::{
        DkgFailureSignedSet, JoinRejectionReason, JoinRequest, JoinResponse, Network, Peer,
        Proposal, RoutingMsg, Section, SignedRelocateDetails, SrcAuthority, Variant,
    },
    section_info::{GetSectionResponse, SectionInfoMsg},
    DestInfo, DstLocation, EndUser, MessageType, SectionAuthorityProvider,
};
use std::{collections::BTreeSet, iter, net::SocketAddr};
use xor_name::XorName;

// Message handling
impl Core {
    pub(crate) async fn handle_message(
        &mut self,
        sender: Option<SocketAddr>,
        msg: RoutingMsg,
        dest_info: DestInfo,
    ) -> Result<Vec<Command>> {
        let mut commands = vec![];

        // Check if the message is for us.
        let in_dst_location = msg.dst.contains(&self.node.name(), self.section.prefix());
        // TODO: Broadcast message to our section when src is a Node as nodes might not know
        // all the elders in our section and the msg needs to be propagated.
        if !in_dst_location {
            info!("Relay closer to the destination");
            if let Some(cmds) = self.relay_message(&msg).await? {
                commands.push(cmds);
            }
        }
        if !in_dst_location {
            // RoutingMsg not for us.
            return Ok(commands);
        }

        match self.decide_message_status(&msg)? {
            MessageStatus::Useful => {
                trace!("Useful message from {:?}: {:?}", sender, msg);
                let (entropy_commands, shall_be_handled) =
                    self.check_for_entropy(&msg, dest_info.clone()).await?;
                commands.extend(entropy_commands);
                if shall_be_handled {
                    info!("Entropy check passed. Handling useful msg!");
                    commands.extend(self.handle_useful_message(sender, msg, dest_info).await?);
                }
            }
            MessageStatus::Untrusted => {
                debug!("Untrusted message from {:?}: {:?} ", sender, msg);
                commands.push(self.handle_untrusted_message(sender, msg, dest_info)?);
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
        dest_info: DestInfo, // The DestInfo contains the XorName of the sender and a random PK during the initial SectionQuery,
    ) -> Vec<Command> {
        // Provide our PK as the dest PK, only redundant as the message
        // itself contains details regarding relocation/registration.
        let dest_info = DestInfo {
            dest: dest_info.dest,
            dest_section_pk: *self.section().chain().last_key(),
        };

        match message {
            SectionInfoMsg::GetSectionQuery(public_key) => {
                let name = XorName::from(public_key);

                debug!("Received GetSectionQuery({}) from {}", name, sender);

                let response = if let (true, Ok(pk_set)) =
                    (self.section.prefix().matches(&name), self.public_key_set())
                {
                    GetSectionResponse::Success(SectionAuthorityProvider {
                        prefix: self.section.authority_provider().prefix(),
                        public_key_set: pk_set,
                        elders: self
                            .section
                            .authority_provider()
                            .peers()
                            .map(|peer| (*peer.name(), *peer.addr()))
                            .collect(),
                    })
                } else {
                    // If we are elder, we should know a section that is closer to `name` that us.
                    // Otherwise redirect to our elders.
                    let section_auth = self
                        .network
                        .closest(&name)
                        .unwrap_or_else(|| self.section.authority_provider());
                    GetSectionResponse::Redirect(section_auth.clone())
                };

                let response = SectionInfoMsg::GetSectionResponse(response);
                debug!("Sending {:?} to {}", response, sender);

                vec![Command::SendMessage {
                    recipients: vec![(name, sender)],
                    delivery_group_size: 1,
                    message: MessageType::SectionInfo {
                        msg: response,
                        dest_info,
                    },
                }]
            }
            SectionInfoMsg::GetSectionResponse(_) => {
                if let Some(RelocateState::InProgress(tx)) = &mut self.relocate_state {
                    trace!("Forwarding {:?} to the bootstrap task", message);
                    let _ = tx
                        .send((
                            MessageType::SectionInfo {
                                msg: message,
                                dest_info,
                            },
                            sender,
                        ))
                        .await;
                }
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
            .into_commands(&self.node, *self.section_chain().last_key())
    }

    // Insert the proposal into the proposal aggregator and handle it if aggregated.
    pub(crate) fn handle_proposal(
        &mut self,
        proposal: Proposal,
        signed_share: SignedShare,
    ) -> Result<Vec<Command>> {
        match self.proposal_aggregator.add(proposal, signed_share) {
            Ok((proposal, signed)) => Ok(vec![Command::HandleAgreement { proposal, signed }]),
            Err(ProposalError::Aggregation(sn_messaging::node::Error::NotEnoughShares)) => {
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

    pub(crate) fn handle_dkg_failure(&mut self, signeds: DkgFailureSignedSet) -> Result<Command> {
        let variant = Variant::DkgFailureAgreement(signeds);
        let message = RoutingMsg::single_src(
            &self.node,
            DstLocation::DirectAndUnrouted,
            variant,
            self.section.authority_provider().section_key(),
        )?;
        Ok(self.send_message_to_our_elders(message))
    }

    pub(crate) fn aggregate_message(&mut self, msg: RoutingMsg) -> Result<Option<RoutingMsg>> {
        let signed_share = if let SrcAuthority::BlsShare { signed_share, .. } = &msg.src {
            signed_share
        } else {
            // Not an aggregating message, return unchanged.
            return Ok(Some(msg));
        };

        let signed_bytes =
            bincode::serialize(&msg.signable_view()).map_err(|_| Error::InvalidMessage)?;
        match self
            .message_aggregator
            .add(&signed_bytes, signed_share.clone())
        {
            Ok(signed) => {
                trace!("Successfully accumulated signatures for message: {:?}", msg);
                Ok(Some(msg.into_dst_accumulated(signed)?))
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
        msg: RoutingMsg,
        dest_info: DestInfo,
    ) -> Result<Vec<Command>> {
        let msg = if let Some(msg) = self.aggregate_message(msg)? {
            msg
        } else {
            return Ok(vec![]);
        };
        let src_name = msg.src.name();

        match &msg.variant {
            Variant::SectionKnowledge { src_info, msg } => {
                let src_info = src_info.clone();
                self.update_section_knowledge(src_info.0, src_info.1);
                if let Some(bounced_msg) = msg {
                    Ok(vec![Command::HandleMessage {
                        sender,
                        message: *bounced_msg.clone(),
                        dest_info,
                    }])
                } else {
                    Ok(vec![])
                }
            }
            Variant::Sync { section, network } => {
                self.handle_sync(section.clone(), network.clone()).await
            }
            Variant::Relocate(_) => {
                if msg.src.is_section() {
                    let signed_relocate = SignedRelocateDetails::new(msg.clone())?;
                    Ok(self
                        .handle_relocate(signed_relocate)
                        .await?
                        .into_iter()
                        .collect())
                } else {
                    Err(Error::InvalidSrcLocation)
                }
            }
            Variant::RelocatePromise(promise) => {
                self.handle_relocate_promise(*promise, msg.clone()).await
            }
            Variant::StartConnectivityTest(name) => Ok(vec![Command::TestConnectivity(*name)]),
            Variant::JoinRequest(join_request) => {
                let sender = sender.ok_or(Error::InvalidSrcLocation)?;
                self.handle_join_request(msg.src.peer(sender)?, *join_request.clone())
            }
            Variant::UserMessage(content) => {
                let bytes = Bytes::from(content.clone());
                self.handle_user_message(msg, bytes).await
            }
            Variant::BouncedUntrustedMessage {
                msg: bounced_msg,
                dest_info,
            } => {
                let sender = sender.ok_or(Error::InvalidSrcLocation)?;
                Ok(vec![self.handle_bounced_untrusted_message(
                    msg.src.peer(sender)?,
                    dest_info.dest_section_pk,
                    *bounced_msg.clone(),
                )?])
            }
            Variant::SectionKnowledgeQuery {
                last_known_key,
                msg: returned_msg,
            } => {
                let sender = sender.ok_or(Error::InvalidSrcLocation)?;
                Ok(vec![self.handle_section_knowledge_query(
                    *last_known_key,
                    returned_msg.clone(),
                    sender,
                    src_name,
                    msg.src.src_location().to_dst(),
                )?])
            }
            Variant::DkgStart {
                dkg_key,
                elder_candidates,
            } => self.handle_dkg_start(*dkg_key, elder_candidates.clone()),
            Variant::DkgMessage { dkg_key, message } => {
                self.handle_dkg_message(*dkg_key, message.clone(), src_name)
            }
            Variant::DkgFailureObservation {
                dkg_key,
                signed,
                non_participants,
            } => self.handle_dkg_failure_observation(*dkg_key, non_participants, *signed),
            Variant::DkgFailureAgreement(signeds) => {
                self.handle_dkg_failure_agreement(&msg.src.name(), signeds)
            }
            Variant::Propose {
                content,
                signed_share,
            } => {
                let mut commands = vec![];
                let result = self.handle_proposal(content.clone(), signed_share.clone());

                if let Some(addr) = sender {
                    commands.extend(self.check_lagging((src_name, addr), signed_share)?);
                }

                commands.extend(result?);
                Ok(commands)
            }
            Variant::JoinResponse(_) => {
                if let Some(RelocateState::InProgress(message_tx)) = &mut self.relocate_state {
                    if let Some(sender) = sender {
                        trace!("Forwarding {:?} to the bootstrap task", msg);
                        let _ = message_tx
                            .send((
                                MessageType::Routing {
                                    msg: msg.clone(),
                                    dest_info: DestInfo {
                                        dest: src_name,
                                        dest_section_pk: *self.section.chain().last_key(),
                                    },
                                },
                                sender,
                            ))
                            .await;
                    } else {
                        error!("Missing sender of {:?}", msg);
                    }
                }

                Ok(vec![])
            }
        }
    }

    fn handle_section_knowledge_query(
        &self,
        given_key: Option<bls::PublicKey>,
        msg: Box<RoutingMsg>,
        sender: SocketAddr,
        src_name: XorName,
        dst_location: DstLocation,
    ) -> Result<Command> {
        let chain = self.section.chain();
        let given_key = if let Some(key) = given_key {
            key
        } else {
            *self.section_chain().root_key()
        };
        let truncated_chain = chain.get_proof_chain_to_current(&given_key)?;
        let section_auth = self.section.proven_authority_provider();
        let variant = Variant::SectionKnowledge {
            src_info: (section_auth.clone(), truncated_chain),
            msg: Some(msg),
        };

        let msg = RoutingMsg::single_src(
            self.node(),
            dst_location,
            variant,
            self.section.authority_provider().section_key(),
        )?;
        let key = self.section_key_by_name(&src_name);
        Ok(Command::send_message_to_node(
            (src_name, sender),
            msg,
            DestInfo {
                dest: src_name,
                dest_section_pk: key,
            },
        ))
    }

    pub(crate) fn verify_message(&self, msg: &RoutingMsg) -> Result<bool> {
        let known_keys: Vec<bls::PublicKey> = self
            .section
            .chain()
            .keys()
            .copied()
            .chain(self.network.keys().map(|(_, key)| key))
            .chain(iter::once(*self.section.genesis_key()))
            .collect();

        match msg.verify(known_keys.iter()) {
            Ok(VerifyStatus::Full) => Ok(true),
            Ok(VerifyStatus::Unknown) => Ok(false),
            Err(error) => {
                warn!("Verification of {:?} failed: {}", msg, error);
                Err(error)
            }
        }
    }

    async fn handle_user_message(
        &mut self,
        msg: RoutingMsg,
        content: Bytes,
    ) -> Result<Vec<Command>> {
        trace!("handle user message {:?}", msg);
        if let DstLocation::EndUser(EndUser {
            xorname: xor_name,
            socket_id,
        }) = msg.dst
        {
            if let Some(socket_addr) = self.get_socket_addr(socket_id).copied() {
                trace!("sending user message {:?} to client {:?}", msg, socket_addr);
                return Ok(vec![Command::SendMessage {
                    recipients: vec![(xor_name, socket_addr)],
                    delivery_group_size: 1,
                    message: MessageType::Client {
                        msg: ClientMsg::from(content)?,
                        dest_info: DestInfo {
                            dest: xor_name,
                            dest_section_pk: *self.section.chain().last_key(),
                        },
                    },
                }]);
            } else {
                trace!(
                    "Cannot route user message, socket id not found for {:?}",
                    msg
                );
                return Err(Error::EmptyRecipientList);
            }
        }

        self.send_event(Event::MessageReceived {
            content,
            src: msg.src.src_location(),
            dst: msg.dst,
            signed: msg.signed(),
            section_pk: msg.section_pk,
        })
        .await;

        Ok(vec![])
    }

    pub(crate) async fn handle_sync(
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
                })
                .await;
            }
        }

        self.update_state(snapshot).await
    }

    pub(crate) fn handle_join_request(
        &mut self,
        peer: Peer,
        join_request: JoinRequest,
    ) -> Result<Vec<Command>> {
        debug!("Received {:?} from {}", join_request, peer);

        if !self.section.prefix().matches(peer.name())
            || join_request.section_key != *self.section.chain().last_key()
        {
            debug!(
                "JoinRequest from {} - name doesn't match our prefix {:?}.",
                peer,
                self.section.prefix()
            );

            let variant = Variant::JoinResponse(Box::new(JoinResponse::Retry(
                self.section.authority_provider().clone(),
            )));
            trace!("Sending {:?} to {}", variant, peer);
            return Ok(vec![self.send_direct_message(
                (*peer.name(), *peer.addr()),
                variant,
                *self.section.chain().last_key(),
            )?]);
        }

        if self.section.members().is_joined(peer.name()) {
            debug!(
                "Ignoring JoinRequest from {} - already member of our section.",
                peer
            );
            return Ok(vec![]);
        }

        // This joining node is being relocated to us.
        let (mut age, previous_name, destination_key) =
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
                    "Rejecting JoinRequest from {} - joins currently not allowed.",
                    peer,
                );
                let variant = Variant::JoinResponse(Box::new(JoinResponse::Rejected(
                    JoinRejectionReason::JoinsDisallowed,
                )));
                trace!("Sending {:?} to {}", variant, peer);
                return Ok(vec![self.send_direct_message(
                    (*peer.name(), *peer.addr()),
                    variant,
                    *self.section.chain().last_key(),
                )?]);
            } else {
                // Start as Adult as long as passed resource signeding.
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

        // Require resource signed only if joining as a new node.
        if previous_name.is_none() {
            if let Some(response) = join_request.resource_proof_response {
                if !self.validate_resource_proof_response(peer.name(), response) {
                    debug!(
                        "Ignoring JoinRequest from {} - invalid resource signed response",
                        peer
                    );
                    return Ok(vec![]);
                }
            } else {
                return Ok(vec![self.send_resource_proof_challenge(&peer)?]);
            }
        }

        Ok(vec![Command::ProposeOnline {
            peer,
            previous_name,
            destination_key,
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
}
