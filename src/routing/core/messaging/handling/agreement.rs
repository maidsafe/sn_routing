// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use std::cmp;

use crate::{
    agreement::ProvenUtils,
    error::Result,
    messages::RoutingMsgUtils,
    network::NetworkUtils,
    peer::PeerUtils,
    routing::command::Command,
    section::{
        ElderCandidatesUtils, SectionAuthorityProviderUtils, SectionPeersUtils, SectionUtils,
    },
    Error, Event, MIN_AGE,
};
use bls_signature_aggregator::Proof;
use secured_linked_list::SecuredLinkedList;
use sn_messaging::{
    node::{
        MemberInfo, PeerState, PlainMessage, Proposal, Proven, RoutingMsg,
        SectionAuthorityProvider, Variant,
    },
    DestInfo, DstLocation,
};
use xor_name::XorName;

use super::Core;

// Agreement
impl Core {
    pub(crate) fn handle_agreement(
        &mut self,
        proposal: Proposal,
        proof: Proof,
    ) -> Result<Vec<Command>> {
        debug!("handle agreement on {:?}", proposal);

        match proposal {
            Proposal::Online {
                member_info,
                previous_name,
                their_knowledge,
            } => self.handle_online_agreement(member_info, previous_name, their_knowledge, proof),
            Proposal::Offline(member_info) => self.handle_offline_agreement(member_info, proof),
            Proposal::SectionInfo(section_auth) => {
                self.handle_section_info_agreement(section_auth, proof)
            }
            Proposal::OurElders(section_auth) => {
                self.handle_our_elders_agreement(section_auth, proof)
            }
            Proposal::AccumulateAtSrc {
                message,
                proof_chain,
            } => {
                let dest_name = if let Some(name) = message.dst.name() {
                    name
                } else {
                    error!(
                        "Not handling AccumulateAtSrc {:?}: No dst_name found",
                        *message
                    );
                    return Err(Error::InvalidDstLocation);
                };
                let dest_section_pk = message.dst_key;
                Ok(vec![self.handle_accumulate_at_src_agreement(
                    *message,
                    proof_chain,
                    proof,
                    DestInfo {
                        dest: dest_name,
                        dest_section_pk,
                    },
                )?])
            }
            Proposal::JoinsAllowed(joins_allowed) => {
                self.joins_allowed = joins_allowed;
                Ok(vec![])
            }
        }
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

        let result = self.promote_and_demote_elders()?;
        if result.is_empty() {
            commands.extend(self.send_sync_to_adults()?);
        }

        commands.extend(result);
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

        let result = self.promote_and_demote_elders()?;
        if result.is_empty() {
            commands.extend(self.send_sync_to_adults()?);
        }

        commands.extend(result);

        self.send_event(Event::MemberLeft {
            name: *peer.name(),
            age,
        });

        Ok(commands)
    }

    fn handle_section_info_agreement(
        &mut self,
        section_auth: SectionAuthorityProvider,
        proof: Proof,
    ) -> Result<Vec<Command>> {
        let mut commands = vec![];

        let equal_or_extension = section_auth.prefix() == *self.section.prefix()
            || section_auth.prefix().is_extension_of(self.section.prefix());
        let section_auth = Proven::new(section_auth, proof.clone());

        if equal_or_extension {
            // Our section of sub-section

            let infos = self.section.promote_and_demote_elders(&self.node.name());
            if !infos.contains(&section_auth.value.elder_candidates()) {
                // SectionInfo out of date, ignore.
                return Ok(commands);
            }

            // Send a `Sync` message to all the to-be-promoted members so they have the full
            // section and network data.
            let sync_recipients: Vec<_> = infos
                .iter()
                .flat_map(|info| info.peers())
                .filter(|peer| !self.section.is_elder(peer.name()))
                .map(|peer| (*peer.name(), *peer.addr()))
                .collect();
            if !sync_recipients.is_empty() {
                let sync_message = RoutingMsg::single_src(
                    &self.node,
                    DstLocation::DirectAndUnrouted,
                    Variant::Sync {
                        section: self.section.clone(),
                        network: self.network.clone(),
                    },
                    None,
                )?;
                let len = sync_recipients.len();
                commands.push(Command::send_message_to_nodes(
                    sync_recipients,
                    len,
                    sync_message,
                    DestInfo {
                        dest: XorName::random(),
                        dest_section_pk: proof.public_key,
                    },
                ));
            }

            // Send the `OurElder` proposal to all of the to-be-elders so it's aggregated by them.
            let our_elders_recipients: Vec<_> =
                infos.iter().flat_map(|info| info.peers()).collect();
            commands.extend(
                self.send_proposal(&our_elders_recipients, Proposal::OurElders(section_auth))?,
            );
        } else {
            // Other section

            let _ = self
                .network
                .update_section(section_auth, None, self.section.chain());
        }

        Ok(commands)
    }

    fn handle_our_elders_agreement(
        &mut self,
        section_auth: Proven<SectionAuthorityProvider>,
        key_proof: Proof,
    ) -> Result<Vec<Command>> {
        let updates = self
            .split_barrier
            .process(self.section.prefix(), section_auth, key_proof);
        if updates.is_empty() {
            return Ok(vec![]);
        }

        let snapshot = self.state_snapshot();

        for (section_auth, key_proof) in updates {
            if section_auth.value.prefix.matches(&self.node.name()) {
                let _ = self.section.update_elders(section_auth, key_proof);
            } else {
                let _ = self.network.update_section(
                    section_auth,
                    Some(key_proof),
                    self.section.chain(),
                );
            }
        }

        self.update_state(snapshot)
    }

    fn handle_accumulate_at_src_agreement(
        &self,
        message: PlainMessage,
        proof_chain: SecuredLinkedList,
        proof: Proof,
        dest_info: DestInfo,
    ) -> Result<Command> {
        let message = RoutingMsg::section_src(message, proof, proof_chain)?;

        Ok(Command::HandleMessage {
            message,
            sender: None,
            dest_info,
        })
    }
}
