// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::Base;
use crate::{
    chain::{
        AccumulatedEvent, AccumulatingEvent, Chain, EldersChange, EldersInfo, MemberState,
        OnlinePayload, PollAccumulated, Proof, ProofSet, SectionKeyInfo, SendAckMessagePayload,
    },
    error::{Result, RoutingError},
    event::Event,
    id::{P2pNode, PublicId},
    messages::VerifyStatus,
    outbox::EventBox,
    parsec::{self, Block, DkgResultWrapper, Observation, ParsecMap},
    relocation::{RelocateDetails, SignedRelocateDetails},
    state_machine::Transition,
    xor_space::{Prefix, XorName},
};
use std::collections::BTreeSet;

/// Common functionality for node states post resource proof.
pub trait Approved: Base {
    fn parsec_map(&self) -> &ParsecMap;
    fn parsec_map_mut(&mut self) -> &mut ParsecMap;
    fn chain(&self) -> &Chain;
    fn chain_mut(&mut self) -> &mut Chain;
    fn send_event(&mut self, event: Event, outbox: &mut dyn EventBox);
    fn set_pfx_successfully_polled(&mut self, val: bool);
    fn is_pfx_successfully_polled(&self) -> bool;

    /// Handles an accumulated relocation trigger
    fn handle_relocate_polled(&mut self, details: RelocateDetails) -> Result<(), RoutingError>;

    /// Handles an accumulated change to our elders
    fn handle_promote_and_demote_elders(
        &mut self,
        new_infos: Vec<EldersInfo>,
    ) -> Result<(), RoutingError>;

    /// Handles a member added.
    fn handle_member_added(
        &mut self,
        payload: OnlinePayload,
        outbox: &mut dyn EventBox,
    ) -> Result<(), RoutingError>;

    /// Handles a member removed.
    fn handle_member_removed(
        &mut self,
        pub_id: PublicId,
        outbox: &mut dyn EventBox,
    ) -> Result<(), RoutingError>;

    /// Handle a member relocated.
    fn handle_member_relocated(
        &mut self,
        payload: RelocateDetails,
        node_knowledge: u64,
        outbox: &mut dyn EventBox,
    ) -> Result<(), RoutingError>;

    /// Handles a completed DKG.
    fn handle_dkg_result_event(
        &mut self,
        participants: &BTreeSet<PublicId>,
        dkg_result: &DkgResultWrapper,
    ) -> Result<(), RoutingError>;

    /// Handles an accumulated `SectionInfo` event.
    fn handle_section_info_event(
        &mut self,
        old_pfx: Prefix<XorName>,
        was_elder: bool,
        neighbour_change: EldersChange,
        outbox: &mut dyn EventBox,
    ) -> Result<Transition, RoutingError>;

    /// Handles an accumulated `NeighbourInfo` event.
    fn handle_neighbour_info_event(
        &mut self,
        elders_info: EldersInfo,
        neighbour_change: EldersChange,
    ) -> Result<(), RoutingError>;

    /// Handle an accumulated `TheirKeyInfo` event
    fn handle_their_key_info_event(&mut self, key_info: SectionKeyInfo)
        -> Result<(), RoutingError>;

    /// Handle an accumulated `SendAckMessage` event
    fn handle_send_ack_message_event(
        &mut self,
        ack_payload: SendAckMessagePayload,
    ) -> Result<(), RoutingError>;

    /// Handles an accumulated `Offline` event.
    fn handle_relocate_prepare_event(
        &mut self,
        payload: RelocateDetails,
        count_down: i32,
        outbox: &mut dyn EventBox,
    );

    /// Handle an accumulated `User` event
    fn handle_user_event(
        &mut self,
        payload: Vec<u8>,
        outbox: &mut dyn EventBox,
    ) -> Result<(), RoutingError> {
        self.send_event(Event::Consensus(payload), outbox);
        Ok(())
    }

    /// Handles an accumulated `ParsecPrune` event.
    fn handle_prune_event(&mut self) -> Result<(), RoutingError>;

    fn handle_parsec_request(
        &mut self,
        msg_version: u64,
        par_request: parsec::Request,
        p2p_node: P2pNode,
        outbox: &mut dyn EventBox,
    ) -> Result<Transition> {
        trace!(
            "{} - handle parsec request v{} from {} (last: v{})",
            self,
            msg_version,
            p2p_node.public_id(),
            self.parsec_map().last_version(),
        );

        let log_ident = self.log_ident();
        let response = self.parsec_map_mut().handle_request(
            msg_version,
            par_request,
            *p2p_node.public_id(),
            &log_ident,
        );

        if let Some(response) = response {
            trace!(
                "{} - send parsec response v{} to {:?}",
                self,
                msg_version,
                p2p_node,
            );
            self.send_direct_message(p2p_node.peer_addr(), response);
        }

        if msg_version == self.parsec_map().last_version() {
            self.parsec_poll(outbox)
        } else {
            Ok(Transition::Stay)
        }
    }

    fn handle_parsec_response(
        &mut self,
        msg_version: u64,
        par_response: parsec::Response,
        pub_id: PublicId,
        outbox: &mut dyn EventBox,
    ) -> Result<Transition> {
        trace!(
            "{} - handle parsec response v{} from {}",
            self,
            msg_version,
            pub_id
        );

        let log_ident = self.log_ident();
        self.parsec_map_mut()
            .handle_response(msg_version, par_response, pub_id, &log_ident);

        if msg_version == self.parsec_map().last_version() {
            self.parsec_poll(outbox)
        } else {
            Ok(Transition::Stay)
        }
    }

    fn parsec_poll(&mut self, outbox: &mut dyn EventBox) -> Result<Transition, RoutingError> {
        while let Some(block) = self.parsec_map_mut().poll() {
            let parsec_version = self.parsec_map_mut().last_version();
            match block.payload() {
                Observation::Accusation { .. } => {
                    // FIXME: Handle properly
                    unreachable!("...")
                }
                Observation::Genesis {
                    group,
                    related_info,
                } => {
                    // FIXME: Validate with Chain info.

                    trace!(
                        "{} Parsec Genesis {}: group {:?} - related_info {}",
                        self,
                        parsec_version,
                        group,
                        related_info.len()
                    );

                    self.chain_mut().handle_genesis_event(group, related_info)?;
                    self.set_pfx_successfully_polled(true);

                    continue;
                }
                Observation::OpaquePayload(event) => {
                    if let Some(proof) = block.proofs().iter().next().map(|p| Proof {
                        pub_id: *p.public_id(),
                        sig: *p.signature(),
                    }) {
                        trace!(
                            "{} Parsec OpaquePayload {}: {} - {:?}",
                            self,
                            parsec_version,
                            proof.pub_id(),
                            event
                        );
                        self.chain_mut().handle_opaque_event(event, proof)?;
                    }
                }
                Observation::Add { peer_id, .. } => {
                    log_or_panic!(
                        log::Level::Error,
                        "{} Unexpected Parsec Add {}: - {}",
                        self,
                        parsec_version,
                        peer_id
                    );
                }
                Observation::Remove { peer_id, .. } => {
                    log_or_panic!(
                        log::Level::Error,
                        "{} Unexpected Parsec Remove {}: - {}",
                        self,
                        parsec_version,
                        peer_id
                    );
                }
                obs @ Observation::StartDkg(_) | obs @ Observation::DkgMessage(_) => {
                    log_or_panic!(
                        log::Level::Error,
                        "parsec_poll polled internal Observation {}: {:?}",
                        parsec_version,
                        obs
                    );
                }
                Observation::DkgResult {
                    participants,
                    dkg_result,
                } => {
                    self.chain_mut()
                        .handle_dkg_result_event(participants, dkg_result)?;
                    self.handle_dkg_result_event(participants, dkg_result)?;
                }
            }

            match self.chain_poll(outbox)? {
                Transition::Stay => (),
                transition => return Ok(transition),
            }
        }

        self.check_voting_status();

        Ok(Transition::Stay)
    }

    fn chain_poll(&mut self, outbox: &mut dyn EventBox) -> Result<Transition, RoutingError> {
        let mut old_pfx = *self.chain_mut().our_prefix();
        let mut was_elder = self.chain().is_self_elder();

        while let Some(event) = self.chain_mut().poll_accumulated()? {
            match event {
                PollAccumulated::AccumulatedEvent(event) => {
                    match self.handle_accumulated_event(event, old_pfx, was_elder, outbox)? {
                        Transition::Stay => (),
                        transition => return Ok(transition),
                    }
                }
                PollAccumulated::RelocateDetails(details) => {
                    self.handle_relocate_polled(details)?;
                }
                PollAccumulated::PromoteDemoteElders(new_infos) => {
                    self.handle_promote_and_demote_elders(new_infos)?;
                }
            }

            old_pfx = *self.chain_mut().our_prefix();
            was_elder = self.chain().is_self_elder();
        }

        Ok(Transition::Stay)
    }

    fn handle_accumulated_event(
        &mut self,
        event: AccumulatedEvent,
        old_pfx: Prefix<XorName>,
        was_elder: bool,
        outbox: &mut dyn EventBox,
    ) -> Result<Transition, RoutingError> {
        trace!("{} Handle accumulated event: {:?}", self, event);

        match event.content {
            AccumulatingEvent::StartDkg(_) => {
                log_or_panic!(
                    log::Level::Error,
                    "StartDkg came out of Parsec - this shouldn't happen"
                );
            }
            AccumulatingEvent::Online(payload) => {
                self.handle_online_event(payload, outbox)?;
            }
            AccumulatingEvent::Offline(pub_id) => {
                self.handle_offline_event(pub_id, outbox)?;
            }
            AccumulatingEvent::SectionInfo(_, _) => {
                return self.handle_section_info_event(
                    old_pfx,
                    was_elder,
                    event.elders_change,
                    outbox,
                );
            }
            AccumulatingEvent::NeighbourInfo(elders_info) => {
                self.handle_neighbour_info_event(elders_info, event.elders_change)?;
            }
            AccumulatingEvent::TheirKeyInfo(key_info) => {
                self.handle_their_key_info_event(key_info)?
            }
            AccumulatingEvent::AckMessage(_payload) => {
                // Update their_knowledge is handled within the chain.
            }
            AccumulatingEvent::SendAckMessage(payload) => {
                self.handle_send_ack_message_event(payload)?
            }
            AccumulatingEvent::ParsecPrune => self.handle_prune_event()?,
            AccumulatingEvent::Relocate(payload) => self.handle_relocate_event(payload, outbox)?,
            AccumulatingEvent::RelocatePrepare(pub_id, count) => {
                self.handle_relocate_prepare_event(pub_id, count, outbox);
            }
            AccumulatingEvent::User(payload) => self.handle_user_event(payload, outbox)?,
        }

        Ok(Transition::Stay)
    }

    // Checking members vote status and vote to remove those non-resposive nodes.
    fn check_voting_status(&mut self) {
        let unresponsive_nodes = self.chain_mut().check_vote_status();
        let log_ident = self.log_ident();
        for pub_id in &unresponsive_nodes {
            info!("{} Voting for unresponsive node {:?}", log_ident, pub_id);
            self.parsec_map_mut().vote_for(
                AccumulatingEvent::Offline(*pub_id).into_network_event(),
                &log_ident,
            );
        }
    }

    fn disconnect_by_id_lookup(&mut self, pub_id: &PublicId) {
        if let Some(node) = self.chain().get_p2p_node(pub_id.name()) {
            let peer_addr = *node.peer_addr();
            self.network_service_mut().disconnect(peer_addr);
        } else {
            log_or_panic!(
                log::Level::Error,
                "{} - Can't disconnect from node we can't lookup in Chain: {}.",
                self,
                pub_id
            );
        };
    }

    fn handle_online_event(
        &mut self,
        payload: OnlinePayload,
        outbox: &mut dyn EventBox,
    ) -> Result<(), RoutingError> {
        if !self.chain().can_add_member(payload.p2p_node.public_id()) {
            info!("{} - ignore Online: {:?}.", self, payload);
        } else {
            info!("{} - handle Online: {:?}.", self, payload);

            let pub_id = *payload.p2p_node.public_id();
            self.chain_mut()
                .add_member(payload.p2p_node.clone(), payload.age);
            self.chain_mut().increment_age_counters(&pub_id);
            self.handle_member_added(payload, outbox)?;
        }

        Ok(())
    }

    fn handle_offline_event(
        &mut self,
        pub_id: PublicId,
        outbox: &mut dyn EventBox,
    ) -> Result<(), RoutingError> {
        if !self.chain().can_remove_member(&pub_id) {
            info!("{} - ignore Offline: {}.", self, pub_id);
        } else {
            info!("{} - handle Offline: {}.", self, pub_id);

            self.chain_mut().increment_age_counters(&pub_id);
            let _ = self.chain_mut().remove_member(&pub_id);
            self.disconnect_by_id_lookup(&pub_id);
            self.handle_member_removed(pub_id, outbox)?;
        }

        Ok(())
    }

    fn handle_relocate_event(
        &mut self,
        details: RelocateDetails,
        outbox: &mut dyn EventBox,
    ) -> Result<(), RoutingError> {
        if !self.chain().can_remove_member(&details.pub_id) {
            info!("{} - ignore Relocate: {:?} - not a member", self, details);
        } else {
            info!("{} - handle Relocate: {:?}.", self, details);

            match self.chain_mut().remove_member(&details.pub_id) {
                MemberState::Relocating { node_knowledge } => {
                    self.handle_member_relocated(details, node_knowledge, outbox)?;
                }
                state => {
                    log_or_panic!(
                        log::Level::Error,
                        "{} - Expected the state of {} to be Relocating, but was {:?}",
                        self,
                        details.pub_id,
                        state,
                    );
                }
            }
        }

        Ok(())
    }

    fn check_signed_relocation_details(&self, msg: &SignedRelocateDetails) -> bool {
        msg.signed_msg()
            .verify(self.chain().get_their_key_infos())
            .and_then(VerifyStatus::require_full)
            .map_err(|error| {
                self.log_verify_failure(
                    msg.signed_msg(),
                    &error,
                    self.chain().get_their_key_infos(),
                );
                error
            })
            .is_ok()
    }
}

#[allow(unused)]
fn to_proof_set(block: &Block) -> ProofSet {
    let sigs = block
        .proofs()
        .iter()
        .map(|proof| (*proof.public_id(), *proof.signature()))
        .collect();
    ProofSet { sigs }
}
