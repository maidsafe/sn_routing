// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::Relocated;
use crate::{
    chain::{
        Chain, ExpectCandidatePayload, NetworkEvent, OnlinePayload, Proof, ProofSet,
        ProvingSection, SectionInfo,
    },
    error::RoutingError,
    id::PublicId,
    outbox::EventBox,
    parsec::{self, Block, Observation, ParsecMap},
    routing_table::Prefix,
    sha3::Digest256,
    state_machine::Transition,
    xor_name::XorName,
    Authority,
};
use maidsafe_utilities::serialisation;

/// Common functionality for node states post resource proof.
pub trait Approved: Relocated {
    fn parsec_map_mut(&mut self) -> &mut ParsecMap;
    fn chain_mut(&mut self) -> &mut Chain;

    fn set_pfx_successfully_polled(&mut self, val: bool);
    fn is_pfx_successfully_polled(&self) -> bool;

    /// Handles an accumulated `AddElder` event.
    fn handle_add_elder_event(
        &mut self,
        new_pub_id: PublicId,
        client_auth: Authority<XorName>,
        outbox: &mut EventBox,
    ) -> Result<(), RoutingError>;

    /// Handles an accumulated `RemoveElder` event.
    fn handle_remove_elder_event(
        &mut self,
        pub_id: PublicId,
        outbox: &mut EventBox,
    ) -> Result<(), RoutingError>;

    /// Handles an accumulated `Online` event.
    fn handle_online_event(&mut self, online_payload: OnlinePayload) -> Result<(), RoutingError>;

    /// Handles an accumulated `Offline` event.
    fn handle_offline_event(&mut self, pub_id: PublicId) -> Result<(), RoutingError>;

    /// Handles an accumulated message.
    fn handle_message_event(&mut self, digest: Digest256) -> Result<(), RoutingError>;

    /// Handles an accumulated `OurMerge` event.
    fn handle_our_merge_event(&mut self) -> Result<(), RoutingError>;

    /// Handles an accumulated `NeighbourMerge` event.
    fn handle_neighbour_merge_event(&mut self) -> Result<(), RoutingError>;

    /// Handles an accumulated `SectionInfo` event.
    fn handle_section_info_event(
        &mut self,
        sec_info: SectionInfo,
        old_pfx: Prefix<XorName>,
        outbox: &mut EventBox,
    ) -> Result<Transition, RoutingError>;

    // Handles an accumulated `ExpectCandidate` event.
    // Context: a node is joining our section. Send the node our section. If the
    // network is unbalanced, send `ExpectCandidate` on to a section with a shorter prefix.
    fn handle_expect_candidate_event(
        &mut self,
        vote: ExpectCandidatePayload,
    ) -> Result<(), RoutingError>;

    /// Handles an accumulated `PurgeCandidate` event.
    fn handle_purge_candidate_event(&mut self, old_public_id: PublicId)
        -> Result<(), RoutingError>;

    /// Handles an accumulated `ProvingSections` event.
    fn handle_proving_sections_event(
        &mut self,
        proving_secs: Vec<ProvingSection>,
        sec_info: SectionInfo,
    ) -> Result<(), RoutingError>;

    fn handle_parsec_request(
        &mut self,
        msg_version: u64,
        par_request: parsec::Request,
        pub_id: PublicId,
        outbox: &mut EventBox,
    ) -> Result<Transition, RoutingError> {
        let log_ident = self.log_ident();
        let (response, poll) =
            self.parsec_map_mut()
                .handle_request(msg_version, par_request, pub_id, &log_ident);

        if let Some(response) = response {
            self.send_direct_message(&pub_id, response);
        }

        if poll {
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
        outbox: &mut EventBox,
    ) -> Result<Transition, RoutingError> {
        let log_ident = self.log_ident();
        if self
            .parsec_map_mut()
            .handle_response(msg_version, par_response, pub_id, &log_ident)
        {
            self.parsec_poll(outbox)
        } else {
            Ok(Transition::Stay)
        }
    }

    fn parsec_poll(&mut self, outbox: &mut EventBox) -> Result<Transition, RoutingError> {
        while let Some(block) = self.parsec_map_mut().poll() {
            match block.payload() {
                Observation::Accusation { .. } => {
                    // FIXME: Handle properly
                    unreachable!("...")
                }
                Observation::Genesis(_) => {
                    // FIXME: Validate with Chain info.
                    self.set_pfx_successfully_polled(true);
                    continue;
                }
                Observation::OpaquePayload(event) => {
                    if let Some(proof) = block.proofs().iter().next().map(|p| Proof {
                        pub_id: *p.public_id(),
                        sig: *p.signature(),
                    }) {
                        trace!(
                            "{} Parsec OpaquePayload: {} - {:?}",
                            self,
                            proof.pub_id(),
                            event
                        );
                        self.chain_mut().handle_opaque_event(event, proof)?;
                    }
                }
                Observation::Add {
                    peer_id,
                    related_info,
                } => {
                    let event = NetworkEvent::AddElder(
                        *peer_id,
                        serialisation::deserialise(&related_info)?,
                    );
                    let proof_set = to_proof_set(&block);
                    trace!("{} Parsec Add: - {}", self, peer_id);
                    self.chain_mut().handle_churn_event(&event, proof_set)?;
                }
                Observation::Remove { peer_id, .. } => {
                    let event = NetworkEvent::RemoveElder(*peer_id);
                    let proof_set = to_proof_set(&block);
                    trace!("{} Parsec Remove: - {}", self, peer_id);
                    self.chain_mut().handle_churn_event(&event, proof_set)?;
                }
            }

            match self.chain_poll(outbox)? {
                Transition::Stay => (),
                transition => return Ok(transition),
            }
        }

        Ok(Transition::Stay)
    }

    fn chain_poll(&mut self, outbox: &mut EventBox) -> Result<Transition, RoutingError> {
        let mut our_pfx = *self.chain_mut().our_prefix();
        while let Some(event) = self.chain_mut().poll()? {
            trace!("{} Handle accumulated event: {:?}", self, event);

            match event {
                NetworkEvent::AddElder(pub_id, client_auth) => {
                    self.handle_add_elder_event(pub_id, client_auth, outbox)?;
                }
                NetworkEvent::RemoveElder(pub_id) => {
                    self.handle_remove_elder_event(pub_id, outbox)?;
                }
                NetworkEvent::Online(info) => {
                    self.handle_online_event(info)?;
                }
                NetworkEvent::Offline(pub_id) => {
                    self.handle_offline_event(pub_id)?;
                }
                NetworkEvent::OurMerge => self.handle_our_merge_event()?,
                NetworkEvent::NeighbourMerge(_) => self.handle_neighbour_merge_event()?,
                NetworkEvent::SectionInfo(sec_info) => {
                    match self.handle_section_info_event(sec_info, our_pfx, outbox)? {
                        Transition::Stay => (),
                        transition => return Ok(transition),
                    }
                }
                NetworkEvent::ExpectCandidate(vote) => self.handle_expect_candidate_event(vote)?,
                NetworkEvent::PurgeCandidate(old_public_id) => {
                    self.handle_purge_candidate_event(old_public_id)?
                }

                NetworkEvent::ProvingSections(proving_secs, sec_info) => {
                    self.handle_proving_sections_event(proving_secs, sec_info)?;
                }
                NetworkEvent::MessageDigest(digest) => {
                    self.handle_message_event(digest)?;
                }
            }

            our_pfx = *self.chain_mut().our_prefix();
        }

        Ok(Transition::Stay)
    }
}

fn to_proof_set(block: &Block) -> ProofSet {
    let sigs = block
        .proofs()
        .iter()
        .map(|proof| (*proof.public_id(), *proof.signature()))
        .collect();
    ProofSet { sigs }
}
