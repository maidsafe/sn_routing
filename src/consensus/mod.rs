// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod dkg;
mod event_accumulator;
mod genesis_prefix_info;
mod network_event;
mod parsec;
mod proof;
mod signature_accumulator;
#[cfg(test)]
pub mod test_utils;

pub use self::{
    dkg::{generate_secret_key_set, threshold_count, DkgResult, DkgVoter},
    genesis_prefix_info::GenesisPrefixInfo,
    network_event::{AccumulatingEvent, NetworkEvent},
    parsec::{
        Block, CreateGossipError, Observation, ParsecNetworkEvent, Request as ParsecRequest,
        Response as ParsecResponse, GOSSIP_PERIOD,
    },
    proof::{Proof, ProofShare, Proven},
    signature_accumulator::{AccumulationError, SignatureAccumulator},
};

#[cfg(feature = "mock_base")]
pub use self::event_accumulator::{UNRESPONSIVE_THRESHOLD, UNRESPONSIVE_WINDOW};

use self::{
    event_accumulator::{EventAccumulator, RemainingEvents},
    parsec::ParsecMap,
};
use crate::{
    id::{FullId, PublicId},
    messages::Variant,
    rng::MainRng,
    section::EldersInfo,
    time::Duration,
};
use std::collections::BTreeSet;
use xor_name::XorName;

// Distributed consensus mechanism backed by the Parsec algorithm.
pub struct ConsensusEngine {
    parsec_map: ParsecMap,
    accumulator: EventAccumulator,
}

impl ConsensusEngine {
    pub fn new(
        rng: &mut MainRng,
        full_id: FullId,
        elders_info: &EldersInfo,
        serialised_state: Vec<u8>,
        parsec_version: u64,
    ) -> Self {
        let mut parsec_map = ParsecMap::default();
        parsec_map.init(rng, full_id, elders_info, serialised_state, parsec_version);

        Self {
            parsec_map,
            accumulator: EventAccumulator::default(),
        }
    }

    /// Returns the next consensused and accumulated event, if any.
    pub fn poll(&mut self, our_elders: &EldersInfo) -> Option<(AccumulatingEvent, Option<Proof>)> {
        while let Some(block) = self.parsec_map.poll() {
            if let Some(output) = self.handle_parsec_block(block, our_elders) {
                return Some(output);
            }
        }

        None
    }

    fn handle_parsec_block(
        &mut self,
        block: Block,
        our_elders: &EldersInfo,
    ) -> Option<(AccumulatingEvent, Option<Proof>)> {
        // TODO: implement Block::into_payload in parsec to avoid cloning.
        match block.payload() {
            Observation::Genesis {
                group,
                related_info,
            } => {
                // FIXME: Validate with Chain info.

                trace!(
                    "Parsec Genesis v{}: group: {:?}, related_info: {}",
                    self.parsec_map.last_version(),
                    group,
                    related_info.len()
                );

                Some((
                    AccumulatingEvent::Genesis {
                        group: group.clone(),
                        related_info: related_info.clone(),
                    },
                    None,
                ))
            }
            Observation::OpaquePayload(event) => {
                let voter_name = *block.proofs().iter().next()?.public_id().name();

                let NetworkEvent {
                    payload: event,
                    proof_share,
                } = event.clone();

                let proof_share = proof_share?;

                trace!(
                    "Parsec OpaquePayload v{}: {} - {:?}",
                    self.parsec_map.last_version(),
                    voter_name,
                    event
                );

                match self
                    .accumulator
                    .insert(event, voter_name, proof_share, our_elders)
                {
                    Ok((event, proof)) => Some((event, Some(proof))),
                    Err(AccumulationError::NotEnoughShares)
                    | Err(AccumulationError::AlreadyAccumulated) => None,
                    Err(AccumulationError::InvalidShare) => {
                        // TODO: penalise
                        log_or_panic!(
                            log::Level::Warn,
                            "Attempt to insert event with invalid signature share"
                        );
                        None
                    }
                    Err(AccumulationError::Serialise(error)) => {
                        // This should never happen
                        log_or_panic!(
                            log::Level::Error,
                            "Failed to serialise accumulating event: {}",
                            error
                        );
                        None
                    }
                    Err(AccumulationError::Combine(error)) => {
                        // This should never happen
                        log_or_panic!(log::Level::Error, "Failed to combine signatures: {}", error);
                        None
                    }
                }
            }
            Observation::DkgResult { .. } => {
                log_or_panic!(
                    log::Level::Error,
                    "DKG shall not be processed by parsec anymore"
                );
                None
            }
            Observation::Add { .. }
            | Observation::Remove { .. }
            | Observation::Accusation { .. }
            | Observation::StartDkg(_)
            | Observation::DkgMessage(_) => {
                log_or_panic!(
                    log::Level::Error,
                    "unexpected Parsec observation v{}: {:?}",
                    self.parsec_map.last_version(),
                    block.payload()
                );
                None
            }
        }
    }

    // Prepares for reset of the consensus engine. Returns all events voted by us that have not
    // accumulated yet, so they can be voted for again. Should be followed by `finalise_reset`.
    pub fn prepare_reset(&mut self, our_name: &XorName) -> Vec<AccumulatingEvent> {
        let RemainingEvents {
            unaccumulated_events,
            accumulated_events,
        } = self.accumulator.reset(our_name);

        unaccumulated_events
            .into_iter()
            .chain(
                self.parsec_map
                    .our_unpolled_observations()
                    .filter_map(|obs| match obs {
                        parsec::Observation::OpaquePayload(event) => Some(event),

                        parsec::Observation::Genesis { .. }
                        | parsec::Observation::Add { .. }
                        | parsec::Observation::Remove { .. }
                        | parsec::Observation::Accusation { .. }
                        | parsec::Observation::StartDkg(_)
                        | parsec::Observation::DkgResult { .. }
                        | parsec::Observation::DkgMessage(_) => None,
                    })
                    .map(|event| event.payload.clone()),
            )
            .filter(|event| !accumulated_events.contains(event))
            .collect()
    }

    // Finalises the reset of the consensus engine.
    pub fn finalise_reset(
        &mut self,
        rng: &mut MainRng,
        full_id: FullId,
        elders_info: &EldersInfo,
        serialised_state: Vec<u8>,
        parsec_version: u64,
    ) {
        self.parsec_map
            .init(rng, full_id, elders_info, serialised_state, parsec_version)
    }

    pub fn detect_unresponsive(&self, elders_info: &EldersInfo) -> BTreeSet<PublicId> {
        self.accumulator.detect_unresponsive(elders_info)
    }

    pub fn vote_for(&mut self, event: NetworkEvent) {
        self.parsec_map.vote_for(event)
    }

    pub fn add_force_gossip_peer(&mut self, peer_id: &PublicId) {
        self.parsec_map.add_force_gossip_peer(peer_id)
    }

    pub fn create_gossip(
        &mut self,
        version: u64,
        target: &PublicId,
    ) -> Result<Variant, CreateGossipError> {
        self.parsec_map.create_gossip(version, target)
    }

    pub fn handle_parsec_request(
        &mut self,
        msg_version: u64,
        request: ParsecRequest,
        pub_id: PublicId,
    ) -> Option<Variant> {
        self.parsec_map.handle_request(msg_version, request, pub_id)
    }

    pub fn handle_parsec_response(
        &mut self,
        msg_version: u64,
        response: ParsecResponse,
        pub_id: PublicId,
    ) {
        self.parsec_map
            .handle_response(msg_version, response, pub_id)
    }

    pub fn needs_pruning(&self) -> bool {
        self.parsec_map.needs_pruning()
    }

    pub fn parsec_version(&self) -> u64 {
        self.parsec_map.last_version()
    }

    pub fn gossip_period(&self) -> Duration {
        self.parsec_map.gossip_period()
    }

    pub fn reset_gossip_period(&mut self) {
        self.parsec_map.reset_gossip_period()
    }

    pub fn should_send_gossip(&mut self) -> bool {
        self.parsec_map.should_send_gossip()
    }

    pub fn gossip_recipients(&self) -> Vec<&PublicId> {
        self.parsec_map.gossip_recipients()
    }

    #[cfg(feature = "mock_base")]
    pub fn parsec_map(&self) -> &ParsecMap {
        &self.parsec_map
    }

    #[cfg(all(test, feature = "mock"))]
    pub fn parsec_map_mut(&mut self) -> &mut ParsecMap {
        &mut self.parsec_map
    }
}
