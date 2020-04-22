// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod event_accumulator;
mod parsec;

pub use self::{
    event_accumulator::{AccumulatingProof, InsertError},
    parsec::{
        generate_bls_threshold_secret_key, generate_first_dkg_result, CreateGossipError, DkgResult,
        DkgResultWrapper, NetworkEvent as ParsecNetworkEvent, Observation,
        Request as ParsecRequest, Response as ParsecResponse, GOSSIP_PERIOD,
    },
};

#[cfg(feature = "mock_base")]
pub use self::event_accumulator::{UNRESPONSIVE_THRESHOLD, UNRESPONSIVE_WINDOW};

use self::{
    event_accumulator::{EventAccumulator, RemainingEvents},
    parsec::{Block, ParsecMap},
};
use crate::{
    chain::{AccumulatingEvent, EventSigPayload, GenesisPfxInfo, NetworkEvent, Proof, ProofSet},
    id::{FullId, PublicId},
    messages::Variant,
    rng::MainRng,
    section::EldersInfo,
    time::Duration,
};
use std::collections::BTreeSet;

// Decentralized, Byzantine-fault-tolerant, Asynchronous, Permission-less consensus mechanism.
pub struct ConsensusEngine {
    parsec_map: ParsecMap,
    accumulator: EventAccumulator,
}

impl ConsensusEngine {
    pub fn new(rng: &mut MainRng, full_id: FullId, gen_pfx_info: &GenesisPfxInfo) -> Self {
        let mut parsec_map = ParsecMap::default();
        parsec_map.init(rng, full_id, gen_pfx_info);

        Self {
            parsec_map,
            accumulator: EventAccumulator::default(),
        }
    }

    pub fn add_proof(
        &mut self,
        event: AccumulatingEvent,
        proof: Proof,
        signature: Option<EventSigPayload>,
    ) -> Result<(), InsertError> {
        self.accumulator.add_proof(event, proof, signature)
    }

    pub fn poll(
        &mut self,
        our_elders: &EldersInfo,
    ) -> Option<(AccumulatingEvent, AccumulatingProof)> {
        let event = self
            .accumulator
            .incomplete_events()
            .find(|(event, proofs)| {
                self.is_accumulated(event, proofs.parsec_proof_set(), our_elders)
            })
            .map(|(event, _)| event.clone())?;

        self.accumulator
            .poll_event(event, our_elders.member_ids().cloned().collect())
    }

    fn is_accumulated(
        &self,
        event: &AccumulatingEvent,
        proofs: &ProofSet,
        our_elders: &EldersInfo,
    ) -> bool {
        match event {
            AccumulatingEvent::SectionInfo(info, _) => {
                if !our_elders.is_quorum(proofs) {
                    return false;
                }

                if !info.is_successor_of(our_elders) {
                    log_or_panic!(
                        log::Level::Error,
                        "We shouldn't have a SectionInfo that is not a direct descendant. our: \
                         {:?}, new: {:?}",
                        our_elders,
                        info
                    );
                }

                true
            }

            AccumulatingEvent::Online(_)
            | AccumulatingEvent::Offline(_)
            | AccumulatingEvent::NeighbourInfo(_)
            | AccumulatingEvent::TheirKeyInfo(_)
            | AccumulatingEvent::AckMessage(_)
            | AccumulatingEvent::ParsecPrune
            | AccumulatingEvent::Relocate(_)
            | AccumulatingEvent::RelocatePrepare(_, _)
            | AccumulatingEvent::User(_) => our_elders.is_quorum(proofs),

            AccumulatingEvent::SendAckMessage(_) => {
                // We may not reach consensus if malicious peer, but when we do we know all our
                // nodes have updated `their_keys`.
                our_elders.is_total_consensus(proofs)
            }

            AccumulatingEvent::StartDkg(_) => {
                unreachable!("StartDkg present in the event accumulator")
            }
        }
    }

    pub fn reset_accumulator(&mut self, our_id: &PublicId) -> RemainingEvents {
        self.accumulator.reset_accumulator(our_id)
    }

    pub fn check_vote_status<'a>(
        &self,
        members: impl Iterator<Item = &'a PublicId>,
    ) -> BTreeSet<PublicId> {
        self.accumulator.check_vote_status(members)
    }

    pub fn parsec_init(
        &mut self,
        rng: &mut MainRng,
        full_id: FullId,
        gen_pfx_info: &GenesisPfxInfo,
    ) {
        self.parsec_map.init(rng, full_id, gen_pfx_info)
    }

    pub fn vote_for(&mut self, event: NetworkEvent) {
        self.parsec_map.vote_for(event)
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

    pub fn parsec_poll(&mut self) -> Option<Block> {
        self.parsec_map.poll()
    }

    pub fn prune_if_needed(&mut self) {
        self.parsec_map.prune_if_needed()
    }

    pub fn parsec_version(&self) -> u64 {
        self.parsec_map.last_version()
    }

    pub fn our_unpolled_observations(
        &self,
    ) -> impl Iterator<Item = &Observation<NetworkEvent, PublicId>> {
        self.parsec_map.our_unpolled_observations()
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
    pub fn has_unpolled_observations(&self) -> bool {
        self.parsec_map.has_unpolled_observations()
    }

    #[cfg(all(test, feature = "mock"))]
    pub fn vote_for_as(&mut self, obs: Observation<NetworkEvent, PublicId>, vote_id: &FullId) {
        self.parsec_map.vote_for_as(obs, vote_id)
    }

    #[cfg(all(test, feature = "mock"))]
    pub fn get_dkg_result_as(
        &mut self,
        participants: BTreeSet<PublicId>,
        vote_id: &FullId,
    ) -> Option<DkgResult> {
        self.parsec_map.get_dkg_result_as(participants, vote_id)
    }
}
