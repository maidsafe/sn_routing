// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Mock implementation of Parsec

mod block;
mod key_gen;
mod observation;
mod state;
#[cfg(test)]
mod tests;

pub use self::{
    block::Block,
    observation::{ConsensusMode, Observation},
};
pub use parsec::{DkgResult, DkgResultWrapper, NetworkEvent, Proof, PublicId, SecretId};

use self::{observation::ObservationHolder, state::SectionState};
use crate::sha3::Digest256;
use rand::Rng;
use std::{
    collections::{BTreeMap, BTreeSet},
    marker::PhantomData,
};

/// Initialise mock parsec. Call this function at the beginning of each test.
#[allow(unused)]
pub fn init_mock() {
    state::reset()
}

pub struct Parsec<T: NetworkEvent, S: SecretId> {
    section_hash: Digest256,
    our_id: S,
    peer_list: BTreeSet<S::PublicId>,
    consensus_mode: ConsensusMode,
    first_unconsensused: usize,
    first_unpolled: usize,
    observations: BTreeMap<ObservationHolder<T, S::PublicId>, ObservationInfo>,
    rng: Box<dyn Rng>,
}

impl<T, S> Parsec<T, S>
where
    T: NetworkEvent + 'static,
    S: SecretId,
    S::PublicId: 'static,
{
    pub fn from_genesis(
        section_hash: Digest256,
        our_id: S,
        genesis_group: &BTreeSet<S::PublicId>,
        genesis_related_info: Vec<u8>,
        consensus_mode: ConsensusMode,
        secure_rng: Box<dyn Rng>,
    ) -> Self {
        let mut parsec = Self {
            section_hash,
            our_id,
            peer_list: genesis_group.iter().cloned().collect(),
            consensus_mode,
            first_unconsensused: 0,
            first_unpolled: 0,
            observations: BTreeMap::new(),
            rng: secure_rng,
        };

        parsec
            .vote_for(Observation::Genesis {
                group: genesis_group.clone(),
                related_info: genesis_related_info,
            })
            .unwrap();
        parsec
    }

    pub fn from_existing(
        section_hash: Digest256,
        our_id: S,
        genesis_group: &BTreeSet<S::PublicId>,
        _section: &BTreeSet<S::PublicId>,
        consensus_mode: ConsensusMode,
        secure_rng: Box<dyn Rng>,
    ) -> Self {
        Self {
            section_hash,
            our_id,
            peer_list: genesis_group.iter().cloned().collect(),
            consensus_mode,
            first_unconsensused: 0,
            first_unpolled: 0,
            observations: BTreeMap::new(),
            rng: secure_rng,
        }
    }

    #[allow(unused)]
    pub fn our_pub_id(&self) -> &S::PublicId {
        &self.our_id.public_id()
    }

    pub fn vote_for(&mut self, observation: Observation<T, S::PublicId>) -> Result<(), Error> {
        state::with(self.section_hash, |state| {
            let holder =
                ObservationHolder::new(observation, self.our_id.public_id(), self.consensus_mode);
            state.vote(&self.our_id, holder.clone());
            self.observations
                .entry(holder)
                .or_insert_with(ObservationInfo::new)
                .our = true;
            self.compute_consensus(state)
        });

        Ok(())
    }

    pub fn gossip_recipients(&self) -> impl Iterator<Item = &S::PublicId> {
        let iter = if self.peer_list.contains(self.our_id.public_id()) {
            Some(
                self.peer_list
                    .iter()
                    .filter(move |peer_id| *peer_id != self.our_id.public_id()),
            )
        } else {
            None
        };

        iter.into_iter().flatten()
    }

    pub fn create_gossip(&self, _peer_id: &S::PublicId) -> Result<Request<T, S::PublicId>, Error> {
        Ok(Request::new())
    }

    pub fn handle_request(
        &mut self,
        _src: &S::PublicId,
        _req: Request<T, S::PublicId>,
    ) -> Result<Response<T, S::PublicId>, Error> {
        state::with(self.section_hash, |state| self.compute_consensus(state));
        Ok(Response::new())
    }

    pub fn handle_response(
        &mut self,
        _src: &S::PublicId,
        _resp: Response<T, S::PublicId>,
    ) -> Result<(), Error> {
        state::with(self.section_hash, |state| self.compute_consensus(state));
        Ok(())
    }

    pub fn poll(&mut self) -> Option<Block<T, S::PublicId>> {
        state::with(self.section_hash, |state| {
            if let Some((block, holder)) = state
                .get_block(self.first_unpolled)
                .map(|(block, holder)| (block.clone(), holder.clone()))
            {
                self.first_unpolled += 1;
                self.observations
                    .entry(holder.clone())
                    .or_insert_with(ObservationInfo::new)
                    .state = ConsensusState::Polled;

                // Simulate DKG: if the consensused payload is `StartDkg`, transform it into
                // `DkgResult` using trusted dealer.
                match block.payload() {
                    Observation::StartDkg(participants) => {
                        let dkg_result = state.get_or_generate_keys(
                            &mut self.rng,
                            self.our_id.public_id(),
                            participants.clone(),
                        );

                        Some(Block::new_dkg(participants.clone(), dkg_result))
                    }
                    _ => Some(block),
                }
            } else {
                None
            }
        })
    }

    #[allow(unused)]
    pub fn can_vote(&self) -> bool {
        unimplemented!()
    }

    #[allow(unused)]
    pub fn have_voted_for(&self, _observation: &Observation<T, S::PublicId>) -> bool {
        unimplemented!()
    }

    pub fn has_unpolled_observations(&self) -> bool {
        state::with::<T, S::PublicId, _, _>(self.section_hash, |state| {
            state.has_unconsensused_observations()
                || state.get_block(self.first_unconsensused).is_some()
        }) || self.our_unpolled_observations().next().is_some()
    }

    pub fn our_unpolled_observations(&self) -> impl Iterator<Item = &Observation<T, S::PublicId>> {
        self.observations
            .iter()
            .filter(|(_, info)| info.our && info.state != ConsensusState::Polled)
            .map(|(holder, _)| &***holder)
    }

    fn compute_consensus(&mut self, state: &mut SectionState<T, S::PublicId>) {
        // Call `update_blocks` once, to allow this node to catch up to the previously consensused
        // blocks.
        let _ = self.update_blocks(state);

        loop {
            state.compute_consensus(&self.peer_list, self.consensus_mode);

            if !self.update_blocks(state) {
                break;
            }
        }
    }

    // Returns whether the membership list changed.
    fn update_blocks(&mut self, state: &mut SectionState<T, S::PublicId>) -> bool {
        let mut change = false;

        while let Some((block, holder)) = state.get_block(self.first_unconsensused) {
            if self.handle_consensus(block.payload()) {
                change = true;
            }

            self.first_unconsensused += 1;
            self.observations
                .entry(holder.clone())
                .or_insert_with(ObservationInfo::new)
                .set_consensused();
        }

        change
    }

    // Returns whether the membership list changed.
    fn handle_consensus(&mut self, observation: &Observation<T, S::PublicId>) -> bool {
        match *observation {
            Observation::Add { ref peer_id, .. } => self.peer_list.insert(peer_id.clone()),
            Observation::Remove { ref peer_id, .. } => self.peer_list.remove(peer_id),
            Observation::Accusation { ref offender, .. } => self.peer_list.remove(offender),
            _ => false,
        }
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Debug)]
pub struct Request<T: NetworkEvent, P: PublicId>(PhantomData<(T, P)>);

impl<T: NetworkEvent, P: PublicId> Request<T, P> {
    fn new() -> Self {
        Request(PhantomData)
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Debug)]
pub struct Response<T: NetworkEvent, P: PublicId>(PhantomData<(T, P)>);

impl<T: NetworkEvent, P: PublicId> Response<T, P> {
    fn new() -> Self {
        Response(PhantomData)
    }
}

#[derive(Debug)]
pub struct Error;

#[derive(Clone, Copy)]
struct ObservationInfo {
    our: bool,
    state: ConsensusState,
}

impl ObservationInfo {
    fn new() -> Self {
        Self {
            our: false,
            state: ConsensusState::Unconsensused,
        }
    }

    fn set_consensused(&mut self) {
        match self.state {
            ConsensusState::Unconsensused => self.state = ConsensusState::Consensused,
            ConsensusState::Consensused | ConsensusState::Polled => {
                panic!("Invalid consensus state")
            }
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ConsensusState {
    Unconsensused,
    Consensused,
    Polled,
}
