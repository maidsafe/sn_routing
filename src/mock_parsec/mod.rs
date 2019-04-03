// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Mock implementation of Parsec

mod block;
mod observation;
mod state;
#[cfg(test)]
mod tests;

pub use self::{
    block::{Block, BlockGroup},
    observation::{ConsensusMode, Observation},
};
pub use parsec::{NetworkEvent, Proof, PublicId, SecretId};

use self::observation::{ObservationHolder, ObservationState};
use crate::sha3::Digest256;
use std::{
    collections::{BTreeMap, BTreeSet},
    marker::PhantomData,
};

/// Initialise mock parsec. Call this function at the beginning of each test.
#[allow(unused)]
pub fn init() {
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
        consensus_mode: ConsensusMode,
    ) -> Self {
        let mut parsec = Self {
            section_hash,
            our_id,
            peer_list: genesis_group.iter().cloned().collect(),
            consensus_mode,
            first_unconsensused: 0,
            first_unpolled: 0,
            observations: BTreeMap::new(),
        };

        parsec
            .vote_for(Observation::Genesis(genesis_group.clone()))
            .unwrap();
        parsec
    }

    pub fn from_existing(
        section_hash: Digest256,
        our_id: S,
        genesis_group: &BTreeSet<S::PublicId>,
        _section: &BTreeSet<S::PublicId>,
        consensus_mode: ConsensusMode,
    ) -> Self {
        Self {
            section_hash,
            our_id,
            peer_list: genesis_group.iter().cloned().collect(),
            consensus_mode,
            first_unconsensused: 0,
            first_unpolled: 0,
            observations: BTreeMap::new(),
        }
    }

    #[allow(unused)]
    pub fn our_pub_id(&self) -> &S::PublicId {
        &self.our_id.public_id()
    }

    pub fn vote_for(&mut self, observation: Observation<T, S::PublicId>) -> Result<(), Error> {
        let holder = ObservationHolder::new(
            observation.clone(),
            self.our_id.public_id(),
            self.consensus_mode,
        );

        state::with(self.section_hash, |state| {
            if let Some(block) = state
                .observations
                .entry(holder.clone())
                .or_insert_with(ObservationState::new)
                .vote(
                    &self.our_id,
                    &self.peer_list,
                    self.consensus_mode,
                    observation,
                )
            {
                state.blocks.push((block, holder.clone()))
            }
        });

        self.observations
            .entry(holder)
            .or_insert_with(ObservationInfo::new)
            .our = true;
        self.update_blocks();

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
        self.update_blocks();
        Ok(Response::new())
    }

    pub fn handle_response(
        &mut self,
        _src: &S::PublicId,
        _resp: Response<T, S::PublicId>,
    ) -> Result<(), Error> {
        self.update_blocks();
        Ok(())
    }

    pub fn poll(&mut self) -> Option<BlockGroup<T, S::PublicId>> {
        state::with(self.section_hash, |state| {
            if let Some((block, holder)) = state.blocks.get(self.first_unpolled) {
                self.first_unpolled += 1;
                self.observations
                    .entry(holder.clone())
                    .or_insert_with(ObservationInfo::new)
                    .state = ConsensusState::Polled;

                Some(BlockGroup(block.clone()))
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

    pub fn has_unconsensused_observations(&self) -> bool {
        state::with::<T, S::PublicId, _, _>(self.section_hash, |state| {
            state
                .observations
                .iter()
                .any(|(holder, observation_state)| {
                    !observation_state.consensused()
                        || self
                            .observations
                            .get(&*holder)
                            .map(|info| info.state == ConsensusState::Unconsensused)
                            .unwrap_or(true)
                })
        })
    }

    pub fn our_unpolled_observations(&self) -> impl Iterator<Item = &Observation<T, S::PublicId>> {
        self.observations
            .iter()
            .filter(|(_, info)| info.our && info.state != ConsensusState::Polled)
            .map(|(holder, _)| &**holder)
    }

    fn update_blocks(&mut self) {
        state::with(self.section_hash, |state| {
            while let Some((block, holder)) = state.blocks.get(self.first_unconsensused) {
                self.handle_consensus(block.payload());
                self.first_unconsensused += 1;
                self.observations
                    .entry(holder.clone())
                    .or_insert_with(ObservationInfo::new)
                    .set_consensused();
            }
        })
    }

    fn handle_consensus(&mut self, observation: &Observation<T, S::PublicId>) {
        match *observation {
            Observation::Add { ref peer_id, .. } => {
                let _ = self.peer_list.insert(peer_id.clone());
            }
            Observation::Remove { ref peer_id, .. } => {
                let _ = self.peer_list.remove(peer_id);
            }
            Observation::Accusation { ref offender, .. } => {
                let _ = self.peer_list.remove(offender);
            }
            _ => (),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Request<T: NetworkEvent, P: PublicId>(PhantomData<(T, P)>);

impl<T: NetworkEvent, P: PublicId> Request<T, P> {
    fn new() -> Self {
        Request(PhantomData)
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
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
