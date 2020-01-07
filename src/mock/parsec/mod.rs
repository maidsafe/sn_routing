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
use crate::crypto::Digest256;
use rand::RngCore;
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
    dkg_participants: BTreeSet<S::PublicId>,
    consensus_mode: ConsensusMode,
    first_unconsensused: usize,
    first_unpolled: usize,
    observations: BTreeMap<ObservationHolder<T, S::PublicId>, ObservationInfo>,
    rng: Box<dyn RngCore>,
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
        secure_rng: Box<dyn RngCore>,
    ) -> Self {
        let mut parsec = Self {
            section_hash,
            our_id,
            peer_list: genesis_group.iter().cloned().collect(),
            dkg_participants: Default::default(),
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
        secure_rng: Box<dyn RngCore>,
    ) -> Self {
        Self {
            section_hash,
            our_id,
            peer_list: genesis_group.iter().cloned().collect(),
            dkg_participants: Default::default(),
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

    pub fn vote_for_as(&mut self, observation: Observation<T, S::PublicId>, vote_id: &S) {
        state::with(self.section_hash, |state| {
            let holder =
                ObservationHolder::new(observation, vote_id.public_id(), self.consensus_mode);
            state.vote(vote_id, holder);
        });
    }

    pub fn get_dkg_result_as(
        &mut self,
        participants: BTreeSet<S::PublicId>,
        vote_id: &S,
    ) -> DkgResult {
        state::with(
            self.section_hash,
            |state: &mut SectionState<T, S::PublicId>| {
                state.get_or_generate_keys(&mut self.rng, vote_id.public_id(), participants.clone())
            },
        )
    }

    pub fn gossip_recipients(&self) -> impl Iterator<Item = &S::PublicId> {
        trace!(
            "gossip_recipients: {:?} -- {:?}",
            self.peer_list,
            self.dkg_participants
        );
        let iter = if self.peer_list.contains(self.our_id.public_id()) {
            Some(
                self.peer_list
                    .union(&self.dkg_participants)
                    .filter(move |peer_id| *peer_id != self.our_id.public_id()),
            )
        } else {
            None
        };

        iter.into_iter().flatten()
    }

    pub fn create_gossip(&self, peer_id: &S::PublicId) -> Result<Request<T, S::PublicId>, Error> {
        self.gossip_recipients()
            .find(|id| id == &peer_id)
            .map(|_| Request::new())
            .ok_or(Error::InvalidPeerState)
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
                    .entry(holder)
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

    fn is_valid_gossip_recipient(&self) -> bool {
        if self.peer_list.contains(self.our_id.public_id()) {
            return true;
        }

        state::with::<T, S::PublicId, _, _>(self.section_hash, |state| {
            state.contains_dkg_participant(self.our_id.public_id())
        })
    }

    pub fn has_unpolled_observations(&self) -> bool {
        if !self.is_valid_gossip_recipient() {
            return false;
        }

        state::with::<T, S::PublicId, _, _>(self.section_hash, |state| {
            state
                .unconsensused_observations_for_peers(&self.peer_list)
                .next()
                .is_some()
                || state.get_block(self.first_unconsensused).is_some()
        }) || self.our_unpolled_observations().next().is_some()
    }

    pub fn unpolled_observations_string(&self) -> String {
        use itertools::Itertools;
        let value = state::with::<T, S::PublicId, _, _>(self.section_hash, |state| {
            format!(
                "unconsensused_observations_for_peers: {:?}, first_unconsensused block: {:?}",
                state
                    .unconsensused_observations_for_peers(&self.peer_list)
                    .format(", "),
                state.get_block(self.first_unconsensused),
            )
        });
        format!(
            "{}, our_unpolled_observations: {:?}",
            value,
            self.our_unpolled_observations().format(", "),
        )
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
            Observation::Remove { ref peer_id, .. } => {
                let _ = self.dkg_participants.remove(peer_id);
                self.peer_list.remove(peer_id)
            }
            Observation::Accusation { ref offender, .. } => {
                let _ = self.dkg_participants.remove(offender);
                self.peer_list.remove(offender)
            }
            Observation::StartDkg(ref participants) => {
                self.dkg_participants.extend(participants.iter().cloned());
                false
            }
            _ => false,
        }
    }
}

// Contains an additional `u8` so that the size is > 0. This is needed when counting sizes to
// determine parsec graph pruning.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Debug, Default)]
pub struct Request<T: NetworkEvent, P: PublicId>(PhantomData<(T, P)>, u8);

impl<T: NetworkEvent, P: PublicId> Request<T, P> {
    pub fn new() -> Self {
        Request(PhantomData, 1)
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Debug, Default)]
pub struct Response<T: NetworkEvent, P: PublicId>(PhantomData<(T, P)>, u8);

impl<T: NetworkEvent, P: PublicId> Response<T, P> {
    pub fn new() -> Self {
        Response(PhantomData, 1)
    }
}

#[derive(Debug)]
pub enum Error {
    InvalidPeerState,
}

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
