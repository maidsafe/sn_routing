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
#[cfg(test)]
mod tests;

pub use self::{
    block::Block,
    observation::{ConsensusMode, Observation},
};
pub use parsec::{NetworkEvent, Proof, PublicId, SecretId};

use self::observation::{ObservationHolder, ObservationInfo, ObservationMap};
use maidsafe_utilities::serialisation;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub struct Parsec<T: NetworkEvent, S: SecretId> {
    our_id: S,
    peer_list: BTreeSet<S::PublicId>,
    consensus_mode: ConsensusMode,
    observations: ObservationMap<T, S::PublicId>,
    pending_blocks: BTreeMap<usize, Block<T, S::PublicId>>,
    consensused_blocks: VecDeque<Block<T, S::PublicId>>,
    next_block_index: usize,
}

impl<T: NetworkEvent, S: SecretId> Parsec<T, S> {
    pub fn from_genesis(
        our_id: S,
        genesis_group: &BTreeSet<S::PublicId>,
        consensus_mode: ConsensusMode,
    ) -> Self {
        let observation = Observation::Genesis(genesis_group.clone());

        let mut info = ObservationInfo::new();
        info.vote(&our_id, &observation);

        let holder = ObservationHolder::new(observation, our_id.public_id(), consensus_mode);

        let mut observations = BTreeMap::new();
        let _ = observations.insert(holder, info);

        Self {
            our_id,
            peer_list: genesis_group.clone(),
            consensus_mode,
            observations,
            pending_blocks: BTreeMap::new(),
            consensused_blocks: VecDeque::new(),
            next_block_index: 0,
        }
    }

    pub fn from_existing(
        our_id: S,
        genesis_group: &BTreeSet<S::PublicId>,
        _section: &BTreeSet<S::PublicId>,
        consensus_mode: ConsensusMode,
    ) -> Self {
        Self {
            our_id,
            peer_list: genesis_group.clone(),
            consensus_mode,
            observations: BTreeMap::new(),
            pending_blocks: BTreeMap::new(),
            consensused_blocks: VecDeque::new(),
            next_block_index: 0,
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

        let info = self
            .observations
            .entry(holder)
            .or_insert(ObservationInfo::new());
        info.vote(&self.our_id, &observation);

        if let Some(index) = detect_consensus(
            self.our_id.public_id(),
            &self.peer_list,
            self.consensus_mode,
            self.next_block_index,
            &observation,
            info,
        ) {
            let block = block::create(observation, info);
            self.add_block(index, block);
        }

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

    pub fn create_gossip(
        &mut self,
        peer_id: &S::PublicId,
    ) -> Result<Request<T, S::PublicId>, Error> {
        Ok(Request {
            observations: self.observations_to_gossip(peer_id),
        })
    }

    pub fn handle_request(
        &mut self,
        src: &S::PublicId,
        req: Request<T, S::PublicId>,
    ) -> Result<Response<T, S::PublicId>, Error> {
        self.handle_gossip(req.observations)?;
        Ok(Response {
            observations: self.observations_to_gossip(src),
        })
    }

    pub fn handle_response(
        &mut self,
        _src: &S::PublicId,
        resp: Response<T, S::PublicId>,
    ) -> Result<(), Error> {
        self.handle_gossip(resp.observations)
    }

    pub fn poll(&mut self) -> Option<Block<T, S::PublicId>> {
        self.consensused_blocks.pop_front()
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
        self.observations
            .values()
            .any(|info| info.consensus_index().is_none())
    }

    pub fn our_unpolled_observations(&self) -> impl Iterator<Item = &Observation<T, S::PublicId>> {
        self.observations
            .iter()
            .filter(move |(observation, info)| {
                info.voted_for_by(self.our_id.public_id())
                    && (info.consensus_index().is_none()
                        || self
                            .consensused_blocks
                            .iter()
                            .any(|block| block.payload() == &***observation))
            })
            .map(|(observation, _)| &**observation)
    }

    fn handle_gossip(&mut self, observations: ObservationMap<T, S::PublicId>) -> Result<(), Error> {
        for (holder, gossiped_info) in observations {
            let info = self
                .observations
                .entry(holder.clone())
                .or_insert(ObservationInfo::new());
            info.handle_gossip(self.our_id.public_id(), gossiped_info);

            if let Some(index) = detect_consensus(
                self.our_id.public_id(),
                &self.peer_list,
                self.consensus_mode,
                self.next_block_index,
                &holder,
                info,
            ) {
                let block = block::create(holder.into_observation(), info);
                self.add_block(index, block);
            }
        }

        Ok(())
    }

    fn observations_to_gossip(&self, dst: &S::PublicId) -> ObservationMap<T, S::PublicId> {
        self.observations
            .iter()
            .filter_map(|(holder, info)| info.create_gossip(dst).map(|info| (holder.clone(), info)))
            .collect()
    }

    fn add_block(&mut self, index: usize, block: Block<T, S::PublicId>) {
        let _ = self.pending_blocks.insert(index, block);

        while let Some(block) = self.pending_blocks.remove(&self.next_block_index) {
            self.handle_consensus(block.payload());

            self.consensused_blocks.push_back(block);
            self.next_block_index += 1;
        }
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
#[serde(bound = "")]
pub struct Request<T: NetworkEvent, P: PublicId> {
    observations: ObservationMap<T, P>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(bound = "")]
pub struct Response<T: NetworkEvent, P: PublicId> {
    observations: ObservationMap<T, P>,
}

#[derive(Debug)]
pub struct Error;

fn detect_consensus<T, P>(
    our_id: &P,
    peers: &BTreeSet<P>,
    consensus_mode: ConsensusMode,
    next_block_index: usize,
    observation: &Observation<T, P>,
    observation_info: &mut ObservationInfo<P>,
) -> Option<usize>
where
    T: NetworkEvent,
    P: PublicId,
{
    if observation_info.knows_consensus(our_id) {
        return None;
    }

    if let Some(index) = observation_info.consensus_index() {
        observation_info.acknowledge_consensus(our_id);
        return Some(index);
    }

    if !is_leader_for(our_id, peers, observation) {
        return None;
    }

    let num_valid_voters = observation_info
        .votes()
        .filter(|(peer_id, _)| peers.contains(peer_id))
        .count();

    let consensused = match (observation, consensus_mode) {
        (&Observation::OpaquePayload(_), ConsensusMode::Single) => num_valid_voters > 0,
        _ => is_more_than_two_thirds(num_valid_voters, peers.len()),
    };

    if consensused {
        observation_info.decide_consensus(our_id, next_block_index);
        Some(next_block_index)
    } else {
        None
    }
}

fn is_leader_for<T, P>(our_id: &P, can_vote: &BTreeSet<P>, observation: &Observation<T, P>) -> bool
where
    T: NetworkEvent,
    P: PublicId,
{
    // Leader is the lexicographically first peer, unless he is the one begin removed, in which
    // case the leader is the second peer.
    if let Observation::Remove { ref peer_id, .. } = *observation {
        if Some(peer_id) == can_vote.iter().nth(0) {
            return Some(our_id) == can_vote.iter().nth(1);
        }
    }

    Some(our_id) == can_vote.iter().nth(0)
}

// Returns whether `small` is more than two thirds of `large`.
fn is_more_than_two_thirds(small: usize, large: usize) -> bool {
    3 * small > 2 * large
}

fn serialise<T: Serialize>(data: &T) -> Vec<u8> {
    if let Ok(serialised) = serialisation::serialise(data) {
        serialised
    } else {
        vec![]
    }
}
