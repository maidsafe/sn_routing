// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

pub use parsec::{ConsensusMode, Observation};

use super::{Block, NetworkEvent, Proof, PublicId, SecretId};
use fxhash::FxHashSet;
use maidsafe_utilities::serialisation;
use serde::Serialize;
use std::ops::Deref;

/// Wrapper for `Observation` and optionally its creator, depending on the consensus mode.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub(super) enum ObservationHolder<T: NetworkEvent, P: PublicId> {
    Single {
        observation: Observation<T, P>,
        creator: P,
    },
    Supermajority(Observation<T, P>),
}

impl<T: NetworkEvent, P: PublicId> ObservationHolder<T, P> {
    pub fn new(observation: Observation<T, P>, creator: &P, consensus_mode: ConsensusMode) -> Self {
        match (&observation, consensus_mode) {
            (&Observation::OpaquePayload(_), ConsensusMode::Single) => ObservationHolder::Single {
                observation,
                creator: creator.clone(),
            },
            _ => ObservationHolder::Supermajority(observation),
        }
    }
}

impl<T: NetworkEvent, P: PublicId> Deref for ObservationHolder<T, P> {
    type Target = Observation<T, P>;
    fn deref(&self) -> &Self::Target {
        match *self {
            ObservationHolder::Single {
                ref observation, ..
            } => observation,
            ObservationHolder::Supermajority(ref observation) => observation,
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct ObservationState<P: PublicId> {
    votes: FxHashSet<Proof<P>>,
    consensused: bool,
}

impl<P: PublicId> ObservationState<P> {
    pub fn new() -> Self {
        Self {
            votes: FxHashSet::default(),
            consensused: false,
        }
    }

    pub fn vote<T: NetworkEvent, S: SecretId<PublicId = P>>(
        &mut self,
        our_secret_id: &S,
        peers: &FxHashSet<P>,
        consensus_mode: ConsensusMode,
        observation: Observation<T, P>,
    ) -> Option<Block<T, P>> {
        let proof = our_secret_id.create_proof(&serialise(&observation));
        if self.votes.insert(proof) {
            self.compute_consensus(peers, consensus_mode, observation)
        } else {
            None
        }
    }

    pub fn consensused(&self) -> bool {
        self.consensused
    }

    fn compute_consensus<T: NetworkEvent>(
        &mut self,
        peers: &FxHashSet<P>,
        consensus_mode: ConsensusMode,
        observation: Observation<T, P>,
    ) -> Option<Block<T, P>> {
        if self.consensused {
            return None;
        }

        let num_valid_voters = self
            .votes
            .iter()
            .map(|proof| proof.public_id())
            .filter(|peer_id| peers.contains(peer_id))
            .count();

        let consensused = match (&observation, consensus_mode) {
            (&Observation::OpaquePayload(_), ConsensusMode::Single) => num_valid_voters > 0,
            _ => is_more_than_two_thirds(num_valid_voters, peers.len()),
        };

        if consensused {
            self.consensused = true;
            Some(Block::new(observation, &self.votes))
        } else {
            None
        }
    }
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
