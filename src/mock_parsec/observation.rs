// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{serialise, NetworkEvent, Proof, PublicId, SecretId};
use fxhash::{FxHashMap, FxHashSet};
pub use parsec::{ConsensusMode, Observation};
use std::{
    collections::{btree_map::BTreeMap, hash_map::Entry},
    ops::Deref,
};

/// Wrapper for `Observation` and optionally its creator, depending on the consensus mode.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize, Debug)]
#[serde(bound = "")]
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

    pub fn into_observation(self) -> Observation<T, P> {
        match self {
            ObservationHolder::Single { observation, .. } => observation,
            ObservationHolder::Supermajority(observation) => observation,
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

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(bound = "")]
pub(super) struct ObservationInfo<P: PublicId> {
    votes: FxHashMap<P, VoteInfo<P>>,
    consensus: Option<ConsensusInfo<P>>,
}

impl<P: PublicId> ObservationInfo<P> {
    pub fn new() -> Self {
        Self {
            votes: FxHashMap::default(),
            consensus: None,
        }
    }

    pub fn vote<T: NetworkEvent, S: SecretId<PublicId = P>>(
        &mut self,
        our_secret_id: &S,
        observation: &Observation<T, P>,
    ) {
        let proof = our_secret_id.create_proof(&serialise(observation));

        let mut knowledge = FxHashSet::default();
        let _ = knowledge.insert(our_secret_id.public_id().clone());

        let _ = self.votes.insert(
            our_secret_id.public_id().clone(),
            VoteInfo { proof, knowledge },
        );
    }

    pub fn handle_gossip(&mut self, our_id: &P, gossip: ObservationInfo<P>) {
        for (peer_id, new_vote) in gossip.votes {
            match self.votes.entry(peer_id) {
                Entry::Vacant(entry) => {
                    let vote = entry.insert(new_vote);
                    let _ = vote.knowledge.insert(our_id.clone());
                }
                Entry::Occupied(mut entry) => {
                    let vote = entry.get_mut();
                    vote.knowledge.extend(new_vote.knowledge);
                }
            }
        }

        if let Some(new_consensus) = gossip.consensus {
            let consensus = self.consensus.get_or_insert(ConsensusInfo {
                index: new_consensus.index,
                knowledge: FxHashSet::default(),
            });

            consensus.knowledge.extend(new_consensus.knowledge);
        }
    }

    pub fn create_gossip(&self, dst: &P) -> Option<Self> {
        let votes: FxHashMap<_, _> = self
            .votes
            .iter()
            .filter(|(_, vote)| !vote.knowledge.contains(dst))
            .map(|(peer_id, vote)| (peer_id.clone(), vote.clone()))
            .collect();

        let consensus = self
            .consensus
            .as_ref()
            .filter(|consensus| !consensus.knowledge.contains(dst))
            .cloned();

        if !votes.is_empty() || consensus.is_some() {
            Some(Self { votes, consensus })
        } else {
            None
        }
    }

    pub fn voted_for_by(&self, peer_id: &P) -> bool {
        self.votes.contains_key(peer_id)
    }

    pub fn votes<'a>(&'a self) -> impl Iterator<Item = (&'a P, &'a Proof<P>)> {
        self.votes
            .iter()
            .map(|(peer_id, vote)| (peer_id, &vote.proof))
    }

    pub fn consensus_index(&self) -> Option<usize> {
        self.consensus.as_ref().map(|consensus| consensus.index)
    }

    pub fn knows_consensus(&self, peer_id: &P) -> bool {
        self.consensus
            .as_ref()
            .map(|consensus| consensus.knowledge.contains(peer_id))
            .unwrap_or(false)
    }

    pub fn acknowledge_consensus(&mut self, peer_id: &P) {
        if let Some(consensus) = self.consensus.as_mut() {
            let _ = consensus.knowledge.insert(peer_id.clone());
        }
    }

    pub fn decide_consensus(&mut self, our_id: &P, index: usize) {
        let mut knowledge = FxHashSet::default();
        let _ = knowledge.insert(our_id.clone());

        self.consensus = Some(ConsensusInfo { index, knowledge });
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(bound = "")]
struct VoteInfo<P: PublicId> {
    proof: Proof<P>,
    knowledge: FxHashSet<P>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(bound = "")]
struct ConsensusInfo<P: PublicId> {
    index: usize,
    knowledge: FxHashSet<P>,
}

pub(super) type ObservationMap<T, P> = BTreeMap<ObservationHolder<T, P>, ObservationInfo<P>>;
