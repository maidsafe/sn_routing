// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Shared state for all mock parsec instances within a single test.

use super::{
    key_gen::KeyGen,
    observation::{ObservationHolder, ObservationState},
    Block, ConsensusMode, DkgResult, NetworkEvent, PublicId, SecretId,
};
use crate::sha3::Digest256;
use rand::Rng;
use std::{
    any::Any,
    cell::RefCell,
    collections::{
        btree_map::{BTreeMap, Entry},
        BTreeSet, HashMap,
    },
    mem,
};
use unwrap::unwrap;

pub(super) struct SectionState<T: NetworkEvent, P: PublicId> {
    observations: BTreeMap<ObservationHolder<T, P>, ObservationState<P>>,
    // Unconsensused Observations in the order they were first voted for.
    // In real Parsec, observations that are voted first should come out first if they all reach
    // consensus at the same time.
    unconsensused_observations: Vec<ObservationHolder<T, P>>,
    blocks: Vec<(Block<T, P>, ObservationHolder<T, P>)>,
    key_gen: KeyGen<P>,
}

impl<T: NetworkEvent, P: PublicId> SectionState<T, P> {
    fn new() -> Self {
        Self {
            observations: BTreeMap::new(),
            unconsensused_observations: Vec::new(),
            blocks: Vec::new(),
            key_gen: KeyGen::new(),
        }
    }

    pub fn vote<S>(&mut self, our_id: &S, holder: ObservationHolder<T, P>)
    where
        S: SecretId<PublicId = P>,
    {
        let state = match self.observations.entry(holder.clone()) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                self.unconsensused_observations.push(holder.clone());
                entry.insert(ObservationState::new())
            }
        };

        state.vote(our_id, &holder)
    }

    pub fn compute_consensus(&mut self, peers: &BTreeSet<P>, consensus_mode: ConsensusMode) {
        let mut unconsensused_genesis = false;

        // Update consensus for unconsensused_observations.
        // Add blocks for consensused observations and keep others in unconsensused_observations.
        // Genesis needs to be the first block: If it is unconsensused, no block is added.
        // (Genesis is the first `unconsensused_observations` if present (voted on creation).
        //  Because it requires supermajority consensus, we need to ensure Opaque payloads that
        //  only require a single vote do not become blocks before genesis.)
        for holder in mem::replace(&mut self.unconsensused_observations, Vec::new()) {
            if !unconsensused_genesis {
                let state = unwrap!(self.observations.get_mut(&holder));
                if let Some(block) = state.compute_consensus(peers, consensus_mode, &holder) {
                    self.blocks.push((block, holder));
                    continue;
                }
            }

            unconsensused_genesis |= holder.is_genesis();
            self.unconsensused_observations.push(holder);
        }
    }

    pub fn get_block(&self, index: usize) -> Option<BlockInfo<T, P>> {
        let (block, holder) = self.blocks.get(index)?;
        Some((block, holder))
    }

    pub fn has_unconsensused_observations(&self) -> bool {
        !self.unconsensused_observations.is_empty()
    }

    /// Returns the result of a fake Distributed Key Generation for the given set of participants.
    /// Note: this uses trusted dealer under the hood, no actual DKG is taking place.
    pub fn get_or_generate_keys(
        &mut self,
        rng: &mut impl Rng,
        our_id: &P,
        participants: BTreeSet<P>,
    ) -> DkgResult {
        self.key_gen.get_or_generate(rng, our_id, participants)
    }
}

pub(super) type BlockInfo<'a, T, P> = (&'a Block<T, P>, &'a ObservationHolder<T, P>);

type NetworkState<T, P> = HashMap<Digest256, SectionState<T, P>>;

thread_local! {
    static STATE: RefCell<Option<Box<dyn Any>>> = RefCell::new(None);
}

pub(super) fn reset() {
    STATE.with(|state| {
        *state.borrow_mut() = None;
    })
}

pub(super) fn with<T, P, F, R>(section_hash: Digest256, f: F) -> R
where
    T: NetworkEvent + 'static,
    P: PublicId + 'static,
    F: FnOnce(&mut SectionState<T, P>) -> R,
{
    STATE.with(|cell| {
        let mut opt_network_state = cell.borrow_mut();
        match opt_network_state.as_mut() {
            None => {
                let mut section_state = SectionState::new();
                let result = f(&mut section_state);

                let mut network_state = HashMap::new();
                let _ = network_state.insert(section_hash, section_state);
                *opt_network_state = Some(Box::new(network_state));

                result
            }
            Some(dyn_network_state) => {
                let network_state: &mut NetworkState<T, P> =
                    unwrap!(dyn_network_state.downcast_mut());
                let section_state = network_state
                    .entry(section_hash)
                    .or_insert_with(SectionState::new);
                f(section_state)
            }
        }
    })
}
