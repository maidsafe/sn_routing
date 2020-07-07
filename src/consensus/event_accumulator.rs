// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    network_event::AccumulatingEvent,
    proof::{Proof, ProofShare},
    signature_accumulator::AccumulationError,
};
use crate::{error::Result, id::PublicId, section::EldersInfo};
use serde::Serialize;
use std::{
    collections::{btree_map::Entry, BTreeMap, BTreeSet, VecDeque},
    iter, mem,
    rc::Rc,
};
use xor_name::XorName;

/// An unresponsive node is detected by conunting how many (defined by UNRESPONSIVE_THRESHOLD)
/// missed votes among the certain number (defined by UNRESPONSIVE_WINDOW) of recent consensused
/// observations.

/// The threshold (number of unvoted votes) a node to be considered as unresponsive.
pub const UNRESPONSIVE_THRESHOLD: usize = 48;
/// The period (X consensued observations) during which node be considered as unresponsive.
pub const UNRESPONSIVE_WINDOW: usize = 64;

#[derive(Default)]
struct VoteStatuses {
    tracked_events: VecDeque<Rc<AccumulatingEvent>>,
    unvoted: BTreeMap<XorName, BTreeSet<Rc<AccumulatingEvent>>>,
}

impl VoteStatuses {
    fn add_expectation(
        &mut self,
        event: AccumulatingEvent,
        voters: &BTreeSet<XorName>,
        elders_info: &EldersInfo,
    ) {
        let event_rc = Rc::new(event);

        for name in elders_info.elders.keys() {
            if voters.contains(name) {
                continue;
            }

            let _ = self
                .unvoted
                .entry(*name)
                .or_default()
                .insert(Rc::clone(&event_rc));
        }

        self.tracked_events.push_back(event_rc);

        // Pruning old events
        if self.tracked_events.len() > UNRESPONSIVE_WINDOW {
            if let Some(removed_event) = self.tracked_events.pop_front() {
                for events in self.unvoted.values_mut() {
                    let _ = events.remove(&removed_event);
                }
            }
        }

        // Pruning old peers
        if self.unvoted.len() > elders_info.elders.len() {
            self.unvoted = mem::replace(&mut self.unvoted, BTreeMap::new())
                .into_iter()
                .filter(|(name, _)| elders_info.elders.contains_key(name))
                .collect();
        }
    }

    fn add_vote(&mut self, event: &AccumulatingEvent, voter: &XorName) {
        if let Some(events) = self.unvoted.get_mut(voter) {
            let _ = events.remove(event);
        }
    }

    fn is_unresponsive(&self, peer: &XorName) -> bool {
        if let Some(events) = self.unvoted.get(peer) {
            events.len() > UNRESPONSIVE_THRESHOLD
        } else {
            false
        }
    }
}

#[derive(Default)]
pub(crate) struct EventAccumulator {
    // A map containing network events that have not been accumulated yet, together with their
    // signature shares that have been collected so far.
    //
    // FIXME: Purge votes that are older than a given period.
    //
    // TODO: replace this with `SignatureAccumulator<AccumulatingEvent>` after we bump the BLS
    // threshold to at least 1/2. This is because `SignatureAccumulator` is based on BLS signature
    // only and currently the threshold is 1/3 which not enough for proper voting (it's not
    // majority).
    unaccumulated_events: BTreeMap<(AccumulatingEvent, bls::PublicKey), State>,
    // Events that were already accumulated: Further incoming shares for these can be ignored.
    // When an event is accumulated, it cannot be inserted again.
    accumulated_events: BTreeSet<AccumulatingEvent>,
    // A struct retains the order of insertion, and keeps tracking of which node has not involved.
    // Entry will be created when an event reached consensus.
    vote_statuses: VoteStatuses,
}

impl EventAccumulator {
    pub fn insert(
        &mut self,
        event: AccumulatingEvent,
        voter_name: XorName,
        proof_share: ProofShare,
        elders_info: &EldersInfo,
    ) -> Result<(AccumulatingEvent, Proof), AccumulationError> {
        if let AccumulatingEvent::Genesis { .. } = event {
            panic!(
                "invalid event inserted into the event accumulator: {:?}",
                event
            );
        }

        if self.accumulated_events.contains(&event) {
            self.vote_statuses.add_vote(&event, &voter_name);
            return Err(AccumulationError::AlreadyAccumulated);
        }

        if !event.verify(&proof_share) {
            return Err(AccumulationError::InvalidShare);
        }

        // Use the public key to differentiate identical events that are signed with different key
        // sets. This is to prevent mixing signature shares from different key sets which would make
        // the whole signature invalid even when the shares themselves are all individually valid.
        let public_key = proof_share.public_key_set.public_key();

        let ((event, _), state) = match self.unaccumulated_events.entry((event, public_key)) {
            Entry::Vacant(entry) => {
                let state = State::new(voter_name, proof_share.index, proof_share.signature_share);
                if state.has_enough_votes(proof_share.public_key_set.threshold(), elders_info) {
                    (entry.into_key(), state)
                } else {
                    let _ = entry.insert(state);
                    return Err(AccumulationError::NotEnoughShares);
                }
            }
            Entry::Occupied(mut entry) => {
                entry
                    .get_mut()
                    .add(voter_name, proof_share.index, proof_share.signature_share);
                if entry
                    .get()
                    .has_enough_votes(proof_share.public_key_set.threshold(), elders_info)
                {
                    entry.remove_entry()
                } else {
                    return Err(AccumulationError::NotEnoughShares);
                }
            }
        };

        let shares = state.shares.iter().map(|(index, share)| (*index, share));
        let signature = proof_share
            .public_key_set
            .combine_signatures(shares)
            .map_err(AccumulationError::Combine)?;
        let proof = Proof {
            public_key,
            signature,
        };

        self.vote_statuses
            .add_expectation(event.clone(), &state.voters, elders_info);
        let _ = self.accumulated_events.insert(event.clone());

        Ok((event, proof))
    }

    pub fn reset(&mut self, our_name: &XorName) -> RemainingEvents {
        let accumulated_events = std::mem::take(&mut self.accumulated_events);
        let unaccumulated_events = std::mem::take(&mut self.unaccumulated_events);
        self.vote_statuses = Default::default();

        RemainingEvents {
            unaccumulated_events: unaccumulated_events
                .into_iter()
                .filter(|(_, state)| state.voters.contains(our_name))
                .map(|((event, _), _)| event)
                .collect(),
            accumulated_events,
        }
    }

    pub fn detect_unresponsive(&self, elders_info: &EldersInfo) -> BTreeSet<PublicId> {
        elders_info
            .elder_ids()
            .filter(|id| self.vote_statuses.is_unresponsive(id.name()))
            .copied()
            .collect()
    }
}

// Accumulation state of a single event in the event accumulator.
#[derive(Default, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Serialize, Deserialize)]
struct State {
    voters: BTreeSet<XorName>,
    shares: BTreeMap<usize, bls::SignatureShare>,
}

impl State {
    fn new(voter_name: XorName, voter_index: usize, signature_share: bls::SignatureShare) -> Self {
        let voters = iter::once(voter_name).collect();
        let shares = iter::once((voter_index, signature_share)).collect();

        Self { voters, shares }
    }

    fn add(
        &mut self,
        voter_name: XorName,
        voter_index: usize,
        signature_share: bls::SignatureShare,
    ) {
        let _ = self.shares.insert(voter_index, signature_share);
        let _ = self.voters.insert(voter_name);
    }

    fn has_enough_votes(&self, threshold: usize, elders_info: &EldersInfo) -> bool {
        self.shares.len() > threshold && elders_info.is_quorum(&self.voters)
    }
}

/// The outcome of a prefix change.
#[derive(Default, PartialEq, Eq, Debug)]
pub(crate) struct RemainingEvents {
    /// The remaining unaccumulated events that should be revoted.
    pub unaccumulated_events: BTreeSet<AccumulatingEvent>,
    /// The already accumulated events.
    pub accumulated_events: BTreeSet<AccumulatingEvent>,
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        id::{FullId, P2pNode},
        rng::{self, MainRng},
        ELDER_SIZE,
    };
    use rand::{distributions::Standard, seq::IteratorRandom, Rng};
    use std::{iter, net::SocketAddr};

    #[test]
    fn insert() {
        let mut rng = rng::new();
        let elders_info = gen_elders_info(&mut rng);
        let sk_set = bls::SecretKeySet::random(3, &mut rng);

        let mut accumulator = EventAccumulator::default();
        let event = gen_event(&mut rng);

        // The first 4 votes are not enough to accumulate
        for (index, name) in elders_info.elders.keys().enumerate().take(4) {
            let proof_share = create_proof_share(&sk_set, index, &event);

            match accumulator.insert(event.clone(), *name, proof_share, &elders_info) {
                Err(AccumulationError::NotEnoughShares) => (),
                result => panic!("unexpected result {:?}", result),
            }
        }

        // With the 5th vote we reach the quorum
        let proof_share = create_proof_share(&sk_set, 4, &event);
        let accumulated_event = match accumulator.insert(
            event.clone(),
            *elders_info.elders.keys().nth(4).unwrap(),
            proof_share,
            &elders_info,
        ) {
            Ok((event, _proofs)) => event,
            Err(error) => panic!("unexpected error: {:?}", error),
        };
        assert_eq!(accumulated_event, event);

        // Any additional votes are redundant
        let proof_share = create_proof_share(&sk_set, 5, &event);
        match accumulator.insert(
            event,
            *elders_info.elders.keys().nth(5).unwrap(),
            proof_share,
            &elders_info,
        ) {
            Err(AccumulationError::AlreadyAccumulated) => (),
            result => panic!("unexpected result {:?}", result),
        }
    }

    #[test]
    fn reset() {
        let mut rng = rng::new();
        let elders_info = gen_elders_info(&mut rng);
        let sk_set = bls::SecretKeySet::random(3, &mut rng);

        let mut accumulator = EventAccumulator::default();

        // one accumulated event
        let event0 = gen_event(&mut rng);
        for (index, name) in elders_info.elders.keys().enumerate().take(5) {
            let proof_share = create_proof_share(&sk_set, index, &event0);
            let _ = accumulator.insert(event0.clone(), *name, proof_share, &elders_info);
        }

        // one unaccumulated event voted for by node 0
        let event1 = gen_event(&mut rng);
        for (index, name) in elders_info.elders.keys().enumerate().take(4) {
            let proof_share = create_proof_share(&sk_set, index, &event1);
            let _ = accumulator.insert(event1.clone(), *name, proof_share, &elders_info);
        }

        // one unaccumulated event not voted for by node 0
        let event2 = gen_event(&mut rng);
        for (index, name) in elders_info.elders.keys().enumerate().skip(1).take(4) {
            let proof_share = create_proof_share(&sk_set, index, &event2);
            let _ = accumulator.insert(event2.clone(), *name, proof_share, &elders_info);
        }

        let RemainingEvents {
            unaccumulated_events,
            accumulated_events,
        } = accumulator.reset(elders_info.elders.keys().next().unwrap());

        assert!(!unaccumulated_events.contains(&event0));
        assert!(accumulated_events.contains(&event0));

        assert!(unaccumulated_events.contains(&event1));
        assert!(!accumulated_events.contains(&event1));

        assert!(!unaccumulated_events.contains(&event2));
        assert!(!accumulated_events.contains(&event2));
    }

    #[test]
    fn tracking_responsiveness() {
        let mut rng = rng::new();

        let elders_info = gen_elders_info(&mut rng);
        let sk_set = bls::SecretKeySet::random(3, &mut rng);

        let unresponsive_node = elders_info.elders.keys().choose(&mut rng).unwrap();

        let mut acc = EventAccumulator::default();

        for step in 0..UNRESPONSIVE_WINDOW {
            let event = AccumulatingEvent::User(step.to_ne_bytes().to_vec());

            for (index, name) in elders_info.elders.keys().enumerate() {
                if step >= (UNRESPONSIVE_WINDOW - UNRESPONSIVE_THRESHOLD - 1)
                    && name == unresponsive_node
                {
                    continue;
                }

                let proof_share = create_proof_share(&sk_set, index, &event);
                let _ = acc.insert(event.clone(), *name, proof_share, &elders_info);
            }
        }

        let expected: BTreeSet<_> = iter::once(*unresponsive_node).collect();
        let detected: BTreeSet<_> = acc
            .detect_unresponsive(&elders_info)
            .into_iter()
            .map(|id| *id.name())
            .collect();
        assert_eq!(detected, expected);
    }

    fn gen_elders_info(rng: &mut MainRng) -> EldersInfo {
        let elders = (0..ELDER_SIZE)
            .map(|_| {
                let full_id = FullId::gen(rng);
                let addr = gen_socket_addr(rng);
                let p2p_node = P2pNode::new(*full_id.public_id(), addr);
                (*p2p_node.public_id().name(), p2p_node)
            })
            .collect();

        EldersInfo::new(elders, Default::default())
    }

    fn gen_socket_addr(rng: &mut MainRng) -> SocketAddr {
        let ip: [u8; 4] = rng.gen();
        let port: u16 = rng.gen();
        SocketAddr::from((ip, port))
    }

    fn gen_event(rng: &mut MainRng) -> AccumulatingEvent {
        AccumulatingEvent::User(rng.sample_iter(&Standard).take(10).collect())
    }

    fn create_proof_share(
        sk_set: &bls::SecretKeySet,
        index: usize,
        event: &AccumulatingEvent,
    ) -> ProofShare {
        let sk_share = sk_set.secret_key_share(index);
        let signature_share = event.sign(&sk_share).unwrap();
        ProofShare {
            public_key_set: sk_set.public_keys(),
            index,
            signature_share,
        }
    }
}
