// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    network_event::{AccumulatingEvent, ProofShare},
    proof::{Proof, ProofSet},
};
use crate::{
    error::{Result, RoutingError},
    id::PublicId,
    section::EldersInfo,
};
use serde::Serialize;
use std::{
    collections::{btree_map::Entry, BTreeMap, BTreeSet, VecDeque},
    mem,
    rc::Rc,
};

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
    unvoted: BTreeMap<PublicId, BTreeSet<Rc<AccumulatingEvent>>>,
}

impl VoteStatuses {
    fn add_expectation(
        &mut self,
        event: AccumulatingEvent,
        non_voters: BTreeSet<PublicId>,
        elders_info: &EldersInfo,
    ) {
        let event_rc = Rc::new(event);
        for id in non_voters {
            let events = self.unvoted.entry(id).or_insert_with(BTreeSet::new);
            let _ = events.insert(Rc::clone(&event_rc));
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
                .filter(|(id, _)| elders_info.elders.contains_key(id.name()))
                .collect();
        }
    }

    fn add_vote(&mut self, event: &AccumulatingEvent, voter: &PublicId) {
        if let Some(events) = self.unvoted.get_mut(voter) {
            let _ = events.remove(event);
        }
    }

    fn is_unresponsive(&self, peer: &PublicId) -> bool {
        if let Some(events) = self.unvoted.get(peer) {
            events.len() > UNRESPONSIVE_THRESHOLD
        } else {
            false
        }
    }
}

#[derive(Default)]
pub struct EventAccumulator {
    // A map containing network events that have not been accumulated yet, together with their
    // proofs that have been collected so far. We are still waiting for more proofs, or to reach a
    // state where we can handle the event.
    // FIXME: Purge votes that are older than a given period.
    unaccumulated_events: BTreeMap<AccumulatingEvent, AccumulatingProof>,
    // Events that were already accumulated: Further incoming proofs for these can be ignored.
    // When an event is accumulated, it cannot be polled or inserted again.
    accumulated_events: BTreeSet<AccumulatingEvent>,
    // A struct retains the order of insertion, and keeps tracking of which node has not involved.
    // Entry will be created when an event reached consensus.
    vote_statuses: VoteStatuses,
}

impl EventAccumulator {
    pub fn insert(
        &mut self,
        event: AccumulatingEvent,
        node_proof: Proof,
        section_proof_share: Option<ProofShare>,
        elders_info: &EldersInfo,
    ) -> Result<(AccumulatingEvent, AccumulatingProof), AccumulatingError> {
        match &event {
            AccumulatingEvent::Genesis { .. }
            | AccumulatingEvent::StartDkg(_)
            | AccumulatingEvent::DkgResult { .. } => panic!(
                "invalid event inserted into the event accumulator: {:?}",
                event
            ),
            _ => (),
        }

        if self.accumulated_events.contains(&event) {
            self.vote_statuses.add_vote(&event, &node_proof.pub_id);
            return Err(AccumulatingError::AlreadyAccumulated);
        }

        let (_, signature_share) = if let Some(proof_share) = section_proof_share {
            (
                Some(proof_share.public_key_set),
                Some((proof_share.index, proof_share.signature_share)),
            )
        } else {
            (None, None)
        };

        let (event, proofs) = match self.unaccumulated_events.entry(event) {
            Entry::Vacant(entry) => {
                let mut proofs = AccumulatingProof::default();
                proofs.add_proof(node_proof, signature_share)?;

                if !elders_info.is_quorum(proofs.parsec_proof_set()) {
                    let _ = entry.insert(proofs);
                    return Err(AccumulatingError::NotEnoughVotes);
                }

                (entry.into_key(), proofs)
            }
            Entry::Occupied(mut entry) => {
                entry.get_mut().add_proof(node_proof, signature_share)?;

                if !elders_info.is_quorum(entry.get().parsec_proof_set()) {
                    return Err(AccumulatingError::NotEnoughVotes);
                }

                entry.remove_entry()
            }
        };

        self.add_expectation(event.clone(), &proofs, elders_info);
        let _ = self.accumulated_events.insert(event.clone());

        Ok((event, proofs))
    }

    pub fn reset(&mut self, our_id: &PublicId) -> RemainingEvents {
        let accumulated_events = std::mem::take(&mut self.accumulated_events);
        let unaccumulated_events = std::mem::take(&mut self.unaccumulated_events);
        self.vote_statuses = Default::default();

        RemainingEvents {
            unaccumulated_events: unaccumulated_events
                .into_iter()
                .filter(|(_, proofs)| proofs.parsec_proofs.contains_id(our_id))
                .map(|(event, _)| event)
                .collect(),
            accumulated_events,
        }
    }

    pub fn detect_unresponsive(&self, elders_info: &EldersInfo) -> BTreeSet<PublicId> {
        elders_info
            .elder_ids()
            .filter(|id| self.vote_statuses.is_unresponsive(id))
            .copied()
            .collect()
    }

    fn add_expectation(
        &mut self,
        event: AccumulatingEvent,
        proofs: &AccumulatingProof,
        elders_info: &EldersInfo,
    ) {
        let non_voted = elders_info
            .elder_ids()
            .filter(|id| !proofs.parsec_proof_set().contains_id(id))
            .copied()
            .collect();

        self.vote_statuses
            .add_expectation(event, non_voted, elders_info);
    }
}

#[derive(Default, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Serialize, Deserialize)]
pub struct AccumulatingProof {
    parsec_proofs: ProofSet,
    sig_shares: BTreeSet<(usize, bls::SignatureShare)>,
}

impl AccumulatingProof {
    /// Return false if share or proof is replaced
    pub fn add_proof(
        &mut self,
        proof: Proof,
        sig_share: Option<(usize, bls::SignatureShare)>,
    ) -> Result<(), AccumulatingError> {
        if let Some(sig_share) = sig_share {
            if !self.sig_shares.insert(sig_share) {
                return Err(AccumulatingError::ReplacedAlreadyInserted);
            }
        }

        if !self.parsec_proofs.add_proof(proof) {
            return Err(AccumulatingError::ReplacedAlreadyInserted);
        }

        Ok(())
    }

    pub fn parsec_proof_set(&self) -> &ProofSet {
        &self.parsec_proofs
    }

    /// Check the signature shares at the given `signature_index` and combine them into a
    /// complete signature.
    pub fn check_and_combine_signatures(
        &self,
        pk_set: &bls::PublicKeySet,
        signed_bytes: &[u8],
    ) -> Result<bls::Signature> {
        let shares = self
            .sig_shares
            .iter()
            .filter(|(index, share)| pk_set.public_key_share(index).verify(share, signed_bytes))
            .map(|(index, share)| (*index, share));

        pk_set.combine_signatures(shares).map_err(|error| {
            log_or_panic!(log::Level::Error, "Failed to combine signatures: {}", error);
            RoutingError::InvalidSignatureShares
        })
    }
}

#[derive(PartialEq, Eq, Debug)]
pub enum AccumulatingError {
    NotEnoughVotes,
    AlreadyAccumulated,
    ReplacedAlreadyInserted,
}

/// The outcome of a prefix change.
#[derive(Default, PartialEq, Eq, Debug)]
pub struct RemainingEvents {
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
    use itertools::Itertools;
    use rand::{distributions::Standard, seq::SliceRandom, Rng};
    use std::{iter, net::SocketAddr};

    #[test]
    fn insert_without_signature_shares() {
        let mut rng = rng::new();
        let (elders_info, full_ids) = gen_elders_info(&mut rng);

        let mut accumulator = EventAccumulator::default();
        let event = gen_event(&mut rng);

        // The first 4 votes are not enough to accumulate
        for full_id in &full_ids[..4] {
            let proof = create_proof(full_id);
            assert_eq!(
                accumulator.insert(event.clone(), proof, None, &elders_info),
                Err(AccumulatingError::NotEnoughVotes)
            );
        }

        // With the 5th vote we reach the quorum
        let proof = create_proof(&full_ids[4]);
        let accumulated_event = match accumulator.insert(event.clone(), proof, None, &elders_info) {
            Ok((event, _proofs)) => event,
            Err(error) => panic!("unexpected error: {:?}", error),
        };
        assert_eq!(accumulated_event, event);

        // Any additional votes are redundant
        let proof = create_proof(&full_ids[5]);
        assert_eq!(
            accumulator.insert(event, proof, None, &elders_info),
            Err(AccumulatingError::AlreadyAccumulated)
        );
    }

    #[test]
    fn reset() {
        let mut rng = rng::new();
        let (elders_info, full_ids) = gen_elders_info(&mut rng);

        let mut accumulator = EventAccumulator::default();

        // one accumulated event
        let event0 = gen_event(&mut rng);
        for full_id in &full_ids[..5] {
            let proof = create_proof(full_id);
            let _ = accumulator.insert(event0.clone(), proof, None, &elders_info);
        }

        // one unaccumulated event voted for by node 0
        let event1 = gen_event(&mut rng);
        for full_id in &full_ids[..4] {
            let proof = create_proof(full_id);
            let _ = accumulator.insert(event1.clone(), proof, None, &elders_info);
        }

        // one unaccumulated event not voted for by node 0
        let event2 = gen_event(&mut rng);
        for full_id in &full_ids[1..5] {
            let proof = create_proof(full_id);
            let _ = accumulator.insert(event2.clone(), proof, None, &elders_info);
        }

        let RemainingEvents {
            unaccumulated_events,
            accumulated_events,
        } = accumulator.reset(full_ids[0].public_id());

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

        let (elders_info, full_ids) = gen_elders_info(&mut rng);
        let proofs: Vec<_> = full_ids.iter().map(create_proof).collect();
        let unresponsive_node = full_ids.choose(&mut rng).unwrap().public_id();

        let mut acc = EventAccumulator::default();

        for i in 0..UNRESPONSIVE_WINDOW {
            let event = AccumulatingEvent::User([i as u8].to_vec());
            for proof in &proofs {
                if i >= (UNRESPONSIVE_WINDOW - UNRESPONSIVE_THRESHOLD - 1)
                    && proof.pub_id == *unresponsive_node
                {
                    continue;
                }

                let _ = acc.insert(event.clone(), *proof, None, &elders_info);
            }
        }

        let expected: BTreeSet<_> = iter::once(*unresponsive_node).collect();
        let detected = acc.detect_unresponsive(&elders_info);
        assert_eq!(detected, expected);
    }

    const TEST_DATA_FOR_SIGN: [u8; 1] = [1];

    // Generate elders info and the corresponding full ids in the same order.
    fn gen_elders_info(rng: &mut MainRng) -> (EldersInfo, Vec<FullId>) {
        let full_ids: Vec<_> = (0..ELDER_SIZE)
            .map(|_| FullId::gen(rng))
            .sorted_by(|lhs, rhs| lhs.public_id().name().cmp(rhs.public_id().name()))
            .collect();

        let elders = full_ids
            .iter()
            .map(|full_id| {
                let addr = gen_socket_addr(rng);
                let p2p_node = P2pNode::new(*full_id.public_id(), addr);
                (*p2p_node.public_id().name(), p2p_node)
            })
            .collect();

        (EldersInfo::new(elders, Default::default()), full_ids)
    }

    fn gen_socket_addr(rng: &mut MainRng) -> SocketAddr {
        let ip: [u8; 4] = rng.gen();
        let port: u16 = rng.gen();
        SocketAddr::from((ip, port))
    }

    fn gen_event(rng: &mut MainRng) -> AccumulatingEvent {
        AccumulatingEvent::User(rng.sample_iter(&Standard).take(10).collect())
    }

    fn create_proof(full_id: &FullId) -> Proof {
        let sig = full_id.sign(&TEST_DATA_FOR_SIGN);
        Proof {
            pub_id: *full_id.public_id(),
            sig,
        }
    }
}
