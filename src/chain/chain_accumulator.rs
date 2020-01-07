// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{AccumulatingEvent, EldersInfo, EventSigPayload, NetworkEvent, Proof, ProofSet};
use crate::id::PublicId;
use log::LogLevel;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    mem,
    rc::Rc,
};
use threshold_crypto::{PublicKeySet, Signature};

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
        all_members: &BTreeSet<PublicId>,
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
        if self.unvoted.len() > all_members.len() {
            self.unvoted = mem::replace(&mut self.unvoted, BTreeMap::new())
                .into_iter()
                .filter(|(peer_id, _)| all_members.contains(peer_id))
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
pub(super) struct ChainAccumulator {
    /// A map containing network events that have not been handled yet, together with their proofs
    /// that have been collected so far. We are still waiting for more proofs, or to reach a state
    /// where we can handle the event.
    // FIXME: Purge votes that are older than a given period.
    chain_accumulator: BTreeMap<AccumulatingEvent, AccumulatingProof>,
    /// Events that were handled: Further incoming proofs for these can be ignored.
    /// When an event is completed, it cannot be or inserted in chain_accumulator.
    completed_events: BTreeSet<AccumulatingEvent>,
    /// A struct retains the order of insertion, and keeps tracking of which node has not involved.
    /// Entry will be created when an event reached consensus.
    vote_statuses: VoteStatuses,
}

impl ChainAccumulator {
    #[cfg(test)]
    pub fn insert_with_proof_set(
        &mut self,
        event: AccumulatingEvent,
        proof_set: ProofSet,
    ) -> Result<(), InsertError> {
        if self.completed_events.contains(&event) {
            return Err(InsertError::AlreadyComplete);
        }

        let proof = AccumulatingProof::from_proof_set(proof_set);
        if self.chain_accumulator.insert(event, proof).is_some() {
            return Err(InsertError::ReplacedAlreadyInserted);
        }

        Ok(())
    }

    pub fn add_proof(
        &mut self,
        event: AccumulatingEvent,
        proof: Proof,
        signature: Option<EventSigPayload>,
    ) -> Result<(), InsertError> {
        if self.completed_events.contains(&event) {
            self.vote_statuses.add_vote(&event, &proof.pub_id);
            return Err(InsertError::AlreadyComplete);
        }

        if !self
            .chain_accumulator
            .entry(event)
            .or_insert_with(AccumulatingProof::default)
            .add_proof(proof, signature)
        {
            return Err(InsertError::ReplacedAlreadyInserted);
        }

        Ok(())
    }

    pub fn poll_event(
        &mut self,
        event: AccumulatingEvent,
        all_voters: BTreeSet<PublicId>,
    ) -> Option<(AccumulatingEvent, AccumulatingProof)> {
        let proofs = self.chain_accumulator.remove(&event)?;

        if !self.completed_events.insert(event.clone()) {
            log_or_panic!(LogLevel::Warn, "Duplicate insert in completed events.");
        }

        self.add_expectation(event.clone(), &proofs, all_voters);

        Some((event, proofs))
    }

    pub fn incomplete_events(
        &self,
    ) -> impl Iterator<Item = (&AccumulatingEvent, &AccumulatingProof)> {
        self.chain_accumulator.iter()
    }

    pub fn reset_accumulator(&mut self, our_id: &PublicId) -> RemainingEvents {
        let completed_events = mem::replace(&mut self.completed_events, Default::default());
        let chain_acc = mem::replace(&mut self.chain_accumulator, Default::default());
        self.vote_statuses = Default::default();

        RemainingEvents {
            cached_events: chain_acc
                .into_iter()
                .filter(|&(_, ref proofs)| proofs.parsec_proofs.contains_id(our_id))
                .map(|(event, proofs)| {
                    event.into_network_event_with(proofs.into_sig_shares().remove(our_id))
                })
                .collect(),
            completed_events,
        }
    }

    pub fn add_expectation(
        &mut self,
        event: AccumulatingEvent,
        proofs: &AccumulatingProof,
        all_voters: BTreeSet<PublicId>,
    ) {
        let mut non_voted = all_voters.clone();
        for id in proofs.parsec_proof_set().ids() {
            let _ = non_voted.remove(id);
        }
        self.vote_statuses
            .add_expectation(event, non_voted, &all_voters);
    }

    pub fn check_vote_status<'a>(
        &self,
        members: impl Iterator<Item = &'a PublicId>,
    ) -> BTreeSet<PublicId> {
        members
            .filter(|peer_id| self.vote_statuses.is_unresponsive(peer_id))
            .cloned()
            .collect()
    }
}

#[derive(Default, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Serialize, Deserialize)]
pub struct AccumulatingProof {
    parsec_proofs: ProofSet,
    sig_shares: BTreeMap<PublicId, EventSigPayload>,
}

impl AccumulatingProof {
    #[allow(unused)]
    pub fn from_proof_set(parsec_proofs: ProofSet) -> Self {
        Self {
            parsec_proofs,
            sig_shares: Default::default(),
        }
    }

    /// Return false if share or proof is replaced
    pub fn add_proof(&mut self, proof: Proof, info_sig: Option<EventSigPayload>) -> bool {
        let new_share = info_sig.map_or(true, |share| {
            self.sig_shares.insert(proof.pub_id, share).is_none()
        });

        let new_proof = self.parsec_proofs.add_proof(proof);
        new_share && new_proof
    }

    pub fn parsec_proof_set(&self) -> &ProofSet {
        &self.parsec_proofs
    }

    pub fn into_sig_shares(self) -> BTreeMap<PublicId, EventSigPayload> {
        self.sig_shares
    }

    pub fn check_and_combine_signatures(
        self,
        elder_info: &EldersInfo,
        pk_set: &PublicKeySet,
        signed_bytes: &[u8],
    ) -> Option<Signature> {
        let fr_and_shares = elder_info
            .member_ids()
            .enumerate()
            .filter_map(|(index, pub_id)| {
                self.sig_shares
                    .get(pub_id)
                    .map(|sig_payload| (index, &sig_payload.sig_share))
            })
            .filter(|&(index, sig_share)| {
                pk_set
                    .public_key_share(index)
                    .verify(sig_share, signed_bytes)
            });
        pk_set.combine_signatures(fr_and_shares).ok()
    }
}

#[derive(PartialEq, Eq, Debug)]
pub enum InsertError {
    AlreadyComplete,
    ReplacedAlreadyInserted,
}

/// The outcome of a prefix change.
#[derive(Default, PartialEq, Eq, Debug)]
pub struct RemainingEvents {
    /// The cached events that should be revoted.
    pub cached_events: BTreeSet<NetworkEvent>,
    /// The completed events.
    pub completed_events: BTreeSet<AccumulatingEvent>,
}

#[cfg(test)]
mod test {
    use super::super::{EldersInfo, SectionKeyInfo};
    use super::*;
    use crate::{
        id::FullId,
        parsec::generate_bls_threshold_secret_key,
        rng::{self, MainRng},
        unwrap,
    };
    use parsec::SecretId;
    use std::iter;

    const TEST_DATA_FOR_SIGN: [u8; 1] = [1u8];

    struct TestData {
        pub our_id: PublicId,
        pub event: AccumulatingEvent,
        pub network_event: NetworkEvent,
        pub first_proof: Proof,
        pub proofs: ProofSet,
        pub acc_proofs: AccumulatingProof,
        pub signature: Option<EventSigPayload>,
    }

    enum EventType {
        WithSignature,
        NoSignature,
    }

    fn empty_elders_info() -> EldersInfo {
        unwrap!(EldersInfo::new_for_test(
            Default::default(),
            Default::default(),
            Default::default(),
        ))
    }

    fn random_section_info_sig_payload(rng: &mut MainRng) -> (EventSigPayload, PublicKeySet) {
        let participants = 2;
        let first_secret_key_index = 0;
        let bls_keys = generate_bls_threshold_secret_key(rng, participants);
        let bls_secret_key_share = bls_keys.secret_key_share(first_secret_key_index);

        (
            EventSigPayload {
                pub_key_share: bls_secret_key_share.public_key_share(),
                sig_share: bls_secret_key_share.sign(&TEST_DATA_FOR_SIGN),
            },
            bls_keys.public_keys(),
        )
    }

    fn random_ids_and_proof(rng: &mut MainRng) -> (FullId, Proof) {
        let id = FullId::gen(rng);
        let pub_id = *id.public_id();
        let sig = id.sign_detached(&TEST_DATA_FOR_SIGN);

        (id, Proof { pub_id, sig })
    }

    fn test_data_random_key(rng: &mut MainRng, event_type: EventType) -> TestData {
        let (id, first_proof) = random_ids_and_proof(rng);
        let proofs = ProofSet {
            sigs: iter::once((first_proof.pub_id, first_proof.sig)).collect(),
        };

        match event_type {
            EventType::NoSignature => {
                let event = AccumulatingEvent::User(vec![0]);
                TestData {
                    our_id: *id.public_id(),
                    event: event.clone(),
                    network_event: event.into_network_event(),
                    first_proof,
                    proofs: proofs.clone(),
                    acc_proofs: AccumulatingProof {
                        parsec_proofs: proofs,
                        sig_shares: Default::default(),
                    },
                    signature: None,
                }
            }
            EventType::WithSignature => {
                let elders_info = empty_elders_info();
                let (sig_payload, keys) = random_section_info_sig_payload(rng);
                let key_info = SectionKeyInfo::from_elders_info(&elders_info, keys.public_key());
                let event = AccumulatingEvent::SectionInfo(elders_info, key_info);

                TestData {
                    our_id: *id.public_id(),
                    event: event.clone(),
                    network_event: event.into_network_event_with(Some(sig_payload.clone())),
                    first_proof,
                    proofs: proofs.clone(),
                    acc_proofs: AccumulatingProof {
                        parsec_proofs: proofs,
                        sig_shares: iter::once((first_proof.pub_id, sig_payload.clone())).collect(),
                    },
                    signature: Some(sig_payload),
                }
            }
        }
    }

    fn incomplete_events(acc: &ChainAccumulator) -> Vec<(AccumulatingEvent, AccumulatingProof)> {
        acc.incomplete_events()
            .map(|(e, p)| (e.clone(), p.clone()))
            .collect()
    }

    fn completed_events(acc: &ChainAccumulator) -> Vec<AccumulatingEvent> {
        acc.completed_events.iter().cloned().collect()
    }

    #[test]
    fn insert_with_proof_set_no_sig() {
        insert_with_proof_set(test_data_random_key(
            &mut rng::new(),
            EventType::NoSignature,
        ));
    }

    fn insert_with_proof_set(data: TestData) {
        let mut acc = ChainAccumulator::default();
        let result = acc.insert_with_proof_set(data.event.clone(), data.proofs.clone());

        assert_eq!(result, Ok(()));
        assert_eq!(incomplete_events(&acc), vec![(data.event, data.acc_proofs)]);
    }

    #[test]
    fn poll_proof_no_sig() {
        poll_proof(test_data_random_key(
            &mut rng::new(),
            EventType::NoSignature,
        ));
    }

    fn poll_proof(data: TestData) {
        let mut acc = ChainAccumulator::default();
        let _ = acc.insert_with_proof_set(data.event.clone(), data.proofs.clone());

        let event_to_poll = unwrap!(acc.incomplete_events().next()).0.clone();
        let result = acc.poll_event(event_to_poll, Default::default());

        assert_eq!(result, Some((data.event, data.acc_proofs)));
        assert_eq!(incomplete_events(&acc), vec![]);
    }

    #[test]
    fn re_insert_with_proof_set_no_sig() {
        let mut rng = rng::new();
        re_insert_with_proof_set(
            test_data_random_key(&mut rng, EventType::NoSignature),
            test_data_random_key(&mut rng, EventType::NoSignature),
        );
    }

    fn re_insert_with_proof_set(data: TestData, data2: TestData) {
        let mut acc = ChainAccumulator::default();
        let _ = acc.insert_with_proof_set(data.event.clone(), data.proofs.clone());

        let result = acc.insert_with_proof_set(data.event.clone(), data2.proofs.clone());

        assert_eq!(result, Err(InsertError::ReplacedAlreadyInserted));
        assert_eq!(
            incomplete_events(&acc),
            vec![(data.event, data2.acc_proofs)]
        );
    }

    #[test]
    fn re_insert_with_proof_set_after_poll_no_sig() {
        let mut rng = rng::new();
        re_insert_with_proof_set_after_poll(
            test_data_random_key(&mut rng, EventType::NoSignature),
            test_data_random_key(&mut rng, EventType::NoSignature),
        );
    }

    fn re_insert_with_proof_set_after_poll(data: TestData, data2: TestData) {
        let mut acc = ChainAccumulator::default();
        let _ = acc.insert_with_proof_set(data.event.clone(), data.proofs.clone());
        let _ = acc.poll_event(data.event.clone(), Default::default());

        let result = acc.insert_with_proof_set(data.event, data2.proofs);

        assert_eq!(result, Err(InsertError::AlreadyComplete));
        assert_eq!(incomplete_events(&acc), vec![]);
    }

    #[test]
    fn add_proof_no_sig() {
        add_proof(test_data_random_key(
            &mut rng::new(),
            EventType::NoSignature,
        ));
    }

    #[test]
    fn add_proof_with_sig() {
        add_proof(test_data_random_key(
            &mut rng::new(),
            EventType::WithSignature,
        ));
    }

    fn add_proof(data: TestData) {
        let mut acc = ChainAccumulator::default();
        let result = acc.add_proof(data.event.clone(), data.first_proof, data.signature.clone());

        assert_eq!(result, Ok(()));
        assert_eq!(incomplete_events(&acc), vec![(data.event, data.acc_proofs)]);
    }

    #[test]
    fn re_add_proof_no_sig() {
        re_add_proof(test_data_random_key(
            &mut rng::new(),
            EventType::NoSignature,
        ));
    }

    #[test]
    fn re_add_proof_with_sig() {
        re_add_proof(test_data_random_key(
            &mut rng::new(),
            EventType::WithSignature,
        ));
    }

    fn re_add_proof(data: TestData) {
        let mut acc = ChainAccumulator::default();
        let _ = acc.add_proof(data.event.clone(), data.first_proof, data.signature.clone());

        let result = acc.add_proof(data.event.clone(), data.first_proof, data.signature.clone());

        assert_eq!(result, Err(InsertError::ReplacedAlreadyInserted));
        assert_eq!(incomplete_events(&acc), vec![(data.event, data.acc_proofs)]);
    }

    #[test]
    fn re_add_proof_after_poll_no_sig() {
        let mut rng = rng::new();
        re_add_proof_after_poll(test_data_random_key(&mut rng, EventType::NoSignature));
    }

    #[test]
    fn re_add_proof_after_poll_with_sig() {
        let mut rng = rng::new();
        re_add_proof_after_poll(test_data_random_key(&mut rng, EventType::WithSignature));
    }

    fn re_add_proof_after_poll(data: TestData) {
        let mut acc = ChainAccumulator::default();
        let _ = acc.add_proof(data.event.clone(), data.first_proof, data.signature.clone());
        let _ = acc.poll_event(data.event.clone(), Default::default());

        let result = acc.add_proof(data.event, data.first_proof, data.signature);

        assert_eq!(result, Err(InsertError::AlreadyComplete));
        assert_eq!(incomplete_events(&acc), vec![]);
    }

    #[test]
    fn reset_all_completed_no_sig() {
        let mut rng = rng::new();
        reset_all_completed(test_data_random_key(&mut rng, EventType::NoSignature));
    }

    #[test]
    fn reset_all_completed_with_sig() {
        let mut rng = rng::new();
        reset_all_completed(test_data_random_key(&mut rng, EventType::WithSignature));
    }

    fn reset_all_completed(data: TestData) {
        let mut acc = ChainAccumulator::default();
        let _ = acc.add_proof(data.event.clone(), data.first_proof, data.signature.clone());
        let _ = acc.poll_event(data.event.clone(), Default::default());

        let result = acc.reset_accumulator(&data.our_id);

        assert_eq!(
            result,
            RemainingEvents {
                cached_events: BTreeSet::new(),
                completed_events: vec![data.event].into_iter().collect()
            }
        );
        assert_eq!(incomplete_events(&acc), vec![]);
        assert_eq!(completed_events(&acc), vec![]);
    }

    #[test]
    fn reset_none_completed_no_sig() {
        let mut rng = rng::new();
        reset_none_completed(test_data_random_key(&mut rng, EventType::NoSignature));
    }

    #[test]
    fn reset_none_completed_with_sig() {
        let mut rng = rng::new();
        reset_none_completed(test_data_random_key(&mut rng, EventType::WithSignature));
    }

    fn reset_none_completed(data: TestData) {
        let mut acc = ChainAccumulator::default();
        let _ = acc.add_proof(data.event.clone(), data.first_proof, data.signature.clone());

        let result = acc.reset_accumulator(&data.our_id);

        assert_eq!(
            result,
            RemainingEvents {
                cached_events: vec![data.network_event].into_iter().collect(),
                completed_events: BTreeSet::new(),
            }
        );
        assert_eq!(incomplete_events(&acc), vec![]);
        assert_eq!(completed_events(&acc), vec![]);
    }

    #[test]
    fn reset_none_completed_none_our_id_no_sig() {
        let mut rng = rng::new();
        let test_data = test_data_random_key(&mut rng, EventType::NoSignature);
        reset_none_completed_none_our_id(&mut rng, test_data);
    }

    #[test]
    fn reset_none_completed_none_our_id_with_sig() {
        let mut rng = rng::new();
        let test_data = test_data_random_key(&mut rng, EventType::WithSignature);
        reset_none_completed_none_our_id(&mut rng, test_data);
    }

    fn reset_none_completed_none_our_id(rng: &mut MainRng, data: TestData) {
        let our_id = *FullId::gen(rng).public_id();
        let mut acc = ChainAccumulator::default();
        let _ = acc.add_proof(data.event.clone(), data.first_proof, data.signature);

        let result = acc.reset_accumulator(&our_id);

        assert_eq!(result, RemainingEvents::default());
        assert_eq!(incomplete_events(&acc), vec![]);
        assert_eq!(completed_events(&acc), vec![]);
    }

    #[test]
    fn tracking_responsiveness() {
        let mut rng = rng::new();

        let ids_and_proofs: Vec<_> = (0..8)
            .map(|_| {
                let (full_id, proof) = random_ids_and_proof(&mut rng);
                (*full_id.public_id(), proof)
            })
            .collect();
        let members: BTreeSet<_> = ids_and_proofs.iter().map(|(id, _)| *id).clone().collect();
        let polling_point = 6;
        let unresponsive_node = ids_and_proofs[5].0;

        let mut acc = ChainAccumulator::default();

        for i in 0..UNRESPONSIVE_WINDOW {
            let event = AccumulatingEvent::User([i as u8].to_vec());
            for (index, (id, proof)) in ids_and_proofs.iter().enumerate() {
                if index == polling_point {
                    let _ = acc.poll_event(event.clone(), members.clone());
                }
                if i >= (UNRESPONSIVE_WINDOW - UNRESPONSIVE_THRESHOLD - 1)
                    && id == &unresponsive_node
                {
                    continue;
                }
                let _ = acc.add_proof(event.clone(), *proof, None);
            }
        }

        let expected: BTreeSet<_> = iter::once(unresponsive_node).collect();
        let detected = acc.check_vote_status(members.iter());
        assert_eq!(detected, expected);
    }
}
