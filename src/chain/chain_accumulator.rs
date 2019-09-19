// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    AckMessagePayload, ExpectCandidatePayload, NetworkEvent, OnlinePayload, Proof, ProofSet,
    SectionInfo, SectionInfoSigPayload, SectionKeyInfo, SendAckMessagePayload,
};
use crate::id::PublicId;
use crate::sha3::Digest256;
use crate::{Authority, XorName};
use log::LogLevel;
use std::collections::{BTreeMap, BTreeSet};
use std::mem;

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
}

impl ChainAccumulator {
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
        signature: Option<SectionInfoSigPayload>,
    ) -> Result<(), InsertError> {
        if self.completed_events.contains(&event) {
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
    ) -> Option<(AccumulatingEvent, AccumulatingProof)> {
        let proofs = self.chain_accumulator.remove(&event)?;

        if !self.completed_events.insert(event.clone()) {
            log_or_panic!(LogLevel::Warn, "Duplicate insert in completed events.");
        }

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

        RemainingEvents {
            cached_events: chain_acc
                .into_iter()
                .filter(|&(_, ref proofs)| proofs.parsec_proofs.contains_id(our_id))
                .map(|(event, proofs)| {
                    event.convert_to_network_event(proofs.into_sig_shares().remove(our_id))
                })
                .collect(),
            completed_events,
        }
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub enum AccumulatingEvent {
    /// Add new elder once we agreed to add a candidate
    AddElder(PublicId, Authority<XorName>),
    /// Remove elder once we agreed to remove the peer
    RemoveElder(PublicId),

    /// Voted for candidate that pass resource proof
    Online(OnlinePayload),
    /// Voted for candidate we no longer consider online.
    Offline(PublicId),

    OurMerge,
    NeighbourMerge(Digest256),
    SectionInfo(SectionInfo),

    /// Voted for received ExpectCandidate Message.
    ExpectCandidate(ExpectCandidatePayload),

    // Voted for timeout expired for this candidate old_public_id.
    PurgeCandidate(PublicId),

    // Voted for received message with keys to we can update their_keys
    TheirKeyInfo(SectionKeyInfo),

    // Voted for received AckMessage to update their_knowledge
    AckMessage(AckMessagePayload),

    // Voted for sending AckMessage (Require 100% consensus)
    SendAckMessage(SendAckMessagePayload),
}

impl AccumulatingEvent {
    pub fn from_network_event(
        event: NetworkEvent,
    ) -> (AccumulatingEvent, Option<SectionInfoSigPayload>) {
        let accumulating_event = match event {
            NetworkEvent::SectionInfo(sec_info, sig) => {
                return (AccumulatingEvent::SectionInfo(sec_info), sig)
            }

            NetworkEvent::AddElder(id, aux) => AccumulatingEvent::AddElder(id, aux),
            NetworkEvent::RemoveElder(id) => AccumulatingEvent::RemoveElder(id),
            NetworkEvent::Online(payload) => AccumulatingEvent::Online(payload),
            NetworkEvent::Offline(id) => AccumulatingEvent::Offline(id),
            NetworkEvent::OurMerge => AccumulatingEvent::OurMerge,
            NetworkEvent::NeighbourMerge(digest) => AccumulatingEvent::NeighbourMerge(digest),
            NetworkEvent::ExpectCandidate(vote) => AccumulatingEvent::ExpectCandidate(vote),
            NetworkEvent::PurgeCandidate(id) => AccumulatingEvent::PurgeCandidate(id),
            NetworkEvent::TheirKeyInfo(payload) => AccumulatingEvent::TheirKeyInfo(payload),
            NetworkEvent::AckMessage(payload) => AccumulatingEvent::AckMessage(payload),
            NetworkEvent::SendAckMessage(payload) => AccumulatingEvent::SendAckMessage(payload),
        };

        (accumulating_event, None)
    }

    pub fn convert_to_network_event(self, sig: Option<SectionInfoSigPayload>) -> NetworkEvent {
        match self {
            AccumulatingEvent::SectionInfo(sec_info) => NetworkEvent::SectionInfo(sec_info, sig),

            AccumulatingEvent::AddElder(id, aux) => NetworkEvent::AddElder(id, aux),
            AccumulatingEvent::RemoveElder(id) => NetworkEvent::RemoveElder(id),
            AccumulatingEvent::Online(payload) => NetworkEvent::Online(payload),
            AccumulatingEvent::Offline(id) => NetworkEvent::Offline(id),
            AccumulatingEvent::OurMerge => NetworkEvent::OurMerge,
            AccumulatingEvent::NeighbourMerge(digest) => NetworkEvent::NeighbourMerge(digest),
            AccumulatingEvent::ExpectCandidate(vote) => NetworkEvent::ExpectCandidate(vote),
            AccumulatingEvent::PurgeCandidate(id) => NetworkEvent::PurgeCandidate(id),
            AccumulatingEvent::TheirKeyInfo(payload) => NetworkEvent::TheirKeyInfo(payload),
            AccumulatingEvent::AckMessage(payload) => NetworkEvent::AckMessage(payload),
            AccumulatingEvent::SendAckMessage(payload) => NetworkEvent::SendAckMessage(payload),
        }
    }

    /// Returns the payload if this is a `SectionInfo` event.
    pub fn section_info(&self) -> Option<&SectionInfo> {
        match *self {
            AccumulatingEvent::SectionInfo(ref self_si) => Some(self_si),
            _ => None,
        }
    }
}

#[derive(Default, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct AccumulatingProof {
    parsec_proofs: ProofSet,
    sig_shares: BTreeMap<PublicId, SectionInfoSigPayload>,
}

impl AccumulatingProof {
    pub fn from_proof_set(parsec_proofs: ProofSet) -> AccumulatingProof {
        AccumulatingProof {
            parsec_proofs,
            sig_shares: Default::default(),
        }
    }

    /// Return false if share or proof is replaced
    pub fn add_proof(&mut self, proof: Proof, info_sig: Option<SectionInfoSigPayload>) -> bool {
        let new_share = info_sig.map_or(true, |share| {
            self.sig_shares.insert(proof.pub_id, share).is_none()
        });

        let new_proof = self.parsec_proofs.add_proof(proof);
        new_share && new_proof
    }

    /// Returns whether the set contains a signature by that ID.
    pub fn contains_id(&self, id: &PublicId) -> bool {
        self.parsec_proofs.contains_id(id)
    }

    pub fn parsec_proof_set(&self) -> &ProofSet {
        &self.parsec_proofs
    }

    pub fn into_proof_set(self) -> ProofSet {
        self.parsec_proofs
    }

    pub fn into_sig_shares(self) -> BTreeMap<PublicId, SectionInfoSigPayload> {
        self.sig_shares
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
    use super::*;
    use crate::{id::FullId, BlsPublicKeySet, BlsPublicKeyShare};
    use parsec::SecretId;
    use std::iter;
    use unwrap::unwrap;

    struct TestData {
        pub our_id: PublicId,
        pub event: AccumulatingEvent,
        pub network_event: NetworkEvent,
        pub first_proof: Proof,
        pub proofs: ProofSet,
        pub acc_proofs: AccumulatingProof,
        pub signature: Option<SectionInfoSigPayload>,
    }

    enum EventType {
        WithSignature,
        NoSignature,
    }

    fn empty_section_info() -> SectionInfo {
        unwrap!(SectionInfo::new_for_test(
            Default::default(),
            Default::default(),
            Default::default(),
        ))
    }

    fn random_section_info_sig_payload() -> SectionInfoSigPayload {
        let (id, first_proof) = random_ids_and_proof();
        SectionInfoSigPayload {
            share: (BlsPublicKeyShare(*id.public_id()), first_proof.sig),
            pk_set: BlsPublicKeySet::from_section_info(empty_section_info()),
        }
    }

    fn random_ids_and_proof() -> (FullId, Proof) {
        let id = FullId::new();
        let pub_id = *id.public_id();
        let sig = id.sign_detached(&[1]);

        (id, Proof { pub_id, sig })
    }

    fn test_data_random_key(event_type: EventType) -> TestData {
        let (id, first_proof) = random_ids_and_proof();
        let proofs = ProofSet {
            sigs: iter::once((first_proof.pub_id, first_proof.sig)).collect(),
        };

        match event_type {
            EventType::NoSignature => TestData {
                our_id: *id.public_id(),
                event: AccumulatingEvent::OurMerge,
                network_event: NetworkEvent::OurMerge,
                first_proof,
                proofs: proofs.clone(),
                acc_proofs: AccumulatingProof {
                    parsec_proofs: proofs,
                    sig_shares: Default::default(),
                },
                signature: None,
            },
            EventType::WithSignature => {
                let sec_info = empty_section_info();
                let sig_payload = random_section_info_sig_payload();

                TestData {
                    our_id: *id.public_id(),
                    event: AccumulatingEvent::SectionInfo(sec_info.clone()),
                    network_event: NetworkEvent::SectionInfo(
                        sec_info.clone(),
                        Some(sig_payload.clone()),
                    ),
                    first_proof,
                    proofs: proofs.clone(),
                    acc_proofs: AccumulatingProof {
                        parsec_proofs: proofs,
                        sig_shares: iter::once((first_proof.pub_id, sig_payload.clone())).collect(),
                    },
                    signature: Some(sig_payload.clone()),
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
        insert_with_proof_set(test_data_random_key(EventType::NoSignature));
    }

    fn insert_with_proof_set(data: TestData) {
        let mut acc = ChainAccumulator::default();
        let result = acc.insert_with_proof_set(data.event.clone(), data.proofs.clone());

        assert_eq!(result, Ok(()));
        assert_eq!(incomplete_events(&acc), vec![(data.event, data.acc_proofs)]);
    }

    #[test]
    fn poll_proof_no_sig() {
        poll_proof(test_data_random_key(EventType::NoSignature));
    }

    fn poll_proof(data: TestData) {
        let mut acc = ChainAccumulator::default();
        let _ = acc.insert_with_proof_set(data.event.clone(), data.proofs.clone());

        let event_to_poll = unwrap!(acc.incomplete_events().next()).0.clone();
        let result = acc.poll_event(event_to_poll);

        assert_eq!(result, Some((data.event, data.acc_proofs)));
        assert_eq!(incomplete_events(&acc), vec![]);
    }

    #[test]
    fn re_insert_with_proof_set_no_sig() {
        re_insert_with_proof_set(
            test_data_random_key(EventType::NoSignature),
            test_data_random_key(EventType::NoSignature),
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
        re_insert_with_proof_set_after_poll(
            test_data_random_key(EventType::NoSignature),
            test_data_random_key(EventType::NoSignature),
        );
    }

    fn re_insert_with_proof_set_after_poll(data: TestData, data2: TestData) {
        let mut acc = ChainAccumulator::default();
        let _ = acc.insert_with_proof_set(data.event.clone(), data.proofs.clone());
        let _ = acc.poll_event(data.event.clone());

        let result = acc.insert_with_proof_set(data.event.clone(), data2.proofs.clone());

        assert_eq!(result, Err(InsertError::AlreadyComplete));
        assert_eq!(incomplete_events(&acc), vec![]);
    }

    #[test]
    fn add_proof_no_sig() {
        add_proof(test_data_random_key(EventType::NoSignature));
    }

    #[test]
    fn add_proof_with_sig() {
        add_proof(test_data_random_key(EventType::WithSignature));
    }

    fn add_proof(data: TestData) {
        let mut acc = ChainAccumulator::default();
        let result = acc.add_proof(data.event.clone(), data.first_proof, data.signature.clone());

        assert_eq!(result, Ok(()));
        assert_eq!(incomplete_events(&acc), vec![(data.event, data.acc_proofs)]);
    }

    #[test]
    fn re_add_proof_no_sig() {
        re_add_proof(test_data_random_key(EventType::NoSignature));
    }

    #[test]
    fn re_add_proof_with_sig() {
        re_add_proof(test_data_random_key(EventType::WithSignature));
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
        re_add_proof_after_poll(test_data_random_key(EventType::NoSignature));
    }

    #[test]
    fn re_add_proof_after_poll_with_sig() {
        re_add_proof_after_poll(test_data_random_key(EventType::WithSignature));
    }

    fn re_add_proof_after_poll(data: TestData) {
        let mut acc = ChainAccumulator::default();
        let _ = acc.add_proof(data.event.clone(), data.first_proof, data.signature.clone());
        let _ = acc.poll_event(data.event.clone());

        let result = acc.add_proof(data.event, data.first_proof, data.signature);

        assert_eq!(result, Err(InsertError::AlreadyComplete));
        assert_eq!(incomplete_events(&acc), vec![]);
    }

    #[test]
    fn reset_all_completed_no_sig() {
        reset_all_completed(test_data_random_key(EventType::NoSignature));
    }

    #[test]
    fn reset_all_completed_with_sig() {
        reset_all_completed(test_data_random_key(EventType::WithSignature));
    }

    fn reset_all_completed(data: TestData) {
        let mut acc = ChainAccumulator::default();
        let _ = acc.add_proof(data.event.clone(), data.first_proof, data.signature.clone());
        let _ = acc.poll_event(data.event.clone());

        let result = acc.reset_accumulator(&data.our_id);

        assert_eq!(
            result,
            RemainingEvents {
                cached_events: BTreeSet::new(),
                completed_events: vec![data.event.clone()].into_iter().collect()
            }
        );
        assert_eq!(incomplete_events(&acc), vec![]);
        assert_eq!(completed_events(&acc), vec![]);
    }

    #[test]
    fn reset_none_completed_no_sig() {
        reset_none_completed(test_data_random_key(EventType::NoSignature));
    }

    #[test]
    fn reset_none_completed_with_sig() {
        reset_none_completed(test_data_random_key(EventType::WithSignature));
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
        reset_none_completed_none_our_id(test_data_random_key(EventType::NoSignature));
    }

    #[test]
    fn reset_none_completed_none_our_id_with_sig() {
        reset_none_completed_none_our_id(test_data_random_key(EventType::WithSignature));
    }

    fn reset_none_completed_none_our_id(data: TestData) {
        let our_id = *FullId::new().public_id();
        let mut acc = ChainAccumulator::default();
        let _ = acc.add_proof(data.event.clone(), data.first_proof, data.signature.clone());

        let result = acc.reset_accumulator(&our_id);

        assert_eq!(result, RemainingEvents::default());
        assert_eq!(incomplete_events(&acc), vec![]);
        assert_eq!(completed_events(&acc), vec![]);
    }
}
