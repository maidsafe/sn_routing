// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{NetworkEvent, ProofSet};
use crate::id::PublicId;
use log::LogLevel;
use std::collections::{BTreeMap, BTreeSet};
use std::mem;

#[derive(Default)]
pub(super) struct ChainAccumulator {
    /// A map containing network events that have not been handled yet, together with their proofs
    /// that have been collected so far. We are still waiting for more proofs, or to reach a state
    /// where we can handle the event.
    // FIXME: Purge votes that are older than a given period.
    chain_accumulator: BTreeMap<NetworkEvent, ProofSet>,
    /// Events that were handled: Further incoming proofs for these can be ignored.
    completed_events: BTreeSet<NetworkEvent>,
}

impl ChainAccumulator {
    pub fn insert_with_proof_set(
        &mut self,
        event: &NetworkEvent,
        proof_set: ProofSet,
    ) -> Result<(), InsertError> {
        if self.completed_events.contains(event) {
            return Err(InsertError::AlreadyComplete);
        }

        if self
            .chain_accumulator
            .insert(event.clone(), proof_set)
            .is_some()
        {
            return Err(InsertError::ReplacedAlreadyInserted);
        }

        Ok(())
    }

    pub fn entry_or_default(&mut self, event: &NetworkEvent) -> Result<&mut ProofSet, InsertError> {
        if self.completed_events.contains(event) {
            return Err(InsertError::AlreadyComplete);
        }

        Ok(self
            .chain_accumulator
            .entry(event.clone())
            .or_insert_with(ProofSet::new))
    }

    pub fn poll_event(&mut self, event: NetworkEvent) -> Option<(NetworkEvent, ProofSet)> {
        let proofs = self.chain_accumulator.remove(&event)?;

        if !self.completed_events.insert(event.clone()) {
            log_or_panic!(LogLevel::Warn, "Duplicate insert in completed events.");
        }

        Some((event, proofs))
    }

    pub fn incomplete_events(&self) -> impl Iterator<Item = (&NetworkEvent, &ProofSet)> {
        self.chain_accumulator.iter()
    }

    pub fn reset_accumulator(&mut self, our_id: &PublicId) -> RemainingEvents {
        let completed_events = mem::replace(&mut self.completed_events, Default::default());
        let chain_acc = mem::replace(&mut self.chain_accumulator, Default::default());

        RemainingEvents {
            cached_events: chain_acc
                .into_iter()
                .filter(|&(ref event, ref proofs)| {
                    !completed_events.contains(event) && proofs.contains_id(our_id)
                })
                .map(|(event, _)| event)
                .collect(),
            completed_events,
        }
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
    pub completed_events: BTreeSet<NetworkEvent>,
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::id::FullId;
    use parsec::SecretId;
    use std::iter;
    use unwrap::unwrap;

    fn test_event_and_proof_set() -> (NetworkEvent, ProofSet) {
        let id = FullId::new();
        let pub_id = *id.public_id();
        let sig = id.sign_detached(&[1]);

        (
            NetworkEvent::OurMerge,
            ProofSet {
                sigs: iter::once((pub_id, sig)).collect(),
            },
        )
    }

    fn incomplete_events(acc: &ChainAccumulator) -> Vec<(NetworkEvent, ProofSet)> {
        acc.incomplete_events()
            .map(|(e, p)| (e.clone(), p.clone()))
            .collect()
    }

    fn completed_events(acc: &ChainAccumulator) -> Vec<NetworkEvent> {
        acc.completed_events.iter().cloned().collect()
    }

    #[test]
    fn insert_with_proof_set() {
        let (event, proofs) = test_event_and_proof_set();

        let mut acc = ChainAccumulator::default();
        let result = acc.insert_with_proof_set(&event, proofs.clone());

        assert_eq!(result, Ok(()));
        assert_eq!(incomplete_events(&acc), vec![(event, proofs)]);
    }

    #[test]
    fn poll_proof() {
        let (event, proofs) = test_event_and_proof_set();
        let mut acc = ChainAccumulator::default();
        let _ = acc.insert_with_proof_set(&event, proofs.clone());

        let event_to_poll = unwrap!(acc.incomplete_events().next()).0.clone();
        let result = acc.poll_event(event_to_poll);

        assert_eq!(result, Some((event, proofs)));
        assert_eq!(incomplete_events(&acc), vec![]);
    }

    #[test]
    fn re_insert_with_proof_set() {
        let (event, proofs) = test_event_and_proof_set();
        let (_, proofs2) = test_event_and_proof_set();
        let mut acc = ChainAccumulator::default();
        let _ = acc.insert_with_proof_set(&event, proofs.clone());

        let result = acc.insert_with_proof_set(&event, proofs2.clone());

        assert_eq!(result, Err(InsertError::ReplacedAlreadyInserted));
        assert_eq!(incomplete_events(&acc), vec![(event, proofs2)]);
    }

    #[test]
    fn re_insert_with_proof_set_after_poll() {
        let (event, proofs) = test_event_and_proof_set();
        let (_, proofs2) = test_event_and_proof_set();
        let mut acc = ChainAccumulator::default();
        let _ = acc.insert_with_proof_set(&event, proofs.clone());
        let _ = acc.poll_event(event.clone());

        let result = acc.insert_with_proof_set(&event, proofs2.clone());

        assert_eq!(result, Err(InsertError::AlreadyComplete));
        assert_eq!(incomplete_events(&acc), vec![]);
    }

    #[test]
    fn entry_or_default() {
        let (event, proofs) = test_event_and_proof_set();

        let mut acc = ChainAccumulator::default();
        let result = acc.entry_or_default(&event).map(|p| {
            *p = proofs.clone();
        });

        assert_eq!(result, Ok(()));
        assert_eq!(incomplete_events(&acc), vec![(event, proofs)]);
    }

    #[test]
    fn re_entry_or_default() {
        let (event, proofs) = test_event_and_proof_set();
        let mut acc = ChainAccumulator::default();
        let _ = acc.entry_or_default(&event).map(|p| {
            *p = proofs.clone();
        });

        let result = acc.entry_or_default(&event).map(|p| p.clone());

        assert_eq!(result, Ok(proofs.clone()));
        assert_eq!(incomplete_events(&acc), vec![(event, proofs)]);
    }

    #[test]
    fn re_entry_or_default_after_poll() {
        let (event, _proofs) = test_event_and_proof_set();
        let mut acc = ChainAccumulator::default();
        let _ = acc.entry_or_default(&event);
        let _ = acc.poll_event(event.clone());

        let result = acc.entry_or_default(&event).map(|p| p.clone());

        assert_eq!(result, Err(InsertError::AlreadyComplete));
        assert_eq!(incomplete_events(&acc), vec![]);
    }

    #[test]
    fn reset_all_completed() {
        let (event, proofs) = test_event_and_proof_set();
        let our_id = *unwrap!(proofs.ids().next());
        let mut acc = ChainAccumulator::default();
        let _ = acc.insert_with_proof_set(&event, proofs.clone());
        let _ = acc.poll_event(event.clone());

        let result = acc.reset_accumulator(&our_id);

        assert_eq!(
            result,
            RemainingEvents {
                cached_events: BTreeSet::new(),
                completed_events: vec![event.clone()].into_iter().collect()
            }
        );
        assert_eq!(incomplete_events(&acc), vec![]);
        assert_eq!(completed_events(&acc), vec![]);
    }

    #[test]
    fn reset_none_completed() {
        let (event, proofs) = test_event_and_proof_set();
        let our_id = *unwrap!(proofs.ids().next());
        let mut acc = ChainAccumulator::default();
        let _ = acc.insert_with_proof_set(&event, proofs.clone());

        let result = acc.reset_accumulator(&our_id);

        assert_eq!(
            result,
            RemainingEvents {
                cached_events: vec![event].into_iter().collect(),
                completed_events: BTreeSet::new(),
            }
        );
        assert_eq!(incomplete_events(&acc), vec![]);
        assert_eq!(completed_events(&acc), vec![]);
    }

    #[test]
    fn reset_none_completed_none_our_id() {
        let (event, proofs) = test_event_and_proof_set();
        let our_id = *FullId::new().public_id();
        let mut acc = ChainAccumulator::default();
        let _ = acc.insert_with_proof_set(&event, proofs.clone());

        let result = acc.reset_accumulator(&our_id);

        assert_eq!(result, RemainingEvents::default());
        assert_eq!(incomplete_events(&acc), vec![]);
        assert_eq!(completed_events(&acc), vec![]);
    }
}
