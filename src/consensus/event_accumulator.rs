// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

// FIXME: bring back unresponsiveness tracking
#![allow(unused)]

/// An unresponsive node is detected by conunting how many (defined by UNRESPONSIVE_THRESHOLD)
/// missed votes among the certain number (defined by UNRESPONSIVE_WINDOW) of recent consensused
/// observations.

/// The threshold (number of unvoted votes) a node to be considered as unresponsive.
pub const UNRESPONSIVE_THRESHOLD: usize = 48;
/// The period (X consensued observations) during which node be considered as unresponsive.
pub const UNRESPONSIVE_WINDOW: usize = 64;

/*

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


#[cfg(test)]
mod test {
    #[test]
    fn tracking_responsiveness() {
        let mut rng = rng::new();

        let (elders_info, _) = gen_elders_info(&mut rng, Default::default(), ELDER_SIZE);
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

*/
