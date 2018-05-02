// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{Block, BlockState, Proof, Vote};
use error::RoutingError;
#[cfg(feature = "use-mock-crust")]
use fake_clock::FakeClock as Instant;
use log::LogLevel;
use public_info::PublicInfo;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::collections::btree_map::Entry;
use std::mem;
#[cfg(not(feature = "use-mock-crust"))]
use std::time::Instant;

/// Time (in seconds) after which a not-yet-valid `Block` will be purged from the accumulator.
const TIMEOUT_SECS: u64 = 600;

#[derive(Debug)]
pub enum AccumulationReturn<T> {
    ExpiredValid(Block<T>), // this allows penalising non-voter(s)
    ExpiredInvalid(Block<T>), // this allows penalising voter(s)
    ValidBlock(Block<T>), // this just accumulated - add to the chain
    ValidProof(Proof), // block corresponding to this has already accumulated - add to the chain
}

#[derive(Default)]
pub struct VoteAccumulator<T: Ord> {
    blocks: BTreeMap<T, State<T>>,
}

impl<T: Clone + Ord + Serialize> VoteAccumulator<T> {
    // FIXME - remove these
    #[allow(unused)]
    pub fn add_vote(
        &mut self,
        vote: &Vote<T>,
        node_info: &PublicInfo,
        valid_nodes: &BTreeSet<PublicInfo>,
    ) -> Result<Vec<AccumulationReturn<T>>, RoutingError> {
        let mut results = self.expire(valid_nodes);

        match self.blocks.entry(vote.payload().clone()) {
            Entry::Vacant(entry) => {
                let _ = entry.insert(State {
                    block: Block::new(vote, node_info)?,
                    timestamp: Instant::now(),
                });
            }
            Entry::Occupied(mut entry) => {
                let valid_before = entry
                    .get()
                    .block
                    .get_block_state(valid_nodes)
                    .valid_or_full();
                let valid_after = entry
                    .get_mut()
                    .block
                    .add_vote(vote, node_info, valid_nodes)?
                    .valid_or_full();

                if valid_after {
                    if valid_before {
                        let proof = vote.proof(node_info)?;
                        results.push(AccumulationReturn::ValidProof(proof));
                    } else {
                        let block = entry.get().block.clone();
                        results.push(AccumulationReturn::ValidBlock(block));
                    }
                }
            }
        }

        Ok(results)
    }

    // FIXME - remove these
    #[allow(unused)]
    pub fn add_block(
        &mut self,
        block: Block<T>,
        valid_nodes: &BTreeSet<PublicInfo>,
    ) -> Result<Vec<AccumulationReturn<T>>, RoutingError> {
        if !block.validate_signatures() {
            log_or_panic!(LogLevel::Error, "Block has invalid signatures.");
        }

        let mut results = self.expire(valid_nodes);

        match self.blocks.entry(block.payload().clone()) {
            Entry::Vacant(entry) => {
                if block.get_block_state(valid_nodes).valid_or_full() {
                    results.push(AccumulationReturn::ValidBlock(block.clone()));
                }

                let _ = entry.insert(State {
                    block,
                    timestamp: Instant::now(),
                });
            }
            Entry::Occupied(mut entry) => {
                let valid_before = entry
                    .get()
                    .block
                    .get_block_state(valid_nodes)
                    .valid_or_full();
                let mut valid_after = false;

                for proof in block.proofs() {
                    match entry.get_mut().block.add_proof(*proof, valid_nodes) {
                        Ok(state) => {
                            valid_after = state.valid_or_full();
                            if valid_before {
                                results.push(AccumulationReturn::ValidProof(*proof));
                            }
                        }
                        /// Duplicate votes are ignored.
                        Err(RoutingError::DuplicateSignatures) => (),
                        Err(error) => return Err(error),
                    }
                }

                if valid_after && !valid_before {
                    results.push(AccumulationReturn::ValidBlock(entry.get().block.clone()));
                }
            }
        }

        Ok(results)
    }

    /// Remove all votes cast by the given node.
    #[allow(unused)]
    pub fn remove_votes_by(&mut self, node_info: &PublicInfo) {
        for state in self.blocks.values_mut() {
            state.block.remove_proofs_by(node_info)
        }

        self.blocks = mem::replace(&mut self.blocks, BTreeMap::new())
            .into_iter()
            .filter(|&(_, ref state)| state.block.num_proofs() > 0)
            .collect()
    }

    fn expire(&mut self, valid_nodes: &BTreeSet<PublicInfo>) -> Vec<AccumulationReturn<T>> {
        let (retained, expired): (BTreeMap<_, _>, _) =
            mem::replace(&mut self.blocks, BTreeMap::new())
                .into_iter()
                .partition(|&(_, ref state)| {
                    state.timestamp.elapsed().as_secs() < TIMEOUT_SECS
                });

        self.blocks = retained;

        expired
            .into_iter()
            .filter_map(|(_, state)| match state.block.get_block_state(
                valid_nodes,
            ) {
                BlockState::NotYetValid => Some(AccumulationReturn::ExpiredInvalid(state.block)),
                BlockState::Valid => Some(AccumulationReturn::ExpiredValid(state.block)),
                BlockState::Full => None,
            })
            .collect()
    }
}

struct State<T> {
    block: Block<T>,
    timestamp: Instant,
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::tests;
    use data_chain;
    use std::collections::BTreeSet;
    #[cfg(feature = "use-mock-crust")]
    use std::iter;

    #[test]
    fn add_vote() {
        let nodes = tests::create_full_infos(None);
        let valid_voters: BTreeSet<_> = nodes.iter().map(|info| *info.public_info()).collect();
        let mut accumulator = VoteAccumulator::default();

        // Add votes for the same payload repeatedly.  Until we get to quorum, an empty vec should
        // should be returned.  On reaching quorum, we should have a single entry returned
        // containing the now-valid block.  Subsequent votes should be returned as single entries.
        // Also have each node double-vote (i.e. vote for the same thing twice) for a second payload
        // to ensure that the behaviour matches as for the first, i.e. that identical votes have no
        // effect.
        let payload1 = "Live";
        let payload2 = "DoubleVote";
        let mut is_valid = false;
        let mut nodes_added = BTreeSet::new();
        for node in &nodes {
            let vote1 = unwrap!(Vote::new(node.secret_sign_key(), payload1));
            let vote2 = unwrap!(Vote::new(node.secret_sign_key(), payload2));
            let results1 = unwrap!(accumulator.add_vote(
                &vote1,
                node.public_info(),
                &valid_voters,
            ));
            let results2 = unwrap!(accumulator.add_vote(
                &vote2,
                node.public_info(),
                &valid_voters,
            ));
            let _ = nodes_added.insert(*node.public_info());

            if data_chain::quorum(&nodes_added, &valid_voters) {
                assert_eq!(results1.len(), 1);
                assert_eq!(results2.len(), 1);
                if is_valid {
                    if let AccumulationReturn::ValidProof(ref proof) = results1[0] {
                        assert_eq!(proof.node_info(), node.public_info());
                    } else {
                        panic!("Should have got a valid proof returned.");
                    }
                    if let AccumulationReturn::ValidProof(ref proof) = results2[0] {
                        assert_eq!(proof.node_info(), node.public_info());
                    } else {
                        panic!("Should have got a valid proof returned.");
                    }
                } else {
                    if let AccumulationReturn::ValidBlock(ref block) = results1[0] {
                        assert_eq!(*block.payload(), payload1);
                    } else {
                        panic!("Should have got a valid block returned.");
                    }
                    if let AccumulationReturn::ValidBlock(ref block) = results2[0] {
                        assert_eq!(*block.payload(), payload2);
                    } else {
                        panic!("Should have got a valid block returned.");
                    }
                    is_valid = true;
                }
            } else {
                assert!(results1.is_empty() && results2.is_empty());
            }
        }
    }

    #[test]
    fn add_block() {
        let nodes = tests::create_full_infos(None);
        let valid_voters: BTreeSet<_> = nodes.iter().map(|info| *info.public_info()).collect();
        let mut accumulator = VoteAccumulator::default();

        // Add a block which doesn't pre-exist.  It should be returned as a `ValidBlock`.
        let mut payload = "Case 1";
        let mut block_in = tests::create_block(payload, &nodes, false);
        let mut results = unwrap!(accumulator.add_block(block_in.clone(), &valid_voters));
        assert_eq!(results.len(), 1);
        if let AccumulationReturn::ValidBlock(ref block_out) = results[0] {
            assert_eq!(block_in, *block_out);
        } else {
            panic!("Should have got the input block returned.");
        }

        // Add a block to one which is not yet valid for us.  It should be returned as a
        // `ValidBlock` containing the union of all the proofs.
        payload = "Case 2";
        let last_node = &nodes[nodes.len() - 1];
        let _ = unwrap!(accumulator.add_vote(
            &unwrap!(
                Vote::new(last_node.secret_sign_key(), payload)
            ),
            last_node.public_info(),
            &valid_voters,
        ));

        block_in = tests::create_block(payload, &nodes, false);
        results = unwrap!(accumulator.add_block(block_in.clone(), &valid_voters));
        assert_eq!(results.len(), 1);
        if let AccumulationReturn::ValidBlock(ref block_out) = results[0] {
            assert_eq!(block_in.payload(), block_out.payload());
            let mut voters_in = block_in.get_node_infos();
            let voters_out = block_out.get_node_infos();
            assert!(voters_in.insert(*last_node.public_info()));
            assert_eq!(voters_out, voters_in);
        } else {
            panic!("Should have got the input block returned.");
        }

        // Add a block to one which is already valid for us, but which holds more proofs than ours.
        // A vector of `ValidProof`s for these extra proofs should be returned.
        payload = "Case 3";
        let valid_block = tests::create_block(payload, &nodes, false);
        let _ = unwrap!(accumulator.add_block(valid_block.clone(), &valid_voters));

        block_in = tests::create_block(payload, &nodes, true);
        let mut extra_voters = block_in
            .get_node_infos()
            .difference(&valid_block.get_node_infos())
            .cloned()
            .collect::<BTreeSet<_>>();
        results = unwrap!(accumulator.add_block(block_in.clone(), &valid_voters));
        assert_eq!(results.len(), extra_voters.len());
        for result in results {
            if let AccumulationReturn::ValidProof(ref proof) = result {
                assert!(extra_voters.remove(proof.node_info()));
            } else {
                panic!("Should have only got valid votes returned.");
            }
        }
        assert!(extra_voters.is_empty());

        // Add a block to one which is already valid for us, but which holds a subset of the proofs
        // in ours.  Nothing should be returned.
        payload = "Case 4";
        let full_block = tests::create_block(payload, &nodes, true);
        let _ = unwrap!(accumulator.add_block(full_block.clone(), &valid_voters));

        block_in = tests::create_block(payload, &nodes, false);
        results = unwrap!(accumulator.add_block(block_in.clone(), &valid_voters));
        assert!(results.is_empty());
    }

    #[cfg(feature = "use-mock-crust")]
    #[test]
    fn timeout() {
        use fake_clock::FakeClock;

        let nodes = tests::create_full_infos(None);
        let valid_voters: BTreeSet<_> = nodes.iter().map(|info| *info.public_info()).collect();
        let mut accumulator = VoteAccumulator::default();

        // Add enough votes to just reach quorum then stop.
        let payload = "Expired";
        for node in &nodes {
            let vote = unwrap!(Vote::new(node.secret_sign_key(), payload));
            if !unwrap!(accumulator.add_vote(
                &vote,
                node.public_info(),
                &valid_voters,
            )).is_empty()
            {
                break;
            }
        }

        // Time this block out and add another vote for it.  The block should be returned as
        // `ExpiredValid` but not include this last late vote.
        FakeClock::advance_time(TIMEOUT_SECS * 1000);
        let late_node1 = &nodes[nodes.len() - 1];
        let mut vote = unwrap!(Vote::new(late_node1.secret_sign_key(), payload));
        let mut results = unwrap!(accumulator.add_vote(
            &vote,
            late_node1.public_info(),
            &valid_voters,
        ));
        assert_eq!(results.len(), 1);
        if let AccumulationReturn::ExpiredValid(ref block) = results[0] {
            assert_eq!(*block.payload(), payload);
            assert!(!block.get_node_infos().contains(late_node1.public_info()))
        } else {
            panic!("Should have got an expired valid block returned.");
        }

        // Now time out this single vote by adding anther late vote for it.  A block with the same
        // payload should now be returned, but this time as `ExpiredInvalid` and only include the
        // first late vote.
        FakeClock::advance_time(TIMEOUT_SECS * 1000);
        let late_node2 = &nodes[nodes.len() - 2];
        vote = unwrap!(Vote::new(late_node2.secret_sign_key(), payload));
        results = unwrap!(accumulator.add_vote(
            &vote,
            late_node2.public_info(),
            &valid_voters,
        ));
        assert_eq!(results.len(), 1);
        if let AccumulationReturn::ExpiredInvalid(ref block) = results[0] {
            assert_eq!(*block.payload(), payload);
            assert_eq!(
                block.get_node_infos(),
                iter::once(*late_node1.public_info()).collect()
            );
        } else {
            panic!("Should have got an expired invalid block returned.");
        }

        // Now time out this second single vote by adding `GROUP_SIZE` votes for a different block.
        // This second late vote should be returned as `ExpiredInvalid` and only include the
        // second late vote.
        FakeClock::advance_time(TIMEOUT_SECS * 1000);
        let new_payload = "SilentlyDrop";
        vote = unwrap!(Vote::new(nodes[0].secret_sign_key(), new_payload));
        results = unwrap!(accumulator.add_vote(
            &vote,
            nodes[0].public_info(),
            &valid_voters,
        ));
        assert_eq!(results.len(), 1);
        if let AccumulationReturn::ExpiredInvalid(ref block) = results[0] {
            assert_eq!(*block.payload(), payload);
            assert_eq!(
                block.get_node_infos(),
                iter::once(*late_node2.public_info()).collect()
            );
        } else {
            panic!("Should have got an expired invalid block returned.");
        }
        for node in &nodes[1..] {
            vote = unwrap!(Vote::new(node.secret_sign_key(), new_payload));
            let _ = unwrap!(accumulator.add_vote(
                &vote,
                node.public_info(),
                &valid_voters,
            ));
        }

        // Time this complete block out.  It shouldn't be returned as expired.
        FakeClock::advance_time(TIMEOUT_SECS * 1000);
        vote = unwrap!(Vote::new(nodes[0].secret_sign_key(), "Dummy"));
        results = unwrap!(accumulator.add_vote(
            &vote,
            nodes[0].public_info(),
            &valid_voters,
        ));
        assert!(results.is_empty());
    }
}
