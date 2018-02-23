// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use super::{Block, Proof, Vote};
use error::RoutingError;
#[cfg(feature = "use-mock-crust")]
use fake_clock::FakeClock as Instant;
use public_info::PublicInfo;
use std::collections::BTreeMap;
#[cfg(not(feature = "use-mock-crust"))]
use std::time::Instant;

// FIXME - remove
#[allow(unused)]
/// Time (in seconds) after which a not-yet-valid `Block` will be purged from the accumulator.
const TIMEOUT_SECS: u64 = 600;

// FIXME - remove
#[allow(unused)]
#[derive(Debug)]
pub enum AccumulationReturn<T> {
    ExpiredValid(Block<T>), // this allows penalising non-voter(s)
    ExpiredInvalid(Block<T>), // this allows penalising voter(s)
    ValidBlock(Block<T>), // this just accumulated - add to the chain
    ValidProof(Proof), // block corresponding to this has already accumulated - add to the chain
}

#[derive(Debug, Default)]
pub struct VoteAccumulator<T: Ord> {
    votes: BTreeMap<T, (Vec<Proof>, Instant)>,
}

impl<T: Ord> VoteAccumulator<T> {
    // FIXME - remove these
    #[allow(unused)]
    #[cfg_attr(feature = "cargo-clippy", allow(needless_pass_by_value))]
    pub fn add_vote<'a, I: IntoIterator<Item = &'a PublicInfo>>(
        &mut self,
        _vote: Vote<T>,
        _node_info: &PublicInfo,
        _valid_nodes_itr: I,
    ) -> Result<Vec<AccumulationReturn<T>>, RoutingError> {
        Ok(vec![])
    }

    // FIXME - remove these
    #[allow(unused)]
    #[cfg_attr(feature = "cargo-clippy", allow(needless_pass_by_value))]
    pub fn add_block(
        &mut self,
        _block: Block<T>,
    ) -> Result<Vec<AccumulationReturn<T>>, RoutingError> {
        Ok(vec![])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::tests;
    use data_chain;
    use full_info::FullInfo;
    use std::collections::BTreeSet;
    #[cfg(feature = "use-mock-crust")]
    use std::iter;

    #[ignore]
    #[test]
    fn add_vote() {
        let nodes = tests::create_full_infos(None);
        let valid_voters = nodes.iter().map(FullInfo::public_info).collect::<Vec<_>>();
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
        let mut nodes_added = vec![];
        for node in &nodes {
            let vote1 = unwrap!(Vote::new(node.secret_sign_key(), payload1));
            let vote2 = unwrap!(Vote::new(node.secret_sign_key(), payload2));
            let results1 = unwrap!(accumulator.add_vote(
                vote1,
                node.public_info(),
                valid_voters.clone(),
            ));
            let results2 = unwrap!(accumulator.add_vote(
                vote2,
                node.public_info(),
                valid_voters.clone(),
            ));
            nodes_added.push(node.public_info());

            if data_chain::quorum(nodes_added.iter().cloned(), valid_voters.clone()) {
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

    #[ignore]
    #[test]
    fn add_block() {
        let nodes = tests::create_full_infos(None);
        let valid_voters = nodes.iter().map(FullInfo::public_info).collect::<Vec<_>>();
        let mut accumulator = VoteAccumulator::default();

        // Add a block which doesn't pre-exist.  It should be returned as a `ValidBlock`.
        let mut payload = "Case 1";
        let mut block_in = tests::create_block(payload, &nodes, false);
        let mut results = unwrap!(accumulator.add_block(block_in.clone()));
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
            unwrap!(
                Vote::new(last_node.secret_sign_key(), payload)
            ),
            last_node.public_info(),
            valid_voters,
        ));

        block_in = tests::create_block(payload, &nodes, false);
        results = unwrap!(accumulator.add_block(block_in.clone()));
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
        // A vector of `ValidVote`s for these extra proofs should be returned.
        payload = "Case 3";
        let valid_block = tests::create_block(payload, &nodes, false);
        let _ = unwrap!(accumulator.add_block(valid_block.clone()));

        block_in = tests::create_block(payload, &nodes, true);
        let mut extra_voters = block_in
            .get_node_infos()
            .difference(&valid_block.get_node_infos())
            .cloned()
            .collect::<BTreeSet<_>>();
        results = unwrap!(accumulator.add_block(block_in.clone()));
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
        let _ = unwrap!(accumulator.add_block(full_block.clone()));

        block_in = tests::create_block(payload, &nodes, false);
        results = unwrap!(accumulator.add_block(block_in.clone()));
        assert!(results.is_empty());
    }

    #[cfg(feature = "use-mock-crust")]
    #[ignore]
    #[test]
    fn timeout() {
        use fake_clock::FakeClock;

        let nodes = tests::create_full_infos(None);
        let valid_voters = nodes.iter().map(FullInfo::public_info).collect::<Vec<_>>();
        let mut accumulator = VoteAccumulator::default();

        // Add enough votes to just reach quorum then stop.
        let payload = "Expired";
        for node in &nodes {
            let vote = unwrap!(Vote::new(node.secret_sign_key(), payload));
            if !unwrap!(accumulator.add_vote(
                vote,
                node.public_info(),
                valid_voters.clone(),
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
            vote,
            late_node1.public_info(),
            valid_voters.clone(),
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
            vote,
            late_node2.public_info(),
            valid_voters.clone(),
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
            vote,
            nodes[0].public_info(),
            valid_voters.clone(),
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
                vote,
                node.public_info(),
                valid_voters.clone(),
            ));
        }

        // Time this complete block out.  It shouldn't be returned as expired.
        FakeClock::advance_time(TIMEOUT_SECS * 1000);
        vote = unwrap!(Vote::new(nodes[0].secret_sign_key(), "Dummy"));
        results = unwrap!(accumulator.add_vote(
            vote,
            nodes[0].public_info(),
            valid_voters.clone(),
        ));
        assert!(results.is_empty());
    }
}
