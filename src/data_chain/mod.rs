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

mod block;
mod chain;
mod node_state;
mod proof;
mod vote;
mod vote_accumulator;

pub use self::block::{Block, BlockState, NodesAndAge};
pub use self::chain::Chain;
pub use self::node_state::{NodeState, State};
pub use self::proof::Proof;
pub use self::vote::Vote;
pub use self::vote_accumulator::VoteAccumulator;

use public_info::PublicInfo;
use std::collections::BTreeSet;

/// Calculates whether a quorum of nodes have voted.  In this case, "quorum" means >50% of the
/// members in `valid_nodes_itr` are included in `voters_itr` and that their cumulative age is >50%
/// of the cumulative age of all members of `valid_nodes_itr`.
pub fn quorum<'a, 'b, I, J>(voters_itr: I, valid_nodes_itr: J) -> bool
where
    I: IntoIterator<Item = &'a PublicInfo>,
    J: IntoIterator<Item = &'b PublicInfo>,
{
    let valid_nodes = valid_nodes_itr.into_iter().collect::<BTreeSet<_>>();
    let valid_voters = voters_itr
        .into_iter()
        .filter(|voter| valid_nodes.contains(voter))
        .collect::<BTreeSet<_>>();

    let valid_total_age = valid_nodes.iter().map(|node| usize::from(node.age())).sum();
    let mut running_total_age = 0;
    for (count, voter) in valid_voters.iter().rev().enumerate() {
        running_total_age += usize::from(voter.age());
        if running_total_age * 2 > valid_total_age && (count + 1) * 2 > valid_nodes.len() {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use full_info::FullInfo;
    use maidsafe_utilities::SeededRng;
    use rust_sodium;
    use std::iter;

    #[test]
    fn quorum_check() {
        // Create a set of voters with ages 5, 6, 7, etc.
        let mut rng = SeededRng::thread_rng();
        unwrap!(rust_sodium::init_with_rng(&mut rng));
        let count = 10;
        let mut nodes: Vec<_> = (0..count)
            .map(|_| *FullInfo::node_new(0).public_info())
            .collect();
        nodes.sort();
        for (index, node) in nodes.iter_mut().enumerate() {
            node.set_age(index as u8 + 5);
        }

        // Check a majority of nodes, but comprising the youngest, don't get quorum.
        assert!(!quorum(nodes.iter().take(count / 2 + 1), &nodes));

        // Check that a non-majority of eldest nodes don't get quorum.
        assert!(!quorum(nodes.iter().rev().take(count / 2), &nodes));

        // Check that only valid voters are considered.
        let invalid = *FullInfo::node_new(100).public_info();
        assert!(!quorum(
            nodes.iter().rev().take(count / 2).chain(
                iter::once(&invalid),
            ),
            &nodes,
        ));

        // Check that duplicate valid voters are counted only once.
        assert!(!quorum(
            nodes.iter().rev().take(count / 2).chain(iter::once(
                &nodes[count - 1],
            )),
            &nodes,
        ));

        // Check a majority of nodes with more than half the total age get quorum.
        assert!(quorum(nodes.iter().rev().take(count / 2 + 1), &nodes));
    }
}
