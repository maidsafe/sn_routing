// Copyright 2015 MaidSafe.net limited.
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

// FIXME: remove when this module is finished
#![allow(dead_code)]

use super::{Block, NodeState, Vote};
use error::RoutingError;
use fs2::FileExt;
use maidsafe_utilities::serialisation;
use public_info::PublicInfo;
use std::fmt::{self, Debug, Formatter};
use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use xor_name::XorName;

/// Placeholder pending design of inclusion of data into data-chain
type DataIdentifier = XorName;

#[allow(unused)]
#[derive(Default, Serialize, Deserialize, PartialEq, PartialOrd, Eq, Ord)]
pub struct Chain {
    blocks: Vec<Block<NodeState>>,
    group_size: usize,
    path: Option<PathBuf>,
    valid_nodes: Vec<Block<NodeState>>, // save to aid network catastrophic failure and restart.
    data: Vec<Block<DataIdentifier>>,
    pending_blocks: Vec<Block<NodeState>>,
}

impl Chain {
    /// Create a new chain backed up on disk
    /// Provide the directory to create the files in
    pub fn create_in_path(path: &PathBuf, group_size: usize) -> io::Result<Chain> {
        let path = path.join("data_chain");
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)?;
        // hold a lock on the file for the whole session
        file.lock_exclusive()?;
        Ok(Chain {
            blocks: vec![],
            group_size,
            path: Some(path),
            valid_nodes: vec![],
            data: vec![],
            pending_blocks: vec![],
        })
    }

    /// Open from existing directory
    pub fn from_path(path: &PathBuf) -> Result<Chain, RoutingError> {
        let path = path.join("data_chain");
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(false)
            .open(&path)?;
        // hold a lock on the file for the whole session
        file.lock_exclusive()?;
        let mut buf = vec![];
        let _ = file.read_to_end(&mut buf)?;
        Ok(serialisation::deserialise(&buf[..])?)
    }

    /// Create chain in memory from some blocks
    pub fn from_blocks(
        blocks: Vec<Block<NodeState>>,
        pending_blocks: Vec<Block<NodeState>>,
        group_size: usize,
    ) -> Chain {
        Chain {
            blocks,
            group_size,
            path: None,
            valid_nodes: vec![],
            data: vec![],
            pending_blocks,
        }
    }

    /// Write current data chain to supplied path
    pub fn write(&self) -> Result<(), RoutingError> {
        if let Some(path) = self.path.to_owned() {
            let mut file = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(false)
                .open(&path.as_path())?;
            return Ok(file.write_all(&serialisation::serialise(&self)?)?);
        }
        Err(RoutingError::CannotWriteFile)
    }

    /// Write current data chain to supplied path
    pub fn write_to_new_path(&mut self, path: PathBuf) -> Result<(), RoutingError> {
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(false)
            .open(path.as_path())?;
        file.write_all(&serialisation::serialise(&self)?)?;
        self.path = Some(path);
        Ok(file.lock_exclusive()?)
    }

    /// Unlock the lock file
    pub fn unlock(&self) {
        if let Some(ref path) = self.path.to_owned() {
            if let Ok(file) = fs::File::open(path.as_path()) {
                let _ = file.unlock();
            }
        }
    }

    // FIXME - re-enable this lint check
    #[cfg_attr(feature = "cargo-clippy", allow(needless_pass_by_value))]
    /// Add the given valid `block` to the chain.
    pub fn add_block(&mut self, _block: Block<NodeState>) {
        unimplemented!();
    }

    // FIXME - re-enable this lint check
    #[cfg_attr(feature = "cargo-clippy", allow(needless_pass_by_value))]
    /// Add the given valid `vote` to the chain.
    pub fn add_vote(&mut self, _vote: Vote<NodeState>, _node_info: PublicInfo) {
        unimplemented!();
    }

    /// Assumes we trust the first `Block`
    fn validate_quorums(&self) -> bool {
        if let Some(mut prev) = self.blocks.first() {
            for blk in self.blocks.iter().skip(1) {
                // TODO, don't count like this use a loop and check quorum age as well
                if blk.get_node_infos()
                    .intersection(&prev.get_node_infos())
                    .count() <= self.group_size / 2
                {
                    return false;
                } else {
                    prev = blk;
                    // TODO check `NetworkEvent` as we may need to add to prev or remove a possible
                    // voter we can probably use a CurrentNodes / NodeState list here to be more
                    // specific. Also which `NetworkEvent`s can follow a sequence, i.e. a lost must
                    // be followed with a promote if its an elder or a merge if nodes drops to group
                    // size. Most events will follow a sequence that is allowed. if blocks are out
                    // of sequence when net is running a node should sequence them properly. Here we
                    // would fail the chain.
                }
            }
            true
        } else {
            false
        }
    }
}

impl Debug for Chain {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        writeln!(formatter, "Chain {{")?;
        writeln!(formatter, "    group_size: {},", self.group_size)?;
        writeln!(formatter, "    path: {:?},", self.path)?;
        writeln!(formatter, "    blocks:")?;
        for block in &self.blocks {
            writeln!(
                formatter,
                "        {:?} signed by {:?},",
                block.payload(),
                block.proofs()
            )?;
        }
        writeln!(formatter, "    valid_nodes:")?;
        for block in &self.valid_nodes {
            writeln!(
                formatter,
                "        {:?},",
                block.payload(),
            )?;
        }
        writeln!(formatter, "    data:")?;
        for block in &self.data {
            writeln!(
                formatter,
                "        {:?} signed by {:?},",
                block.payload(),
                block.proofs()
            )?;
        }
        writeln!(formatter, "    pending_blocks:")?;
        for block in &self.pending_blocks {
            writeln!(
                formatter,
                "        {:?} signed by {:?},",
                block.payload(),
                block.proofs()
            )?;
        }
        writeln!(formatter, "}}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::tests;
    use data_chain::{NodeState, Proof, State};
    use full_info::FullInfo;
    use maidsafe_utilities::SeededRng;
    use rand::Rng;
    use routing_table::Prefix;
    use rust_sodium;

    #[ignore]
    #[test]
    fn pending_blocks() {
        // Start with the chain having Live(A).  Create blocks for Offline(A), Live(B), and
        // Relocated(B), Live(C).  Add the four of them in reverse order and assert after each is
        // added that they're held in the `pending_blocks` until the final one is added and they can
        // all be added to the chain in the order defined above.
        let mut rng = SeededRng::thread_rng();
        unwrap!(rust_sodium::init_with_rng(&mut rng));

        let prefix = Prefix::default().pushed(rng.gen()).with_version(rng.gen());
        let nodes = tests::create_full_infos(Some(prefix));

        // Create Live(A) and Offline(A).
        let node_a = FullInfo::within_range(5, &prefix.lower_bound(), &prefix.upper_bound());
        let mut payload = NodeState {
            state: State::ElderLive,
            public_key: *node_a.public_info().sign_key(),
            age: node_a.public_info().age(),
            section: prefix,
        };
        let live_a = tests::create_block(payload, &nodes, false);
        payload = NodeState {
            state: State::ElderOffline,
            public_key: *node_a.public_info().sign_key(),
            age: node_a.public_info().age(),
            section: prefix,
        };
        let offline_a = tests::create_block(payload, &nodes, false);

        // Create Live(B) and Relocated(B).
        let node_b = FullInfo::within_range(6, &prefix.lower_bound(), &prefix.upper_bound());
        payload = NodeState {
            state: State::ElderLive,
            public_key: *node_b.public_info().sign_key(),
            age: node_b.public_info().age(),
            section: prefix,
        };
        let live_b = tests::create_block(payload, &nodes, false);
        payload = NodeState {
            state: State::ElderRelocated,
            public_key: *node_b.public_info().sign_key(),
            age: node_b.public_info().age(),
            section: prefix,
        };
        let relocated_b = tests::create_block(payload, &nodes, false);

        // Create Live(C).
        let node_c = FullInfo::within_range(7, &prefix.lower_bound(), &prefix.upper_bound());
        payload = NodeState {
            state: State::ElderLive,
            public_key: *node_c.public_info().sign_key(),
            age: node_c.public_info().age(),
            section: prefix,
        };
        let live_c = tests::create_block(payload, &nodes, false);

        // Create chain containing just Live(A).
        let mut chain = Chain::from_blocks(vec![live_a.clone()], vec![], nodes.len());
        let mut expected_blocks = vec![live_a.clone()];
        let mut expected_pendings = vec![];

        // Add Live(C) - should be held in `pending_blocks` as there's no corresponding Offline/
        // Demoted/Relocated in the `pending_blocks`.
        chain.add_block(live_c.clone());
        expected_pendings.push(live_c.clone());
        assert_eq!(chain.blocks, expected_blocks);
        assert_eq!(chain.pending_blocks, expected_pendings);

        // Add Relocated(B) - should be held in `pending_blocks` as B isn't marked as Live in the
        // chain anywhere yet.
        chain.add_block(relocated_b.clone());
        expected_pendings.push(relocated_b.clone());
        assert_eq!(chain.blocks, expected_blocks);
        assert_eq!(chain.pending_blocks, expected_pendings);

        // Add Live(B) - should be held in `pending_blocks` as the only possible Offline/Demoted/
        // Relocated in the `pending_blocks` is Relocated(B), and that can't be added since B isn't
        // marked as Live in the chain anywhere yet.
        chain.add_block(live_b.clone());
        expected_pendings.push(live_b.clone());
        assert_eq!(chain.blocks, expected_blocks);
        assert_eq!(chain.pending_blocks, expected_pendings);

        // Add Offline(A) - should cause Offline(A)/Live(B) to be added as a pair (favouring Live(B)
        // over Live(C) since there's a valid Offline/Demoted/Relocated for B, but not C), then also
        // should cause Relocated(B)/Live(C) to get moved to the `blocks`, leaving `pending_blocks`
        // empty.
        chain.add_block(offline_a.clone());
        expected_blocks = vec![live_a, offline_a, live_b, relocated_b, live_c];
        assert_eq!(chain.blocks, expected_blocks);
        assert!(chain.pending_blocks.is_empty());
    }

    #[ignore]
    #[test]
    fn add_vote() {
        // Start with the chain having Live(A) in `blocks` and Live(B) in `pending_blocks`.  Add a
        // vote for each and check the vote is added correctly.
        let mut rng = SeededRng::thread_rng();
        unwrap!(rust_sodium::init_with_rng(&mut rng));

        let prefix = Prefix::default().pushed(rng.gen()).with_version(rng.gen());
        let nodes = tests::create_full_infos(Some(prefix));

        // Create Live(A) block and extra vote for Live(A).
        let node_a = FullInfo::within_range(5, &prefix.lower_bound(), &prefix.upper_bound());
        let mut payload = NodeState {
            state: State::ElderLive,
            public_key: *node_a.public_info().sign_key(),
            age: node_a.public_info().age(),
            section: prefix,
        };
        let live_a_block = tests::create_block(payload.clone(), &nodes, false);
        let last_node = &nodes[nodes.len() - 1];
        assert!(!live_a_block.get_node_infos().contains(
            last_node.public_info(),
        ));
        let live_a_vote = unwrap!(Vote::new(nodes[0].secret_sign_key(), payload));

        // Create Live(B) and extra vote for Live(B).
        let node_b = FullInfo::within_range(6, &prefix.lower_bound(), &prefix.upper_bound());
        payload = NodeState {
            state: State::ElderLive,
            public_key: *node_b.public_info().sign_key(),
            age: node_b.public_info().age(),
            section: prefix,
        };
        let live_b_block = tests::create_block(payload.clone(), &nodes, false);
        assert!(!live_b_block.get_node_infos().contains(
            last_node.public_info(),
        ));
        let live_b_vote = unwrap!(Vote::new(nodes[0].secret_sign_key(), payload));

        // Create chain containing Live(A) in `blocks` and Live(B) in `pending_blocks`.
        let mut chain = Chain::from_blocks(
            vec![live_a_block.clone()],
            vec![live_b_block.clone()],
            nodes.len(),
        );

        // Add the vote for Live(A) and check it gets added to the Live(A) block.
        let mut proof = Proof {
            node_info: *last_node.public_info(),
            sig: *live_a_vote.signature(),
        };
        chain.add_vote(live_a_vote, *last_node.public_info());
        assert_eq!(chain.blocks.len(), 1);
        assert!(chain.blocks[0].proofs().contains(&proof));
        assert_eq!(chain.pending_blocks.len(), 1);
        assert!(!chain.pending_blocks[0].proofs().contains(&proof));

        // Add the vote for Live(B) and check it gets added to the Live(B) block.
        proof.sig = *live_b_vote.signature();
        chain.add_vote(live_b_vote, *last_node.public_info());
        assert_eq!(chain.blocks.len(), 1);
        assert!(!chain.blocks[0].proofs().contains(&proof));
        assert_eq!(chain.pending_blocks.len(), 1);
        assert!(chain.pending_blocks[0].proofs().contains(&proof));
    }

    #[ignore]
    #[test]
    fn equality() {
        // Create one chain comprising:
        //     Live(A)→Live(B)→Offline(A)→Live(C)→Relocated(B)→Live(D)
        // and another comprising:
        //     Live(A)→Live(B)→Relocated(B)→Live(C)→Offline(A)→Live(D)
        let mut rng = SeededRng::thread_rng();
        unwrap!(rust_sodium::init_with_rng(&mut rng));

        let prefix = Prefix::default().pushed(rng.gen()).with_version(rng.gen());
        let nodes = tests::create_full_infos(Some(prefix));

        // Create Live(A) and Offline(A).
        let node_a = FullInfo::within_range(5, &prefix.lower_bound(), &prefix.upper_bound());
        let mut payload = NodeState {
            state: State::ElderLive,
            public_key: *node_a.public_info().sign_key(),
            age: node_a.public_info().age(),
            section: prefix,
        };
        let live_a = tests::create_block(payload, &nodes, false);
        payload = NodeState {
            state: State::ElderOffline,
            public_key: *node_a.public_info().sign_key(),
            age: node_a.public_info().age(),
            section: prefix,
        };
        let offline_a = tests::create_block(payload, &nodes, false);

        // Create Live(B) and Relocated(B).
        let node_b = FullInfo::within_range(6, &prefix.lower_bound(), &prefix.upper_bound());
        payload = NodeState {
            state: State::ElderLive,
            public_key: *node_b.public_info().sign_key(),
            age: node_b.public_info().age(),
            section: prefix,
        };
        let live_b = tests::create_block(payload, &nodes, false);
        payload = NodeState {
            state: State::ElderRelocated,
            public_key: *node_b.public_info().sign_key(),
            age: node_b.public_info().age(),
            section: prefix,
        };
        let relocated_b = tests::create_block(payload, &nodes, false);

        // Create Live(C).
        let node_c = FullInfo::within_range(7, &prefix.lower_bound(), &prefix.upper_bound());
        payload = NodeState {
            state: State::ElderLive,
            public_key: *node_c.public_info().sign_key(),
            age: node_c.public_info().age(),
            section: prefix,
        };
        let live_c = tests::create_block(payload, &nodes, false);

        // Create Live(D).
        let node_d = FullInfo::within_range(6, &prefix.lower_bound(), &prefix.upper_bound());
        payload = NodeState {
            state: State::ElderLive,
            public_key: *node_d.public_info().sign_key(),
            age: node_d.public_info().age(),
            section: prefix,
        };
        let live_d = tests::create_block(payload, &nodes, false);

        // Create chains and assert that they compare equal.
        let chain1 = Chain::from_blocks(
            vec![
                live_a.clone(),
                live_b.clone(),
                offline_a.clone(),
                live_c.clone(),
                relocated_b.clone(),
                live_d.clone(),
            ],
            vec![],
            nodes.len(),
        );
        let chain2 = Chain::from_blocks(
            vec![live_a, live_b, relocated_b, live_c, offline_a, live_d],
            vec![],
            nodes.len(),
        );
        assert_ne!(chain1.blocks, chain2.blocks);
        assert_eq!(chain1, chain2);
    }
}
