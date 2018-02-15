// Copyright 2017 MaidSafe.net limited.
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

use super::{Proof, Vote};
use error::RoutingError;
use public_info::PublicInfo;
use serde::Serialize;
use std::collections::BTreeSet;
use std::iter;

#[allow(unused)]
pub struct NodesAndAge {
    nodes: usize,
    age: usize,
}

#[allow(unused)]
impl NodesAndAge {
    pub fn new(nodes: usize, age: usize) -> NodesAndAge {
        NodesAndAge {
            nodes: nodes,
            age: age,
        }
    }

    #[allow(unused)]
    pub fn nodes(&self) -> usize {
        self.nodes
    }

    #[allow(unused)]
    pub fn age(&self) -> usize {
        self.age
    }
}

/// Validity and "completeness" of a `Block`. Some `Block`s are complete with less than `group_size`
/// `Proof`s.
#[derive(Debug, PartialEq)]
pub enum BlockState {
    NotYetValid,
    Valid,
    Full,
}

/// A `Block` *is* network consensus. It covers a group of nodes closest to an address and is signed
/// With quorum valid votes, the consensus is then valid and therefore the `Block` however it's
/// worth recognising quorum is the weakest consensus as any difference on network view will break
/// it. Full group consensus is strongest, but likely unachievable most of the time, so a union
/// can increase a single `Node`s quorum valid `Block`.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Ord, PartialOrd, Clone)]
pub struct Block<T> {
    payload: T,
    proofs: BTreeSet<Proof>,
}

impl<T: Serialize + Clone> Block<T> {
    /// A new `Block` requires a valid vote and the `PublicInfo` of the node who sent us this. For
    /// this reason the `Vote` will require a `DirectMessage` from a node to us.
    pub fn new(vote: &Vote<T>, node_info: &PublicInfo) -> Result<Block<T>, RoutingError> {
        Ok(Block {
            payload: vote.payload().clone(),
            proofs: iter::once(vote.proof(node_info)?).collect(),
        })
    }

    /// Add a vote from a node when we know we have an existing `Block`.
    pub fn add_vote(
        &mut self,
        vote: &Vote<T>,
        node_info: &PublicInfo,
        valid_voters: &BTreeSet<PublicInfo>,
    ) -> Result<BlockState, RoutingError> {
        let proof = vote.proof(node_info)?;
        self.insert_proof(proof, valid_voters)
    }

    /// Add a proof from a node when we know we have an existing `Block`.
    pub fn add_proof(
        &mut self,
        proof: Proof,
        valid_voters: &BTreeSet<PublicInfo>,
    ) -> Result<BlockState, RoutingError> {
        if !proof.validate_signature(&self.payload) {
            Err(RoutingError::FailedSignature)
        } else {
            self.insert_proof(proof, valid_voters)
        }
    }

    pub fn get_node_infos(&self) -> BTreeSet<PublicInfo> {
        let mut node_infos = BTreeSet::new();
        for proof in &self.proofs {
            let _ = node_infos.insert(proof.node_info().clone());
        }
        node_infos
    }

    /// Return number of `Proof`s.
    pub fn num_proofs(&self) -> usize {
        self.proofs.len()
    }

    /// Return total age of all of signatories.
    pub fn total_age(&self) -> usize {
        self.proofs.iter().fold(
            0,
            |total, proof| total + usize::from(proof.node_info().age()),
        )
    }

    /// getter
    pub fn proofs(&self) -> &BTreeSet<Proof> {
        &self.proofs
    }

    /// getter
    pub fn payload(&self) -> &T {
        &self.payload
    }

    /// Return the block state given a set of valid voters.
    pub fn get_block_state(
        &self,
        valid_voters: &BTreeSet<PublicInfo>,
    ) -> Result<BlockState, RoutingError> {
        if self.proofs.len() >= valid_voters.len() {
            return Ok(BlockState::Full);
        }
        let total_age = valid_voters
            .iter()
            .map(|node_info| usize::from(node_info.age()))
            .sum();
        if self.total_age() * 2 > total_age && self.num_proofs() * 2 > valid_voters.len() {
            Ok(BlockState::Valid)
        } else {
            Ok(BlockState::NotYetValid)
        }
    }

    /// Create an iterator over all proofs and transform into votes.
    pub fn votes_iter<'a>(&'a self) -> Box<Iterator<Item = (&PublicInfo, Vote<T>)> + 'a> {
        Box::new(self.proofs.iter().map(move |proof| {
            (
                proof.node_info(),
                Vote::compose(self.payload.clone(), *proof.sig()),
            )
        }))
    }

    fn insert_proof(
        &mut self,
        proof: Proof,
        valid_voters: &BTreeSet<PublicInfo>,
    ) -> Result<BlockState, RoutingError> {
        if !valid_voters.contains(proof.node_info()) {
            return Err(RoutingError::InvalidSource);
        }
        if self.proofs.insert(proof) {
            self.get_block_state(valid_voters)
        } else {
            Err(RoutingError::DuplicateSignatures)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use full_info::FullInfo;
    use maidsafe_utilities::SeededRng;
    use rand::Rng;
    use rust_sodium;
    use std::collections::BTreeMap;

    #[test]
    fn create_then_add_proofs() {
        let mut rng = SeededRng::thread_rng();
        unwrap!(rust_sodium::init_with_rng(&mut rng));

        let mut full_info_0 = FullInfo::node_new(0);
        let mut full_info_1 = FullInfo::node_new(0);
        let public_info_0 = *full_info_0.public_info();
        let public_info_1 = *full_info_1.public_info();

        let payload = "Gone";
        let vote0 = unwrap!(Vote::new(full_info_0.secret_sign_key(), payload));
        assert!(vote0.validate_signature(&public_info_0));
        let vote1 = unwrap!(Vote::new(full_info_1.secret_sign_key(), payload));
        assert!(vote1.validate_signature(&public_info_1));

        full_info_0.set_age(1u8);
        full_info_1.set_age(rng.gen_range(0, 255));
        let public_info_00 = *full_info_0.public_info();
        let public_info_10 = *full_info_1.public_info();

        let proof0 = unwrap!(vote0.proof(&public_info_00));
        assert!(proof0.validate_signature(&payload));
        let proof1 = unwrap!(vote1.proof(&public_info_10));
        assert!(proof1.validate_signature(&payload));
        let mut b0 = unwrap!(Block::new(&vote0, &public_info_00));
        assert!(proof0.validate_signature(&b0.payload));
        assert!(proof1.validate_signature(&b0.payload));
        let mut valid_voters = BTreeSet::new();
        let _ = valid_voters.insert(public_info_00);
        let _ = valid_voters.insert(public_info_10);
        assert!(b0.add_proof(proof0, &valid_voters).is_err());
        assert_eq!(b0.num_proofs(), 1);
        assert!(b0.add_proof(proof1, &valid_voters).is_ok());
        assert_eq!(b0.num_proofs(), 2);
    }

    #[test]
    fn confirm_new_proof_batch() {
        let mut rng = SeededRng::thread_rng();
        unwrap!(rust_sodium::init_with_rng(&mut rng));

        let mut full_info_0 = FullInfo::node_new(0);
        let mut full_info_1 = FullInfo::node_new(0);
        let mut full_info_2 = FullInfo::node_new(0);

        let payload = "Gone";
        let vote0 = unwrap!(Vote::new(full_info_0.secret_sign_key(), payload));
        let vote1 = unwrap!(Vote::new(full_info_1.secret_sign_key(), payload));
        let vote2 = unwrap!(Vote::new(full_info_2.secret_sign_key(), payload));
        let age0: u8 = rng.gen_range(0, 255);
        let age1: u8 = rng.gen_range(0, 255);
        let age2: u8 = rng.gen_range(0, 255);
        full_info_0.set_age(age0);
        full_info_1.set_age(age1);
        full_info_2.set_age(age2);
        let public_info_0 = *full_info_0.public_info();
        let public_info_1 = *full_info_1.public_info();
        let public_info_2 = *full_info_2.public_info();

        let mut valid_voters = BTreeSet::new();
        let _ = valid_voters.insert(public_info_0);
        let _ = valid_voters.insert(public_info_1);
        let _ = valid_voters.insert(public_info_2);
        let proof1 = unwrap!(vote1.proof(&public_info_1));
        let proof2 = unwrap!(vote2.proof(&public_info_2));
        // So 3 votes all valid will be added to block
        let mut b0 = unwrap!(Block::new(&vote0, &public_info_0));
        if (usize::from(age0) + usize::from(age1)) > usize::from(age2) {
            assert_eq!(
                unwrap!(b0.add_proof(proof1, &valid_voters)),
                BlockState::Valid
            );
        } else {
            assert_eq!(
                unwrap!(b0.add_proof(proof1, &valid_voters)),
                BlockState::NotYetValid
            );
        }
        assert_eq!(
            unwrap!(b0.add_proof(proof2, &valid_voters)),
            BlockState::Full
        );
        assert_eq!(b0.num_proofs(), 3);
    }

    #[test]
    fn votes_iter() {
        let mut rng = SeededRng::thread_rng();
        unwrap!(rust_sodium::init_with_rng(&mut rng));

        let full_info_0 = FullInfo::node_new(0);
        let full_info_1 = FullInfo::node_new(0);

        let payload = "Gone";
        let vote0 = unwrap!(Vote::new(full_info_0.secret_sign_key(), payload));
        let vote1 = unwrap!(Vote::new(full_info_1.secret_sign_key(), payload));

        let mut voters = BTreeSet::new();
        let _ = voters.insert(*full_info_0.public_info());
        let _ = voters.insert(*full_info_1.public_info());

        let mut block = unwrap!(Block::new(&vote0, full_info_0.public_info()));
        let _ = unwrap!(block.add_vote(&vote1, full_info_1.public_info(), &voters));

        let votes: BTreeMap<_, _> = block.votes_iter().collect();
        assert_eq!(votes.len(), 2);

        let vote_0 = unwrap!(votes.get(full_info_0.public_info()));
        assert!(vote_0.validate_signature(full_info_0.public_info()));

        let vote_1 = unwrap!(votes.get(full_info_1.public_info()));
        assert!(vote_1.validate_signature(full_info_1.public_info()));
    }
}
