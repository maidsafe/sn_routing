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

use error::RoutingError;
use peer_id::PeerId;
use proof::Proof;
use serde::Serialize;
use std::collections::BTreeSet;
use std::iter;
use vote::Vote;

#[allow(unused)]
pub struct PeersAndAge {
    peers: usize,
    age: usize,
}

#[allow(unused)]
impl PeersAndAge {
    pub fn new(peers: usize, age: usize) -> PeersAndAge {
        PeersAndAge {
            peers: peers,
            age: age,
        }
    }

    #[allow(unused)]
    pub fn peers(&self) -> usize {
        self.peers
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
/// can increase a single `Peer`s quorum valid `Block`.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Ord, PartialOrd, Clone)]
pub struct Block<T> {
    payload: T,
    proofs: BTreeSet<Proof>,
}

impl<T: Serialize + Clone> Block<T> {
    /// A new `Block` requires a valid vote and the `PeerId` of the peer who sent us this. For
    /// this reason the `Vote` will require a `DirectMessage` from a peer to us.
    pub fn new(vote: &Vote<T>, peer_id: &PeerId) -> Result<Block<T>, RoutingError> {
        Ok(Block {
            payload: vote.payload().clone(),
            proofs: iter::once(vote.proof(peer_id)?).collect(),
        })
    }

    /// Add a vote from a peer when we know we have an existing `Block`.
    pub fn add_vote(
        &mut self,
        vote: &Vote<T>,
        peer_id: &PeerId,
        valid_voters: &BTreeSet<PeerId>,
    ) -> Result<BlockState, RoutingError> {
        let proof = vote.proof(peer_id)?;
        self.insert_proof(proof, valid_voters)
    }

    /// Add a proof from a peer when we know we have an existing `Block`.
    pub fn add_proof(
        &mut self,
        proof: Proof,
        valid_voters: &BTreeSet<PeerId>,
    ) -> Result<BlockState, RoutingError> {
        if !proof.validate_signature(&self.payload) {
            Err(RoutingError::FailedSignature)
        } else {
            self.insert_proof(proof, valid_voters)
        }
    }

    pub fn get_peer_ids(&self) -> BTreeSet<PeerId> {
        let mut peers = BTreeSet::new();
        for proof in &self.proofs {
            let _ = peers.insert(proof.peer_id().clone());
        }
        peers
    }

    /// Return number of `Proof`s.
    pub fn num_proofs(&self) -> usize {
        self.proofs.iter().count()
    }

    /// Return total age of all of signatories.
    pub fn total_age(&self) -> usize {
        self.proofs.iter().fold(0, |total, proof| {
            total + proof.peer_id().age() as usize
        })
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
        valid_voters: &BTreeSet<PeerId>,
    ) -> Result<BlockState, RoutingError> {
        if self.proofs.len() >= valid_voters.len() {
            return Ok(BlockState::Full);
        }
        let total_age = valid_voters
            .iter()
            .map(|peer_id| peer_id.age() as usize)
            .sum();
        if self.total_age() * 2 > total_age && self.num_proofs() * 2 > valid_voters.len() {
            Ok(BlockState::Valid)
        } else {
            Ok(BlockState::NotYetValid)
        }
    }

    fn insert_proof(
        &mut self,
        proof: Proof,
        valid_voters: &BTreeSet<PeerId>,
    ) -> Result<BlockState, RoutingError> {
        if !valid_voters.contains(proof.peer_id()) {
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
    use maidsafe_utilities::SeededRng;
    use network_event::SectionState;
    use rand::Rng;
    use rust_sodium;
    use rust_sodium::crypto::sign;

    #[test]
    fn create_then_add_proofs() {
        let mut rng = SeededRng::thread_rng();
        unwrap!(rust_sodium::init_with_rng(&mut rng));

        let keys0 = sign::gen_keypair();
        let keys1 = sign::gen_keypair();
        let peer_id0 = PeerId::new(0, keys0.0);
        let peer_id1 = PeerId::new(0, keys1.0);
        let payload = SectionState::Gone(peer_id0.clone());
        let vote0 = unwrap!(Vote::new(&keys0.1, payload.clone()));
        assert!(vote0.validate_signature(&peer_id0));
        let vote1 = unwrap!(Vote::new(&keys1.1, payload.clone()));
        assert!(vote1.validate_signature(&peer_id1));
        let peer_id00 = PeerId::new(1u8, keys0.0);
        let peer_id10 = PeerId::new(rng.gen_range(0, 255), keys1.0);
        let proof0 = unwrap!(vote0.proof(&peer_id00));
        assert!(proof0.validate_signature(&payload));
        let proof1 = unwrap!(vote1.proof(&peer_id10));
        assert!(proof1.validate_signature(&payload));
        let mut b0 = unwrap!(Block::new(&vote0, &peer_id00));
        assert!(proof0.validate_signature(&b0.payload));
        assert!(proof1.validate_signature(&b0.payload));
        let mut valid_voters = BTreeSet::new();
        let _ = valid_voters.insert(peer_id00);
        let _ = valid_voters.insert(peer_id10);
        assert!(b0.add_proof(proof0, &valid_voters).is_err());
        assert_eq!(b0.num_proofs(), 1);
        assert!(b0.add_proof(proof1, &valid_voters).is_ok());
        assert_eq!(b0.num_proofs(), 2);
    }

    #[test]
    fn confirm_new_proof_batch() {
        let mut rng = SeededRng::thread_rng();
        unwrap!(rust_sodium::init_with_rng(&mut rng));

        let keys0 = sign::gen_keypair();
        let keys1 = sign::gen_keypair();
        let keys2 = sign::gen_keypair();
        let payload = SectionState::Gone(PeerId::new(0, keys0.0));
        let vote0 = unwrap!(Vote::new(&keys0.1, payload.clone()));
        let vote1 = unwrap!(Vote::new(&keys1.1, payload.clone()));
        let vote2 = unwrap!(Vote::new(&keys2.1, payload.clone()));
        let age0 = rng.gen_range(0, 255);
        let age1 = rng.gen_range(0, 255);
        let age2 = rng.gen_range(0, 255);
        let peer_id0 = PeerId::new(age0, keys0.0);
        let peer_id1 = PeerId::new(age1, keys1.0);
        let peer_id2 = PeerId::new(age2, keys2.0);
        let mut valid_voters = BTreeSet::new();
        let _ = valid_voters.insert(peer_id0.clone());
        let _ = valid_voters.insert(peer_id1.clone());
        let _ = valid_voters.insert(peer_id2.clone());
        let proof1 = unwrap!(vote1.proof(&peer_id1));
        let proof2 = unwrap!(vote2.proof(&peer_id2));
        // So 3 votes all valid will be added to block
        let mut b0 = unwrap!(Block::new(&vote0, &peer_id0));
        if (age0 as usize + age1 as usize) > age2 as usize {
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
    fn random_vote_or_proof() {
        let mut rng = SeededRng::thread_rng();
        unwrap!(rust_sodium::init_with_rng(&mut rng));

        let num_of_voters = 8;
        let mut total_age = 0;
        let mut keys_list = Vec::new();

        let valid_voters: BTreeSet<PeerId> = (0..num_of_voters)
            .map(|_| {
                let age = rng.gen_range(0, 255);
                total_age += age as usize;
                let keys = sign::gen_keypair();
                keys_list.push(keys.clone());
                PeerId::new(age, keys.0)
            })
            .collect();

        let peer_id0 = unwrap!(valid_voters.iter().find(|peer_id| {
            *peer_id.pub_key() == keys_list[0].0
        }));
        let payload = SectionState::Live(PeerId::new(0, keys_list[0].0));
        let vote0 = unwrap!(Vote::new(&keys_list[0].1, payload.clone()));
        let mut block = unwrap!(Block::new(&vote0, peer_id0));
        let mut accumulated_age = peer_id0.age() as usize;

        for idx in 1..num_of_voters {
            let peer_id = unwrap!(valid_voters.iter().find(|peer_id| {
                *peer_id.pub_key() == keys_list[idx].0
            }));
            accumulated_age += peer_id.age() as usize;
            let vote = unwrap!(Vote::new(&keys_list[idx].1, payload.clone()));
            if rng.gen() {
                // insert as vote
                assert!(block.add_vote(&vote, peer_id, &valid_voters).is_ok());
            } else {
                // insert as proof
                let proof = unwrap!(vote.proof(peer_id));
                assert!(block.add_proof(proof, &valid_voters).is_ok());
            }
            assert_eq!(accumulated_age, block.total_age());
            if block.num_proofs() == num_of_voters {
                assert_eq!(
                    unwrap!(block.get_block_state(&valid_voters)),
                    BlockState::Full
                );
            } else if accumulated_age * 2 > total_age && block.num_proofs() * 2 > num_of_voters {
                assert_eq!(
                    unwrap!(block.get_block_state(&valid_voters)),
                    BlockState::Valid
                );
            } else {
                assert_eq!(
                    unwrap!(block.get_block_state(&valid_voters)),
                    BlockState::NotYetValid
                );
            }
        }
    }
}
