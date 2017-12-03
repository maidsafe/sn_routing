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
/// Validity and "completeness" of a `Block`. Some `Block`s are complete with less than group_size `Proof`s.
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
    /// A new `Block` requires a valid vote and the `PublicKey` of the node who sent us this. For
    /// this reason The `Vote` will require a Direct Message from a `Peer` to us.
    #[allow(unused)]
    pub fn new(vote: &Vote<T>, peer_id: &PeerId) -> Result<Block<T>, RoutingError> {
        if let Some(proof) = vote.proof(peer_id) {
            let mut proofset = BTreeSet::<Proof>::new();
            if !proofset.insert(proof) {
                return Err(RoutingError::FailedSignature);
            }
            return Ok(Block::<T> {
                payload: vote.payload().clone(),
                proofs: proofset,
            });
        }
        Err(RoutingError::FailedSignature)
    }

    /// Add a proof from a peer when we know we have an existing `Block`.
    #[allow(unused)]
    pub fn add_proof(&mut self, proof: Proof) -> Result<(), RoutingError> {
        if !proof.validate_signature(&self.payload) {
            return Err(RoutingError::FailedSignature);
        }
        if self.proofs.insert(proof) {
            return Ok(());
        }
        Err(RoutingError::FailedSignature)
    }


    pub fn get_peer_ids(&self) -> BTreeSet<PeerId> {
        let mut peers = BTreeSet::new();
        for proof in self.proofs.iter() {
            let _ = peers.insert(proof.peer_id().clone());
        }
        peers
    }

    /// Return number of `Proof`s.
    #[allow(unused)]
    pub fn num_proofs(&self) -> usize {
        self.proofs.iter().count()
    }

    /// Return total age of all of signatories.
    #[allow(unused)]
    pub fn total_age(&self) -> usize {
        self.proofs
            .iter()
            .fold(0, |total, proof| total + proof.peer_id().age() as usize)
    }

    #[allow(unused)]
    /// getter
    pub fn proofs(&self) -> &BTreeSet<Proof> {
        &self.proofs
    }

    /// getter
    pub fn payload(&self) -> &T {
        &self.payload
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maidsafe_utilities::SeededRng;
    use rand::random;
    use rust_sodium;
    use rust_sodium::crypto::sign;
    use network_event::SectionState;

    #[test]
    fn create_then_add_proofs() {
        let mut rng = SeededRng::thread_rng();
        unwrap!(rust_sodium::init_with_rng(&mut rng));

        let keys0 = sign::gen_keypair();
        let keys1 = sign::gen_keypair();
        let payload = SectionState::Gone(PeerId::new(0, keys0.0));
        let vote0 = Vote::new(&keys0.1, payload.clone()).unwrap();
        assert!(vote0.validate_signature(&keys0.0));
        let vote1 = Vote::new(&keys1.1, payload.clone()).unwrap();
        assert!(vote1.validate_signature(&keys1.0));
        let proof0 = vote0.proof(&PeerId::new(1u8, keys0.0)).unwrap();
        assert!(proof0.validate_signature(&payload));
        let proof1 = vote1.proof(&PeerId::new(random::<u8>(), keys1.0)).unwrap();
        assert!(proof1.validate_signature(&payload));
        let mut b0 = Block::new(&vote0, &PeerId::new(1u8, keys0.0)).unwrap();
        assert!(proof0.validate_signature(&b0.payload));
        assert!(proof1.validate_signature(&b0.payload));
        assert!(b0.add_proof(proof0).is_err());
        assert_eq!(b0.num_proofs(), 1);
        assert!(b0.add_proof(proof1).is_ok());
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
        let vote0 = Vote::new(&keys0.1, payload.clone()).unwrap();
        let vote1 = Vote::new(&keys1.1, payload.clone()).unwrap();
        let vote2 = Vote::new(&keys2.1, payload.clone()).unwrap();
        let proof1 = vote1.proof(&PeerId::new(random::<u8>(), keys1.0)).unwrap();
        let proof2 = vote2.proof(&PeerId::new(random::<u8>(), keys2.0)).unwrap();
        // So 3 votes all valid will be added to block
        let mut b0 = Block::new(&vote0, &PeerId::new(random::<u8>(), keys0.0)).unwrap();
        assert!(b0.add_proof(proof1).is_ok());
        assert!(b0.add_proof(proof2).is_ok());
        assert_eq!(b0.num_proofs(), 3);
    }
}
