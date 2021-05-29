// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    crypto::{self, Digest256, Keypair, Verifier},
    peer::PeerUtils,
    section::ElderCandidatesUtils,
    supermajority,
};
use sn_messaging::node::{DkgFailureProof, DkgFailureProofSet, DkgKey, ElderCandidates};
use std::collections::BTreeSet;
use tiny_keccak::{Hasher, Sha3};
use xor_name::XorName;

pub trait DkgKeyUtils {
    fn new(elder_candidates: &ElderCandidates, generation: u64) -> Self;
}

impl DkgKeyUtils for DkgKey {
    fn new(elder_candidates: &ElderCandidates, generation: u64) -> Self {
        // Calculate the hash without involving serialization to avoid having to return `Result`.
        let mut hasher = Sha3::v256();
        let mut hash = Digest256::default();

        for peer in elder_candidates.peers() {
            hasher.update(&peer.name().0);
        }

        hasher.update(&elder_candidates.prefix.name().0);
        hasher.update(&elder_candidates.prefix.bit_count().to_le_bytes());
        hasher.finalize(&mut hash);

        Self { hash, generation }
    }
}

pub trait DkgFailureProofUtils {
    fn new(keypair: &Keypair, non_participants: &BTreeSet<XorName>, dkg_key: &DkgKey) -> Self;

    fn verify(&self, dkg_key: &DkgKey, non_participants: &BTreeSet<XorName>) -> bool;
}

impl DkgFailureProofUtils for DkgFailureProof {
    fn new(keypair: &Keypair, non_participants: &BTreeSet<XorName>, dkg_key: &DkgKey) -> Self {
        DkgFailureProof {
            public_key: keypair.public,
            signature: crypto::sign(&failure_proof_hash(dkg_key, non_participants), keypair),
        }
    }

    fn verify(&self, dkg_key: &DkgKey, non_participants: &BTreeSet<XorName>) -> bool {
        let hash = failure_proof_hash(dkg_key, non_participants);
        self.public_key.verify(&hash, &self.signature).is_ok()
    }
}

pub trait DkgFailureProofSetUtils {
    fn insert(&mut self, proof: DkgFailureProof, non_participants: &BTreeSet<XorName>) -> bool;

    fn has_agreement(&self, elder_candidates: &ElderCandidates) -> bool;

    fn verify(&self, elder_candidates: &ElderCandidates, generation: u64) -> bool;
}

impl DkgFailureProofSetUtils for DkgFailureProofSet {
    // Insert a proof into this set. The proof is assumed valid. Returns `true` if the proof was
    // not already present in the set and `false` otherwise.
    fn insert(&mut self, proof: DkgFailureProof, non_participants: &BTreeSet<XorName>) -> bool {
        if self.non_participants.is_empty() {
            self.non_participants = non_participants.clone();
        }
        if self
            .proofs
            .iter()
            .all(|existing_proof| existing_proof.public_key != proof.public_key)
        {
            self.proofs.push(proof);
            true
        } else {
            false
        }
    }

    // Check whether we have enough proofs to reach agreement on the failure. The contained proofs
    // are assumed valid.
    fn has_agreement(&self, elder_candidates: &ElderCandidates) -> bool {
        has_failure_agreement(elder_candidates.elders.len(), self.proofs.len())
    }

    fn verify(&self, elder_candidates: &ElderCandidates, generation: u64) -> bool {
        let hash = failure_proof_hash(
            &DkgKey::new(elder_candidates, generation),
            &self.non_participants,
        );
        let votes = self
            .proofs
            .iter()
            .filter(|proof| {
                elder_candidates
                    .elders
                    .contains_key(&crypto::name(&proof.public_key))
                    && proof.public_key.verify(&hash, &proof.signature).is_ok()
            })
            .count();

        has_failure_agreement(elder_candidates.elders.len(), votes)
    }
}

// Check whether we have enough proofs to reach agreement on the failure. We only need
// `N - supermajority(N) + 1` proofs, because that already makes a supermajority agreement on a
// successful outcome impossible.
fn has_failure_agreement(num_participants: usize, num_votes: usize) -> bool {
    num_votes > num_participants - supermajority(num_participants)
}

// Create a value whose signature serves as the proof that a failure of a DKG session with the given
// `dkg_key` was observed.
fn failure_proof_hash(dkg_key: &DkgKey, non_participants: &BTreeSet<XorName>) -> Digest256 {
    let mut hasher = Sha3::v256();
    let mut hash = Digest256::default();
    hasher.update(&dkg_key.hash);
    hasher.update(&dkg_key.generation.to_le_bytes());
    for name in non_participants.iter() {
        hasher.update(&name.0);
    }
    hasher.update(b"failure");
    hasher.finalize(&mut hash);
    hash
}
