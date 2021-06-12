// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    ed25519::{self, Digest256, Keypair, Verifier},
    peer::PeerUtils,
    section::ElderCandidatesUtils,
    supermajority,
};
use sn_messaging::node::{DkgFailureSigned, DkgFailureSignedSet, DkgKey, ElderCandidates};
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

pub trait DkgFailureSignedUtils {
    fn new(keypair: &Keypair, non_participants: &BTreeSet<XorName>, dkg_key: &DkgKey) -> Self;

    fn verify(&self, dkg_key: &DkgKey, non_participants: &BTreeSet<XorName>) -> bool;
}

impl DkgFailureSignedUtils for DkgFailureSigned {
    fn new(keypair: &Keypair, non_participants: &BTreeSet<XorName>, dkg_key: &DkgKey) -> Self {
        DkgFailureSigned {
            public_key: keypair.public,
            signature: ed25519::sign(&failure_signed_hash(dkg_key, non_participants), keypair),
        }
    }

    fn verify(&self, dkg_key: &DkgKey, non_participants: &BTreeSet<XorName>) -> bool {
        let hash = failure_signed_hash(dkg_key, non_participants);
        self.public_key.verify(&hash, &self.signature).is_ok()
    }
}

pub trait DkgFailureSignedSetUtils {
    fn insert(&mut self, signed: DkgFailureSigned, non_participants: &BTreeSet<XorName>) -> bool;

    fn has_agreement(&self, elder_candidates: &ElderCandidates) -> bool;

    fn verify(&self, elder_candidates: &ElderCandidates, generation: u64) -> bool;
}

impl DkgFailureSignedSetUtils for DkgFailureSignedSet {
    // Insert a signed into this set. The signed is assumed valid. Returns `true` if the signed was
    // not already present in the set and `false` otherwise.
    fn insert(&mut self, signed: DkgFailureSigned, non_participants: &BTreeSet<XorName>) -> bool {
        if self.non_participants.is_empty() {
            self.non_participants = non_participants.clone();
        }
        if self
            .signeds
            .iter()
            .all(|existing_signed| existing_signed.public_key != signed.public_key)
        {
            self.signeds.push(signed);
            true
        } else {
            false
        }
    }

    // Check whether we have enough signeds to reach agreement on the failure. The contained signeds
    // are assumed valid.
    fn has_agreement(&self, elder_candidates: &ElderCandidates) -> bool {
        has_failure_agreement(elder_candidates.elders.len(), self.signeds.len())
    }

    fn verify(&self, elder_candidates: &ElderCandidates, generation: u64) -> bool {
        let hash = failure_signed_hash(
            &DkgKey::new(elder_candidates, generation),
            &self.non_participants,
        );
        let votes = self
            .signeds
            .iter()
            .filter(|signed| {
                elder_candidates
                    .elders
                    .contains_key(&ed25519::name(&signed.public_key))
                    && signed.public_key.verify(&hash, &signed.signature).is_ok()
            })
            .count();

        has_failure_agreement(elder_candidates.elders.len(), votes)
    }
}

// Check whether we have enough signeds to reach agreement on the failure. We only need
// `N - supermajority(N) + 1` signeds, because that already makes a supermajority agreement on a
// successful outcome impossible.
fn has_failure_agreement(num_participants: usize, num_votes: usize) -> bool {
    num_votes > num_participants - supermajority(num_participants)
}

// Create a value whose signature serves as the signed that a failure of a DKG session with the given
// `dkg_key` was observed.
fn failure_signed_hash(dkg_key: &DkgKey, non_participants: &BTreeSet<XorName>) -> Digest256 {
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
