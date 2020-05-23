// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{crypto::signing::Signature, id::PublicId};
#[cfg(test)]
use crate::{error::Result, id::FullId};
use itertools::Itertools;
use serde::Serialize;
use std::{
    collections::BTreeMap,
    fmt::{self, Debug, Formatter},
};

/// Proof as provided by a close group member. This struct should be ordered by age then `PublicKey`
#[derive(Serialize, Deserialize, PartialOrd, Ord, PartialEq, Eq, Clone, Copy, Hash)]
pub struct Proof {
    pub pub_id: PublicId,
    pub sig: Signature,
}

impl Proof {
    /// getter
    pub fn pub_id(&self) -> &PublicId {
        &self.pub_id
    }

    /// getter
    pub fn _sig(&self) -> &Signature {
        &self.sig
    }

    /// Create a new proof for `payload`
    #[cfg(test)]
    pub fn new<S: Serialize>(full_id: &FullId, payload: &S) -> Result<Self> {
        let sig = full_id.sign(&bincode::serialize(&payload)?[..]);
        Ok(Self {
            pub_id: *full_id.public_id(),
            sig,
        })
    }

    /// Validates `payload` against this `Proof`'s `key` and `sig`.
    #[cfg(test)]
    pub fn validate_signature<S: Serialize>(&self, payload: &S) -> bool {
        match bincode::serialize(payload) {
            Ok(data) => self.pub_id.verify(&data[..], &self.sig),
            _ => false,
        }
    }
}

impl Debug for Proof {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "Proof{{ {:?}, sig: ... }}", self.pub_id.name(),)
    }
}

/// A set of proofs.
#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Hash, Default, Ord, PartialOrd)]
pub struct ProofSet {
    // TODO: Make the field private again after refactoring.
    pub sigs: BTreeMap<PublicId, Signature>,
}

impl ProofSet {
    /// Inserts a proof into the set. Returns `true` if it wasn't already there.
    pub fn add_proof(&mut self, Proof { pub_id, sig }: Proof) -> bool {
        self.sigs.insert(pub_id, sig).is_none()
    }

    /// Returns whether the set contains a signature by that ID.
    pub fn contains_id(&self, id: &PublicId) -> bool {
        self.sigs.contains_key(id)
    }

    /// Returns an iterator of all public IDs that have signed.
    pub fn ids(&self) -> impl Iterator<Item = &PublicId> {
        self.sigs.keys()
    }
}

impl Debug for ProofSet {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "ProofSet {{ {:?} }}",
            self.sigs.keys().collect_vec(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::Proof;
    use crate::{consensus::AccumulatingEvent, id::FullId, rng};

    #[test]
    fn confirm_proof() {
        let mut rng = rng::new();
        let full_id = FullId::gen(&mut rng);
        let payload = AccumulatingEvent::User(vec![0]);
        let proof = Proof::new(&full_id, &payload).unwrap();
        assert!(proof.validate_signature(&payload));
    }

    #[test]
    #[ignore] // Enable once sig checks are enabled
    fn bad_construction() {
        let mut rng = rng::new();
        let full_id = FullId::gen(&mut rng);
        let pub_id = *full_id.public_id();
        let payload = AccumulatingEvent::User(vec![0]);
        let other_payload = AccumulatingEvent::Offline(pub_id);
        let proof = Proof::new(&full_id, &payload).unwrap();
        assert!(!proof.validate_signature(&other_payload));
    }
}
