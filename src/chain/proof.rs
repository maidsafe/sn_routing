// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::error::Result;
use crate::id::{FullId, PublicId};
use itertools::Itertools;
use maidsafe_utilities::serialisation;
use crate::ed25519::Signature;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fmt::{self, Debug, Formatter};

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
    #[allow(clippy::new_ret_no_self)]
    pub fn new<S: Serialize>(id: &FullId, payload: &S) -> Result<Self> {
        let signature = id.ed_sign(&serialisation::serialise(&payload)?[..]);
        Ok(Proof {
            pub_id: *id.public_id(),
            sig: signature,
        })
    }

    /// Validates `payload` against this `Proof`'s `key` and `sig`.
    pub fn validate_signature<S: Serialize>(&self, payload: &S) -> bool {
        match serialisation::serialise(payload) {
            Ok(data) => self
                .pub_id
                .verify(&data[..], &self.sig),
            _ => false,
        }
    }
}

impl Debug for Proof {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "Proof{{ {:?}, age: {}, sig: ... }}",
            self.pub_id.name(),
            self.pub_id.age()
        )
    }
}

/// A set of proofs.
#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Hash, Default, Ord, PartialOrd)]
pub struct ProofSet {
    // TODO: Make the field private again after refactoring.
    pub sigs: BTreeMap<PublicId, Signature>,
}

impl ProofSet {
    /// Creates a new empty set.
    pub fn new() -> ProofSet {
        ProofSet::default()
    }

    /// Inserts a proof into the set. Returns `true` if it wasn't already there.
    pub fn add_proof(&mut self, Proof { pub_id, sig }: Proof) -> bool {
        self.sigs.insert(pub_id, sig).is_none()
    }

    /// Returns whether the set contains a signature by that ID.
    pub fn contains_id(&self, id: &PublicId) -> bool {
        self.sigs.contains_key(id)
    }

    /// Validates `payload` against all signatures.
    pub fn validate_signatures<S: Serialize>(&self, payload: &S) -> bool {
        match serialisation::serialise(payload) {
            Ok(data) => self.validate_signatures_for_bytes(&data),
            _ => false,
        }
    }

    /// Validates `data` against all signatures.
    fn validate_signatures_for_bytes(&self, data: &[u8]) -> bool {
        let validate =
            |(id, sig): (&PublicId, &Signature)| id.verify(data, sig);
        self.sigs.iter().all(validate)
    }

    /// Returns an iterator of all public IDs that have signed.
    pub fn ids(&self) -> impl Iterator<Item = &PublicId> {
        self.sigs.keys()
    }

    /// Returns the number of signatures.
    pub fn len(&self) -> usize {
        self.sigs.len()
    }

    /// Removes the node's signature. Returns `false` if it already didn't exist.
    pub fn remove(&mut self, id: &PublicId) -> bool {
        self.sigs.remove(id).is_some()
    }

    /// Merges the other proof set into this one.
    pub fn merge(&mut self, other: Self) {
        self.sigs.extend(other.sigs);
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
    use super::super::NetworkEvent;
    use super::Proof;
    use crate::id::FullId;
    use safe_crypto;
    use unwrap::unwrap;

    #[test]
    fn confirm_proof() {
        unwrap!(safe_crypto::init());
        let full_id = FullId::new();
        let payload = NetworkEvent::OurMerge;
        let proof = unwrap!(Proof::new(&full_id, &payload));
        assert!(proof.validate_signature(&payload));
    }

    #[test]
    #[ignore] // Enable once sig checks are enabled
    fn bad_construction() {
        unwrap!(safe_crypto::init());
        let full_id = FullId::new();
        let pub_id = *full_id.public_id();
        let payload = NetworkEvent::OurMerge;
        let other_payload = NetworkEvent::Offline(pub_id);
        let proof = unwrap!(Proof::new(&full_id, &payload));
        assert!(!proof.validate_signature(&other_payload));
    }
}
