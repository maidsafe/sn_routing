// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::SectionInfo;
use crate::error::Result;
use crate::id::PublicId;
use itertools::Itertools;
use maidsafe_utilities::serialisation;
use safe_crypto::{SecretSignKey, Signature};
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
    pub fn new<S: Serialize>(pub_id: PublicId, key: &SecretSignKey, payload: &S) -> Result<Self> {
        let signature = key.sign_detached(&serialisation::serialise(&payload)?[..]);
        Ok(Proof {
            pub_id,
            sig: signature,
        })
    }

    /// Validates `payload` against this `Proof`'s `key` and `sig`.
    pub fn validate_signature<S: Serialize>(&self, payload: &S) -> bool {
        match serialisation::serialise(payload) {
            Ok(data) => self
                .pub_id
                .signing_public_key()
                .verify_detached(&self.sig, &data[..]),
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
            |(id, sig): (&PublicId, &Signature)| id.signing_public_key().verify_detached(sig, data);
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

/// An element in a chain of sections, where each item's authenticity is proved by the next one.
///
/// A section proves the authenticity of another one if it's either its successor (i.e. the hash
/// matches), or if there is a quorum of signatures.
#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Hash, Serialize, Deserialize, Debug)]
pub struct ProvingSection {
    /// The section proving the previous item's authenticity.
    pub sec_info: SectionInfo,
    /// If the section is the previous one's successor, this is `None`, otherwise a quorum.
    pub signatures: Option<ProofSet>,
}

impl ProvingSection {
    /// Creates a proving section for the given section's successor.
    pub fn successor(sec_info: &SectionInfo) -> ProvingSection {
        ProvingSection {
            sec_info: sec_info.clone(),
            signatures: None,
        }
    }

    /// Creates a proving section with the given section and proofs.
    pub fn signatures(sec_info: &SectionInfo, sigs: &ProofSet) -> ProvingSection {
        ProvingSection {
            sec_info: sec_info.clone(),
            signatures: Some(sigs.clone()),
        }
    }

    /// Returns `true` if `self` proves the authenticity of `sec_info`.
    pub fn validate(&self, sec_info: &SectionInfo) -> bool {
        match self.signatures {
            None => self.sec_info.is_successor_of(sec_info),
            Some(ref proofs) => self.sec_info.proves(sec_info, proofs),
        }
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
        let pub_id = *full_id.public_id();
        let payload = NetworkEvent::OurMerge;
        let proof = unwrap!(Proof::new(pub_id, full_id.signing_private_key(), &payload));
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
        let proof = unwrap!(Proof::new(pub_id, full_id.signing_private_key(), &payload));
        assert!(!proof.validate_signature(&other_payload));
    }
}
