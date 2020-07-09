// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::section::SectionProofChain;
use serde::Serialize;
use std::{
    borrow::Borrow,
    fmt::{self, Debug, Formatter},
};
use xor_name::Prefix;

/// Proof that a quorum of the section elders has agreed on something.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub struct Proof {
    /// The BLS public key.
    pub public_key: bls::PublicKey,
    /// The BLS signature corresponding to the public key.
    pub signature: bls::Signature,
}

impl Proof {
    /// Verifies this proof against the payload.
    pub fn verify(&self, payload: &[u8]) -> bool {
        self.public_key.verify(&self.signature, payload)
    }
}

/// Single share of `Proof`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ProofShare {
    /// BLS public key set.
    pub public_key_set: bls::PublicKeySet,
    /// Index of the node that created this proof share.
    pub index: usize,
    /// BLS signature share corresponding to the `index`-th public key share of the public key set.
    pub signature_share: bls::SignatureShare,
}

impl ProofShare {
    /// Creates new proof share.
    pub fn new(
        public_key_set: bls::PublicKeySet,
        index: usize,
        secret_key_share: &bls::SecretKeyShare,
        payload: &[u8],
    ) -> Self {
        Self {
            public_key_set,
            index,
            signature_share: secret_key_share.sign(payload),
        }
    }

    /// Verifies this proof share against the payload.
    pub fn verify(&self, payload: &[u8]) -> bool {
        self.public_key_set
            .public_key_share(self.index)
            .verify(&self.signature_share, payload)
    }
}

impl Debug for ProofShare {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "ProofShare {{ public_key: {:?}, index: {}, .. }}",
            self.public_key_set.public_key(),
            self.index
        )
    }
}

/// A value together with the proof that it was agreed on by the quorum of the section elders.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub struct Proven<T: Serialize> {
    pub value: T,
    pub proof: Proof,
}

impl<T: Serialize> Proven<T> {
    pub fn new(value: T, proof: Proof) -> Self {
        Self { value, proof }
    }

    pub fn verify(&self, history: &SectionProofChain) -> bool {
        if let Ok(bytes) = bincode::serialize(&self.value) {
            history.has_key(&self.proof.public_key) && self.proof.verify(&bytes)
        } else {
            false
        }
    }
}

impl<T> Borrow<Prefix> for Proven<T>
where
    T: Borrow<Prefix> + Serialize,
{
    fn borrow(&self) -> &Prefix {
        self.value.borrow()
    }
}
