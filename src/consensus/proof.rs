// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use std::borrow::Borrow;
use xor_name::{Prefix, XorName};

/// Proof that a quorum of the section elders has agreed on something.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub struct Proof {
    pub public_key: bls::PublicKey,
    pub signature: bls::Signature,
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
    pub(crate) fn verify(&self, signed_bytes: &[u8]) -> bool {
        self.public_key_set
            .public_key_share(self.index)
            .verify(&self.signature_share, signed_bytes)
    }
}

/// A value together with the proof that it was agreed on by the quorum of the section elders.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub struct Proven<T> {
    pub value: T,
    pub proof: Proof,
}

impl<T> Proven<T> {
    pub fn new(value: T, proof: Proof) -> Self {
        Self { value, proof }
    }
}

impl<T> Borrow<Prefix<XorName>> for Proven<T>
where
    T: Borrow<Prefix<XorName>>,
{
    fn borrow(&self) -> &Prefix<XorName> {
        self.value.borrow()
    }
}
