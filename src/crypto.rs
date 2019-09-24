// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Cryptographic primitives.

/// SHA3-256 hash function.
pub use tiny_keccak::sha3_256 as hash;

/// SHA3-256 hash digest.
pub type Digest256 = [u8; 32];

/// Signing and verification.
pub mod signing {
    use ed25519_dalek::ExpandedSecretKey;
    pub use ed25519_dalek::{PublicKey, SecretKey, Signature, SIGNATURE_LENGTH};

    pub fn sign(msg: &[u8], public_key: &PublicKey, secret_key: &SecretKey) -> Signature {
        let expanded_secret_key = ExpandedSecretKey::from(secret_key);
        expanded_secret_key.sign(msg, public_key)
    }
}
