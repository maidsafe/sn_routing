// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Cryptographic primitives.

pub use ed25519_dalek::{
    Keypair, PublicKey, SecretKey, Signature, Verifier, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH,
};

use ed25519_dalek::ExpandedSecretKey;
use std::ops::RangeInclusive;
use xor_name::XorName;

/// SHA3-256 hash digest.
pub type Digest256 = [u8; 32];

/// SHA3-256 hash function.
pub fn sha3_256(input: &[u8]) -> Digest256 {
    use tiny_keccak::{Hasher, Sha3};

    let mut hasher = Sha3::v256();
    let mut output = Digest256::default();
    hasher.update(input);
    hasher.finalize(&mut output);
    output
}

pub fn sign(msg: &[u8], keypair: &Keypair) -> Signature {
    let expanded_secret_key = ExpandedSecretKey::from(&keypair.secret);
    expanded_secret_key.sign(msg, &keypair.public)
}

pub fn pub_key(name: &XorName) -> Result<PublicKey, ed25519_dalek::SignatureError> {
    PublicKey::from_bytes(&name.0)
}

pub fn name(public_key: &sn_data_types::PublicKey) -> XorName {
    XorName::from(*public_key)
}

/// Construct a random `Keypair`
pub fn gen_keypair() -> Keypair {
    Keypair::generate(&mut rand::thread_rng())
}

/// Construct a `Keypair` whose name is in the interval [start, end] (both endpoints inclusive).
pub fn gen_keypair_within_range(range: &RangeInclusive<XorName>) -> Keypair {
    let mut rng = rand::thread_rng();

    loop {
        let keypair = Keypair::generate(&mut rng);
        if range.contains(&name(&sn_data_types::PublicKey::Ed25519(keypair.public))) {
            return keypair;
        }
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    use super::*;
    use ed25519_dalek::SECRET_KEY_LENGTH;
    use proptest::prelude::*;

    pub(crate) fn arbitrary_keypair() -> impl Strategy<Value = Keypair> {
        any::<[u8; SECRET_KEY_LENGTH]>().prop_map(|bytes| {
            // OK to unwrap because `from_bytes` returns error only if the input slice has incorrect
            // length. But here we only generate arrays of size `SECRET_KEY_LENGTH` which is the
            // correct one.
            let secret = SecretKey::from_bytes(&bytes[..]).unwrap();
            let public = PublicKey::from(&secret);

            Keypair { public, secret }
        })
    }
}
