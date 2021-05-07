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
use xor_name::{XorName, XOR_NAME_LEN};

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

#[cfg(test)]
/// Construct a random `XorName` whose last byte represents the targeted age.
pub fn gen_name_with_age(age: u8) -> XorName {
    loop {
        let name = XorName::random();
        if age == name[XOR_NAME_LEN - 1] {
            return name;
        }
    }
}

/// Construct a `Keypair` whose name is in the interval [start, end] (both endpoints inclusive).
/// And the last byte equals to the targeted age.
pub fn gen_keypair(range: &RangeInclusive<XorName>, age: u8) -> Keypair {
    let mut rng = rand::thread_rng();

    loop {
        let keypair = Keypair::generate(&mut rng);
        let new_name = XorName::from(sn_data_types::PublicKey::Ed25519(keypair.public));
        if range.contains(&new_name) && age == new_name[XOR_NAME_LEN - 1] {
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

            Keypair { secret, public }
        })
    }
}
