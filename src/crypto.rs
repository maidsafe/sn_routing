// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Cryptographic primitives.

use ed25519_dalek::ExpandedSecretKey;
pub use ed25519_dalek::{
    Keypair, PublicKey, SecretKey, Signature, Verifier, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH,
};
use rand::{CryptoRng, Rng};
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

pub fn name(public_key: &PublicKey) -> XorName {
    XorName(public_key.to_bytes())
}

/// Construct a `Keypair` whose name is in the interval [start, end] (both endpoints inclusive).
pub fn keypair_within_range<T: Sized>(rng: &mut T, range: &RangeInclusive<XorName>) -> Keypair
where
    T: CryptoRng + Rng,
{
    loop {
        let keypair = Keypair::generate(rng);
        if range.contains(&name(&keypair.public)) {
            return keypair;
        }
    }
}
