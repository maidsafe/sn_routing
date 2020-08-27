// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Cryptographic primitives.

use ed25519_dalek::ExpandedSecretKey;
pub use ed25519_dalek::{PublicKey, SecretKey, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};
use std::{
    cmp::Ordering,
    fmt::{self, Debug, Formatter},
    hash::{Hash, Hasher},
};

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

// Wrapper for `ed25519_dalek::Signature` that adds `Hash` and `Ord` impls.
#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub struct Signature(pub ed25519_dalek::Signature);

#[allow(clippy::derive_hash_xor_eq)]
impl Hash for Signature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.to_bytes().hash(state);
    }
}

impl Ord for Signature {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.to_bytes().cmp(&other.0.to_bytes())
    }
}

impl PartialOrd for Signature {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Debug for Signature {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

pub fn sign(msg: &[u8], public_key: &PublicKey, secret_key: &SecretKey) -> Signature {
    let expanded_secret_key = ExpandedSecretKey::from(secret_key);
    Signature(expanded_secret_key.sign(msg, public_key))
}

#[cfg(test)]
mod test {
    use super::*;
    use ed25519_dalek::{Keypair, Verifier};
    use rand::rngs::OsRng;

    #[test]
    fn check_sig_validate() {
        let mut csprng = OsRng;
        let keypair = Keypair::generate(&mut csprng);
        let pub_key = (&keypair.secret).into();
        let msg: &[u8] = b"test message";
        let sig = sign(msg, &pub_key, &keypair.secret);
        let sig2 = sign(msg, &pub_key, &keypair.secret);
        assert_eq!(sig, sig2);
        assert!(pub_key.verify(msg, &sig.0).is_ok());
        assert!(!(sig < sig2));
        assert!(!(sig > sig2));
    }
    #[test]
    fn check_pub_key_is_32_bytes() {
        let mut csprng = OsRng;
        let keypair = Keypair::generate(&mut csprng);
        let pub_key: PublicKey = (&keypair.secret).into();
        assert!(pub_key.to_bytes().len() == 32)
    }

    #[test]
    fn ensure_same_data_hashes_same() {
        let data: &[u8] = b"Some data";
        assert!(sha3_256(data) == sha3_256(data));
    }

    #[test]
    fn ensure_different_data_hashes_different() {
        let data: &[u8] = b"Some data";
        let not_data: &[u8] = b"Some data.";
        assert!(sha3_256(data) != sha3_256(not_data));
    }
}
