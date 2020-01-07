// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Mock cryptographic primitives.

pub type Digest256 = [u8; 32];
// Note: using the real thing here as it seems to be already fast enough for tests.
pub use tiny_keccak::sha3_256;

pub mod signing {
    pub use ed25519_dalek::SIGNATURE_LENGTH;
    use ed25519_dalek::{PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH};
    use rand_crypto::{CryptoRng, Rng};
    use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
    use std::{
        cmp::Ordering,
        collections::hash_map::DefaultHasher,
        fmt::{self, Debug, Display, Formatter},
        hash::{Hash, Hasher},
    };

    #[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
    pub struct PublicKey([u8; PUBLIC_KEY_LENGTH]);

    impl PublicKey {
        pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LENGTH] {
            self.0
        }

        pub fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), SignatureError> {
            let mut hasher = DefaultHasher::new();
            hasher.write(msg);
            hasher.write(&self.0);
            let hash = hasher.finish().to_le_bytes();

            if signature.0[..8] == hash {
                Ok(())
            } else {
                Err(SignatureError)
            }
        }
    }

    impl<'a> From<&'a SecretKey> for PublicKey {
        fn from(sk: &'a SecretKey) -> Self {
            Self(sk.0)
        }
    }

    pub struct SecretKey([u8; SECRET_KEY_LENGTH]);

    impl SecretKey {
        pub fn generate<T: CryptoRng + Rng>(rng: &mut T) -> Self {
            Self(rng.gen())
        }
    }

    #[derive(Copy, Clone)]
    pub struct Signature([u8; SIGNATURE_LENGTH]);

    impl Signature {
        pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
            if bytes.len() < SIGNATURE_LENGTH {
                Err(SignatureError)
            } else {
                let mut signature = Self([0; SIGNATURE_LENGTH]);
                signature.0.copy_from_slice(bytes);
                Ok(signature)
            }
        }
    }

    impl PartialEq for Signature {
        fn eq(&self, other: &Self) -> bool {
            self.0[..].eq(&other.0[..])
        }
    }

    impl Eq for Signature {}

    impl PartialOrd for Signature {
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            Some(self.cmp(other))
        }
    }

    impl Ord for Signature {
        fn cmp(&self, other: &Self) -> Ordering {
            self.0[..].cmp(&other.0[..])
        }
    }

    impl Hash for Signature {
        fn hash<H: Hasher>(&self, state: &mut H) {
            self.0[..].hash(state)
        }
    }

    impl Debug for Signature {
        fn fmt(&self, f: &mut Formatter) -> fmt::Result {
            write!(f, "{:?}", &self.0[..])
        }
    }

    impl Serialize for Signature {
        fn serialize<S: Serializer>(&self, serialiser: S) -> Result<S::Ok, S::Error> {
            self.0[..].serialize(serialiser)
        }
    }

    impl<'de> Deserialize<'de> for Signature {
        fn deserialize<D: Deserializer<'de>>(deserialiser: D) -> Result<Self, D::Error> {
            let bytes: &[u8] = Deserialize::deserialize(deserialiser)?;
            Self::from_bytes(bytes).map_err(de::Error::custom)
        }
    }

    #[derive(Debug)]
    pub struct SignatureError;

    impl Display for SignatureError {
        fn fmt(&self, f: &mut Formatter) -> fmt::Result {
            write!(f, "SignatureError")
        }
    }

    pub fn sign(msg: &[u8], _public_key: &PublicKey, secret_key: &SecretKey) -> Signature {
        let mut hasher = DefaultHasher::new();
        hasher.write(msg);
        hasher.write(&secret_key.0);
        let hash = hasher.finish().to_le_bytes();

        let mut signature = Signature([0; SIGNATURE_LENGTH]);
        signature.0[..8].copy_from_slice(&hash[..]);
        signature
    }
}

pub mod encryption {
    use rand_crypto::{
        distributions::{Distribution, Standard},
        Rng,
    };

    const KEY_LENGTH: usize = 32;

    #[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
    pub struct PublicKey([u8; KEY_LENGTH]);

    impl PublicKey {
        pub fn encrypt<M: AsRef<[u8]>>(&self, msg: M) -> Ciphertext {
            let mut ciphertext = msg.as_ref().to_vec();
            ciphertext.extend_from_slice(&self.0);

            Ciphertext(ciphertext)
        }

        pub fn encrypt_with_rng<R: Rng, M: AsRef<[u8]>>(&self, _rng: &mut R, msg: M) -> Ciphertext {
            self.encrypt(msg)
        }
    }

    pub struct SecretKey([u8; KEY_LENGTH]);

    impl SecretKey {
        pub fn public_key(&self) -> PublicKey {
            PublicKey(self.0)
        }

        pub fn decrypt(&self, ciphertext: &Ciphertext) -> Option<Vec<u8>> {
            let offset = ciphertext.0.len() - self.0.len();

            if ciphertext.0[offset..] == self.0 {
                Some(ciphertext.0[..offset].to_vec())
            } else {
                None
            }
        }
    }

    impl Distribution<SecretKey> for Standard {
        fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> SecretKey {
            SecretKey(rng.gen())
        }
    }

    #[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Serialize, Deserialize, Debug)]
    pub struct Ciphertext(Vec<u8>);

    impl Ciphertext {
        pub fn verify(&self) -> bool {
            true
        }
    }
}
