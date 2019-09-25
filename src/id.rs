// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    crypto::{encryption, signing},
    parsec,
    utils::RngCompat,
    xor_name::XorName,
};
use maidsafe_utilities::serialisation::{deserialise, serialise};
use serde::de::Deserialize;
use serde::{Deserializer, Serialize, Serializer};
use std::fmt::{self, Debug, Display, Formatter};
use std::{ops::RangeInclusive, rc::Rc};

/// Network identity component containing name, and public and private keys.
#[derive(Clone)]
pub struct FullId {
    public_id: PublicId,
    // Keep the secret keys in Rc to allow Clone while also preventing multiple copies to exist in
    // memory which might be unsafe.
    secret_keys: Rc<SecretKeys>,
}

impl FullId {
    /// Construct a `FullId` with newly generated keys.
    pub fn new() -> FullId {
        let secret_signing_key = gen_secret_signing_key();
        let public_signing_key = signing::PublicKey::from(&secret_signing_key);

        let secret_encryption_key = gen_secret_encryption_key();
        let public_encryption_key = secret_encryption_key.public_key();

        let public_id = PublicId::new(public_signing_key, public_encryption_key);

        FullId {
            public_id,
            secret_keys: Rc::new(SecretKeys {
                signing: secret_signing_key,
                encryption: secret_encryption_key,
            }),
        }
    }

    /// Construct a `FullId` whose name is in the interval [start, end] (both endpoints inclusive).
    /// FIXME(Fraser) - time limit this function? Document behaviour
    pub fn within_range(range: &RangeInclusive<XorName>) -> FullId {
        loop {
            let secret_signing_key = gen_secret_signing_key();
            let public_signing_key = signing::PublicKey::from(&secret_signing_key);
            let name = name_from_key(&public_signing_key);

            if range.contains(&name) {
                let secret_encryption_key = gen_secret_encryption_key();
                let public_encryption_key = secret_encryption_key.public_key();

                return Self {
                    public_id: PublicId::new(public_signing_key, public_encryption_key),
                    secret_keys: Rc::new(SecretKeys {
                        signing: secret_signing_key,
                        encryption: secret_encryption_key,
                    }),
                };
            }
        }
    }

    /// Returns public ID reference.
    pub fn public_id(&self) -> &PublicId {
        &self.public_id
    }

    /// Returns mutable reference to public ID.
    pub fn public_id_mut(&mut self) -> &mut PublicId {
        &mut self.public_id
    }

    /// Sign a message.
    pub fn sign(&self, message: &[u8]) -> signing::Signature {
        signing::sign(
            message,
            self.public_id.public_signing_key(),
            &self.secret_keys.signing,
        )
    }
}

impl parsec::SecretId for FullId {
    type PublicId = PublicId;

    fn public_id(&self) -> &Self::PublicId {
        self.public_id()
    }

    fn sign_detached(&self, data: &[u8]) -> <Self::PublicId as parsec::PublicId>::Signature {
        self.sign(data)
    }

    fn encrypt<M: AsRef<[u8]>>(&self, to: &Self::PublicId, plaintext: M) -> Option<Vec<u8>> {
        serialise(&encrypt(to.public_encryption_key(), plaintext)).ok()
    }

    fn decrypt(&self, _from: &Self::PublicId, ciphertext: &[u8]) -> Option<Vec<u8>> {
        let ciphertext: encryption::Ciphertext = deserialise(ciphertext).ok()?;
        self.secret_keys.encryption.decrypt(&ciphertext)
    }
}

impl Default for FullId {
    fn default() -> FullId {
        FullId::new()
    }
}

struct SecretKeys {
    signing: signing::SecretKey,
    encryption: encryption::SecretKey,
}

/// Network identity component containing name and public keys.
///
/// Note that the `name` member is omitted when serialising `PublicId` and is calculated from the
/// `public_signing_key` when deserialising.
#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Copy, Clone)]
pub struct PublicId {
    name: XorName,
    public_signing_key: signing::PublicKey,
    public_encryption_key: encryption::PublicKey,
}

impl Debug for PublicId {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "PublicId(name: {})", self.name())
    }
}

impl Display for PublicId {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl Serialize for PublicId {
    fn serialize<S: Serializer>(&self, serialiser: S) -> Result<S::Ok, S::Error> {
        (&self.public_signing_key, &self.public_encryption_key).serialize(serialiser)
    }
}

impl<'de> Deserialize<'de> for PublicId {
    fn deserialize<D: Deserializer<'de>>(deserialiser: D) -> Result<Self, D::Error> {
        let (public_signing_key, public_encryption_key) = Deserialize::deserialize(deserialiser)?;
        Ok(PublicId::new(public_signing_key, public_encryption_key))
    }
}

impl parsec::PublicId for PublicId {
    type Signature = signing::Signature;

    fn verify_signature(&self, signature: &Self::Signature, data: &[u8]) -> bool {
        self.verify(data, signature)
    }
}

impl PublicId {
    /// Returns initial/relocated name.
    pub fn name(&self) -> &XorName {
        &self.name
    }

    /// Verifies this id signed a message
    pub fn verify(&self, message: &[u8], sig: &signing::Signature) -> bool {
        self.public_signing_key.verify(message, sig).is_ok()
    }

    /// Returns public signing key.
    pub fn public_signing_key(&self) -> &signing::PublicKey {
        &self.public_signing_key
    }

    /// Returns public encryption key.
    pub fn public_encryption_key(&self) -> &encryption::PublicKey {
        &self.public_encryption_key
    }

    fn new(
        public_signing_key: signing::PublicKey,
        public_encryption_key: encryption::PublicKey,
    ) -> PublicId {
        PublicId {
            name: name_from_key(&public_signing_key),
            public_signing_key,
            public_encryption_key,
        }
    }
}

fn name_from_key(public_key: &signing::PublicKey) -> XorName {
    XorName(public_key.to_bytes())
}

#[cfg(not(any(test, feature = "mock_base")))]
fn gen_secret_signing_key() -> signing::SecretKey {
    use rand::OsRng;
    let rng = OsRng::new().expect("Cannot generate random data, unsafe to continue");
    signing::SecretKey::generate(&mut RngCompat(rng))
}

#[cfg(any(test, feature = "mock_base"))]
fn gen_secret_signing_key() -> signing::SecretKey {
    use maidsafe_utilities::SeededRng;
    let rng = SeededRng::thread_rng();
    signing::SecretKey::generate(&mut RngCompat(rng))
}

#[cfg(not(any(test, feature = "mock_base")))]
fn gen_secret_encryption_key() -> encryption::SecretKey {
    use rand::OsRng;
    use rand_crypto::Rng;

    let rng = OsRng::new().expect("Cannot generate random data, unsafe to continue");
    RngCompat(rng).gen()
}

#[cfg(any(test, feature = "mock_base"))]
fn gen_secret_encryption_key() -> encryption::SecretKey {
    use maidsafe_utilities::SeededRng;
    use rand_crypto::Rng;

    let rng = SeededRng::thread_rng();
    RngCompat(rng).gen()
}

#[cfg(not(any(test, feature = "mock_base")))]
fn encrypt<M: AsRef<[u8]>>(
    public_key: &encryption::PublicKey,
    plaintext: M,
) -> encryption::Ciphertext {
    // Note: this uses OsRng under the hood.
    public_key.encrypt(plaintext)
}

#[cfg(any(test, feature = "mock_base"))]
fn encrypt<M: AsRef<[u8]>>(
    public_key: &encryption::PublicKey,
    plaintext: M,
) -> encryption::Ciphertext {
    use maidsafe_utilities::SeededRng;

    let mut rng = RngCompat(SeededRng::thread_rng());
    public_key.encrypt_with_rng(&mut rng, plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use unwrap::unwrap;

    #[test]
    fn serialisation() {
        let full_id = FullId::new();
        let serialised = unwrap!(serialise(full_id.public_id()));
        let parsed = unwrap!(deserialise(&serialised));
        assert_eq!(*full_id.public_id(), parsed);
    }
}
