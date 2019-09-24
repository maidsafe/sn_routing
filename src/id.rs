// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    crypto::{
        self,
        signing::{PublicKey, SecretKey, Signature},
    },
    parsec,
    utils::RngCompat,
    xor_name::XorName,
};
use serde::de::Deserialize;
use serde::{Deserializer, Serialize, Serializer};
use std::fmt::{self, Debug, Display, Formatter};
use std::{ops::RangeInclusive, rc::Rc};

/// Network identity component containing name, and public and private keys.
#[derive(Clone)]
pub struct FullId {
    public_id: PublicId,
    // Keep the secret key in Rc to allow Clone while also preventing multiple copies to exist in
    // memory which might be unsafe.
    secret_key: Rc<SecretKey>,
}

impl FullId {
    /// Construct a `FullId` with newly generated keys.
    pub fn new() -> FullId {
        let secret_key = gen_secret_key();
        let public_key = PublicKey::from(&secret_key);
        let public_id = PublicId::new(0, public_key);

        FullId {
            public_id,
            secret_key: Rc::new(secret_key),
        }
    }

    /// Construct a `FullId` whose name is in the interval [start, end] (both endpoints inclusive).
    /// FIXME(Fraser) - time limit this function? Document behaviour
    pub fn within_range(range: &RangeInclusive<XorName>) -> FullId {
        loop {
            let secret_key = gen_secret_key();
            let public_key = PublicKey::from(&secret_key);
            let name = name_from_key(&public_key);

            if range.contains(&name) {
                return Self {
                    public_id: PublicId::new(0, public_key),
                    secret_key: Rc::new(secret_key),
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
    pub fn sign(&self, message: &[u8]) -> Signature {
        crypto::signing::sign(message, self.public_id.public_key(), &self.secret_key)
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

    fn encrypt<M: AsRef<[u8]>>(&self, _to: &Self::PublicId, _msg: M) -> Option<Vec<u8>> {
        unimplemented!()
    }

    fn decrypt(&self, _from: &Self::PublicId, _ct: &[u8]) -> Option<Vec<u8>> {
        unimplemented!()
    }
}

impl Default for FullId {
    fn default() -> FullId {
        FullId::new()
    }
}

/// Network identity component containing name and public keys.
///
/// Note that the `name` member is omitted when serialising `PublicId` and is calculated from the
/// `public_sign_key` when deserialising.
#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Copy, Clone)]
pub struct PublicId {
    age: u8,
    name: XorName,
    public_key: PublicKey,
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
        (self.age, &self.public_key).serialize(serialiser)
    }
}

impl<'de> Deserialize<'de> for PublicId {
    fn deserialize<D: Deserializer<'de>>(deserialiser: D) -> Result<Self, D::Error> {
        let (age, public_key): (u8, PublicKey) = Deserialize::deserialize(deserialiser)?;
        Ok(PublicId::new(age, public_key))
    }
}

impl parsec::PublicId for PublicId {
    type Signature = Signature;
    fn verify_signature(&self, signature: &Self::Signature, data: &[u8]) -> bool {
        self.verify(data, signature)
    }
}

impl PublicId {
    /// Return age.
    pub fn age(&self) -> u8 {
        self.age
    }

    /// Return initial/relocated name.
    pub fn name(&self) -> &XorName {
        &self.name
    }

    /// Verify this id signed a message
    pub fn verify(&self, message: &[u8], sig: &Signature) -> bool {
        self.public_key.verify(message, sig).is_ok()
    }

    /// Return public signing key.
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    fn new(age: u8, public_key: PublicKey) -> PublicId {
        PublicId {
            age,
            name: name_from_key(&public_key),
            public_key,
        }
    }
}

fn name_from_key(public_key: &PublicKey) -> XorName {
    XorName(public_key.to_bytes())
}

#[cfg(not(any(test, feature = "mock_base")))]
fn gen_secret_key() -> SecretKey {
    use rand::OsRng;
    let rng = OsRng::new().expect("Cannot generate random data, unsafe to continue");
    SecretKey::generate(&mut RngCompat(rng))
}

#[cfg(any(test, feature = "mock_base"))]
fn gen_secret_key() -> SecretKey {
    use maidsafe_utilities::SeededRng;
    let rng = SeededRng::thread_rng();
    SecretKey::generate(&mut RngCompat(rng))
}

#[cfg(test)]
mod tests {
    use super::*;
    use maidsafe_utilities::serialisation;
    use safe_crypto;
    use unwrap::unwrap;

    #[test]
    fn serialisation() {
        unwrap!(safe_crypto::init());

        let full_id = FullId::new();
        let serialised = unwrap!(serialisation::serialise(full_id.public_id()));
        let parsed = unwrap!(serialisation::deserialise(&serialised));
        assert_eq!(*full_id.public_id(), parsed);
    }
}
