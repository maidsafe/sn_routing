// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use crust::Uid;
use rust_sodium::crypto::{box_, sign};
use serde::{Deserializer, Serialize, Serializer};
use serde::de::Deserialize;
use std::fmt::{self, Debug, Display, Formatter};
use tiny_keccak::sha3_256;
use xor_name::XorName;

/// Network identity component containing name, and public and private keys.
#[derive(Clone)]
pub struct FullId {
    public_id: PublicId,
    private_encrypt_key: box_::SecretKey,
    private_sign_key: sign::SecretKey,
}

impl FullId {
    /// Construct a `FullId` with newly generated keys.
    pub fn new() -> FullId {
        let encrypt_keys = box_::gen_keypair();
        let sign_keys = sign::gen_keypair();
        FullId {
            public_id: PublicId::new(encrypt_keys.0, sign_keys.0),
            private_encrypt_key: encrypt_keys.1,
            private_sign_key: sign_keys.1,
        }
    }

    /// Construct with given keys (client requirement).
    pub fn with_keys(
        encrypt_keys: (box_::PublicKey, box_::SecretKey),
        sign_keys: (sign::PublicKey, sign::SecretKey),
    ) -> FullId {
        // TODO Verify that pub/priv key pairs match
        FullId {
            public_id: PublicId::new(encrypt_keys.0, sign_keys.0),
            private_encrypt_key: encrypt_keys.1,
            private_sign_key: sign_keys.1,
        }
    }

    /// Construct a `FullId` whose name is in the interval [start, end] (both endpoints inclusive).
    /// FIXME(Fraser) - time limit this function? Document behaviour
    pub fn within_range(start: &XorName, end: &XorName) -> FullId {
        let mut sign_keys = sign::gen_keypair();
        loop {
            let name = PublicId::name_from_key(&sign_keys.0);
            if name >= *start && name <= *end {
                let encrypt_keys = box_::gen_keypair();
                let full_id = FullId::with_keys(encrypt_keys, sign_keys);
                return full_id;
            }
            sign_keys = sign::gen_keypair();
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

    /// Secret signing key.
    pub fn signing_private_key(&self) -> &sign::SecretKey {
        &self.private_sign_key
    }

    /// Private encryption key.
    pub fn encrypting_private_key(&self) -> &box_::SecretKey {
        &self.private_encrypt_key
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
    name: XorName,
    public_sign_key: sign::PublicKey,
    public_encrypt_key: box_::PublicKey,
}

impl Uid for PublicId {}

impl Debug for PublicId {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "PublicId(name: {})", self.name)
    }
}

impl Display for PublicId {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl Serialize for PublicId {
    fn serialize<S: Serializer>(&self, serialiser: S) -> Result<S::Ok, S::Error> {
        (&self.public_encrypt_key, &self.public_sign_key).serialize(serialiser)
    }
}

impl<'de> Deserialize<'de> for PublicId {
    fn deserialize<D: Deserializer<'de>>(deserialiser: D) -> Result<Self, D::Error> {
        let (public_encrypt_key, public_sign_key): (box_::PublicKey, sign::PublicKey) =
            Deserialize::deserialize(deserialiser)?;
        Ok(PublicId::new(public_encrypt_key, public_sign_key))
    }
}

impl PublicId {
    /// Return initial/relocated name.
    pub fn name(&self) -> &XorName {
        &self.name
    }

    /// Return public signing key.
    pub fn encrypting_public_key(&self) -> &box_::PublicKey {
        &self.public_encrypt_key
    }

    /// Return public signing key.
    pub fn signing_public_key(&self) -> &sign::PublicKey {
        &self.public_sign_key
    }

    fn new(public_encrypt_key: box_::PublicKey, public_sign_key: sign::PublicKey) -> PublicId {
        PublicId {
            public_encrypt_key: public_encrypt_key,
            public_sign_key: public_sign_key,
            name: Self::name_from_key(&public_sign_key),
        }
    }

    fn name_from_key(public_sign_key: &sign::PublicKey) -> XorName {
        XorName(sha3_256(&public_sign_key[..]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maidsafe_utilities::{SeededRng, serialisation};
    use rust_sodium;

    /// Confirm `PublicId` `Ord` trait favours name over sign or encryption keys.
    #[test]
    fn public_id_order() {
        let mut rng = SeededRng::thread_rng();
        unwrap!(rust_sodium::init_with_rng(&mut rng));

        let pub_id_1 = *FullId::new().public_id();
        let pub_id_2;
        loop {
            let temp_pub_id = *FullId::new().public_id();
            if temp_pub_id.name > pub_id_1.name &&
                temp_pub_id.public_sign_key < pub_id_1.public_sign_key &&
                temp_pub_id.public_encrypt_key < pub_id_1.public_encrypt_key
            {
                pub_id_2 = temp_pub_id;
                break;
            }
        }
        assert!(pub_id_1 < pub_id_2);
    }

    #[test]
    fn serialisation() {
        let mut rng = SeededRng::thread_rng();
        unwrap!(rust_sodium::init_with_rng(&mut rng));

        let full_id = FullId::new();
        let serialised = unwrap!(serialisation::serialise(full_id.public_id()));
        let parsed = unwrap!(serialisation::deserialise(&serialised));
        assert_eq!(*full_id.public_id(), parsed);
    }
}
