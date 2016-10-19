// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use rust_sodium::crypto::{box_, hash, sign};
use std::fmt::{self, Debug, Formatter};
use xor_name::XorName;

/// Network identity component containing name, and public and private keys.
#[derive(Clone)]
pub struct FullId {
    public_id: PublicId,
    private_encrypt_key: box_::SecretKey,
    private_sign_key: sign::SecretKey,
}

impl FullId {
    /// Construct a FullId with newly generated keys.
    pub fn new() -> FullId {
        let encrypt_keys = box_::gen_keypair();
        let sign_keys = sign::gen_keypair();
        FullId {
            public_id: PublicId::new(encrypt_keys.0, sign_keys.0),
            private_encrypt_key: encrypt_keys.1,
            private_sign_key: sign_keys.1,
        }
    }

    /// Construct with given keys, (Client requirement).
    pub fn with_keys(encrypt_keys: (box_::PublicKey, box_::SecretKey),
                     sign_keys: (sign::PublicKey, sign::SecretKey))
                     -> FullId {
        // TODO Verify that pub/priv key pairs match
        FullId {
            public_id: PublicId::new(encrypt_keys.0, sign_keys.0),
            private_encrypt_key: encrypt_keys.1,
            private_sign_key: sign_keys.1,
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

#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Copy, Clone, RustcEncodable, RustcDecodable)]
/// Network identity component containing name and public keys.
pub struct PublicId {
    public_encrypt_key: box_::PublicKey,
    public_sign_key: sign::PublicKey,
    name: XorName,
}

impl Debug for PublicId {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "PublicId(name: {})", self.name)
    }
}

impl PublicId {
    /// Return initial/relocated name.
    pub fn name(&self) -> &XorName {
        &self.name
    }

    /// Name field is initially same as original_name, this should be replaced by relocated name
    /// calculated by the nodes close to original_name by using this method
    pub fn set_name(&mut self, name: XorName) {
        self.name = name;
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
            name: XorName(hash::sha256::hash(&public_sign_key[..]).0),
        }
    }
}
