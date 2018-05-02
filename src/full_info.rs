// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use public_info::PublicInfo;
use rust_sodium::crypto::{box_, sign};
use xor_name::XorName;

/// A container for a peer's cryptographic keys, and in the case of a node, its age too. The public
/// signing key defines the peer's name on the network.
#[derive(Clone)]
pub struct FullInfo {
    public_info: PublicInfo,
    secret_encrypt_key: box_::SecretKey,
    secret_sign_key: sign::SecretKey,
}

impl FullInfo {
    /// Construct a `FullInfo` for a client with newly generated keys.
    pub fn client_new() -> FullInfo {
        Self::new(None)
    }

    /// Construct a `FullInfo` for a node with newly generated keys.
    pub fn node_new(age: u8) -> FullInfo {
        Self::new(Some(age))
    }

    /// Construct a `FullInfo` for a client with given keys.
    pub fn with_keys(
        encrypt_keys: (box_::PublicKey, box_::SecretKey),
        sign_keys: (sign::PublicKey, sign::SecretKey),
    ) -> FullInfo {
        FullInfo {
            public_info: PublicInfo::Client {
                sign_key: sign_keys.0,
                encrypt_key: encrypt_keys.0,
            },
            secret_encrypt_key: encrypt_keys.1,
            secret_sign_key: sign_keys.1,
        }
    }

    /// Construct a `FullInfo` for a node whose name is in the interval [start, end] (both endpoints
    /// inclusive).
    pub fn within_range(age: u8, start: &XorName, end: &XorName) -> FullInfo {
        let (public_encrypt_key, secret_encrypt_key) = box_::gen_keypair();
        let mut sign_keys = sign::gen_keypair();
        loop {
            let name = XorName((sign_keys.0).0);
            if name >= *start && name <= *end {
                return FullInfo {
                    public_info: PublicInfo::Node {
                        age,
                        sign_key: sign_keys.0,
                        encrypt_key: public_encrypt_key,
                    },
                    secret_encrypt_key,
                    secret_sign_key: sign_keys.1,
                };
            }
            sign_keys = sign::gen_keypair();
        }
    }

    /// Returns public ID reference.
    pub fn public_info(&self) -> &PublicInfo {
        &self.public_info
    }

    /// Secret encryption key.
    pub fn secret_encrypt_key(&self) -> &box_::SecretKey {
        &self.secret_encrypt_key
    }

    /// Secret signing key.
    pub fn secret_sign_key(&self) -> &sign::SecretKey {
        &self.secret_sign_key
    }

    /// Update the age of the node
    #[cfg(test)]
    pub fn set_age(&mut self, new_age: u8) {
        self.public_info.set_age(new_age)
    }

    fn new(node_age: Option<u8>) -> FullInfo {
        let (public_encrypt_key, secret_encrypt_key) = box_::gen_keypair();
        let (public_sign_key, secret_sign_key) = sign::gen_keypair();
        let public_info = if let Some(age) = node_age {
            PublicInfo::Node {
                age,
                sign_key: public_sign_key,
                encrypt_key: public_encrypt_key,
            }
        } else {
            PublicInfo::Client {
                sign_key: public_sign_key,
                encrypt_key: public_encrypt_key,
            }
        };
        FullInfo {
            public_info,
            secret_encrypt_key,
            secret_sign_key,
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use maidsafe_utilities::{SeededRng, serialisation};
    use rust_sodium;

    #[test]
    fn serialisation() {
        let mut rng = SeededRng::thread_rng();
        unwrap!(rust_sodium::init_with_rng(&mut rng));

        let full_info = FullInfo::node_new(1u8);
        let serialised = unwrap!(serialisation::serialise(full_info.public_info()));
        let parsed = unwrap!(serialisation::deserialise(&serialised));
        assert_eq!(*full_info.public_info(), parsed);
    }
}
