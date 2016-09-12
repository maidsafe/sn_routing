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

use maidsafe_utilities::serialisation::serialise;
use rust_sodium::crypto::sign::{self, PublicKey, SecretKey, Signature};
use std::collections::BTreeSet;
use xor_name::XorName;
use data::DataIdentifier;
use error::RoutingError;
use priv_appendable_data::PrivAppendedData;

/// The type of access filter for appendable data.
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, RustcDecodable, RustcEncodable)]
pub enum Filter {
    /// Everyone except the listed keys are allowed to append data.
    BlackList(BTreeSet<PublicKey>),
    /// Only the listed keys are allowed to append data.
    WhiteList(BTreeSet<PublicKey>),
}

impl Filter {
    /// Returns a filter black listing the given keys.
    pub fn black_list<T: IntoIterator<Item = PublicKey>>(keys: T) -> Filter {
        Filter::BlackList(keys.into_iter().collect())
    }

    /// Returns a filter white listing the given keys.
    pub fn white_list<T: IntoIterator<Item = PublicKey>>(keys: T) -> Filter {
        Filter::WhiteList(keys.into_iter().collect())
    }
}

/// An appended data item, pointing to another data chunk in the network.
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, RustcDecodable, RustcEncodable, Debug)]
pub struct AppendedData {
    /// A pointer to the chunk with the actual data.
    pub pointer: DataIdentifier,
    /// The public key of the signer.
    pub sign_key: PublicKey,
    /// The signature of the above fields.
    pub signature: Signature,
}

impl AppendedData {
    /// Returns a new signed appended data.
    pub fn new(pointer: DataIdentifier,
               pub_key: PublicKey,
               secret_key: &SecretKey)
               -> Result<AppendedData, RoutingError> {
        let data_to_sign = try!(serialise(&(&pointer, &pub_key)));
        let signature = sign::sign_detached(&data_to_sign, secret_key);
        Ok(AppendedData {
            pointer: pointer,
            sign_key: pub_key,
            signature: signature,
        })
    }

    /// Returns `true` if the signature matches the data.
    pub fn verify_signature(&self) -> bool {
        let data_to_sign = match serialise(&(&self.pointer, &self.sign_key)) {
            Err(_) => return false,
            Ok(data) => data,
        };
        sign::verify_detached(&self.signature, &data_to_sign, &self.sign_key)
    }
}

/// An `AppendedData` item, together with the identifier of the data to append it to.
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, RustcDecodable, RustcEncodable, Debug)]
pub enum AppendWrapper {
    /// A wrapper for public appendable data.
    Pub {
        /// The name of the data chunk to add to.
        append_to: XorName,
        /// The item to add to the chunk.
        data: AppendedData,
        /// The current version of the chunk.
        version: u64,
    },
    /// A wrapper for private appendable data.
    Priv {
        /// The name of the data chunk to add to.
        append_to: XorName,
        /// The item to add to the chunk.
        data: PrivAppendedData,
        /// The signer's public_key.
        sign_key: PublicKey,
        /// The current version of the chunk.
        version: u64,
        /// All the above fields
        signature: Signature,
    },
}

impl AppendWrapper {
    /// Returns a new append wrapper for public data.
    pub fn new_pub(append_to: XorName, data: AppendedData, version: u64) -> Self {
        AppendWrapper::Pub {
            append_to: append_to,
            data: data,
            version: version,
        }
    }

    /// Returns a new, signed append wrapper for private data.
    pub fn new_priv(append_to: XorName,
                    data: PrivAppendedData,
                    sign_pair: (&PublicKey, &SecretKey),
                    version: u64)
                    -> Result<AppendWrapper, RoutingError> {
        let data_to_sign = try!(serialise(&(&append_to, &data, &sign_pair.0, &version)));
        let signature = sign::sign_detached(&data_to_sign, sign_pair.1);
        Ok(AppendWrapper::Priv {
            append_to: append_to,
            data: data,
            sign_key: *sign_pair.0,
            version: version,
            signature: signature,
        })
    }

    /// Returns the identifier of the data to append to.
    pub fn identifier(&self) -> DataIdentifier {
        match *self {
            AppendWrapper::Priv { append_to, .. } => DataIdentifier::PrivAppendable(append_to),
            AppendWrapper::Pub { append_to, .. } => DataIdentifier::PubAppendable(append_to),
        }
    }

    /// Returns `true` if the signature matches the data.
    pub fn verify_signature(&self) -> bool {
        match *self {
            AppendWrapper::Pub { ref data, .. } => data.verify_signature(),
            AppendWrapper::Priv { ref append_to,
                                  ref data,
                                  ref sign_key,
                                  ref version,
                                  ref signature } => {
                let data_to_sign = match serialise(&(append_to, data, sign_key, version)) {
                    Err(_) => return false,
                    Ok(data) => data,
                };
                sign::verify_detached(signature, &data_to_sign, sign_key)
            }
        }
    }

    /// Returns `sign_key` of the signer.
    pub fn sign_key(&self) -> &PublicKey {
        match *self {
            AppendWrapper::Pub { ref data, .. } => &data.sign_key,
            AppendWrapper::Priv { ref sign_key, .. } => sign_key,
        }
    }

    /// Returns `version` of the wrapper item.
    pub fn version(&self) -> &u64 {
        match *self {
            AppendWrapper::Pub { ref version, .. } |
            AppendWrapper::Priv { ref version, .. } => version,
        }
    }

    /// Returns `priv_appended_data` if AppendWrapper::Priv.
    pub fn priv_appended_data(&self) -> Option<&PrivAppendedData> {
        match *self {
            AppendWrapper::Pub { .. } => None,
            AppendWrapper::Priv { ref data, .. } => Some(data),
        }
    }

    /// Returns `pub_appended_data` if AppendWrapper::Pub.
    pub fn pub_appended_data(&self) -> Option<&AppendedData> {
        match *self {
            AppendWrapper::Pub { ref data, .. } => Some(data),
            AppendWrapper::Priv { .. } => None,
        }
    }
}

#[cfg(test)]
mod test {
    extern crate rand;
    use super::*;

    use data::DataIdentifier;
    use rust_sodium::crypto::{sign, box_};
    use priv_appendable_data::PrivAppendedData;

    #[test]
    fn pub_signatures() {
        let pointer = DataIdentifier::Immutable(rand::random());
        let (pub_key, secret_key) = sign::gen_keypair();
        let mut ad = unwrap!(AppendedData::new(pointer, pub_key, &secret_key));
        assert!(AppendWrapper::new_pub(rand::random(), ad.clone(), 5).verify_signature());
        ad.pointer = DataIdentifier::Structured(rand::random(), 10000);
        assert!(!AppendWrapper::new_pub(rand::random(), ad, 5).verify_signature());
    }

    #[test]
    fn priv_signatures() {
        let pointer = DataIdentifier::Immutable(rand::random());
        let (pub_sign_key, secret_sign_key) = sign::gen_keypair();
        let (pub_encrypt_key, secret_encrypt_key) = box_::gen_keypair();
        let ad = unwrap!(AppendedData::new(pointer, pub_sign_key, &secret_sign_key));
        let pad = unwrap!(PrivAppendedData::new(&ad, &pub_encrypt_key));
        assert_eq!(ad, unwrap!(pad.open(&pub_encrypt_key, &secret_encrypt_key)));
        let mut wrapper = unwrap!(AppendWrapper::new_priv(rand::random(),
                                                          pad,
                                                          (&pub_sign_key, &secret_sign_key),
                                                          5));
        assert!(wrapper.verify_signature());
        match wrapper {
            AppendWrapper::Pub { .. } => unreachable!(),
            AppendWrapper::Priv { ref mut version, .. } => *version = 6,
        }
        assert!(!wrapper.verify_signature());
    }
}
