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
use xor_name::XorName;
use data::DataIdentifier;
use error::RoutingError;
use priv_appendable_data::PrivAppendedData;

/// Size of a serialised appended_data item.
pub const SERIALISED_APPENDED_DATA_SIZE: usize = 164;

/// The type of access filter for appendable data.
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, RustcDecodable, RustcEncodable)]
pub enum Filter {
    /// Everyone except the listed keys are allowed to append data.
    BlackList(Vec<PublicKey>),
    /// Only the listed keys are allowed to append data.
    WhiteList(Vec<PublicKey>),
}

/// An appended data item, pointing to another data chunk in the network.
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, RustcDecodable, RustcEncodable, Debug)]
pub struct AppendedData {
    pointer: DataIdentifier, // Pointer to actual data
    sign_key: PublicKey,
    signature: Signature, // All the above fields
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
        let signature = sign::sign_detached(&data_to_sign, &sign_pair.1);
        Ok(AppendWrapper::Priv {
            append_to: append_to,
            data: data,
            sign_key: *sign_pair.0,
            version: version,
            signature: signature,
        })
    }
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

    /// Returns reference to pointer.
    pub fn pointer(&self) -> &DataIdentifier {
        &self.pointer
    }

    /// Returns reference to sign_key.
    pub fn sign_key(&self) -> &PublicKey {
        &self.sign_key
    }

    /// Returns reference to signature.
    pub fn signature(&self) -> &Signature {
        &self.signature
    }
}

#[cfg(test)]
mod test {
    extern crate rand;
    use super::*;

    use data::DataIdentifier;
    use maidsafe_utilities::serialisation::serialise;
    use rust_sodium::crypto::sign;

    #[test]
    fn serialised_appended_data_size() {
        let keys = sign::gen_keypair();
        let pointer = DataIdentifier::Structured(rand::random(), 10000);
        let appended_data = unwrap!(AppendedData::new(pointer, keys.0, &keys.1));
        let serialised = unwrap!(serialise(&appended_data));
        assert_eq!(SERIALISED_APPENDED_DATA_SIZE, serialised.len());
    }
}
