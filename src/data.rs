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

use std::fmt::{self, Debug, Formatter};
use rustc_serialize::{Decoder, Encodable, Encoder};
pub use structured_data::StructuredData;
pub use immutable_data::{ImmutableData, ImmutableDataBackup, ImmutableDataSacrificial};
pub use plain_data::PlainData;
use xor_name::XorName;

#[allow(missing_docs)]
/// This is the data types routing handles in the public interface
#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Clone, RustcEncodable, RustcDecodable)]
pub enum Data {
    /// StructuredData Data type.
    Structured(StructuredData),
    /// ImmutableData Data type.
    Immutable(ImmutableData),
    ImmutableBackup(ImmutableDataBackup),
    ImmutableSacrificial(ImmutableDataSacrificial),
    /// PlainData Data type.
    Plain(PlainData),
}

impl Data {
    /// Return data name.
    pub fn name(&self) -> XorName {
        match *self {
            Data::Structured(ref data) => data.name(),
            Data::Immutable(ref data) => data.name(),
            Data::ImmutableBackup(ref data) => data.name(),
            Data::ImmutableSacrificial(ref data) => data.name(),
            Data::Plain(ref data) => data.name(),
        }
    }

    /// Return data size.
    pub fn payload_size(&self) -> usize {
        match *self {
            Data::Structured(ref data) => data.payload_size(),
            Data::Immutable(ref data) => data.payload_size(),
            Data::ImmutableBackup(ref data) => data.payload_size(),
            Data::ImmutableSacrificial(ref data) => data.payload_size(),
            Data::Plain(ref data) => data.payload_size(),
        }
    }
}

#[allow(missing_docs)]
#[derive(Hash, Debug, PartialEq, Eq, PartialOrd, Ord, Clone, RustcEncodable, RustcDecodable)]
/// DataIdentifier.
pub enum DataIdentifier {
    /// Data request, (Identifier, TypeTag) pair for name resolution, for StructuredData.
    Structured(XorName, u64),
    /// Data request, (Identifier), for ImmutableData types.
    Immutable(XorName),
    ImmutableBackup(XorName),
    ImmutableSacrificial(XorName),
    /// Request for PlainData.
    Plain(XorName),
}

impl Debug for Data {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match *self {
            Data::Structured(ref data) => data.fmt(formatter),
            Data::Immutable(ref data) => data.fmt(formatter),
            Data::ImmutableBackup(ref data) => data.fmt(formatter),
            Data::ImmutableSacrificial(ref data) => data.fmt(formatter),
            Data::Plain(ref data) => data.fmt(formatter),
        }
    }
}

impl DataIdentifier {
    /// DataIdentifier name.
    pub fn name(&self) -> XorName {
        match *self {
            DataIdentifier::Structured(name, tag) => StructuredData::compute_name(tag, &name),
            DataIdentifier::Immutable(name) |
            DataIdentifier::ImmutableBackup(name) |
            DataIdentifier::ImmutableSacrificial(name) |
            DataIdentifier::Plain(name) => name,
        }
    }
}

#[cfg(test)]
mod test {
    extern crate rand;

    use super::*;
    use sodiumoxide::crypto::sign;
    use sodiumoxide::crypto::hash::sha512;
    use xor_name::XorName;

    #[test]
    fn data_name() {
        // name() resolves correctly for StructuredData
        let keys = sign::gen_keypair();
        let owner_keys = vec![keys.0];
        match StructuredData::new(0,
                                  rand::random(),
                                  0,
                                  vec![],
                                  owner_keys.clone(),
                                  vec![],
                                  Some(&keys.1)) {
            Ok(structured_data) => {
                assert_eq!(structured_data.clone().name(),
                           Data::Structured(structured_data.clone()).name());
                assert_eq!(DataIdentifier::Structured(structured_data.name(),
                                                      structured_data.get_type_tag()),
                           structured_data.identifier());
            }
            Err(error) => panic!("Error: {:?}", error),
        }


        // name() resolves correctly for ImmutableData
        let value = "immutable data value".to_owned().into_bytes();
        let immutable_data = ImmutableData::new(value);
        assert_eq!(immutable_data.name(),
                   Data::Immutable(immutable_data.clone()).name());
        assert_eq!(immutable_data.identifier(),
                   DataIdentifier::Immutable(immutable_data.name()));

        let backup_data = ImmutableDataBackup::new(immutable_data.clone());
        assert_eq!(backup_data.identifier(),
                   DataIdentifier::ImmutableBackup(backup_data.name()));
        let sacrificial_data = ImmutableDataSacrificial::new(immutable_data.clone());
        assert_eq!(sacrificial_data.identifier(),
                   DataIdentifier::ImmutableSacrificial(sacrificial_data.name()));
        // name() resolves correctly for PlainData
        let name = XorName(sha512::hash(&[]).0);
        let plain_data = PlainData::new(name, vec![]);
        assert_eq!(plain_data.name(), Data::Plain(plain_data.clone()).name());
        assert_eq!(plain_data.identifier(),
                   DataIdentifier::Plain(plain_data.name()));
    }

    #[test]
    fn data_payload_size() {
        // payload_size() resolves correctly for StructuredData
        let keys = ::sodiumoxide::crypto::sign::gen_keypair();
        let owner_keys = vec![keys.0];
        match StructuredData::new(0,
                                  rand::random(),
                                  0,
                                  vec![],
                                  owner_keys.clone(),
                                  vec![],
                                  Some(&keys.1)) {
            Ok(structured_data) => {
                assert_eq!(structured_data.payload_size(),
                           Data::Structured(structured_data).payload_size());
            }
            Err(error) => panic!("Error: {:?}", error),
        }

        // payload_size() resolves correctly for ImmutableData
        let value = "immutable data value".to_owned().into_bytes();
        let immutable_data = ImmutableData::new(value);
        assert_eq!(immutable_data.payload_size(),
                   Data::Immutable(immutable_data).payload_size());

        // payload_size() resolves correctly for PlainData
        let name = XorName(sha512::hash(&[]).0);
        let plain_data = PlainData::new(name, vec![]);
        assert_eq!(plain_data.payload_size(),
                   Data::Plain(plain_data).payload_size());
    }

    #[test]
    fn data_request_name() {
        let name = XorName(sha512::hash(&[]).0);

        // name() resolves correctly for StructuedData
        let tag = 0;
        assert_eq!(StructuredData::compute_name(tag, &name),
                   DataIdentifier::Structured(name, tag).name());

        // name() resolves correctly for ImmutableData
        let actual_name = DataIdentifier::Immutable(name).name();
        assert_eq!(name, actual_name);

        // name() resolves correctly for PlainData
        assert_eq!(name, DataIdentifier::Plain(name).name());
    }
}
