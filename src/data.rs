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
pub use immutable_data::{ImmutableData, ImmutableDataName};
pub use plain_data::PlainData;
use xor_name::XorName;

/// This is the data types routing handles in the public interface
#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Clone, RustcEncodable, RustcDecodable)]
pub enum Data {
    /// StructuredData Data type.
    Structured(StructuredData),
    /// ImmutableData Data type.
    Immutable(ImmutableData),
    /// PlainData Data type.
    Plain(PlainData),
}

impl Data {
    /// Return data name.
    pub fn name(&self) -> XorName {
        match *self {
            Data::Structured(ref data) => data.name(),
            Data::Immutable(ref data) => *data.raw_name(),
            Data::Plain(ref data) => data.name(),
        }
    }

    /// Return data size.
    pub fn payload_size(&self) -> usize {
        match *self {
            Data::Structured(ref data) => data.payload_size(),
            Data::Immutable(ref data) => data.payload_size(),
            Data::Plain(ref data) => data.payload_size(),
        }
    }
}

#[derive(Hash, Debug, PartialEq, Eq, PartialOrd, Ord, Clone, RustcEncodable, RustcDecodable)]
/// DataRequest.
pub enum DataRequest {
    /// Data request, (Identifier, TypeTag) pair for name resolution, for StructuredData.
    Structured(XorName, u64),
    /// Data request, (Identifier, Type), for ImmutableData types.
    Immutable(ImmutableDataName),
    /// Request for PlainData.
    Plain(XorName),
}

impl Debug for Data {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match *self {
            Data::Structured(ref data) => data.fmt(formatter),
            Data::Immutable(ref data) => data.fmt(formatter),
            Data::Plain(ref data) => data.fmt(formatter),
        }
    }
}

impl DataRequest {
    /// DataRequest name.
    pub fn name(&self) -> XorName {
        match *self {
            DataRequest::Structured(ref name, tag) => StructuredData::compute_name(tag, name),
            DataRequest::Immutable(ref name) => *name.raw(),
            DataRequest::Plain(ref name) => *name,
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
                assert_eq!(structured_data.name(), Data::Structured(structured_data).name());
            }
            Err(error) => panic!("Error: {:?}", error),
        }

        // name() resolves correctly for ImmutableData
        let value = "immutable data value".to_owned().into_bytes();
        let immutable_data = ImmutableData::new(value);
        let immutable_data_raw_name = *immutable_data.raw_name();
        assert_eq!(immutable_data_raw_name, Data::Immutable(immutable_data).name());

        // name() resolves correctly for PlainData
        let name = XorName(sha512::hash(&[]).0);
        let plain_data = PlainData::new(name, vec![]);
        assert_eq!(plain_data.name(), Data::Plain(plain_data).name());
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
        let name = ImmutableDataName::new(&[]);

        // name() resolves correctly for StructuedData
        let tag = 0;
        assert_eq!(StructuredData::compute_name(tag, name.raw()),
                   DataRequest::Structured(*name.raw(), tag).name());

        // name() resolves correctly for ImmutableData
        let immutable_data_raw_name = *name.raw();
        assert_eq!(immutable_data_raw_name, DataRequest::Immutable(name).name());

        // name() resolves correctly for PlainData
        assert_eq!(immutable_data_raw_name, DataRequest::Plain(immutable_data_raw_name).name());
    }
}
