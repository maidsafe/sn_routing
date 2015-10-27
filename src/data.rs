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

use rustc_serialize::{Decoder, Encodable, Encoder};
pub use structured_data::StructuredData;
pub use immutable_data::{ImmutableData, ImmutableDataType};
pub use plain_data::PlainData;
use NameType;

/// This is the data types routing handles in the public interface
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, RustcEncodable, RustcDecodable)]
pub enum Data {
    /// StructuredData Data type.
    StructuredData(StructuredData),
    /// ImmutableData Data type.
    ImmutableData(ImmutableData),
    /// PlainData Data type.
    PlainData(PlainData),
}

impl Data {

    /// Return data name.
    pub fn name(&self) -> NameType {
        match *self {
            Data::StructuredData(ref d) => d.name(),
            Data::ImmutableData(ref d) => d.name(),
            Data::PlainData(ref d) => d.name(),
        }
    }

    /// Return data size.
    pub fn payload_size(&self) -> usize {
        match *self {
            Data::StructuredData(ref d) => d.payload_size(),
            Data::ImmutableData(ref d) => d.payload_size(),
            Data::PlainData(ref d) => d.payload_size(),
        }
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, RustcEncodable, RustcDecodable)]
/// DataRequest.
pub enum DataRequest {
    /// Data request, (Identifier, TypeTag) pair for name resolution, for StructuredData.
    StructuredData(NameType, u64),
    /// Data request, (Identifier, Type), for ImmutableData types.
    ImmutableData(NameType, ImmutableDataType),
    /// Request for PlainData.
    PlainData(NameType),
}

impl DataRequest {

    /// DataRequest name.
    pub fn name(&self) -> NameType {
        match *self {
            DataRequest::StructuredData(ref name, tag) => StructuredData::compute_name(tag, name),
            DataRequest::ImmutableData(ref name, _) => name.clone(),
            DataRequest::PlainData(ref name) => name.clone(),
        }
    }
}

#[cfg(test)]
mod test {
    use rand;

    #[test]
    fn data_name() {
        // name() resolves correctly for StructuedData
        let keys = ::sodiumoxide::crypto::sign::gen_keypair();
        let owner_keys = vec![keys.0];
        match ::structured_data::StructuredData::new(0,
                                  rand::random(),
                                  0,
                                  vec![],
                                  owner_keys.clone(),
                                  vec![],
                                  Some(&keys.1)) {
            Ok(structured_data) => {
                assert_eq!(
                    structured_data.name(),
                    ::data::Data::StructuredData(structured_data).name()
                );
            },
            Err(error) => panic!("Error: {:?}", error),
        }

        // name() resolves correctly for ImmutableData
        let value = "immutable data value".to_string().into_bytes();
        let immutable_data = ::immutable_data::ImmutableData::new(
            ::immutable_data::ImmutableDataType::Normal,
            value);
        assert_eq!(immutable_data.name(), ::data::Data::ImmutableData(immutable_data).name());

        // name() resolves correctly for PlainData
        let name = ::NameType(::sodiumoxide::crypto::hash::sha512::hash(&vec![]).0);
        let plain_data = ::plain_data::PlainData::new(name, vec![]);
        assert_eq!(plain_data.name(), ::data::Data::PlainData(plain_data).name());
    }

    #[test]
    fn data_payload_size() {
        // payload_size() resolves correctly for StructuedData
        let keys = ::sodiumoxide::crypto::sign::gen_keypair();
        let owner_keys = vec![keys.0];
        match ::structured_data::StructuredData::new(0,
                                  rand::random(),
                                  0,
                                  vec![],
                                  owner_keys.clone(),
                                  vec![],
                                  Some(&keys.1)) {
            Ok(structured_data) => {
                assert_eq!(
                    structured_data.payload_size(),
                    ::data::Data::StructuredData(structured_data).payload_size()
                );
            },
            Err(error) => panic!("Error: {:?}", error),
        }

        // payload_size() resolves correctly for ImmutableData
        let value = "immutable data value".to_string().into_bytes();
        let immutable_data = ::immutable_data::ImmutableData::new(
            ::immutable_data::ImmutableDataType::Normal,
            value);
        assert_eq!(
            immutable_data.payload_size(),
            ::data::Data::ImmutableData(immutable_data).payload_size()
        );

        // payload_size() resolves correctly for PlainData
        let name = ::NameType(::sodiumoxide::crypto::hash::sha512::hash(&vec![]).0);
        let plain_data = ::plain_data::PlainData::new(name, vec![]);
        assert_eq!(plain_data.payload_size(), ::data::Data::PlainData(plain_data).payload_size());
    }

    #[test]
    fn data_request_name() {
        let name = ::NameType(::sodiumoxide::crypto::hash::sha512::hash(&vec![]).0);

        // name() resolves correctly for StructuedData    
        let tag = 0;
        assert_eq!(
            ::structured_data::StructuredData::compute_name(tag, &name),
            ::data::DataRequest::StructuredData(name, tag).name()
        );

        // name() resolves correctly for ImmutableData
        let actual_name = ::data::DataRequest::ImmutableData(
            name, ::immutable_data::ImmutableDataType::Normal).name();
        assert_eq!(name.clone(), actual_name);

        // name() resolves correctly for PlainData
        assert_eq!(name.clone(), ::data::DataRequest::PlainData(name).name());
    }
}
