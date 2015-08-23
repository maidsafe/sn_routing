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
    StructuredData(StructuredData),
    ImmutableData(ImmutableData),
    PlainData(PlainData),
}

impl Data {
    pub fn name(&self) -> NameType {
        match *self {
            Data::StructuredData(ref d) => d.name(),
            Data::ImmutableData(ref d) => d.name(),
            Data::PlainData(ref d) => d.name(),
        }
    }

    pub fn payload_size(&self) -> usize {
        match *self {
            Data::StructuredData(ref d) => d.payload_size(),
            Data::ImmutableData(ref d) => d.payload_size(),
            Data::PlainData(ref d) => d.payload_size(),
        }
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, RustcEncodable, RustcDecodable)]
pub enum DataRequest {
    StructuredData(NameType, u64),
    ImmutableData(NameType, ImmutableDataType),
    PlainData(NameType),
}

impl DataRequest {
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

    // use super::*;

    #[test]
    fn creation() {
    }

}
