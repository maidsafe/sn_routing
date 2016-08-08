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

use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};
use rust_sodium::crypto::hash::sha256;
use data::DataIdentifier;
use xor_name::XorName;


/// An immutable chunk of data.
#[derive(Hash, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct ImmutableData {
    name: XorName,
    value: Vec<u8>,
}

impl ImmutableData {
    /// Creates a new instance of `ImmutableData`
    pub fn new(value: Vec<u8>) -> ImmutableData {
        ImmutableData {
            name: XorName(sha256::hash(&value).0),
            value: value,
        }
    }

    /// Returns the value
    pub fn value(&self) -> &Vec<u8> {
        &self.value
    }


    /// Returns name ensuring invariant.
    pub fn name(&self) -> &XorName {
        &self.name
    }

    /// Returns size of contained value.
    pub fn payload_size(&self) -> usize {
        self.value.len()
    }

    /// Returns `DataIdentifier` for this data element.
    pub fn identifier(&self) -> DataIdentifier {
        DataIdentifier::Immutable(self.name)
    }
}


impl Encodable for ImmutableData {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), E::Error> {
        self.value.encode(encoder)
    }
}

impl Decodable for ImmutableData {
    fn decode<D: Decoder>(decoder: &mut D) -> Result<ImmutableData, D::Error> {
        let value: Vec<u8> = try!(Decodable::decode(decoder));
        Ok(ImmutableData {
            name: XorName(sha256::hash(&value).0),
            value: value,
        })
    }
}

impl Debug for ImmutableData {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "ImmutableData {:?}", self.name())
    }
}

#[cfg(test)]
mod test {
    extern crate rand;

    use super::*;
    use rustc_serialize::hex::ToHex;

    #[test]
    fn deterministic_test() {
        let value = "immutable data value".to_owned().into_bytes();

        // Normal
        let immutable_data = ImmutableData::new(value);
        let immutable_data_name = immutable_data.name().0.as_ref().to_hex();
        let expected_name = "ec0775555a7a6afba5f6e0a1deaa06f8928da80cf6ca94742ecc2a00c31033d3";

        assert_eq!(&expected_name, &immutable_data_name);
    }
}
