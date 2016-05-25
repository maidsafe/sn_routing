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

use sodiumoxide::crypto::hash::sha512;
use data::DataIdentifier;
use xor_name::XorName;


/// An immutable chunk of data.
#[derive(Hash, Clone, Eq, PartialEq, Ord, PartialOrd, RustcEncodable, RustcDecodable)]
pub struct ImmutableData {
    value: Vec<u8>,
}

impl ImmutableData {
    /// Creates a new instance of `ImmutableData`
    pub fn new(value: Vec<u8>) -> ImmutableData {
        ImmutableData { value: value }
    }

    /// Returns the value
    pub fn value(&self) -> &Vec<u8> {
        &self.value
    }


    /// Returns name ensuring invariant.
    pub fn name(&self) -> XorName {
        XorName(sha512::hash(&self.value).0)
    }

    /// Returns size of contained value.
    pub fn payload_size(&self) -> usize {
        self.value.len()
    }

    /// Returns `DataIdentifier` for this data element.
    pub fn identifier(&self) -> DataIdentifier {
        DataIdentifier::Immutable(self.name())
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
        let expected_immutable_data_name = "9f1c9e526f47e36d782de464ea9df0a31a5c19c321f2a5d9c8faac\
                                            dda4d59abc713445c8c853e1842d7c2c2311650df1ee2410737193\
                                            5b6be88a10cbf4cd2f8f";

        assert_eq!(&expected_immutable_data_name, &immutable_data_name);
    }
}
