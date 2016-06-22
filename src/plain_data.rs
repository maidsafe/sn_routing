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
use xor_name::XorName;
use data::DataIdentifier;
use utils;

/// Plain data with a name and a value.
///
/// Its name is independent of its value and no restrictions on name or value are enforced. These
/// are left to the implementation.
#[derive(Hash, Clone, RustcEncodable, RustcDecodable, PartialEq, Eq, PartialOrd, Ord)]
pub struct PlainData {
    name: XorName,
    value: Vec<u8>,
}

impl PlainData {
    /// Creates a new instance of `PlainData`.
    pub fn new(name: XorName, value: Vec<u8>) -> PlainData {
        PlainData {
            name: name,
            value: value,
        }
    }

    /// Returns the value.
    pub fn value(&self) -> &Vec<u8> {
        &self.value
    }


    /// Returns the name.
    pub fn name(&self) -> XorName {
        self.name
    }

    /// Returns the size of the contained data. Equivalent to `value().len()`.
    pub fn payload_size(&self) -> usize {
        self.value.len()
    }

    /// Returns `DataIdentifier` for this data element.
    pub fn identifier(&self) -> DataIdentifier {
        DataIdentifier::Plain(self.name())
    }
}

impl Debug for PlainData {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter,
               "PlainData {{ name: {}, value: {} }}",
               self.name,
               utils::format_binary_array(&self.value))
    }
}

#[cfg(test)]
mod test {
    use super::PlainData;
    use itertools::Itertools;
    use rand::{self, Rng};
    use rustc_serialize::hex::ToHex;

    #[test]
    fn basic_check() {
        let name1 = rand::random();
        let name2 = rand::random();
        let value1 = rand::thread_rng().gen_iter().take(1025).collect_vec();
        let value2 = rand::thread_rng().gen_iter().take(1025).collect_vec();
        let plain_data1 = PlainData::new(name1, value1.clone());
        let plain_data2 = PlainData::new(name2, value2.clone());
        assert!(plain_data1.name() != plain_data2.name());
        assert!(plain_data1.value().to_hex() != plain_data2.value().to_hex());
        assert_eq!(plain_data1.value().to_hex(), value1.to_hex());
        assert_eq!(plain_data2.value().to_hex(), value2.to_hex());
    }

}
