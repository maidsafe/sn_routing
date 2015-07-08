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
use NameType;

/// PlainData
#[derive(Clone, RustcEncodable, RustcDecodable, PartialEq, Debug)]
pub struct PlainData {
    name: NameType,
    value: Vec<u8>,
}

impl PlainData {

    /// Creates a new instance of PlainData
    pub fn new(name: NameType, value: Vec<u8>) -> PlainData {
        PlainData {
            name: name,
            value: value,
        }
    }

    /// Returns the value
    pub fn value(&self) -> &Vec<u8> {
        &self.value
    }


    /// Returns name ensuring invariant
    pub fn name(&self) -> &NameType {
        &self.name
    }
}



#[cfg(test)]
mod test {

    extern crate rand;

    use NameType;
    use super::PlainData;
    use self::rand::Rng;
    use sodiumoxide::crypto;
    use rustc_serialize::hex::ToHex;

        fn generate_random() -> Vec<u8> {
            let size = 1025;
            let mut data = Vec::with_capacity(size);
            let mut rng = rand::thread_rng();
            for _ in 0..size {
                data.push(rng.gen::<u8>());
            }
            data
        }


    #[test]
    fn basic_check() {
        let name1 = NameType(crypto::hash::sha512::hash(&generate_random()).0);
        let name2 = NameType(crypto::hash::sha512::hash(&generate_random()).0);
        let value1 = generate_random();
        let value2 = generate_random();
        let plain_data1 = PlainData::new(name1, value1.clone());
        let plain_data2 = PlainData::new(name2, value2.clone());
        assert!(plain_data1.name() != plain_data2.name());
        assert!(plain_data1.value().to_hex() != plain_data2.value().to_hex());
        assert_eq!(plain_data1.value().to_hex(), value1.to_hex());
        assert_eq!(plain_data2.value().to_hex(), value2.to_hex());
    }

}
