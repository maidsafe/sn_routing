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

use rustc_serialize::{Decodable, Decoder};

use routing::immutable_data::ImmutableData;
use routing::structured_data::StructuredData;

pub enum Data {
    Immutable(ImmutableData),
    Structured(StructuredData),
    Unknown(u64),
}

// /// All Maidsafe tagging should offset from this
// pub const MAIDSAFE_TAG: u64 = 5483_000;

/// All Maidsafe Data tags
#[allow(missing_docs)]
pub mod data_tags {
    pub const MAIDSAFE_DATA_TAG: u64 = 5483_000 + 100;

    pub const IMMUTABLE_DATA_TAG: u64             = MAIDSAFE_DATA_TAG + 1;
    // pub const IMMUTABLE_DATA_BACKUP_TAG: u64      = MAIDSAFE_DATA_TAG + 2;
    // pub const IMMUTABLE_DATA_SACRIFICIAL_TAG: u64 = MAIDSAFE_DATA_TAG + 3;
    pub const STRUCTURED_DATA_TAG: u64            = MAIDSAFE_DATA_TAG + 4;
}


impl Decodable for Data {
    fn decode<D: Decoder>(decoder: &mut D) -> Result<Data, D::Error> {
        let tag = try!(decoder.read_u64());
        match tag {
            data_tags::IMMUTABLE_DATA_TAG => Ok(Data::Immutable(try!(Decodable::decode(decoder)))),
            data_tags::STRUCTURED_DATA_TAG =>
                Ok(Data::Structured(try!(Decodable::decode(decoder)))),
            _ => Ok(Data::Unknown(tag)),
        }
    }
}

#[cfg(test)]
 mod test {
    extern crate rand;
    extern crate cbor;

    use rand::Rng;

    use super::*;
    use maidsafe_types::*;

    #[test]
    fn data_parsing() {
        let size = 64;
        let mut data = Vec::with_capacity(size);
        let mut rng = rand::thread_rng();
        for _ in 0..size {
            data.push(rng.gen());
        }
        let immutable_data = ImmutableData::new(data);

        let mut encoder = cbor::Encoder::from_memory();
        encoder.encode(&[&immutable_data]).unwrap();

        let mut decoder = cbor::Decoder::from_bytes(encoder.as_bytes());

        match decoder.decode().next().unwrap().unwrap() {
            Data::Immutable(immut_data) => assert_eq!(immut_data, immutable_data),
            _ => panic!("Unexpected!"),
        }
    }
}
