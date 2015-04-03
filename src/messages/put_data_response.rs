// Copyright 2015 MaidSafe.net limited
// This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
// By contributing code to the MaidSafe Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
// directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
// available at: http://www.maidsafe.net/licenses
// Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
// OF ANY KIND, either express or implied.
// See the Licences for the specific language governing permissions and limitations relating to
// use of the MaidSafe
// Software.

#![allow(unused_assignments)]

extern crate rand;

use types;
use cbor::CborTagEncode;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct PutDataResponse {
  pub type_id : u32,
  pub data : Vec<u8>,  // len() == 0 indicates no data responsed
  pub error : Vec<u8>  //  TODO this shall be a serializable MaidSafeError type
}

impl PutDataResponse {
    pub fn generate_random() -> PutDataResponse {
        PutDataResponse {
            type_id: rand::random::<u32>(),
            data: types::generate_random_vec_u8(99),
            error: types::generate_random_vec_u8(27),
        }
    }
}

impl Encodable for PutDataResponse {
  fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
    CborTagEncode::new(5483_001, &(&self.type_id, &self.data, &self.error)).encode(e)
  }
}

impl Decodable for PutDataResponse {
  fn decode<D: Decoder>(d: &mut D)->Result<PutDataResponse, D::Error> {
    try!(d.read_u64());
    let (type_id, data, error) = try!(Decodable::decode(d));
    Ok(PutDataResponse { type_id: type_id, data: data, error: error })
  }
}

mod test {
    extern crate cbor;

    use types;
    use super::*;
    use cbor::CborTagEncode;

    #[test]
    fn put_data_response_serialisation() {
        let obj_before = PutDataResponse::generate_random();

        let mut e = cbor::Encoder::from_memory();
        e.encode(&[&obj_before]).unwrap();

        let mut d = cbor::Decoder::from_bytes(e.as_bytes());
        let obj_after: PutDataResponse = d.decode().next().unwrap().unwrap();

        assert_eq!(obj_before, obj_after);
    }
}
