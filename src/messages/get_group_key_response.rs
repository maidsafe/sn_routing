// Copyright 2015 MaidSafe.net limited
//
// This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the MaidSafe Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
// directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
// available at: http://www.maidsafe.net/licenses
//
// Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
// OF ANY KIND, either express or implied.
//
// See the Licences for the specific language governing permissions and limitations relating to
// use of the MaidSafe Software.

#![allow(unused_assignments)]

use cbor::CborTagEncode;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};

use types;

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
pub struct GetGroupKeyResponse {
  pub target_id : types::GroupAddress,
  pub public_keys : Vec<(types::Address, Vec<u8>)>
}

impl GetGroupKeyResponse {
    pub fn generate_random() -> GetGroupKeyResponse {
        let mut vec: Vec<(types::Address, Vec<u8>)> = Vec::with_capacity(30);
        for i in 0..30 {
            vec.push((types::generate_random_vec_u8(64), types::generate_random_vec_u8(99)));
        }
        GetGroupKeyResponse {
            target_id: types::generate_random_vec_u8(64),
            public_keys: vec,
        }
    }
}

impl Encodable for GetGroupKeyResponse {
  fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
    CborTagEncode::new(5483_001, &(&self.target_id, &self.public_keys)).encode(e)
  }
}

impl Decodable for GetGroupKeyResponse {
  fn decode<D: Decoder>(d: &mut D)->Result<GetGroupKeyResponse, D::Error> {
    try!(d.read_u64());
    let (target_id, public_keys) = try!(Decodable::decode(d));
    Ok(GetGroupKeyResponse { target_id: target_id , public_keys: public_keys})
  }
}

#[cfg(test)]
mod test {
    extern crate cbor;

    use super::*;

    #[test]
    fn get_group_key_response_serialisation() {
        let obj_before = GetGroupKeyResponse::generate_random();

        let mut e = cbor::Encoder::from_memory();
        e.encode(&[&obj_before]).unwrap();

        let mut d = cbor::Decoder::from_bytes(e.as_bytes());
        let obj_after: GetGroupKeyResponse = d.decode().next().unwrap().unwrap();

        assert_eq!(obj_before, obj_after);
    }
}

