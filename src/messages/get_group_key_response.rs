// Copyright 2015 MaidSafe.net limited
//
// This Safe Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the Safe Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
// directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
// available at: http://maidsafe.net/network-platform-licensing
//
// Unless required by applicable law or agreed to in writing, the Safe Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
// OF ANY KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations relating to
// use of the Safe Network Software.

#![allow(unused_assignments)]

use cbor::CborTagEncode;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};
use frequency::{Frequency};
use types::{PublicSignKey, GROUP_SIZE, QUORUM_SIZE, Mergable};
use NameType;

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
pub struct GetGroupKeyResponse {
  pub public_sign_keys : Vec<(NameType, PublicSignKey)>
}

impl Mergable for GetGroupKeyResponse {
    fn merge<'a, I>(xs: I) -> Option<Self> where I: Iterator<Item=&'a Self> {
        let mut frequency = Frequency::new();

        for response in xs {
            for public_sign_key in &response.public_sign_keys {
                frequency.update(public_sign_key.clone());
            }
        }

        let merged_group = frequency.sort_by_highest().into_iter()
                           .filter(|&(_, ref count)| *count >= QUORUM_SIZE as usize)
                           .take(GROUP_SIZE as usize)
                           .map(|(k, _)| k)
                           .collect::<Vec<_>>();

        if merged_group.is_empty() { return None; }
        Some(GetGroupKeyResponse{ public_sign_keys: merged_group })
    }
}

impl Encodable for GetGroupKeyResponse {
  fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
    CborTagEncode::new(5483_001, &self.public_sign_keys).encode(e)
  }
}

impl Decodable for GetGroupKeyResponse {
  fn decode<D: Decoder>(d: &mut D)->Result<GetGroupKeyResponse, D::Error> {
    try!(d.read_u64());
    let public_sign_keys = try!(Decodable::decode(d));
    Ok(GetGroupKeyResponse { public_sign_keys: public_sign_keys})
  }
}

#[cfg(test)]
mod test {
    use types;
    use super::*;
    use cbor;
    use NameType;
    use test_utils::Random;

    #[test]
    fn get_group_key_response_serialisation() {
        let obj_before : GetGroupKeyResponse = Random::generate_random();

        let mut e = cbor::Encoder::from_memory();
        e.encode(&[&obj_before]).unwrap();

        let mut d = cbor::Decoder::from_bytes(e.as_bytes());
        let obj_after: GetGroupKeyResponse = d.decode().next().unwrap().unwrap();

        assert_eq!(obj_before, obj_after);
    }

    #[test]
    fn merge() {
        let obj : GetGroupKeyResponse = Random::generate_random();
        assert!(obj.public_sign_keys.len() >= types::GROUP_SIZE as usize);
        // if group size changes, reimplement the below
        assert!(types::GROUP_SIZE >= 13);

        // pick random keys
        let mut keys = Vec::<(NameType, types::PublicSignKey)>::new();
        keys.push(obj.public_sign_keys[3].clone());
        keys.push(obj.public_sign_keys[5].clone());
        keys.push(obj.public_sign_keys[7].clone());
        keys.push(obj.public_sign_keys[8].clone());
        keys.push(obj.public_sign_keys[9].clone());
        keys.push(obj.public_sign_keys[10].clone());
        keys.push(obj.public_sign_keys[13].clone());

        let mut responses = Vec::<GetGroupKeyResponse>::new();
        responses.push(obj);
        for _ in 0..4 {
            let mut response = GetGroupKeyResponse::generate_random();
            response.public_sign_keys[1] = keys[0].clone();
            response.public_sign_keys[4] = keys[1].clone();
            response.public_sign_keys[6] = keys[2].clone();
            response.public_sign_keys[0] = keys[3].clone();
            response.public_sign_keys[5] = keys[4].clone();
            response.public_sign_keys[9] = keys[5].clone();
            response.public_sign_keys[10] = keys[6].clone();
            responses.push(response);
        }

        let merged_obj = types::Mergable::merge(responses.iter());
        assert!(merged_obj.is_some());
        let merged_response = merged_obj.unwrap();
        for i in 0..7 {
            assert!(keys.iter().find(|a| **a == merged_response.public_sign_keys[i]).is_some());
        }
    }
}
