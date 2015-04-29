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

#![allow(unused_assignments)]

use cbor::CborTagEncode;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};
use frequency::Frequency;
use types::{PublicPmid, GROUP_SIZE, QUORUM_SIZE, Mergable};

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct FindGroupResponse {
  pub group : Vec<PublicPmid>
}

impl Mergable for FindGroupResponse {
    fn merge<'a, I>(responses: I) -> Option<Self> where I: Iterator<Item=&'a Self> {
        let mut frequency = Frequency::new();

        for response in responses {
            for public_pmid in &response.group {
                frequency.update(public_pmid.clone());
            }
        }

        let merged_group = frequency.sort_by_highest().into_iter()
                           .filter(|&(_, ref count)| *count >= QUORUM_SIZE as usize)
                           .take(GROUP_SIZE as usize)
                           .map(|(k, _)| k)
                           .collect::<Vec<_>>();

        if merged_group.is_empty() { return None; }
        Some(FindGroupResponse{ group: merged_group })
    }
}

impl Encodable for FindGroupResponse {
  fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
    CborTagEncode::new(5483_001, &self.group).encode(e)
  }
}

impl Decodable for FindGroupResponse {
  fn decode<D: Decoder>(d: &mut D)->Result<FindGroupResponse, D::Error> {
    try!(d.read_u64());
    let group = try!(Decodable::decode(d));
    Ok(FindGroupResponse { group: group})
  }
}

#[cfg(test)]
mod test {
    use super::*;
    use cbor;
    use types;
    use test_utils::Random;

    #[test]
    fn find_group_response_serialisation() {
        let obj_before : FindGroupResponse = Random::generate_random();

        let mut e = cbor::Encoder::from_memory();
        e.encode(&[&obj_before]).unwrap();

        let mut d = cbor::Decoder::from_bytes(e.as_bytes());
        let obj_after: FindGroupResponse = d.decode().next().unwrap().unwrap();

        assert_eq!(obj_before, obj_after);
    }

    #[test]
    fn merge() {
        let obj : FindGroupResponse = Random::generate_random();
        assert!(obj.group.len() >= types::GROUP_SIZE as usize);
        // if group size changes, reimplement the below
        assert!(types::GROUP_SIZE >= 13);

        // pick random keys
        let mut keys = Vec::<types::PublicPmid>::with_capacity(7);
        keys.push(obj.group[3].clone());
        keys.push(obj.group[5].clone());
        keys.push(obj.group[7].clone());
        keys.push(obj.group[8].clone());
        keys.push(obj.group[9].clone());
        keys.push(obj.group[10].clone());
        keys.push(obj.group[13].clone());

        let mut responses = Vec::<FindGroupResponse>::with_capacity(4);
        responses.push(obj);
        for _ in 0..4 {
            let mut response : FindGroupResponse = Random::generate_random();
            response.group[1] = keys[0].clone();
            response.group[4] = keys[1].clone();
            response.group[6] = keys[2].clone();
            response.group[0] = keys[3].clone();
            response.group[5] = keys[4].clone();
            response.group[9] = keys[5].clone();
            response.group[10] = keys[6].clone();
            responses.push(response);
        }

        let merged_obj = types::Mergable::merge(responses.iter());
        assert!(merged_obj.is_some());
        let merged_response = merged_obj.unwrap();
        for i in 0..7 {
            assert!(keys.iter().find(|a| **a == merged_response.group[i]).is_some());
        }
    }
}
