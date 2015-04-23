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

use cbor::CborTagEncode;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};
use types;
use NameType;

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct FindGroupResponse {
  pub target_id : NameType,
  pub group : Vec<types::PublicPmid>
}

impl FindGroupResponse {


    // TODO(ben 2015-04-09) to be replaced with a proper merge trait
    //                      for every message type
    pub fn merge(&self, others : &Vec<FindGroupResponse>) -> Option<FindGroupResponse> {
      let mut frequency_count : Vec<(types::PublicPmid, usize)>
        = Vec::with_capacity(2 * types::GROUP_SIZE as usize);
      for public_pmid in &self.group {
        let mut new_public_pmid : bool = false;
        match frequency_count.iter_mut()
              .find(|ref mut count| count.0.public_key == public_pmid.public_key) {
          Some(count) => count.1 += 1,
          None => new_public_pmid = true
        };
        if new_public_pmid { frequency_count.push((public_pmid.clone(), 1)); };
      }
      for other in others {
        if other.target_id != self.target_id { return None; }
        for public_pmid in &other.group {
          let mut new_public_pmid : bool = false;
          match frequency_count.iter_mut()
                .find(|ref mut count| count.0.public_key == public_pmid.public_key) {
            Some(count) => count.1 += 1,
            None => new_public_pmid = true
          };
          if new_public_pmid { frequency_count.push((public_pmid.clone(), 1)); };
        }
      }
      // sort from highest mention_count to lowest
      frequency_count.sort_by(|a, b| b.1.cmp(&a.1));
      let mut merged_group : Vec<types::PublicPmid>
        = Vec::with_capacity(types::GROUP_SIZE as usize);
      for public_pmid_count in frequency_count {
        if merged_group.len() < types::GROUP_SIZE as usize {
          // can also be done with map_in_place,
          // but explicit for-loop allows for asserts
          // assert!(public_pmid_count.1 >= types::QUORUM_SIZE as usize);
          assert!(public_pmid_count.1 <= types::GROUP_SIZE as usize);
          // TODO(ben 2015-04-09) return None once logic assured
          merged_group.push(public_pmid_count.0);
        } else {
          break; //  NOTE(ben 2015-04-15): here we can measure the fuzzy
                 //  boundary of groups
        }
      }
      assert_eq!(merged_group.len(), types::GROUP_SIZE as usize);
      // TODO(ben 2015-04-09) : curtosy call to sort to target,
      //                        but requires correct name on PublicPmid
      // merged_group.sort_by(...)
      Some(FindGroupResponse{target_id : self.target_id.clone(),
                             group : merged_group})
    }
}

impl Encodable for FindGroupResponse {
  fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
    CborTagEncode::new(5483_001, &(&self.target_id, &self.group)).encode(e)
  }
}

impl Decodable for FindGroupResponse {
  fn decode<D: Decoder>(d: &mut D)->Result<FindGroupResponse, D::Error> {
    try!(d.read_u64());
    let (target_id, group) = try!(Decodable::decode(d));
    Ok(FindGroupResponse { target_id: target_id, group: group})
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
        for _ in 0..4 {
            let mut response : FindGroupResponse = Random::generate_random();
            response.target_id = obj.target_id.clone();
            response.group[1] = keys[0].clone();
            response.group[4] = keys[1].clone();
            response.group[6] = keys[2].clone();
            response.group[0] = keys[3].clone();
            response.group[5] = keys[4].clone();
            response.group[9] = keys[5].clone();
            response.group[10] = keys[6].clone();
            responses.push(response);
        }

        let merged_obj = obj.merge(&responses);
        assert!(merged_obj.is_some());
        let merged_response = merged_obj.unwrap();
        for i in 0..7 {
            assert!(keys.iter().find(|a| **a == merged_response.group[i]).is_some());
        }
    }
}
