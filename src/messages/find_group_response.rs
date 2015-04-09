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

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct FindGroupResponse {
  pub target_id : types::Address,
  pub group : Vec<types::PublicPmid>
}

impl FindGroupResponse {
    pub fn generate_random() -> FindGroupResponse {
        let mut vec: Vec<types::PublicPmid> = Vec::with_capacity(99);
        for i in 0..99 {
            vec.push(types::PublicPmid::generate_random());
        }

        FindGroupResponse {
            target_id: types::generate_random_vec_u8(64),
            group: vec,
        }
    }

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
          assert!(public_pmid_count.1 >= types::QUORUM_SIZE as usize);
          assert!(public_pmid_count.1 <= types::GROUP_SIZE as usize);
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
    extern crate cbor;

    use super::*;

    #[test]
    fn find_group_response_serialisation() {
        let obj_before = FindGroupResponse::generate_random();

        let mut e = cbor::Encoder::from_memory();
        e.encode(&[&obj_before]).unwrap();

        let mut d = cbor::Decoder::from_bytes(e.as_bytes());
        let obj_after: FindGroupResponse = d.decode().next().unwrap().unwrap();

        assert_eq!(obj_before, obj_after);
    }
}
