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

#![allow(dead_code)]

use chunk_store::ChunkStore;
use routing::NameType;
use routing::types::{Action};
use routing::error::{ResponseError, InterfaceError};
use routing;
use maidsafe_types;
use routing::sendable::Sendable;
use cbor::Decoder;


pub struct PmidNode {
  chunk_store_ : ChunkStore
}

impl PmidNode {
  pub fn new() -> PmidNode {
    PmidNode { chunk_store_: ChunkStore::with_max_disk_usage(1073741824), } // TODO adjustable max_disk_space
  }

  pub fn handle_get(&self, name: NameType) ->Result<Action, InterfaceError> {
    let data = self.chunk_store_.get(name);
    if data.len() == 0 {
      return Err(From::from(ResponseError::NoData));
    }
    Ok(Action::Reply(data))
  }

  pub fn handle_put(&mut self, data : Vec<u8>) ->Result<Action, InterfaceError> {
    let mut data_name : NameType;
    let mut d = Decoder::from_bytes(&data[..]);
    let payload: maidsafe_types::Payload = d.decode().next().unwrap().unwrap();
    match payload.get_type_tag() {
      maidsafe_types::PayloadTypeTag::ImmutableData => {
        data_name = payload.get_data::<maidsafe_types::ImmutableData>().name();
      }
      maidsafe_types::PayloadTypeTag::PublicMaid => {
        data_name = payload.get_data::<maidsafe_types::PublicMaid>().name();
      }
      maidsafe_types::PayloadTypeTag::PublicAnMaid => {
        data_name = payload.get_data::<maidsafe_types::PublicAnMaid>().name();
      }
      _ => return Err(From::from(ResponseError::InvalidRequest))
    }
    // the type_tag needs to be stored as well    
    self.chunk_store_.put(data_name, data);
    Err(InterfaceError::Abort)
  }

}
#[cfg(test)]
mod test {
  use cbor;
  use maidsafe_types;
  use routing;
  use routing::error::InterfaceError;
  use super::*;
  use maidsafe_types::*;
  use routing::NameType;
  use routing::types::array_as_vector;
  use routing::sendable::Sendable;

  #[test]
  fn handle_put_get() {
    let mut pmid_node = super::PmidNode::new();
    let name = NameType([3u8; 64]);
    let value = routing::types::generate_random_vec_u8(1024);
    let data = ImmutableData::new(value);
    let payload = Payload::new(PayloadTypeTag::ImmutableData, &data);
    let mut encoder = cbor::Encoder::from_memory();
    let encode_result = encoder.encode(&[&payload]);
    assert_eq!(encode_result.is_ok(), true);

    let put_result = pmid_node.handle_put(array_as_vector(encoder.as_bytes()));
    assert_eq!(put_result.is_err(), true);
    match put_result.err().unwrap() {
      InterfaceError::Abort => { }
      _ => panic!("Unexpected"),
    }
    let get_result = pmid_node.handle_get(data.name());
    assert_eq!(get_result.is_err(), false);
    match get_result.ok().unwrap() {
        Action::Reply(ref x) => {
            let mut d = cbor::Decoder::from_bytes(&x[..]);
            let obj_after: Payload = d.decode().next().unwrap().unwrap();
            assert_eq!(obj_after.get_type_tag(), PayloadTypeTag::ImmutableData);
            let data_after = obj_after.get_data::<maidsafe_types::ImmutableData>();
            assert_eq!(data.name().0.to_vec(), data_after.name().0.to_vec());
            assert_eq!(data.serialised_contents(), data_after.serialised_contents());
        },
        _ => panic!("Unexpected"),
    }
  }
}
