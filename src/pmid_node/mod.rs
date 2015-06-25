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
use maidsafe_types::*;
use routing::NameType;
use routing::types::MessageAction;
use routing::error::{ResponseError, InterfaceError};
use routing::sendable::Sendable;
use cbor::Decoder;


pub struct PmidNode {
  chunk_store_ : ChunkStore
}

impl PmidNode {
  pub fn new() -> PmidNode {
    PmidNode { chunk_store_: ChunkStore::with_max_disk_usage(1073741824), } // TODO adjustable max_disk_space
  }

  pub fn handle_get(&self, name: NameType) ->Result<MessageAction, InterfaceError> {
    let data = self.chunk_store_.get(name);
    if data.len() == 0 {
      return Err(From::from(ResponseError::NoData));
    }
    Ok(MessageAction::Reply(data))
  }

  pub fn handle_put(&mut self, data : Vec<u8>) ->Result<MessageAction, InterfaceError> {
    let mut data_name : NameType;
    let mut d = Decoder::from_bytes(&data[..]);
    let payload: Payload = d.decode().next().unwrap().unwrap();
    let mut remove_sacrificial = false;
    match payload.get_type_tag() {
      PayloadTypeTag::ImmutableData => {
        data_name = payload.get_data::<ImmutableData>().name();
        remove_sacrificial = true;
      }
      PayloadTypeTag::ImmutableDataBackup => {
        data_name = payload.get_data::<ImmutableDataBackup>().name();
      }
      PayloadTypeTag::ImmutableDataSacrificial => {
        data_name = payload.get_data::<ImmutableDataSacrificial>().name();
      }
      PayloadTypeTag::PublicMaid => {
        data_name = payload.get_data::<PublicIdType>().name();
        remove_sacrificial = true;
      }
      _ => return Err(From::from(ResponseError::InvalidRequest))
    }
    if self.chunk_store_.has_disk_space(data.len()) {
      // the type_tag needs to be stored as well
      self.chunk_store_.put(data_name, data.clone());
      return Ok(MessageAction::Reply(data));
    }
    // TODO: due to the limitation of current return type, only one notification can be sent out
    //       so we will try to remove the first Sacrificial copy larger enough to free up space
    //       if such Sacrifical copy does not exist, then return with error
    if !remove_sacrificial {
      return Err(From::from(ResponseError::InvalidRequest))
    }
    let required_space = data.len() - (self.chunk_store_.max_disk_usage() - self.chunk_store_.current_disk_usage());
    let names = self.chunk_store_.names();
    for name in names.iter() {
      let fetched_data = self.chunk_store_.get(name.clone());
      let mut decoder = Decoder::from_bytes(&fetched_data[..]);
      let fetched_payload: Payload = decoder.decode().next().unwrap().unwrap();
      // Only remove Sacrificial copy
      match fetched_payload.get_type_tag() {
        PayloadTypeTag::ImmutableDataSacrificial => {
          if fetched_data.len() > required_space {
            self.chunk_store_.delete(name.clone());
            self.chunk_store_.put(data_name, data);
            // TODO: ideally, the InterfaceError shall have an option holding a list of copies
            return Err(From::from(ResponseError::FailedToStoreData(fetched_data)));
          }
        }
        _ => {}
      }
    }
    Err(From::from(ResponseError::InvalidRequest))
  }

}
#[cfg(test)]
mod test {
  use cbor;
  use routing;
  use routing::error::InterfaceError;
  use super::*;
  use maidsafe_types::*;
  use routing::types::{ MessageAction, array_as_vector};
  use routing::sendable::Sendable;

  #[test]
  fn handle_put_get() {
    let mut pmid_node = PmidNode::new();
    let value = routing::types::generate_random_vec_u8(1024);
    let data = ImmutableData::new(value);
    let payload = Payload::new(PayloadTypeTag::ImmutableData, &data);
    let mut encoder = cbor::Encoder::from_memory();
    let encode_result = encoder.encode(&[&payload]);
    assert_eq!(encode_result.is_ok(), true);
    let bytes = array_as_vector(encoder.as_bytes());
    let put_result = pmid_node.handle_put(bytes.clone());
    assert_eq!(put_result.is_ok(), true);
    match put_result {
      Err(InterfaceError::Abort) => panic!("Unexpected"),
      Ok(MessageAction::Reply(reply_bytes)) => assert_eq!(reply_bytes, bytes),
      _ => panic!("Unexpected"),
    }
    let get_result = pmid_node.handle_get(data.name());
    assert_eq!(get_result.is_err(), false);
    match get_result.ok().unwrap() {
        MessageAction::Reply(ref x) => {
            let mut d = cbor::Decoder::from_bytes(&x[..]);
            let obj_after: Payload = d.decode().next().unwrap().unwrap();
            assert_eq!(obj_after.get_type_tag(), PayloadTypeTag::ImmutableData);
            let data_after = obj_after.get_data::<ImmutableData>();
            assert_eq!(data.name().0.to_vec(), data_after.name().0.to_vec());
            assert_eq!(data.serialised_contents(), data_after.serialised_contents());
        },
        _ => panic!("Unexpected"),
    }
  }
}
