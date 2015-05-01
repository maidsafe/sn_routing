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
use routing;
use maidsafe_types;
use routing::NameType;
use chunk_store::ChunkStore;
use routing::sendable::Sendable;
use cbor::{ Decoder, Encoder };

pub struct VersionHandler {
  // This is assuming ChunkStore has the ability of handling mutable(SDV) data, and put is overwritable
  // If such assumption becomes in-valid, LruCache or Sqlite based persona specific database shall be used
  chunk_store_ : ChunkStore
}

impl VersionHandler {
  pub fn new() -> VersionHandler {
    // TODO adjustable max_disk_space
    VersionHandler { chunk_store_: ChunkStore::with_max_disk_usage(1073741824) }
  }

  pub fn handle_get(&self, name: NameType) ->Result<routing::Action, routing::RoutingError> {
    let data = self.chunk_store_.get(name);
    if data.len() == 0 {
      return Err(routing::RoutingError::NoData);
    }
    Ok(routing::Action::Reply(data))
  }

  pub fn handle_put(&mut self, data : Vec<u8>) ->Result<routing::Action, routing::RoutingError> {
    let mut data_name : NameType;
    let mut d = Decoder::from_bytes(&data[..]);
    let payload: maidsafe_types::Payload = d.decode().next().unwrap().unwrap();
    match payload.get_type_tag() {
      maidsafe_types::PayloadTypeTag::StructuredData => {
        data_name = payload.get_data::<maidsafe_types::StructuredData>().name();
      }
       _ => return Err(routing::RoutingError::InvalidRequest)
    }
    // the type_tag needs to be stored as well, ChunkStore::put is overwritable
    self.chunk_store_.put(data_name, data);
    return Err(routing::RoutingError::Success);
  }

  pub fn retrieve_all_and_reset(&mut self) -> Vec<routing::node_interface::RoutingNodeAction> {
       let names = self.chunk_store_.names();
       let mut sendable = Vec::with_capacity(names.len());
       for name in names {
            let data = self.chunk_store_.get(name.clone());
            sendable.push(routing::node_interface::RoutingNodeAction::Put {
                destination: name.clone(),
                content: generic_sendable_type::GenericSendableType::new(name, 1, data), //TODO Get type_tag correct
            });
       }
       self.chunk_store_ = ChunkStore::with_max_disk_usage(1073741824);
       sendable
  }

}

#[cfg(test)]
mod test {
 use cbor;
 use maidsafe_types;
 use routing;
 use super::*;
 use maidsafe_types::*;
 use routing::types::*;
 use routing::NameType;
 use routing::sendable::Sendable;

 #[test]
 fn handle_put_get() {
    let mut version_handler = VersionHandler::new();
    let name = NameType([3u8; 64]);
    let owner = NameType([4u8; 64]);
    let mut value = Vec::new();
    value.push(vec![NameType([5u8; 64]), NameType([6u8; 64])]);
    let sdv = StructuredData::new(name, owner, value);
    let payload = Payload::new(PayloadTypeTag::StructuredData, &sdv);
    let mut encoder = cbor::Encoder::from_memory();
    let encode_result = encoder.encode(&[&payload]);
    assert_eq!(encode_result.is_ok(), true);

    let put_result = version_handler.handle_put(array_as_vector(encoder.as_bytes()));
    assert_eq!(put_result.is_err(), true);
    match put_result.err().unwrap() {
        routing::RoutingError::Success => assert_eq!(true, true),
        _ => assert_eq!(true, false),
    }

    let data_name = NameType::new(sdv.name().0);
    let get_result = version_handler.handle_get(data_name);
    assert_eq!(get_result.is_err(), false);
    match get_result.ok().unwrap() {
        routing::Action::SendOn(_) => panic!("Unexpected"),
        routing::Action::Reply(x) => {
                let mut d = cbor::Decoder::from_bytes(x);
                let obj_after: Payload = d.decode().next().unwrap().unwrap();
                assert_eq!(obj_after.get_type_tag(), PayloadTypeTag::StructuredData);
                let sdv_after = obj_after.get_data::<maidsafe_types::StructuredData>();
                assert_eq!(sdv_after.name(), NameType([3u8;64]));
                assert_eq!(sdv_after.owner().unwrap(), NameType([4u8;64]));
                assert_eq!(sdv_after.get_value().len(), 1);
                assert_eq!(sdv_after.get_value()[0].len(), 2);
                assert_eq!(sdv_after.get_value()[0][0], NameType([5u8;64]));
                assert_eq!(sdv_after.get_value()[0][1], NameType([6u8;64]));
            }
        }
    }
}
