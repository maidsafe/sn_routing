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
use maidsafe_types;
use maidsafe_types::StructuredData;
use routing::NameType;
use routing::node_interface::MethodCall;
use routing::error::{ResponseError, InterfaceError};
use routing::types::{MessageAction, GROUP_SIZE};
use chunk_store::ChunkStore;
use routing::sendable::Sendable;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};
use cbor;

#[derive(RustcEncodable, RustcDecodable, PartialEq, Eq, Clone, Debug)]
pub struct VersionHandlerSendable {
    name: NameType,
    tag: u64,
    data: Vec<u8>,
}

impl VersionHandlerSendable {
    pub fn new(name: NameType, data: Vec<u8>) -> VersionHandlerSendable {
        VersionHandlerSendable {
            name: name,
            tag: 209, // FIXME : Change once the tag is freezed
            data: data,
        }
    }

    pub fn get_data(&self) -> &Vec<u8> {
        &self.data
    }
}
impl Sendable for VersionHandlerSendable {
    fn name(&self) -> NameType {
        self.name.clone()
    }

    fn type_tag(&self) -> u64 {
        self.tag.clone()
    }

    fn serialised_contents(&self) -> Vec<u8> {
        let mut e = cbor::Encoder::from_memory();
        e.encode(&[&self]).unwrap();
        e.into_bytes()
    }

    fn refresh(&self) -> bool {
        true
    }

    fn merge(&self, responses: Vec<Box<Sendable>>) -> Option<Box<Sendable>> {
        let mut tmp_wrapper: VersionHandlerSendable;
        let mut sdvs: Vec<Box<Sendable>> = Vec::new();
        for value in responses {
            let mut d = cbor::Decoder::from_bytes(value.serialised_contents());
            tmp_wrapper = d.decode().next().unwrap().unwrap();
            let mut d_sdv = cbor::Decoder::from_bytes(&tmp_wrapper.get_data()[..]);
            let sdv: StructuredData = d_sdv.decode().next().unwrap().unwrap();
            sdvs.push(Box::new(sdv));
        }
        assert!(sdvs.len() < (GROUP_SIZE + 1) / 2);
        let mut d = cbor::Decoder::from_bytes(&self.data[..]);
        let seed_sdv: StructuredData = d.decode().next().unwrap().unwrap();
        match seed_sdv.merge(sdvs) {
            Some(merged_sdv) => {
                Some(Box::new(VersionHandlerSendable::new(self.name.clone(), merged_sdv.serialised_contents())))
            }
            None => None
        }
    }

}

pub struct VersionHandler {
  // TODO: This is assuming ChunkStore has the ability of handling mutable(SDV) data, and put is overwritable
  // If such assumption becomes in-valid, LruCache or Sqlite based persona specific database shall be used
  chunk_store_ : ChunkStore
}

impl VersionHandler {
  pub fn new() -> VersionHandler {
    // TODO adjustable max_disk_space
    VersionHandler { chunk_store_: ChunkStore::with_max_disk_usage(1073741824) }
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
    let mut d = cbor::Decoder::from_bytes(&data[..]);
    let payload: maidsafe_types::Payload = d.decode().next().unwrap().unwrap();
    match payload.get_type_tag() {
      maidsafe_types::PayloadTypeTag::StructuredData => {
        data_name = payload.get_data::<StructuredData>().name();
      }
       _ => return Err(From::from(ResponseError::InvalidRequest))
    }
    // the type_tag needs to be stored as well, ChunkStore::put is overwritable
    self.chunk_store_.put(data_name.clone(), data.clone());
    return Ok(MessageAction::Reply(data));
  }

  pub fn handle_account_transfer(&mut self, payload : maidsafe_types::Payload) {
      let version_handler_sendable : VersionHandlerSendable = payload.get_data();
      // TODO: Assuming the incoming merged entry has the priority and shall also be trusted first
      self.chunk_store_.delete(version_handler_sendable.name());
      self.chunk_store_.put(version_handler_sendable.name(), version_handler_sendable.get_data().clone());
  }

  pub fn retrieve_all_and_reset(&mut self) -> Vec<MethodCall> {
       let names = self.chunk_store_.names();
       let mut actions = Vec::with_capacity(names.len());
       for name in names {
            let data = self.chunk_store_.get(name.clone());
            let version_handler_sendable = VersionHandlerSendable::new(name, data);
            let payload = maidsafe_types::Payload::new(maidsafe_types::PayloadTypeTag::VersionHandlerAccountTransfer,
                                                       &version_handler_sendable);
            let mut e = cbor::Encoder::from_memory();
            e.encode(&[payload]).unwrap();
            actions.push(MethodCall::Refresh {
                type_tag: version_handler_sendable.type_tag(), from_group: version_handler_sendable.name(),
                payload: e.as_bytes().to_vec()
            });
       }
       self.chunk_store_ = ChunkStore::with_max_disk_usage(1073741824);
       actions
  }

}

#[cfg(test)]
mod test {
 use cbor;
 use super::*;
 use maidsafe_types::*;
 use routing::types::*;
 use routing::error::InterfaceError;
 use routing::NameType;
 use routing::sendable::Sendable;

 #[test]
 fn handle_put_get() {
    let mut version_handler = VersionHandler::new();
    let name = NameType([3u8; 64]);
    let owner = NameType([4u8; 64]);
    let value = vec![NameType([5u8; 64]), NameType([6u8; 64])];
    let sdv = StructuredData::new(name, owner, value);
    let payload = Payload::new(PayloadTypeTag::StructuredData, &sdv);
    let mut encoder = cbor::Encoder::from_memory();
    let encode_result = encoder.encode(&[&payload]);
    assert_eq!(encode_result.is_ok(), true);
    let bytes = array_as_vector(encoder.as_bytes());
    let put_result = version_handler.handle_put(bytes.clone());
    assert_eq!(put_result.is_ok(), true);
    match put_result {
        Err(InterfaceError::Abort) => panic!("Unexpected"),
        Ok(MessageAction::Reply(replied_bytes)) => assert_eq!(replied_bytes, bytes),
        _ => panic!("Unexpected"),
    }

    let data_name = NameType::new(sdv.name().0);
    let get_result = version_handler.handle_get(data_name);
    assert_eq!(get_result.is_err(), false);
    match get_result.ok().unwrap() {
        MessageAction::SendOn(_) => panic!("Unexpected"),
        MessageAction::Reply(x) => {
                let mut d = cbor::Decoder::from_bytes(x);
                let obj_after: Payload = d.decode().next().unwrap().unwrap();
                assert_eq!(obj_after.get_type_tag(), PayloadTypeTag::StructuredData);
                let sdv_after = obj_after.get_data::<StructuredData>();
                assert_eq!(sdv_after.name(), NameType([3u8;64]));
                assert_eq!(sdv_after.owner().unwrap(), NameType([4u8;64]));
                assert_eq!(sdv_after.value().len(), 2);
                assert_eq!(sdv_after.value()[0], NameType([5u8;64]));
                assert_eq!(sdv_after.value()[1], NameType([6u8;64]));
            }
        }
    }

    #[test]
    fn handle_account_transfer() {
        let name = NameType([3u8; 64]);
        let owner = NameType([4u8; 64]);
        let value = vec![NameType([5u8; 64]), NameType([6u8; 64])];
        let sdv = StructuredData::new(name.clone(), owner, value);

        let mut version_handler = VersionHandler::new();
        let payload = Payload::new(PayloadTypeTag::VersionHandlerAccountTransfer,
                                   &VersionHandlerSendable::new(name.clone(), sdv.serialised_contents()));
        version_handler.handle_account_transfer(payload);
        assert_eq!(version_handler.chunk_store_.has_chunk(name), true);
    }

    #[test]
    fn version_handler_sendable_serialisation() {
        let obj_before = VersionHandlerSendable::new(NameType([1u8;64]), vec![2,3,45,5]);

        let mut e = cbor::Encoder::from_memory();
        e.encode(&[&obj_before]).unwrap();

        let mut d = cbor::Decoder::from_bytes(e.as_bytes());
        let obj_after: VersionHandlerSendable = d.decode().next().unwrap().unwrap();

        assert_eq!(obj_before, obj_after);
    }


}
