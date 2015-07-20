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

use routing::NameType;
use routing::data::Data;
use routing::error::{ResponseError, InterfaceError};
use routing::node_interface::{MessageAction, MethodCall};
use routing::sendable::Sendable;
use routing::structured_data::StructuredData;

use chunk_store::ChunkStore;
use transfer_parser::transfer_tags::VERSION_HANDLER_ACCOUNT_TAG;
use utils::{encode, decode};

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
        let sd : StructuredData = try!(decode(&data));
        Ok(MessageAction::Reply(Data::StructuredData(sd)))
    }

    pub fn handle_put(&mut self, structured_data: StructuredData) ->Result<MessageAction, InterfaceError> {
        // TODO: SD using PUT for the first copy, then POST to update and transfer in case of churn
        //       so if the data exists, then the put shall be rejected
        //          if the data does not exist, and the request is not from SDM(i.e. a transfer),
        //              then the post shall be rejected
        //       in addition to above, POST shall check the ownership
        if self.chunk_store_.has_chunk(structured_data.name()) {
            Err(InterfaceError::Response(ResponseError::FailedToStoreData(Data::StructuredData(structured_data))))
        } else {
            let serialised_data = try!(encode(&structured_data));
            self.chunk_store_.put(structured_data.name(), serialised_data);
            Ok(MessageAction::Reply(Data::StructuredData(structured_data)))
        }
    }

    pub fn handle_account_transfer(&mut self, in_coming_sd: Vec<u8>) {
        let sd : StructuredData = match decode(&in_coming_sd) {
            Ok(result) => { result }
            Err(_) => return
        };
        self.chunk_store_.delete(sd.name());
        self.chunk_store_.put(sd.name(), in_coming_sd);
    }

    pub fn retrieve_all_and_reset(&mut self) -> Vec<MethodCall> {
        let names = self.chunk_store_.names();
        let mut actions = Vec::with_capacity(names.len());
        for name in names {
            let data = self.chunk_store_.get(name.clone());
            actions.push(MethodCall::Refresh {
                type_tag: VERSION_HANDLER_ACCOUNT_TAG,
                from_group: name,
                payload: data
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
 use data_parser::Data;
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
    let bytes = sdv.serialised_contents();
    let put_result = version_handler.handle_put(bytes.clone(), sdv.clone());
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
                if let Some(parsed_data) = d.decode().next().and_then(|result| result.ok()) {
                    match parsed_data {
                        Data::Structured(sdv_after) => {
                            assert_eq!(sdv_after.name(), NameType([3u8;64]));
                            assert_eq!(sdv_after.owner().unwrap(), NameType([4u8;64]));
                            assert_eq!(sdv_after.value().len(), 2);
                            assert_eq!(sdv_after.value()[0], NameType([5u8;64]));
                            assert_eq!(sdv_after.value()[1], NameType([6u8;64]));
                        },
                        _ => panic!("Unexpected"),
                    }
                }
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
        version_handler.handle_account_transfer(
            VersionHandlerSendable::new(name.clone(), sdv.serialised_contents()));
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
