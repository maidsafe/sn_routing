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

mod database;

use cbor::Decoder;

use routing::error::{ResponseError, InterfaceError};
use routing::NameType;
use routing::node_interface::MethodCall;
use routing::sendable::Sendable;
use routing::types::{MessageAction, DestinationAddress};

use data_parser::Data;

pub use self::database::{PmidManagerAccountWrapper, PmidManagerAccount};

pub struct PmidManager {
    db_ : database::PmidManagerDatabase
}

impl PmidManager {
    pub fn new() -> PmidManager {
        PmidManager {
            db_: database::PmidManagerDatabase::new()
        }
    }

    pub fn handle_put(&mut self, dest_address: &DestinationAddress,
                      data: &Vec<u8>) ->Result<MessageAction, InterfaceError> {
        if self.db_.put_data(&dest_address.dest, data.len() as u64) {
            let mut destinations : Vec<NameType> = Vec::new();
            destinations.push(dest_address.dest.clone());
            Ok(MessageAction::SendOn(destinations))
        } else {
            Err(From::from(ResponseError::InvalidRequest))
        }
    }

    pub fn handle_put_response(&mut self, from_address: &NameType,
                               response: &Result<Vec<u8>, ResponseError>) -> MethodCall {
        // TODO: here the assumption is pmid_node's routing will send back the whole original
        //       payload data, when the return from pmid_node->handle_put() is Err(InvalidRequest).
        //       The content in response is payload for the failing to store data or the removed
        //       Sacrificial copy.
        if response.is_err() {
            return MethodCall::None;
        }

        let data = response.clone().unwrap();
        self.db_.delete_data(from_address, data.len() as u64);

        let mut decoder = Decoder::from_bytes(&data[..]);
        if let Some(parsed_data) = decoder.decode().next().and_then(|result| result.ok()) {
            match parsed_data {
                Data::Immutable(parsed) => return MethodCall::SendOn { destination: parsed.name() },
                Data::ImmutableBackup(parsed) =>
                    return MethodCall::SendOn { destination: parsed.name() },
                Data::ImmutableSacrificial(parsed) =>
                    return MethodCall::SendOn { destination: parsed.name() },
                _ => return MethodCall::None,
            }
        }

        MethodCall::None
    }

    pub fn handle_account_transfer(&mut self, merged_account: PmidManagerAccountWrapper) {
        self.db_.handle_account_transfer(&merged_account);
    }

    pub fn retrieve_all_and_reset(&mut self, close_group: &Vec<NameType>) -> Vec<MethodCall> {
        self.db_.retrieve_all_and_reset(close_group)
    }
}

#[cfg(test)]
mod test {
  use cbor;
  use routing;
  use super::PmidManager;
  use maidsafe_types::*;
  use routing::types::*;
  use super::database::{PmidManagerAccount, PmidManagerAccountWrapper};

  #[test]
  fn handle_put() {
    let mut pmid_manager = PmidManager::new();
    let dest = DestinationAddress { dest: routing::test_utils::Random::generate_random(), relay_to: None };
    let value = generate_random_vec_u8(1024);
    let data = ImmutableData::new(value);
    let payload = Payload::new(PayloadTypeTag::ImmutableData, &data);
    let mut encoder = cbor::Encoder::from_memory();
    let encode_result = encoder.encode(&[&payload]);
    assert_eq!(encode_result.is_ok(), true);

    let put_result = pmid_manager.handle_put(&dest, &array_as_vector(encoder.as_bytes()));
    assert_eq!(put_result.is_err(), false);
    match put_result.ok().unwrap() {
      MessageAction::SendOn(ref x) => {
        assert_eq!(x.len(), 1);
        assert_eq!(x[0], dest.dest);
      }
      MessageAction::Reply(_) => panic!("Unexpected"),
    }
  }

    #[test]
    fn handle_account_transfer() {
        let mut pmid_manager = PmidManager::new();
        let name : routing::NameType = routing::test_utils::Random::generate_random();
        let account_wrapper = PmidManagerAccountWrapper::new(name.clone(), PmidManagerAccount::new());
        let payload = Payload::new(PayloadTypeTag::PmidManagerAccountTransfer, &account_wrapper);
        pmid_manager.handle_account_transfer(payload);
        assert_eq!(pmid_manager.db_.exist(&name), true);
    }
}
