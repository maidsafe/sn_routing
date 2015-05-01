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

use cbor::{ Decoder };
use routing;
use routing::NameType;
use maidsafe_types;
use routing::sendable::Sendable;
pub use self::database::MaidManagerAccountWrapper;

type Address = NameType;

pub struct MaidManager {
  db_ : database::MaidManagerDatabase
}

impl MaidManager {
  pub fn new() -> MaidManager {
    MaidManager { db_: database::MaidManagerDatabase::new() }
  }

  pub fn handle_put(&mut self, from : &NameType, data : &Vec<u8>) ->Result<routing::Action, routing::RoutingError> {
    let mut d = Decoder::from_bytes(&data[..]);
    let payload: maidsafe_types::Payload = d.decode().next().unwrap().unwrap();
    let mut destinations : Vec<NameType> = Vec::new();
    match payload.get_type_tag() {
      maidsafe_types::PayloadTypeTag::ImmutableData => {
        let immutable_data : maidsafe_types::ImmutableData = payload.get_data();
        let data_name = routing::types::array_as_vector(&immutable_data.name().get_id());
        if !self.db_.put_data(from, immutable_data.get_value().len() as u64) {
          return Err(routing::RoutingError::InvalidRequest);
        }
        destinations.push(NameType::new(immutable_data.name().get_id()));
      }
      maidsafe_types::PayloadTypeTag::PublicMaid => {
        // PublicMaid doesn't use any allowance
        destinations.push(NameType::new(payload.get_data::<maidsafe_types::PublicMaid>().name().get_id()));
      }
      maidsafe_types::PayloadTypeTag::PublicAnMaid => {
        // PublicAnMaid doesn't use any allowance
        destinations.push(NameType::new(payload.get_data::<maidsafe_types::PublicAnMaid>().name().get_id()));
      }
      _ => return Err(routing::RoutingError::InvalidRequest)
    }
    Ok(routing::Action::SendOn(destinations))
  }

  pub fn retrieve_all_and_reset(&mut self) -> Vec<RoutingNodeAction> {
    self.db_.retrieve_all_and_reset()
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
    fn handle_put() {
        let mut maid_manager = MaidManager::new();
        let from: NameType = routing::test_utils::Random::generate_random();
        let name = NameType([3u8; 64]);
        let value = routing::types::generate_random_vec_u8(1024);
        let data = ImmutableData::new(value);
        let payload = Payload::new(PayloadTypeTag::ImmutableData, &data);
        let mut encoder = cbor::Encoder::from_memory();
        let encode_result = encoder.encode(&[&payload]);
        assert_eq!(encode_result.is_ok(), true);
        let put_result = maid_manager.handle_put(&from, &array_as_vector(encoder.as_bytes()));
        assert_eq!(put_result.is_err(), false);
        match put_result.ok().unwrap() {
            routing::Action::SendOn(ref x) => {
                assert_eq!(x.len(), 1);
                assert_eq!(x[0], data.name());
            }
            routing::Action::Reply(x) => panic!("Unexpected"),
        }
    }
}
