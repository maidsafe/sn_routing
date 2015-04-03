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

#![allow(dead_code)]

extern crate routing;
extern crate maidsafe_types;

mod database;

use cbor::{ Decoder };

type CloseGroupDifference = self::routing::types::CloseGroupDifference;
type Address = self::routing::types::Address;

pub struct MaidManager {
  db_ : database::MaidManagerDatabase
}

impl MaidManager {
  pub fn new() -> MaidManager {
    MaidManager { db_: database::MaidManagerDatabase::new() }
  }

  pub fn handle_put(&mut self, from : &routing::types::Address, data : &Vec<u8>) ->Result<routing::Action, routing::RoutingError> {
    let mut d = Decoder::from_bytes(&data[..]);
    let payload: maidsafe_types::Payload = d.decode().next().unwrap().unwrap();
    let mut destinations : Vec<routing::DhtIdentity> = Vec::new();
    match payload.get_type_tag() {
      maidsafe_types::PayloadTypeTag::ImmutableData => {
        let immutable_data : maidsafe_types::ImmutableData = payload.get_data();
        let data_name = self::routing::types::array_as_vector(&immutable_data.get_name().get_id());
        if !self.db_.put_data(from, immutable_data.get_value().len() as u64) {
          return Err(routing::RoutingError::InvalidRequest);
        }
        destinations.push(routing::DhtIdentity { id : immutable_data.get_name().get_id() });
      }
      maidsafe_types::PayloadTypeTag::PublicMaid => {
        // PublicMaid doesn't use any allowance
        destinations.push(routing::DhtIdentity {
            id : payload.get_data::<maidsafe_types::PublicMaid>().get_name().get_id() });
      }
      maidsafe_types::PayloadTypeTag::PublicAnMaid => {
        // PublicAnMaid doesn't use any allowance
        destinations.push(routing::DhtIdentity {
            id : payload.get_data::<maidsafe_types::PublicAnMaid>().get_name().get_id() });
      }
      _ => return Err(routing::RoutingError::InvalidRequest)
    }
    Ok(routing::Action::SendOn(destinations))
  }

}
