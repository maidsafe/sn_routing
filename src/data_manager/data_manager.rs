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

use self::routing::types;

use cbor::{ Decoder };

type CloseGroupDifference = self::routing::types::CloseGroupDifference;
type Address = self::routing::types::Address;

pub struct DataManager {
  db_ : database::DataManagerDatabase,
  // TODO : 1, the population of close_nodes
  //        2, currently defined as RoutingTable to utilise all the algorithm,
  //           ideally shall be only a vector of nodes
  close_nodes_ : routing::routing_table::RoutingTable
}

impl DataManager {
  pub fn new() -> DataManager {
    DataManager { db_: database::DataManagerDatabase::new(),
                  // TODO : own_id of the RoutingTable
                  close_nodes_: routing::routing_table::RoutingTable::new(maidsafe_types::NameType([3u8; 64])) }
  }

  pub fn handle_get(&mut self, name : &routing::types::Identity) ->Result<routing::Action, routing::RoutingError> {
	  let result = self.db_.get_pmid_nodes(name);
	  if result.len() == 0 {
	    return Err(routing::RoutingError::NoData);
	  }
      
	  let mut dest_pmids : Vec<routing::DhtIdentity> = Vec::new();
	  for pmid in result.iter() {
        dest_pmids.push(routing::DhtIdentity { id: types::vector_as_u8_64_array(pmid.clone()) });
	  }
	  Ok(routing::Action::SendOn(dest_pmids))
  }

  pub fn handle_put(&mut self, data : &Vec<u8>) ->Result<routing::Action, routing::RoutingError> {
    // TODO the data_type shall be passed down or data needs to be name + content
    //      here assuming data is serialised_data of ImmutableData
    let mut d = Decoder::from_bytes(&data[..]);
    let immutable_data: maidsafe_types::ImmutableData = d.decode().next().unwrap().unwrap();
    let data_name = self::routing::types::array_as_vector(&immutable_data.get_name().get_id());
    if self.db_.exist(&data_name) {
      return Err(routing::RoutingError::Success);
    }
    let close_nodes = self.close_nodes_.target_nodes(immutable_data.get_name().clone());
    let mut pmid_nodes : self::routing::types::PmidNodes = Vec::new();
    let mut dest_pmids : Vec<routing::DhtIdentity> = Vec::new();
    for node in close_nodes.iter() {
      pmid_nodes.push(self::routing::types::array_as_vector(&node.fob.id.get_id()));
      dest_pmids.push(routing::DhtIdentity { id: node.fob.id.get_id() });
    }
    self.db_.put_pmid_nodes(&data_name, pmid_nodes);
    Ok(routing::Action::SendOn(dest_pmids))
  }
}

mod test {
  extern crate cbor;
  extern crate maidsafe_types;
  extern crate rand;
  extern crate routing;
  use super::*;
  use self::maidsafe_types::*;
  use self::routing::types::*;

  pub fn generate_random_bytes(size : u32) -> Vec<u8> {
    let mut random_bytes: Vec<u8> = vec![];
    for _ in (0..size) {
      random_bytes.push(rand::random::<u8>());
    }
    random_bytes
  }

  #[test]
  fn handle_put_get() {
    let mut data_manager = DataManager::new();
    let name = NameType([3u8; 64]);
    let value = generate_random_bytes(1024);
    let data = ImmutableData::new(name, value);
    let mut encoder = cbor::Encoder::from_memory();

    encoder.encode(&[&data]);

    let result = data_manager.handle_put(&array_as_vector(encoder.as_bytes()));
    assert_eq!(result.is_err(), false);

    let data_name = array_as_vector(&data.get_name().get_id());
    let result = data_manager.handle_get(&data_name);
    // FIXME see TODO in DataManager struct
    // assert_eq!(result.is_err(), false); error no pmid nodes
  }
}
