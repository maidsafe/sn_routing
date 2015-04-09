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

use std::cmp;

use self::routing::types::DhtId;
use self::routing::routing_table;

use cbor::{ Decoder };

type CloseGroupDifference = self::routing::types::CloseGroupDifference;
type Address = DhtId;

pub struct DataManager {
  db_ : database::DataManagerDatabase
}

impl DataManager {
  pub fn new() -> DataManager { DataManager { db_: database::DataManagerDatabase::new() } }

  pub fn handle_get(&mut self, name : &DhtId) ->Result<routing::Action, routing::RoutingError> {
	  let result = self.db_.get_pmid_nodes(name);
	  if result.len() == 0 {
	    return Err(routing::RoutingError::NoData);
	  }
      
	  let mut dest_pmids : Vec<DhtId> = Vec::new();
	  for pmid in result.iter() {
        dest_pmids.push(pmid.clone());
	  }
	  Ok(routing::Action::SendOn(dest_pmids))
  }

  pub fn handle_put(&mut self, data : &Vec<u8>, nodes_in_table : &mut Vec<DhtId>) ->Result<routing::Action, routing::RoutingError> {
    let mut name : maidsafe_types::NameType;
    let mut d = Decoder::from_bytes(&data[..]);
    let payload: maidsafe_types::Payload = d.decode().next().unwrap().unwrap();
    match payload.get_type_tag() {
      maidsafe_types::PayloadTypeTag::ImmutableData => {
        name = payload.get_data::<maidsafe_types::ImmutableData>().get_name().clone();
      }
      maidsafe_types::PayloadTypeTag::PublicMaid => {
        name = payload.get_data::<maidsafe_types::PublicMaid>().get_name().clone();
      }
      maidsafe_types::PayloadTypeTag::PublicAnMaid => {
        name = payload.get_data::<maidsafe_types::PublicAnMaid>().get_name().clone();
      }
      _ => return Err(routing::RoutingError::InvalidRequest)
    }

    let data_name = DhtId::new(name.get_id());
    if self.db_.exist(&data_name) {
      return Err(routing::RoutingError::Success);
    }

    nodes_in_table.sort_by(|a, b|
        if routing_table::RoutingTable::closer_to_target(&a, &b, &data_name) {
          cmp::Ordering::Less
        } else {
          cmp::Ordering::Greater
        });
    let pmid_nodes_num = cmp::min(nodes_in_table.len(), routing_table::PARALLELISM);
    let mut dest_pmids : Vec<DhtId> = Vec::new();
    for index in 0..pmid_nodes_num {
      dest_pmids.push(nodes_in_table[index].clone());
    }
    self.db_.put_pmid_nodes(&data_name, dest_pmids.clone());
    Ok(routing::Action::SendOn(dest_pmids))
  }
}

#[cfg(test)]
mod test {
  extern crate cbor;
  extern crate maidsafe_types;
  extern crate routing;
  use super::*;
  use self::maidsafe_types::*;
  use self::routing::types::*;
  use self::routing::routing_table;

  #[test]
  fn handle_put_get() {
    let mut data_manager = DataManager::new();
    let name = NameType([3u8; 64]);
    let value = routing::types::generate_random_vec_u8(1024);
    let data = ImmutableData::new(name, value);
    let payload = Payload::new(PayloadTypeTag::ImmutableData, &data);
    let mut encoder = cbor::Encoder::from_memory();
    let encode_result = encoder.encode(&[&payload]);
    assert_eq!(encode_result.is_ok(), true);
    let mut nodes_in_table = vec![DhtId::new([1u8; 64]), DhtId::new([2u8; 64]), DhtId::new([3u8; 64]), DhtId::new([4u8; 64]),
                                  DhtId::new([5u8; 64]), DhtId::new([6u8; 64]), DhtId::new([7u8; 64]), DhtId::new([8u8; 64])];
    let put_result = data_manager.handle_put(&array_as_vector(encoder.as_bytes()), &mut nodes_in_table);
    assert_eq!(put_result.is_err(), false);
    match put_result.ok().unwrap() {
      routing::Action::SendOn(ref x) => {
        assert_eq!(x.len(), routing_table::PARALLELISM);
        assert_eq!(x[0].0, [3u8; 64].to_vec());
        assert_eq!(x[1].0, [2u8; 64].to_vec());
        assert_eq!(x[2].0, [1u8; 64].to_vec());
        assert_eq!(x[3].0, [7u8; 64].to_vec());
      }
      routing::Action::Reply(x) => panic!("Unexpected"),
    }

    let data_name = DhtId::new(data.get_name().get_id());
    let get_result = data_manager.handle_get(&data_name);
    assert_eq!(get_result.is_err(), false);
    match get_result.ok().unwrap() {
      routing::Action::SendOn(ref x) => {
        assert_eq!(x.len(), routing_table::PARALLELISM);
        assert_eq!(x[0].0, [3u8; 64].to_vec());
        assert_eq!(x[1].0, [2u8; 64].to_vec());
        assert_eq!(x[2].0, [1u8; 64].to_vec());
        assert_eq!(x[3].0, [7u8; 64].to_vec());
      }
      routing::Action::Reply(x) => panic!("Unexpected"),
    }
  }
}
