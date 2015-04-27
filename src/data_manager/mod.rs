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

mod database;

use std::cmp;
use routing;
use routing::NameType;
use maidsafe_types;
use cbor::{ Decoder };
use routing::sendable::Sendable;
pub use self::database::DataManagerAccount;
type Address = NameType;

pub static PARALLELISM: usize = 4;

pub struct DataManager {
  db_ : database::DataManagerDatabase
}

impl DataManager {
  pub fn new() -> DataManager { DataManager { db_: database::DataManagerDatabase::new() } }

  pub fn handle_get(&mut self, name : &NameType) ->Result<routing::Action, routing::RoutingError> {
	  let result = self.db_.get_pmid_nodes(name);
	  if result.len() == 0 {
	    return Err(routing::RoutingError::NoData);
	  }
      
	  let mut dest_pmids : Vec<NameType> = Vec::new();
	  for pmid in result.iter() {
        dest_pmids.push(pmid.clone());
	  }
	  Ok(routing::Action::SendOn(dest_pmids))
  }

  pub fn handle_put(&mut self, data : &Vec<u8>, nodes_in_table : &mut Vec<NameType>) ->Result<routing::Action, routing::RoutingError> {    
    let mut name : routing::NameType;
    let mut d = Decoder::from_bytes(&data[..]);
    let payload: maidsafe_types::Payload = d.decode().next().unwrap().unwrap();
    match payload.get_type_tag() {
      maidsafe_types::PayloadTypeTag::ImmutableData => {
        name = payload.get_data::<maidsafe_types::ImmutableData>().name();
      }
      maidsafe_types::PayloadTypeTag::PublicMaid => {
        name = payload.get_data::<maidsafe_types::PublicMaid>().name();
      }
      maidsafe_types::PayloadTypeTag::PublicAnMaid => {
        name = payload.get_data::<maidsafe_types::PublicAnMaid>().name();
      }
      _ => return Err(routing::RoutingError::InvalidRequest)
    }

    let data_name = NameType::new(name.get_id());
    if self.db_.exist(&data_name) {
      return Err(routing::RoutingError::Success);
    }

    nodes_in_table.sort_by(|a, b|
        if super::vault::closer_to_target(&a, &b, &data_name) {
          cmp::Ordering::Less
        } else {
          cmp::Ordering::Greater
        });
    let pmid_nodes_num = cmp::min(nodes_in_table.len(), PARALLELISM);
    let mut dest_pmids : Vec<NameType> = Vec::new();
    for index in 0..pmid_nodes_num {
      dest_pmids.push(nodes_in_table[index].clone());
    }
    self.db_.put_pmid_nodes(&data_name, dest_pmids.clone());
    Ok(routing::Action::SendOn(dest_pmids))
  }

  pub fn retrieve_all_and_reset(&mut self) -> Vec<DataManagerAccount> {
    self.db_.retrieve_all_and_reset()
  }
}

#[cfg(test)]
mod test {
  extern crate cbor;
  extern crate maidsafe_types;
  extern crate routing;

  use super::{DataManager};
  use maidsafe_types::{ImmutableData, PayloadTypeTag, Payload};
  use routing::types::{array_as_vector};
  use routing::NameType;
  use routing::sendable::Sendable;

  #[test]
  fn handle_put_get() {
    let mut data_manager = DataManager::new();
    let value = routing::types::generate_random_vec_u8(1024);
    let data = ImmutableData::new(value);
    let payload = Payload::new(PayloadTypeTag::ImmutableData, &data);
    let mut encoder = cbor::Encoder::from_memory();
    let encode_result = encoder.encode(&[&payload]);
    assert_eq!(encode_result.is_ok(), true);
    let mut nodes_in_table = vec![NameType::new([1u8; 64]), NameType::new([2u8; 64]), NameType::new([3u8; 64]), NameType::new([4u8; 64]),
                                  NameType::new([5u8; 64]), NameType::new([6u8; 64]), NameType::new([7u8; 64]), NameType::new([8u8; 64])];
    let put_result = data_manager.handle_put(&array_as_vector(encoder.as_bytes()), &mut nodes_in_table);
    assert_eq!(put_result.is_err(), false);
    match put_result.ok().unwrap() {
      routing::Action::SendOn(ref x) => {
        assert_eq!(x.len(), super::PARALLELISM);
        assert_eq!(x[0], nodes_in_table[0]);
        assert_eq!(x[1], nodes_in_table[1]);
        assert_eq!(x[2], nodes_in_table[2]);
        assert_eq!(x[3], nodes_in_table[3]);
      }
      routing::Action::Reply(_) => panic!("Unexpected"),
    }
      let data_name = NameType::new(data.name().get_id());
    let get_result = data_manager.handle_get(&data_name);
     assert_eq!(get_result.is_err(), false);
     match get_result.ok().unwrap() {
       routing::Action::SendOn(ref x) => {
         assert_eq!(x.len(), super::PARALLELISM);
         assert_eq!(x[0], nodes_in_table[0]);
         assert_eq!(x[1], nodes_in_table[1]);
         assert_eq!(x[2], nodes_in_table[2]);
         assert_eq!(x[3], nodes_in_table[3]);
       }
       routing::Action::Reply(_) => panic!("Unexpected"),
     }
   }
}
