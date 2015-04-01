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

extern crate lru_cache;

extern crate routing;

use self::lru_cache::LruCache;

type Identity = self::routing::types::Identity; // name of the chunk
type PmidNode = self::routing::types::PmidNode;
type PmidNodes = self::routing::types::PmidNodes;

pub struct DataManagerDatabase {
  storage : LruCache<Identity, PmidNodes>
}

impl DataManagerDatabase {
  pub fn new () -> DataManagerDatabase {
    DataManagerDatabase { storage: LruCache::new(10000) }
  }

  pub fn exist(&mut self, name : &Identity) -> bool {
    self.storage.get(name).is_some()
  }

  pub fn put_pmid_nodes(&mut self, name : &Identity, pmid_nodes: PmidNodes) {
  	self.storage.insert(name.clone(), pmid_nodes.clone());
  }

  pub fn add_pmid_node(&mut self, name : &Identity, pmid_node: PmidNode) {
  	let entry = self.storage.remove(&name);
  	if entry.is_some() {
  	  let mut tmp = entry.unwrap();
  	  for i in 0..tmp.len() {
  	  	if tmp[i] == pmid_node {
  	  	  return;
  	  	}
  	  }
  	  tmp.push(pmid_node);
  	  self.storage.insert(name.clone(), tmp);
  	} else {
  	  self.storage.insert(name.clone(), vec![pmid_node]);
  	}
  }

  pub fn remove_pmid_node(&mut self, name : &Identity, pmid_node: PmidNode) {
  	let entry = self.storage.remove(&name);
  	if entry.is_some() {
  	  let mut tmp = entry.unwrap();
  	  for i in 0..tmp.len() {
  	  	if tmp[i] == pmid_node {
  	  	  tmp.remove(i);
          break;
  	  	}
  	  }
  	  self.storage.insert(name.clone(), tmp);
  	}
  }

  pub fn get_pmid_nodes(&mut self, name : &Identity) -> PmidNodes {
  	let entry = self.storage.get(&name);
  	if entry.is_some() {
  	  entry.unwrap().clone()
  	} else {
  	  Vec::<PmidNode>::new()
  	}
  }

}

mod test {
  extern crate cbor;
  extern crate maidsafe_types;
  extern crate rand;
  extern crate routing;
  use super::*;
  use self::maidsafe_types::ImmutableData;
  use self::routing::types::*;

  pub fn generate_random_bytes(size : u32) -> Vec<u8> {
    let mut random_bytes: Vec<u8> = vec![];
    for _ in (0..size) {
      random_bytes.push(rand::random::<u8>());
    }
    random_bytes
  }

  #[test]
  fn exist() {
    let mut db = DataManagerDatabase::new();
    let name = maidsafe_types::NameType([3u8; 64]);
    let value = generate_random_bytes(1024);
    let data = ImmutableData::new(name, value);
    let mut pmid_nodes : Vec<Address> = vec![];

    for _ in 0..4 {
      pmid_nodes.push(generate_random_bytes(64));
    }

    let data_name = array_as_vector(&data.get_name().get_id());
    assert_eq!(db.exist(&data_name), false);
    db.put_pmid_nodes(&data_name, pmid_nodes);
    assert_eq!(db.exist(&data_name), true);
  }

  #[test]
  fn put() {
    let mut db = DataManagerDatabase::new();
    let name = maidsafe_types::NameType([3u8; 64]);
    let value = generate_random_bytes(1024);
    let data = ImmutableData::new(name, value);
    let data_name = array_as_vector(&data.get_name().get_id());
    let mut pmid_nodes : Vec<Address> = vec![];

    for _ in 0..4 {
      pmid_nodes.push(generate_random_bytes(64));
    }

    let result = db.get_pmid_nodes(&data_name);
    assert_eq!(result.len(), 0);

    db.put_pmid_nodes(&data_name, pmid_nodes.clone());

    let result = db.get_pmid_nodes(&data_name);
    assert_eq!(result.len(), pmid_nodes.len());
  }

  #[test]
  fn remove_pmid() {
    let mut db = DataManagerDatabase::new();
    let name = maidsafe_types::NameType([3u8; 64]);
    let value = generate_random_bytes(1024);
    let data = ImmutableData::new(name, value);
    let data_name = array_as_vector(&data.get_name().get_id());
    let mut pmid_nodes : Vec<Address> = vec![];

    for _ in 0..4 {
      pmid_nodes.push(generate_random_bytes(64));
    }

    db.put_pmid_nodes(&data_name, pmid_nodes.clone());
    let result = db.get_pmid_nodes(&data_name);
    assert_eq!(result, pmid_nodes);

    db.remove_pmid_node(&data_name, pmid_nodes[0].clone());

    let result = db.get_pmid_nodes(&data_name);
    assert_eq!(result.len(), 3);
    for index in 0..result.len() {
      assert!(result[index] != pmid_nodes[0]);
    }
  }

  #[test]
  fn replace_pmids() {
    let mut db = DataManagerDatabase::new();
    let name = maidsafe_types::NameType([3u8; 64]);
    let value = generate_random_bytes(1024);
    let data = ImmutableData::new(name, value);
    let data_name = array_as_vector(&data.get_name().get_id());
    let mut pmid_nodes : Vec<Address> = vec![];
    let mut new_pmid_nodes : Vec<Address> = vec![];

    for _ in 0..4 {
      pmid_nodes.push(generate_random_bytes(64));
      new_pmid_nodes.push(generate_random_bytes(64));
    }

    db.put_pmid_nodes(&data_name, pmid_nodes.clone());
    let result = db.get_pmid_nodes(&data_name);
    assert_eq!(result, pmid_nodes);
    assert!(result != new_pmid_nodes);

    for index in 0..4 {
      db.remove_pmid_node(&data_name, pmid_nodes[index].clone());
      db.add_pmid_node(&data_name, new_pmid_nodes[index].clone());
    }

    let result = db.get_pmid_nodes(&data_name);
    assert_eq!(result, new_pmid_nodes);
    assert!(result != pmid_nodes);
  }
}
