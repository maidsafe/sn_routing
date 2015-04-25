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

use routing;
use lru_time_cache::LruCache;
use cbor;
use cbor::CborTagEncode;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};

type Identity = routing::NameType; // name of the chunk
use routing::types::PmidNode;
use routing::types::PmidNodes;
use routing::NameType;
use routing::sendable::Sendable;

pub struct DataManagerDatabase {
  storage : LruCache<Identity, PmidNodes>
}

pub struct DataManagerAccount {
  name: NameType,
  pmid_nodes: Vec<NameType>
}

impl Sendable for DataManagerAccount {
    fn name(&self) -> NameType {
        self.name.clone()
    }

    fn type_tag(&self)->u64 {
        501
    }

    fn serialised_contents(&self)->Vec<u8> {
        let mut e = cbor::Encoder::from_memory();
        e.encode(&[&self]).unwrap();
        e.into_bytes()
    }
}

impl Encodable for DataManagerAccount {
    fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {        
        CborTagEncode::new(5001, &(
            self.name.clone(),
            self.pmid_nodes.clone())).encode(e)
    }
}

impl Decodable for DataManagerAccount {
    fn decode<D: Decoder>(d: &mut D)-> Result<DataManagerAccount, D::Error> {
        try!(d.read_u64());
        let (name, pmid_nodes) : (NameType, Vec<NameType>) = try!(Decodable::decode(d));    
        Ok(DataManagerAccount{ name: name, pmid_nodes: pmid_nodes })
    }
}

impl DataManagerDatabase {
  pub fn new () -> DataManagerDatabase {
    DataManagerDatabase { storage: LruCache::with_capacity(10000) }
  }

  pub fn exist(&mut self, name : &Identity) -> bool {
    self.storage.get(name.clone()).is_some()
  }

  pub fn put_pmid_nodes(&mut self, name : &Identity, pmid_nodes: PmidNodes) {
    self.storage.add(name.clone(), pmid_nodes.clone());
  }

  pub fn add_pmid_node(&mut self, name : &Identity, pmid_node: PmidNode) {
    let entry = self.storage.remove(name.clone());
  	if entry.is_some() {
  	  let mut tmp = entry.unwrap();
  	  for i in 0..tmp.len() {
  	  	if tmp[i] == pmid_node {
  	  	  return;
  	  	}
  	  }
  	  tmp.push(pmid_node);
      self.storage.add(name.clone(), tmp);
  	} else {
      self.storage.add(name.clone(), vec![pmid_node]);
  	}
  }

  pub fn remove_pmid_node(&mut self, name : &Identity, pmid_node: PmidNode) {
    let entry = self.storage.remove(name.clone());
  	if entry.is_some() {
  	  let mut tmp = entry.unwrap();
  	  for i in 0..tmp.len() {
  	  	if tmp[i] == pmid_node {
  	  	  tmp.remove(i);
          break;
  	  	}
  	  }
      self.storage.add(name.clone(), tmp);
  	}
  }

  pub fn get_pmid_nodes(&mut self, name : &Identity) -> PmidNodes {
    let entry = self.storage.get(name.clone());
  	if entry.is_some() {
  	  entry.unwrap().clone()
  	} else {
  	  Vec::<PmidNode>::new()
  	}
  }

  pub fn retrieve_all_and_reset(&mut self) -> Vec<DataManagerAccount> {
    let data: Vec<(Identity, PmidNodes)> = self.storage.retrieve_all();
    let mut sendable_data: Vec<DataManagerAccount> = Vec::with_capacity(data.len());
    self.storage = LruCache::with_capacity(10000);
    for acc in data {
      sendable_data.push(DataManagerAccount {
        name : acc.0,
        pmid_nodes : acc.1,
      });
    }
    sendable_data
  }

}

#[cfg(test)]
mod test {
  use cbor;
  use maidsafe_types;
  use rand;
  use routing;
  use super::*;  
  use maidsafe_types::ImmutableData;
  use routing::NameType;
  use routing::types::{generate_random_vec_u8};
  use routing::test_utils::Random;
  use routing::sendable::Sendable;
  
  #[test]
  fn exist() {
    let mut db = DataManagerDatabase::new();
    let name = NameType([3u8; 64]);
    let value = generate_random_vec_u8(1024);
    let data = ImmutableData::new(value);
    let mut pmid_nodes : Vec<NameType> = vec![];

    for _ in 0..4 {
      pmid_nodes.push(Random::generate_random());
    }

    let data_name = data.name();
    assert_eq!(db.exist(&data_name), false);
    db.put_pmid_nodes(&data_name, pmid_nodes);
    assert_eq!(db.exist(&data_name), true);
  }

  #[test]
  fn put() {
    let mut db = DataManagerDatabase::new();
    let name = NameType([3u8; 64]);
    let value = generate_random_vec_u8(1024);
    let data = ImmutableData::new(value);
    let data_name = data.name();
    let mut pmid_nodes : Vec<NameType> = vec![];

    for _ in 0..4 {
      pmid_nodes.push(Random::generate_random());
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
    let name = NameType([3u8; 64]);
    let value = generate_random_vec_u8(1024);
    let data = ImmutableData::new(value);
    let data_name = data.name();
    let mut pmid_nodes : Vec<NameType> = vec![];

    for _ in 0..4 {
      pmid_nodes.push(Random::generate_random());
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
    let name = NameType([3u8; 64]);
    let value = generate_random_vec_u8(1024);
    let data = ImmutableData::new(value);
    let data_name = data.name();
    let mut pmid_nodes : Vec<NameType> = vec![];
    let mut new_pmid_nodes : Vec<NameType> = vec![];

    for _ in 0..4 {
      pmid_nodes.push(Random::generate_random());
      new_pmid_nodes.push(Random::generate_random());
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
