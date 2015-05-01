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

use routing::generic_sendable_type;
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

/// PmidManagerAccountWrapper implemets the sendable trait from routing, thus making it transporatble
/// across through the routing layer
#[derive(RustcEncodable, RustcDecodable, PartialEq, Eq, Debug)]
pub struct DataManagerWrapper {
    name: NameType,
    tag: u64,
    pmids: PmidNodes
}

impl DataManagerWrapper {
    pub fn new(name: routing::NameType, account: PmidNodes) -> DataManagerWrapper {
        DataManagerWrapper {
            name: name,
            tag: 202, // FIXME : Change once the tag is freezed
            pmids: account
        }
    }

    pub fn get_pmids(&self) -> PmidNodes {
        self.pmids.clone()
    }
}

impl Clone for DataManagerWrapper {
    fn clone(&self) -> Self {
        DataManagerWrapper::new(self.name.clone(), self.pmids.clone())
    }
}

impl Sendable for DataManagerWrapper {
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

    fn refresh(&self)->bool {
        true
    }

    fn merge<'a, I>(responses: I) -> Option<Self> where I: Iterator<Item=&'a Self> {
        // let mut tmp_wrapper: PmidManagerAccountWrapper;
        // let mut offered_space: Vec<u64> = Vec::new();
        // let mut lost_total_size: Vec<u64> = Vec::new();
        // let mut stored_total_size: Vec<u64> = Vec::new();
        // for value in responses {
        //     let mut d = cbor::Decoder::from_bytes(value.serialised_contents());
        //     tmp_wrapper = d.decode().next().unwrap().unwrap();
        //     offered_space.push(tmp_wrapper.get_account().get_offered_space());
        //     lost_total_size.push(tmp_wrapper.get_account().get_lost_total_size());
        //     stored_total_size.push(tmp_wrapper.get_account().get_stored_total_size());
        // }
        // assert!(offered_space.len() < (GROUP_SIZE as usize + 1) / 2);
        // Some(PmidManagerAccountWrapper::new(routing::NameType([0u8;64]), PmidManagerAccount {
        //     offered_space : median(&offered_space),
        //     lost_total_size: median(&lost_total_size),
        //     stored_total_size: median(&stored_total_size)
        // }))
        None
    }
}

pub struct DataManagerDatabase {
    storage : LruCache<Identity, PmidNodes>
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

    pub fn retrieve_all_and_reset(&mut self) -> Vec<DataManagerWrapper> {
        let data: Vec<(Identity, PmidNodes)> = self.storage.retrieve_all();
        let mut sendable_data = Vec::<DataManagerWrapper>::with_capacity(data.len());
        for element in data {
            sendable_data.push(DataManagerWrapper::new(element.0, element.1));
        }
        self.storage = LruCache::with_capacity(10000);
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
