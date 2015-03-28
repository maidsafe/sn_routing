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

extern crate Routing;

use self::lru_cache::LruCache;

type Identity = self::Routing::types::Identity; // name of the chunk
type PmidNode = self::Routing::types::PmidNode;
type PmidNodes = self::Routing::types::PmidNodes;

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
