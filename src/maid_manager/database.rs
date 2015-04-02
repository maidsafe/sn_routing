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

type Identity = self::routing::types::Address; // maid node address

pub struct MaidManagerAccount {
  data_stored : u64,
  space_available : u64
}

impl MaidManagerAccount {
  pub fn new() -> MaidManagerAccount {
    MaidManagerAccount { data_stored: 0, space_available: 0 }
  }

  pub fn put_data(&mut self, size : u64) -> bool {
    if size > self.space_available {
      return false;
    }
    self.data_stored += size;
    self.space_available -= size;
    true
  }

  pub fn delete_data(&mut self, size : u64) {
    if self.data_stored < size {
      self.space_available += self.data_stored;
      self.data_stored = 0;
    } else {
      self.data_stored -= size;
      self.space_available += size;
    }
  }

}

pub struct MaidManagerDatabase {
  storage : LruCache<Identity, MaidManagerAccount>
}

impl MaidManagerDatabase {
  pub fn new () -> MaidManagerDatabase {
    MaidManagerDatabase { storage: LruCache::new(10000) }
  }

  pub fn exist(&mut self, name : &Identity) -> bool {
    self.storage.get(name).is_some()
  }

  pub fn put_data(&mut self, name : &Identity, size: u64) -> bool {
    let mut tmp = MaidManagerAccount::new();
  	let entry = self.storage.remove(&name);
  	if entry.is_some() {
  	  tmp = entry.unwrap();
  	} 
    let result = tmp.put_data(size);
    self.storage.insert(name.clone(), tmp);
    result
  }

  pub fn delete_data(&mut self, name : &Identity, size: u64) {
    let entry = self.storage.remove(&name);
    if entry.is_some() {
      let mut tmp = entry.unwrap();
      tmp.delete_data(size);
      self.storage.insert(name.clone(), tmp);
    }
  }

}
