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

type Identity = self::routing::types::Address; // pmidnode address

pub struct PmidManagerAccount {
  stored_total_size : u64,
  lost_total_size : u64,
  offered_space : u64
}

impl PmidManagerAccount {
  pub fn new() -> PmidManagerAccount {
    // FIXME : to bypass the AccountCreation process for simple network, capacity is assumed automatically
    PmidManagerAccount { stored_total_size: 0, lost_total_size: 0, offered_space: 1073741824 }
  }

  pub fn put_data(&mut self, size : u64) -> bool {
    if (self.stored_total_size + size) > self.offered_space {
      return false;
    }
    self.stored_total_size += size;
    true
  }

  pub fn delete_data(&mut self, size : u64) {
    if self.stored_total_size < size {
      self.stored_total_size = 0;
    } else {
      self.stored_total_size -= size;
    }
  }

  pub fn handle_lost_data(&mut self, size : u64) {
    self.delete_data(size);
    self.lost_total_size += size;
  }

  pub fn handle_falure(&mut self, size : u64) {
    self.handle_lost_data(size);
  }

  pub fn set_available_size(&mut self, available_size : u64) {
    self.offered_space = available_size;
  }

  pub fn update_account(&mut self, diff_size : u64) {
    if self.stored_total_size < diff_size {
      self.stored_total_size = 0;
    } else {
      self.stored_total_size -= diff_size;
    }
    self.lost_total_size += diff_size;
  }
}

pub struct PmidManagerDatabase {
  storage : LruCache<Identity, PmidManagerAccount>
}

impl PmidManagerDatabase {
  pub fn new () -> PmidManagerDatabase {
    PmidManagerDatabase { storage: LruCache::new(10000) }
  }

  pub fn exist(&mut self, name : &Identity) -> bool {
    self.storage.get(name).is_some()
  }

  pub fn put_data(&mut self, name : &Identity, size: u64) -> bool {
    let mut tmp = PmidManagerAccount::new();
  	let entry = self.storage.remove(&name);
  	if entry.is_some() {
  	  tmp = entry.unwrap();
  	} 
    let result = tmp.put_data(size);
    self.storage.insert(name.clone(), tmp);
    result
  }

}


#[cfg(test)]
mod test {
  extern crate cbor;
  extern crate maidsafe_types;
  extern crate rand;
  extern crate routing;
  use super::*;
  use self::routing::types::*;

  #[test]
  fn exist() {
    let mut db = PmidManagerDatabase::new();
    let name = routing::types::generate_random_vec_u8(64);
    assert_eq!(db.exist(&name), false);
    db.put_data(&name, 1024);
    assert_eq!(db.exist(&name), true);
  }

  #[test]
  fn put_data() {
    let mut db = PmidManagerDatabase::new();
    let name = routing::types::generate_random_vec_u8(64);
    assert_eq!(db.put_data(&name, 0), true);
    assert_eq!(db.exist(&name), true);
    assert_eq!(db.put_data(&name, 1), true);
    assert_eq!(db.put_data(&name, 1073741823), true);
    assert_eq!(db.put_data(&name, 1), false);
    assert_eq!(db.put_data(&name, 1), false);
    assert_eq!(db.put_data(&name, 0), true);
    assert_eq!(db.put_data(&name, 1), false);
    assert_eq!(db.exist(&name), true);
  }


}