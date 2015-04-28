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


use routing::generic_sendable_type;
use lru_time_cache::LruCache;
use routing::NameType;
use routing::sendable::Sendable;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};
use cbor;

type Identity = NameType; // maid node address

#[derive(RustcEncodable, RustcDecodable, PartialEq, Eq, Debug)]
pub struct MaidManagerAccount {
  data_stored : u64,
  space_available : u64
}

impl Clone for MaidManagerAccount {
    fn clone(&self) -> Self {
        MaidManagerAccount {
          data_stored: self.data_stored,
          space_available: self.space_available
        }
    }
}

impl MaidManagerAccount {
    pub fn new() -> MaidManagerAccount {
        // FIXME : to bypass the AccountCreation process for simple network allownance is granted automatically
        MaidManagerAccount { data_stored: 0, space_available: 1073741824 }
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

    pub fn get_available_space(&self) -> u64 {
      self.space_available.clone()
    }


    pub fn get_data_stored(&self) -> u64 {
        self.data_stored.clone()
    }

}

pub struct MaidManagerDatabase {
  storage : LruCache<Identity, MaidManagerAccount>
}

impl MaidManagerDatabase {
  pub fn new () -> MaidManagerDatabase {
    MaidManagerDatabase { storage: LruCache::with_capacity(10000) }
  }

  pub fn exist(&mut self, name : &Identity) -> bool {
    self.storage.get(name.clone()).is_some()
  }

  pub fn put_data(&mut self, name : &Identity, size: u64) -> bool {
    let mut tmp = MaidManagerAccount::new();
    let entry = self.storage.remove(name.clone());
  	if entry.is_some() {
  	  tmp = entry.unwrap();
  	}
    let result = tmp.put_data(size);
    self.storage.add(name.clone(), tmp);
    result
  }

  pub fn retrieve_all_and_reset(&mut self) -> Vec<(Identity, generic_sendable_type::GenericSendableType)> {
    let data: Vec<(Identity, MaidManagerAccount)> = self.storage.retrieve_all();
    let mut sendable_data = Vec::<(Identity, generic_sendable_type::GenericSendableType)>::with_capacity(data.len());
    for element in data {
        let mut e = cbor::Encoder::from_memory();
        e.encode(&[&element.1]).unwrap();
        let serialised_content = e.into_bytes();
        let sendable_type = generic_sendable_type::GenericSendableType::new(element.0.clone(), 0, serialised_content); //TODO Get type_tag correct
        sendable_data.push((element.0, sendable_type));
    }
    self.storage = LruCache::with_capacity(10000);
    sendable_data
  }

  pub fn delete_data(&mut self, name : &Identity, size: u64) {
    let entry = self.storage.remove(name.clone());
    if entry.is_some() {
      let mut tmp = entry.unwrap();
      tmp.delete_data(size);
      self.storage.add(name.clone(), tmp);
    }
  }

}


#[cfg(test)]
mod test {
  use super::*;
  use routing;
  use cbor;

  #[test]
  fn exist() {
    let mut db = MaidManagerDatabase::new();
    let name = routing::test_utils::Random::generate_random();
    assert_eq!(db.exist(&name), false);
    db.put_data(&name, 1024);
    assert_eq!(db.exist(&name), true);
  }

  #[test]
  fn put_data() {
    let mut db = MaidManagerDatabase::new();
    let name = routing::test_utils::Random::generate_random();
    assert_eq!(db.put_data(&name, 0), true);
    assert_eq!(db.put_data(&name, 1), true);
    assert_eq!(db.put_data(&name, 1073741823), true);
    assert_eq!(db.put_data(&name, 1), false);
    assert_eq!(db.put_data(&name, 1), false);
    assert_eq!(db.put_data(&name, 0), true);
    assert_eq!(db.put_data(&name, 1), false);
    assert_eq!(db.exist(&name), true);
  }

  #[test]
  fn delete_data() {
    let mut db = MaidManagerDatabase::new();
    let name = routing::test_utils::Random::generate_random();
    db.delete_data(&name, 0);
    assert_eq!(db.exist(&name), false);
    assert_eq!(db.put_data(&name, 0), true);
    assert_eq!(db.exist(&name), true);
    db.delete_data(&name, 1);
    assert_eq!(db.exist(&name), true);
    assert_eq!(db.put_data(&name, 1073741824), true);
    assert_eq!(db.put_data(&name, 1), false);
    db.delete_data(&name, 1);
    assert_eq!(db.put_data(&name, 1), true);
    assert_eq!(db.put_data(&name, 1), false);
    db.delete_data(&name, 1073741825);
    assert_eq!(db.exist(&name), true);
    assert_eq!(db.put_data(&name, 1073741825), false);
    assert_eq!(db.put_data(&name, 1073741824), true);
  }

  #[test]
  fn maid_manager_account_serialisation() {
      let obj_before = MaidManagerAccount::new();

       let mut e = cbor::Encoder::from_memory();
       e.encode(&[&obj_before]).unwrap();

       let mut d = cbor::Decoder::from_bytes(e.into_bytes());
       let obj_after: MaidManagerAccount = d.decode().next().unwrap().unwrap();

       assert_eq!(obj_before, obj_after);
  }

}
