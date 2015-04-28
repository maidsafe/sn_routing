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

extern crate lru_time_cache;

extern crate routing;

use cbor;
use routing::generic_sendable_type;
use self::lru_time_cache::LruCache;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};

type Identity = self::routing::NameType; // pmidnode address

#[derive(RustcEncodable, RustcDecodable, PartialEq, Eq, Debug)]
pub struct PmidManagerAccount {
  stored_total_size : u64,
  lost_total_size : u64,
  offered_space : u64
}

impl Clone for PmidManagerAccount {
  fn clone(&self) -> Self {
    PmidManagerAccount {
      stored_total_size : self.stored_total_size,
      lost_total_size : self.lost_total_size,
      offered_space : self.offered_space
    }
  }
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

  pub fn get_offered_space(&self) -> u64 {
      self.offered_space.clone()
  }

  pub fn get_lost_total_size(&self) -> u64 {
      self.lost_total_size.clone()
  }


  pub fn get_stored_total_size(&self) -> u64 {
      self.stored_total_size.clone()
  }
}

pub struct PmidManagerDatabase {
  storage : LruCache<Identity, PmidManagerAccount>
}

impl PmidManagerDatabase {
  pub fn new () -> PmidManagerDatabase {
    PmidManagerDatabase { storage: LruCache::with_capacity(10000) }
  }

  pub fn exist(&mut self, name : &Identity) -> bool {
    self.storage.get(name.clone()).is_some()
  }

  pub fn put_data(&mut self, name : &Identity, size: u64) -> bool {
    let mut tmp = PmidManagerAccount::new();
    let entry = self.storage.remove(name.clone());
      if entry.is_some() {
        tmp = entry.unwrap();
      }
    let result = tmp.put_data(size);
    self.storage.add(name.clone(), tmp);
    result
  }

    pub fn retrieve_all_and_reset(&mut self) -> Vec<(Identity, generic_sendable_type::GenericSendableType)> {
        let data: Vec<(Identity, PmidManagerAccount)> = self.storage.retrieve_all();
        let mut sendable_data = Vec::<(Identity, generic_sendable_type::GenericSendableType)>::with_capacity(data.len());
        for element in data {
            let mut e = cbor::Encoder::from_memory();
            e.encode(&[&element.1]).unwrap();
            let serialised_content = e.into_bytes();
            let sendable_type = generic_sendable_type::GenericSendableType::new(element.0.clone(), 2, serialised_content); //TODO Get type_tag correct
            sendable_data.push((element.0, sendable_type));
        }
        self.storage = LruCache::with_capacity(10000);
        sendable_data
    }
}


#[cfg(test)]
mod test {
  extern crate cbor;
  extern crate maidsafe_types;
  extern crate rand;
  extern crate routing;
  use super::{PmidManagerDatabase, PmidManagerAccount};
  use self::routing::types::*;

    #[test]
    fn exist() {
        let mut db = PmidManagerDatabase::new();
        let name = routing::test_utils::Random::generate_random();
        assert_eq!(db.exist(&name), false);
        db.put_data(&name, 1024);
        assert_eq!(db.exist(&name), true);
    }

    #[test]
    fn put_data() {
        let mut db = PmidManagerDatabase::new();
        let name = routing::test_utils::Random::generate_random();
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

    #[test]
    fn pmid_manager_account_serialisation() {
        let obj_before = super::PmidManagerAccount::new();

        let mut e = cbor::Encoder::from_memory();
        e.encode(&[&obj_before]).unwrap();

        let mut d = cbor::Decoder::from_bytes(e.as_bytes());
        let obj_after: super::PmidManagerAccount = d.decode().next().unwrap().unwrap();

        assert_eq!(obj_before, obj_after);
    }

}
