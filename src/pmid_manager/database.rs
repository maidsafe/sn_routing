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

extern crate routing;

use cbor;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};
use std::collections;
use routing::types::{GROUP_SIZE};
use utils::median;
use routing::sendable::Sendable;

type Identity = self::routing::NameType; // pmidnode address

/// PmidManagerAccountWrapper implemets the sendable trait from routing, thus making it transporatble
/// across through the routing layer
#[derive(RustcEncodable, RustcDecodable, PartialEq, Eq, Debug)]
pub struct PmidManagerAccountWrapper {
    name: Identity,
    tag: u64,
    account: PmidManagerAccount
}

impl PmidManagerAccountWrapper {
    pub fn new(name: routing::NameType, account: PmidManagerAccount) -> PmidManagerAccountWrapper {
        PmidManagerAccountWrapper {
            name: name,
            tag: 201, // FIXME : Change once the tag is freezed
            account: account
        }
    }

    pub fn get_account(&self) -> PmidManagerAccount {
        self.account.clone()
    }
}

impl Clone for PmidManagerAccountWrapper {
    fn clone(&self) -> Self {
        PmidManagerAccountWrapper::new(self.name.clone(), self.account.clone())
    }
}

impl Sendable for PmidManagerAccountWrapper {
    fn name(&self) -> Identity {
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
        let mut tmp_wrapper: PmidManagerAccountWrapper;
        let mut offered_space: Vec<u64> = Vec::new();
        let mut lost_total_size: Vec<u64> = Vec::new();
        let mut stored_total_size: Vec<u64> = Vec::new();
        for value in responses {
            let mut d = cbor::Decoder::from_bytes(value.serialised_contents());
            tmp_wrapper = d.decode().next().unwrap().unwrap();
            offered_space.push(tmp_wrapper.get_account().get_offered_space());
            lost_total_size.push(tmp_wrapper.get_account().get_lost_total_size());
            stored_total_size.push(tmp_wrapper.get_account().get_stored_total_size());
        }
        assert!(offered_space.len() < (GROUP_SIZE as usize + 1) / 2);
        Some(PmidManagerAccountWrapper::new(routing::NameType([0u8;64]), PmidManagerAccount {
            offered_space : median(&offered_space),
            lost_total_size: median(&lost_total_size),
            stored_total_size: median(&stored_total_size)
        }))
    }
}

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
  storage : collections::HashMap<Identity, PmidManagerAccount>,
}

impl PmidManagerDatabase {
    pub fn new () -> PmidManagerDatabase {
        PmidManagerDatabase { storage: collections::HashMap::with_capacity(10000), }
    }

    pub fn exist(&mut self, name : &Identity) -> bool {
        self.storage.contains_key(name)
    }

    pub fn put_data(&mut self, name : &Identity, size: u64) -> bool {
        let entry = self.storage.entry(name.clone()).or_insert(PmidManagerAccount::new());
        entry.put_data(size)
    }

    pub fn retrieve_all_and_reset(&mut self, close_group: &Vec<routing::NameType>) -> Vec<RoutingNodeAction> {
        let data: Vec<_> = self.storage.drain().collect();
        let mut actions = Vec::with_capacity(data.len());
        for element in data {
            if close_group.iter().find(|a| **a == element.0).is_some() {
                actions.push(RoutingNodeAction::Put {
                    destination: element.0.clone(),
                    content: Box::new(PmidManagerAccountWrapper::new(element.0, element.1)),
                });
            }
        }
        actions
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
