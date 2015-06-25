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

use std::collections;
use utils::median;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};
use cbor;

use routing::NameType;
use routing::node_interface::MethodCall;
use routing::types::GROUP_SIZE;
use routing::sendable::Sendable;

type Identity = NameType; // pmidnode address

/// PmidManagerAccountWrapper implemets the sendable trait from routing, thus making it transporatble
/// across through the routing layer
#[derive(RustcEncodable, RustcDecodable, PartialEq, Eq, Debug)]
pub struct PmidManagerAccountWrapper {
    name: Identity,
    tag: u64,
    account: PmidManagerAccount
}

impl PmidManagerAccountWrapper {
    pub fn new(name: NameType, account: PmidManagerAccount) -> PmidManagerAccountWrapper {
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

    fn merge(&self, responses: Vec<Box<Sendable>>) -> Option<Box<Sendable>> {
        let mut tmp_wrapper: PmidManagerAccountWrapper;
        let mut offered_space: Vec<u64> = Vec::with_capacity(responses.len());
        let mut lost_total_size: Vec<u64> = Vec::with_capacity(responses.len());
        let mut stored_total_size: Vec<u64> = Vec::with_capacity(responses.len());
        assert!(responses.len() < (GROUP_SIZE + 1) / 2);
        for value in responses {
           let mut d = cbor::Decoder::from_bytes(value.serialised_contents());
           tmp_wrapper = d.decode().next().unwrap().unwrap();
           offered_space.push(tmp_wrapper.get_account().get_offered_space());
           lost_total_size.push(tmp_wrapper.get_account().get_lost_total_size());
           stored_total_size.push(tmp_wrapper.get_account().get_stored_total_size());
        }
        Some(Box::new(PmidManagerAccountWrapper::new(NameType([0u8;64]), PmidManagerAccount {
           offered_space : median(&offered_space),
           lost_total_size: median(&lost_total_size),
           stored_total_size: median(&stored_total_size)
        })))
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

  // TODO: Always return true to allow pmid_node carry out removal of Sacrificial copies
  //       Otherwise PmidManagerAccount need to remember storage info of Primary, Backup and Sacrificial
  //       copies separately to trigger an early alert
  pub fn put_data(&mut self, size : u64) -> bool {
    // if (self.stored_total_size + size) > self.offered_space {
    //   return false;
    // }
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

    pub fn delete_data(&mut self, name : &Identity, size: u64) {
        let entry = self.storage.entry(name.clone()).or_insert(PmidManagerAccount::new());
        entry.delete_data(size)
    }

    pub fn handle_account_transfer(&mut self, account_wrapper : &PmidManagerAccountWrapper) {
        // TODO: Assuming the incoming merged account entry has the priority and shall also be trusted first
        let _ = self.storage.remove(&account_wrapper.name());
        self.storage.insert(account_wrapper.name(), account_wrapper.get_account());
    }

    pub fn retrieve_all_and_reset(&mut self, close_group: &Vec<NameType>) -> Vec<MethodCall> {
        let mut actions = Vec::with_capacity(self.storage.len());
        for (key, value) in self.storage.iter() {
            if close_group.iter().find(|a| **a == *key).is_some() {
                let pmid_manager_wrapper = PmidManagerAccountWrapper::new((*key).clone(), (*value).clone());
                let payload = Payload::new(PayloadTypeTag::PmidManagerAccountTransfer, &pmid_manager_wrapper);
                let mut e = cbor::Encoder::from_memory();
                e.encode(&[payload]).unwrap();
                actions.push(MethodCall::Refresh {
                    type_tag: pmid_manager_wrapper.type_tag(), from_group: pmid_manager_wrapper.name(),
                    payload: e.as_bytes().to_vec()
                });
            }
        }
        self.storage.clear();
        actions
    }
}


#[cfg(test)]
mod test {
  extern crate cbor;
  extern crate maidsafe_types;
  extern crate routing;
  use super::{PmidManagerDatabase, PmidManagerAccount, PmidManagerAccountWrapper};

    #[test]
    fn exist() {
        let mut db = PmidManagerDatabase::new();
        let name = routing::test_utils::Random::generate_random();
        assert_eq!(db.exist(&name), false);
        db.put_data(&name, 1024);
        assert_eq!(db.exist(&name), true);
    }

    // #[test]
    // fn put_data() {
    //     let mut db = PmidManagerDatabase::new();
    //     let name = routing::test_utils::Random::generate_random();
    //     assert_eq!(db.put_data(&name, 0), true);
    //     assert_eq!(db.exist(&name), true);
    //     assert_eq!(db.put_data(&name, 1), true);
    //     assert_eq!(db.put_data(&name, 1073741823), true);
    //     assert_eq!(db.put_data(&name, 1), false);
    //     assert_eq!(db.put_data(&name, 1), false);
    //     assert_eq!(db.put_data(&name, 0), true);
    //     assert_eq!(db.put_data(&name, 1), false);
    //     assert_eq!(db.exist(&name), true);
    // }

    #[test]
    fn handle_account_transfer() {
        let mut db = PmidManagerDatabase::new();
        let name = routing::test_utils::Random::generate_random();
        assert_eq!(db.put_data(&name, 1024), true);
        assert_eq!(db.exist(&name), true);

        let pmidmanager_account_wrapper = PmidManagerAccountWrapper::new(name.clone(), PmidManagerAccount::new());
        db.handle_account_transfer(&pmidmanager_account_wrapper);
        assert_eq!(db.storage[&name].get_offered_space(), 1073741824);
        assert_eq!(db.storage[&name].get_lost_total_size(), 0);
        assert_eq!(db.storage[&name].get_stored_total_size(), 0);
    }

    #[test]
    fn pmid_manager_account_serialisation() {
        let obj_before = PmidManagerAccount::new();

        let mut e = cbor::Encoder::from_memory();
        e.encode(&[&obj_before]).unwrap();

        let mut d = cbor::Decoder::from_bytes(e.as_bytes());
        let obj_after: PmidManagerAccount = d.decode().next().unwrap().unwrap();

        assert_eq!(obj_before, obj_after);
    }

}
