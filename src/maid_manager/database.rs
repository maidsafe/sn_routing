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
use routing::NameType;
use routing::sendable::Sendable;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};
use routing::node_interface::RoutingNodeAction;
use cbor;
use routing::types::GROUP_SIZE;
use utils::median;

type Identity = NameType; // maid node address

/// MaidManagerAccountWrapper implemets the sendable trait from routing, thus making it transporatble
/// across through the routing layer
#[derive(RustcEncodable, RustcDecodable, PartialEq, Eq, Debug)]
pub struct MaidManagerAccountWrapper {
    name: NameType,
    tag: u64,
    account: MaidManagerAccount
}

impl MaidManagerAccountWrapper {
    pub fn new(name: NameType, account: MaidManagerAccount) -> MaidManagerAccountWrapper {
        MaidManagerAccountWrapper {
            name: name,
            tag: 200, // FIXME : Change once the tag is freezed
            account: account
        }
    }

    pub fn get_account(&self) -> MaidManagerAccount {
        self.account.clone()
    }
}

impl Clone for MaidManagerAccountWrapper {
    fn clone(&self) -> Self {
        MaidManagerAccountWrapper::new(self.name.clone(), self.account.clone())
    }
}

impl Sendable for MaidManagerAccountWrapper {
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
        let mut tmp_wrapper: MaidManagerAccountWrapper;
        let mut data_stored: Vec<u64> = Vec::new();
        let mut space_available: Vec<u64> = Vec::new();
        for value in responses {
            let mut d = cbor::Decoder::from_bytes(value.serialised_contents());
            tmp_wrapper = d.decode().next().unwrap().unwrap();
            data_stored.push(tmp_wrapper.get_account().get_data_stored());
            space_available.push(tmp_wrapper.get_account().get_available_space());
        }
        assert!(data_stored.len() < (GROUP_SIZE as usize + 1) / 2);

        Some(MaidManagerAccountWrapper::new(NameType([0u8;64]), MaidManagerAccount {
            data_stored : median(&data_stored),
            space_available: median(&space_available)
        }))
    }
}

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
  storage: collections::HashMap<Identity, MaidManagerAccount>,
}

impl MaidManagerDatabase {
  pub fn new () -> MaidManagerDatabase {
      MaidManagerDatabase { storage: collections::HashMap::with_capacity(10000), }
  }

  pub fn exist(&mut self, name : &Identity) -> bool {
      self.storage.contains_key(name)
  }

  pub fn put_data(&mut self, name: &Identity, size: u64) -> bool {
      let entry = self.storage.entry(name.clone()).or_insert(MaidManagerAccount::new());
      entry.put_data(size)
  }

  pub fn retrieve_all_and_reset(&mut self) -> Vec<RoutingNodeAction> {
      let data: Vec<_> = self.storage.drain().collect();
      let mut actions = Vec::with_capacity(data.len());
      for element in data {
          actions.push(RoutingNodeAction::Put {
              destination: element.0.clone(),
              content: Box::new(MaidManagerAccountWrapper::new(element.0, element.1)),
          });
      }
      actions
  }

  pub fn delete_data(&mut self, name : &Identity, size: u64) {
      match self.storage.get_mut(name) {
          Some(value) => value.delete_data(size),
          None => (),
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
    fn maid_manager_account_wrapper_serialisation() {
        let obj_before = MaidManagerAccountWrapper::new(routing::NameType([1u8;64]), MaidManagerAccount::new());

        let mut e = cbor::Encoder::from_memory();
        e.encode(&[&obj_before]).unwrap();

        let mut d = cbor::Decoder::from_bytes(e.into_bytes());
        let obj_after: MaidManagerAccountWrapper = d.decode().next().unwrap().unwrap();

        assert_eq!(obj_before, obj_after);
    }

}
