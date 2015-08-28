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

use cbor;
use rustc_serialize::{Decoder, Encodable, Encoder};
use std::collections;

use routing_types::*;
use transfer_parser::transfer_tags::MAID_MANAGER_ACCOUNT_TAG;
use utils;

type Identity = NameType; // maid node address

/// MaidManagerAccountWrapper implements the sendable trait from Routing, thus making it
/// transportable through the Routing layer.
#[derive(RustcEncodable, RustcDecodable, PartialEq, Eq, Debug)]
pub struct MaidManagerAccountWrapper {
    name: NameType,
    account: MaidManagerAccount
}

impl MaidManagerAccountWrapper {
    pub fn new(name: NameType, account: MaidManagerAccount) -> MaidManagerAccountWrapper {
        MaidManagerAccountWrapper {
            name: name,
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
        MAID_MANAGER_ACCOUNT_TAG
    }

    fn serialised_contents(&self) -> Vec<u8> {
        match ::routing::utils::encode(&self) {
            Ok(result) => result,
            Err(_) => Vec::new()
        }
    }

    fn refresh(&self)->bool {
        true
    }

    fn merge(&self, responses: Vec<Box<Sendable>>) -> Option<Box<Sendable>> {
        let mut data_stored: Vec<u64> = Vec::new();
        let mut space_available: Vec<u64> = Vec::new();
        for value in responses {
            let wrapper = match ::routing::utils::decode::<MaidManagerAccountWrapper>(
                &value.serialised_contents()) {
                    Ok(result) => result,
                    Err(_) => { continue }
                };
            data_stored.push(wrapper.get_account().get_data_stored());
            space_available.push(wrapper.get_account().get_available_space());
        }
        Some(Box::new(MaidManagerAccountWrapper::new(self.name.clone(), MaidManagerAccount {
            data_stored: utils::median(data_stored),
            space_available: utils::median(space_available)
        })))
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

    pub fn handle_account_transfer(&mut self, account_wrapper : &MaidManagerAccountWrapper) {
        // TODO: Assuming the incoming merged account entry has the priority and shall also be trusted first
        let _ = self.storage.remove(&account_wrapper.name());
        let _ = self.storage.insert(account_wrapper.name(), account_wrapper.get_account());
        info!("MaidManager updated account {:?} to {:?}",
              account_wrapper.name(), account_wrapper.get_account());
    }

    pub fn retrieve_all_and_reset(&mut self) -> Vec<MethodCall> {
        let mut actions = Vec::with_capacity(self.storage.len());
        for (key, value) in self.storage.iter() {
            let maid_manager_wrapper =
                MaidManagerAccountWrapper::new((*key).clone(), (*value).clone());
            let mut encoder = cbor::Encoder::from_memory();
            if encoder.encode(&[maid_manager_wrapper.clone()]).is_ok() {
                actions.push(MethodCall::Refresh {
                    type_tag: MAID_MANAGER_ACCOUNT_TAG, from_group: maid_manager_wrapper.name(),
                    payload: encoder.as_bytes().to_vec()
                });
            }
        }
        self.storage.clear();
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
    use cbor;

    use super::*;

    use routing_types::*;

    #[test]
    fn exist() {
        let mut db = MaidManagerDatabase::new();
        let name = NameType(vector_as_u8_64_array(generate_random_vec_u8(64)));
        assert_eq!(db.exist(&name), false);
        db.put_data(&name, 1024);
        assert_eq!(db.exist(&name), true);
    }

    #[test]
    fn put_data() {
        let mut db = MaidManagerDatabase::new();
        let name = NameType(vector_as_u8_64_array(generate_random_vec_u8(64)));
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
        let name = NameType(vector_as_u8_64_array(generate_random_vec_u8(64)));
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
    fn handle_account_transfer() {
        let mut db = MaidManagerDatabase::new();
        let name = NameType(vector_as_u8_64_array(generate_random_vec_u8(64)));
        assert_eq!(db.put_data(&name, 0), true);
        assert_eq!(db.put_data(&name, 1073741823), true);
        assert_eq!(db.put_data(&name, 2), false);

        let mut account = MaidManagerAccount::new();
        account.put_data(1073741822);
        {
            let account_wrapper = MaidManagerAccountWrapper::new(name.clone(), account.clone());
            db.handle_account_transfer(&account_wrapper);
        }
        assert_eq!(db.put_data(&name, 3), false);
        assert_eq!(db.put_data(&name, 2), true);

        account.delete_data(1073741822);
        {
            let account_wrapper = MaidManagerAccountWrapper::new(name.clone(), account.clone());
            db.handle_account_transfer(&account_wrapper);
        }
        assert_eq!(db.put_data(&name, 1073741825), false);
        assert_eq!(db.put_data(&name, 1073741824), true);
    }

    #[test]
    fn maid_manager_account_wrapper_serialisation() {
        let obj_before = MaidManagerAccountWrapper::new(NameType([1u8;64]), MaidManagerAccount::new());

        let mut e = cbor::Encoder::from_memory();
        e.encode(&[&obj_before]).unwrap();

        let mut d = cbor::Decoder::from_bytes(e.into_bytes());
        let obj_after: MaidManagerAccountWrapper = d.decode().next().unwrap().unwrap();

        assert_eq!(obj_before, obj_after);
    }

}
