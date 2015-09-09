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

use cbor;
use rustc_serialize::{Decoder, Encodable, Encoder};
use std::collections;

use transfer_parser::transfer_tags::MAID_MANAGER_ACCOUNT_TAG;
use utils;

pub type MaidNodeName = ::routing::NameType;

#[derive(RustcEncodable, RustcDecodable, PartialEq, Eq, Debug, Clone)]
pub struct Account {
    name: MaidNodeName,
    value: AccountValue,
}

impl Account {
    pub fn new(name: MaidNodeName, value: AccountValue) -> Account {
        Account {
            name: name,
            value: value
        }
    }

    pub fn name(&self) -> &MaidNodeName {
        &self.name
    }

    pub fn value(&self) -> &AccountValue {
        &self.value
    }
}

impl ::types::Refreshable for Account {
    fn merge(from_group: ::routing::NameType,
              responses: Vec<Account>) -> Option<Account> {
        let mut data_stored: Vec<u64> = Vec::new();
        let mut space_available: Vec<u64> = Vec::new();
        for response in responses {
            let account = match ::routing::utils::decode::<Account>(&response.serialised_contents()) {
                Ok(result) => {
                    if *result.name() != from_group {
                        continue;
                    }
                    result
                },
                Err(_) => continue,
            };
            data_stored.push(account.value().data_stored());
            space_available.push(account.value().space_available());
        }
        Some(Account::new(from_group, AccountValue::new(utils::median(data_stored),
                                                        utils::median(space_available))))
    }
}



#[derive(RustcEncodable, RustcDecodable, PartialEq, Eq, Debug, Clone)]
pub struct AccountValue {
    data_stored : u64,
    space_available : u64
}

impl Default for AccountValue {
    // FIXME: to bypass the AccountCreation process for simple network allowance is granted automatically
    fn default() -> AccountValue {
        AccountValue { data_stored: 0, space_available: 1073741824 }
    }
}

impl AccountValue {
    pub fn new(data_stored : u64, space_available : u64) -> AccountValue {
        AccountValue { data_stored: data_stored, space_available: space_available }
    }

    pub fn put_data(&mut self, size : u64) -> bool {
        if size > self.space_available {
            return false;
        }
        self.data_stored += size;
        self.space_available -= size;
        true
    }

    #[allow(dead_code)]
    pub fn delete_data(&mut self, size : u64) {
        if self.data_stored < size {
            self.space_available += self.data_stored;
            self.data_stored = 0;
        } else {
            self.data_stored -= size;
            self.space_available += size;
        }
    }

    pub fn space_available(&self) -> u64 {
      self.space_available
    }

    pub fn data_stored(&self) -> u64 {
        self.data_stored
    }
}


pub struct MaidManagerDatabase {
    storage: collections::HashMap<MaidNodeName, AccountValue>,
}

impl MaidManagerDatabase {
    pub fn new () -> MaidManagerDatabase {
        MaidManagerDatabase { storage: collections::HashMap::with_capacity(10000), }
    }

    pub fn get_balance(&mut self, name: &MaidNodeName) -> u64 {
        let default: AccountValue = Default::default();
        self.storage.entry(name.clone()).or_insert(default).space_available()
    }

    pub fn put_data(&mut self, name: &MaidNodeName, size: u64) -> bool {
        let default: AccountValue = Default::default();
        let entry = self.storage.entry(name.clone()).or_insert(default);
        entry.put_data(size)
    }

    pub fn handle_account_transfer(&mut self, merged_account: Account) {
        // TODO: Assuming the incoming merged account entry has the priority and shall also be trusted first
        let _ = self.storage.remove(merged_account.name());
        let _ = self.storage.insert(*merged_account.name(), merged_account.value().clone());
        info!("MaidManager updated account {:?} to {:?}",
              merged_account.name(), merged_account.value());
    }

    pub fn retrieve_all_and_reset(&mut self) -> Vec<::types::MethodCall> {
        let mut actions = Vec::with_capacity(self.storage.len());
        for (key, value) in self.storage.iter() {
            let account = Account::new((*key).clone(), (*value).clone());
            let mut encoder = cbor::Encoder::from_memory();
            if encoder.encode(&[account.clone()]).is_ok() {
                actions.push(::types::MethodCall::Refresh {
                    type_tag: MAID_MANAGER_ACCOUNT_TAG, from_group: *account.name(),
                    payload: encoder.as_bytes().to_vec()
                });
            }
        }
        self.storage.clear();
        actions
    }

    #[allow(dead_code)]
    pub fn delete_data(&mut self, name : &MaidNodeName, size: u64) {
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

    #[test]
    fn put_data() {
        let mut db = MaidManagerDatabase::new();
        let name = ::utils::random_name();
        assert!(db.put_data(&name, 0));
        assert!(db.put_data(&name, 1));
        assert!(db.put_data(&name, 1073741823));
        assert!(!db.put_data(&name, 1));
        assert!(!db.put_data(&name, 1));
        assert!(db.put_data(&name, 0));
        assert!(!db.put_data(&name, 1));
        assert!(db.storage.contains_key(&name));
    }

    #[test]
    fn delete_data() {
        let mut db = MaidManagerDatabase::new();
        let name = ::utils::random_name();
        db.delete_data(&name, 0);
        assert!(!db.storage.contains_key(&name));
        assert!(db.put_data(&name, 0));
        assert!(db.storage.contains_key(&name));
        db.delete_data(&name, 1);
        assert!(db.storage.contains_key(&name));
        assert!(db.put_data(&name, 1073741824));
        assert!(!db.put_data(&name, 1));
        db.delete_data(&name, 1);
        assert!(db.put_data(&name, 1));
        assert!(!db.put_data(&name, 1));
        db.delete_data(&name, 1073741825);
        assert!(db.storage.contains_key(&name));
        assert!(!db.put_data(&name, 1073741825));
        assert!(db.put_data(&name, 1073741824));
    }

    #[test]
    fn handle_account_transfer() {
        let mut db = MaidManagerDatabase::new();
        let name = ::utils::random_name();
        assert!(db.put_data(&name, 0));
        assert!(db.put_data(&name, 1073741823));
        assert!(!db.put_data(&name, 2));

        let mut account_value: AccountValue = Default::default();
        account_value.put_data(1073741822);
        {
            let account = Account::new(name.clone(), account_value.clone());
            db.handle_account_transfer(account);
        }
        assert!(!db.put_data(&name, 3));
        assert!(db.put_data(&name, 2));

        account_value.delete_data(1073741822);
        {
            let account = Account::new(name.clone(), account_value.clone());
            db.handle_account_transfer(account);
        }
        assert!(!db.put_data(&name, 1073741825));
        assert!(db.put_data(&name, 1073741824));
    }

    #[test]
    fn maid_manager_account_serialisation() {
        let obj_before = Account::new(::routing::NameType([1u8; 64]),
            AccountValue::new(::rand::random::<u64>(), ::rand::random::<u64>()));

        let mut e = cbor::Encoder::from_memory();
        e.encode(&[&obj_before]).unwrap();

        let mut d = cbor::Decoder::from_bytes(e.into_bytes());
        let obj_after: Account = d.decode().next().unwrap().unwrap();

        assert_eq!(obj_before, obj_after);
    }

}
