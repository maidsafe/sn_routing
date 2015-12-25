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

use maidsafe_utilities::serialisation::serialise;
use routing::{Authority, ChurnEventId, Routing};
use sodiumoxide::crypto::hash::sha512;
use transfer_tag::TAG_INDEX;
use types::{MergedValue, Refreshable};
use utils::median;
use xor_name::XorName;
pub type MaidNodeName = XorName;

#[derive(RustcEncodable, RustcDecodable, PartialEq, Eq, Debug, Clone)]
pub struct Account {
    data_stored: u64,
    space_available: u64,
}

impl Default for Account {
    // FIXME: Account Creation process required https://maidsafe.atlassian.net/browse/MAID-1191
    //   To bypass the the process for a simple network, allowance is granted by default
    fn default() -> Account {
        Account {
            data_stored: 0,
            space_available: 1073741824,
        }
    }
}

impl Refreshable for Account {
    fn merge(name: XorName, values: Vec<Account>, _quorum_size: usize) -> Option<MergedValue<Account>> {
        let mut data_stored: Vec<u64> = Vec::new();
        let mut space_available: Vec<u64> = Vec::new();
        for value in values {
            data_stored.push(value.data_stored);
            space_available.push(value.space_available);
        }
        Some(MergedValue {
            name: name,
            value: Account::new(median(data_stored), median(space_available)),
        })
    }
}

impl Account {
    fn new(data_stored: u64, space_available: u64) -> Account {
        Account {
            data_stored: data_stored,
            space_available: space_available,
        }
    }

    fn put_data(&mut self, size: u64) -> bool {
        if size > self.space_available {
            return false;
        }
        self.data_stored += size;
        self.space_available -= size;
        true
    }

    #[allow(dead_code)]
    fn delete_data(&mut self, size: u64) {
        if self.data_stored < size {
            self.space_available += self.data_stored;
            self.data_stored = 0;
        } else {
            self.data_stored -= size;
            self.space_available += size;
        }
    }
}



pub struct Database {
    storage: ::std::collections::HashMap<MaidNodeName, Account>,
}

impl Database {
    pub fn new() -> Database {
        Database { storage: ::std::collections::HashMap::with_capacity(10000) }
    }

    #[allow(unused)]
    pub fn get_balance(&mut self, name: &MaidNodeName) -> u64 {
        let default: Account = Default::default();
        self.storage.entry(name.clone()).or_insert(default).space_available
    }

    pub fn put_data(&mut self, name: &MaidNodeName, size: u64) -> bool {
        let default: Account = Default::default();
        let entry = self.storage.entry(name.clone()).or_insert(default);
        entry.put_data(size)
    }

    pub fn handle_account_transfer(&mut self, merged: MergedValue<Account>) {
        info!("MaidManager updating account {:?} to {:?}",
              merged.name,
              merged.value);
        let _ = self.storage.insert(merged.name, merged.value);
    }

    pub fn handle_churn(&mut self, routing: &Routing, churn_event_id: &ChurnEventId) {
        for (key, value) in self.storage.iter() {
            let src = Authority::ClientManager(key.clone());
            let to_hash = churn_event_id.id.0.iter().chain(key.0.iter()).cloned().collect::<Vec<_>>();
            let mut nonce = sha512::hash(&to_hash);
            nonce.0[TAG_INDEX] = super::ACCOUNT_TAG;
            if let Ok(serialised_account) = serialise(value) {
                debug!("MaidManager sending refresh for account {:?}",
                       src.get_name());
                let _ = routing.send_refresh_request(src.clone(), nonce, serialised_account);
            }
        }
    }

    pub fn cleanup(&mut self) {
        self.storage.clear();
    }

    #[allow(dead_code)]
    pub fn delete_data(&mut self, name: &MaidNodeName, size: u64) {
        match self.storage.get_mut(name) {
            Some(value) => value.delete_data(size),
            None => (),
        }
    }
}



#[cfg(test)]
mod test {
    use super::*;
    use rand::random;
    use xor_name::XorName;

    #[test]
    fn put_data() {
        let mut db = Database::new();
        let name = random();
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
        let mut db = Database::new();
        let name = random();
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
        let mut db = Database::new();
        let name = random();
        assert!(db.put_data(&name, 0));
        assert!(db.put_data(&name, 1073741823));
        assert!(!db.put_data(&name, 2));

        let mut account_value: Account = Default::default();
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
        let obj_before = Account::new(XorName([1u8; 64]),
                                      Account::new(::rand::random::<u64>(), ::rand::random::<u64>()));

        let mut e = ::cbor::Encoder::from_memory();
        unwrap_result!(e.encode(&[&obj_before]));

        let mut d = ::cbor::Decoder::from_bytes(e.into_bytes());
        let obj_after: Account = unwrap_result!(unwrap_option!(d.decode().next(), ""));

        assert_eq!(obj_before, obj_after);
    }

}
