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

use maidsafe_utilities::serialisation::{deserialise, serialise};
use routing::{Authority, Data, DataRequest, Event, ImmutableData, RequestContent, RequestMessage, ResponseContent,
              ResponseMessage, StructuredData};
use xor_name::XorName;
type MaidNodeName = XorName;

#[derive(RustcEncodable, RustcDecodable, PartialEq, Eq, Debug, Clone)]
pub struct Account {
    name: MaidNodeName,
    value: AccountValue,
}

impl Account {
    fn new(name: MaidNodeName, value: AccountValue) -> Account {
        Account { name: name, value: value }
    }
}

impl ::types::Refreshable for Account {
    fn merge(from_group: XorName, responses: Vec<Account>) -> Option<Account> {
        let mut data_stored: Vec<u64> = Vec::new();
        let mut space_available: Vec<u64> = Vec::new();
        for response in responses {
            if response.name == from_group {
                data_stored.push(response.value.data_stored);
                space_available.push(response.value.space_available);
            }
        }
        Some(Account::new(from_group,
                          AccountValue::new(::utils::median(data_stored),
                                            ::utils::median(space_available))))
    }
}



#[derive(RustcEncodable, RustcDecodable, PartialEq, Eq, Debug, Clone)]
pub struct AccountValue {
    data_stored: u64,
    space_available: u64,
}

impl Default for AccountValue {
    // FIXME: Account Creation process required https://maidsafe.atlassian.net/browse/MAID-1191
    //   To bypass the the process for a simple network, allowance is granted by default
    fn default() -> AccountValue {
        AccountValue { data_stored: 0, space_available: 1073741824 }
    }
}

impl AccountValue {
    fn new(data_stored: u64, space_available: u64) -> AccountValue {
        AccountValue { data_stored: data_stored, space_available: space_available }
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
    storage: ::std::collections::HashMap<MaidNodeName, AccountValue>,
}

impl Database {
    pub fn new() -> Database {
        Database { storage: ::std::collections::HashMap::with_capacity(10000) }
    }

    pub fn get_balance(&mut self, name: &MaidNodeName) -> u64 {
        let default: AccountValue = Default::default();
        self.storage.entry(name.clone()).or_insert(default).space_available
    }

    pub fn put_data(&mut self, name: &MaidNodeName, size: u64) -> bool {
        let default: AccountValue = Default::default();
        let entry = self.storage.entry(name.clone()).or_insert(default);
        entry.put_data(size)
    }

    pub fn handle_account_transfer(&mut self, merged_account: Account) {
        let _ = self.storage.remove(&merged_account.name);
        let value = merged_account.value.clone();
        let _ = self.storage.insert(merged_account.name, merged_account.value);
        info!("MaidManager updated account {:?} to {:?}", merged_account.name, value);
    }

    pub fn handle_churn(&mut self, routing: &::vault::Routing,
                        churn_node: &XorName) {
        for (key, value) in self.storage.iter() {
            let account = Account::new((*key).clone(), (*value).clone());
            let our_authority = Authority::ClientManager(account.name);
            if let Ok(serialised_account) = serialise(&[account]) {
                debug!("MaidManager sending refresh for account {:?}",
                       our_authority.get_name());
                routing.send_refresh_request(super::ACCOUNT_TAG, our_authority.clone(),
                                             serialised_account, churn_node.clone());
            }
        }
        // As pointed out in https://github.com/maidsafe/safe_vault/issues/250
        // the uncontrollable order of events (churn/refresh/account_transfer)
        // forcing the node have to keep its current records to avoid losing record
        // self.cleanup();
    }

    pub fn do_refresh(&mut self,
                      type_tag: &u64,
                      our_authority: &::routing::Authority,
                      churn_node: &XorName,
                      routing: &::vault::Routing) -> Option<()> {
        if type_tag == &super::ACCOUNT_TAG {
            for (key, value) in self.storage.iter() {
                if key == our_authority.get_name() {
                    let account = Account::new((*key).clone(), (*value).clone());
                    if let Ok(serialised_account) = serialise(&[account]) {
                        debug!("MaidManager sending on_refresh for account {:?}",
                               our_authority.get_name());
                        routing.send_refresh_request(super::ACCOUNT_TAG, our_authority.clone(),
                                                     serialised_account, churn_node.clone());
                    }
                }
            }
            return ::utils::HANDLED;
        }
        ::utils::NOT_HANDLED
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

    #[test]
    fn put_data() {
        let mut db = Database::new();
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
        let mut db = Database::new();
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
        let mut db = Database::new();
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
        let obj_before = Account::new(XorName([1u8; 64]),
                                      AccountValue::new(::rand::random::<u64>(),
                                                        ::rand::random::<u64>()));

        let mut e = ::cbor::Encoder::from_memory();
        evaluate_result!(e.encode(&[&obj_before]));

        let mut d = ::cbor::Decoder::from_bytes(e.into_bytes());
        let obj_after: Account = evaluate_result!(evaluate_option!(d.decode().next(), ""));

        assert_eq!(obj_before, obj_after);
    }

}
