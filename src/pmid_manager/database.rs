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
use routing::{Authority, Data, DataRequest, Event, ImmutableData, ImmutableDataType, RequestContent, RequestMessage, ResponseContent,
              ResponseMessage, StructuredData};
use xor_name::XorName;
type PmidNodeName = XorName;

#[derive(RustcEncodable, RustcDecodable, PartialEq, Eq, Debug, Clone)]
pub struct Account {
    name: PmidNodeName,
    value: AccountValue,
}

impl Account {
    fn new(name: PmidNodeName, value: AccountValue) -> Account {
        Account { name: name, value: value }
    }
}

impl ::types::Refreshable for Account {
    fn merge(from_group: XorName, responses: Vec<Account>) -> Option<Account> {
        let mut stored_total_size: Vec<u64> = Vec::new();
        let mut lost_total_size: Vec<u64> = Vec::new();
        for response in responses {
            if response.name == from_group {
                stored_total_size.push(response.value.stored_total_size);
                lost_total_size.push(response.value.lost_total_size);
            }
        }
        Some(Account::new(from_group,
                          AccountValue::new(::utils::median(stored_total_size),
                                            ::utils::median(lost_total_size))))
    }
}



#[derive(RustcEncodable, RustcDecodable, PartialEq, Eq, Debug, Clone)]
pub struct AccountValue {
    stored_total_size: u64,
    lost_total_size: u64,
}

impl Default for AccountValue {
    // FIXME: Account Creation process required https://maidsafe.atlassian.net/browse/MAID-1191
    //   To bypass the the process for a simple network, allowance is granted by default
    fn default() -> AccountValue {
        AccountValue { stored_total_size: 0, lost_total_size: 0 }
    }
}

impl AccountValue {
    fn new(stored_total_size: u64, lost_total_size: u64) -> AccountValue {
        AccountValue {
            stored_total_size: stored_total_size,
            lost_total_size: lost_total_size,
        }
    }

  // Always return true to allow pmid_node carry out removal of Sacrificial copies
  // Otherwise AccountValue need to remember storage info of Primary, Backup and Sacrificial
  // copies separately to trigger an early alert
    fn put_data(&mut self, size: u64) {
        // if (self.stored_total_size + size) > self.offered_space {
        //   return false;
        // }
        self.stored_total_size += size;
    }

    fn delete_data(&mut self, size: u64) {
        if self.stored_total_size < size {
            self.stored_total_size = 0;
        } else {
            self.stored_total_size -= size;
        }
    }

    #[allow(dead_code)]
    fn handle_lost_data(&mut self, size: u64) {
        self.delete_data(size);
        self.lost_total_size += size;
    }

    #[allow(dead_code)]
    fn handle_falure(&mut self, size: u64) {
        self.handle_lost_data(size);
    }

    #[allow(dead_code)]
    fn update_account(&mut self, diff_size: u64) {
        if self.stored_total_size < diff_size {
            self.stored_total_size = 0;
        } else {
            self.stored_total_size -= diff_size;
        }
        self.lost_total_size += diff_size;
    }
}



pub struct Database {
    storage: ::std::collections::HashMap<PmidNodeName, AccountValue>,
}

impl Database {
    pub fn new() -> Database {
        Database { storage: ::std::collections::HashMap::with_capacity(10000) }
    }

    pub fn put_data(&mut self, name: &PmidNodeName, size: u64) {
        let default: AccountValue = Default::default();
        let entry = self.storage.entry(name.clone()).or_insert(default);
        entry.put_data(size)
    }

    pub fn delete_data(&mut self, name: &PmidNodeName, size: u64) {
        let default: AccountValue = Default::default();
        let entry = self.storage.entry(name.clone()).or_insert(default);
        entry.delete_data(size)
    }

    pub fn handle_account_transfer(&mut self, merged_account: Account) {
        let _ = self.storage.remove(&merged_account.name);
        let value = merged_account.value.clone();
        let _ = self.storage.insert(merged_account.name, merged_account.value);
        info!("PmidManager updated account {:?} to {:?}", merged_account.name, value);
    }

    pub fn handle_churn(&mut self, close_group: &Vec<XorName>,
                        routing: &::vault::Routing, churn_node: &XorName) {
        for (key, value) in self.storage.iter() {
            if close_group.iter().find(|a| **a == *key).is_some() {
                let account = Account::new((*key).clone(), (*value).clone());
                let our_authority = Authority::NodeManager(account.name);
                if let Ok(serialised_account) = serialise(&[account]) {
                    debug!("PmidManager sending refresh for account {:?}",
                           our_authority.get_name());
                    routing.send_refresh_request(super::ACCOUNT_TAG, our_authority.clone(),
                                                 serialised_account, churn_node.clone());
                }
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
                        debug!("PmidManager sending on_refresh for account {:?}",
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
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn exist() {
        let mut db = Database::new();
        let name = ::utils::random_name();
        assert!(!db.storage.contains_key(&name));
        db.put_data(&name, 1024);
        assert!(db.storage.contains_key(&name));
    }

    // #[test]
    // fn put_data() {
    //     let mut db = Database::new();
    //     let name = ::utils::random_name();
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
        let mut db = Database::new();
        let name = ::utils::random_name();
        db.put_data(&name, 1024);
        assert!(db.storage.contains_key(&name));

        let account_value = AccountValue::new(::rand::random::<u64>(),
                                              ::rand::random::<u64>());
        let account = Account::new(name.clone(), account_value.clone());
        db.handle_account_transfer(account);
        assert_eq!(db.storage[&name], account_value);
    }

    #[test]
    fn pmid_manager_account_serialisation() {
        let obj_before = Account::new(XorName([1u8; 64]),
                                      AccountValue::new(::rand::random::<u64>(),
                                                        ::rand::random::<u64>()));

        let mut e = ::cbor::Encoder::from_memory();
        evaluate_result!(e.encode(&[&obj_before]));

        let mut d = ::cbor::Decoder::from_bytes(e.as_bytes());
        let obj_after: Account = evaluate_result!(evaluate_option!(d.decode().next(), ""));

        assert_eq!(obj_before, obj_after);
    }

}
