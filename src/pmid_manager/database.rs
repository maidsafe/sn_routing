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
use routing::{Authority, MessageId, Node};
use types::{Refresh, RefreshValue};
use xor_name::XorName;
pub type PmidNodeName = XorName;

#[derive(RustcEncodable, RustcDecodable, PartialEq, Eq, Debug, Clone)]
pub struct Account {
    stored_total_size: u64,
    lost_total_size: u64,
}

impl Default for Account {
    // FIXME: Account Creation process required https://maidsafe.atlassian.net/browse/MAID-1191
    //   To bypass the the process for a simple network, allowance is granted by default
    fn default() -> Account {
        Account {
            stored_total_size: 0,
            lost_total_size: 0,
        }
    }
}

impl Account {
    // Always return true to allow pmid_node carry out removal of Sacrificial copies
    // Otherwise Account need to remember storage info of Primary, Backup and Sacrificial
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
    storage: ::std::collections::HashMap<PmidNodeName, Account>,
}

impl Database {
    pub fn new() -> Database {
        Database { storage: ::std::collections::HashMap::with_capacity(10000) }
    }

    pub fn put_data(&mut self, name: &PmidNodeName, size: u64) {
        let default: Account = Default::default();
        let entry = self.storage.entry(name.clone()).or_insert(default);
        entry.put_data(size)
    }

    #[allow(unused)]
    pub fn delete_data(&mut self, name: &PmidNodeName, size: u64) {
        let default: Account = Default::default();
        let entry = self.storage.entry(name.clone()).or_insert(default);
        entry.delete_data(size)
    }

    pub fn handle_account_transfer(&mut self, name: PmidNodeName, account: Account) {
        info!("PmidManager updating account {:?} to {:?}", name, account);
        let _ = self.storage.insert(name, account);
    }

    pub fn handle_churn(&mut self, routing_node: &Node, churn_event_id: &MessageId) {
        for (key, value) in self.storage.iter() {
            // Only refresh accounts for PmidNodes which are still in our close group
            let close_group = match routing_node.close_group() {
                Ok(group) => group,
                Err(error) => {
                    error!("Failed to get close group from Routing: {:?}", error);
                    return;
                }
            };
            if !close_group.iter().any(|&elt| elt == *key) {
                continue;
            }

            let src = Authority::NodeManager(key.clone());
            let refresh = Refresh {
                id: churn_event_id.clone(),
                name: key.clone(),
                value: RefreshValue::PmidManager(value.clone()),
            };
            if let Ok(serialised_refresh) = serialise(&refresh) {
                debug!("PmidManager sending refresh for account {:?}",
                       src.get_name());
                let _ = routing_node.send_refresh_request(src, serialised_refresh);
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::random;
    use xor_name::XorName;

    #[test]
    fn exist() {
        let mut db = Database::new();
        let name = random();
        assert!(!db.storage.contains_key(&name));
        db.put_data(&name, 1024);
        assert!(db.storage.contains_key(&name));
    }

    // #[test]
    // fn put_data() {
    //     let mut db = Database::new();
    //     let name = random();
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
        let name = random();
        db.put_data(&name, 1024);
        assert!(db.storage.contains_key(&name));

        let account_value = Account::new(::rand::random::<u64>(), ::rand::random::<u64>());
        let account = Account::new(name.clone(), account_value.clone());
        db.handle_account_transfer(account);
        assert_eq!(db.storage[&name], account_value);
    }

    #[test]
    fn pmid_manager_account_serialisation() {
        let obj_before = Account::new(XorName([1u8; 64]),
                                      Account::new(::rand::random::<u64>(), ::rand::random::<u64>()));

        let mut e = ::cbor::Encoder::from_memory();
        unwrap_result!(e.encode(&[&obj_before]));

        let mut d = ::cbor::Decoder::from_bytes(e.as_bytes());
        let obj_after: Account = unwrap_result!(unwrap_option!(d.decode().next(), ""));

        assert_eq!(obj_before, obj_after);
    }

}
