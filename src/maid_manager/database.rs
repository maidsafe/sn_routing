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

impl Account {
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

    pub fn handle_account_transfer(&mut self, name: MaidNodeName, account: Account) {
        info!("MaidManager updating account {:?} to {:?}", name, account);
        let _ = self.storage.insert(name, account);
    }

    pub fn handle_churn(&mut self, routing_node: &Node, churn_event_id: &MessageId) {
        for (key, value) in self.storage.iter() {
            let src = Authority::ClientManager(key.clone());
            let refresh = Refresh {
                id: churn_event_id.clone(),
                name: key.clone(),
                value: RefreshValue::MaidManager(value.clone()),
            };
            if let Ok(serialised_refresh) = serialise(&refresh) {
                debug!("MaidManager sending refresh for account {:?}",
                       src.get_name());
                let _ = routing_node.send_refresh_request(src, serialised_refresh);
            }
        }
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
        unimplemented!();
    }
}
