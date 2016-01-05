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

use kademlia_routing_table;
use maidsafe_utilities::serialisation::serialise;
use routing::{Authority, DataRequest, ImmutableDataType, MessageId, Node, RequestContent};
use sodiumoxide::crypto::hash::sha512;
use types::{Refresh, RefreshValue};
use xor_name::XorName;

pub type PmidNode = XorName;
pub type PmidNodes = Vec<PmidNode>;
pub type DataName = XorName;

#[derive(RustcEncodable, RustcDecodable, PartialEq, Eq, Debug, Clone)]
pub struct Account {
    data_holders: PmidNodes,
    preserialised_content: Vec<u8>,
    has_preserialised_content: bool,
}

impl Account {
    fn new(data_holders: PmidNodes) -> Account {
        Account {
            data_holders: data_holders,
            preserialised_content: Vec::new(),
            has_preserialised_content: false,
        }
    }

    fn serialised_contents(&self) -> Vec<u8> {
        if self.has_preserialised_content {
            self.preserialised_content.clone()
        } else {
            serialise(&self).unwrap_or(vec![])
        }
    }
}



pub struct Database {
    storage: ::std::collections::HashMap<DataName, PmidNodes>,
}

impl Database {
    pub fn new() -> Database {
        Database { storage: ::std::collections::HashMap::with_capacity(10000) }
    }

    pub fn exist(&self, name: &DataName) -> bool {
        self.storage.contains_key(name)
    }

    pub fn put_pmid_nodes(&mut self, name: &DataName, pmid_nodes: PmidNodes) {
        let _ = self.storage.entry(name.clone()).or_insert(pmid_nodes.clone());
    }

    #[allow(unused)]
    pub fn add_pmid_node(&mut self, name: &DataName, pmid_node: PmidNode) {
        let nodes = self.storage.entry(name.clone()).or_insert(vec![pmid_node.clone()]);
        if !nodes.contains(&pmid_node) {
            nodes.push(pmid_node);
        }
    }

    pub fn remove_pmid_node(&mut self, name: &DataName, pmid_node: PmidNode) {
        if !self.storage.contains_key(name) {
            return;
        }
        let nodes = self.storage.entry(name.clone()).or_insert(vec![]);
        for i in 0..nodes.len() {
            if nodes[i] == pmid_node {
                let _ = nodes.remove(i);
                break;
            }
        }
    }

    pub fn get_pmid_nodes(&mut self, name: &DataName) -> PmidNodes {
        match self.storage.get(&name) {
            Some(entry) => entry.clone(),
            None => Vec::<PmidNode>::new(),
        }
    }

    pub fn handle_account_transfer(&mut self, name: DataName, account: Account) {
        info!("DataManager updating account {:?} to {:?}", name, account);
        let _ = self.storage.insert(name, account.data_holders);
    }

    pub fn handle_churn(&mut self, routing_node: &Node, churn_event_id: &MessageId) {
        for (key, value) in self.storage.iter() {
            let account = Account::new(value.clone());
            let src = Authority::NaeManager(key.clone());
            let refresh = Refresh {
                id: churn_event_id.clone(),
                name: key.clone(),
                value: RefreshValue::DataManager(account),
            };
            if let Ok(serialised_refresh) = serialise(&refresh) {
                debug!("DataManager sending refresh for account {:?}",
                       src.get_name());
                let _ = routing_node.send_refresh_request(src, serialised_refresh);
            }
        }
    }

    pub fn cleanup(&mut self) {
        self.storage.clear();
    }
}



#[cfg(test)]
mod test {
    use super::*;
    use rand::random;
    use routing::{ImmutableData, ImmutableDataType};
    use utils::test::generate_random_vec_u8;
    use xor_name::XorName;

    #[test]
    fn exist() {
        let mut db = Database::new();
        let value = generate_random_vec_u8(1024);
        let data = ::routing::ImmutableData::new(::routing::ImmutableDataType::Normal, value);
        let mut pmid_nodes: Vec<XorName> = vec![];

        for _ in 0..4 {
            pmid_nodes.push(random());
        }

        let data_name = data.name();
        assert_eq!(db.exist(&data_name), false);
        db.put_pmid_nodes(&data_name, pmid_nodes);
        assert_eq!(db.exist(&data_name), true);
    }

    #[test]
    fn put() {
        let mut db = Database::new();
        let value = generate_random_vec_u8(1024);
        let data = ImmutableData::new(ImmutableDataType::Normal, value);
        let data_name = data.name();
        let mut pmid_nodes: Vec<XorName> = vec![];

        for _ in 0..4 {
            pmid_nodes.push(random());
        }

        let result = db.get_pmid_nodes(&data_name);
        assert_eq!(result.len(), 0);

        db.put_pmid_nodes(&data_name, pmid_nodes.clone());

        let result = db.get_pmid_nodes(&data_name);
        assert_eq!(result.len(), pmid_nodes.len());
    }

    #[test]
    fn remove_pmid() {
        let mut db = Database::new();
        let value = generate_random_vec_u8(1024);
        let data = ImmutableData::new(ImmutableDataType::Normal, value);
        let data_name = data.name();
        let mut pmid_nodes: Vec<XorName> = vec![];

        for _ in 0..4 {
            pmid_nodes.push(random());
        }

        db.put_pmid_nodes(&data_name, pmid_nodes.clone());
        let result = db.get_pmid_nodes(&data_name);
        assert_eq!(result, pmid_nodes);

        db.remove_pmid_node(&data_name, pmid_nodes[0].clone());

        let result = db.get_pmid_nodes(&data_name);
        assert_eq!(result.len(), 3);
        for index in 0..result.len() {
            assert!(result[index] != pmid_nodes[0]);
        }
    }

    #[test]
    fn replace_pmids() {
        let mut db = Database::new();
        let value = generate_random_vec_u8(1024);
        let data = ImmutableData::new(ImmutableDataType::Normal, value);
        let data_name = data.name();
        let mut pmid_nodes: Vec<XorName> = vec![];
        let mut new_pmid_nodes: Vec<XorName> = vec![];

        for _ in 0..4 {
            pmid_nodes.push(random());
            new_pmid_nodes.push(random());
        }

        db.put_pmid_nodes(&data_name, pmid_nodes.clone());
        let result = db.get_pmid_nodes(&data_name);
        assert_eq!(result, pmid_nodes);
        assert!(result != new_pmid_nodes);

        for index in 0..4 {
            db.remove_pmid_node(&data_name, pmid_nodes[index].clone());
            db.add_pmid_node(&data_name, new_pmid_nodes[index].clone());
        }

        let result = db.get_pmid_nodes(&data_name);
        assert_eq!(result, new_pmid_nodes);
        assert!(result != pmid_nodes);
    }

    #[test]
    fn handle_account_transfer() {
        let mut db = Database::new();
        let value = generate_random_vec_u8(1024);
        let data = ImmutableData::new(ImmutableDataType::Normal, value);
        let data_name = data.name();
        let mut pmid_nodes: Vec<XorName> = vec![];

        for _ in 0..4 {
            pmid_nodes.push(random());
        }
        db.put_pmid_nodes(&data_name, pmid_nodes.clone());
        assert_eq!(db.get_pmid_nodes(&data_name).len(), pmid_nodes.len());

        db.handle_account_transfer(Account::new(data_name.clone(), vec![]));
        assert_eq!(db.get_pmid_nodes(&data_name).len(), 0);
    }
}
