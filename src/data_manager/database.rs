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
use routing::{Authority, DataRequest, ImmutableDataType, RequestContent};
use xor_name::XorName;

pub type DataName = XorName;
pub type PmidNodes = Vec<PmidNode>;

type PmidNode = XorName;

#[derive(RustcEncodable, RustcDecodable, PartialEq, Eq, Debug, Clone)]
pub struct Account {
    name: DataName,
    data_holders: PmidNodes,
    preserialised_content: Vec<u8>,
    has_preserialised_content: bool,
}

impl Account {
    fn new(name: DataName, data_holders: PmidNodes) -> Account {
        Account {
            name: name,
            data_holders: data_holders,
            preserialised_content: Vec::new(),
            has_preserialised_content: false,
        }
    }
}

impl ::types::Refreshable for Account {
    fn serialised_contents(&self) -> Vec<u8> {
        if self.has_preserialised_content {
            self.preserialised_content.clone()
        } else {
            serialise(&self).unwrap_or(vec![])
        }
    }

    fn merge(from_group: XorName, responses: Vec<Account>) -> Option<Account> {
        let mut candidates = vec![];
        let mut stats = Vec::<(PmidNode, u64)>::new();
        for response in responses {
            debug!("DataManager merging one response of chunk {:?} stored on nodes {:?}",
                   response.name,
                   response.data_holders);
            if response.name == from_group {
                for holder in response.data_holders.iter() {
                    if candidates.contains(holder) {
                        match stats.iter_mut().find(|a| a.0 == *holder) {
                            Some(find_res) => find_res.1 += 1,
                            None => {}
                        };
                    } else {
                        stats.push((holder.clone(), 1));
                        candidates.push(holder.clone());
                    }
                }
            }
        }
        stats.sort_by(|a, b| b.1.cmp(&a.1));
        let mut pmids = vec![];
        for i in 0..stats.len() {
            if stats[i].1 >= (kademlia_routing_table::GROUP_SIZE as u64 + 1) / 2 {
                pmids.push(stats[i].0.clone());
            }
        }
        debug!("DataManager merged chunk {:?} stored on nodes {:?}",
               from_group,
               pmids);
        if pmids.len() == 0 {
            None
        } else {
            Some(Account::new(from_group, pmids))
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

    pub fn exist(&mut self, name: &DataName) -> bool {
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


    pub fn handle_account_transfer(&mut self, merged_account: Account) {
        let _ = self.storage.remove(&merged_account.name);
        let data_holders = merged_account.data_holders.clone();
        let _ = self.storage.insert(merged_account.name, merged_account.data_holders);
        info!("DataManager updated account {:?} to {:?}",
              merged_account.name,
              data_holders);
    }

    pub fn handle_churn(&mut self,
                        routing: &::vault::Routing,
                        churn_node: &XorName,
                        offline: bool)
                        -> Vec<(XorName, Vec<XorName>)> {
        let mut on_going_gets = vec![];
        for (key, mut value) in self.storage.iter_mut() {
            if offline {
                for i in 0..value.len() {
                    if value[i] == *churn_node {
                        let _ = value.remove(i);
                        for pmid_node in value.iter() {
                            info!("DataManager sends out a Get request in churn_down, fetching data {:?} from \
                                   pmid_node {:?}",
                                  *key,
                                  pmid_node);
                            let src = Authority::NaeManager((*key).clone());
                            let dst = Authority::ManagedNode(pmid_node.clone());
                            let content = RequestContent::Get(DataRequest::ImmutableData((*key).clone(),
                                                                                         ImmutableDataType::Backup));
                            let _ = routing.send_get_request(src, dst, content);
                        }
                        on_going_gets.push(((*key).clone(), (*value).clone()));
                        break;
                    }
                }
            }

            let account = Account::new((*key).clone(), (*value).clone());
            let target_authority = Authority::NaeManager(account.name.clone());
            if let Ok(serialised_account) = serialise(&[account]) {
                debug!("DataManager sending refresh for account {:?}",
                       target_authority.get_name());
                let _ = routing.send_refresh_request(super::ACCOUNT_TAG,
                                                     target_authority,
                                                     serialised_account,
                                                     churn_node.clone());
            }
        }
        // As pointed out in https://github.com/maidsafe/safe_vault/issues/250
        // the uncontrollable order of events (churn/refresh/account_transfer)
        // forcing the node have to keep its current records to avoid losing record
        // self.cleanup();
        on_going_gets
    }

    pub fn do_refresh(&mut self,
                      type_tag: &u64,
                      our_authority: &::routing::Authority,
                      churn_node: &XorName,
                      routing: &::vault::Routing)
                      -> Option<()> {
        if type_tag == &super::ACCOUNT_TAG {
            for (key, value) in self.storage.iter() {
                if key == our_authority.get_name() {
                    let account = Account::new((*key).clone(), (*value).clone());
                    if let Ok(serialised_account) = serialise(&[account]) {
                        debug!("DataManager sending on_refresh for account {:?}",
                               our_authority.get_name());
                        let _ = routing.send_refresh_request(super::ACCOUNT_TAG,
                                                             our_authority.clone(),
                                                             serialised_account,
                                                             churn_node.clone());
                    }
                }
            }
            return ::utils::HANDLED;
        }
        ::utils::NOT_HANDLED
    }

    #[allow(unused)]
    pub fn cleanup(&mut self) {
        self.storage.clear();
    }
}



#[cfg(test)]
mod test {
    use super::*;
    use rand::random;
    use routing::{ImmutableData, ImmutableDataType};
    use xor_name::XorName;

    #[test]
    fn exist() {
        let mut db = Database::new();
        let value = ::routing::types::generate_random_vec_u8(1024);
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
        let value = ::routing::types::generate_random_vec_u8(1024);
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
        let value = ::routing::types::generate_random_vec_u8(1024);
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
        let value = ::routing::types::generate_random_vec_u8(1024);
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
        let value = ::routing::types::generate_random_vec_u8(1024);
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
