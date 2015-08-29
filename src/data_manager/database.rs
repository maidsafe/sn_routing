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
use rustc_serialize::Encodable;
use std::collections::HashMap;

use routing_types::*;
use transfer_parser::transfer_tags::DATA_MANAGER_ACCOUNT_TAG;

type Identity = NameType; // name of the chunk
type PmidNode = NameType;

pub type PmidNodes = Vec<PmidNode>;

#[derive(RustcEncodable, RustcDecodable, PartialEq, Eq, Debug, Clone)]
pub struct DataManagerSendable {
    name: NameType,
    data_holders: PmidNodes,
    preserialised_content: Vec<u8>,
    has_preserialised_content: bool,
}

impl DataManagerSendable {
    pub fn new(name: NameType, data_holders: PmidNodes) -> DataManagerSendable {
        DataManagerSendable {
            name: name,
            data_holders: data_holders,
            preserialised_content: Vec::new(),
            has_preserialised_content: false,
        }
    }

    pub fn with_content(name: NameType, preserialised_content: Vec<u8>) -> DataManagerSendable {
        DataManagerSendable {
            name: name,
            data_holders: PmidNodes::new(),
            preserialised_content: preserialised_content,
            has_preserialised_content: true,
        }
    }

    pub fn get_data_holders(&self) -> PmidNodes {
        self.data_holders.clone()
    }
}

impl Sendable for DataManagerSendable {
    fn name(&self) -> NameType {
        self.name.clone()
    }

    fn type_tag(&self) -> u64 {
        DATA_MANAGER_ACCOUNT_TAG
    }

    fn serialised_contents(&self) -> Vec<u8> {
        if self.has_preserialised_content {
            self.preserialised_content.clone()
        } else {
            match ::routing::utils::encode(&self) {
                Ok(result) => result,
                Err(_) => Vec::new()
            }
        }
    }

    fn refresh(&self)->bool {
        true
    }

    fn merge(&self, responses: Vec<Box<Sendable>>) -> Option<Box<Sendable>> {
        let mut stats = Vec::<(PmidNodes, u64)>::new();
        for it in responses.iter() {
            let wrapper =
                match ::routing::utils::decode::<DataManagerSendable>(&it.serialised_contents()) {
                    Ok(result) => result,
                    Err(_) => { continue }
                };
            let push_in_vec = match stats.iter_mut().find(|a| a.0 == wrapper.get_data_holders()) {
                    Some(find_res) => { find_res.1 += 1; false }
                    None => { true }
                };
            if push_in_vec {
                stats.push((wrapper.get_data_holders(), 1));
            }
        }
        stats.sort_by(|a, b| b.1.cmp(&a.1));
        let (pmids, count) = stats[0].clone();
        if count >= (GROUP_SIZE as u64 + 1) / 2 {
            return Some(Box::new(DataManagerSendable::new(self.name.clone(), pmids)));
        }
        None
    }

}



pub struct DataManagerDatabase {
    storage : HashMap<Identity, PmidNodes>,
    pub close_grp_from_churn: Vec<NameType>,
    pub temp_storage_after_churn: HashMap<NameType, PmidNodes>,
}

impl DataManagerDatabase {
    pub fn new () -> DataManagerDatabase {
        DataManagerDatabase {
            storage: HashMap::with_capacity(10000),
            close_grp_from_churn: Vec::new(),
            temp_storage_after_churn: HashMap::new(),
        }
    }

    pub fn exist(&mut self, name : &Identity) -> bool {
        self.storage.contains_key(name)
    }

    pub fn put_pmid_nodes(&mut self, name : &Identity, pmid_nodes: PmidNodes) {
        let _ = self.storage.entry(name.clone()).or_insert(pmid_nodes.clone());
    }

    pub fn add_pmid_node(&mut self, name : &Identity, pmid_node: PmidNode) {
        let nodes = self.storage.entry(name.clone()).or_insert(vec![pmid_node.clone()]);
        if !nodes.contains(&pmid_node) {
            nodes.push(pmid_node);
        }
    }

    pub fn remove_pmid_node(&mut self, name : &Identity, pmid_node: PmidNode) {
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

    pub fn get_pmid_nodes(&mut self, name : &Identity) -> PmidNodes {
        match self.storage.get(&name) {
            Some(entry) => entry.clone(),
            None => Vec::<PmidNode>::new()
        }
    }


    pub fn handle_account_transfer(&mut self, account_wrapper : &DataManagerSendable) {
        // TODO: Assuming the incoming merged account entry has the priority and shall also be trusted first
        let _ = self.storage.remove(&account_wrapper.name());
        let _ = self.storage.insert(account_wrapper.name(), account_wrapper.get_data_holders());
        info!("DataManager updated account {:?} to {:?}",
              account_wrapper.name(), account_wrapper.get_data_holders());
    }

    pub fn retrieve_all_and_reset(&mut self, _close_group: &mut Vec<NameType>) -> Vec<MethodCall> {
        self.temp_storage_after_churn = self.storage.clone();
        let mut actions = Vec::<MethodCall>::new();
        for (key, value) in self.storage.iter() {
            if value.len() < 3 {
                for pmid_node in value.iter() {
                    info!("DataManager sends out a Get request in churn, fetching data {:?} from pmid_node {:?}",
                          *key, pmid_node);
                    actions.push(MethodCall::Get {
                        location: Authority::ManagedNode(pmid_node.clone()),
                        // DataManager only handles ImmutableData
                        data_request: DataRequest::ImmutableData((*key).clone(), ImmutableDataType::Normal)
                    });
                }
            }
            let data_manager_sendable = DataManagerSendable::new((*key).clone(), (*value).clone());
            let mut encoder = cbor::Encoder::from_memory();
            if encoder.encode(&[data_manager_sendable.clone()]).is_ok() {
                debug!("DataManager sends out a refresh regarding account {:?}", data_manager_sendable.name());
                actions.push(MethodCall::Refresh {
                    type_tag: DATA_MANAGER_ACCOUNT_TAG,
                    from_group: data_manager_sendable.name(),
                    payload: encoder.as_bytes().to_vec()
                });
            }
        }
        self.storage.clear();
        debug!("DataManager storage cleaned in churn with actions.len() = {:?}", actions.len());
        actions
    }
}

#[cfg(test)]
mod test {
  use super::*;
  use routing_types::*;

  #[test]
  fn exist() {
    let mut db = DataManagerDatabase::new();
    let value = generate_random_vec_u8(1024);
    let data = ImmutableData::new(ImmutableDataType::Normal, value);
    let mut pmid_nodes : Vec<NameType> = vec![];

    for _ in 0..4 {
      pmid_nodes.push(NameType(vector_as_u8_64_array(generate_random_vec_u8(64))));
    }

    let data_name = data.name();
    assert_eq!(db.exist(&data_name), false);
    db.put_pmid_nodes(&data_name, pmid_nodes);
    assert_eq!(db.exist(&data_name), true);
  }

  #[test]
  fn put() {
    let mut db = DataManagerDatabase::new();
    let value = generate_random_vec_u8(1024);
    let data = ImmutableData::new(ImmutableDataType::Normal, value);
    let data_name = data.name();
    let mut pmid_nodes : Vec<NameType> = vec![];

    for _ in 0..4 {
      pmid_nodes.push(NameType(vector_as_u8_64_array(generate_random_vec_u8(64))));
    }

    let result = db.get_pmid_nodes(&data_name);
    assert_eq!(result.len(), 0);

    db.put_pmid_nodes(&data_name, pmid_nodes.clone());

    let result = db.get_pmid_nodes(&data_name);
    assert_eq!(result.len(), pmid_nodes.len());
  }

  #[test]
  fn remove_pmid() {
    let mut db = DataManagerDatabase::new();
    let value = generate_random_vec_u8(1024);
    let data = ImmutableData::new(ImmutableDataType::Normal, value);
    let data_name = data.name();
    let mut pmid_nodes : Vec<NameType> = vec![];

    for _ in 0..4 {
      pmid_nodes.push(NameType(vector_as_u8_64_array(generate_random_vec_u8(64))));
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
    let mut db = DataManagerDatabase::new();
    let value = generate_random_vec_u8(1024);
    let data = ImmutableData::new(ImmutableDataType::Normal, value);
    let data_name = data.name();
    let mut pmid_nodes : Vec<NameType> = vec![];
    let mut new_pmid_nodes : Vec<NameType> = vec![];

    for _ in 0..4 {
      pmid_nodes.push(NameType(vector_as_u8_64_array(generate_random_vec_u8(64))));
      new_pmid_nodes.push(NameType(vector_as_u8_64_array(generate_random_vec_u8(64))));
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
    let mut db = DataManagerDatabase::new();
    let value = generate_random_vec_u8(1024);
    let data = ImmutableData::new(ImmutableDataType::Normal, value);
    let data_name = data.name();
    let mut pmid_nodes : Vec<NameType> = vec![];

    for _ in 0..4 {
      pmid_nodes.push(NameType(vector_as_u8_64_array(generate_random_vec_u8(64))));
    }
    db.put_pmid_nodes(&data_name, pmid_nodes.clone());
    assert_eq!(db.get_pmid_nodes(&data_name).len(), pmid_nodes.len());

    db.handle_account_transfer(&DataManagerSendable::new(data_name.clone(), vec![]));
    assert_eq!(db.get_pmid_nodes(&data_name).len(), 0);
  }
}
