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

mod database;

use std::cmp;
use cbor;
use rustc_serialize::Encodable;

use routing_types::*;
use transfer_parser::transfer_tags::DATA_MANAGER_STATS_TAG;
use utils;

type Address = NameType;

pub use self::database::DataManagerSendable;

pub static PARALLELISM: usize = 4;

pub struct DataManager {
  db_: database::DataManagerDatabase,
  // the higher the index is, the slower the farming rate will be
  resource_index: u64
}

#[derive(RustcEncodable, RustcDecodable, Clone, PartialEq, Eq, Debug)]
pub struct DataManagerStatsSendable {
    name: NameType,
    resource_index: u64
}

impl DataManagerStatsSendable {
    pub fn new(name: NameType, resource_index: u64) -> DataManagerStatsSendable {
        DataManagerStatsSendable {
            name: name,
            resource_index: resource_index
        }
    }

    pub fn get_resource_index(&self) -> u64 {
        self.resource_index
    }
}

impl Sendable for DataManagerStatsSendable {
    fn name(&self) -> NameType {
        self.name.clone()
    }

    fn type_tag(&self) -> u64 {
        DATA_MANAGER_STATS_TAG
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
        let mut resource_indexes: Vec<u64> = Vec::new();
        for value in responses {
            match ::routing::utils::decode::<DataManagerStatsSendable>(
                    &value.serialised_contents()) {
                Ok(senderable) => { resource_indexes.push(senderable.get_resource_index()); }
                Err(_) => {}
            }
        }
        Some(Box::new(DataManagerStatsSendable::new(NameType([0u8; 64]),
                                                    utils::median(resource_indexes))))
    }
}



impl DataManager {
    pub fn new() -> DataManager {
        DataManager { db_: database::DataManagerDatabase::new(), resource_index: 1 }
    }

    pub fn handle_get(&mut self, name: &NameType, data_request: DataRequest) -> Vec<MethodCall> {
        let result = self.db_.get_pmid_nodes(name);
        if result.len() == 0 {
            return vec![];
        }

        let mut forward_to_pmids: Vec<MethodCall> = Vec::new();
        for pmid in result.iter() {
            forward_to_pmids.push(MethodCall::Get { location: Authority::ManagedNode(pmid.clone()),
                                              data_request: data_request.clone() });
        }
        forward_to_pmids
    }

    pub fn handle_put(&mut self, data: ImmutableData,
                      nodes_in_table: &mut Vec<NameType>) -> Vec<MethodCall> {
      let data_name = data.name();
      if self.db_.exist(&data_name) {
          return vec![];
      }

      nodes_in_table.sort_by(|a, b|
          if closer_to_target(&a, &b, &data_name) {
            cmp::Ordering::Less
          } else {
            cmp::Ordering::Greater
          });
      let pmid_nodes_num = cmp::min(nodes_in_table.len(), PARALLELISM);
      let mut dest_pmids: Vec<NameType> = Vec::new();
      for index in 0..pmid_nodes_num {
          dest_pmids.push(nodes_in_table[index].clone());
      }
      self.db_.put_pmid_nodes(&data_name, dest_pmids.clone());
      match *data.get_type_tag() {
          ImmutableDataType::Sacrificial => {
              self.resource_index = cmp::min(1048576, self.resource_index + dest_pmids.len() as u64);
          }
          _ => {}
      }
      let mut forwarding_calls: Vec<MethodCall> = Vec::new();
      for pmid in dest_pmids {
          forwarding_calls.push(MethodCall::Put { location: Authority::NodeManager(pmid.clone()),
                                                  content: Data::ImmutableData(data.clone()), });
      }
      forwarding_calls
    }

    pub fn handle_get_response(&mut self, response: Data) -> Vec<MethodCall> {
        let replicate_to = self.replicate_to(&response.name());
        match replicate_to {
            Some(pmid_node) => {
                self.db_.add_pmid_node(&response.name(), pmid_node.clone());
                vec![MethodCall::Put { location: Authority::ManagedNode(pmid_node), content: response, }]
            },
            None => vec![]
        }
    }

    pub fn handle_put_response(&mut self, response: ResponseError,
                               from_address: &NameType) -> Vec<MethodCall> {
        info!("DataManager handle_put_responsen from {:?}", from_address);
        match response {
            ResponseError::FailedRequestForData(data) => {
                // TODO: giving more weight when failed in storing a Normal immutable data ?
                self.resource_index = cmp::max(1, self.resource_index - 4);
                match data.clone() {
                    // DataManager shall only handle Immutable data
                    // Structured Data shall be handled in StructuredDataManager
                    Data::ImmutableData(immutable_data) => {
                        let name = data.name();
                        self.db_.remove_pmid_node(&name, from_address.clone());
                        match *immutable_data.get_type_tag() {
                            ImmutableDataType::Normal => {
                                let replicate_to = self.replicate_to(&name);
                                match replicate_to {
                                    Some(pmid_node) => {
                                        self.db_.add_pmid_node(&name, pmid_node.clone());
                                        return vec![MethodCall::Put { location: Authority::NodeManager(pmid_node), 
                                                                      content: data }];
                                    },
                                    None => {}
                                }
                            }
                            _ => {}
                        }
                    }
                    _ => {}
                }
            },
            ResponseError::HadToClearSacrificial(name, _) => {
                // giving less weight when removing a sacrificial data
                self.resource_index = cmp::max(1, self.resource_index - 1);
                self.db_.remove_pmid_node(&name, from_address.clone());
            },
            _ => {}
        }
        vec![]
    }

    pub fn handle_account_transfer(&mut self, merged_account: DataManagerSendable) {
        self.db_.handle_account_transfer(&merged_account);
    }

    pub fn handle_stats_transfer(&mut self, merged_stats: DataManagerStatsSendable) {
        // TODO: shall give more priority to the incoming stats?
        self.resource_index = (self.resource_index + merged_stats.get_resource_index()) / 2;
    }

    pub fn retrieve_all_and_reset(&mut self, close_group: &mut Vec<NameType>) -> Vec<MethodCall> {
        // TODO: as Vault doesn't have access to what ID it is, we have to use the first one in the
        //       close group as its ID
        let mut result = self.db_.retrieve_all_and_reset(close_group);
        let data_manager_stats_sendable =
            DataManagerStatsSendable::new(close_group[0].clone(), self.resource_index);
        let mut encoder = cbor::Encoder::from_memory();
        if encoder.encode(&[data_manager_stats_sendable.clone()]).is_ok() {
            result.push(MethodCall::Refresh {
                type_tag: DATA_MANAGER_STATS_TAG, from_group: data_manager_stats_sendable.name(),
                payload: encoder.as_bytes().to_vec()
            });
        }
        result
    }

    fn replicate_to(&mut self, name: &NameType) -> Option<NameType> {
        match self.db_.temp_storage_after_churn.get(name) {
            Some(pmid_nodes) => {
                if pmid_nodes.len() < 3 {
                    self.db_.close_grp_from_churn.sort_by(|a, b| {
                        if closer_to_target(&a, &b, &name) {
                          cmp::Ordering::Less
                        } else {
                          cmp::Ordering::Greater
                        }
                    });
                    let mut close_grp_node_to_add = NameType::new([0u8; 64]);
                    for close_grp_it in self.db_.close_grp_from_churn.iter() {
                        if pmid_nodes.iter().find(|a| **a == *close_grp_it).is_none() {
                            close_grp_node_to_add = close_grp_it.clone();
                            break;
                        }
                    }
                    return Some(close_grp_node_to_add);
                }
            },
            None => {}
        }
        None
    }
}

#[cfg(test)]
mod test {
    use super::{DataManager, DataManagerStatsSendable};
    use super::database::DataManagerSendable;

    use routing_types::*;

    #[test]
    fn handle_put_get() {
        let mut data_manager = DataManager::new();
        let value = generate_random_vec_u8(1024);
        let data = ImmutableData::new(ImmutableDataType::Normal, value);
        let mut nodes_in_table = vec![NameType::new([1u8; 64]), NameType::new([2u8; 64]), NameType::new([3u8; 64]), NameType::new([4u8; 64]),
                                      NameType::new([5u8; 64]), NameType::new([6u8; 64]), NameType::new([7u8; 64]), NameType::new([8u8; 64])];
        {
            let put_result = data_manager.handle_put(data.clone(), &mut nodes_in_table);
            assert_eq!(put_result.len(), super::PARALLELISM);
            for i in 0..put_result.len() {
                match put_result[i].clone() {
                    MethodCall::Put { location, content } => {
                        assert_eq!(location, Authority::NodeManager(nodes_in_table[i]));
                        assert_eq!(content, Data::ImmutableData(data.clone()));
                    }
                    _ => panic!("Unexpected"),
                }
            }
        }
        let data_name = NameType::new(data.name().get_id());
        {
            let request = DataRequest::ImmutableData(data_name.clone(), ImmutableDataType::Normal);
            let get_result = data_manager.handle_get(&data_name, request.clone());
            assert_eq!(get_result.len(), super::PARALLELISM);
            for i in 0..get_result.len() {
                match get_result[i].clone() {
                    MethodCall::Get { location, data_request } => {
                        assert_eq!(location, Authority::ManagedNode(nodes_in_table[i]));
                        assert_eq!(data_request, request);
                    }
                    _ => panic!("Unexpected"),
                }
            }
        }
    }

    #[test]
    fn handle_account_transfer() {
        let mut data_manager = DataManager::new();
        let name = NameType(vector_as_u8_64_array(generate_random_vec_u8(64)));
        let account_wrapper = DataManagerSendable::new(name.clone(), vec![]);
        data_manager.handle_account_transfer(account_wrapper);
        assert_eq!(data_manager.db_.exist(&name), true);
    }

    #[test]
    fn handle_stats_transfer() {
        let mut data_manager = DataManager::new();
        let name = NameType(vector_as_u8_64_array(generate_random_vec_u8(64)));
        let stats_sendable = DataManagerStatsSendable::new(name.clone(), 1023);
        data_manager.handle_stats_transfer(stats_sendable);
        assert_eq!(data_manager.resource_index, 512);
    }
}
