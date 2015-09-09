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

use transfer_parser::transfer_tags::DATA_MANAGER_STATS_TAG;
use utils;

type Address = ::routing::NameType;

pub use self::database::Account;

pub static PARALLELISM: usize = 4;

pub struct DataManager {
  database: database::Database,
  // the higher the index is, the slower the farming rate will be
  resource_index: u64
}

#[derive(RustcEncodable, RustcDecodable, Clone, PartialEq, Eq, Debug)]
pub struct Stats {
    name: ::routing::NameType,
    resource_index: u64
}

impl Stats {
    pub fn new(name: ::routing::NameType, resource_index: u64) -> Stats {
        Stats {
            name: name,
            resource_index: resource_index
        }
    }

    pub fn name(&self) -> &::routing::NameType {
        &self.name
    }

    pub fn resource_index(&self) -> u64 {
        self.resource_index
    }
}

impl ::types::Refreshable for Stats {
    fn merge(from_group: ::routing::NameType,
             responses: Vec<Stats>) -> Option<Stats> {
        let mut resource_indexes: Vec<u64> = Vec::new();
        for value in responses {
            match ::routing::utils::decode::<Stats>(&value.serialised_contents()) {
                Ok(refreshable) => {
                    if *refreshable.name() == from_group {
                        resource_indexes.push(refreshable.resource_index());
                    }
                },
                Err(_) => {}
            }
        }
        Some(Stats::new(::routing::NameType([0u8; 64]), utils::median(resource_indexes)))
    }
}




impl DataManager {
    pub fn new() -> DataManager {
        DataManager { database: database::Database::new(), resource_index: 1 }
    }

    pub fn handle_get(&mut self, name: &::routing::NameType, data_request: ::routing::data::DataRequest) -> Vec<::types::MethodCall> {
        let result = self.database.get_pmid_nodes(name);
        if result.len() == 0 {
            return vec![];
        }

        let mut forward_to_pmids: Vec<::types::MethodCall> = Vec::new();
        for pmid in result.iter() {
            forward_to_pmids.push(::types::MethodCall::Get { location: ::routing::authority::Authority::ManagedNode(pmid.clone()),
                                              data_request: data_request.clone() });
        }
        forward_to_pmids
    }

    pub fn handle_put(&mut self, data: ::routing::immutable_data::ImmutableData,
                      nodes_in_table: &mut Vec<::routing::NameType>) -> Vec<::types::MethodCall> {
      let data_name = data.name();
      if self.database.exist(&data_name) {
          return vec![];
      }

      nodes_in_table.sort_by(|a, b|
          if ::routing::closer_to_target(&a, &b, &data_name) {
            cmp::Ordering::Less
          } else {
            cmp::Ordering::Greater
          });
      let pmid_nodes_num = cmp::min(nodes_in_table.len(), PARALLELISM);
      let mut dest_pmids: Vec<::routing::NameType> = Vec::new();
      for index in 0..pmid_nodes_num {
          dest_pmids.push(nodes_in_table[index].clone());
      }
      self.database.put_pmid_nodes(&data_name, dest_pmids.clone());
      match *data.get_type_tag() {
          ::routing::immutable_data::ImmutableDataType::Sacrificial => {
              self.resource_index = cmp::min(1048576, self.resource_index + dest_pmids.len() as u64);
          }
          _ => {}
      }
      let mut forwarding_calls: Vec<::types::MethodCall> = Vec::new();
      for pmid in dest_pmids {
          forwarding_calls.push(::types::MethodCall::Put { location: ::routing::authority::Authority::NodeManager(pmid.clone()),
                                                  content: ::routing::data::Data::ImmutableData(data.clone()), });
      }
      forwarding_calls
    }

    pub fn handle_get_response(&mut self, response: ::routing::data::Data) -> Vec<::types::MethodCall> {
        let replicate_to = self.replicate_to(&response.name());
        match replicate_to {
            Some(pmid_node) => {
                self.database.add_pmid_node(&response.name(), pmid_node.clone());
                vec![::types::MethodCall::Put { location: ::routing::authority::Authority::ManagedNode(pmid_node), content: response, }]
            },
            None => vec![]
        }
    }

    pub fn handle_put_response(&mut self, response: ::routing::error::ResponseError,
                               from_address: &::routing::NameType) -> Vec<::types::MethodCall> {
        info!("DataManager handle_put_responsen from {:?}", from_address);
        match response {
            ::routing::error::ResponseError::FailedRequestForData(data) => {
                // TODO: giving more weight when failed in storing a Normal immutable data ?
                self.resource_index = cmp::max(1, self.resource_index - 4);
                match data.clone() {
                    // DataManager shall only handle Immutable data
                    // Structured Data shall be handled in StructuredDataManager
                    ::routing::data::Data::ImmutableData(immutable_data) => {
                        let name = data.name();
                        self.database.remove_pmid_node(&name, from_address.clone());
                        match *immutable_data.get_type_tag() {
                            ::routing::immutable_data::ImmutableDataType::Normal => {
                                let replicate_to = self.replicate_to(&name);
                                match replicate_to {
                                    Some(pmid_node) => {
                                        self.database.add_pmid_node(&name, pmid_node.clone());
                                        return vec![::types::MethodCall::Put { location: ::routing::authority::Authority::NodeManager(pmid_node),
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
            ::routing::error::ResponseError::HadToClearSacrificial(name, _) => {
                // giving less weight when removing a sacrificial data
                self.resource_index = cmp::max(1, self.resource_index - 1);
                self.database.remove_pmid_node(&name, from_address.clone());
            },
            _ => {}
        }
        vec![]
    }

    pub fn handle_account_transfer(&mut self, merged_account: Account) {
        self.database.handle_account_transfer(merged_account);
    }

    pub fn handle_stats_transfer(&mut self, merged_stats: Stats) {
        // TODO: shall give more priority to the incoming stats?
        self.resource_index = (self.resource_index + merged_stats.resource_index()) / 2;
    }

    pub fn retrieve_all_and_reset(&mut self, close_group: &mut Vec<::routing::NameType>) -> Vec<::types::MethodCall> {
        // TODO: as Vault doesn't have access to what ID it is, we have to use the first one in the
        //       close group as its ID
        let mut result = self.database.retrieve_all_and_reset(close_group);
        let data_manager_stats =
            Stats::new(close_group[0].clone(), self.resource_index);
        let mut encoder = cbor::Encoder::from_memory();
        if encoder.encode(&[data_manager_stats.clone()]).is_ok() {
            result.push(::types::MethodCall::Refresh {
                type_tag: DATA_MANAGER_STATS_TAG, from_group: *data_manager_stats.name(),
                payload: encoder.as_bytes().to_vec()
            });
        }
        result
    }

    fn replicate_to(&mut self, name: &::routing::NameType) -> Option<::routing::NameType> {
        match self.database.temp_storage_after_churn.get(name) {
            Some(pmid_nodes) => {
                if pmid_nodes.len() < 3 {
                    self.database.close_grp_from_churn.sort_by(|a, b| {
                        if ::routing::closer_to_target(&a, &b, &name) {
                          cmp::Ordering::Less
                        } else {
                          cmp::Ordering::Greater
                        }
                    });
                    let mut close_grp_node_to_add = ::routing::NameType::new([0u8; 64]);
                    for close_grp_it in self.database.close_grp_from_churn.iter() {
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
    use super::{DataManager, Stats};
    use super::database::Account;

    #[test]
    fn handle_put_get() {
        let mut data_manager = DataManager::new();
        let value = ::routing::types::generate_random_vec_u8(1024);
        let data = ::routing::immutable_data::ImmutableData::new(::routing::immutable_data::ImmutableDataType::Normal, value);
        let mut nodes_in_table = vec![::routing::NameType::new([1u8; 64]), ::routing::NameType::new([2u8; 64]), ::routing::NameType::new([3u8; 64]), ::routing::NameType::new([4u8; 64]),
                                      ::routing::NameType::new([5u8; 64]), ::routing::NameType::new([6u8; 64]), ::routing::NameType::new([7u8; 64]), ::routing::NameType::new([8u8; 64])];
        {
            let put_result = data_manager.handle_put(data.clone(), &mut nodes_in_table);
            assert_eq!(put_result.len(), super::PARALLELISM);
            for i in 0..put_result.len() {
                match put_result[i].clone() {
                    ::types::MethodCall::Put { location, content } => {
                        assert_eq!(location, ::routing::authority::Authority::NodeManager(nodes_in_table[i]));
                        assert_eq!(content, ::routing::data::Data::ImmutableData(data.clone()));
                    }
                    _ => panic!("Unexpected"),
                }
            }
        }
        let data_name = ::routing::NameType::new(data.name().get_id());
        {
            let request = ::routing::data::DataRequest::ImmutableData(data_name.clone(), ::routing::immutable_data::ImmutableDataType::Normal);
            let get_result = data_manager.handle_get(&data_name, request.clone());
            assert_eq!(get_result.len(), super::PARALLELISM);
            for i in 0..get_result.len() {
                match get_result[i].clone() {
                    ::types::MethodCall::Get { location, data_request } => {
                        assert_eq!(location, ::routing::authority::Authority::ManagedNode(nodes_in_table[i]));
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
        let name = ::utils::random_name();
        let account = Account::new(name.clone(), vec![]);
        data_manager.handle_account_transfer(account);
        assert_eq!(data_manager.database.exist(&name), true);
    }

    #[test]
    fn handle_stats_transfer() {
        let mut data_manager = DataManager::new();
        let name = ::utils::random_name();
        let stats = Stats::new(name.clone(), 1023);
        data_manager.handle_stats_transfer(stats);
        assert_eq!(data_manager.resource_index, 512);
    }
}
