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

mod database;

pub use self::database::Account;

pub struct PmidManager {
    database: database::PmidManagerDatabase,
}

impl PmidManager {
    pub fn new() -> PmidManager {
        PmidManager { database: database::PmidManagerDatabase::new() }
    }

    pub fn handle_put(&mut self,
                      pmid_node: ::routing::NameType,
                      data: ::routing::data::Data)
                      -> Vec<::types::MethodCall> {
        if self.database.put_data(&pmid_node, data.payload_size() as u64) {
            vec![::types::MethodCall::Put {
                     location: ::routing::authority::Authority::ManagedNode(pmid_node.clone()),
                     content: data
                 }]
        } else {
            vec![]
        }
    }

    pub fn handle_put_response(&mut self,
                               from_address: &::routing::NameType,
                               response: ::routing::error::ResponseError)
                               -> Vec<::types::MethodCall> {
        match response {
            ::routing::error::ResponseError::FailedRequestForData(data) => {
                self.database.delete_data(from_address, data.payload_size() as u64);
                return vec![::types::MethodCall::FailedPut {
                                location: ::routing::authority::Authority::NaeManager(data.name()),
                                data: data
                            }];
            }
            ::routing::error::ResponseError::HadToClearSacrificial(name, size) => {
                self.database.delete_data(from_address, size as u64);
                return vec![::types::MethodCall::ClearSacrificial {
                    location: ::routing::authority::Authority::NaeManager(name),
                    name: name,
                    size: size
                }];
            }
            _ => {}
        }
        vec![]
    }

    pub fn handle_get_failure_notification(&mut self,
                                           from_address: &::routing::NameType,
                                           response: ::routing::error::ResponseError)
                                           -> Vec<::types::MethodCall> {
        match response {
            ::routing::error::ResponseError::FailedRequestForData(data) => {
                self.database.delete_data(from_address, data.payload_size() as u64);
            }
            _ => {}
        }
        vec![]
    }

    pub fn handle_account_transfer(&mut self, merged_account: Account) {
        self.database.handle_account_transfer(merged_account);
    }

    pub fn retrieve_all_and_reset(&mut self,
                                  close_group: &Vec<::routing::NameType>)
                                  -> Vec<::types::MethodCall> {
        self.database.retrieve_all_and_reset(close_group)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn handle_put() {
        let mut pmid_manager = PmidManager::new();
        let dest = ::utils::random_name();
        let value = ::routing::types::generate_random_vec_u8(1024);
        let data = ::routing::immutable_data::ImmutableData::new(
                       ::routing::immutable_data::ImmutableDataType::Normal, value);
        let put_result =
            pmid_manager.handle_put(dest, ::routing::data::Data::ImmutableData(data.clone()));
        assert_eq!(put_result.len(), 1);
        match put_result[0].clone() {
            ::types::MethodCall::Put { location, content } => {
                assert_eq!(location, ::routing::authority::Authority::ManagedNode(dest));
                assert_eq!(content, ::routing::data::Data::ImmutableData(data.clone()));
            }
            _ => panic!("Unexpected"),
        }
    }
}
