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

use routing_types::*;

pub use self::database::{PmidManagerAccountWrapper, PmidManagerAccount};

pub struct PmidManager {
    db_ : database::PmidManagerDatabase
}

impl PmidManager {
    pub fn new() -> PmidManager {
        PmidManager {
            db_: database::PmidManagerDatabase::new()
        }
    }

    pub fn handle_put(&mut self, pmid_node: NameType, data: Data) -> Vec<MethodCall> {
        if self.db_.put_data(&pmid_node, data.payload_size() as u64) {
            vec![MethodCall::Put { location: Authority::ManagedNode(pmid_node.clone()),
                                   content: data }]
        } else {
            vec![]
        }
    }

    pub fn handle_put_response(&mut self, from_address: &NameType,
                               response: ResponseError) -> Vec<MethodCall> {
        match response {
            ResponseError::FailedRequestForData(data) => {
                self.db_.delete_data(from_address, data.payload_size() as u64);
                return vec![MethodCall::FailedPut { location: Authority::NaeManager(data.name()),
                                                    data: data }];
            },
            ResponseError::HadToClearSacrificial(name, size) => {
                self.db_.delete_data(from_address, size as u64);
                return vec![MethodCall::ClearSacrificial {
                    location: Authority::NaeManager(name), name: name, size: size }];
            },
            _ => {}
        }
        vec![]
    }

    pub fn handle_account_transfer(&mut self, merged_account: PmidManagerAccountWrapper) {
        self.db_.handle_account_transfer(&merged_account);
    }

    pub fn retrieve_all_and_reset(&mut self, close_group: &Vec<NameType>) -> Vec<MethodCall> {
        self.db_.retrieve_all_and_reset(close_group)
    }
}

#[cfg(test)]
mod test {
  use super::database::{PmidManagerAccount, PmidManagerAccountWrapper};
  use super::PmidManager;

  use routing_types::*;

  #[test]
  fn handle_put() {
    let mut pmid_manager = PmidManager::new();
    let dest = NameType(vector_as_u8_64_array(generate_random_vec_u8(64)));
    let value = generate_random_vec_u8(1024);
    let data = ImmutableData::new(ImmutableDataType::Normal, value);
    let put_result = pmid_manager.handle_put(dest, Data::ImmutableData(data.clone()));
    assert_eq!(put_result.len(), 1);
    match put_result[0].clone() {
        MethodCall::Put { location, content } => {
            assert_eq!(location, Authority::ManagedNode(dest));
            assert_eq!(content, Data::ImmutableData(data.clone()));
        }
        _ => panic!("Unexpected"),
    }
  }

    #[test]
    fn handle_account_transfer() {
        let mut pmid_manager = PmidManager::new();
        let name = NameType(vector_as_u8_64_array(generate_random_vec_u8(64)));
        let account_wrapper = PmidManagerAccountWrapper::new(name.clone(), PmidManagerAccount::new());
        pmid_manager.handle_account_transfer(account_wrapper);
        assert_eq!(pmid_manager.db_.exist(&name), true);
    }
}
