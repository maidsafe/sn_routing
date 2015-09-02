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

pub use self::database::{MaidManagerAccountWrapper, MaidManagerAccount};

type Address = NameType;

pub struct MaidManager {
    db_ : database::MaidManagerDatabase
}

impl MaidManager {
    pub fn new() -> MaidManager {
        MaidManager {
            db_: database::MaidManagerDatabase::new()
        }
    }

    pub fn handle_put(&mut self, from: &NameType, data: Data) -> Vec<MethodCall> {
        if self.db_.put_data(from, data.payload_size() as u64) {
            vec![MethodCall::Put { location: Authority::NaeManager(data.name()), content: data }]
        } else {
            vec![MethodCall::NotEnoughAllowance]
        }
    }

    pub fn handle_account_transfer(&mut self, merged_account: MaidManagerAccountWrapper) {
        self.db_.handle_account_transfer(&merged_account);
    }

    pub fn retrieve_all_and_reset(&mut self) -> Vec<MethodCall> {
        self.db_.retrieve_all_and_reset()
    }

}

#[cfg(test)]
mod test {
    use super::*;

    use routing_types::*;

    #[test]
    fn handle_put() {
        let mut maid_manager = MaidManager::new();
        let from = NameType(vector_as_u8_64_array(generate_random_vec_u8(64)));
        let value = generate_random_vec_u8(1024);
        let data = ImmutableData::new(ImmutableDataType::Normal, value);
        let put_result = maid_manager.handle_put(&from, Data::ImmutableData(data.clone()));
        assert_eq!(put_result.len(), 1);
        match put_result[0] {
            MethodCall::Put { ref location, ref content } => {
                assert_eq!(*location, Authority::NaeManager(data.name()));
                assert_eq!(*content, Data::ImmutableData(data));
            }
            _ => panic!("Unexpected"),
        }
    }

    #[test]
    fn handle_account_transfer() {
        let mut maid_manager = MaidManager::new();
        let name = NameType(vector_as_u8_64_array(generate_random_vec_u8(64)));
        let account_wrapper = MaidManagerAccountWrapper::new(name.clone(), MaidManagerAccount::new());
        maid_manager.handle_account_transfer(account_wrapper);
        assert_eq!(maid_manager.db_.exist(&name), true);
    }
}
