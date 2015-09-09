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

type Address = ::routing::NameType;

pub struct MaidManager {
    database : database::MaidManagerDatabase
}

impl MaidManager {
    pub fn new() -> MaidManager {
        MaidManager {
            database: database::MaidManagerDatabase::new()
        }
    }

    pub fn handle_put(&mut self, from: &::routing::NameType,
                      from_authority: ::routing::authority::Authority,
                      data: ::routing::data::Data) -> Vec<::types::MethodCall> {
        if self.database.put_data(from, data.payload_size() as u64) {
            vec![::types::MethodCall::Put { location: ::routing::authority::Authority::NaeManager(data.name()), content: data }]
        } else {
            vec![::types::MethodCall::LowBalance { location: from_authority,
                                                   data: data, balance: self.database.get_balance(from) as u32}]
        }
    }

    pub fn handle_account_transfer(&mut self, merged_account: Account) {
        self.database.handle_account_transfer(merged_account);
    }

    pub fn retrieve_all_and_reset(&mut self) -> Vec<::types::MethodCall> {
        self.database.retrieve_all_and_reset()
    }
}

#[cfg(test)]
mod test {
    use sodiumoxide::crypto;

    use super::*;

    #[test]
    fn handle_put() {
        let mut maid_manager = MaidManager::new();
        let from = ::utils::random_name();
        let keys = crypto::sign::gen_keypair();
        let client = ::routing::authority::Authority::Client(from, keys.0);
        let value = ::routing::types::generate_random_vec_u8(1024);
        let data = ::routing::immutable_data::ImmutableData::new(::routing::immutable_data::ImmutableDataType::Normal, value);
        let put_result = maid_manager.handle_put(&from, client, ::routing::data::Data::ImmutableData(data.clone()));
        assert_eq!(put_result.len(), 1);
        match put_result[0] {
            ::types::MethodCall::Put { ref location, ref content } => {
                assert_eq!(*location, ::routing::authority::Authority::NaeManager(data.name()));
                assert_eq!(*content, ::routing::data::Data::ImmutableData(data));
            }
            _ => panic!("Unexpected"),
        }
    }
}
