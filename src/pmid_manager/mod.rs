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

pub const ACCOUNT_TAG: u64 = ::transfer_tag::TransferTag::PmidManagerAccount as u64;
pub use self::database::Account;
pub use ::routing::Authority::NodeManager as Authority;

pub struct PmidManager {
    routing: ::vault::Routing,
    database: database::PmidManagerDatabase,
}

impl PmidManager {
    pub fn new(routing: ::vault::Routing) -> PmidManager {
        PmidManager { routing: routing, database: database::PmidManagerDatabase::new() }
    }

    pub fn handle_put(&mut self,
                      our_authority: &::routing::Authority,
                      from_authority: &::routing::Authority,
                      data: &::routing::data::Data) -> Option<()> {
        // Check if this is for this persona.
        if !::utils::is_pmid_manager_authority_type(&our_authority) {
            return ::utils::NOT_HANDLED;
        }

        // Validate from authority, and that the Data is ImmutableData.
        if !::utils::is_data_manager_authority_type(&from_authority) {
            warn!("Invalid authority for PUT at PmidManager: {:?}", from_authority);
            return ::utils::HANDLED;
        }
        let immutable_data = match data {
            &::routing::data::Data::ImmutableData(ref immutable_data) => immutable_data,
            _ => {
                warn!("Invalid data type for PUT at PmidManager: {:?}", data);
                return ::utils::HANDLED;
            }
        };

        // Handle the request and send on
        let pmid_node = our_authority.get_location();
        if self.database.put_data(pmid_node, immutable_data.payload_size() as u64) {
            let location = ::pmid_node::Authority(pmid_node.clone());
            let content = ::routing::data::Data::ImmutableData(immutable_data.clone());
            self.routing.put_request(our_authority.clone(), location, content);
        }
        ::utils::HANDLED
    }

    pub fn handle_put_response(&mut self,
                               from_address: &::routing::NameType,
                               response: ::routing::error::ResponseError)
                               -> Vec<::types::MethodCall> {
        match response {
            ::routing::error::ResponseError::FailedRequestForData(data) => {
                self.database.delete_data(from_address, data.payload_size() as u64);
                match data {
                    ::routing::data::Data::ImmutableData(immutable_data) => {
                        return vec![::types::MethodCall::FailedPut {
                                        location: ::data_manager::Authority(immutable_data.name()),
                                        data: ::routing::data::Data::ImmutableData(immutable_data)
                                    }];
                    },
                    _ => return vec![::types::MethodCall::Deprecated],
                }
            }
            ::routing::error::ResponseError::HadToClearSacrificial(name, size) => {
                self.database.delete_data(from_address, size as u64);
                return vec![::types::MethodCall::ClearSacrificial {
                    location: ::data_manager::Authority(name),
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

#[cfg(all(test, feature = "use-mock-routing"))]
mod test {
    use super::*;

    #[test]
    fn handle_put() {
        let routing = ::vault::Routing::new(::std::sync::mpsc::channel().0);
        let mut pmid_manager = PmidManager::new(routing.clone());

        let dest = ::utils::random_name();
        let our_authority = Authority(dest.clone());

        let from = ::utils::random_name();
        let from_authority = ::data_manager::Authority(from.clone());

        let value = ::routing::types::generate_random_vec_u8(1024);
        let data = ::routing::immutable_data::ImmutableData::new(
                       ::routing::immutable_data::ImmutableDataType::Normal, value);

        assert_eq!(::utils::HANDLED,
            pmid_manager.handle_put(&our_authority, &from_authority,
                                    &::routing::data::Data::ImmutableData(data.clone())));

        let put_requests = routing.put_requests_given();
        assert_eq!(put_requests.len(), 1);
        assert_eq!(put_requests[0].our_authority, our_authority);
        assert_eq!(put_requests[0].location, ::pmid_node::Authority(dest));
        assert_eq!(put_requests[0].data, ::routing::data::Data::ImmutableData(data));
    }
}
