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

    pub fn handle_refresh(&mut self, type_tag: &u64, our_authority: &::routing::Authority,
                          payloads: &Vec<Vec<u8>>) -> Option<()> {
        if *type_tag == ACCOUNT_TAG {
            if let &Authority(from_group) = our_authority {
                if let Some(merged) = ::utils::merge::<Account>(from_group,
                                                                payloads.clone()) {
                    self.handle_account_transfer(merged);
                    return ::utils::HANDLED;
                }
            }
        }
        ::utils::NOT_HANDLED
    }

    fn handle_account_transfer(&mut self, merged_account: Account) {
        self.database.handle_account_transfer(merged_account);
    }

    pub fn handle_churn(&mut self, close_group: &Vec<::routing::NameType>) {
        self.database.handle_churn(close_group, &self.routing);
    }
}

#[cfg(all(test, feature = "use-mock-routing"))]
mod test {
    use cbor;

    use super::*;

    fn env_setup() -> (::routing::Authority, ::vault::Routing, PmidManager,
                       ::routing::Authority, ::routing::immutable_data::ImmutableData) {
        let routing = ::vault::Routing::new(::std::sync::mpsc::channel().0);
        let pmid_manager = PmidManager::new(routing.clone());
        let value = ::routing::types::generate_random_vec_u8(1024);
        let data = ::routing::immutable_data::ImmutableData::new(
                       ::routing::immutable_data::ImmutableDataType::Normal, value);
        (Authority(::utils::random_name()), routing, pmid_manager,
         ::data_manager::Authority(::utils::random_name()), data)
    }

    #[test]
    fn handle_put() {
        let (our_authority, routing, mut pmid_manager, from_authority, data) = env_setup();
        assert_eq!(::utils::HANDLED,
            pmid_manager.handle_put(&our_authority, &from_authority,
                                    &::routing::data::Data::ImmutableData(data.clone())));
        let put_requests = routing.put_requests_given();
        assert_eq!(put_requests.len(), 1);
        assert_eq!(put_requests[0].our_authority, our_authority);
        assert_eq!(put_requests[0].location,
                   ::pmid_node::Authority(our_authority.get_location().clone()));
        assert_eq!(put_requests[0].data, ::routing::data::Data::ImmutableData(data));
    }

    #[test]
    fn handle_churn_and_account_transfer() {
        let (our_authority, routing, mut pmid_manager, from_authority, data) = env_setup();
        assert_eq!(::utils::HANDLED,
            pmid_manager.handle_put(&our_authority, &from_authority,
                                    &::routing::data::Data::ImmutableData(data.clone())));
        let close_group = vec![::routing::NameType::new([1u8; 64]),
                               ::routing::NameType::new([2u8; 64]),
                               ::routing::NameType::new([3u8; 64]),
                               ::routing::NameType::new([4u8; 64]),
                               our_authority.get_location().clone(),
                               ::routing::NameType::new([5u8; 64]),
                               ::routing::NameType::new([6u8; 64]),
                               ::routing::NameType::new([7u8; 64]),
                               ::routing::NameType::new([8u8; 64])];
        pmid_manager.handle_churn(&close_group);
        let refresh_requests = routing.refresh_requests_given();
        assert_eq!(refresh_requests.len(), 1);
        assert_eq!(refresh_requests[0].type_tag, ACCOUNT_TAG);
        assert_eq!(refresh_requests[0].our_authority.get_location(), our_authority.get_location());

        let mut d = cbor::Decoder::from_bytes(&refresh_requests[0].content[..]);
        if let Some(pm_account) = d.decode().next().and_then(|result| result.ok()) {
            pmid_manager.handle_account_transfer(pm_account);
        }
        pmid_manager.handle_churn(&close_group);
        let refresh_requests = routing.refresh_requests_given();
        assert_eq!(refresh_requests.len(), 2);
        assert_eq!(refresh_requests[0], refresh_requests[1]);

        pmid_manager.handle_churn(&close_group);
        let refresh_requests = routing.refresh_requests_given();
        assert_eq!(refresh_requests.len(), 2);
    }
}
