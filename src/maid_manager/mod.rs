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

pub const ACCOUNT_TAG: u64 = ::transfer_tag::TransferTag::MaidManagerAccount as u64;
pub use self::database::Account;
pub use ::routing::Authority::ClientManager as Authority;

pub struct MaidManager {
    routing: ::vault::Routing,
    database: database::MaidManagerDatabase,
}

impl MaidManager {
    pub fn new(routing: ::vault::Routing) -> MaidManager {
        MaidManager { routing: routing, database: database::MaidManagerDatabase::new() }
    }

    pub fn handle_put(&mut self,
                      our_authority: &::routing::Authority,
                      from_authority: &::routing::Authority,
                      data: &::routing::data::Data,
                      response_token: &Option<::routing::SignedToken>) -> Option<()> {
        // Check if this is for this persona.
        if !::utils::is_maid_manager_authority_type(&our_authority) {
            return ::utils::NOT_HANDLED;
        }

        // Validate from authority.
        if !::utils::is_client_authority_type(&from_authority) {
            warn!("Invalid authority for PUT at MaidManager: {:?}", from_authority);
            return ::utils::HANDLED;
        }

        // Handle the request by sending on to the DM or SDM, or replying with error to the client.
        if self.database.put_data(our_authority.get_location(), data.payload_size() as u64) {
            match data {
                &::routing::data::Data::StructuredData(ref structured_data) => {
                    let location = ::sd_manager::Authority(structured_data.name());
                    let content = ::routing::data::Data::StructuredData(structured_data.clone());
                    self.routing.put_request(our_authority.clone(), location, content);
                },
                &::routing::data::Data::ImmutableData(ref immutable_data) => {
                    let location = ::data_manager::Authority(immutable_data.name());
                    let content = ::routing::data::Data::ImmutableData(immutable_data.clone());
                    self.routing.put_request(our_authority.clone(), location, content);
                },
                _ => {
                    warn!("Invalid PUT request data type.");
                },
            }
        } else {
            debug!("As {:?}, failed in putting data {:?}, responding to {:?}",
                   our_authority, data, from_authority);
            let error = ::routing::error::ResponseError::LowBalance(data.clone(),
                            self.database.get_balance(our_authority.get_location()) as u32);
            self.routing.put_response(our_authority.clone(), from_authority.clone(), error,
                                      response_token.clone());
        }
        ::utils::HANDLED
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

    pub fn handle_churn(&mut self) {
        self.database.handle_churn(&self.routing);
    }
}

#[cfg(all(test, feature = "use-mock-routing"))]
mod test {
    use cbor;
    use sodiumoxide::crypto;

    use super::*;

    fn env_setup() -> (::routing::Authority, ::vault::Routing, MaidManager,
                       ::routing::Authority, ::routing::immutable_data::ImmutableData) {
        let routing = ::vault::Routing::new(::std::sync::mpsc::channel().0);
        let maid_manager = MaidManager::new(routing.clone());
        let from = ::utils::random_name();
        let keys = crypto::sign::gen_keypair();
        let value = ::routing::types::generate_random_vec_u8(1024);
        let data = ::routing::immutable_data::ImmutableData::new(
                       ::routing::immutable_data::ImmutableDataType::Normal, value);
        (Authority(from.clone()), routing, maid_manager,
         ::routing::Authority::Client(from, keys.0), data)
    }

    #[test]
    fn handle_put() {
        let (our_authority, routing, mut maid_manager, client, data) = env_setup();
        assert_eq!(::utils::HANDLED,
            maid_manager.handle_put(&our_authority, &client,
                                    &::routing::data::Data::ImmutableData(data.clone()), &None));
        let put_requests = routing.put_requests_given();
        assert_eq!(put_requests.len(), 1);
        assert_eq!(put_requests[0].our_authority, our_authority);
        assert_eq!(put_requests[0].location, ::data_manager::Authority(data.name()));
        assert_eq!(put_requests[0].data, ::routing::data::Data::ImmutableData(data));
    }

    #[test]
    fn handle_churn_and_account_transfer() {
        let (our_authority, routing, mut maid_manager, client, data) = env_setup();
        assert_eq!(::utils::HANDLED,
            maid_manager.handle_put(&our_authority, &client,
                                    &::routing::data::Data::ImmutableData(data.clone()), &None));
        maid_manager.handle_churn();
        let refresh_requests = routing.refresh_requests_given();
        assert_eq!(refresh_requests.len(), 1);
        assert_eq!(refresh_requests[0].type_tag, ACCOUNT_TAG);
        assert_eq!(refresh_requests[0].our_authority.get_location(), client.get_location());

        let mut d = cbor::Decoder::from_bytes(&refresh_requests[0].content[..]);
        if let Some(mm_account) = d.decode().next().and_then(|result| result.ok()) {
            maid_manager.handle_account_transfer(mm_account);
        }
        maid_manager.handle_churn();
        let refresh_requests = routing.refresh_requests_given();
        assert_eq!(refresh_requests.len(), 2);
        assert_eq!(refresh_requests[0], refresh_requests[1]);

        maid_manager.handle_churn();
        let refresh_requests = routing.refresh_requests_given();
        assert_eq!(refresh_requests.len(), 2);
    }
}
