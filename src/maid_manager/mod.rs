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

use self::database::{Account, Database};
use routing::{Authority, Data, RequestContent, RequestMessage, ResponseContent};
use vault::Routing;
use xor_name::XorName;

pub const ACCOUNT_TAG: u64 = ::transfer_tag::TransferTag::MaidManagerAccount as u64;

mod database;

pub struct MaidManager {
    database: Database,
}

impl MaidManager {
    pub fn new() -> MaidManager {
        MaidManager { database: Database::new() }
    }

    pub fn handle_put(&mut self, routing: &Routing, request: &RequestMessage) {
        // Handle the request by sending on to the DM or SDM, or replying with error to the client.
        let data = match request.content {
            RequestContent::Put(Data::ImmutableData(ref data)) => Data::ImmutableData(data.clone()),
            RequestContent::Put(Data::StructuredData(ref data)) => Data::StructuredData(data.clone()),
            _ => unreachable!("Error in vault demuxing"),
        };

        if !self.database.put_data(request.src.get_name(), data.payload_size() as u64) {
            // let error = ::routing::error::ResponseError::LowBalance(data.clone(),
            let src = request.dst.clone();
            let dst = request.src.clone();
            let content = ResponseContent::PutFailure {
                request: request.clone(),
                external_error_indicator: vec![],
            };  // TODO - set proper error value
            debug!("As {:?} sending {:?} to {:?}", src, content, dst);
            let _ = routing.send_put_response(src, dst, content);
            return;
        }

        let dst = Authority::NaeManager(data.name());
        let content = RequestContent::Put(data);
        let _ = routing.send_put_request(request.dst.clone(), dst, content);
    }

    pub fn handle_refresh(&mut self, type_tag: &u64, our_authority: &Authority, payloads: &Vec<Vec<u8>>) -> Option<()> {
        if *type_tag == ACCOUNT_TAG {
            if let &Authority::ClientManager(from_group) = our_authority {
                if let Some(merged_account) = ::utils::merge::<Account>(from_group, payloads.clone()) {
                    self.database.handle_account_transfer(merged_account);
                }
            } else {
                warn!("Invalid authority for refresh at MaidManager: {:?}",
                      our_authority);
            }
            ::utils::HANDLED
        } else {
            ::utils::NOT_HANDLED
        }
    }

    pub fn handle_churn(&mut self, routing: &Routing, churn_node: &XorName) {
        self.database.handle_churn(routing, churn_node);
    }

    pub fn do_refresh(&mut self,
                      routing: &Routing,
                      type_tag: &u64,
                      our_authority: &Authority,
                      churn_node: &XorName)
                      -> Option<()> {
        self.database.do_refresh(type_tag, our_authority, churn_node, routing)
    }

    // pub fn reset(&mut self, routing: &Routing) {
    //     self.routing = routing;
    //     self.database.cleanup();
    // }
}



#[cfg(all(test, feature = "use-mock-routing"))]
mod test {
    use super::*;

    fn env_setup()
        -> (::routing::Authority,
            ::vault::Routing,
            MaidManager,
            ::routing::Authority,
            ImmutableData)
    {
        let routing = ::vault::Routing::new(::std::sync::mpsc::channel().0);
        let maid_manager = MaidManager::new(routing.clone());
        let from = random();
        let keys = ::sodiumoxide::crypto::sign::gen_keypair();
        let value = ::routing::types::generate_random_vec_u8(1024);
        let data =
            ImmutableData::new(ImmutableDataType::Normal, value);
        (Authority(from.clone()),
         routing,
         maid_manager,
         ::routing::Authority::Client(from, keys.0),
         data)
    }

    #[test]
    fn handle_put() {
        let (our_authority, routing, mut maid_manager, client, data) = env_setup();
        assert_eq!(::utils::HANDLED,
                   maid_manager.handle_put(&our_authority,
                                           &client,
                                           &::routing::data::Data::ImmutableData(data.clone()),
                                           &None));
        let put_requests = routing.put_requests_given();
        assert_eq!(put_requests.len(), 1);
        assert_eq!(put_requests[0].our_authority, our_authority);
        assert_eq!(put_requests[0].location,
                   ::data_manager::Authority(data.name()));
        assert_eq!(put_requests[0].data,
                   ::routing::data::Data::ImmutableData(data));
    }

    #[test]
    fn handle_churn_and_account_transfer() {
        let churn_node = random();
        let (our_authority, routing, mut maid_manager, client, data) = env_setup();
        assert_eq!(::utils::HANDLED,
                   maid_manager.handle_put(&our_authority,
                                           &client,
                                           &::routing::data::Data::ImmutableData(data.clone()),
                                           &None));
        maid_manager.handle_churn(&churn_node);
        let refresh_requests = routing.refresh_requests_given();
        assert_eq!(refresh_requests.len(), 1);
        assert_eq!(refresh_requests[0].type_tag, ACCOUNT_TAG);
        assert_eq!(refresh_requests[0].our_authority.get_name(),
                   client.get_name());

        let mut d = ::cbor::Decoder::from_bytes(&refresh_requests[0].content[..]);
        if let Some(mm_account) = d.decode().next().and_then(|result| result.ok()) {
            maid_manager.database.handle_account_transfer(mm_account);
        }
        maid_manager.handle_churn(&churn_node);
        let refresh_requests = routing.refresh_requests_given();
        assert_eq!(refresh_requests.len(), 2);
        assert_eq!(refresh_requests[0], refresh_requests[1]);
    }
}
