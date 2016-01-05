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

pub use self::database::Account;
use self::database::Database;
use routing::{Authority, Data, MessageId, RequestContent, RequestMessage};
use vault::RoutingNode;
use xor_name::XorName;

mod database;

pub struct MaidManager {
    database: Database,
}

impl MaidManager {
    pub fn new() -> MaidManager {
        MaidManager { database: Database::new() }
    }

    pub fn handle_put(&mut self, routing_node: &RoutingNode, request: &RequestMessage) {
        // Handle the request by sending on to the DM or SDM, or replying with error to the client.
        let (data, message_id) = match request.content {
            RequestContent::Put(Data::ImmutableData(ref data), ref message_id) => {
                (Data::ImmutableData(data.clone()), message_id.clone())
            }
            RequestContent::Put(Data::StructuredData(ref data), ref message_id) => {
                (Data::StructuredData(data.clone()), message_id.clone())
            }
            _ => unreachable!("Error in vault demuxing"),
        };

        if !self.database.put_data(request.src.get_name(), data.payload_size() as u64) {
            // let error = ::routing::error::ResponseError::LowBalance(data.clone(),
            let src = request.dst.clone();
            let dst = request.src.clone();
            debug!("As {:?} sending Put failure message to {:?}", src, dst);
            let _ = routing_node.send_put_failure(src, dst, request.clone(), vec![], message_id);  // TODO - set proper error value
            return;
        }

        let dst = Authority::NaeManager(data.name());
        let _ = routing_node.send_put_request(request.dst.clone(), dst, data, message_id);
    }

    pub fn handle_refresh(&mut self, name: XorName, account: Account) {
        self.database.handle_account_transfer(name, account)
    }

    pub fn handle_churn(&mut self, routing_node: &RoutingNode, churn_event_id: &MessageId) {
        self.database.handle_churn(routing_node, churn_event_id)
    }
}


/*
#[cfg(all(test, feature = "use-mock-routing"))]
mod test {
    use super::*;
    use lru_time_cache::LruCache;
    use maidsafe_utilities::serialisation::serialise;
    use rand::random;
    use routing::{Authority, Data, DataRequest, ImmutableData, ImmutableDataType, RequestContent, RequestMessage,
                  ResponseContent, ResponseMessage};
    use std::cmp::{Ordering, max, min};
    use std::collections::BTreeSet;
    use time::{Duration, SteadyTime};
    use types::Refreshable;
    use utils::{HANDLED, NOT_HANDLED, median, merge};
    use vault::Routing;
    use xor_name::{XorName, closer_to_target};

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
        let value = generate_random_vec_u8(1024);
        let data = ImmutableData::new(ImmutableDataType::Normal, value);
        (Authority::ClientManager(from.clone()),
         routing,
         maid_manager,
         Authority::Client(from, keys.0),
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
        assert_eq!(put_requests[0].location, Authority::NaeManager(data.name()));
        assert_eq!(put_requests[0].data, Data::ImmutableData(data));
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
*/
