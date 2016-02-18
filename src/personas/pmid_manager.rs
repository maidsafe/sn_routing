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

use error::InternalError;
use maidsafe_utilities::serialisation;
use routing::{Authority, Data, ImmutableData, MessageId, ResponseMessage};
use std::collections::HashMap;
use types::{Refresh, RefreshValue};
use vault::RoutingNode;
use xor_name::XorName;

#[derive(RustcEncodable, RustcDecodable, PartialEq, Eq, Debug, Clone)]
pub struct Account {
    stored_total_size: u64,
    lost_total_size: u64,
}

impl Default for Account {
    // FIXME: Account Creation process required https://maidsafe.atlassian.net/browse/MAID-1191
    //   To bypass the the process for a simple network, allowance is granted by default
    fn default() -> Account {
        Account {
            stored_total_size: 0,
            lost_total_size: 0,
        }
    }
}

impl Account {
    // Always return true to allow pmid_node carry out removal of Sacrificial copies
    // Otherwise Account need to remember storage info of Primary, Backup and Sacrificial
    // copies separately to trigger an early alert
    fn put_data(&mut self, size: u64) {
        // if (self.stored_total_size + size) > self.offered_space {
        //   return false;
        // }
        self.stored_total_size += size;
    }

    fn delete_data(&mut self, size: u64) {
        if self.stored_total_size < size {
            self.stored_total_size = 0;
        } else {
            self.stored_total_size -= size;
        }
    }

    #[allow(dead_code)]
    fn handle_lost_data(&mut self, size: u64) {
        self.delete_data(size);
        self.lost_total_size += size;
    }

    #[allow(dead_code)]
    fn handle_falure(&mut self, size: u64) {
        self.handle_lost_data(size);
    }

    #[allow(dead_code)]
    fn update_account(&mut self, diff_size: u64) {
        if self.stored_total_size < diff_size {
            self.stored_total_size = 0;
        } else {
            self.stored_total_size -= diff_size;
        }
        self.lost_total_size += diff_size;
    }
}



pub struct PmidManager {
    accounts: HashMap<XorName, Account>,
}

impl PmidManager {
    pub fn new() -> PmidManager {
        PmidManager { accounts: HashMap::new() }
    }

    pub fn handle_put(&mut self,
                      routing_node: &RoutingNode,
                      data: &ImmutableData,
                      message_id: &MessageId,
                      pmid_node: XorName)
                      -> Result<(), InternalError> {
        // Put data always being allowed, i.e. no early alert
        self.accounts
            .entry(pmid_node.clone())
            .or_insert(Account::default())
            .put_data(data.payload_size() as u64);

        let src = Authority::NodeManager(pmid_node.clone());
        let dst = Authority::ManagedNode(pmid_node);
        let _ = routing_node.send_put_request(src,
                                              dst,
                                              Data::ImmutableData(data.clone()),
                                              message_id.clone());
        Ok(())
    }

    #[allow(dead_code)]
    pub fn handle_put_failure(&mut self, _response: ResponseMessage) {
        //        match from_authority {
        // &Authority::ManagedNode(from_address) => {
        // self.handle_put_response_from_pmid_node(our_authority.clone(),
        //                                         from_address,
        //                                         response.clone(),
        //                                         response_token.clone());
        // match response {
        // ::routing::error::ResponseError::FailedRequestForData(data) => {
        // let payload_size = data.payload_size() as u64;
        // match data {
        // ::routing::data::Data::ImmutableData(immutable_data) => {
        // self.database.delete_data(&from_address, payload_size);
        // let location = ::immutable_data_manager::Authority(immutable_data.name());
        // let response = ::routing::error::ResponseError::FailedRequestForData(
        // ::routing::data::Data::ImmutableData(immutable_data));
        // self.routing
        // .put_response(our_authority, location, response, response_token);
        // }
        // _ => warn!("Invalid data type for PUT RESPONSE at PmidManager: {:?}", data),
        // }
        // }
        // ::routing::error::ResponseError::HadToClearSacrificial(data_name, data_size) => {
        // self.database.delete_data(&from_address, data_size as u64);
        // let location = ::immutable_data_manager::Authority(data_name.clone());
        // let response = ::routing::error::ResponseError::HadToClearSacrificial(data_name,
        // data_size);
        // self.routing.put_response(our_authority, location, response, response_token);
        // }
        // _ => warn!("Invalid response type from PmidNode for PUT RESPONSE at PmidManager"),
        // }
        // }
        // &::immutable_data_manager::Authority(_) => {
        //     self.handle_put_response_from_data_manager(pmid_node, response.clone());
        // }
        // _ => warn!("Invalid authority for PUT RESPONSE at PmidManager: {:?}", from_authority),
        // }
        // ::utils::HANDLED
        //
    }

    pub fn handle_refresh(&mut self, name: XorName, account: Account) {
        let _ = self.accounts.insert(name, account);
    }

    pub fn handle_churn(&mut self, routing_node: &RoutingNode) {
        for (pmid_node, account) in self.accounts.iter() {
            // Only refresh accounts for PmidNodes to which we are still close
            if routing_node.close_group(pmid_node.clone()).ok().is_none() {
                continue;
            }

            let src = Authority::NodeManager(pmid_node.clone());
            let refresh = Refresh::new(pmid_node, RefreshValue::PmidManager(account.clone()));
            if let Ok(serialised_refresh) = serialisation::serialise(&refresh) {
                debug!("PmidManager sending refresh for account {:?}", src.name());
                let _ = routing_node.send_refresh_request(src, serialised_refresh);
            }
        }
    }

    // fn handle_put_response_from_data_manager(&mut self,
    //                                          pmid_node: XorName,
    //                                          response: ::routing::error::ResponseError) {
    //     match response {
    //         ::routing::error::ResponseError::FailedRequestForData(data) => {
    //             self.database.delete_data(&pmid_node, data.payload_size() as u64);
    //         }
    //         _ => warn!("Invalid response type from ImmutableDataManager for PUT RESPONSE at PmidManager"),
    //     }
    // }
}


// #[cfg(all(test, feature = "use-mock-routing"))]
// mod test {
// use super::*;
// use lru_time_cache::LruCache;
// use maidsafe_utilities::serialisation::serialise;
// use rand::random;
// use routing::{Authority, Data, DataRequest, ImmutableData, ImmutableDataType, RequestContent, RequestMessage,
// ResponseContent, ResponseMessage};
// use std::cmp::{max, min, Ordering};
// use std::collections::BTreeSet;
// use time::{Duration, SteadyTime};
// use types::Refreshable;
// use utils::{median, merge, HANDLED, NOT_HANDLED};
// use vault::Routing;
// use xor_name::{XorName, closer_to_target};
//
// fn env_setup()
// -> (::routing::Authority,
// ::vault::Routing,
// PmidManager,
// ::routing::Authority,
// ImmutableData)
// {
// let routing = ::vault::Routing::new(::std::sync::mpsc::channel().0);
// let pmid_manager = PmidManager::new(routing.clone());
// let value = generate_random_vec_u8(1024);
// let data =
// ImmutableData::new(ImmutableDataType::Normal, value);
// (Authority::NodeManager(random()),
// routing,
// pmid_manager,
// Authority::NaeManager(random()),
// data)
// }
//
// #[test]
// fn handle_put() {
// let (our_authority,
// routing,
// mut pmid_manager,
// from_authority,
// data) = env_setup();
// assert_eq!(::utils::HANDLED,
// pmid_manager.handle_put(&our_authority,
// &from_authority,
// &::routing::data::Data::ImmutableData(data.clone())));
// let put_requests = routing.put_requests_given();
// assert_eq!(put_requests.len(), 1);
// assert_eq!(put_requests[0].our_authority, our_authority);
// assert_eq!(put_requests[0].location,
// Authority::ManagedNode(our_authority.name().clone()));
// assert_eq!(put_requests[0].data,
// ::routing::data::Data::ImmutableData(data));
// }
//
// #[test]
// fn handle_churn_and_account_transfer() {
// let (our_authority,
// routing,
// mut pmid_manager,
// from_authority,
// data) = env_setup();
// assert_eq!(::utils::HANDLED,
// pmid_manager.handle_put(&our_authority,
// &from_authority,
// &::routing::data::Data::ImmutableData(data.clone())));
// let close_group = vec![XorName::new([1u8; 64]),
// XorName::new([2u8; 64]),
// XorName::new([3u8; 64]),
// XorName::new([4u8; 64]),
// our_authority.name().clone(),
// XorName::new([5u8; 64]),
// XorName::new([6u8; 64]),
// XorName::new([7u8; 64]),
// XorName::new([8u8; 64])];
// let churn_node = random();
// pmid_manager.handle_churn(&close_group, &churn_node);
// let refresh_requests = routing.refresh_requests_given();
// assert_eq!(refresh_requests.len(), 1);
// assert_eq!(refresh_requests[0].type_tag, ACCOUNT_TAG);
// assert_eq!(refresh_requests[0].our_authority.name(),
// our_authority.name());
//
// let mut d = ::cbor::Decoder::from_bytes(&refresh_requests[0].content[..]);
// if let Some(pm_account) = d.decode().next().and_then(|result| result.ok()) {
// pmid_manager.database.handle_account_transfer(pm_account);
// }
// pmid_manager.handle_churn(&close_group, &churn_node);
// let refresh_requests = routing.refresh_requests_given();
// assert_eq!(refresh_requests.len(), 2);
// assert_eq!(refresh_requests[0], refresh_requests[1]);
// }
// }
//
