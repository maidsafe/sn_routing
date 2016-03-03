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
use routing::{Authority, Data, MessageId, RequestContent, RequestMessage};
use sodiumoxide::crypto::hash::sha512;
use std::collections::HashMap;
use time::{Duration, SteadyTime};
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


#[derive(Clone, PartialEq, Eq, Debug)]
struct MetadataForPutRequest {
    pub request: RequestMessage,
    pub creation_timestamp: SteadyTime,
}

impl MetadataForPutRequest {
    pub fn new(request: RequestMessage) -> MetadataForPutRequest {
        MetadataForPutRequest {
            request: request,
            creation_timestamp: SteadyTime::now(),
        }
    }
}


pub struct PmidManager {
    accounts: HashMap<XorName, Account>,
    // key -- (message_id, targeted pmid_node)
    ongoing_puts: HashMap<(MessageId, XorName), MetadataForPutRequest>,
}

impl PmidManager {
    pub fn new() -> PmidManager {
        PmidManager {
            accounts: HashMap::new(),
            ongoing_puts: HashMap::new(),
        }
    }

    pub fn handle_put(&mut self,
                      routing_node: &RoutingNode,
                      request: &RequestMessage) -> Result<(), InternalError> {
        let (data, message_id) = match request.content {
            RequestContent::Put(Data::Immutable(ref data), ref message_id) =>
                    (data.clone(), message_id.clone()),
            _ => unreachable!("Error in vault demuxing"),
        };
        // Put data always being allowed, i.e. no early alert
        self.accounts
            .entry(request.dst.name().clone())
            .or_insert(Account::default())
            .put_data(data.payload_size() as u64);

        let src = Authority::NodeManager(request.dst.name().clone());
        let dst = Authority::ManagedNode(request.dst.name().clone());
        let _ = routing_node.send_put_request(src,
                                              dst,
                                              Data::Immutable(data.clone()),
                                              message_id.clone());
        let _ = self.ongoing_puts.insert((message_id, request.dst.name().clone()),
                                         MetadataForPutRequest::new(request.clone()));
        Ok(())
    }

    pub fn check_timeout(&mut self, routing_node: &RoutingNode) {
        let time_limit = Duration::minutes(1);
        let mut timed_out_puts = Vec::<(MessageId, XorName)>::new();
        for (key, metadata_for_put) in &self.ongoing_puts {
            if metadata_for_put.creation_timestamp + time_limit < SteadyTime::now() {
                timed_out_puts.push(key.clone());
            }
        }
        for key in &timed_out_puts {
            match self.ongoing_puts.remove(key) {
                Some(metadata_for_put) => {
                    let _ = self.handle_put_failure(routing_node, &metadata_for_put.request);
                }
                None => continue,
            }
        }
    }

    pub fn handle_put_success(&mut self,
                              routing_node: &RoutingNode,
                              pmid_node: &XorName,
                              message_id: &MessageId) -> Result<(), InternalError> {
        match self.ongoing_puts.remove(&(*message_id, *pmid_node)) {
            Some(metadata_for_put) => {
                let message_hash = sha512::hash(&try!(serialisation::serialise(&metadata_for_put.request))[..]);
                let src = metadata_for_put.request.dst.clone();
                let dst = metadata_for_put.request.src.clone();
                trace!("As {:?} sending put success to {:?}", src, dst);
                let _ = routing_node.send_put_success(src, dst, message_hash, *message_id);
            }
            None => {},
        }
        Ok(())
    }

    pub fn handle_put_failure(&mut self,
                              routing_node: &RoutingNode,
                              request: &RequestMessage) -> Result<(), InternalError> {
        let (data, message_id) = match request.content {
            RequestContent::Put(Data::Immutable(ref data), ref message_id) =>
                    (data.clone(), message_id.clone()),
            _ => unreachable!("Error in vault demuxing"),
        };

        let src = request.dst.clone();
        let dst = request.src.clone();
        trace!("As {:?} sending Put failure to {:?} of data {}", src, dst, data.name());
        let _ = routing_node.send_put_failure(src, dst, request.clone(), vec![], message_id);

        self.accounts
            .entry(request.dst.name().clone())
            .or_insert(Account::default())
            .delete_data(data.payload_size() as u64);
        Ok(())
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
            let refresh = Refresh::new(pmid_node,
                                       RefreshValue::PmidManagerAccount(account.clone()));
            if let Ok(serialised_refresh) = serialisation::serialise(&refresh) {
                debug!("PmidManager sending refresh for account {:?}", src.name());
                let _ = routing_node.send_refresh_request(src, serialised_refresh);
            }
        }
    }

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
// &::routing::data::Data::Immutable(data.clone())));
// let put_requests = routing.put_requests_given();
// assert_eq!(put_requests.len(), 1);
// assert_eq!(put_requests[0].our_authority, our_authority);
// assert_eq!(put_requests[0].location,
// Authority::ManagedNode(our_authority.name().clone()));
// assert_eq!(put_requests[0].data,
// ::routing::data::Data::Immutable(data));
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
// &::routing::data::Data::Immutable(data.clone())));
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
