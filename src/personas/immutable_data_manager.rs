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

// TODO remove this
#![allow(unused)]

use error::{ClientError, InternalError};
use lru_time_cache::LruCache;
use maidsafe_utilities::serialisation;
use routing::{Authority, Data, DataRequest, ImmutableData, ImmutableDataType, MessageId, RequestContent,
              RequestMessage, ResponseContent, ResponseMessage};
use sodiumoxide::crypto::hash::sha512;
use std::cmp::{self, Ordering};
use std::collections::{HashMap, HashSet};
use time::{Duration, SteadyTime};
use types::{Refresh, RefreshValue};
use vault::RoutingNode;
use xor_name::{self, XorName};

pub const REPLICANTS: usize = 2;
pub const MIN_REPLICANTS: usize = 2;

// This is the name of a PmidNode which has been chosen to store the data on.  It is assumed to be
// `Good` (can return the data) until it fails a Get request, at which time it is deemed `Failed`.
#[derive(Clone, PartialEq, Eq, Hash, Debug, RustcEncodable, RustcDecodable)]
pub enum DataHolder {
    Good(XorName),
    Failed(XorName),
}

impl DataHolder {
    pub fn name(&self) -> &XorName {
        match self {
            &DataHolder::Good(ref name) => name,
            &DataHolder::Failed(ref name) => name,
        }
    }
}

// This is the name of a node which *should* hold the data and has been sent a Get request.  Until
// it responds it is held as the `PendingResponse` variant.  Once it responds or the request times
// out, it becomes the `Responded` variant.
#[derive(Clone, PartialEq, Eq, Debug)]
enum QueriedDataHolder {
    PendingResponse(XorName),
    Responded(DataHolder),
}

#[derive(Clone, PartialEq, Eq, Debug)]
struct MetadataForGetRequest {
    pub requests: Vec<RequestMessage>,
    // Some(holder) indicates success/failure to provide chunk - None indicates no reply from pmid node yet
    pub pmid_nodes: Vec<QueriedDataHolder>,
    pub creation_timestamp: SteadyTime,
    pub data: Option<ImmutableData>,
    pub backup_ok: Option<bool>,
    pub sacrificial_ok: Option<bool>,
}

impl MetadataForGetRequest {
    pub fn new(request: &RequestMessage, pmid_nodes: &Account) -> MetadataForGetRequest {
        // We only want to try and get data from "good" holders
        let good_nodes = pmid_nodes.iter().filter_map(|data_holder| {
            match data_holder {
                &DataHolder::Good(pmid_node) => Some(QueriedDataHolder::PendingResponse(pmid_node)),
                &DataHolder::Failed(_) => None,
            }
        }).collect();

        MetadataForGetRequest{
            requests: vec![request.clone(); 1],
            pmid_nodes: good_nodes,
            creation_timestamp: SteadyTime::now(),
            data: None,
            backup_ok: None,
            sacrificial_ok: None,
        }
    }
}

pub type Account = HashSet<DataHolder>;  // Collection of PmidNodes holding a copy of the chunk

const LRU_CACHE_SIZE: usize = 1000;

pub struct ImmutableDataManager {
    // <Data name, PmidNodes holding a copy of the data>
    accounts: HashMap<XorName, Account>,
    // key is chunk_name
    ongoing_gets: LruCache<XorName, MetadataForGetRequest>,
}

impl ImmutableDataManager {
    pub fn new() -> ImmutableDataManager {
        ImmutableDataManager {
            accounts: HashMap::new(),
            ongoing_gets: LruCache::with_expiry_duration_and_capacity(Duration::minutes(5), LRU_CACHE_SIZE),
        }
    }

    pub fn handle_get(&mut self, routing_node: &RoutingNode, request: &RequestMessage) -> Result<(), InternalError> {
        let (data_name, message_id) = match &request.content {
            &RequestContent::Get(DataRequest::ImmutableData(ref data_name, _), ref message_id) => {
                (data_name.clone(), message_id.clone())
            }
            _ => unreachable!("Error in vault demuxing"),
        };

        // If the data doesn't exist, respond with GetFailure
        let pmid_nodes = match self.accounts.get(&data_name) {
            Some(account) => account,
            None => {
                let src = request.dst.clone();
                let dst = request.src.clone();
                let error = ClientError::NoSuchData;
                let external_error_indicator = try!(serialisation::serialise(&error));
                let _ = routing_node.send_get_failure(src, dst, request.clone(), external_error_indicator, message_id);
                return Err(InternalError::Client(error));
            }
        };

        match self.ongoing_gets.get_mut(&data_name) {
            Some(metadata) => {
                // If we've already received the chunk, send it to the new requester.  Otherwise
                // add the request to the others for later handling.
                match metadata.data {
                    Some(ref data) => {
                        let src = request.dst.clone();
                        let dst = request.src.clone();
                        let _ = routing_node.send_get_success(src,
                                                              dst,
                                                              Data::ImmutableData(data.clone()),
                                                              message_id.clone());
                    }
                    None => {
                        metadata.requests.push(request.clone());
                    }
                }
            }
            None => {
                // This is new cache entry
                let entry = MetadataForGetRequest::new(request, pmid_nodes);
                for good_node in entry.pmid_nodes.iter() {
//                    send Get
                }
                self.ongoing_gets.insert(data_name, entry);
            }
        }






        // // Cache the request
        // debug!("ImmutableDataManager {:?} cached request {:?}",
        //        routing_node.name(),
        //        request);
        // // FIXME - should append to requests in the case of a pre-existing request for this chunk
        // let _ = self.request_cache.insert(data_name, request.clone());

        // // Before querying the records, first ensure all records are valid
        // let ongoing_gets = self.ongoing_gets.retrieve_all();
        // let mut failing_entries = Vec::new();
        // let mut fetching_list = HashSet::new();
        // fetching_list.insert(data_name.clone());
        // for ongoing_get in ongoing_gets {
        //     if ongoing_get.1 + Duration::seconds(10) < SteadyTime::now() {
        //         debug!("ImmutableDataManager {:?} removing pmid_node {:?} for chunk {:?}",
        //                routing_node.name(),
        //                (ongoing_get.0).1,
        //                (ongoing_get.0).0);
        //         // self.remove_pmid_node_from_account(&(ongoing_get.0).0, &(ongoing_get.0).1);
        //         // Starts fetching immediately no matter how many alive pmid_nodes left over
        //         // so that correspondent PmidManagers can be notified ASAP, also reduce the risk
        //         // of account status not synchronized among the DataManagers
        //         //         let _ = self.replicate_to((ongoing_get.0).0).and_then(
        //         //                 fetching_list.insert((ongoing_get.0).0.clone()));
        //         fetching_list.insert((ongoing_get.0).0.clone());
        //         failing_entries.push(ongoing_get.0.clone());
        //         // if self.failed_pmid_nodes.contains_key(&(ongoing_get.0).0) {
        //         //     match self.failed_pmid_nodes.get_mut(&(ongoing_get.0).0) {
        //         //         Some(ref mut pmid_nodes) => pmid_nodes.push((ongoing_get.0).1.clone()),
        //         //         None => error!("Failed to insert failed_pmid_node in the cache."),
        //         //     };
        //         // } else {
        //         //     let _ = self.failed_pmid_nodes
        //         //                 .insert((ongoing_get.0).0.clone(), vec![(ongoing_get.0).1.clone()]);
        //         // }
        //     }
        // }
        // for failed_entry in failing_entries {
        //     let _ = self.ongoing_gets.remove(&failed_entry);
        // }
        // for fetch_name in fetching_list.iter() {
        //     debug!("ImmutableDataManager {:?} having {:?} records for chunk {:?}",
        //            routing_node.name(),
        //            self.accounts.contains_key(&fetch_name),
        //            fetch_name);
        //     if let Some(account) = self.accounts.get(&data_name) {
        //         for pmid_node in account.iter() {
        //             let src = Authority::NaeManager(fetch_name.clone());
        //             let dst = Authority::ManagedNode(pmid_node.name().clone());
        //             let data_request = DataRequest::ImmutableData(fetch_name.clone(), ImmutableDataType::Normal);
        //             debug!("ImmutableDataManager {:?} sending get {:?} to {:?}",
        //                    routing_node.name(),
        //                    fetch_name,
        //                    dst);
        //             let _ = routing_node.send_get_request(src, dst, data_request, message_id.clone());
        //             let _ = self.ongoing_gets
        //                         .insert((fetch_name.clone(), pmid_node.name().clone()),
        //                                 SteadyTime::now());
        //         }
        //     }
        // }
        Ok(())
    }

    pub fn handle_put(&mut self,
                      routing_node: &RoutingNode,
                      data: &ImmutableData,
                      message_id: &MessageId)
                      -> Result<(), InternalError> {
        // If the data already exists, there's no more to do.
        let data_name = data.name();
        if self.accounts.contains_key(&data_name) {
            return Ok(());
        }

        // Choose the PmidNodes to store the data on, and add them in a new database entry.
        let target_pmid_nodes = try!(Self::choose_target_pmid_nodes(routing_node, &data_name));
        debug!("ImmutableDataManager chosen {:?} as pmid_nodes for chunk {:?}",
               target_pmid_nodes,
               data_name);
        let _ = self.accounts.insert(data_name, target_pmid_nodes.clone());

        // Send the message on to the PmidNodes' managers.
        for pmid_node in target_pmid_nodes {
            let src = Authority::NaeManager(data_name);
            let dst = Authority::NodeManager(pmid_node.name().clone());
            let _ = routing_node.send_put_request(src,
                                                  dst,
                                                  Data::ImmutableData(data.clone()),
                                                  message_id.clone());
        }
        Ok(())
    }

    pub fn handle_get_success(&mut self,
                              routing_node: &RoutingNode,
                              response: &ResponseMessage)
                              -> Result<(), InternalError> {
        let (data, message_id): (&ImmutableData, &MessageId) = match response.content {
            ResponseContent::GetSuccess(Data::ImmutableData(ref data), ref message_id) => (data, message_id),
            _ => unreachable!("Error in vault demuxing"),
        };
        let data_name = data.name();

        // Respond if there is a corresponding cached request.
        // if self.request_cache.contains_key(&data_name) {
        //     match self.request_cache.remove(&data_name) {
        //         Some(request) => {
        //             // for request in requests {
        //             let src = response.dst.clone();
        //             let dst = request.src;
        //             let _ = routing_node.send_get_success(src,
        //                                                   dst,
        //                                                   Data::ImmutableData(data.clone()),
        //                                                   message_id.clone());
        //             // }
        //         }
        //         None => {
        //             debug!("Failed to find any requests for get response {:?}",
        //                    response)
        //         }
        //     };
        // }
        Ok(())

        // let _ = self.ongoing_gets.remove(&(response.name(), request.src.get_name().clone()));
        // match self.failed_pmid_nodes.remove(&response.name()) {
        //     Some(failed_pmid_nodes) => {
        //         for failed_pmid_node in failed_pmid_nodes {
        //             // utilise put_response as get_response doesn't take ResponseError
        //             debug!("ImmutableDataManager {:?} notifying a failed pmid_node {:?} regarding chunk {:?}",
        //                    routing.name(), failed_pmid_node, response.name());
        //             let location = Authority::NodeManager(failed_pmid_node);
        //             self.routing.put_response(our_authority.clone(), location,
        //                 ::routing::error::ResponseError::FailedRequestForData(response.clone()),
        //                 response_token.clone());
        //         }
        //     }
        //     None => {}
        // }

        // if let Some(pmid_node) = self.replicate_to(&response.name()) {
        //     debug!("ImmutableDataManager {:?} replicate chunk {:?} to a new pmid_node {:?}",
        //            routing.name(), response.name(), pmid_node);
        //     self.database.add_pmid_node(&response.name(), pmid_node.clone());
        //     let location = Authority::ManagedNode(pmid_node);
        //     self.routing.put_request(our_authority.clone(), location, response.clone());
        // }
    }

    pub fn handle_get_failure(&mut self,
                              _pmid_node: XorName,
                              _message_id: &MessageId,
                              _request: &RequestMessage,
                              _external_error_indicator: &Vec<u8>)
                              -> Result<(), InternalError> {
        Ok(())
    }

    #[allow(unused)]
    pub fn handle_put_failure(&mut self, response: ResponseMessage) -> Result<(), InternalError> {
        // match response {
        //     ::routing::error::ResponseError::FailedRequestForData(data) => {
        //         self.handle_failed_request_for_data(data, pmid_node, our_authority.clone());
        //     }
        //     ::routing::error::ResponseError::HadToClearSacrificial(data_name, _) => {
        //         self.handle_had_to_clear_sacrificial(data_name, pmid_node);
        //     }
        //     _ => warn!("Invalid response type for PUT response at ImmutableDataManager: {:?}", response),
        // }
        Ok(())
    }

    pub fn handle_refresh(&mut self, data_name: XorName, account: Account) {
        let _ = self.accounts.insert(data_name, account);
    }

    pub fn handle_churn(&mut self,
                        routing_node: &RoutingNode,
                        churn_event_id: &MessageId,
                        lost_close_node: Option<XorName>) {
        for (data_name, pmid_nodes) in self.accounts.iter() {
            let src = Authority::NaeManager(data_name.clone());
            let refresh = Refresh {
                id: churn_event_id.clone(),
                name: data_name.clone(),
                value: RefreshValue::ImmutableDataManager(pmid_nodes.clone()),
            };
            if let Ok(serialised_refresh) = serialisation::serialise(&refresh) {
                debug!("ImmutableDataManager sending refresh for account {:?}",
                       src.get_name());
                let _ = routing_node.send_refresh_request(src, serialised_refresh);
            }
        }

        // // If the churn_node exists in the previous DM's nodes_in_table,
        // // but not in this reported close_group, it indicates such node is leaving the group.
        // // However, it is not to say the node is offline, as it may still connected with other
        // let node_leaving = !close_group.contains(churn_node) /*&& self.nodes_in_table.contains(churn_node)*/;
        // let on_going_gets = self.database.handle_churn(routing, churn_node, node_leaving);

        // for entry in on_going_gets.iter() {
        //     if self.failed_pmid_nodes.contains_key(&entry.0) {
        //         match self.failed_pmid_nodes.get_mut(&entry.0) {
        //             Some(ref mut pmid_nodes) => pmid_nodes.push(churn_node.clone()),
        //             None => error!("Failed to insert failed_pmid_node in the cache."),
        //         };
        //     } else {
        //         let _ = self.failed_pmid_nodes.insert(entry.0.clone(), vec![churn_node.clone()]);
        //     }
        //     for pmid_node in entry.1.iter() {
        //         let _ = self.ongoing_gets
        //                     .insert((entry.0.clone(), pmid_node.clone()), SteadyTime::now());
        //     }
        // }
        // // close_group[0] is supposed to be the vault id
        // let data_manager_stats = Stats::new(close_group[0].clone(), self.resource_index);
        // if let Ok(serialised_stats) = serialise(&[data_manager_stats.clone()]) {
        //     let _ = routing.send_refresh_request(STATS_TAG,
        //                                          Authority::NaeManager(churn_node.clone()),
        //                                          serialised_stats,
        //                                          churn_node.clone());
        // }
    }

    fn choose_target_pmid_nodes(routing_node: &RoutingNode,
                                data_name: &XorName)
                                -> Result<HashSet<DataHolder>, InternalError> {
        let own_name = try!(routing_node.name());
        let mut target_pmid_nodes = try!(routing_node.close_group());
        target_pmid_nodes.push(own_name.clone());
        Self::sort_from_target(&mut target_pmid_nodes, data_name);
        target_pmid_nodes.truncate(REPLICANTS);
        Ok(target_pmid_nodes.into_iter().map(|pmid_node| DataHolder::Good(pmid_node)).collect::<HashSet<DataHolder>>())
    }

    #[allow(unused)]
    fn replicate_to(&mut self, _name: &XorName) -> Option<XorName> {
        // let pmid_nodes = self.database.get_pmid_nodes(name);
        // if pmid_nodes.len() < MIN_REPLICANTS && pmid_nodes.len() > 0 {
        //     let mut close_group = routing.close_group_including_self();
        //     Self::sort_from_target(&mut close_group, &name);
        //     for close_grp_it in close_group.iter() {
        //         if pmid_nodes.iter().find(|a| **a == *close_grp_it).is_none() {
        //             debug!("node {:?} replicating chunk {:?} to a new node {:?}",
        //                    routing.name(),
        //                    name,
        //                    close_grp_it);
        //             return Some(close_grp_it.clone());
        //         }
        //     }
        // }
        None
    }

    fn sort_from_target(names: &mut Vec<XorName>, target: &XorName) {
        names.sort_by(|a, b| {
            match xor_name::closer_to_target(&a, &b, target) {
                true => Ordering::Less,
                false => Ordering::Greater,
            }
        });
    }

    // fn remove_pmid_node_from_account(&mut self, data_name: &XorName, pmid_node: &XorName) {
    //     if let Some(account) = self.accounts.get_mut(data_name) {
    //         let _ = account.remove(pmid_node);
    //     }
    // }

    // fn handle_failed_request_for_data(&mut self,
    //                                   data: ::routing::data::Data,
    //                                   pmid_node: XorName,
    //                                   our_authority: Authority) {
    //     // Validate that the Data is ImmutableData.
    //     let immutable_data = match data {
    //         ::routing::data::Data::ImmutableData(immutable_data) => immutable_data,
    //         _ => return,
    //     };

    //     // giving more weight when failed in storing a Normal immutable data
    //     // i.e increasing slowly but dropping quickly
    //     self.resource_index = ::std::cmp::max(1, self.resource_index - 4);

    //     let data_name = immutable_data.name();
    //     self.database.remove_pmid_node(&data_name, pmid_node);
    //     match *immutable_data.get_type_tag() {
    //         ImmutableDataType::Normal => {
    //             match self.replicate_to(&data_name) {
    //                 Some(pmid_node) => {
    //                     self.database.add_pmid_node(&data_name, pmid_node.clone());
    //                     let location = Authority::NodeManager(pmid_node);
    //                     let content = ::routing::data::Data::ImmutableData(immutable_data);
    //                     self.routing.send_put_request(our_authority, location, content);
    //                 }
    //                 None => {
    //                     warn!("Failed to find nodes to replicate data to.");
    //                 }
    //             }
    //         }
    //         // Don't need to replicate Backup or Sacrificial chunks
    //         _ => {}
    //     }
    // }

    // fn handle_had_to_clear_sacrificial(&mut self, data_name: &XorName, pmid_node: &XorName) {
    //     self.remove_pmid_node_from_account(data_name, pmid_node);
    // }
}



#[cfg(all(test, feature = "use-mock-routing"))]
mod test {
    use super::*;
    use rand::random;
    use routing::{Authority, Data, DataRequest, ImmutableData, ImmutableDataType, MessageId, RequestContent,
                  RequestMessage};
    use sodiumoxide::crypto::sign;
    use std::sync::mpsc;
    use utils::generate_random_vec_u8;

    struct TestEnv {
        pub our_authority: Authority,
        pub routing: ::vault::RoutingNode,
        pub immutable_data_manager: ImmutableDataManager,
        pub data: ImmutableData,
    }

    fn env_setup() -> TestEnv {
        let routing = unwrap_result!(::vault::RoutingNode::new(mpsc::channel().0));
        let immutable_data_manager = ImmutableDataManager::new();
        let value = generate_random_vec_u8(1024);
        let data = ImmutableData::new(ImmutableDataType::Normal, value);
        TestEnv {
            our_authority: Authority::NaeManager(data.name().clone()),
            routing: routing,
            immutable_data_manager: immutable_data_manager,
            data: data,
        }
    }

    #[test]
    fn handle_put_get() {
        let mut env = env_setup();
        {
            let message_id = MessageId::new();
            env.immutable_data_manager.handle_put(&env.routing, &env.data, &message_id);
            let put_requests = env.routing.put_requests_given();
            assert_eq!(put_requests.len(), REPLICANTS);
            for i in 0..put_requests.len() {
                assert_eq!(put_requests[i].src, env.our_authority);
                assert_eq!(put_requests[i].content,
                           RequestContent::Put(Data::ImmutableData(env.data.clone()), message_id.clone()));
            }
        }
        {
            let keys = sign::gen_keypair();
            let from = random();
            let client = Authority::Client {
                client_key: keys.0,
                proxy_node_name: from,
            };

            let message_id = MessageId::new();
            let content = RequestContent::Get(DataRequest::ImmutableData(env.data.name().clone(),
                                                                         ImmutableDataType::Normal),
                                              message_id);
            let request = RequestMessage {
                src: client.clone(),
                dst: env.our_authority.clone(),
                content: content.clone(),
            };
            env.immutable_data_manager.handle_get(&env.routing, &request);
            let get_requests = env.routing.get_requests_given();
            assert_eq!(get_requests.len(), REPLICANTS);
            for i in 0..get_requests.len() {
                assert_eq!(get_requests[i].src, env.our_authority);
                assert_eq!(get_requests[i].content, content);
            }
        }
    }

    #[test]
    fn handle_churn() {
        // let mut env = env_setup();
        // env.immutable_data_manager.handle_put(&env.routing, &env.data);
        // let close_group = vec![env.our_authority.get_name().clone()]
        //                       .into_iter()
        //                       .chain(env.routing.close_group_including_self().into_iter())
        //                       .collect();
        // let churn_node = random();
        // env.immutable_data_manager.handle_churn(&env.routing, close_group, &churn_node);
        // let refresh_requests = env.routing.refresh_requests_given();
        // assert_eq!(refresh_requests.len(), 2);
        // {
        //     // Account refresh
        //     assert_eq!(refresh_requests[0].src.get_name().clone(), env.data.name());
        //     let (type_tag, cause) = match refresh_requests[0].content {
        //         RequestContent::Refresh{ type_tag, cause, .. } => (type_tag, cause),
        //         _ => panic!("Invalid content type"),
        //     };
        //     assert_eq!(type_tag, ACCOUNT_TAG);
        //     assert_eq!(cause, churn_node);
        // }
        // {
        //     // Stats refresh
        //     assert_eq!(refresh_requests[1].src.get_name().clone(), churn_node);
        //     let (type_tag, cause) = match refresh_requests[1].content {
        //         RequestContent::Refresh{ type_tag, cause, .. } => (type_tag, cause),
        //         _ => panic!("Invalid content type"),
        //     };
        //     assert_eq!(type_tag, STATS_TAG);
        //     assert_eq!(cause, churn_node);
        // }
    }
}
