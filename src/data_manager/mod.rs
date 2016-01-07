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

use error::Error;
use lru_time_cache::LruCache;
use maidsafe_utilities::serialisation::serialise;
use routing::{Authority, Data, DataRequest, ImmutableData, ImmutableDataType, MessageId, RequestContent,
              RequestMessage, ResponseContent, ResponseMessage};
use self::database::Database;
use sodiumoxide::crypto::hash::sha512;
use std::cmp::{Ordering, max, min};
use std::collections::BTreeSet;
use time::{Duration, SteadyTime};
use vault::RoutingNode;
use xor_name::{XorName, closer_to_target};

pub const REPLICANTS: usize = 2;
pub const MIN_REPLICANTS: usize = 2;

mod database;

pub type Account = Vec<XorName>;
type Address = XorName;
type ChunkNameAndPmidNode = (XorName, XorName);

const LRU_CACHE_SIZE: usize = 1000;

#[derive(RustcEncodable, RustcDecodable, Clone, PartialEq, Eq, Debug)]
pub struct Stats {
    pub resource_index: u64,
}



pub struct DataManager {
    database: Database,
    // FIXME - this cache should include the requester auth in the key since repeated requests for
    // the same chunk could end up never being removed.  However, we need to be able to search in
    // the cache by chunk name only.
    request_cache: LruCache<XorName, RequestMessage>,
    // the higher the resource_index is, the slower the farming rate will be
    stats: Stats,
    // key is pair of chunk_name and pmid_node, value is insertion time
    ongoing_gets: LruCache<ChunkNameAndPmidNode, SteadyTime>,
    // key is chunk_name and value is failing pmid nodes
    failed_pmids: LruCache<XorName, Vec<XorName>>,
}

impl DataManager {
    pub fn new() -> DataManager {
        DataManager {
            database: Database::new(),
            request_cache: LruCache::with_expiry_duration_and_capacity(Duration::minutes(5), LRU_CACHE_SIZE),
            stats: Stats { resource_index: 1 },
            ongoing_gets: LruCache::with_capacity(LRU_CACHE_SIZE),
            failed_pmids: LruCache::with_capacity(LRU_CACHE_SIZE),
        }
    }

    pub fn handle_get(&mut self, routing_node: &RoutingNode, request: &RequestMessage) {
        let (data_name, message_id) = match &request.content {
            &RequestContent::Get(DataRequest::ImmutableData(ref data_name, _), ref message_id) => {
                (data_name.clone(), message_id.clone())
            }
            _ => unreachable!("Error in vault demuxing"),
        };

        // Cache the request
        debug!("DataManager {:?} cached request {:?}",
               routing_node.name(),
               request);
        // FIXME - should append to requests in the case of a pre-existing request for this chunk
        let _ = self.request_cache.insert(data_name, request.clone());

        // Before querying the records, first ensure all records are valid
        let ongoing_gets = self.ongoing_gets.retrieve_all();
        let mut failing_entries = Vec::new();
        let mut fetching_list = BTreeSet::new();
        fetching_list.insert(data_name.clone());
        for ongoing_get in ongoing_gets {
            if ongoing_get.1 + Duration::seconds(10) < SteadyTime::now() {
                debug!("DataManager {:?} removing pmid_node {:?} for chunk {:?}",
                       routing_node.name(),
                       (ongoing_get.0).1,
                       (ongoing_get.0).0);
                self.database.remove_pmid_node(&(ongoing_get.0).0, (ongoing_get.0).1.clone());
                // Starts fetching immediately no matter how many alive pmid_nodes left over
                // so that correspondent PmidManagers can be notified ASAP, also reduce the risk
                // of account status not synchronized among the DataManagers
                //         let _ = self.replicate_to((ongoing_get.0).0).and_then(
                //                 fetching_list.insert((ongoing_get.0).0.clone()));
                fetching_list.insert((ongoing_get.0).0.clone());
                failing_entries.push(ongoing_get.0.clone());
                if self.failed_pmids.contains_key(&(ongoing_get.0).0) {
                    match self.failed_pmids.get_mut(&(ongoing_get.0).0) {
                        Some(ref mut pmids) => pmids.push((ongoing_get.0).1.clone()),
                        None => error!("Failed to insert failed_pmid in the cache."),
                    };
                } else {
                    let _ = self.failed_pmids
                                .insert((ongoing_get.0).0.clone(), vec![(ongoing_get.0).1.clone()]);
                }
            }
        }
        for failed_entry in failing_entries {
            let _ = self.ongoing_gets.remove(&failed_entry);
        }
        for fetch_name in fetching_list.iter() {
            debug!("DataManager {:?} having {:?} records for chunk {:?}",
                   routing_node.name(),
                   self.database.exist(&fetch_name),
                   fetch_name);
            for pmid in self.database.get_pmid_nodes(fetch_name) {
                let src = Authority::NaeManager(fetch_name.clone());
                let dst = Authority::ManagedNode(pmid.clone());
                let data_request = DataRequest::ImmutableData(fetch_name.clone(), ImmutableDataType::Normal);
                debug!("DataManager {:?} sending get {:?} to {:?}",
                       routing_node.name(),
                       fetch_name,
                       dst);
                let _ = routing_node.send_get_request(src, dst, data_request, message_id.clone());
                let _ = self.ongoing_gets
                            .insert((fetch_name.clone(), pmid.clone()), SteadyTime::now());
            }
        }
    }

    pub fn handle_put(&mut self, routing_node: &RoutingNode, data: &ImmutableData, message_id: &MessageId) {
        // If the data already exists, there's no more to do.
        let data_name = data.name();
        if self.database.exist(&data_name) {
            return;
        }

        // Choose the PmidNodes to store the data on, and add them in a new database entry.
        let target_pmids = match Self::choose_target_pmids(routing_node, &data_name) {
            Ok(pmids) => pmids,
            Err(_) => return,
        };
        debug!("DataManager chosen {:?} as pmid_nodes for chunk {:?}",
               target_pmids,
               data_name);
        self.database.put_pmid_nodes(&data_name, target_pmids.clone());
        match *data.get_type_tag() {
            ImmutableDataType::Sacrificial => {
                self.stats.resource_index = min(1048576,
                                                self.stats.resource_index + target_pmids.len() as u64);
            }
            _ => {}
        }

        // Send the message on to the PmidNodes' managers.
        for pmid in target_pmids {
            let src = Authority::NaeManager(data_name);
            let dst = Authority::NodeManager(pmid);
            let _ = routing_node.send_put_request(src,
                                                  dst,
                                                  Data::ImmutableData(data.clone()),
                                                  message_id.clone());
        }
    }

    pub fn handle_get_success(&mut self, routing_node: &RoutingNode, response: &ResponseMessage) {
        let (data, message_id): (&ImmutableData, &MessageId) = match response.content {
            ResponseContent::GetSuccess(Data::ImmutableData(ref data), ref message_id) => (data, message_id),
            _ => unreachable!("Error in vault demuxing"),
        };
        let data_name = data.name();

        // Respond if there is a corresponding cached request.
        if self.request_cache.contains_key(&data_name) {
            match self.request_cache.remove(&data_name) {
                Some(request) => {
                    // for request in requests {
                    let src = response.dst.clone();
                    let dst = request.src;
                    let _ = routing_node.send_get_success(src,
                                                          dst,
                                                          Data::ImmutableData(data.clone()),
                                                          message_id.clone());
                    // }
                }
                None => {
                    debug!("Failed to find any requests for get response {:?}",
                           response)
                }
            };
        }

        // let _ = self.ongoing_gets.remove(&(response.name(), request.src.get_name().clone()));
        // match self.failed_pmids.remove(&response.name()) {
        //     Some(failed_pmids) => {
        //         for failed_pmid in failed_pmids {
        //             // utilise put_response as get_response doesn't take ResponseError
        //             debug!("DataManager {:?} notifying a failed pmid_node {:?} regarding chunk {:?}",
        //                    routing.name(), failed_pmid, response.name());
        //             let location = Authority::NodeManager(failed_pmid);
        //             self.routing.put_response(our_authority.clone(), location,
        //                 ::routing::error::ResponseError::FailedRequestForData(response.clone()),
        //                 response_token.clone());
        //         }
        //     }
        //     None => {}
        // }

        // if let Some(pmid_node) = self.replicate_to(&response.name()) {
        //     debug!("DataManager {:?} replicate chunk {:?} to a new pmid_node {:?}",
        //            routing.name(), response.name(), pmid_node);
        //     self.database.add_pmid_node(&response.name(), pmid_node.clone());
        //     let location = Authority::ManagedNode(pmid_node);
        //     self.routing.put_request(our_authority.clone(), location, response.clone());
        // }
    }

    pub fn handle_get_failure(&mut self,
                              _pmid_node_name: XorName,
                              _message_id: &MessageId,
                              _request: &RequestMessage,
                              _external_error_indicator: &Vec<u8>) {
    }

    #[allow(unused)]
    pub fn handle_put_failure(&mut self, response: ResponseMessage) {
        // match response {
        //     ::routing::error::ResponseError::FailedRequestForData(data) => {
        //         self.handle_failed_request_for_data(data, pmid_node_name, our_authority.clone());
        //     }
        //     ::routing::error::ResponseError::HadToClearSacrificial(data_name, _) => {
        //         self.handle_had_to_clear_sacrificial(data_name, pmid_node_name);
        //     }
        //     _ => warn!("Invalid response type for PUT response at DataManager: {:?}", response),
        // }
    }

    pub fn handle_account_refresh(&mut self, name: XorName, account: Account) {
        self.database.put_pmid_nodes(&name, account)
    }

    pub fn handle_stats_refresh(&mut self, stats: Stats) {
        self.stats = stats;
    }

    pub fn handle_churn(&mut self,
                        routing_node: &RoutingNode,
                        churn_event_id: &MessageId,
                        lost_close_node: Option<XorName>) {
        // self.database.handle_churn(routing, churn_node);

        // // If the churn_node exists in the previous DM's nodes_in_table,
        // // but not in this reported close_group, it indicates such node is leaving the group.
        // // However, it is not to say the node is offline, as it may still connected with other
        // let node_leaving = !close_group.contains(churn_node) /*&& self.nodes_in_table.contains(churn_node)*/;
        // let on_going_gets = self.database.handle_churn(routing, churn_node, node_leaving);

        // for entry in on_going_gets.iter() {
        //     if self.failed_pmids.contains_key(&entry.0) {
        //         match self.failed_pmids.get_mut(&entry.0) {
        //             Some(ref mut pmids) => pmids.push(churn_node.clone()),
        //             None => error!("Failed to insert failed_pmid in the cache."),
        //         };
        //     } else {
        //         let _ = self.failed_pmids.insert(entry.0.clone(), vec![churn_node.clone()]);
        //     }
        //     for pmid in entry.1.iter() {
        //         let _ = self.ongoing_gets
        //                     .insert((entry.0.clone(), pmid.clone()), SteadyTime::now());
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

    pub fn reset(&mut self) {
        self.request_cache = LruCache::with_expiry_duration_and_capacity(Duration::minutes(5), 1000);
        self.stats.resource_index = 1;
        self.ongoing_gets = LruCache::with_capacity(LRU_CACHE_SIZE);
        self.failed_pmids = LruCache::with_capacity(LRU_CACHE_SIZE);
        self.database.cleanup();
    }

    fn choose_target_pmids(routing_node: &RoutingNode, data_name: &XorName) -> Result<Vec<XorName>, Error> {
        let own_name = try!(routing_node.name());
        let mut target_pmids = try!(routing_node.close_group());
        target_pmids.push(own_name.clone());
        Self::sort_from_target(&mut target_pmids, data_name);
        target_pmids.truncate(REPLICANTS);
        Ok(target_pmids)
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
            match closer_to_target(&a, &b, target) {
                true => Ordering::Less,
                false => Ordering::Greater,
            }
        });
    }

    // fn handle_failed_request_for_data(&mut self,
    //                                   data: ::routing::data::Data,
    //                                   pmid_node_name: XorName,
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
    //     self.database.remove_pmid_node(&data_name, pmid_node_name);
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

    #[allow(unused)]
    fn handle_had_to_clear_sacrificial(&mut self, data_name: XorName, pmid_node_name: XorName) {
        // giving less weight when removing a sacrificial data
        self.stats.resource_index = max(1, self.stats.resource_index - 1);
        self.database.remove_pmid_node(&data_name, pmid_node_name);
    }
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
        pub data_manager: DataManager,
        pub data: ImmutableData,
    }

    fn env_setup() -> TestEnv {
        let routing = unwrap_result!(::vault::RoutingNode::new(mpsc::channel().0));
        let data_manager = DataManager::new();
        let value = generate_random_vec_u8(1024);
        let data = ImmutableData::new(ImmutableDataType::Normal, value);
        TestEnv {
            our_authority: Authority::NaeManager(data.name().clone()),
            routing: routing,
            data_manager: data_manager,
            data: data,
        }
    }

    #[test]
    fn handle_put_get() {
        let mut env = env_setup();
        {
            let message_id = MessageId::new();
            env.data_manager.handle_put(&env.routing, &env.data, &message_id);
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
            env.data_manager.handle_get(&env.routing, &request);
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
        // env.data_manager.handle_put(&env.routing, &env.data);
        // let close_group = vec![env.our_authority.get_name().clone()]
        //                       .into_iter()
        //                       .chain(env.routing.close_group_including_self().into_iter())
        //                       .collect();
        // let churn_node = random();
        // env.data_manager.handle_churn(&env.routing, close_group, &churn_node);
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
