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
use lru_time_cache::LruCache;
use maidsafe_utilities::serialisation::serialise;
use routing::{Authority, Data, DataRequest, ImmutableData, ImmutableDataType, RequestContent, RequestMessage,
              ResponseContent, ResponseMessage};
use std::cmp::{max, min, Ordering};
use std::collections::BTreeSet;
use time::{Duration, SteadyTime};
use types::Refreshable;
use utils::{median, merge, HANDLED, NOT_HANDLED};
use vault::Routing;
use xor_name::{XorName, closer_to_target};

pub const ACCOUNT_TAG: u64 = ::transfer_tag::TransferTag::DataManagerAccount as u64;
pub const STATS_TAG: u64 = ::transfer_tag::TransferTag::DataManagerStats as u64;
pub const REPLICANTS: usize = 4;
#[allow(unused)]
pub const MIN_REPLICANTS: usize = 3;

mod database;

type Address = XorName;
type ChunkNameAndPmidNode = (XorName, XorName);

const LRU_CACHE_SIZE: usize = 1000;

#[derive(RustcEncodable, RustcDecodable, Clone, PartialEq, Eq, Debug)]
pub struct Stats {
    name: XorName,
    resource_index: u64,
}

impl Stats {
    pub fn new(name: XorName, resource_index: u64) -> Stats {
        Stats {
            name: name,
            resource_index: resource_index,
        }
    }

    pub fn name(&self) -> &XorName {
        &self.name
    }

    pub fn resource_index(&self) -> u64 {
        self.resource_index
    }
}

impl Refreshable for Stats {
    fn merge(from_group: XorName, responses: Vec<Stats>) -> Option<Stats> {
        let mut resource_indexes: Vec<u64> = Vec::new();
        for value in responses {
            if *value.name() == from_group {
                resource_indexes.push(value.resource_index());
            }
        }
        Some(Stats::new(XorName([0u8; 64]), median(resource_indexes)))
    }
}



pub struct DataManager {
    database: Database,
    id: XorName,
    nodes_in_table: Vec<XorName>,
    request_cache: LruCache<(XorName, Authority), RequestMessage>,
    // the higher the index is, the slower the farming rate will be
    resource_index: u64,
    // key is pair of chunk_name and pmid_node, value is insertion time
    ongoing_gets: LruCache<ChunkNameAndPmidNode, SteadyTime>,
    // key is chunk_name and value is failing pmid nodes
    failed_pmids: LruCache<XorName, Vec<XorName>>,
}

impl DataManager {
    pub fn new() -> DataManager {
        DataManager {
            database: Database::new(),
            id: XorName::new([0u8; 64]),
            nodes_in_table: vec![],
            request_cache: LruCache::with_expiry_duration_and_capacity(Duration::minutes(5), LRU_CACHE_SIZE),
            resource_index: 1,
            ongoing_gets: LruCache::with_capacity(LRU_CACHE_SIZE),
            failed_pmids: LruCache::with_capacity(LRU_CACHE_SIZE),
        }
    }

    pub fn handle_get(&mut self, routing: &Routing, request: &RequestMessage) {
        let data_name = match &request.content {
            &RequestContent::Get(DataRequest::ImmutableData(ref data_name, _)) => data_name.clone(),
            _ => unreachable!("Error in vault demuxing"),
        };

        // Cache the request
        debug!("DataManager {:?} cached request {:?}", self.id, request);
        let _ = self.request_cache.insert((data_name, request.src.clone()), request.clone());

        // Before querying the records, first ensure all records are valid
        let ongoing_gets = self.ongoing_gets.retrieve_all();
        let mut failing_entries = Vec::new();
        let mut fetching_list = BTreeSet::new();
        fetching_list.insert(data_name.clone());
        for ongoing_get in ongoing_gets {
            if ongoing_get.1 + Duration::seconds(10) < SteadyTime::now() {
                debug!("DataManager {:?} removing pmid_node {:?} for chunk {:?}",
                       self.id,
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
                   self.id,
                   self.database.exist(&fetch_name),
                   fetch_name);
            for pmid in self.database.get_pmid_nodes(fetch_name) {
                let src = Authority::NaeManager(fetch_name.clone());
                let dst = Authority::ManagedNode(pmid.clone());
                let content = RequestContent::Get(DataRequest::ImmutableData(fetch_name.clone(),
                                                                             ImmutableDataType::Normal));
                debug!("DataManager {:?} sending get {:?} to {:?}",
                       self.id,
                       fetch_name,
                       dst);
                let _ = routing.send_get_request(src, dst, content);
                let _ = self.ongoing_gets
                            .insert((fetch_name.clone(), pmid.clone()), SteadyTime::now());
            }
        }
    }

    pub fn handle_put(&mut self, routing: &Routing, data: &ImmutableData) {
        // If the data already exists, there's no more to do.
        let data_name = data.name();
        if self.database.exist(&data_name) {
            return;
        }

        // Choose the PmidNodes to store the data on, and add them in a new database entry.
        Self::sort_from_target(&mut self.nodes_in_table, &data_name);
        let pmid_nodes_num = min(self.nodes_in_table.len(), REPLICANTS);
        let mut dest_pmids: Vec<XorName> = vec![];
        for index in 0..pmid_nodes_num {
            dest_pmids.push(self.nodes_in_table[index].clone());
        }
        debug!("DataManager {:?} chosen {:?} as pmid_nodes for chunk {:?}",
               self.id,
               dest_pmids,
               data_name);
        self.database.put_pmid_nodes(&data_name, dest_pmids.clone());
        match *data.get_type_tag() {
            ImmutableDataType::Sacrificial => {
                self.resource_index = min(1048576, self.resource_index + dest_pmids.len() as u64);
            }
            _ => {}
        }

        // Send the message on to the PmidNodes' managers.
        for pmid in dest_pmids {
            let src = Authority::NaeManager(data_name);
            let dst = Authority::NodeManager(pmid);
            let content = RequestContent::Put(Data::ImmutableData(data.clone()));
            let _ = routing.send_put_request(src, dst, content);
        }
    }

    pub fn handle_get_success(&mut self, response: &ResponseMessage) {
        let data = match response.content {
            ResponseContent::GetSuccess(Data::ImmutableData(ref data)) => data.clone(),
            _ => unreachable!("Error in vault demuxing"),
        };
        let _data_name = data.name();

        // // Respond if there is a corresponding cached request.
        // if self.request_cache.contains_key(&(data_name, *))) {
        //     match self.request_cache.remove(&response.name()) {
        //         Some(requests) => {
        //             for request in requests {
        //                 self.routing.send_get_response(response.dst.clone(),
        //                                                request.0,
        //                                                response.clone(),
        //                                                request.1,
        //                                                request.2);
        //             }
        //         }
        //         None => debug!("Failed to find any requests for get response {:?}", response),
        //     };
        // }

        // let _ = self.ongoing_gets.remove(&(response.name(), request.src.get_name().clone()));
        // match self.failed_pmids.remove(&response.name()) {
        //     Some(failed_pmids) => {
        //         for failed_pmid in failed_pmids {
        //             // utilise put_response as get_response doesn't take ResponseError
        //             debug!("DataManager {:?} notifying a failed pmid_node {:?} regarding chunk {:?}",
        //                    self.id, failed_pmid, response.name());
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
        //            self.id, response.name(), pmid_node);
        //     self.database.add_pmid_node(&response.name(), pmid_node.clone());
        //     let location = Authority::ManagedNode(pmid_node);
        //     self.routing.put_request(our_authority.clone(), location, response.clone());
        // }
    }

    pub fn handle_get_failure(&mut self,
                              _pmid_node_name: XorName,
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

    pub fn handle_refresh(&mut self, type_tag: &u64, our_authority: &Authority, payloads: &Vec<Vec<u8>>) -> Option<()> {
        match type_tag {
            &ACCOUNT_TAG => {
                if let &Authority::NaeManager(from_group) = our_authority {
                    if let Some(merged_account) = merge::<Account>(from_group, payloads.clone()) {
                        debug!("DataManager {:?} receiving refreshed account {:?}",
                               self.id,
                               merged_account);
                        self.database.handle_account_transfer(merged_account);
                    }
                } else {
                    warn!("Invalid authority for refresh account at DataManager: {:?}",
                          our_authority);
                }
                HANDLED
            }
            &STATS_TAG => {
                if let &Authority::NaeManager(from_group) = our_authority {
                    if let Some(merged_stats) = merge::<Stats>(from_group, payloads.clone()) {
                        // give priority to incoming stats
                        self.resource_index = merged_stats.resource_index();
                    }
                } else {
                    warn!("Invalid authority for refresh stats at DataManager: {:?}",
                          our_authority);
                }
                HANDLED
            }
            _ => NOT_HANDLED,
        }
    }

    pub fn set_node_table(&mut self, close_group: Vec<XorName>) {
        self.id = close_group[0].clone();
        self.nodes_in_table = close_group;
    }

    pub fn handle_churn(&mut self, routing: &Routing, close_group: Vec<XorName>, churn_node: &XorName) {
        // If the churn_node exists in the previous DM's nodes_in_table,
        // but not in this reported close_group, it indicates such node is leaving the group.
        // However, it is not to say the node is offline, as it may still connected with other
        let node_leaving = !close_group.contains(churn_node) && self.nodes_in_table.contains(churn_node);
        let on_going_gets = self.database.handle_churn(routing, churn_node, node_leaving);

        for entry in on_going_gets.iter() {
            if self.failed_pmids.contains_key(&entry.0) {
                match self.failed_pmids.get_mut(&entry.0) {
                    Some(ref mut pmids) => pmids.push(churn_node.clone()),
                    None => error!("Failed to insert failed_pmid in the cache."),
                };
            } else {
                let _ = self.failed_pmids.insert(entry.0.clone(), vec![churn_node.clone()]);
            }
            for pmid in entry.1.iter() {
                let _ = self.ongoing_gets
                            .insert((entry.0.clone(), pmid.clone()), SteadyTime::now());
            }
        }
        // close_group[0] is supposed to be the vault id
        let data_manager_stats = Stats::new(close_group[0].clone(), self.resource_index);
        if let Ok(serialised_stats) = serialise(&[data_manager_stats.clone()]) {
            let _ = routing.send_refresh_request(STATS_TAG,
                                                 Authority::NaeManager(churn_node.clone()),
                                                 serialised_stats,
                                                 churn_node.clone());
        }
        self.set_node_table(close_group);
    }

    // pub fn reset(&mut self, routing: &Routing) {
    //     self.routing = routing;
    //     self.nodes_in_table.clear();
    //     self.request_cache = LruCache::with_expiry_duration_and_capacity(Duration::minutes(5), 1000);
    //     self.resource_index = 1;
    //     self.ongoing_gets = LruCache::with_capacity(LRU_CACHE_SIZE);
    //     self.failed_pmids = LruCache::with_capacity(LRU_CACHE_SIZE);
    //     self.database.cleanup();
    // }

    pub fn do_refresh(&mut self,
                      routing: &Routing,
                      type_tag: &u64,
                      our_authority: &Authority,
                      churn_node: &XorName)
                      -> Option<()> {
        self.database.do_refresh(type_tag, our_authority, churn_node, routing)
    }

    pub fn nodes_in_table_len(&self) -> usize {
        self.nodes_in_table.len()
    }

    #[allow(unused)]
    fn replicate_to(&mut self, name: &XorName) -> Option<XorName> {
        let pmid_nodes = self.database.get_pmid_nodes(name);
        if pmid_nodes.len() < MIN_REPLICANTS && pmid_nodes.len() > 0 {
            Self::sort_from_target(&mut self.nodes_in_table, &name);
            for close_grp_it in self.nodes_in_table.iter() {
                if pmid_nodes.iter().find(|a| **a == *close_grp_it).is_none() {
                    debug!("node {:?} replicating chunk {:?} to a new node {:?}",
                           self.id,
                           name,
                           close_grp_it);
                    return Some(close_grp_it.clone());
                }
            }
        }
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
        self.resource_index = max(1, self.resource_index - 1);
        self.database.remove_pmid_node(&data_name, pmid_node_name);
    }
}



#[cfg(all(test, feature = "use-mock-routing"))]
mod test {
    use super::*;

    fn env_setup()
        -> (::routing::Authority,
            ::vault::Routing,
            DataManager,
            ::routing::Authority,
            ImmutableData)
    {
        let routing = ::vault::Routing::new(::std::sync::mpsc::channel().0);
        let mut data_manager = DataManager::new(routing.clone());
        let value = ::routing::types::generate_random_vec_u8(1024);
        let data =
            ImmutableData::new(ImmutableDataType::Normal, value);
        data_manager.nodes_in_table = vec![XorName::new([1u8; 64]),
                                           XorName::new([2u8; 64]),
                                           XorName::new([3u8; 64]),
                                           XorName::new([4u8; 64]),
                                           XorName::new([5u8; 64]),
                                           XorName::new([6u8; 64]),
                                           XorName::new([7u8; 64]),
                                           XorName::new([8u8; 64])];
        (Authority(data.name().clone()),
         routing,
         data_manager,
         ::maid_manager::Authority(random()),
         data)
    }

    #[test]
    fn handle_put_get() {
        let (our_authority,
             routing,
             mut data_manager,
             from_authority,
             data) = env_setup();
        {
            assert_eq!(::utils::HANDLED,
                       data_manager.handle_put(&our_authority,
                                               &from_authority,
                                               &::routing::data::Data::ImmutableData(data.clone())));
            let put_requests = routing.put_requests_given();
            assert_eq!(put_requests.len(), REPLICANTS);
            for i in 0..put_requests.len() {
                assert_eq!(put_requests[i].our_authority, our_authority);
                assert_eq!(put_requests[i].location,
                           Authority::NodeManager(data_manager.nodes_in_table[i]));
                assert_eq!(put_requests[i].data,
                           ::routing::data::Data::ImmutableData(data.clone()));
            }
        }
        {
            let from = random();
            let keys = ::sodiumoxide::crypto::sign::gen_keypair();
            let client = ::routing::Authority::Client(from, keys.0);

            let request =
                ::routing::data::DataRequest::ImmutableData(data.name().clone(),
                                                            ImmutableDataType::Normal);

            assert_eq!(::utils::HANDLED,
                       data_manager.handle_get(&our_authority, &client, &request, &None));
            let get_requests = routing.get_requests_given();
            assert_eq!(get_requests.len(), REPLICANTS);
            for i in 0..get_requests.len() {
                assert_eq!(get_requests[i].our_authority, our_authority);
                assert_eq!(get_requests[i].location,
                           Authority::ManagedNode(data_manager.nodes_in_table[i]));
                assert_eq!(get_requests[i].request_for, request);
            }
        }
    }

    #[test]
    fn handle_churn() {
        let (our_authority,
             routing,
             mut data_manager,
             from_authority,
             data) = env_setup();
        assert_eq!(::utils::HANDLED,
                   data_manager.handle_put(&our_authority,
                                           &request.src,
                                           &::routing::data::Data::ImmutableData(data.clone())));
        let close_group = vec![our_authority.get_name().clone()]
                              .into_iter()
                              .chain(data_manager.nodes_in_table.clone().into_iter())
                              .collect();
        let churn_node = random();
        data_manager.handle_churn(close_group, &churn_node);
        let refresh_requests = routing.refresh_requests_given();
        assert_eq!(refresh_requests.len(), 2);
        assert_eq!(refresh_requests[0].type_tag, ACCOUNT_TAG);
        assert_eq!(refresh_requests[0].our_authority.get_name().clone(),
                   data.name());
        assert_eq!(refresh_requests[1].type_tag, STATS_TAG);
        assert_eq!(refresh_requests[1].our_authority.get_name().clone(),
                   churn_node);
    }
}
