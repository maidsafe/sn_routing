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

pub use routing::Authority::NaeManager as Authority;

pub const ACCOUNT_TAG: u64 = ::transfer_tag::TransferTag::DataManagerAccount as u64;
pub const STATS_TAG: u64 = ::transfer_tag::TransferTag::DataManagerStats as u64;
pub const REPLICANTS: usize = 4;
pub const MIN_REPLICANTS: usize = 3;

mod database;

type Account = self::database::Account;
type Address = ::routing::NameType;
type ChunkNameAndPmidNode = (::routing::NameType, ::routing::NameType);

const LRU_CACHE_SIZE: usize = 1000;

#[derive(RustcEncodable, RustcDecodable, Clone, PartialEq, Eq, Debug)]
pub struct Stats {
    name: ::routing::NameType,
    resource_index: u64,
}

impl Stats {
    pub fn new(name: ::routing::NameType, resource_index: u64) -> Stats {
        Stats { name: name, resource_index: resource_index }
    }

    pub fn name(&self) -> &::routing::NameType {
        &self.name
    }

    pub fn resource_index(&self) -> u64 {
        self.resource_index
    }
}

impl ::types::Refreshable for Stats {
    fn merge(from_group: ::routing::NameType, responses: Vec<Stats>) -> Option<Stats> {
        let mut resource_indexes: Vec<u64> = Vec::new();
        for value in responses {
            if *value.name() == from_group {
                resource_indexes.push(value.resource_index());
            }
        }
        Some(Stats::new(::routing::NameType([0u8; 64]), ::utils::median(resource_indexes)))
    }
}



pub struct DataManager {
    routing: ::vault::Routing,
    database: database::Database,
    id: ::routing::NameType,
    nodes_in_table: Vec<::routing::NameType>,
    request_cache: ::lru_time_cache::LruCache<::routing::NameType,
                             Vec<(::routing::authority::Authority, ::routing::data::DataRequest,
                                  Option<::routing::SignedToken>)>>,
    // the higher the index is, the slower the farming rate will be
    resource_index: u64,
    // key is pair of chunk_name and pmid_node, value is insertion time
    ongoing_gets: ::lru_time_cache::LruCache<ChunkNameAndPmidNode, ::time::SteadyTime>,
    // key is chunk_name and value is failing pmid nodes
    failed_pmids: ::lru_time_cache::LruCache<::routing::NameType, Vec<::routing::NameType>>,
}

impl DataManager {
    pub fn new(routing: ::vault::Routing) -> DataManager {
        DataManager {
            routing: routing,
            database: database::Database::new(),
            id: ::routing::NameType::new([0u8; 64]),
            nodes_in_table: vec![],
            request_cache: ::lru_time_cache::LruCache::with_expiry_duration_and_capacity(
                ::time::Duration::minutes(5), LRU_CACHE_SIZE),
            resource_index: 1,
            ongoing_gets: ::lru_time_cache::LruCache::with_capacity(LRU_CACHE_SIZE),
            failed_pmids: ::lru_time_cache::LruCache::with_capacity(LRU_CACHE_SIZE),
        }
    }

    pub fn handle_get(&mut self,
                      our_authority: &::routing::Authority,
                      from_authority: &::routing::Authority,
                      data_request: &::routing::data::DataRequest,
                      response_token: &Option<::routing::SignedToken>)
                      -> Option<()> {
        // Check if this is for this persona and that the Data is Immutable
        if !::utils::is_data_manager_authority_type(our_authority) {
            return ::utils::NOT_HANDLED;
        }
        let data_name = match data_request {
            &::routing::data::DataRequest::ImmutableData(ref data_name, _) => data_name,
            _ => return ::utils::NOT_HANDLED,
        };

        // Validate from authority and ImmutableDataType
        if !::utils::is_client_authority_type(from_authority) {
            warn!("Invalid authority for GET at DataManager: {:?}", from_authority);
            return ::utils::HANDLED;
        }
        // all immutable_data type shall be handled in DataManager
        // if *immutable_data_name_and_type.1 != ::routing::immutable_data::ImmutableDataType::Normal {
        //     warn!("Invalid immutable data type for GET at DataManager: {:?}",
        //           immutable_data_name_and_type.1);
        //     return ::utils::HANDLED;
        // }

        // Cache the request
        if self.request_cache.contains_key(data_name) {
            debug!("DataManager {:?} inserting original request {:?} from {:?} into {:?} ",
                   self.id, data_request, from_authority, data_name);
            match self.request_cache.get_mut(data_name) {
                Some(ref mut request) => request.push((from_authority.clone(),
                                                       data_request.clone(),
                                                       response_token.clone())),
                None => error!("Failed to insert get request in the cache."),
            };
        } else {
            debug!("DataManager {:?} created original request {:?} from {:?} as entry {:?}",
                   self.id, data_request, from_authority, data_name);
            let _ = self.request_cache.insert(*data_name,
                                              vec![(from_authority.clone(),
                data_request.clone(), response_token.clone())]);
        }

        // Before querying the records, first ensure all records are valid
        let ongoing_gets = self.ongoing_gets.retrieve_all();
        let mut failing_entries = Vec::new();
        let mut fetching_list = ::std::collections::BTreeSet::new();
        fetching_list.insert(data_name.clone());
        for ongoing_get in ongoing_gets {
            if ongoing_get.1 + ::time::Duration::seconds(10) < ::time::SteadyTime::now() {
                debug!("DataManager {:?} removing pmid_node {:?} for chunk {:?}",
                       self.id, (ongoing_get.0).1, (ongoing_get.0).0);
                self.database.remove_pmid_node(&(ongoing_get.0).0, (ongoing_get.0).1.clone());
                // Starts fecthing immediately no matter how many alive pmid_nodes left over
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
                    let _ = self.failed_pmids.insert((ongoing_get.0).0.clone(),
                                                     vec![(ongoing_get.0).1.clone()]);
                }
            }
        }
        for failed_entry in failing_entries {
            let _ = self.ongoing_gets.remove(&failed_entry);
        }
        for fetch_name in fetching_list.iter() {
            debug!("DataManager {:?} having {:?} records for chunk {:?}",
                   self.id, self.database.exist(&fetch_name), fetch_name);
            for pmid in self.database.get_pmid_nodes(fetch_name) {
                let location = ::pmid_node::Authority(pmid.clone());
                debug!("DataManager {:?} sending get {:?} request to {:?}",
                       self.id, fetch_name, location);
                self.routing.get_request(Authority(fetch_name.clone()), location,
                    ::routing::data::DataRequest::ImmutableData(fetch_name.clone(),
                        ::routing::immutable_data::ImmutableDataType::Normal));
                let _ = self.ongoing_gets
                            .insert((fetch_name.clone(), pmid.clone()), ::time::SteadyTime::now());
            }
        }
        ::utils::HANDLED
    }

    pub fn handle_put(&mut self,
                      our_authority: &::routing::Authority,
                      from_authority: &::routing::Authority,
                      data: &::routing::data::Data)
                      -> Option<()> {
        // Check if this is for this persona and that the Data is Immutable.
        if !::utils::is_data_manager_authority_type(our_authority) {
            return ::utils::NOT_HANDLED;
        }
        let immutable_data = match data {
            &::routing::data::Data::ImmutableData(ref immutable_data) => immutable_data,
            _ => return ::utils::NOT_HANDLED,
        };

        // Validate from authority.
        if !::utils::is_maid_manager_authority_type(from_authority) {
            warn!("Invalid authority for PUT at DataManager: {:?}", from_authority);
            return ::utils::HANDLED;
        }

        // If the data already exists, there's no more to do.
        let data_name = immutable_data.name();
        if self.database.exist(&data_name) {
            return ::utils::HANDLED;
        }

        // Choose the PmidNodes to store the data on, and add them in a new database entry.
        Self::sort_from_target(&mut self.nodes_in_table, &data_name);
        let pmid_nodes_num = ::std::cmp::min(self.nodes_in_table.len(), REPLICANTS);
        let mut dest_pmids: Vec<::routing::NameType> = Vec::new();
        for index in 0..pmid_nodes_num {
            dest_pmids.push(self.nodes_in_table[index].clone());
        }
        debug!("DataManager {:?} chosen {:?} as pmid_nodes for chunk {:?}",
                self.id, dest_pmids, data_name);
        self.database.put_pmid_nodes(&data_name, dest_pmids.clone());
        match *immutable_data.get_type_tag() {
            ::routing::immutable_data::ImmutableDataType::Sacrificial => {
                self.resource_index = ::std::cmp::min(1048576,
                                                      self.resource_index +
                                                      dest_pmids.len() as u64);
            }
            _ => {}
        }

        // Send the message on to the PmidNodes' managers.
        for pmid in dest_pmids {
            let location = ::pmid_manager::Authority(pmid);
            let content = ::routing::data::Data::ImmutableData(immutable_data.clone());
            self.routing.put_request(our_authority.clone(), location, content);
        }
        ::utils::HANDLED
    }

    pub fn handle_get_response(&mut self,
                               our_authority: &::routing::Authority,
                               from_authority: &::routing::Authority,
                               response: &::routing::data::Data,
                               response_token: &Option<::routing::SignedToken>)
                               -> Option<()> {
        // Check if this is for this persona.
        if !::utils::is_data_manager_authority_type(our_authority) {
            return ::utils::NOT_HANDLED;
        }

        // Validate from authority, and that the Data is ImmutableData.
        if !::utils::is_pmid_node_authority_type(from_authority) {
            warn!("Invalid authority for GET response at DataManager: {:?}", from_authority);
            return ::utils::HANDLED;
        }
        let _ = match response {
            &::routing::data::Data::ImmutableData(_) => (),
            _ => {
                warn!("Invalid data type for GET response at DataManager: {:?}", response);
                return ::utils::HANDLED;
            }
        };

        // Respond if there is a corresponding cached request.
        if self.request_cache.contains_key(&response.name()) {
            match self.request_cache.remove(&response.name()) {
                Some(requests) => {
                    for request in requests {
                        self.routing.get_response(our_authority.clone(),
                                                  request.0,
                                                  response.clone(),
                                                  request.1,
                                                  request.2);
                    }
                }
                None => debug!("Failed to find any requests for get response from {:?} with our \
                               authority {:?}: {:?}.", from_authority, our_authority, response),
            };
        }

        let _ = self.ongoing_gets.remove(&(response.name(), from_authority.get_location().clone()));
        match self.failed_pmids.remove(&response.name()) {
            Some(failed_pmids) => {
                for failed_pmid in failed_pmids {
                    // utilise put_response as get_response doesn't take ResponseError
                    debug!("DataManager {:?} notifying a failed pmid_node {:?} regarding chunk {:?}",
                           self.id, failed_pmid, response.name());
                    let location = ::pmid_manager::Authority(failed_pmid);
                    self.routing.put_response(our_authority.clone(), location,
                        ::routing::error::ResponseError::FailedRequestForData(response.clone()),
                        response_token.clone());
                }
            }
            None => {}
        }

        if let Some(pmid_node) = self.replicate_to(&response.name()) {
            debug!("DataManager {:?} replicate chunk {:?} to a new pmid_node {:?}",
                   self.id, response.name(), pmid_node);
            self.database.add_pmid_node(&response.name(), pmid_node.clone());
            let location = ::pmid_node::Authority(pmid_node);
            self.routing.put_request(our_authority.clone(), location, response.clone());
        };

        ::utils::HANDLED
    }

    pub fn handle_put_response(&mut self,
                               our_authority: &::routing::Authority,
                               from_authority: &::routing::Authority,
                               response: &::routing::error::ResponseError)
                               -> Option<()> {
        // Check if this is for this persona.
        if !::utils::is_data_manager_authority_type(our_authority) {
            return ::utils::NOT_HANDLED;
        }
        info!("DataManager handle_put_responsen from {:?}", from_authority);

        // Validate from authority.
        let pmid_node_name = match from_authority {
            &::pmid_manager::Authority(name) => name,
            _ => {
                warn!("Invalid authority for PUT response at DataManager: {:?}", from_authority);
                return ::utils::HANDLED;
            }
        };

        match response.clone() {
            ::routing::error::ResponseError::FailedRequestForData(data) => {
                self.handle_failed_request_for_data(data, pmid_node_name, our_authority.clone());
            }
            ::routing::error::ResponseError::HadToClearSacrificial(data_name, _) => {
                self.handle_had_to_clear_sacrificial(data_name, pmid_node_name);
            }
            _ => warn!("Invalid response type for PUT response at DataManager: {:?}", response),
        }
        ::utils::HANDLED
    }

    pub fn handle_refresh(&mut self,
                          type_tag: &u64,
                          our_authority: &::routing::Authority,
                          payloads: &Vec<Vec<u8>>)
                          -> Option<()> {
        match type_tag {
            &ACCOUNT_TAG => {
                if let &Authority(from_group) = our_authority {
                    if let Some(merged_account) = ::utils::merge::<Account>(from_group,
                                                                            payloads.clone()) {
                        debug!("DataManager {:?} receiving refreshed account {:?}",
                               self.id, merged_account);
                        self.database.handle_account_transfer(merged_account);
                    }
                } else {
                    warn!("Invalid authority for refresh account at DataManager: {:?}",
                          our_authority);
                }
                ::utils::HANDLED
            }
            &STATS_TAG => {
                if let &Authority(from_group) = our_authority {
                    if let Some(merged_stats) = ::utils::merge::<Stats>(from_group,
                                                                        payloads.clone()) {
                        // give priority to incoming stats
                        self.resource_index = merged_stats.resource_index();
                    }
                } else {
                    warn!("Invalid authority for refresh stats at DataManager: {:?}",
                          our_authority);
                }
                ::utils::HANDLED
            }
            _ => ::utils::NOT_HANDLED,
        }
    }

    pub fn set_node_table(&mut self, close_group: Vec<::routing::NameType>) {
        self.id = close_group[0].clone();
        self.nodes_in_table = close_group;
    }

    pub fn handle_churn(&mut self, close_group: Vec<::routing::NameType>,
                        churn_node: &::routing::NameType) {
        // If the churn_node exists in the previous DM's nodes_in_table,
        // but not in this reported close_group, it indicates such node is leaving the group.
        // However, it is not to say the node is offline, as it may still connected with other
        let node_leaving = !close_group.contains(churn_node) &&
                           self.nodes_in_table.contains(churn_node);
        let on_going_gets = self.database.handle_churn(&self.routing, churn_node, node_leaving);

        for entry in on_going_gets.iter() {
            if self.failed_pmids.contains_key(&entry.0) {
                match self.failed_pmids.get_mut(&entry.0) {
                    Some(ref mut pmids) => pmids.push(churn_node.clone()),
                    None => error!("Failed to insert failed_pmid in the cache."),
                };
            } else {
                let _ = self.failed_pmids.insert(entry.0.clone(),
                                                 vec![churn_node.clone()]);
            }
            for pmid in entry.1.iter() {
                let _ = self.ongoing_gets
                            .insert((entry.0.clone(), pmid.clone()), ::time::SteadyTime::now());
            }
        }
        // close_group[0] is supposed to be the vault id
        let data_manager_stats = Stats::new(close_group[0].clone(), self.resource_index);
        let mut encoder = ::cbor::Encoder::from_memory();
        if encoder.encode(&[data_manager_stats.clone()]).is_ok() {
            self.routing.refresh_request(STATS_TAG, Authority(churn_node.clone()),
                                         encoder.as_bytes().to_vec(), churn_node.clone());
        }
        self.set_node_table(close_group);
    }

    pub fn reset(&mut self, routing: ::vault::Routing) {
        self.routing = routing;
        self.nodes_in_table.clear();
        self.request_cache = ::lru_time_cache::LruCache::with_expiry_duration_and_capacity(
                ::time::Duration::minutes(5), 1000);
        self.resource_index = 1;
        self.ongoing_gets = ::lru_time_cache::LruCache::with_capacity(LRU_CACHE_SIZE);
        self.failed_pmids = ::lru_time_cache::LruCache::with_capacity(LRU_CACHE_SIZE);
        self.database.cleanup();
    }

    pub fn do_refresh(&mut self,
                      type_tag: &u64,
                      our_authority: &::routing::Authority,
                      churn_node: &::routing::NameType) -> Option<()> {
        self.database.do_refresh(type_tag, our_authority, churn_node, &self.routing)
    }

    pub fn nodes_in_table_len(&self) -> usize {
        self.nodes_in_table.len()
    }

    fn replicate_to(&mut self, name: &::routing::NameType) -> Option<::routing::NameType> {
        let pmid_nodes = self.database.get_pmid_nodes(name);
        if pmid_nodes.len() < MIN_REPLICANTS && pmid_nodes.len() > 0 {
            Self::sort_from_target(&mut self.nodes_in_table, &name);
            for close_grp_it in self.nodes_in_table.iter() {
                if pmid_nodes.iter().find(|a| **a == *close_grp_it).is_none() {
                    debug!("node {:?} replicating chunk {:?} to a new node {:?}",
                           self.id, name, close_grp_it);
                    return Some(close_grp_it.clone());
                }
            }
        }
        None
    }

    fn sort_from_target(names: &mut Vec<::routing::NameType>, target: &::routing::NameType) {
        names.sort_by(|a, b| {
            if ::routing::closer_to_target(&a, &b, target) {
                ::std::cmp::Ordering::Less
            } else {
                ::std::cmp::Ordering::Greater
            }
        });
    }

    fn handle_failed_request_for_data(&mut self,
                                      data: ::routing::data::Data,
                                      pmid_node_name: ::routing::NameType,
                                      our_authority: ::routing::Authority) {
        // Validate that the Data is ImmutableData.
        let immutable_data = match data {
            ::routing::data::Data::ImmutableData(immutable_data) => immutable_data,
            _ => return,
        };

        // giving more weight when failed in storing a Normal immutable data
        // i.e increasing slowly but dropping quickly
        self.resource_index = ::std::cmp::max(1, self.resource_index - 4);

        let data_name = immutable_data.name();
        self.database.remove_pmid_node(&data_name, pmid_node_name);
        match *immutable_data.get_type_tag() {
            ::routing::immutable_data::ImmutableDataType::Normal => {
                match self.replicate_to(&data_name) {
                    Some(pmid_node) => {
                        self.database.add_pmid_node(&data_name, pmid_node.clone());
                        let location = ::pmid_manager::Authority(pmid_node);
                        let content = ::routing::data::Data::ImmutableData(immutable_data);
                        self.routing.put_request(our_authority, location, content);
                    }
                    None => {
                        warn!("Failed to find nodes to replicate data to.");
                    }
                }
            }
            // Don't need to replicate Backup or Sacrificial chunks
            _ => {}
        }
    }

    fn handle_had_to_clear_sacrificial(&mut self,
                                       data_name: ::routing::NameType,
                                       pmid_node_name: ::routing::NameType) {
        // giving less weight when removing a sacrificial data
        self.resource_index = ::std::cmp::max(1, self.resource_index - 1);
        self.database.remove_pmid_node(&data_name, pmid_node_name);
    }
}



#[cfg(all(test, feature = "use-mock-routing"))]
mod test {
    use super::*;

    fn env_setup() -> (::routing::Authority, ::vault::Routing, DataManager, ::routing::Authority,
                       ::routing::immutable_data::ImmutableData) {
        let routing = ::vault::Routing::new(::std::sync::mpsc::channel().0);
        let mut data_manager = DataManager::new(routing.clone());
        let value = ::routing::types::generate_random_vec_u8(1024);
        let data = ::routing::immutable_data::ImmutableData::new(
                       ::routing::immutable_data::ImmutableDataType::Normal, value);
        data_manager.nodes_in_table = vec![::routing::NameType::new([1u8; 64]),
                                           ::routing::NameType::new([2u8; 64]),
                                           ::routing::NameType::new([3u8; 64]),
                                           ::routing::NameType::new([4u8; 64]),
                                           ::routing::NameType::new([5u8; 64]),
                                           ::routing::NameType::new([6u8; 64]),
                                           ::routing::NameType::new([7u8; 64]),
                                           ::routing::NameType::new([8u8; 64])];
        (Authority(data.name().clone()),
         routing,
         data_manager,
         ::maid_manager::Authority(::utils::random_name()),
         data)
    }

    #[test]
    fn handle_put_get() {
        let (our_authority, routing, mut data_manager, from_authority, data) = env_setup();
        {
            assert_eq!(::utils::HANDLED,
                data_manager.handle_put(&our_authority, &from_authority,
                                        &::routing::data::Data::ImmutableData(data.clone())));
            let put_requests = routing.put_requests_given();
            assert_eq!(put_requests.len(), REPLICANTS);
            for i in 0..put_requests.len() {
                assert_eq!(put_requests[i].our_authority, our_authority);
                assert_eq!(put_requests[i].location,
                           ::pmid_manager::Authority(data_manager.nodes_in_table[i]));
                assert_eq!(put_requests[i].data,
                           ::routing::data::Data::ImmutableData(data.clone()));
            }
        }
        {
            let from = ::utils::random_name();
            let keys = ::sodiumoxide::crypto::sign::gen_keypair();
            let client = ::routing::Authority::Client(from, keys.0);

            let request = ::routing::data::DataRequest::ImmutableData(data.name().clone(),
                              ::routing::immutable_data::ImmutableDataType::Normal);

            assert_eq!(::utils::HANDLED,
                       data_manager.handle_get(&our_authority, &client, &request, &None));
            let get_requests = routing.get_requests_given();
            assert_eq!(get_requests.len(), REPLICANTS);
            for i in 0..get_requests.len() {
                assert_eq!(get_requests[i].our_authority, our_authority);
                assert_eq!(get_requests[i].location,
                           ::pmid_node::Authority(data_manager.nodes_in_table[i]));
                assert_eq!(get_requests[i].request_for, request);
            }
        }
    }

    #[test]
    fn handle_churn() {
        let (our_authority, routing, mut data_manager, from_authority, data) = env_setup();
        assert_eq!(::utils::HANDLED,
            data_manager.handle_put(&our_authority, &from_authority,
                                    &::routing::data::Data::ImmutableData(data.clone())));
        let close_group = vec![our_authority.get_location().clone()]
                              .into_iter()
                              .chain(data_manager.nodes_in_table.clone().into_iter())
                              .collect();
        let churn_node = ::utils::random_name();
        data_manager.handle_churn(close_group, &churn_node);
        let refresh_requests = routing.refresh_requests_given();
        assert_eq!(refresh_requests.len(), 2);
        assert_eq!(refresh_requests[0].type_tag, ACCOUNT_TAG);
        assert_eq!(refresh_requests[0].our_authority.get_location().clone(), data.name());
        assert_eq!(refresh_requests[1].type_tag, STATS_TAG);
        assert_eq!(refresh_requests[1].our_authority.get_location().clone(), churn_node);
    }
}
