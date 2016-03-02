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
use routing::{Authority, Data, DataRequest, ImmutableData, ImmutableDataType, MessageId,
              RequestContent, RequestMessage, ResponseContent, ResponseMessage};
use sodiumoxide::crypto::hash::sha512;
use std::cmp::{self, Ordering};
use std::collections::{HashMap, HashSet};
use time::{Duration, SteadyTime};
use types::{Refresh, RefreshValue};
use vault::RoutingNode;
use xor_name::{self, XorName};

pub const REPLICANTS: usize = 6;
pub const MIN_REPLICANTS: usize = 6;

// This is the name of a PmidNode which has been chosen to store the data on.  It is assumed to be
// `Good` (can return the data) until it fails a Get request, at which time it is deemed `Failed`.
#[derive(Clone, PartialEq, Eq, Hash, Debug, RustcEncodable, RustcDecodable)]
pub enum DataHolder {
    Good(XorName),
    Failed(XorName),
}

impl DataHolder {
    pub fn name(&self) -> &XorName {
        match *self {
            DataHolder::Good(ref name) | DataHolder::Failed(ref name) => name,
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

impl QueriedDataHolder {
    pub fn name(&self) -> &XorName {
        match *self {
            QueriedDataHolder::PendingResponse(ref name) => name,
            QueriedDataHolder::Responded(ref data_holder) => data_holder.name(),
        }
    }
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
        let good_nodes = pmid_nodes.iter()
                                   .filter_map(|data_holder| {
                                       match *data_holder {
                                           DataHolder::Good(pmid_node) => {
                                               Some(QueriedDataHolder::PendingResponse(pmid_node))
                                           }
                                           DataHolder::Failed(_) => None,
                                       }
                                   })
                                   .collect();

        MetadataForGetRequest {
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
            ongoing_gets: LruCache::with_expiry_duration_and_capacity(Duration::minutes(5),
                                                                      LRU_CACHE_SIZE),
        }
    }

    pub fn handle_get(&mut self,
                      routing_node: &RoutingNode,
                      request: &RequestMessage)
                      -> Result<(), InternalError> {
        let (data_name, message_id) = match request.content {
            RequestContent::Get(DataRequest::Immutable(ref data_name, _), ref message_id) => {
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
                let _ = routing_node.send_get_failure(src,
                                                      dst,
                                                      request.clone(),
                                                      external_error_indicator,
                                                      message_id);
                return Err(InternalError::Client(error));
            }
        };

        {
            // If there's already a cached get request, handle it here and return
            if let Some(metadata) = self.ongoing_gets.get_mut(&data_name) {
                return Ok(Self::reply_with_data_else_cache_request(routing_node,
                                                                   request,
                                                                   &message_id,
                                                                   metadata));
            }
        }

        // This is new cache entry
        let entry = MetadataForGetRequest::new(request, pmid_nodes);
        for good_node in entry.pmid_nodes.iter() {
            let src = request.dst.clone();
            let dst = Authority::ManagedNode(good_node.name().clone());
            let data_request = DataRequest::Immutable(data_name.clone(), ImmutableDataType::Normal);
            debug!("ImmutableDataManager {:?} sending get {:?} to {:?}",
                   routing_node.name(),
                   data_name,
                   dst);
            let _ = routing_node.send_get_request(src, dst, data_request, message_id.clone());
        }
        let _ = self.ongoing_gets.insert(data_name, entry);

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
        let target_pmid_nodes = try!(Self::choose_target_pmid_nodes(routing_node,
                                                                    &data_name,
                                                                    vec![]));
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
                                                  Data::Immutable(data.clone()),
                                                  message_id.clone());
        }
        Ok(())
    }

    pub fn handle_get_success(&mut self,
                              routing_node: &RoutingNode,
                              response: &ResponseMessage)
                              -> Result<(), InternalError> {
        let (data, message_id) = match response.content {
            ResponseContent::GetSuccess(Data::Immutable(ref data), ref message_id) => {
                (data, message_id)
            }
            _ => unreachable!("Error in vault demuxing"),
        };
        let data_name = data.name();

        let mut result = Err(InternalError::FailedToFindCachedRequest(message_id.clone()));
        if let Some(metadata) = self.ongoing_gets.get_mut(&data_name) {
            result = Ok(());
            // Reply to any unanswered requests
            while let Some(request) = metadata.requests.pop() {
                let src = request.dst.clone();
                let dst = request.src;
                let _ = routing_node.send_get_success(src,
                                                      dst,
                                                      Data::Immutable(data.clone()),
                                                      message_id.clone());
            }

            // Mark the responder as "good"
            let predicate = |elt: &QueriedDataHolder| {
                match elt {
                    &QueriedDataHolder::PendingResponse(ref name) => name == response.src.name(),
                    &QueriedDataHolder::Responded(_) => false,
                }
            };
            if let Some(pmid_node_index) = metadata.pmid_nodes.iter().position(predicate) {
                let good_name = DataHolder::Good(metadata.pmid_nodes
                                                         .remove(pmid_node_index)
                                                         .name()
                                                         .clone());
                let _ = metadata.pmid_nodes.push(QueriedDataHolder::Responded(good_name));
            }

            // Keep the data with the cached metadata in case further get requests arrive for it
            if metadata.data.is_none() {
                metadata.data = Some(data.clone());
            }
        }

        try!(self.check_and_replicate(routing_node, &data_name));
        result
    }

    pub fn handle_get_failure(&mut self,
                              routing_node: &RoutingNode,
                              pmid_node: &XorName,
                              message_id: &MessageId,
                              request: &RequestMessage,
                              external_error_indicator: &Vec<u8>)
                              -> Result<(), InternalError> {
        let data_name = match request.content {
            RequestContent::Get(ref data_request, _) => data_request.name(),
            _ => {
                warn!("Request type doesn't correspond to response type: {:?}",
                      request);
                return Err(InternalError::InvalidResponse);
            }
        };

        let mut result = Err(InternalError::FailedToFindCachedRequest(message_id.clone()));
        if let Some(metadata) = self.ongoing_gets.get_mut(&data_name) {
            result = Ok(());

            // Mark the responder as "failed" in the cached get request
            let predicate = |elt: &QueriedDataHolder| {
                match elt {
                    &QueriedDataHolder::PendingResponse(ref name) => name == pmid_node,
                    &QueriedDataHolder::Responded(_) => false,
                }
            };
            if let Some(pmid_node_index) = metadata.pmid_nodes.iter().position(predicate) {
                let failed_name = DataHolder::Failed(metadata.pmid_nodes
                                                             .remove(pmid_node_index)
                                                             .name()
                                                             .clone());
                let _ = metadata.pmid_nodes.push(QueriedDataHolder::Responded(failed_name));
            }
        }

        // Mark the responder as "failed" in the account if it was previously marked "good"
        if let Some(pmid_nodes) = self.accounts.get_mut(&data_name) {
            if pmid_nodes.remove(&DataHolder::Good(pmid_node.clone())) {
                pmid_nodes.insert(DataHolder::Failed(pmid_node.clone()));
            }
        }

        try!(self.check_and_replicate(routing_node, &data_name));
        result
    }

    pub fn handle_refresh(&mut self, data_name: XorName, account: Account) {
        let _ = self.accounts.insert(data_name, account);
    }

    pub fn handle_node_added(&mut self, routing_node: &RoutingNode, _node_added: XorName) {
        self.handle_churn(routing_node)
    }

    pub fn handle_node_lost(&mut self, routing_node: &RoutingNode, _node_lost: XorName) {
        self.handle_churn(routing_node)
    }

    pub fn handle_churn(&mut self, routing_node: &RoutingNode) {
        for (data_name, pmid_nodes) in self.accounts.iter() {
            let src = Authority::NaeManager(data_name.clone());
            let refresh =
                Refresh::new(data_name,
                             RefreshValue::ImmutableDataManagerAccount(pmid_nodes.clone()));
            if let Ok(serialised_refresh) = serialisation::serialise(&refresh) {
                debug!("ImmutableDataManager sending refresh for account {:?}",
                       src.name());
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

    fn reply_with_data_else_cache_request(routing_node: &RoutingNode,
                                          request: &RequestMessage,
                                          message_id: &MessageId,
                                          metadata: &mut MetadataForGetRequest) {
        // If we've already received the chunk, send it to the new requester.  Otherwise
        // add the request to the others for later handling.
        match metadata.data {
            Some(ref data) => {
                let src = request.dst.clone();
                let dst = request.src.clone();
                let _ = routing_node.send_get_success(src,
                                                      dst,
                                                      Data::Immutable(data.clone()),
                                                      message_id.clone());
            }
            None => {
                metadata.requests.push(request.clone());
            }
        }
    }

    fn check_and_replicate(&mut self,
                           routing_node: &RoutingNode,
                           data_name: &XorName)
                           -> Result<(), InternalError> {
        let mut finished = false;
        let mut new_pmid_nodes = HashSet::<DataHolder>::new();
        if let Some(metadata) = self.ongoing_gets.get_mut(&data_name) {
            // Count the good holders, but just return from this function if any queried holders
            // haven't responded yet
            let mut good_holder_count = 0;
            for queried_data_holder in metadata.pmid_nodes.iter() {
                match queried_data_holder {
                    &QueriedDataHolder::PendingResponse(_) => return Ok(()),
                    &QueriedDataHolder::Responded(DataHolder::Good(_)) => good_holder_count += 1,
                    &QueriedDataHolder::Responded(DataHolder::Failed(_)) => (),
                }
            }

            if good_holder_count >= MIN_REPLICANTS {
                // We can now delete this cached get request with no need for further action
                finished = true;
            } else if let Some(ref data) = metadata.data {
                // Put to new close peers and delete this cached get request
                let mut good_nodes = HashSet::<DataHolder>::new();
                let mut nodes_to_exclude = vec![];
                for queried_data_holder in metadata.pmid_nodes.iter() {
                    match queried_data_holder {
                        &QueriedDataHolder::Responded(DataHolder::Good(ref name)) => {
                            let _ = good_nodes.insert(DataHolder::Good(name.clone()));
                        }
                        &QueriedDataHolder::Responded(DataHolder::Failed(ref name)) => {
                            nodes_to_exclude.push(name);
                        }
                        _ => unreachable!(),
                    }
                }
                let target_pmid_nodes = try!(Self::choose_target_pmid_nodes(routing_node,
                                                                            data_name,
                                                                            nodes_to_exclude));
                let message_id = MessageId::new();
                for new_pmid_node in target_pmid_nodes.difference(&good_nodes).into_iter() {
                    let src = Authority::NaeManager(data_name.clone());
                    let dst = Authority::NodeManager(new_pmid_node.name().clone());
                    new_pmid_nodes.insert(new_pmid_node.clone());
                    let _ = routing_node.send_put_request(src,
                                                          dst,
                                                          Data::Immutable(data.clone()),
                                                          message_id.clone());
                }
                finished = true;
            } else {
                // Recover the data from backup and/or sacrificial locations
                metadata.pmid_nodes.clear();
                // TODO - actually retrieve the data
            }
        }

        if finished {
            let _ = self.ongoing_gets.remove(data_name);
        }

        if !new_pmid_nodes.is_empty() {
            if let Some(pmid_nodes) = self.accounts.get_mut(data_name) {
                *pmid_nodes = pmid_nodes.union(&new_pmid_nodes).cloned().collect();
            }
        }

        Ok(())
    }

    fn choose_target_pmid_nodes(routing_node: &RoutingNode,
                                data_name: &XorName,
                                nodes_to_exclude: Vec<&XorName>)
                                -> Result<HashSet<DataHolder>, InternalError> {
        match try!(routing_node.close_group(data_name.clone())) {
            Some(mut target_pmid_nodes) => {
                target_pmid_nodes.retain(|elt| {
                    !nodes_to_exclude.iter().any(|exclude| elt == *exclude)
                });
                Self::sort_from_target(&mut target_pmid_nodes, data_name);
                target_pmid_nodes.truncate(REPLICANTS);
                Ok(target_pmid_nodes.into_iter()
                                    .map(|pmid_node| DataHolder::Good(pmid_node))
                                    .collect::<HashSet<DataHolder>>())
            }
            None => Err(InternalError::NotInCloseGroup),
        }
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
    //         ::routing::data::Data::Immutable(immutable_data) => immutable_data,
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
    //                     let content = ::routing::data::Data::Immutable(immutable_data);
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
    use maidsafe_utilities::log;
    use rand::random;
    use routing::{Authority, Data, DataRequest, ImmutableData, ImmutableDataType, MessageId,
                  RequestContent, RequestMessage};
    use sodiumoxide::crypto::sign;
    use std::sync::mpsc;
    use utils::generate_random_vec_u8;
    use vault::RoutingNode;

    struct Environment {
        pub our_authority: Authority,
        pub routing: RoutingNode,
        pub immutable_data_manager: ImmutableDataManager,
        pub data: ImmutableData,
    }

    fn environment_setup() -> Environment {
        log::init(false);
        let routing = unwrap_result!(RoutingNode::new(mpsc::channel().0));
        let immutable_data_manager = ImmutableDataManager::new();
        loop {
            // Create random ImmutableData until we get one we're close to.
            let value = generate_random_vec_u8(1024);
            let data = ImmutableData::new(ImmutableDataType::Normal, value);
            if unwrap_result!(routing.close_group(data.name())).is_some() {
                return Environment {
                    our_authority: Authority::NaeManager(data.name().clone()),
                    routing: routing,
                    immutable_data_manager: immutable_data_manager,
                    data: data,
                };
            }
        }
    }

    #[test]
    fn handle_put_get() {
        let mut env = environment_setup();
        {
            let message_id = MessageId::new();
            unwrap_result!(env.immutable_data_manager
                              .handle_put(&env.routing, &env.data, &message_id));
            let put_requests = env.routing.put_requests_given();
            assert_eq!(put_requests.len(), REPLICANTS);
            for i in 0..put_requests.len() {
                assert_eq!(put_requests[i].src, env.our_authority);
                assert_eq!(put_requests[i].content,
                           RequestContent::Put(Data::Immutable(env.data.clone()),
                                               message_id.clone()));
            }
        }
        {
            let keys = sign::gen_keypair();
            let from = random();
            let client = Authority::Client {
                client_key: keys.0,
                peer_id: random(),
                proxy_node_name: from,
            };

            let message_id = MessageId::new();
            let content = RequestContent::Get(DataRequest::Immutable(env.data.name().clone(),
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
        // let mut env = environment_setup();
        // env.immutable_data_manager.handle_put(&env.routing, &env.data);
        // let close_group = vec![env.our_authority.name().clone()]
        //                       .into_iter()
        //                       .chain(env.routing.close_group_including_self().into_iter())
        //                       .collect();
        // let churn_node = random();
        // env.immutable_data_manager.handle_churn(&env.routing, close_group, &churn_node);
        // let refresh_requests = env.routing.refresh_requests_given();
        // assert_eq!(refresh_requests.len(), 2);
        // {
        //     // Account refresh
        //     assert_eq!(refresh_requests[0].src.name().clone(), env.data.name());
        //     let (type_tag, cause) = match refresh_requests[0].content {
        //         RequestContent::Refresh{ type_tag, cause, .. } => (type_tag, cause),
        //         _ => panic!("Invalid content type"),
        //     };
        //     assert_eq!(type_tag, ACCOUNT_TAG);
        //     assert_eq!(cause, churn_node);
        // }
        // {
        //     // Stats refresh
        //     assert_eq!(refresh_requests[1].src.name().clone(), churn_node);
        //     let (type_tag, cause) = match refresh_requests[1].content {
        //         RequestContent::Refresh{ type_tag, cause, .. } => (type_tag, cause),
        //         _ => panic!("Invalid content type"),
        //     };
        //     assert_eq!(type_tag, STATS_TAG);
        //     assert_eq!(cause, churn_node);
        // }
    }
}
