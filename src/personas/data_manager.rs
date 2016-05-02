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

use std::collections::{HashMap, HashSet};
use std::convert::From;
use std::fmt::{self, Debug, Formatter};
use std::ops::Add;
use std::rc::Rc;
use std::time::{Duration, Instant};

use accumulator::Accumulator;
use chunk_store::ChunkStore;
use error::InternalError;
use itertools::Itertools;
use kademlia_routing_table::{ContactInfo, GROUP_SIZE, RoutingTable};
use maidsafe_utilities::serialisation;
use routing::{Authority, Data, DataIdentifier, MessageId, RequestMessage, StructuredData};
use safe_network_common::client_errors::{MutationError, GetError};
use vault::{CHUNK_STORE_PREFIX, NodeInfo, RoutingNode};
use xor_name::{self, XorName};

const MAX_FULL_PERCENT: u64 = 50;
/// The quorum for accumulating refresh messages.
const ACCUMULATOR_QUORUM: usize = GROUP_SIZE / 2 + 1;
/// The timeout for accumulating refresh messages.
const ACCUMULATOR_TIMEOUT_SECS: u64 = 180;
/// The timeout for retrieving data chunks from individual peers.
const GET_FROM_DATA_HOLDER_TIMEOUT_SECS: u64 = 20;

/// Specification of a particular version of a data chunk. For immutable data, the `u64` is always
/// 0; for structured data, it specifies the version.
pub type IdAndVersion = (DataIdentifier, u64);

pub struct DataManager {
    chunk_store: ChunkStore<DataIdentifier, Data>,
    /// Accumulates refresh messages and the peers we received them from.
    refresh_accumulator: Accumulator<IdAndVersion, XorName>,
    /// Maps the peers to the set of data chunks that we need and we know they hold.
    data_holders: HashMap<XorName, HashSet<DataIdentifier>>,
    /// Maps the peers to the data chunks we requested from them, and the timestamp of the request.
    ongoing_gets: HashMap<XorName, (Instant, DataIdentifier)>,
    routing_node: Rc<RoutingNode>,
    immutable_data_count: u64,
    structured_data_count: u64,
    ongoing_gets_count: usize,
    data_holder_items_count: usize,
}

impl Debug for DataManager {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter,
               "Stats - Data stored - ImmData {} - SD {} - total {} bytes",
               self.immutable_data_count,
               self.structured_data_count,
               self.chunk_store.used_space())
    }
}

impl DataManager {
    pub fn new(routing_node: Rc<RoutingNode>, capacity: u64) -> Result<DataManager, InternalError> {
        Ok(DataManager {
            chunk_store: try!(ChunkStore::new(CHUNK_STORE_PREFIX, capacity)),
            refresh_accumulator:
                Accumulator::with_duration(ACCUMULATOR_QUORUM,
                                           Duration::from_secs(ACCUMULATOR_TIMEOUT_SECS)),
            data_holders: HashMap::new(),
            ongoing_gets: HashMap::new(),
            routing_node: routing_node,
            immutable_data_count: 0,
            structured_data_count: 0,
            ongoing_gets_count: 0,
            data_holder_items_count: 0,
        })
    }

    pub fn handle_get(&mut self,
                      request: &RequestMessage,
                      data_id: &DataIdentifier,
                      message_id: &MessageId)
                      -> Result<(), InternalError> {
        if let Ok(data) = self.chunk_store.get(&data_id) {
            trace!("As {:?} sending data {:?} to {:?}",
                   request.dst,
                   data,
                   request.src);
            let _ = self.routing_node
                        .send_get_success(request.dst.clone(),
                                          request.src.clone(),
                                          data,
                                          *message_id);
            return Ok(());
        }
        trace!("DM sending get_failure of {:?}", data_id);
        let error = GetError::NoSuchData;
        let external_error_indicator = try!(serialisation::serialise(&error));
        try!(self.routing_node
                 .send_get_failure(request.dst.clone(),
                                   request.src.clone(),
                                   request.clone(),
                                   external_error_indicator,
                                   message_id.clone()));
        Ok(())
    }

    pub fn handle_put(&mut self,
                      request: &RequestMessage,
                      data: &Data,
                      message_id: &MessageId)
                      -> Result<(), InternalError> {
        let data_identifier = data.identifier();
        let response_src = request.dst.clone();
        let response_dst = request.src.clone();

        if self.chunk_store.has(&data_identifier) {
            let error = MutationError::DataExists;
            let external_error_indicator = try!(serialisation::serialise(&error));
            trace!("DM sending PutFailure for data {:?}", data_identifier);
            let _ = self.routing_node
                        .send_put_failure(response_src,
                                          response_dst,
                                          request.clone(),
                                          external_error_indicator,
                                          *message_id);
            return Err(From::from(error));
        }

        // Check there aren't too many full nodes in the close group to this data
        if self.chunk_store.used_space() > (self.chunk_store.max_space() / 100) * MAX_FULL_PERCENT {
            let error = MutationError::NetworkFull;
            let external_error_indicator = try!(serialisation::serialise(&error));
            let _ = self.routing_node
                        .send_put_failure(response_src,
                                          response_dst,
                                          request.clone(),
                                          external_error_indicator,
                                          *message_id);
            return Err(From::from(error));
        }

        if let Err(err) = self.chunk_store
                              .put(&data_identifier, data) {
            trace!("DM failed to store {:?} in chunkstore: {:?}",
                   data_identifier,
                   err);
            let error = MutationError::Unknown;
            let external_error_indicator = try!(serialisation::serialise(&error));
            let _ = self.routing_node
                        .send_put_failure(response_src,
                                          response_dst,
                                          request.clone(),
                                          external_error_indicator,
                                          *message_id);
            Err(From::from(error))
        } else {
            let version = match *data {
                Data::Immutable(_) => {
                    self.immutable_data_count += 1;
                    0
                }
                Data::Structured(ref sd) => {
                    self.structured_data_count += 1;
                    sd.get_version()
                }
                _ => unreachable!(),
            };
            trace!("DM sending PutSuccess for data {:?}", data_identifier);
            info!("{:?}", self);
            let _ = self.routing_node
                        .send_put_success(response_src, response_dst, data_identifier, *message_id);
            let data_list = vec![(data_identifier, version)];
            let _ = self.send_refresh(Authority::NaeManager(data.name()), data_list);
            Ok(())
        }
    }

    // This function is only for SD
    pub fn handle_post(&mut self,
                       request: &RequestMessage,
                       new_data: &StructuredData,
                       message_id: &MessageId)
                       -> Result<(), InternalError> {
        if let Ok(Data::Structured(mut data)) = self.chunk_store.get(&new_data.identifier()) {
            if data.replace_with_other(new_data.clone()).is_ok() {
                if let Ok(()) = self.chunk_store
                                    .put(&data.identifier(), &Data::Structured(data.clone())) {
                    trace!("DM updated for: {:?}", data.identifier());
                    let _ = self.routing_node
                                .send_post_success(request.dst.clone(),
                                                   request.src.clone(),
                                                   data.identifier(),
                                                   *message_id);
                    let data_list = vec![(new_data.identifier(), new_data.get_version())];
                    let _ = self.send_refresh(Authority::NaeManager(data.name()), data_list);
                    return Ok(());
                }
            }
        }

        trace!("DM sending post_failure {:?}", new_data.identifier());
        Ok(try!(self.routing_node.send_post_failure(request.dst.clone(),
                                                    request.src.clone(),
                                                    request.clone(),
                                                    try!(serialisation::serialise(&MutationError::InvalidSuccessor)),
                                                    *message_id)))
    }

    /// The structured_data in the delete request must be a valid updating version of the target
    pub fn handle_delete(&mut self,
                         request: &RequestMessage,
                         new_data: &StructuredData,
                         message_id: &MessageId)
                         -> Result<(), InternalError> {
        if let Ok(Data::Structured(data)) = self.chunk_store.get(&new_data.identifier()) {
            if data.validate_self_against_successor(&new_data).is_ok() {
                if let Ok(()) = self.chunk_store.delete(&data.identifier()) {
                    self.structured_data_count -= 1;
                    trace!("DM deleted {:?}", data.identifier());
                    info!("{:?}", self);
                    let _ = self.routing_node
                                .send_delete_success(request.dst.clone(),
                                                     request.src.clone(),
                                                     data.identifier(),
                                                     *message_id);
                    // TODO: Send a refresh message.
                    return Ok(());
                }
            }
        }
        trace!("DM sending delete_failure for {:?}", new_data.identifier());
        try!(self.routing_node.send_delete_failure(request.dst.clone(),
                                                   request.src.clone(),
                                                   request.clone(),
                                                   try!(serialisation::serialise(&MutationError::InvalidSuccessor)),
                                                   *message_id));
        Ok(())
    }

    pub fn handle_get_success(&mut self, src: &XorName, data: &Data) -> Result<(), InternalError> {
        let mut unexpected = true;
        if let Some((timestamp, data_id)) = self.ongoing_gets.remove(src) {
            if data_id == data.identifier() {
                unexpected = false;
            } else {
                let _ = self.ongoing_gets.insert(*src, (timestamp, data_id));
            }
        };
        if unexpected {
            warn!("Got unexpected GetSuccess for data {:?}.",
                  data.identifier());
            return Err(InternalError::InvalidMessage);
        }
        for (_, data_ids) in &mut self.data_holders {
            let _ = data_ids.remove(&data.identifier());
        }
        try!(self.send_gets_for_needed_data());
        // If we're no longer in the close group, return.
        if !self.close_to_address(&data.name()) {
            return Ok(());
        }
        // TODO: Check that the data's hash actually agrees with an accumulated entry.
        let mut got_new_data = true;
        match *data {
            Data::Structured(ref new_structured_data) => {
                if let Ok(Data::Structured(structured_data)) = self.chunk_store
                                                                   .get(&data.identifier()) {
                    // Make sure we don't 'update' to a lower version.
                    if structured_data.get_version() >= new_structured_data.get_version() {
                        return Ok(());
                    }
                    got_new_data = false;
                }
            }
            Data::Immutable(_) => {
                if self.chunk_store.has(&data.identifier()) {
                    return Ok(()); // Immutable data is already there.
                }
            }
            _ => unreachable!(),
        }

        // chunk_store::put() deletes the old data automatically.
        try!(self.chunk_store.put(&data.identifier(), &data));
        if got_new_data {
            match *data {
                Data::Immutable(_) => self.immutable_data_count += 1,
                Data::Structured(_) => self.structured_data_count += 1,
                _ => unreachable!(),
            }
        }
        info!("{:?}", self);
        Ok(())
    }

    pub fn handle_get_failure(&mut self,
                              src: &XorName,
                              data_id: &DataIdentifier)
                              -> Result<(), InternalError> {
        let mut unexpected = true;
        if let Some((timestamp, expected_id)) = self.ongoing_gets.remove(src) {
            if expected_id == *data_id {
                unexpected = false;
            } else {
                let _ = self.ongoing_gets.insert(*src, (timestamp, expected_id));
            }
        };
        if unexpected {
            warn!("Got unexpected GetFailure for data {:?}.", data_id);
            return Err(InternalError::InvalidMessage);
        }
        self.send_gets_for_needed_data()
    }

    pub fn handle_refresh(&mut self,
                          src: &XorName,
                          serialised_data_list: &[u8])
                          -> Result<(), InternalError> {
        let data_list = try!(serialisation::deserialise::<Vec<IdAndVersion>>(serialised_data_list));
        for (data_id, version) in data_list {
            if self.data_holders.values().any(|data_ids| data_ids.contains(&data_id)) {
                let _ = self.data_holders.entry(*src).or_insert_with(HashSet::new).insert(data_id);
            } else if let Some(holders) = self.refresh_accumulator.add((data_id, version), *src) {
                self.refresh_accumulator.delete(&(data_id, version));
                let data_needed = match data_id {
                    DataIdentifier::Immutable(..) => !self.chunk_store.has(&data_id),
                    DataIdentifier::Structured(..) => {
                        match self.chunk_store.get(&data_id) {
                            Err(_) => true, // We don't have the data, so we need to retrieve it.
                            Ok(Data::Structured(sd)) => sd.get_version() < version,
                            _ => unreachable!(),
                        }
                    }
                    _ => {
                        error!("Received unexpected refresh for {:?}.", data_id);
                        continue;
                    }
                };
                if !data_needed {
                    continue;
                }
                for holder in holders {
                    let _ = self.data_holders
                                .entry(holder)
                                .or_insert_with(HashSet::new)
                                .insert(data_id);
                }
            }
        }
        self.send_gets_for_needed_data()
    }

    fn send_gets_for_needed_data(&mut self) -> Result<(), InternalError> {
        let empty_holders = self.data_holders
                                .iter()
                                .filter(|&(_, ref data_ids)| data_ids.is_empty())
                                .map(|(holder, _)| *holder)
                                .collect_vec();
        for holder in empty_holders {
            let _ = self.data_holders.remove(&holder);
        }
        let expired_gets = self.ongoing_gets
                               .iter()
                               .filter(|&(_, &(ref timestamp, _))| {
                                   timestamp.elapsed().as_secs() > GET_FROM_DATA_HOLDER_TIMEOUT_SECS
                               })
                               .map(|(holder, _)| *holder)
                               .collect_vec();
        for holder in expired_gets {
            let _ = self.ongoing_gets.remove(&holder);
        }
        let mut outstanding_data_ids: HashSet<DataIdentifier> = self.ongoing_gets
                                                                    .values()
                                                                    .map(|&(_, data_id)| data_id)
                                                                    .collect();
        let idle_holders = self.data_holders
                               .keys()
                               .filter(|holder| !self.ongoing_gets.contains_key(holder))
                               .cloned()
                               .collect_vec();
        for idle_holder in idle_holders {
            if let Some(data_ids) = self.data_holders.get_mut(&idle_holder) {
                if let Some(&data_id) = data_ids.iter()
                                                .find(|data_id| {
                                                    !outstanding_data_ids.contains(data_id)
                                                }) {
                    let _ = data_ids.remove(&data_id);
                    if let Ok(Some(group)) = self.routing_node.close_group(data_id.name()) {
                        if group.contains(&idle_holder) {
                            let now = Instant::now();
                            let _ = self.ongoing_gets.insert(idle_holder, (now, data_id));
                            let _ = outstanding_data_ids.insert(data_id);
                            let src = Authority::ManagedNode(try!(self.routing_node.name()));
                            let dst = Authority::ManagedNode(idle_holder);
                            let msg_id = MessageId::new();
                            let _ = self.routing_node.send_get_request(src, dst, data_id, msg_id);
                        }
                    }
                }
            }
        }
        let new_og_count = self.ongoing_gets.len();
        let new_dhi_count = self.data_holders.values().map(HashSet::len).fold(0, Add::add);
        if new_og_count != self.ongoing_gets_count ||
           new_dhi_count != self.data_holder_items_count {
            self.ongoing_gets_count = new_og_count;
            self.data_holder_items_count = new_dhi_count;
            info!("Stats - Expecting {} Get responses. {} entries in data_holders.",
                  new_og_count,
                  new_dhi_count);
        }
        // TODO: Check whether we can do without a return value.
        Ok(())
    }

    fn close_to_address(&self, address: &XorName) -> bool {
        match self.routing_node.close_group(*address) {
            Ok(Some(_)) => true,
            _ => false,
        }
    }

    pub fn handle_node_added(&mut self,
                             node_name: &XorName,
                             routing_table: &RoutingTable<NodeInfo>) {
        self.prune_ongoing_gets(routing_table);
        // Only retain data for which we're still in the close group.
        let data_ids = self.chunk_store.keys();
        let mut data_list = Vec::new();
        for data_id in data_ids {
            match routing_table.other_close_nodes(&data_id.name()) {
                None => {
                    match data_id {
                        DataIdentifier::Immutable(_) => self.immutable_data_count -= 1,
                        DataIdentifier::Structured(_, _) => self.structured_data_count -= 1,
                        _ => unreachable!(),
                    }
                    trace!("No longer a DM for {:?}", data_id);
                    let _ = self.chunk_store.delete(&data_id);
                }
                Some(close_group) => {
                    if !close_group.into_iter().any(|node_info| node_info.name() == node_name) {
                        continue;
                    }
                    match data_id {
                        DataIdentifier::Immutable(_) => data_list.push((data_id, 0)),
                        DataIdentifier::Structured(_, _) => {
                            if let Ok(Data::Structured(data)) = self.chunk_store.get(&data_id) {
                                data_list.push((data_id, data.get_version()));
                            } else {
                                error!("Failed to get {:?} from chunk store.", data_id);
                            };
                        }
                        _ => unreachable!(),
                    }
                }
            }
        }
        if !data_list.is_empty() {
            let _ = self.send_refresh(Authority::ManagedNode(*node_name), data_list);
        }
        info!("{:?}", self);
    }

    /// Get all names and hashes of all data. // [TODO]: Can be optimised - 2016-04-23 09:11pm
    /// Send o all members of group of data
    pub fn handle_node_lost(&mut self,
                            node_name: &XorName,
                            routing_table: &RoutingTable<NodeInfo>) {
        self.prune_ongoing_gets(routing_table);
        let data_ids = self.chunk_store.keys();
        let mut data_lists: HashMap<XorName, Vec<IdAndVersion>> = HashMap::new();
        for data_id in data_ids {
            match routing_table.other_close_nodes(&data_id.name()) {
                None => {
                    error!("Moved out of close group of {:?} in a NodeLost event!",
                           node_name);
                    continue;
                }
                Some(close_group) => {
                    // If no new node joined the group due to this event, continue:
                    // If the group has fewer than GROUP_SIZE elements, the lost node was not
                    // replaced at all. Otherwise, if the group's last node is closer to the data
                    // than the lost node, the lost node was not in the group in the first place.
                    let outer_node = if let Some(node) = close_group.get(GROUP_SIZE - 2) {
                        *node.name()
                    } else {
                        continue;
                    };
                    if !xor_name::closer_to_target(node_name, &outer_node, &data_id.name()) {
                        continue;
                    }
                    data_lists.entry(outer_node).or_insert_with(Vec::new).push(match data_id {
                        DataIdentifier::Immutable(_) => (data_id, 0),
                        DataIdentifier::Structured(_, _) => {
                            if let Ok(Data::Structured(data)) = self.chunk_store.get(&data_id) {
                                (data_id, data.get_version())
                            } else {
                                error!("Failed to get {:?} from chunk store.", data_id);
                                continue;
                            }
                        }
                        _ => unreachable!(),
                    });
                }
            }
        }
        for (node_name, data_list) in data_lists {
            let _ = self.send_refresh(Authority::ManagedNode(node_name), data_list);
        }
    }

    pub fn check_timeouts(&mut self) {
        let _ = self.send_gets_for_needed_data();
    }

    #[cfg(any(test, feature = "use-mock-crust"))]
    pub fn get_stored_names(&self) -> Vec<DataIdentifier> {
        self.chunk_store.keys()
    }

    /// Remove entries from `ongoing_gets` that are no longer responsible for the data or that
    /// disconnected.
    fn prune_ongoing_gets(&mut self, routing_table: &RoutingTable<NodeInfo>) {
        let lost_gets = self.ongoing_gets
                            .iter()
                            .filter(|&(ref holder, &(_, ref data_id))| {
                                routing_table.other_close_nodes(&data_id.name())
                                             .map_or(true, |group| {
                                                 !group.iter()
                                                       .map(NodeInfo::name)
                                                       .any(|name| name == *holder)
                                             })
                            })
                            .map(|(holder, _)| *holder)
                            .collect_vec();
        if !lost_gets.is_empty() {
            for holder in lost_gets {
                let _ = self.ongoing_gets.remove(&holder);
            }
            let _ = self.send_gets_for_needed_data();
        }
    }

    fn send_refresh(&self,
                    dst: Authority,
                    data_list: Vec<IdAndVersion>)
                    -> Result<(), InternalError> {
        let src = Authority::ManagedNode(try!(self.routing_node.name()));
        // FIXME - We need to handle >2MB chunks
        match serialisation::serialise(&data_list) {
            Ok(serialised_list) => {
                trace!("DM sending refresh to {:?}.", dst);
                let _ = self.routing_node
                            .send_refresh_request(src, dst, serialised_list, MessageId::new());
                Ok(())
            }
            Err(error) => {
                warn!("Failed to serialise account: {:?}", error);
                Err(From::from(error))
            }
        }
    }
}
