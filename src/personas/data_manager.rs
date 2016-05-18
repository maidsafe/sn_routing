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

use std::collections::{HashMap, HashSet, VecDeque};
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

struct Cache {
    /// Chunks we are no longer responsible for. These can be deleted from the chunk store.
    unneeded_chunks: VecDeque<DataIdentifier>,
    /// Maps the peers to the set of data chunks that we need and we know they hold.
    data_holders: HashMap<XorName, HashSet<IdAndVersion>>,
    /// Maps the peers to the data chunks we requested from them, and the timestamp of the request.
    ongoing_gets: HashMap<XorName, (Instant, IdAndVersion)>,
    ongoing_gets_count: usize,
    data_holder_items_count: usize,
}

impl Default for Cache {
    fn default() -> Cache {
        Cache {
            unneeded_chunks: VecDeque::new(),
            data_holders: HashMap::new(),
            ongoing_gets: HashMap::new(),
            ongoing_gets_count: 0,
            data_holder_items_count: 0,
        }
    }
}

impl Cache {
    fn insert_into_ongoing_gets(&mut self, idle_holder: &XorName, data_idv: &IdAndVersion) {
        let _ = self.ongoing_gets.insert(*idle_holder, (Instant::now(), *data_idv));
    }

    fn handle_get_success(&mut self, src: &XorName, data_id: &DataIdentifier, version: &u64) {
        if let Some((timestamp, expected_idv)) = self.ongoing_gets.remove(src) {
            if &expected_idv.0 != data_id {
                let _ = self.ongoing_gets.insert(*src, (timestamp, expected_idv));
            }
        }
        for (_, data_idvs) in &mut self.data_holders {
            let _ = data_idvs.remove(&(*data_id, *version));
        }
    }

    fn handle_get_failure(&mut self, src: &XorName, data_id: &DataIdentifier) -> bool {
        if let Some((timestamp, data_idv)) = self.ongoing_gets.remove(src) {
            if data_idv.0 == *data_id {
                return true;
            } else {
                let _ = self.ongoing_gets.insert(*src, (timestamp, data_idv));
            }
        };
        false
    }

    fn register_data_with_holder(&mut self, src: &XorName, data_idv: &IdAndVersion) -> bool {
        if self.data_holders.values().any(|data_idvs| data_idvs.contains(data_idv)) {
            let _ = self.data_holders.entry(*src).or_insert_with(HashSet::new).insert(*data_idv);
            return true;
        }
        false
    }

    fn add_records(&mut self, data_idv: IdAndVersion, holders: Vec<XorName>) {
        for holder in holders {
            let _ = self.data_holders.entry(holder).or_insert_with(HashSet::new).insert(data_idv);
        }
    }

    fn is_in_unneeded(&self, data_id: &DataIdentifier) -> bool {
        self.unneeded_chunks.iter().any(|id| id == data_id)
    }

    fn add_as_unneeded(&mut self, data_id: DataIdentifier) {
        self.unneeded_chunks.push_back(data_id);
    }

    fn chain_records_in_cache(&self, records_in_store: Vec<IdAndVersion>) -> HashSet<IdAndVersion> {
        let mut records = self.data_holders
            .values()
            .flat_map(|idvs| idvs.iter().cloned())
            .chain(self.ongoing_gets.values().map(|&(_, idv)| idv))
            .chain(records_in_store)
            .collect_vec();
        for data_id in &self.unneeded_chunks {
            records.retain(|&idv| idv != (*data_id, 0));
        }
        records.iter().cloned().collect::<HashSet<_>>()
    }

    fn prune_unneeded_chunks<T: ContactInfo>(&mut self, routing_table: &RoutingTable<T>) -> u64 {
        let pruned_unneeded_chunks = self.unneeded_chunks
            .iter()
            .filter(|data_id| routing_table.is_close(&data_id.name()))
            .cloned()
            .collect_vec();
        if !pruned_unneeded_chunks.is_empty() {
            self.unneeded_chunks.retain(|data_id| !pruned_unneeded_chunks.contains(data_id));
        }
        pruned_unneeded_chunks.len() as u64
    }

    fn pop_unneeded_chunk(&mut self) -> Option<DataIdentifier> {
        self.unneeded_chunks.pop_front()
    }

    /// Remove entries from `ongoing_gets` that are no longer responsible for the data or that
    /// disconnected.
    fn prune_ongoing_gets<T: ContactInfo>(&mut self, routing_table: &RoutingTable<T>) -> bool {
        let lost_gets = self.ongoing_gets
            .iter()
            .filter(|&(ref holder, &(_, (ref data_id, _)))| {
                routing_table.other_close_nodes(&data_id.name())
                    .map_or(true, |group| {
                        !group.iter()
                            .map(T::name)
                            .any(|name| name == *holder)
                    })
            })
            .map(|(holder, _)| *holder)
            .collect_vec();
        if !lost_gets.is_empty() {
            for holder in lost_gets {
                let _ = self.ongoing_gets.remove(&holder);
            }
            return true;
        }
        false
    }

    fn needed_data(&mut self) -> Vec<(XorName, IdAndVersion)> {
        let empty_holders = self.data_holders
            .iter()
            .filter(|&(_, ref data_idvs)| data_idvs.is_empty())
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
        let mut outstanding_data_ids: HashSet<_> = self.ongoing_gets
            .values()
            .map(|&(_, (data_id, _))| data_id)
            .collect();
        let idle_holders = self.data_holders
            .keys()
            .filter(|holder| !self.ongoing_gets.contains_key(holder))
            .cloned()
            .collect_vec();
        let mut candidates = Vec::new();
        for idle_holder in idle_holders {
            if let Some(data_idvs) = self.data_holders.get_mut(&idle_holder) {
                if let Some(&data_idv) = data_idvs.iter()
                    .find(|&&(ref data_id, _)| !outstanding_data_ids.contains(data_id)) {
                    let _ = data_idvs.remove(&data_idv);
                    let (data_id, _) = data_idv;
                    let _ = outstanding_data_ids.insert(data_id);
                    candidates.push((idle_holder, data_idv));
                }
            }
        }
        candidates
    }

    fn print_stats(&mut self) {
        let new_og_count = self.ongoing_gets.len();
        let new_dhi_count = self.data_holders.values().map(HashSet::len).fold(0, Add::add);
        if new_og_count != self.ongoing_gets_count ||
           new_dhi_count != self.data_holder_items_count {
            self.ongoing_gets_count = new_og_count;
            self.data_holder_items_count = new_dhi_count;
            info!("Cache Stats - Expecting {} Get responses. {} entries in data_holders.",
                  new_og_count,
                  new_dhi_count);
        }
    }
}


pub struct DataManager {
    chunk_store: ChunkStore<DataIdentifier, Data>,
    routing_node: Rc<RoutingNode>,
    /// Accumulates refresh messages and the peers we received them from.
    refresh_accumulator: Accumulator<IdAndVersion, XorName>,
    cache: Cache,
    immutable_data_count: u64,
    structured_data_count: u64,
    client_get_requests: u64,
}

fn id_and_version_of(data: &Data) -> IdAndVersion {
    (data.identifier(),
     if let Data::Structured(ref sd) = *data {
        sd.get_version()
    } else {
        0
    })
}

impl Debug for DataManager {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter,
               "Stats : Client Get requests received {} ; Data stored - ID {} - SD {} - total {} \
                bytes",
               self.client_get_requests,
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
            cache: Default::default(),
            routing_node: routing_node,
            immutable_data_count: 0,
            structured_data_count: 0,
            client_get_requests: 0,
        })
    }

    pub fn handle_get(&mut self,
                      request: &RequestMessage,
                      data_id: &DataIdentifier,
                      message_id: &MessageId)
                      -> Result<(), InternalError> {
        if let Authority::Client { .. } = request.src {
            self.client_get_requests += 1;
            info!("{:?}", self);
        }
        if let Ok(data) = self.chunk_store.get(data_id) {
            trace!("As {:?} sending data {:?} to {:?}",
                   request.dst,
                   data,
                   request.src);
            let _ = self.routing_node
                .send_get_success(request.dst.clone(), request.src.clone(), data, *message_id);
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
        let (data_id, version) = id_and_version_of(data);
        let response_src = request.dst.clone();
        let response_dst = request.src.clone();

        if self.chunk_store.has(&data_id) {
            match data_id {
                DataIdentifier::Structured(..) => {
                    let error = MutationError::DataExists;
                    let external_error_indicator = try!(serialisation::serialise(&error));
                    trace!("DM sending PutFailure for data {:?}, it already exists.",
                           data_id);
                    let _ = self.routing_node
                        .send_put_failure(response_src,
                                          response_dst,
                                          request.clone(),
                                          external_error_indicator,
                                          *message_id);
                    return Err(From::from(error));
                }
                DataIdentifier::Immutable(..) => {
                    trace!("DM sending PutSuccess for data {:?}, it already exists.",
                           data_id);
                    let _ = self.routing_node
                        .send_put_success(response_src, response_dst, data_id, *message_id);
                    return Ok(());
                }
                _ => unimplemented!(),
            }
        }

        self.clean_chunk_store();

        if self.chunk_store_full() {
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

        if let Err(err) = self.chunk_store.put(&data_id, data) {
            trace!("DM failed to store {:?} in chunkstore: {:?}", data_id, err);
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
            self.count_added_data(&data_id);
            trace!("DM sending PutSuccess for data {:?}", data_id);
            info!("{:?}", self);
            let _ = self.routing_node
                .send_put_success(response_src, response_dst, data_id, *message_id);
            let data_list = vec![(data_id, version)];
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
        Ok(try!(self.routing_node
            .send_post_failure(request.dst.clone(),
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
            if data.validate_self_against_successor(new_data).is_ok() {
                let data_id = data.identifier();
                if let Ok(()) = self.chunk_store.delete(&data_id) {
                    self.count_removed_data(&data_id);
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
                                                   try!(serialisation::serialise(
                                                           &MutationError::InvalidSuccessor)),
                                                   *message_id));
        Ok(())
    }

    pub fn handle_get_success(&mut self, src: &XorName, data: &Data) -> Result<(), InternalError> {
        let (data_id, version) = id_and_version_of(data);
        self.cache.handle_get_success(src, &data_id, &version);
        try!(self.send_gets_for_needed_data());
        // If we're no longer in the close group, return.
        if !self.close_to_address(&data_id.name()) {
            return Ok(());
        }
        // TODO: Check that the data's hash actually agrees with an accumulated entry.
        let mut got_new_data = true;
        match data_id {
            DataIdentifier::Structured(..) => {
                if let Ok(Data::Structured(structured_data)) = self.chunk_store.get(&data_id) {
                    // Make sure we don't 'update' to a lower version.
                    if structured_data.get_version() >= version {
                        return Ok(());
                    }
                    got_new_data = false;
                }
            }
            DataIdentifier::Immutable(..) => {
                if self.chunk_store.has(&data_id) {
                    return Ok(()); // Immutable data is already there.
                }
            }
            _ => unreachable!(),
        }

        self.clean_chunk_store();
        // chunk_store::put() deletes the old data automatically.
        try!(self.chunk_store.put(&data_id, &data));
        if got_new_data {
            self.count_added_data(&data_id);
            info!("{:?}", self);
        }
        Ok(())
    }

    pub fn handle_get_failure(&mut self,
                              src: &XorName,
                              data_id: &DataIdentifier)
                              -> Result<(), InternalError> {
        if !self.cache.handle_get_failure(src, data_id) {
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
        for data_idv in data_list {
            if !self.cache.register_data_with_holder(src, &data_idv) {
                if let Some(holders) = self.refresh_accumulator.add(data_idv, *src) {
                    self.refresh_accumulator.delete(&data_idv);
                    let (ref data_id, ref version) = data_idv;
                    let data_needed = match *data_id {
                        DataIdentifier::Immutable(..) => !self.chunk_store.has(data_id),
                        DataIdentifier::Structured(..) => {
                            match self.chunk_store.get(data_id) {
                                Err(_) => true, // We don't have the data, so we need to retrieve it
                                Ok(Data::Structured(sd)) => sd.get_version() < *version,
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
                    self.cache.add_records(data_idv, holders);
                }
            }
        }
        self.send_gets_for_needed_data()
    }

    fn send_gets_for_needed_data(&mut self) -> Result<(), InternalError> {
        let src = Authority::ManagedNode(try!(self.routing_node.name()));
        let candidates = self.cache.needed_data();
        for (idle_holder, data_idv) in candidates {
            if let Ok(Some(group)) = self.routing_node.close_group(data_idv.0.name()) {
                if group.contains(&idle_holder) {
                    self.cache.insert_into_ongoing_gets(&idle_holder, &data_idv);
                    let (data_id, _) = data_idv;
                    let dst = Authority::ManagedNode(idle_holder);
                    let msg_id = MessageId::new();
                    let _ = self.routing_node.send_get_request(src.clone(), dst, data_id, msg_id);
                }
            }
        }
        self.cache.print_stats();
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
        if self.cache.prune_ongoing_gets(routing_table) {
            let _ = self.send_gets_for_needed_data();
        }
        let data_idvs = self.cache.chain_records_in_cache(self.chunk_store
            .keys()
            .into_iter()
            .filter_map(|data_id| self.to_id_and_version(data_id))
            .collect_vec());
        let mut has_pruned_data = false;
        // Only retain data for which we're still in the close group.
        let mut data_list = Vec::new();
        for (data_id, version) in data_idvs {
            match routing_table.other_close_nodes(&data_id.name()) {
                None => {
                    trace!("No longer a DM for {:?}", data_id);
                    if self.chunk_store.has(&data_id) && !self.cache.is_in_unneeded(&data_id) {
                        self.count_removed_data(&data_id);
                        has_pruned_data = true;
                        if let DataIdentifier::Structured(..) = data_id {
                            let _ = self.chunk_store.delete(&data_id);
                        } else {
                            self.cache.add_as_unneeded(data_id);
                        }
                    }
                }
                Some(close_group) => {
                    if close_group.into_iter().any(|node_info| node_info.name() == node_name) {
                        data_list.push((data_id, version));
                    }
                }
            }
        }
        if !data_list.is_empty() {
            let _ = self.send_refresh(Authority::ManagedNode(*node_name), data_list);
        }
        if has_pruned_data {
            info!("{:?}", self);
        }
    }

    /// Get all names and hashes of all data. // [TODO]: Can be optimised - 2016-04-23 09:11pm
    /// Send to all members of group of data.
    pub fn handle_node_lost(&mut self,
                            node_name: &XorName,
                            routing_table: &RoutingTable<NodeInfo>) {
        let pruned_unneeded_chunks = self.cache.prune_unneeded_chunks(routing_table);
        if pruned_unneeded_chunks != 0 {
            self.immutable_data_count += pruned_unneeded_chunks;
            info!("{:?}", self);
        }
        if self.cache.prune_ongoing_gets(routing_table) {
            let _ = self.send_gets_for_needed_data();
        }

        let data_idvs = self.cache.chain_records_in_cache(self.chunk_store
            .keys()
            .into_iter()
            .filter_map(|data_id| self.to_id_and_version(data_id))
            .collect_vec());
        let mut data_lists: HashMap<XorName, Vec<IdAndVersion>> = HashMap::new();
        for data_idv in data_idvs {
            match routing_table.other_close_nodes(&data_idv.0.name()) {
                None => {
                    error!("Moved out of close group of {:?} in a NodeLost event!",
                           node_name);
                }
                Some(close_group) => {
                    // If no new node joined the group due to this event, continue:
                    // If the group has fewer than GROUP_SIZE elements, the lost node was not
                    // replaced at all. Otherwise, if the group's last node is closer to the data
                    // than the lost node, the lost node was not in the group in the first place.
                    if let Some(node) = close_group.get(GROUP_SIZE - 2) {
                        let outer_node = *node.name();
                        if xor_name::closer_to_target(node_name, &outer_node, &data_idv.0.name()) {
                            data_lists.entry(outer_node).or_insert_with(Vec::new).push(data_idv);
                        }
                    }
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

    /// Returns the `IdAndVersion` for the given data identifier, or `None` if not stored.
    fn to_id_and_version(&self, data_id: DataIdentifier) -> Option<IdAndVersion> {
        match data_id {
            DataIdentifier::Immutable(_) => Some((data_id, 0)),
            DataIdentifier::Structured(_, _) => {
                if let Ok(Data::Structured(data)) = self.chunk_store.get(&data_id) {
                    Some((data_id, data.get_version()))
                } else {
                    error!("Failed to get {:?} from chunk store.", data_id);
                    None
                }
            }
            _ => unreachable!(),
        }
    }

    fn count_added_data(&mut self, data_id: &DataIdentifier) {
        match *data_id {
            DataIdentifier::Immutable(_) => self.immutable_data_count += 1,
            DataIdentifier::Structured(_, _) => self.structured_data_count += 1,
            _ => unreachable!(),
        }
    }

    fn count_removed_data(&mut self, data_id: &DataIdentifier) {
        match *data_id {
            DataIdentifier::Immutable(_) => self.immutable_data_count -= 1,
            DataIdentifier::Structured(_, _) => self.structured_data_count -= 1,
            _ => unreachable!(),
        }
    }

    /// Returns whether our data uses more than `MAX_FULL_PERCENT` percent of available space.
    fn chunk_store_full(&self) -> bool {
        self.chunk_store.used_space() > (self.chunk_store.max_space() / 100) * MAX_FULL_PERCENT
    }

    /// Removes data chunks we are no longer responsible for until the chunk store is not full
    /// anymore.
    fn clean_chunk_store(&mut self) {
        while self.chunk_store_full() {
            if let Some(data_id) = self.cache.pop_unneeded_chunk() {
                let _ = self.chunk_store.delete(&data_id);
            } else {
                break;
            }
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
