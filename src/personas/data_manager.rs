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

use std::collections::HashMap;
use std::convert::From;
use std::fmt::{self, Debug, Formatter};
use std::ops::Add;
use std::rc::Rc;
use std::time::Duration;
use chunk_store::ChunkStore;
use error::InternalError;
use kademlia_routing_table::{ContactInfo, GROUP_SIZE, RoutingTable};
use maidsafe_utilities::serialisation;
use rand;
use routing::{Authority, Data, DataIdentifier, MessageId, RequestMessage, StructuredData};
use safe_network_common::client_errors::{MutationError, GetError};
use sodiumoxide::crypto::hash::sha512;
use timed_buffer::TimedBuffer;
use vault::{CHUNK_STORE_PREFIX, NodeInfo, RoutingNode};
use xor_name::{self, XorName};

const MAX_FULL_PERCENT: u64 = 50;

type DataList = Vec<(DataIdentifier, Option<sha512::Digest>)>;

#[derive(Clone, Debug)]
enum DataInfo {
    Immutable(u8),
    Structured(HashMap<sha512::Digest, u8>),
}

pub struct DataManager {
    chunk_store: ChunkStore<DataIdentifier, Data>,
    refresh_accumulator: TimedBuffer<DataIdentifier, DataInfo>,
    routing_node: Rc<RoutingNode>,
    immutable_data_count: u64,
    structured_data_count: u64,
}

impl Debug for DataManager {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter,
               "Data stored - ImmData {} - SD {} - total {} bytes",
               self.immutable_data_count,
               self.structured_data_count,
               self.chunk_store.used_space())
    }
}

impl DataManager {
    pub fn new(routing_node: Rc<RoutingNode>, capacity: u64) -> Result<DataManager, InternalError> {
        Ok(DataManager {
            chunk_store: try!(ChunkStore::new(CHUNK_STORE_PREFIX, capacity)),
            refresh_accumulator: TimedBuffer::new(Duration::from_secs(60)),
            routing_node: routing_node,
            immutable_data_count: 0,
            structured_data_count: 0,
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
            let data_hash = match *data {
                Data::Immutable(_) => {
                    self.immutable_data_count += 1;
                    None
                }
                Data::Structured(_) => {
                    self.structured_data_count += 1;
                    Some(sha512::hash(&try!(serialisation::serialise(data))))
                }
                _ => unreachable!(),
            };
            trace!("DM sending PutSuccess for data {:?}", data_identifier);
            trace!("{:?}", self);
            let _ = self.routing_node
                        .send_put_success(response_src,
                                          response_dst,
                                          data_identifier.clone(),
                                          *message_id);
            let data_list = vec![(data_identifier, data_hash)];
            if let Ok(Some(close_group)) = self.routing_node.close_group(data.name()) {
                for node_name in close_group {
                    let _ = self.send_refresh(&node_name, data_list.clone(), MessageId::new());
                }
            }
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
                    trace!("{:?}", self);
                    let _ = self.routing_node
                                .send_post_success(request.dst.clone(),
                                                   request.src.clone(),
                                                   data.identifier(),
                                                   *message_id);
                    let data_hash = Some(sha512::hash(&try!(serialisation::serialise(new_data))));
                    let data_list = vec![(new_data.identifier(), data_hash)];
                    if let Ok(Some(close_group)) = self.routing_node.close_group(data.name()) {
                        for node_name in close_group {
                            let _ = self.send_refresh(&node_name,
                                                      data_list.clone(),
                                                      MessageId::new());
                        }
                    }
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
    // This function is only for SD
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
                    trace!("{:?}", self);
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

    pub fn handle_get_success(&mut self,
                              data: &Data,
                              _message_id: &MessageId)
                              -> Result<(), InternalError> {
        // If we're no longer in the close group, return.
        if !self.close_to_address(&data.name()) {
            return Ok(());
        }
        // If we don't have an entry for this in the `refresh_accumulator`, return.
        let _data_info = match self.refresh_accumulator.remove(&data.identifier()) {
            Some(entry) => entry,
            None => return Ok(()),
        };
        // TODO: Check that the data's hash actually agrees with an accumulated entry.
        let mut got_new_data = true;
        match *data {
            Data::Structured(ref new_structured_data) => {
                if let Ok(Data::Structured(structured_data)) = self.chunk_store
                                                                   .get(&data.identifier()) {
                    // Make sure we don't 'update' to a lower version.
                    if structured_data.validate_self_against_successor(new_structured_data)
                                      .is_err() {
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
        trace!("{:?}", self);
        Ok(())
    }

    pub fn handle_get_failure(&mut self,
                              src: &XorName,
                              data_id: &DataIdentifier)
                              -> Result<(), InternalError> {
        // If we're no longer in the close group, return.
        if !self.close_to_address(&data_id.name()) {
            return Ok(());
        }
        self.send_single_get(data_id.clone(), MessageId::new(), Some(*src))
    }

    pub fn handle_refresh(&mut self,
                          serialised_data_list: &[u8],
                          message_id: &MessageId)
                          -> Result<(), InternalError> {
        let quorum_size = try!(self.routing_node.quorum_size());
        let data_list = try!(serialisation::deserialise::<DataList>(serialised_data_list));
        for (data_id, opt_hash) in data_list {
            if self.chunk_store.has(&data_id) {
                // TODO: If our data is outdated, send a Get request.
                continue;
            }
            // Exclude data we are not close to
            if !self.close_to_address(&data_id.name()) {
                continue;
            }
            let mut send_single = false;
            let mut send_group = false;
            let mut add_entry = false;
            let mut data_info = DataInfo::Immutable(1);
            if let Some(info) = self.refresh_accumulator.get_mut(&data_id) {
                // TODO - since we're using dynamic quorum size here, the following equality
                // checks could trigger more than once.  Should refactor to avoid this.
                match *info {
                    DataInfo::Immutable(ref mut count) => {
                        *count += 1;
                        if *count as usize == quorum_size {
                            send_single = true;
                        }
                    }
                    DataInfo::Structured(ref mut hashes_and_counts) => {
                        let hash = try!(Self::get_expected_hash(opt_hash));
                        {
                            let count = hashes_and_counts.entry(hash).or_insert(0);
                            *count += 1;
                            // If we have agreement for a single hash value, send Get to a
                            // single peer
                            if *count as usize == quorum_size {
                                send_single = true;
                            }
                        }
                        // If we have `quorum_size()` disagreeing entries, send Gets to the
                        // group
                        if hashes_and_counts.values().fold(0, Add::add) as usize == quorum_size {
                            send_group = true;
                        }
                    }
                }
            } else {
                add_entry = true;
                data_info = match data_id {
                    DataIdentifier::Immutable(_) => DataInfo::Immutable(1),
                    DataIdentifier::Structured(_, _) => {
                        let hash = try!(Self::get_expected_hash(opt_hash));
                        let mut sd_info = HashMap::new();
                        let _ = sd_info.insert(hash, 1);
                        DataInfo::Structured(sd_info)
                    }
                    _ => unreachable!(),
                };
            }
            if send_single {
                let _ = self.send_single_get(data_id.clone(), *message_id, None);
            } else if send_group {
                let _ = self.send_group_get(data_id.clone(), *message_id);
            } else if add_entry {
                let _ = self.refresh_accumulator.insert(data_id, data_info);
            }
        }
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
                    let _ = self.refresh_accumulator.remove(&data_id);
                }
                Some(close_group) => {
                    if !close_group.into_iter().any(|node_info| node_info.name() == node_name) {
                        continue;
                    }
                    match data_id {
                        DataIdentifier::Immutable(_) => data_list.push((data_id, None)),
                        DataIdentifier::Structured(_, _) => {
                            let data = if let Ok(data) = self.chunk_store.get(&data_id) {
                                data
                            } else {
                                error!("Failed to get {:?} from chunk store.", data_id);
                                continue;
                            };
                            let hash = if let Ok(serialised_data) =
                                              serialisation::serialise(&data) {
                                sha512::hash(&serialised_data)
                            } else {
                                error!("Failed to serialise {:?}.", data_id);
                                continue;
                            };
                            data_list.push((data_id, Some(hash)));
                        }
                        _ => unreachable!(),
                    }
                }
            }
        }
        if !data_list.is_empty() {
            let _ = self.send_refresh(node_name, data_list, MessageId::new());
        }
    }

    /// Get all names and hashes of all data. // [TODO]: Can be optimised - 2016-04-23 09:11pm
    /// Send o all members of group of data
    pub fn handle_node_lost(&mut self,
                            node_name: &XorName,
                            routing_table: &RoutingTable<NodeInfo>) {
        let data_ids = self.chunk_store.keys();
        let mut data_lists: HashMap<XorName, DataList> = HashMap::new();
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
                        DataIdentifier::Immutable(_) => (data_id, None),
                        DataIdentifier::Structured(_, _) => {
                            let data = if let Ok(data) = self.chunk_store.get(&data_id) {
                                data
                            } else {
                                error!("Failed to get {:?} from chunk store.", data_id);
                                continue;
                            };
                            let hash = if let Ok(serialised_data) =
                                              serialisation::serialise(&data) {
                                sha512::hash(&serialised_data)
                            } else {
                                error!("Failed to serialise {:?}.", data_id);
                                continue;
                            };
                            (data_id, Some(hash))
                        }
                        _ => unreachable!(),
                    });
                }
            }
        }
        for (node_name, data_list) in data_lists {
            let _ = self.send_refresh(&node_name, data_list, MessageId::new());
        }
    }

    pub fn check_timeouts(&mut self) {
        for data_id in self.refresh_accumulator.get_expired() {
            trace!("Timed out waiting for {:?}", data_id);
            self.refresh_accumulator.update_timestamp(&data_id);
            // TODO: should keep the original MessageId and which peer we're waiting for?
            let _ = self.send_single_get(data_id, MessageId::new(), None);
        }
    }

    #[cfg(feature = "use-mock-crust")]
    pub fn get_stored_names(&self) -> Vec<DataIdentifier> {
        self.chunk_store.keys()
    }

    fn send_refresh(&self,
                    node_name: &XorName,
                    data_list: DataList,
                    message_id: MessageId)
                    -> Result<(), InternalError> {
        let src = Authority::ManagedNode(try!(self.routing_node.name()));
        let dst = Authority::ManagedNode(*node_name);
        // FIXME - We need to handle >2MB chunks
        match serialisation::serialise(&data_list) {
            Ok(serialised_list) => {
                trace!("DM sending refresh to {}", node_name);
                let _ = self.routing_node
                            .send_refresh_request(src, dst, serialised_list, message_id);
                Ok(())
            }
            Err(error) => {
                warn!("Failed to serialise account: {:?}", error);
                Err(From::from(error))
            }
        }
    }

    // Sends Get request(s) to peer(s) close to `data_id`.  If `single` is true, sends one request
    // to a randomly-selected member of the group (excluding `exclude_peer` if `Some`), otherwise
    // sends to all group members.  When sending to all group members, this is done as multiple
    // ManagedNode (MN) to MN messages so that responses (which may all be different) can also be
    // sent as MN to MN, hence circumventing Routing's accumulation checks.
    fn send_get(&self,
                data_id: DataIdentifier,
                message_id: MessageId,
                exclude_peer: Option<XorName>,
                single: bool)
                -> Result<(), InternalError> {
        let close_group = match self.routing_node
                                    .close_group(data_id.name()) {
            Ok(Some(close_group)) => {
                if let Some(to_exclude) = exclude_peer {
                    close_group.into_iter().filter(|name| *name != to_exclude).collect()
                } else {
                    close_group
                }
            }
            Ok(None) => {
                trace!("Not a DM for {:?}", data_id);
                return Ok(());
            }
            Err(error) => {
                error!("Failed to get close group: {:?} for {:?}", error, data_id);
                return Err(From::from(error));
            }
        };
        let src = Authority::ManagedNode(try!(self.routing_node.name()));
        if single {
            let index = rand::random::<usize>() % close_group.len();
            let dst = Authority::ManagedNode(close_group[index]);
            let _ = self.routing_node
                        .send_get_request(src, dst, data_id, message_id);
        } else {
            for peer in close_group {
                let dst = Authority::ManagedNode(peer);
                let _ = self.routing_node
                            .send_get_request(src.clone(), dst, data_id.clone(), message_id);
            }
        }
        Ok(())
    }

    // See comments for `send_get()`.
    fn send_single_get(&self,
                       data_id: DataIdentifier,
                       message_id: MessageId,
                       exclude_peer: Option<XorName>)
                       -> Result<(), InternalError> {
        self.send_get(data_id, message_id, exclude_peer, true)
    }

    // See comments for `send_get()`.
    fn send_group_get(&self,
                      data_id: DataIdentifier,
                      message_id: MessageId)
                      -> Result<(), InternalError> {
        self.send_get(data_id, message_id, None, false)
    }

    fn get_expected_hash(opt_hash: Option<sha512::Digest>) -> Result<sha512::Digest, InternalError> {
        if let Some(hash) = opt_hash {
            Ok(hash)
        } else {
            warn!("Received invalid message: hash should not be `None`)");
            Err(InternalError::InvalidMessage)
        }
    }
}



#[cfg(test)]
#[cfg(not(feature="use-mock-crust"))]
mod test_sd {
    use super::*;
    use super::DataList;

    use std::rc::Rc;
    use std::sync::mpsc;

    use kademlia_routing_table::GROUP_SIZE;
    use maidsafe_utilities::{log, serialisation};
    use rand::distributions::{IndependentSample, Range};
    use rand::{random, thread_rng};
    use routing::{Authority, Data, DataIdentifier, MessageId, RequestContent, RequestMessage,
                  ResponseContent, ResponseMessage, StructuredData};
    use safe_network_common::client_errors::{GetError, MutationError};
    use sodiumoxide::crypto::hash::sha512;
    use sodiumoxide::crypto::sign::{self, PublicKey, SecretKey};
    use utils;
    use vault::RoutingNode;
    use xor_name::{self, XorName};

    pub struct Environment {
        pub routing: Rc<RoutingNode>,
        pub data_manager: DataManager,
    }

    pub struct PutEnvironment {
        pub keys: (PublicKey, SecretKey),
        pub client: Authority,
        pub client_manager: Authority,
        pub sd_data: StructuredData,
        pub message_id: MessageId,
        pub request: RequestMessage,
    }

    pub struct GetEnvironment {
        pub client: Authority,
        pub message_id: MessageId,
        pub request: RequestMessage,
    }

    pub struct PostEnvironment {
        pub keys: (PublicKey, SecretKey),
        pub client: Authority,
        pub sd_data: StructuredData,
        pub message_id: MessageId,
        pub request: RequestMessage,
    }

    pub struct DeleteEnvironment {
        pub keys: (PublicKey, SecretKey),
        pub client: Authority,
        pub sd_data: StructuredData,
        pub message_id: MessageId,
        pub request: RequestMessage,
    }

    impl Environment {
        pub fn new() -> Environment {
            let _ = log::init(true);
            let routing = unwrap_result!(RoutingNode::new(mpsc::channel().0, false));
            let routing = Rc::new(routing);

            Environment {
                routing: routing.clone(),
                data_manager: unwrap_result!(DataManager::new(routing.clone(), 322_122_546)),
            }
        }

        pub fn get_close_data(&self, keys: (PublicKey, SecretKey)) -> StructuredData {
            loop {
                let identifier = random();
                let structured_data = unwrap_result!(StructuredData::new(0,
                                                       identifier,
                                                       0,
                                                       utils::generate_random_vec_u8(1024),
                                                       vec![keys.0],
                                                       vec![],
                                                       Some(&keys.1)));
                if let Ok(Some(_)) = self.routing.close_group(structured_data.name()) {
                    return structured_data;
                }
            }
        }

        pub fn lose_close_node(&self, target: &XorName) -> XorName {
            if let Ok(Some(close_group)) = self.routing.close_group(*target) {
                let mut rng = thread_rng();
                let range = Range::new(0, close_group.len());
                let our_name = if let Ok(ref name) = self.routing.name() {
                    *name
                } else {
                    unreachable!()
                };
                loop {
                    let index = range.ind_sample(&mut rng);
                    if close_group[index] != our_name {
                        return close_group[index];
                    }
                }
            } else {
                random::<XorName>()
            }
        }

        pub fn get_close_node_to_target(&self, target: &XorName) -> XorName {
            let close_group = unwrap_option!(unwrap_result!(self.routing.close_group(*target)), "");
            loop {
                let name = random::<XorName>();
                if xor_name::closer_to_target(&name, &close_group[GROUP_SIZE - 1], target) {
                    return name;
                }
            }
        }

        pub fn put_sd_data(&mut self) -> PutEnvironment {
            let keys = sign::gen_keypair();
            let sd_data = self.get_close_data(keys.clone());
            self.put_existing_sd_data(sd_data, keys)
        }

        pub fn put_existing_sd_data(&mut self,
                                    sd_data: StructuredData,
                                    keys: (PublicKey, SecretKey))
                                    -> PutEnvironment {
            let message_id = MessageId::new();
            let content = RequestContent::Put(Data::Structured(sd_data.clone()), message_id);
            let client = Authority::Client {
                client_key: keys.0,
                peer_id: random(),
                proxy_node_name: random::<XorName>(),
            };
            let client_manager = Authority::ClientManager(utils::client_name(&client));
            let request = RequestMessage {
                src: client_manager.clone(),
                dst: Authority::NaeManager(sd_data.name()),
                content: content.clone(),
            };
            let data = Data::Structured(sd_data.clone());
            let _ = self.data_manager.handle_put(&request, &data, &message_id);
            PutEnvironment {
                keys: keys,
                client: client,
                client_manager: client_manager,
                sd_data: sd_data,
                message_id: message_id,
                request: request,
            }
        }

        pub fn get_sd_data(&mut self, sd_data: StructuredData) -> GetEnvironment {
            let message_id = MessageId::new();
            let content =
                RequestContent::Get(DataIdentifier::Structured(*sd_data.get_identifier(),
                                                               sd_data.get_type_tag()),
                                    message_id);
            let keys = sign::gen_keypair();
            let client = Authority::Client {
                client_key: keys.0,
                peer_id: random(),
                proxy_node_name: random::<XorName>(),
            };
            let request = RequestMessage {
                src: client.clone(),
                dst: Authority::NaeManager(sd_data.name()),
                content: content.clone(),
            };
            let data = Data::Structured(sd_data.clone());
            let _ = self.data_manager.handle_get(&request, &data.identifier(), &message_id);
            GetEnvironment {
                client: client,
                message_id: message_id,
                request: request,
            }
        }

        pub fn post_sd_data(&mut self) -> PostEnvironment {
            let keys = sign::gen_keypair();
            let sd_data = self.get_close_data(keys.clone());
            let client = Authority::Client {
                client_key: keys.0,
                peer_id: random(),
                proxy_node_name: random::<XorName>(),
            };
            self.post_existing_sd_data(sd_data, keys, client)
        }

        pub fn post_existing_sd_data(&mut self,
                                     sd_data: StructuredData,
                                     keys: (PublicKey, SecretKey),
                                     client: Authority)
                                     -> PostEnvironment {
            let message_id = MessageId::new();
            let content = RequestContent::Post(Data::Structured(sd_data.clone()), message_id);
            let request = RequestMessage {
                src: client.clone(),
                dst: Authority::NaeManager(sd_data.name()),
                content: content.clone(),
            };
            let _ = self.data_manager.handle_post(&request, &sd_data, &message_id);
            PostEnvironment {
                keys: keys,
                client: client,
                sd_data: sd_data,
                message_id: message_id,
                request: request,
            }
        }

        pub fn delete_sd_data(&mut self) -> DeleteEnvironment {
            let keys = sign::gen_keypair();
            let sd_data = self.get_close_data(keys.clone());
            let client = Authority::Client {
                client_key: keys.0,
                peer_id: random(),
                proxy_node_name: random::<XorName>(),
            };
            self.delete_existing_sd_data(sd_data, keys, client)
        }

        pub fn delete_existing_sd_data(&mut self,
                                       sd_data: StructuredData,
                                       keys: (PublicKey, SecretKey),
                                       client: Authority)
                                       -> DeleteEnvironment {
            let message_id = MessageId::new();
            let content = RequestContent::Delete(Data::Structured(sd_data.clone()), message_id);
            let request = RequestMessage {
                src: client.clone(),
                dst: Authority::NaeManager(sd_data.name()),
                content: content.clone(),
            };
            let _ = self.data_manager.handle_delete(&request, &sd_data, &message_id);
            DeleteEnvironment {
                keys: keys,
                client: client,
                sd_data: sd_data,
                message_id: message_id,
                request: request,
            }
        }

        pub fn get_from_chunkstore(&self,
                                   data_identifier: &DataIdentifier)
                                   -> Option<StructuredData> {
            if let Ok(data) = self.data_manager.chunk_store.get(data_identifier) {
                if let Data::Structured(sd) = data {
                    return Some(sd);
                }
            }
            None
        }
    }

    #[test]
    fn handle_put_get_normal_flow() {
        let mut env = Environment::new();
        let put_env = env.put_sd_data();
        assert_eq!(Some(put_env.sd_data.clone()),
                   env.get_from_chunkstore(&put_env.sd_data.identifier()));
        assert_eq!(0, env.routing.put_requests_given().len());
        let put_responses = env.routing.put_successes_given();
        assert_eq!(put_responses.len(), 1);
        if let ResponseContent::PutSuccess(identifier, id) = put_responses[0].content.clone() {
            assert_eq!(put_env.message_id, id);
            assert_eq!(put_env.sd_data.identifier(), identifier);
        } else {
            panic!("Received unexpected response {:?}", put_responses[0]);
        }
        assert_eq!(put_env.client_manager, put_responses[0].dst);
        assert_eq!(Authority::NaeManager(put_env.sd_data.name()),
                   put_responses[0].src);

        let get_env = env.get_sd_data(put_env.sd_data.clone());
        let get_responses = env.routing.get_successes_given();
        assert_eq!(get_responses.len(), 1);
        if let ResponseMessage { content: ResponseContent::GetSuccess(response_data, id), .. } =
               get_responses[0].clone() {
            assert_eq!(Data::Structured(put_env.sd_data.clone()), response_data);
            assert_eq!(get_env.message_id, id);
        } else {
            panic!("Received unexpected response {:?}", get_responses[0]);
        }
        assert_eq!(get_responses[0].dst, get_env.client);
    }

    #[test]
    fn handle_put_get_error_flow() {
        // This shows a non-owner can still store the sd_data
        let mut env = Environment::new();
        let keys = sign::gen_keypair();
        let sd_data = env.get_close_data(keys.clone());
        let put_env = env.put_existing_sd_data(sd_data.clone(), keys.clone());
        assert_eq!(env.routing.put_successes_given().len(), 1);

        // Put to the same data
        let put_existing_env = env.put_existing_sd_data(put_env.sd_data.clone(),
                                                        put_env.keys.clone());
        let put_failures = env.routing.put_failures_given();

        assert_eq!(put_failures.len(), 1);
        assert_eq!(put_failures[0].dst, put_existing_env.client_manager);

        if let ResponseContent::PutFailure { ref id, ref request, ref external_error_indicator } =
               put_failures[0].content {
            assert_eq!(*id, put_existing_env.message_id);
            assert_eq!(*request, put_existing_env.request);
            let err = unwrap_result!(
                    serialisation::deserialise::<MutationError>(external_error_indicator));
            match err.clone() {
                MutationError::DataExists => {}
                _ => panic!("received unexpected erro r {:?}", err),
            }
        } else {
            unreachable!()
        }

        // Get non-existing data
        let non_existing_sd_data = env.get_close_data(keys.clone());
        let get_env = env.get_sd_data(non_existing_sd_data.clone());
        assert_eq!(env.routing.get_requests_given().len(), 0);
        assert_eq!(env.routing.get_successes_given().len(), 0);
        let get_failure = env.routing.get_failures_given();
        assert_eq!(get_failure.len(), 1);
        if let ResponseContent::GetFailure { ref external_error_indicator, ref id, .. } =
               get_failure[0].content.clone() {
            assert_eq!(get_env.message_id, *id);
            let parsed_error = unwrap_result!(serialisation::deserialise(external_error_indicator));
            if let GetError::NoSuchData = parsed_error {} else {
                panic!("Received unexpected external_error_indicator with parsed error as {:?}",
                       parsed_error);
            }
        } else {
            panic!("Received unexpected response {:?}", get_failure[0]);
        }
        assert_eq!(get_env.client, get_failure[0].dst);
        assert_eq!(Authority::NaeManager(non_existing_sd_data.name()),
                   get_failure[0].src);
    }

    #[test]
    fn handle_post() {
        let mut env = Environment::new();
        // posting to non-existent data
        let post_env = env.post_sd_data();
        assert_eq!(None,
                   env.get_from_chunkstore(&post_env.sd_data.identifier()));
        let mut post_failure = env.routing.post_failures_given();
        assert_eq!(post_failure.len(), 1);
        if let ResponseContent::PostFailure { ref external_error_indicator, ref id, .. } =
               post_failure[0].content.clone() {
            assert_eq!(post_env.message_id, *id);
            let parsed_error = unwrap_result!(serialisation::deserialise::<MutationError>(
                    &external_error_indicator[..]));
            assert_eq!(parsed_error, MutationError::InvalidSuccessor);
        } else {
            panic!("Received unexpected response {:?}", post_failure[0]);
        }
        assert_eq!(post_env.client, post_failure[0].dst);
        assert_eq!(Authority::NaeManager(post_env.sd_data.name()),
                   post_failure[0].src);

        // PUT the data
        let put_env = env.put_existing_sd_data(post_env.sd_data.clone(), post_env.keys.clone());
        assert_eq!(env.routing.put_successes_given().len(), 1);

        // incorrect version
        let mut sd_new_bad = unwrap_result!(StructuredData::new(0,
                                                                *put_env.sd_data.get_identifier(),
                                                                3,
                                                                put_env.sd_data
                                                                       .get_data()
                                                                       .clone(),
                                                                vec![put_env.keys.0],
                                                                vec![],
                                                                Some(&put_env.keys.1)));
        let post_incorrect_env = env.post_existing_sd_data(sd_new_bad.clone(),
                                                           put_env.keys.clone(),
                                                           put_env.client.clone());
        post_failure = env.routing.post_failures_given();
        assert_eq!(post_failure.len(), 2);
        if let ResponseContent::PostFailure { ref external_error_indicator, ref id, .. } =
               post_failure[1].content.clone() {
            assert_eq!(post_incorrect_env.message_id, *id);
            let parsed_error = unwrap_result!(serialisation::deserialise::<MutationError>(
                    &external_error_indicator[..]));
            assert_eq!(parsed_error, MutationError::InvalidSuccessor);
        } else {
            panic!("Received unexpected response {:?}", post_failure[1]);
        }
        assert_eq!(post_incorrect_env.client, post_failure[1].dst);
        assert_eq!(Authority::NaeManager(post_incorrect_env.sd_data.name()),
                   post_failure[1].src);
        assert_eq!(Some(put_env.sd_data.clone()),
                   env.get_from_chunkstore(&sd_new_bad.identifier()));

        // correct version
        let mut sd_new = unwrap_result!(StructuredData::new(0,
                                                            *put_env.sd_data.get_identifier(),
                                                            1,
                                                            put_env.sd_data.get_data().clone(),
                                                            vec![put_env.keys.0],
                                                            vec![],
                                                            Some(&put_env.keys.1)));
        let mut post_correct_env = env.post_existing_sd_data(sd_new.clone(),
                                                             put_env.keys.clone(),
                                                             put_env.client.clone());
        let mut post_success = env.routing.post_successes_given();
        assert_eq!(post_success.len(), 1);
        if let ResponseContent::PostSuccess(identifier, id) = post_success[0].content.clone() {
            assert_eq!(post_correct_env.message_id, id);
            assert_eq!(sd_new.identifier(), identifier);
        } else {
            panic!("Received unexpected response {:?}", post_success[0]);
        }
        assert_eq!(post_correct_env.client, post_success[0].dst);
        assert_eq!(Authority::NaeManager(post_correct_env.sd_data.name()),
                   post_success[0].src);
        assert_eq!(Some(sd_new.clone()),
                   env.get_from_chunkstore(&put_env.sd_data.identifier()));

        // update to a new owner, wrong signature
        let keys2 = sign::gen_keypair();
        sd_new_bad = unwrap_result!(StructuredData::new(0,
                                                        *put_env.sd_data.get_identifier(),
                                                        2,
                                                        put_env.sd_data.get_data().clone(),
                                                        vec![keys2.0],
                                                        vec![put_env.keys.0],
                                                        Some(&keys2.1)));
        let _ = env.post_existing_sd_data(sd_new_bad.clone(),
                                          put_env.keys.clone(),
                                          put_env.client.clone());
        post_failure = env.routing.post_failures_given();
        assert_eq!(post_failure.len(), 3);
        if let ResponseContent::PostFailure { ref external_error_indicator, .. } = post_failure[2]
                                                                                       .content
                                                                                       .clone() {
            let parsed_error = unwrap_result!(serialisation::deserialise::<MutationError>(
                    &external_error_indicator[..]));
            assert_eq!(parsed_error, MutationError::InvalidSuccessor);
        } else {
            panic!("Received unexpected response {:?}", post_failure[2]);
        }
        assert_eq!(Some(sd_new.clone()),
                   env.get_from_chunkstore(&put_env.sd_data.identifier()));

        // update to a new owner, correct signature
        sd_new = unwrap_result!(StructuredData::new(0,
                                                    *put_env.sd_data.get_identifier(),
                                                    2,
                                                    put_env.sd_data.get_data().clone(),
                                                    vec![keys2.0],
                                                    vec![put_env.keys.0],
                                                    Some(&put_env.keys.1)));
        post_correct_env = env.post_existing_sd_data(sd_new.clone(),
                                                     put_env.keys.clone(),
                                                     put_env.client.clone());
        post_success = env.routing.post_successes_given();
        assert_eq!(env.routing.post_successes_given().len(), 2);
        if let ResponseContent::PostSuccess(identifier, id) = post_success[1].content.clone() {
            assert_eq!(post_correct_env.message_id, id);
            assert_eq!(sd_new.identifier(), identifier);
        } else {
            panic!("Received unexpected response {:?}", post_success[1]);
        }
        assert_eq!(Some(sd_new.clone()),
                   env.get_from_chunkstore(&put_env.sd_data.identifier()));
    }

    #[test]
    fn handle_delete() {
        let mut env = Environment::new();
        // posting to non-existent data
        let delete_env = env.delete_sd_data();
        assert_eq!(None,
                   env.get_from_chunkstore(&delete_env.sd_data.identifier()));
        let mut delete_failure = env.routing.delete_failures_given();
        assert_eq!(delete_failure.len(), 1);
        if let ResponseContent::DeleteFailure { ref external_error_indicator, ref id, .. } =
               delete_failure[0].content.clone() {
            assert_eq!(delete_env.message_id, *id);
            let parsed_error = unwrap_result!(serialisation::deserialise::<MutationError>(
                    &external_error_indicator[..]));
            assert_eq!(parsed_error, MutationError::InvalidSuccessor);
        } else {
            panic!("Received unexpected response {:?}", delete_failure[0]);
        }
        assert_eq!(delete_env.client, delete_failure[0].dst);
        assert_eq!(Authority::NaeManager(delete_env.sd_data.name()),
                   delete_failure[0].src);

        // PUT the data
        let put_env = env.put_existing_sd_data(delete_env.sd_data.clone(), delete_env.keys.clone());
        assert_eq!(env.routing.put_successes_given().len(), 1);

        // incorrect version
        let sd_new_bad = unwrap_result!(StructuredData::new(0,
                                                            *put_env.sd_data.get_identifier(),
                                                            3,
                                                            vec![],
                                                            vec![put_env.keys.0],
                                                            vec![],
                                                            Some(&put_env.keys.1)));
        let _ = env.delete_existing_sd_data(sd_new_bad.clone(),
                                            put_env.keys.clone(),
                                            put_env.client.clone());
        delete_failure = env.routing.delete_failures_given();
        assert_eq!(delete_failure.len(), 2);
        if let ResponseContent::DeleteFailure { ref external_error_indicator, .. } =
               delete_failure[1].content.clone() {
            let parsed_error = unwrap_result!(serialisation::deserialise::<MutationError>(
                    &external_error_indicator[..]));
            assert_eq!(parsed_error, MutationError::InvalidSuccessor);
        } else {
            panic!("Received unexpected response {:?}", delete_failure[1]);
        }
        assert_eq!(Some(put_env.sd_data.clone()),
                   env.get_from_chunkstore(&sd_new_bad.identifier()));

        // correct version
        let sd_new = unwrap_result!(StructuredData::new(0,
                                                        *put_env.sd_data.get_identifier(),
                                                        1,
                                                        vec![],
                                                        vec![put_env.keys.0],
                                                        vec![],
                                                        Some(&put_env.keys.1)));
        let delete_correct_env = env.delete_existing_sd_data(sd_new.clone(),
                                                             put_env.keys.clone(),
                                                             put_env.client.clone());
        let delete_success = env.routing.delete_successes_given();
        assert_eq!(delete_success.len(), 1);
        if let ResponseContent::DeleteSuccess(identifier, id) = delete_success[0].content.clone() {
            assert_eq!(delete_correct_env.message_id, id);
            assert_eq!(sd_new.identifier(), identifier);
        } else {
            panic!("Received unexpected response {:?}", delete_success[0]);
        }
        assert_eq!(delete_correct_env.client, delete_success[0].dst);
        assert_eq!(Authority::NaeManager(delete_correct_env.sd_data.name()),
                   delete_success[0].src);
        assert_eq!(None, env.get_from_chunkstore(&put_env.sd_data.identifier()));

        // allow put after deletion
        let _ = env.put_existing_sd_data(put_env.sd_data.clone(), put_env.keys.clone());
        assert_eq!(Some(put_env.sd_data.clone()),
                   env.get_from_chunkstore(&put_env.sd_data.identifier()));
    }

    #[test]
    fn handle_churn() {
        let mut env = Environment::new();
        let put_env = env.put_sd_data();
        assert_eq!(env.routing.put_successes_given().len(), 1);
        let mut refresh_requests = env.routing.refresh_requests_given();
        assert_eq!(refresh_requests.len(), GROUP_SIZE);
        let mut close_group = unwrap_option!(
            unwrap_result!(env.routing.close_group(put_env.sd_data.name())), "");
        for i in 0..GROUP_SIZE {
            assert_eq!(refresh_requests[i].src,
                       Authority::ManagedNode(unwrap_result!(env.routing.name())));
            assert_eq!(refresh_requests[i].dst,
                       Authority::ManagedNode(close_group[i]));
        }

        let hash = if let Ok(serialised_data) =
                serialisation::serialise(&Data::Structured(put_env.sd_data.clone())) {
            sha512::hash(&serialised_data)
        } else {
            panic!("Failed to serialise {:?}.", put_env.sd_data.identifier());
        };

        // handle_node_lost
        let lost_node = env.lose_close_node(&put_env.sd_data.name());
        env.routing.node_lost_event(lost_node);
        let _ = env.data_manager.handle_node_lost(&lost_node, &env.routing.get_routing_table());

        refresh_requests = env.routing.refresh_requests_given();
        assert_eq!(refresh_requests.len(), GROUP_SIZE + 1);
        assert_eq!(refresh_requests[GROUP_SIZE].src,
                   Authority::ManagedNode(unwrap_result!(env.routing.name())));
        close_group = unwrap_option!(
            unwrap_result!(env.routing.close_group(put_env.sd_data.name())), "");
        assert_eq!(refresh_requests[GROUP_SIZE].dst,
                   Authority::ManagedNode(close_group[GROUP_SIZE - 1]));
        if let RequestContent::Refresh(received_serialised_refresh, _) =
                refresh_requests[GROUP_SIZE].content.clone() {
            let parsed_data_list = unwrap_result!(serialisation::deserialise::<DataList>(
                    &received_serialised_refresh[..]));
            assert_eq!(parsed_data_list.len(), 1);
            assert_eq!(parsed_data_list[0].0, put_env.sd_data.identifier());
            assert_eq!(parsed_data_list[0].1, Some(hash));
        } else {
            panic!("Received unexpected refresh {:?}", refresh_requests[GROUP_SIZE]);
        }

        // handle_node_added
        let node_added = env.get_close_node_to_target(&put_env.sd_data.name());
        env.routing.node_added_event(node_added.clone());
        let _ = env.data_manager.handle_node_added(&node_added, &env.routing.get_routing_table());

        refresh_requests = env.routing.refresh_requests_given();
        assert_eq!(refresh_requests.len(), GROUP_SIZE + 2);
        assert_eq!(refresh_requests[GROUP_SIZE + 1].src,
                   Authority::ManagedNode(unwrap_result!(env.routing.name())));
        assert_eq!(refresh_requests[GROUP_SIZE + 1].dst,
                   Authority::ManagedNode(node_added.clone()));
        if let RequestContent::Refresh(received_serialised_refresh, _) =
                refresh_requests[GROUP_SIZE + 1].content.clone() {
            let parsed_data_list = unwrap_result!(serialisation::deserialise::<DataList>(
                    &received_serialised_refresh[..]));
            assert_eq!(parsed_data_list.len(), 1);
            assert_eq!(parsed_data_list[0].0, put_env.sd_data.identifier());
            assert_eq!(parsed_data_list[0].1, Some(hash));
        } else {
            panic!("Received unexpected refresh {:?}", refresh_requests[GROUP_SIZE + 1]);
        }
    }

    #[test]
    fn handle_refresh() {
        let mut env = Environment::new();
        let keys = sign::gen_keypair();
        let sd_data = env.get_close_data(keys.clone());

        let hash_1 = if let Ok(serialised_data) =
                serialisation::serialise(&Data::Structured(sd_data.clone())) {
            sha512::hash(&serialised_data)
        } else {
            panic!("Failed to serialise {:?}.", sd_data.identifier());
        };
        let data_list_1 = vec![(sd_data.identifier(), Some(hash_1.clone()))];
        let serialised_data_list_1 = if let Ok(serialised_data) =
                serialisation::serialise(&data_list_1) {
            serialised_data
        } else {
            panic!("Failed to serialise {:?}.", data_list_1);
        };

        let hash_2 = if let Ok(serialised_data) = serialisation::serialise(&sd_data) {
            sha512::hash(&serialised_data)
        } else {
            panic!("Failed to serialise {:?}.", sd_data.identifier());
        };
        let data_list_2 = vec![(sd_data.identifier(), Some(hash_2.clone()))];
        let serialised_data_list_2 = if let Ok(serialised_data) =
                serialisation::serialise(&data_list_2) {
            serialised_data
        } else {
            panic!("Failed to serialise {:?}.", data_list_2);
        };

        let close_group = unwrap_option!(
            unwrap_result!(env.routing.close_group(sd_data.name())), "");

        for i in 0..10 {
            if i % 2 == 0 {
                let _ = env.data_manager.handle_refresh(&serialised_data_list_1, &MessageId::new());
            } else {
                let _ = env.data_manager.handle_refresh(&serialised_data_list_2, &MessageId::new());
            }
            if i < 4 {
                assert_eq!(env.routing.get_requests_given().len(), 0);
            }
            if i  == 4 {
                let get_requests = env.routing.get_requests_given();
                assert_eq!(get_requests.len(), GROUP_SIZE);
                for j in 0..GROUP_SIZE {
                    assert_eq!(get_requests[j].src,
                               Authority::ManagedNode(unwrap_result!(env.routing.name())));
                    assert_eq!(get_requests[j].dst,
                               Authority::ManagedNode(close_group[j]));
                    if let RequestContent::Get(ref data_identifier, _) = get_requests[j].content {
                        assert_eq!(*data_identifier, sd_data.identifier());
                    } else {
                        panic!("Received unexpected get request {:?}", get_requests[j]);
                    }
                }
            }
            if i  == 8 {
                let get_requests = env.routing.get_requests_given();
                assert_eq!(get_requests.len(), GROUP_SIZE + 1);
                assert_eq!(get_requests[GROUP_SIZE].src,
                           Authority::ManagedNode(unwrap_result!(env.routing.name())));
                assert!(close_group.contains(get_requests[GROUP_SIZE].dst.name()));
                if let RequestContent::Get(ref data_identifier, _) =
                        get_requests[GROUP_SIZE].content {
                    assert_eq!(*data_identifier, sd_data.identifier());
                } else {
                    panic!("Received unexpected get request {:?}", get_requests[GROUP_SIZE]);
                }
            }
            if i  == 9 {
                let get_requests = env.routing.get_requests_given();
                assert_eq!(get_requests.len(), GROUP_SIZE + 2);
                assert_eq!(get_requests[GROUP_SIZE + 1].src,
                           Authority::ManagedNode(unwrap_result!(env.routing.name())));
                assert!(close_group.contains(get_requests[GROUP_SIZE + 1].dst.name()));
                if let RequestContent::Get(ref data_identifier, _) =
                        get_requests[GROUP_SIZE + 1].content {
                    assert_eq!(*data_identifier, sd_data.identifier());
                } else {
                    panic!("Received unexpected get request {:?}", get_requests[GROUP_SIZE + 1]);
                }
            }
        }
    }
}


#[cfg(test)]
#[cfg_attr(feature="clippy", allow(indexing_slicing))]
#[cfg(not(feature="use-mock-crust"))]
mod test_im {
    use super::*;
    use super::DataList;

    use std::rc::Rc;
    use std::sync::mpsc;

    use kademlia_routing_table::GROUP_SIZE;
    use maidsafe_utilities::{log, serialisation};
    use rand::distributions::{IndependentSample, Range};
    use rand::{random, thread_rng};
    use routing::{Authority, Data, DataIdentifier, ImmutableData, MessageId, RequestContent,
                  RequestMessage, ResponseContent, ResponseMessage};
    use safe_network_common::client_errors::GetError;
    use sodiumoxide::crypto::sign;
    use utils::generate_random_vec_u8;
    use vault::RoutingNode;
    use xor_name::{self, XorName};

    struct PutEnvironment {
        pub client_manager: Authority,
        pub im_data: ImmutableData,
        pub message_id: MessageId,
        pub incoming_request: RequestMessage,
    }

    struct GetEnvironment {
        pub client: Authority,
        pub message_id: MessageId,
        pub request: RequestMessage,
    }

    struct Environment {
        pub routing: Rc<RoutingNode>,
        pub data_manager: DataManager,
    }

    impl Environment {
        pub fn new() -> Environment {
            let _ = log::init(false);
            let routing = unwrap_result!(RoutingNode::new(mpsc::channel().0, false));
            let routing = Rc::new(routing);

            Environment {
                routing: routing.clone(),
                data_manager: unwrap_result!(DataManager::new(routing.clone(), 322_122_546)),
            }
        }

        pub fn get_close_data(&self) -> ImmutableData {
            loop {
                let im_data = ImmutableData::new(generate_random_vec_u8(1024));
                if let Ok(Some(_)) = self.routing.close_group(im_data.name()) {
                    return im_data;
                }
            }
        }

        pub fn get_close_node_to_target(&self, target: &XorName) -> XorName {
            let close_group = unwrap_option!(unwrap_result!(self.routing.close_group(*target)), "");
            loop {
                let name = random::<XorName>();
                if xor_name::closer_to_target(&name, &close_group[GROUP_SIZE - 1], target) {
                    return name;
                }
            }
        }

        fn lose_close_node(&self, target: &XorName) -> XorName {
            if let Ok(Some(close_group)) = self.routing.close_group(*target) {
                let mut rng = thread_rng();
                let range = Range::new(0, close_group.len());
                let our_name = if let Ok(ref name) = self.routing.name() {
                    *name
                } else {
                    unreachable!()
                };
                loop {
                    let index = range.ind_sample(&mut rng);
                    if close_group[index] != our_name {
                        return close_group[index];
                    }
                }
            } else {
                random::<XorName>()
            }
        }

        pub fn put_im_data(&mut self) -> PutEnvironment {
            let im_data = self.get_close_data();
            let message_id = MessageId::new();
            let content = RequestContent::Put(Data::Immutable(im_data.clone()), message_id);
            let client_manager = Authority::ClientManager(random());
            let client_request = RequestMessage {
                src: client_manager.clone(),
                dst: Authority::NaeManager(im_data.name()),
                content: content.clone(),
            };
            let data = Data::Immutable(im_data.clone());
            unwrap_result!(self.data_manager
                               .handle_put(&client_request, &data, &message_id));

            PutEnvironment {
                client_manager: client_manager,
                im_data: im_data,
                message_id: message_id,
                incoming_request: client_request,
            }
        }

        pub fn get_im_data(&mut self, data_identifier: DataIdentifier) -> GetEnvironment {
            let message_id = MessageId::new();
            let content = RequestContent::Get(data_identifier.clone(), message_id);
            let keys = sign::gen_keypair();
            let from = random();
            let client = Authority::Client {
                client_key: keys.0,
                peer_id: random(),
                proxy_node_name: from,
            };
            let request = RequestMessage {
                src: client.clone(),
                dst: Authority::NaeManager(data_identifier.name()),
                content: content.clone(),
            };

            let _ = self.data_manager
                        .handle_get(&request, &data_identifier, &message_id);
            GetEnvironment {
                client: client,
                message_id: message_id,
                request: request,
            }
        }

        pub fn get_from_chunkstore(&self,
                                   data_identifier: &DataIdentifier)
                                   -> Option<ImmutableData> {
            if let Ok(data) = self.data_manager.chunk_store.get(data_identifier) {
                if let Data::Immutable(im_data) = data {
                    return Some(im_data);
                }
            }
            None
        }
    }

    #[test]
    fn handle_put() {
        let mut env = Environment::new();
        let put_env = env.put_im_data();

        assert_eq!(Some(put_env.im_data.clone()),
                   env.get_from_chunkstore(&put_env.im_data.identifier()));

        let put_successes = env.routing.put_successes_given();
        assert_eq!(put_successes.len(), 1);
        if let ResponseContent::PutSuccess(identifier, id) = put_successes[0].content.clone() {
            assert_eq!(put_env.message_id, id);
            assert_eq!(put_env.im_data.identifier(), identifier);
        } else {
            panic!("Received unexpected response {:?}", put_successes[0]);
        }
        assert_eq!(put_env.client_manager, put_successes[0].dst);
        assert_eq!(Authority::NaeManager(put_env.im_data.name()),
                   put_successes[0].src);
    }

    #[test]
    fn get_non_existing_data() {
        let mut env = Environment::new();
        let im_data = env.get_close_data();
        let get_env = env.get_im_data(im_data.identifier());
        assert!(env.routing.get_requests_given().is_empty());
        assert!(env.routing.get_successes_given().is_empty());
        let get_failure = env.routing.get_failures_given();
        assert_eq!(get_failure.len(), 1);
        if let ResponseContent::GetFailure { ref external_error_indicator, ref id, .. } =
               get_failure[0].content.clone() {
            assert_eq!(get_env.message_id, *id);
            let parsed_error = unwrap_result!(serialisation::deserialise(external_error_indicator));
            if let GetError::NoSuchData = parsed_error {} else {
                panic!("Received unexpected external_error_indicator with parsed error as {:?}",
                       parsed_error);
            }
        } else {
            panic!("Received unexpected response {:?}", get_failure[0]);
        }
        assert_eq!(get_env.client, get_failure[0].dst);
        assert_eq!(Authority::NaeManager(im_data.name()), get_failure[0].src);
    }

    #[test]
    fn get_existing_data() {
        let mut env = Environment::new();
        let put_env = env.put_im_data();

        let get_env = env.get_im_data(put_env.im_data.identifier());
        let get_responses = env.routing.get_successes_given();
        assert_eq!(get_responses.len(), 1);
        if let ResponseMessage { content: ResponseContent::GetSuccess(response_data, id), .. } =
               get_responses[0].clone() {
            assert_eq!(Data::Immutable(put_env.im_data.clone()), response_data);
            assert_eq!(get_env.message_id, id);
        } else {
            panic!("Received unexpected response {:?}", get_responses[0]);
        }
        assert_eq!(get_responses[0].dst, get_env.client);
    }

    #[test]
    fn handle_churn() {
        let mut env = Environment::new();
        let put_env = env.put_im_data();
        assert_eq!(env.routing.put_successes_given().len(), 1);
        let mut refresh_requests = env.routing.refresh_requests_given();
        assert_eq!(refresh_requests.len(), GROUP_SIZE);
        let mut close_group = unwrap_option!(
            unwrap_result!(env.routing.close_group(put_env.im_data.name())), "");
        for i in 0..GROUP_SIZE {
            assert_eq!(refresh_requests[i].src,
                       Authority::ManagedNode(unwrap_result!(env.routing.name())));
            assert_eq!(refresh_requests[i].dst,
                       Authority::ManagedNode(close_group[i]));
        }

        // handle_node_lost
        let lost_node = env.lose_close_node(&put_env.im_data.name());
        env.routing.node_lost_event(lost_node);
        let _ = env.data_manager.handle_node_lost(&lost_node, &env.routing.get_routing_table());

        refresh_requests = env.routing.refresh_requests_given();
        assert_eq!(refresh_requests.len(), GROUP_SIZE + 1);
        assert_eq!(refresh_requests[GROUP_SIZE].src,
                   Authority::ManagedNode(unwrap_result!(env.routing.name())));
        close_group = unwrap_option!(
            unwrap_result!(env.routing.close_group(put_env.im_data.name())), "");
        assert_eq!(refresh_requests[GROUP_SIZE].dst,
                   Authority::ManagedNode(close_group[GROUP_SIZE - 1]));
        if let RequestContent::Refresh(received_serialised_refresh, _) =
                refresh_requests[GROUP_SIZE].content.clone() {
            let parsed_data_list = unwrap_result!(serialisation::deserialise::<DataList>(
                    &received_serialised_refresh[..]));
            assert_eq!(parsed_data_list.len(), 1);
            assert_eq!(parsed_data_list[0].0, put_env.im_data.identifier());
            assert_eq!(parsed_data_list[0].1, None);
        } else {
            panic!("Received unexpected refresh {:?}", refresh_requests[GROUP_SIZE]);
        }

        // handle_node_added
        let node_added = env.get_close_node_to_target(&put_env.im_data.name());
        env.routing.node_added_event(node_added.clone());
        let _ = env.data_manager.handle_node_added(&node_added, &env.routing.get_routing_table());

        refresh_requests = env.routing.refresh_requests_given();
        assert_eq!(refresh_requests.len(), GROUP_SIZE + 2);
        assert_eq!(refresh_requests[GROUP_SIZE + 1].src,
                   Authority::ManagedNode(unwrap_result!(env.routing.name())));
        assert_eq!(refresh_requests[GROUP_SIZE + 1].dst,
                   Authority::ManagedNode(node_added.clone()));
        if let RequestContent::Refresh(received_serialised_refresh, _) =
                refresh_requests[GROUP_SIZE + 1].content.clone() {
            let parsed_data_list = unwrap_result!(serialisation::deserialise::<DataList>(
                    &received_serialised_refresh[..]));
            assert_eq!(parsed_data_list.len(), 1);
            assert_eq!(parsed_data_list[0].0, put_env.im_data.identifier());
            assert_eq!(parsed_data_list[0].1, None);
        } else {
            panic!("Received unexpected refresh {:?}", refresh_requests[GROUP_SIZE + 1]);
        }
    }

    #[test]
    fn handle_refresh() {
        let mut env = Environment::new();
        let im_data = env.get_close_data();
        let data_list : DataList = vec![(im_data.identifier(), None)];
        let serialised_data_list = if let Ok(serialised_data) =
                serialisation::serialise(&data_list) {
            serialised_data
        } else {
            panic!("Failed to serialise {:?}.", data_list);
        };
        let close_group = unwrap_option!(
            unwrap_result!(env.routing.close_group(im_data.name())), "");

        for i in 0..GROUP_SIZE {
            let _ = env.data_manager.handle_refresh(&serialised_data_list, &MessageId::new());
            if i < 4 {
                assert_eq!(env.routing.get_requests_given().len(), 0);
            }
            if i  == 4 {
                let get_requests = env.routing.get_requests_given();
                assert_eq!(get_requests.len(), 1);
                assert_eq!(get_requests[0].src,
                           Authority::ManagedNode(unwrap_result!(env.routing.name())));
                assert!(close_group.contains(get_requests[0].dst.name()));
                if let RequestContent::Get(ref data_identifier, _) = get_requests[0].content {
                    assert_eq!(*data_identifier, im_data.identifier());
                } else {
                    panic!("Received unexpected get request {:?}", get_requests[0]);
                }
            }
            if i > 4 {
                assert_eq!(env.routing.get_requests_given().len(), 1);
            }
        }
    }

}
