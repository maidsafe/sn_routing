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

use kademlia_routing_table::RoutingTable;
use lru_time_cache::LruCache;
use xor_name::XorName;
use routing::{NodeInfo, RequestMessage, ResponseMessage, RequestContent, ResponseContent,
              MessageId, Authority, Node, Event, Data, DataIdentifier};
use maidsafe_utilities::serialisation::{serialise, deserialise};
use std::collections::{HashMap, HashSet};
use std::mem;
use rustc_serialize::{Encoder, Decoder};
use time;

const STORE_REDUNDANCY: usize = 4;

/// A simple example node implementation for a network based on the Routing library.
#[allow(unused)]
pub struct ExampleNode {
    /// The node interface to the Routing library.
    node: Node,
    /// The receiver through which the Routing library will send events.
    receiver: ::std::sync::mpsc::Receiver<Event>,
    /// A clone of the event sender passed to the Routing library.
    sender: ::std::sync::mpsc::Sender<Event>,
    /// A map of the data chunks this node is storing.
    db: HashMap<XorName, Data>,
    /// A map that contains for the name of each data chunk a list of nodes that are responsible
    /// for storing that chunk.
    dm_accounts: HashMap<XorName, Vec<XorName>>,
    client_accounts: HashMap<XorName, u64>,
    connected: bool,
    /// A cache that contains for each data chunk name the list of client authorities that recently
    /// asked for that data.
    client_request_cache: LruCache<XorName, Vec<(Authority, MessageId)>>,
    /// A cache that contains the data necessary to respond with a `PutSuccess` to a `Client`.
    put_request_cache: LruCache<MessageId, (Authority, Authority)>,
}

#[allow(unused)]
impl ExampleNode {
    /// Creates a new node and attempts to establish a connection to the network.
    pub fn new() -> ExampleNode {
        let (sender, receiver) = ::std::sync::mpsc::channel::<Event>();
        let node = unwrap_result!(Node::new(sender.clone(), false));

        ExampleNode {
            node: node,
            receiver: receiver,
            sender: sender,
            db: HashMap::new(),
            dm_accounts: HashMap::new(),
            client_accounts: HashMap::new(),
            connected: false,
            client_request_cache: LruCache::with_expiry_duration(time::Duration::minutes(10)),
            put_request_cache: LruCache::with_expiry_duration(time::Duration::minutes(10)),
        }
    }

    /// Runs the event loop, handling events raised by the Routing library.
    pub fn run(&mut self) {
        while let Ok(event) = self.receiver.recv() {
            match event {
                Event::Request(msg) => self.handle_request(msg),
                Event::Response(msg) => self.handle_response(msg),
                Event::NodeAdded(name, routing_table) => {
                    trace!("{} Received NodeAdded event {:?}",
                           self.get_debug_name(),
                           name);
                    self.handle_node_added(name, routing_table);
                }
                Event::NodeLost(name, routing_table) => {
                    trace!("{} Received NodeLost event {:?}",
                           self.get_debug_name(),
                           name);
                    self.handle_node_lost(name, routing_table);
                }
                Event::Connected => {
                    trace!("{} Received connected event", self.get_debug_name());
                    self.connected = true;
                }
                Event::Disconnected => {
                    trace!("{} Received disconnected event", self.get_debug_name());
                    self.connected = false;
                }
                event => {
                    trace!("{} Received {:?} event", self.get_debug_name(), event);
                }
            }
        }
    }

    /// Returns the event sender to allow external tests to send events.
    pub fn get_sender(&self) -> ::std::sync::mpsc::Sender<Event> {
        self.sender.clone()
    }

    fn handle_request(&mut self, msg: RequestMessage) {
        match msg.content {
            RequestContent::Get(data_id, id) => {
                self.handle_get_request(data_id, id, msg.src, msg.dst);
            }
            RequestContent::Put(data, id) => {
                self.handle_put_request(data, id, msg.src, msg.dst);
            }
            RequestContent::Post(..) => {
                warn!("{:?} ExampleNode: Post unimplemented.",
                      self.get_debug_name());
            }
            RequestContent::Delete(..) => {
                warn!("{:?} ExampleNode: Delete unimplemented.",
                      self.get_debug_name());
            }
            RequestContent::Refresh(content, id) => {
                self.handle_refresh(content, id);
            }
            _ => (),
        }
    }

    fn handle_response(&mut self, msg: ResponseMessage) {
        match (msg.content, msg.dst.clone()) {
            (ResponseContent::GetSuccess(data, id), Authority::NaeManager(_)) => {
                self.handle_get_success(data, id, msg.src, msg.dst);
            }
            (ResponseContent::GetFailure { id, request: RequestMessage {
                content: RequestContent::Get(data_id, _),
                ..
            }, ..},
             Authority::NaeManager(_)) => {
                self.process_failed_dm(&data_id.name(), msg.src.name(), id);
            }
            (ResponseContent::PutFailure { id, request: RequestMessage {
                content: RequestContent::Put(data, _),
                ..
            }, .. },
             Authority::NaeManager(_)) => {
                self.process_failed_dm(&data.name(), msg.src.name(), id);
            }
            (ResponseContent::PutSuccess(data_id, id), Authority::ClientManager(name)) => {
                if let Some((src, dst)) = self.put_request_cache.remove(&id) {
                    unwrap_result!(self.node.send_put_success(src, dst, data_id, id));
                }
            }
            (ResponseContent::PutSuccess(data_name, id), Authority::NaeManager(name)) => {
                trace!("Received PutSuccess for {:?} with ID {:?}", data_name, id);
            }
            _ => unreachable!(),
        }
    }

    fn process_failed_dm(&mut self, data_name: &XorName, dm_name: &XorName, id: MessageId) {
        if let Some(dms) = self.dm_accounts.get_mut(&data_name) {
            if let Some(i) = dms.iter().position(|n| n == dm_name) {
                let _ = dms.remove(i);
            } else {
                return;
            }
        } else {
            return;
        }
        self.process_lost_close_node(id);
    }

    fn handle_get_request(&mut self,
                          data_id: DataIdentifier,
                          id: MessageId,
                          src: Authority,
                          dst: Authority) {
        match dst {
            Authority::NaeManager(_) => {
                if let Some(managed_nodes) = self.dm_accounts.get(&data_id.name()) {
                    {
                        let requests = self.client_request_cache
                                           .entry(data_id.name())
                                           .or_insert_with(Vec::new);
                        requests.push((src, id));
                        if requests.len() > 1 {
                            trace!("Added Get request to request cache: data {:?}.",
                                   data_id.name());
                            return;
                        }
                    }
                    for it in managed_nodes.iter() {
                        trace!("{:?} Handle Get request for NaeManager: data {:?} from {:?}",
                               self.get_debug_name(),
                               data_id.name(),
                               it);
                        unwrap_result!(self.node
                                           .send_get_request(dst.clone(),
                                                             Authority::ManagedNode(it.clone()),
                                                             data_id,
                                                             id));
                    }
                } else {
                    error!("{:?} Data name {:?} not found in NaeManager. Current DM Account: {:?}",
                           self.get_debug_name(),
                           data_id.name(),
                           self.dm_accounts);
                    let msg = RequestMessage {
                        src: src.clone(),
                        dst: dst.clone(),
                        content: RequestContent::Get(data_id, id),
                    };
                    let text = "Data not found".to_owned().into_bytes();
                    unwrap_result!(self.node.send_get_failure(dst, src, msg, text, id));
                }
            }
            Authority::ManagedNode(_) => {
                trace!("{:?} Handle get request for ManagedNode: data {:?}",
                       self.get_debug_name(),
                       data_id.name());
                if let Some(data) = self.db.get(&data_id.name()) {
                    unwrap_result!(self.node.send_get_success(dst, src, data.clone(), id))
                } else {
                    trace!("{:?} GetDataRequest failed for {:?}.",
                           self.get_debug_name(),
                           data_id.name());
                    let msg = RequestMessage {
                        src: src.clone(),
                        dst: dst.clone(),
                        content: RequestContent::Get(data_id, id),
                    };
                    let text = "Data not found".to_owned().into_bytes();
                    unwrap_result!(self.node.send_get_failure(dst, src, msg, text, id));
                    return;
                }
            }
            _ => unreachable!("Wrong Destination Authority {:?}", dst),
        }
    }

    fn handle_put_request(&mut self, data: Data, id: MessageId, src: Authority, dst: Authority) {
        match dst {
            Authority::NaeManager(_) => {
                self.node
                    .send_put_success(dst.clone(), src, DataIdentifier::Plain(data.name()), id);
                if self.dm_accounts.contains_key(&data.name()) {
                    return; // Don't allow duplicate put.
                }
                let mut close_grp = match unwrap_result!(self.node.close_group(data.name())) {
                    None => {
                        warn!("CloseGroup action returned None.");
                        return;
                    }
                    Some(close_grp) => close_grp,
                };
                close_grp.truncate(STORE_REDUNDANCY);

                for name in close_grp.iter().cloned() {
                    unwrap_result!(self.node
                                       .send_put_request(dst.clone(),
                                                         Authority::ManagedNode(name),
                                                         data.clone(),
                                                         id));
                }
                // We assume these messages are handled by the managed nodes.
                let _ = self.dm_accounts.insert(data.name(), close_grp.clone());
                trace!("{:?} Put Request: Updating NaeManager: data {:?}, nodes {:?}",
                       self.get_debug_name(),
                       data.name(),
                       close_grp);
            }
            Authority::ClientManager(_) => {
                trace!("{:?} Put Request: Updating ClientManager: key {:?}, value {:?}",
                       self.get_debug_name(),
                       data.name(),
                       data);
                {
                    let src = dst.clone();
                    let dst = Authority::NaeManager(data.name());
                    unwrap_result!(self.node.send_put_request(src, dst, data.clone(), id));
                }
                if self.put_request_cache.insert(id, (dst, src)).is_some() {
                    warn!("Overwrote message {:?} in put_request_cache.", id);
                }
            }
            Authority::ManagedNode(_) => {
                trace!("{:?} Storing as ManagedNode: key {:?}, value {:?}",
                       self.get_debug_name(),
                       data.name(),
                       data);
                self.node.send_put_success(dst, src, DataIdentifier::Plain(data.name()), id);
                let _ = self.db.insert(data.name(), data);
            }
            _ => unreachable!("ExampleNode: Unexpected dst ({:?})", dst),
        }
    }

    fn handle_get_success(&mut self, data: Data, id: MessageId, src: Authority, dst: Authority) {
        // If the request came from a client, relay the retrieved data to them.
        if let Some(requests) = self.client_request_cache.remove(&data.name()) {
            trace!("{:?} Sending GetSuccess to Client for data {:?}",
                   self.get_debug_name(),
                   data.name());
            let src = dst.clone();
            for (client_auth, message_id) in requests {
                let _ = self.node
                            .send_get_success(src.clone(), client_auth, data.clone(), message_id);
            }
        }

        if self.add_dm(data.name(), *src.name()) {
            trace!("Added {:?} as a DM for {:?} on GetSuccess.",
                   src.name(),
                   data.name());
        }

        // If the retrieved data is missing a copy, send a `Put` request to store one.
        if self.dm_accounts.get(&data.name()).into_iter().any(|dms| dms.len() < STORE_REDUNDANCY) {
            trace!("{:?} GetSuccess received for data {:?}",
                   self.get_debug_name(),
                   data.name());
            // Find a member of our close group that doesn't already have the lost data item.
            let close_grp = match unwrap_result!(self.node.close_group(data.name())) {
                None => {
                    warn!("CloseGroup action returned None.");
                    return;
                }
                Some(close_grp) => close_grp,
            };
            if let Some(node) = close_grp.into_iter().find(|close_node| {
                self.dm_accounts[&data.name()].iter().all(|data_node| *data_node != *close_node)
            }) {
                let src = dst;
                let dst = Authority::ManagedNode(node);
                unwrap_result!(self.node
                                   .send_put_request(src.clone(), dst, data.clone(), id));

                // TODO: Currently we assume these messages are saved by managed nodes. We should
                // wait for Put success to confirm the same.
                unwrap_option!(self.dm_accounts.get_mut(&data.name()), "").push(node);
                trace!("{:?} Replicating chunk {:?} to {:?}",
                       self.get_debug_name(),
                       data.name(),
                       self.dm_accounts[&data.name()]);

                // Send Refresh message with updated storage locations in DataManager
                self.send_data_manager_refresh_message(&data.name(),
                                                       &self.dm_accounts[&data.name()],
                                                       id);
            }
        }
    }

    /// Add the given `dm_name` to the `dm_accounts` for `data_name`, if appropriate.
    fn add_dm(&mut self, data_name: XorName, dm_name: XorName) -> bool {
        if Some(true) == self.dm_accounts.get(&data_name).map(|dms| dms.contains(&dm_name)) {
            return false; // The dm is already in our map.
        }
        if let Some(close_grp) = unwrap_result!(self.node.close_group(data_name)) {
            if close_grp.contains(&dm_name) {
                self.dm_accounts.entry(data_name).or_insert_with(Vec::new).push(dm_name);
                return true;
            } else {
                warn!("Data holder {:?} is not close to data {:?}.",
                      dm_name,
                      data_name);
            }
        } else {
            warn!("Not close to data {:?}.", data_name);
        }
        false
    }

    // While handling churn messages, we first "action" it ourselves and then
    // send the corresponding refresh messages out to our close group.
    fn handle_node_added(&mut self, name: XorName, _routing_table: RoutingTable<NodeInfo>) {
        // TODO: Use the given routing table instead of repeatedly querying the routing node.
        let id = MessageId::from_added_node(name);
        for (client_name, stored) in &self.client_accounts {
            // TODO: Check whether name is actually close to client_name.
            let refresh_content = RefreshContent::Client {
                client_name: *client_name,
                data: *stored,
            };

            let content = unwrap_result!(serialise(&refresh_content));

            unwrap_result!(self.node
                               .send_refresh_request(Authority::ClientManager(*client_name),
                                                     Authority::ClientManager(*client_name),
                                                     content,
                                                     id));
        }

        self.process_lost_close_node(id);
        self.send_data_manager_refresh_messages(id);
    }

    fn handle_node_lost(&mut self, name: XorName, _routing_table: RoutingTable<NodeInfo>) {
        // TODO: Use the given routing table instead of repeatedly querying the routing node.
        let id = MessageId::from_lost_node(name);
        // TODO: Check whether name was actually close to client_name.
        for (client_name, stored) in &self.client_accounts {
            let refresh_content = RefreshContent::Client {
                client_name: *client_name,
                data: *stored,
            };

            let content = unwrap_result!(serialise(&refresh_content));

            unwrap_result!(self.node
                               .send_refresh_request(Authority::ClientManager(*client_name),
                                                     Authority::ClientManager(*client_name),
                                                     content,
                                                     id));
        }

        self.process_lost_close_node(id);
        self.send_data_manager_refresh_messages(id);
    }

    /// Sends `Get` requests to retrieve all data chunks that have lost a copy.
    fn process_lost_close_node(&mut self, id: MessageId) {
        let dm_accounts = mem::replace(&mut self.dm_accounts, HashMap::new());
        self.dm_accounts =
            dm_accounts.into_iter()
                       .filter_map(|(data_name, mut dms)| {
                           // TODO: This switches threads on every close_group() call!
                           let close_grp: HashSet<_> =
                               match unwrap_result!(self.node.close_group(data_name)) {
                                   None => {
                                       // Remove entry, as we're not part of the NaeManager anymore.
                                       let _ = self.db.remove(&data_name);
                                       return None;
                                   }
                                   Some(close_grp) => close_grp.into_iter().collect(),
                               };
                           dms.retain(|elt| close_grp.contains(elt));
                           if dms.is_empty() {
                               error!("Chunk lost - No valid nodes left to retrieve chunk {:?}",
                                      data_name);
                               return None;
                           }
                           Some((data_name, dms))
                       })
                       .collect();
        for (data_name, dms) in &self.dm_accounts {
            if dms.len() < STORE_REDUNDANCY {
                trace!("Node({:?}) Recovering data {:?}",
                       unwrap_result!(self.node.name()),
                       data_name);
                let src = Authority::NaeManager(*data_name);
                // Find the remaining places where the data is stored and send a `Get` there.
                for dm in dms {
                    if let Err(err) = self.node
                                          .send_get_request(src.clone(),
                                                            Authority::ManagedNode(*dm),
                                                            DataIdentifier::Plain(*data_name),
                                                            id) {
                        error!("Failed to send get request to retrieve chunk - {:?}", err);
                    }
                }
            }
        }
    }

    /// For each `data_name` we manage, send a refresh message to all the other members of the
    /// data's `NaeManager`, so that the whole group has the same information on where the copies
    /// reside.
    fn send_data_manager_refresh_messages(&self, id: MessageId) {
        for (data_name, managed_nodes) in &self.dm_accounts {
            self.send_data_manager_refresh_message(data_name, managed_nodes, id);
        }
    }

    /// Send a refresh message to all the other members of the given data's `NaeManager`, so that
    /// the whole group has the same information on where the copies reside.
    fn send_data_manager_refresh_message(&self,
                                         data_name: &XorName,
                                         managed_nodes: &[XorName],
                                         id: MessageId) {
        let refresh_content = RefreshContent::Nae {
            data_name: *data_name,
            pmid_nodes: managed_nodes.to_vec(),
        };

        let content = unwrap_result!(serialise(&refresh_content));
        let src = Authority::NaeManager(*data_name);
        unwrap_result!(self.node.send_refresh_request(src.clone(), src, content, id));
    }

    /// Receiving a refresh message means that a quorum has been reached: Enough other members in
    /// the group agree, so we need to update our data accordingly.
    fn handle_refresh(&mut self, content: Vec<u8>, _id: MessageId) {
        match unwrap_result!(deserialise(&content)) {
            RefreshContent::Client { client_name, data } => {
                trace!("{:?} handle_refresh for ClientManager. client - {:?}",
                       self.get_debug_name(),
                       client_name);
                let _ = self.client_accounts.insert(client_name, data);
            }
            RefreshContent::Nae { data_name, pmid_nodes } => {
                let old_val = self.dm_accounts.insert(data_name, pmid_nodes.clone());
                if old_val != Some(pmid_nodes.clone()) {
                    trace!("{:?} DM for {:?} refreshed from {:?} to {:?}.",
                           self.get_debug_name(),
                           data_name,
                           old_val.unwrap_or_else(Vec::new),
                           pmid_nodes);
                }
            }
        }
    }

    fn get_debug_name(&self) -> String {
        format!("Node({:?})",
                match self.node.name() {
                    Ok(name) => name,
                    Err(err) => {
                        error!("Could not get node name - {:?}", err);
                        panic!("Could not get node name - {:?}", err);
                    }
                })
    }
}

/// Refresh messages.
#[allow(unused)]
#[derive(RustcEncodable, RustcDecodable)]
enum RefreshContent {
    /// A message to a `ClientManager` to insert a new client.
    Client {
        client_name: XorName,
        data: u64,
    },
    /// A message to an `NaeManager` to add a new data chunk.
    Nae {
        data_name: XorName,
        pmid_nodes: Vec<XorName>,
    },
}
