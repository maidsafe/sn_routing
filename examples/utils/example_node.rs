// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.1.  This, along with the
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
use maidsafe_utilities::serialisation::{deserialise, serialise};
use routing::{Authority, Data, DataIdentifier, Event, MessageId, Node, Request, Response, XorName};
use std::collections::{HashMap, HashSet};
use std::mem;
use std::sync::mpsc;
use std::time::Duration;

const STORE_REDUNDANCY: usize = 4;

/// A simple example node implementation for a network based on the Routing library.
pub struct ExampleNode {
    /// The node interface to the Routing library.
    node: Node,
    /// The receiver through which the Routing library will send events.
    receiver: mpsc::Receiver<Event>,
    /// A clone of the event sender passed to the Routing library.
    sender: mpsc::Sender<Event>,
    /// A map of the data chunks this node is storing.
    db: HashMap<DataIdentifier, Data>,
    /// A map that contains for the name of each data chunk a list of nodes that are responsible
    /// for storing that chunk.
    dm_accounts: HashMap<DataIdentifier, Vec<XorName>>,
    client_accounts: HashMap<XorName, u64>,
    /// A cache that contains for each data chunk name the list of client authorities that recently
    /// asked for that data.
    client_request_cache: LruCache<DataIdentifier, Vec<(Authority, MessageId)>>,
    /// A cache that contains the data necessary to respond with a `PutSuccess` to a `Client`.
    put_request_cache: LruCache<MessageId, (Authority, Authority)>,
}

impl ExampleNode {
    /// Creates a new node and attempts to establish a connection to the network.
    pub fn new(first: bool) -> ExampleNode {
        let (sender, receiver) = mpsc::channel::<Event>();
        let node = unwrap!(Node::builder().first(first).create(sender.clone()));

        ExampleNode {
            node: node,
            receiver: receiver,
            sender: sender,
            db: HashMap::new(),
            dm_accounts: HashMap::new(),
            client_accounts: HashMap::new(),
            client_request_cache: LruCache::with_expiry_duration(Duration::from_secs(60 * 10)),
            put_request_cache: LruCache::with_expiry_duration(Duration::from_secs(60 * 10)),
        }
    }

    /// Runs the event loop, handling events raised by the Routing library.
    pub fn run(&mut self) {
        while let Ok(event) = self.receiver.recv() {
            match event {
                Event::Request { request, src, dst } => self.handle_request(request, src, dst),
                Event::Response { response, src, dst } => self.handle_response(response, src, dst),
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
                }
                Event::Terminate => {
                    info!("{} Received Terminate event", self.get_debug_name());
                    break;
                }
                Event::RestartRequired => {
                    info!("{} Received RestartRequired event", self.get_debug_name());
                    let new_node = unwrap!(Node::builder().create(self.sender.clone()));
                    let _ = mem::replace(&mut self.node, new_node);
                }
                event => {
                    trace!("{} Received {:?} event", self.get_debug_name(), event);
                }
            }
        }
    }

    fn handle_request(&mut self, request: Request, src: Authority, dst: Authority) {
        match request {
            Request::Get(data_id, id) => {
                self.handle_get_request(data_id, id, src, dst);
            }
            Request::Put(data, id) => {
                self.handle_put_request(data, id, src, dst);
            }
            Request::Post(..) => {
                warn!("{:?} ExampleNode: Post unimplemented.",
                      self.get_debug_name());
            }
            Request::Delete(..) => {
                warn!("{:?} ExampleNode: Delete unimplemented.",
                      self.get_debug_name());
            }
            Request::GetAccountInfo(..) => {
                warn!("{:?} ExampleNode: GetAccountInfo unimplemented.",
                      self.get_debug_name());
            }
            Request::Append(..) => {
                warn!("{:?} ExampleNode: Append unimplemented.",
                      self.get_debug_name());
            }
            Request::Refresh(content, id) => {
                self.handle_refresh(content, id);
            }
        }
    }

    fn handle_response(&mut self, response: Response, src: Authority, dst: Authority) {
        match (response, dst.clone()) {
            (Response::GetSuccess(data, id), Authority::NaeManager(_)) => {
                self.handle_get_success(data, id, src, dst);
            }
            (Response::GetFailure { id, data_id, .. }, Authority::NaeManager(_)) |
            (Response::PutFailure { id, data_id, .. }, Authority::NaeManager(_)) => {
                self.process_failed_dm(&data_id, src.name(), id);
            }
            (Response::PutSuccess(data_id, id), Authority::ClientManager(_name)) => {
                if let Some((src, dst)) = self.put_request_cache.remove(&id) {
                    unwrap!(self.node.send_put_success(src, dst, data_id, id));
                }
            }
            (Response::PutSuccess(data_id, id), Authority::NaeManager(_name)) => {
                trace!("Received PutSuccess for {:?} with ID {:?}", data_id, id);
            }
            _ => unreachable!(),
        }
    }

    fn process_failed_dm(&mut self, data_id: &DataIdentifier, dm_name: &XorName, id: MessageId) {
        if let Some(dms) = self.dm_accounts.get_mut(data_id) {
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
                if let Some(managed_nodes) = self.dm_accounts.get(&data_id) {
                    {
                        let requests =
                            self.client_request_cache.entry(data_id).or_insert_with(Vec::new);
                        requests.push((src, id));
                        if requests.len() > 1 {
                            trace!("Added Get request to request cache: data {:?}.", data_id);
                            return;
                        }
                    }
                    for it in managed_nodes.iter() {
                        trace!("{:?} Handle Get request for NaeManager: data {:?} from {:?}",
                               self.get_debug_name(),
                               data_id,
                               it);
                        unwrap!(self.node
                            .send_get_request(dst.clone(),
                                              Authority::ManagedNode(it.clone()),
                                              data_id,
                                              id));
                    }
                } else {
                    error!("{:?} Data {:?} not found in NaeManager. Current DM Account: {:?}",
                           self.get_debug_name(),
                           data_id,
                           self.dm_accounts);
                    let text = "Data not found".to_owned().into_bytes();
                    unwrap!(self.node.send_get_failure(dst, src, data_id, text, id));
                }
            }
            Authority::ManagedNode(_) => {
                trace!("{:?} Handle get request for ManagedNode: data {:?}",
                       self.get_debug_name(),
                       data_id);
                if let Some(data) = self.db.get(&data_id) {
                    unwrap!(self.node.send_get_success(dst, src, data.clone(), id))
                } else {
                    trace!("{:?} GetDataRequest failed for {:?}.",
                           self.get_debug_name(),
                           data_id);
                    let text = "Data not found".to_owned().into_bytes();
                    unwrap!(self.node.send_get_failure(dst, src, data_id, text, id));
                    return;
                }
            }
            _ => unreachable!("Wrong Destination Authority {:?}", dst),
        }
    }

    fn handle_put_request(&mut self, data: Data, id: MessageId, src: Authority, dst: Authority) {
        let data_id = data.identifier();
        match dst {
            Authority::NaeManager(_) => {
                let _ = self.node.send_put_success(dst.clone(), src, data_id, id);
                if self.dm_accounts.contains_key(&data_id) {
                    return; // Don't allow duplicate put.
                }
                let mut close_grp = match unwrap!(self.node.close_group(*data.name())) {
                    None => {
                        warn!("CloseGroup action returned None.");
                        return;
                    }
                    Some(close_grp) => close_grp,
                };
                close_grp.truncate(STORE_REDUNDANCY);

                for name in close_grp.iter().cloned() {
                    unwrap!(self.node
                        .send_put_request(dst.clone(),
                                          Authority::ManagedNode(name),
                                          data.clone(),
                                          id));
                }
                // We assume these messages are handled by the managed nodes.
                let _ = self.dm_accounts.insert(data_id, close_grp.clone());
                trace!("{:?} Put Request: Updating NaeManager: data {:?}, nodes {:?}",
                       self.get_debug_name(),
                       data_id,
                       close_grp);
            }
            Authority::ClientManager(_) => {
                trace!("{:?} Put Request: Updating ClientManager: key {:?}, value {:?}",
                       self.get_debug_name(),
                       data_id,
                       data);
                {
                    let src = dst.clone();
                    let dst = Authority::NaeManager(*data.name());
                    unwrap!(self.node.send_put_request(src, dst, data, id));
                }
                if self.put_request_cache.insert(id, (dst, src)).is_some() {
                    warn!("Overwrote message {:?} in put_request_cache.", id);
                }
            }
            Authority::ManagedNode(_) => {
                trace!("{:?} Storing as ManagedNode: key {:?}, value {:?}",
                       self.get_debug_name(),
                       data_id,
                       data);
                let _ = self.node.send_put_success(dst, src, data_id, id);
                let _ = self.db.insert(data_id, data);
            }
            _ => unreachable!("ExampleNode: Unexpected dst ({:?})", dst),
        }
    }

    fn handle_get_success(&mut self, data: Data, id: MessageId, src: Authority, dst: Authority) {
        let data_id = data.identifier();
        // If the request came from a client, relay the retrieved data to them.
        if let Some(requests) = self.client_request_cache.remove(&data_id) {
            trace!("{:?} Sending GetSuccess to Client for data {:?}",
                   self.get_debug_name(),
                   data_id);
            let src = dst.clone();
            for (client_auth, message_id) in requests {
                let _ = self.node
                    .send_get_success(src.clone(), client_auth, data.clone(), message_id);
            }
        }

        if self.add_dm(data_id, *src.name()) {
            trace!("Added {:?} as a DM for {:?} on GetSuccess.",
                   src.name(),
                   data_id);
        }

        // If the retrieved data is missing a copy, send a `Put` request to store one.
        if self.dm_accounts.get(&data_id).into_iter().any(|dms| dms.len() < STORE_REDUNDANCY) {
            trace!("{:?} GetSuccess received for data {:?}",
                   self.get_debug_name(),
                   data_id);
            // Find a member of our close group that doesn't already have the lost data item.
            let close_grp = match unwrap!(self.node.close_group(*data.name())) {
                None => {
                    warn!("CloseGroup action returned None.");
                    return;
                }
                Some(close_grp) => close_grp,
            };
            if let Some(node) = close_grp.into_iter().find(|close_node| {
                self.dm_accounts[&data_id].iter().all(|data_node| *data_node != *close_node)
            }) {
                let src = dst;
                let dst = Authority::ManagedNode(node);
                unwrap!(self.node.send_put_request(src.clone(), dst, data, id));

                // TODO: Currently we assume these messages are saved by managed nodes. We should
                // wait for Put success to confirm the same.
                unwrap!(self.dm_accounts.get_mut(&data_id), "").push(node);
                let account = &self.dm_accounts[&data_id];
                trace!("{:?} Replicating chunk {:?} to {:?}",
                       self.get_debug_name(),
                       data_id,
                       account);

                // Send Refresh message with updated storage locations in DataManager
                self.send_data_manager_refresh_message(&data_id, account, id);
            }
        }
    }

    /// Add the given `dm_name` to the `dm_accounts` for `data_id`, if appropriate.
    fn add_dm(&mut self, data_id: DataIdentifier, dm_name: XorName) -> bool {
        if Some(true) == self.dm_accounts.get(&data_id).map(|dms| dms.contains(&dm_name)) {
            return false; // The dm is already in our map.
        }
        if let Some(close_grp) = unwrap!(self.node.close_group(*data_id.name())) {
            if close_grp.contains(&dm_name) {
                self.dm_accounts.entry(data_id).or_insert_with(Vec::new).push(dm_name);
                return true;
            } else {
                warn!("Data holder {:?} is not close to data {:?}.",
                      dm_name,
                      data_id);
            }
        } else {
            warn!("Not close to data {:?}.", data_id);
        }
        false
    }

    // While handling churn messages, we first "action" it ourselves and then
    // send the corresponding refresh messages out to our close group.
    fn handle_node_added(&mut self, name: XorName, _routing_table: RoutingTable<XorName>) {
        // TODO: Use the given routing table instead of repeatedly querying the routing node.
        let id = MessageId::from_added_node(name);
        for (client_name, stored) in &self.client_accounts {
            // TODO: Check whether name is actually close to client_name.
            let refresh_content = RefreshContent::Client {
                client_name: *client_name,
                data: *stored,
            };

            let content = unwrap!(serialise(&refresh_content));

            unwrap!(self.node
                .send_refresh_request(Authority::ClientManager(*client_name),
                                      Authority::ClientManager(*client_name),
                                      content,
                                      id));
        }

        self.process_lost_close_node(id);
        self.send_data_manager_refresh_messages(id);
    }

    fn handle_node_lost(&mut self, name: XorName, _routing_table: RoutingTable<XorName>) {
        // TODO: Use the given routing table instead of repeatedly querying the routing node.
        let id = MessageId::from_lost_node(name);
        // TODO: Check whether name was actually close to client_name.
        for (client_name, stored) in &self.client_accounts {
            let refresh_content = RefreshContent::Client {
                client_name: *client_name,
                data: *stored,
            };

            let content = unwrap!(serialise(&refresh_content));

            unwrap!(self.node
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
        self.dm_accounts = dm_accounts.into_iter()
            .filter_map(|(data_id, mut dms)| {
                // TODO: This switches threads on every close_group() call!
                let close_grp: HashSet<_> = match unwrap!(self.node.close_group(*data_id.name())) {
                    None => {
                        // Remove entry, as we're not part of the NaeManager anymore.
                        let _ = self.db.remove(&data_id);
                        return None;
                    }
                    Some(close_grp) => close_grp.into_iter().collect(),
                };
                dms.retain(|elt| close_grp.contains(elt));
                if dms.is_empty() {
                    error!("Chunk lost - No valid nodes left to retrieve chunk {:?}",
                           data_id);
                    return None;
                }
                Some((data_id, dms))
            })
            .collect();
        for (data_id, dms) in &self.dm_accounts {
            if dms.len() < STORE_REDUNDANCY {
                trace!("Node({:?}) Recovering data {:?}",
                       unwrap!(self.node.name()),
                       data_id);
                let src = Authority::NaeManager(*data_id.name());
                // Find the remaining places where the data is stored and send a `Get` there.
                for dm in dms {
                    let dst = Authority::ManagedNode(*dm);
                    if let Err(err) = self.node.send_get_request(src.clone(), dst, *data_id, id) {
                        error!("Failed to send get request to retrieve chunk - {:?}", err);
                    }
                }
            }
        }
    }

    /// For each `data_id` we manage, send a refresh message to all the other members of the
    /// data's `NaeManager`, so that the whole group has the same information on where the copies
    /// reside.
    fn send_data_manager_refresh_messages(&self, id: MessageId) {
        for (data_id, managed_nodes) in &self.dm_accounts {
            self.send_data_manager_refresh_message(data_id, managed_nodes, id);
        }
    }

    /// Send a refresh message to all the other members of the given data's `NaeManager`, so that
    /// the whole group has the same information on where the copies reside.
    fn send_data_manager_refresh_message(&self,
                                         data_id: &DataIdentifier,
                                         managed_nodes: &[XorName],
                                         id: MessageId) {
        let refresh_content = RefreshContent::Nae {
            data_id: *data_id,
            pmid_nodes: managed_nodes.to_vec(),
        };

        let content = unwrap!(serialise(&refresh_content));
        let src = Authority::NaeManager(*data_id.name());
        unwrap!(self.node.send_refresh_request(src.clone(), src, content, id));
    }

    /// Receiving a refresh message means that a quorum has been reached: Enough other members in
    /// the group agree, so we need to update our data accordingly.
    fn handle_refresh(&mut self, content: Vec<u8>, _id: MessageId) {
        match unwrap!(deserialise(&content)) {
            RefreshContent::Client { client_name, data } => {
                trace!("{:?} handle_refresh for ClientManager. client - {:?}",
                       self.get_debug_name(),
                       client_name);
                let _ = self.client_accounts.insert(client_name, data);
            }
            RefreshContent::Nae { data_id, pmid_nodes } => {
                let old_val = self.dm_accounts.insert(data_id, pmid_nodes.clone());
                if old_val != Some(pmid_nodes.clone()) {
                    trace!("{:?} DM for {:?} refreshed from {:?} to {:?}.",
                           self.get_debug_name(),
                           data_id,
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
#[derive(RustcEncodable, RustcDecodable)]
enum RefreshContent {
    /// A message to a `ClientManager` to insert a new client.
    Client { client_name: XorName, data: u64 },
    /// A message to an `NaeManager` to add a new data chunk.
    Nae {
        data_id: DataIdentifier,
        pmid_nodes: Vec<XorName>,
    },
}
