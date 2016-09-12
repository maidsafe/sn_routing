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
use maidsafe_utilities::serialisation::{deserialise, serialise};
use routing::{Authority, Data, DataIdentifier, Event, MessageId, Node, Request, Response, XorName};
use std::collections::HashMap;
use std::sync::mpsc;
use std::time::Duration;

/// A simple example node implementation for a network based on the Routing library.
pub struct ExampleNode {
    /// The node interface to the Routing library.
    node: Node,
    /// The receiver through which the Routing library will send events.
    receiver: mpsc::Receiver<Event>,
    /// A clone of the event sender passed to the Routing library.
    sender: mpsc::Sender<Event>,
    /// A map of the data chunks this node is storing.
    db: HashMap<XorName, Data>,
    client_accounts: HashMap<XorName, u64>,
    /// A cache that contains the data necessary to respond with a `PutSuccess` to a `Client`.
    put_request_cache: LruCache<MessageId, (Authority, Authority)>,
}

impl ExampleNode {
    /// Creates a new node and attempts to establish a connection to the network.
    pub fn new(first: bool) -> ExampleNode {
        let (sender, receiver) = mpsc::channel::<Event>();
        let node = unwrap_result!(Node::builder().first(first).create(sender.clone()));

        ExampleNode {
            node: node,
            receiver: receiver,
            sender: sender,
            db: HashMap::new(),
            client_accounts: HashMap::new(),
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
                    self.node = unwrap_result!(Node::builder().create(self.sender.clone()));
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
            Request::Refresh(content, id) => {
                self.handle_refresh(content, id);
            }
        }
    }

    fn handle_response(&mut self, response: Response, _src: Authority, dst: Authority) {
        match (response, dst.clone()) {
            (Response::PutSuccess(data_id, id), Authority::ClientManager(_name)) => {
                if let Some((src, dst)) = self.put_request_cache.remove(&id) {
                    unwrap_result!(self.node.send_put_success(src, dst, data_id, id));
                }
            }
            _ => unreachable!(),
        }
    }

    fn handle_get_request(&mut self,
                          data_id: DataIdentifier,
                          id: MessageId,
                          src: Authority,
                          dst: Authority) {
        match (src, dst) {
            (src @ Authority::Client { .. }, dst @ Authority::NaeManager(_)) => {
                if let Some(data) = self.db.get(data_id.name()) {
                    unwrap_result!(self.node.send_get_success(dst, src, data.clone(), id))
                } else {
                    trace!("{:?} GetDataRequest failed for {:?}.",
                           self.get_debug_name(),
                           data_id.name());
                    let text = "Data not found".to_owned().into_bytes();
                    unwrap_result!(self.node.send_get_failure(dst, src, data_id, text, id));
                    return;
                }
            }
            (src, dst) => unreachable!("Wrong Src and Dest Authority {:?} - {:?}", src, dst),
        }
    }

    fn handle_put_request(&mut self, data: Data, id: MessageId, src: Authority, dst: Authority) {
        match dst {
            Authority::NaeManager(_) => {
                trace!("{:?} Storing : key {:?}, value {:?}",
                       self.get_debug_name(),
                       data.name(),
                       data);
                let _ = self.node
                    .send_put_success(dst, src, DataIdentifier::Plain(*data.name()), id);
                let _ = self.db.insert(*data.name(), data);
            }
            Authority::ClientManager(_) => {
                trace!("{:?} Put Request: Updating ClientManager: key {:?}, value {:?}",
                       self.get_debug_name(),
                       data.name(),
                       data);
                {
                    let src = dst.clone();
                    let dst = Authority::NaeManager(*data.name());
                    unwrap_result!(self.node.send_put_request(src, dst, data, id));
                }
                if self.put_request_cache.insert(id, (dst, src)).is_some() {
                    warn!("Overwrote message {:?} in put_request_cache.", id);
                }
            }
            _ => unreachable!("ExampleNode: Unexpected dst ({:?})", dst),
        }
    }

    // While handling churn messages, we first "action" it ourselves and then
    // send the corresponding refresh messages out to our close group.
    fn handle_node_added(&mut self, name: XorName, _routing_table: RoutingTable<XorName>) {
        // TODO: Use the given routing table instead of repeatedly querying the routing node.
        self.send_refresh(MessageId::from_added_node(name));
    }

    fn handle_node_lost(&mut self, name: XorName, _routing_table: RoutingTable<XorName>) {
        // TODO: Use the given routing table instead of repeatedly querying the routing node.
        self.send_refresh(MessageId::from_lost_node(name));

    }

    fn send_refresh(&mut self, id: MessageId) {
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
        // TODO: Check whether name was actually close to data_name.
        for (data_name, data) in &self.db {
            let refresh_content = RefreshContent::NaeManager {
                data_name: *data_name,
                data: data.clone(),
            };
            let content = unwrap_result!(serialise(&refresh_content));
            unwrap_result!(self.node
                .send_refresh_request(Authority::NaeManager(*data_name),
                                      Authority::NaeManager(*data_name),
                                      content,
                                      id));
        }
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
            RefreshContent::NaeManager { data_name, data } => {
                trace!("{:?} handle_refresh for NaeManager. data - {:?}",
                       self.get_debug_name(),
                       data_name);
                let _ = self.db.insert(data_name, data);
            }
        }
    }

    fn get_debug_name(&self) -> String {
        match self.node.name() {
            Ok(name) => format!("Node({:?})", name),
            Err(err) => {
                error!("Could not get node name - {:?}", err);
                "Node(unknown)".to_owned()
            }
        }
    }
}

/// Refresh messages.
#[derive(RustcEncodable, RustcDecodable)]
enum RefreshContent {
    /// A message to a `ClientManager` to insert a new client.
    Client { client_name: XorName, data: u64 },
    /// A message to an `NaeManager` to add a new data chunk.
    NaeManager { data_name: XorName, data: Data },
}
