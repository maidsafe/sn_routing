// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use super::MIN_SECTION_SIZE;
use lru_time_cache::LruCache;
use maidsafe_utilities::serialisation::{deserialise, serialise};
use routing::{Authority, Data, DataIdentifier, Event, EventStream, MessageId, Node, Prefix,
              Request, Response, XorName};
use std::collections::HashMap;
use std::time::Duration;

/// A simple example node implementation for a network based on the Routing library.
pub struct ExampleNode {
    /// The node interface to the Routing library.
    node: Node,
    /// A map of the data chunks this node is storing.
    db: HashMap<DataIdentifier, Data>,
    client_accounts: HashMap<XorName, u64>,
    /// A cache that contains the data necessary to respond with a `PutSuccess` to a `Client`.
    put_request_cache: LruCache<MessageId, (Authority<XorName>, Authority<XorName>)>,
}

impl ExampleNode {
    /// Creates a new node and attempts to establish a connection to the network.
    pub fn new(first: bool) -> ExampleNode {
        let node = unwrap!(Node::builder().first(first).create(MIN_SECTION_SIZE));

        ExampleNode {
            node: node,
            db: HashMap::new(),
            client_accounts: HashMap::new(),
            put_request_cache: LruCache::with_expiry_duration(Duration::from_secs(60 * 10)),
        }
    }

    /// Runs the event loop, handling events raised by the Routing library.
    pub fn run(&mut self) {
        while let Ok(event) = self.node.next_ev() {
            match event {
                Event::Request { request, src, dst } => self.handle_request(request, src, dst),
                Event::Response { response, src, dst } => self.handle_response(response, src, dst),
                Event::NodeAdded(name, _routing_table) => {
                    trace!("{} Received NodeAdded event {:?}",
                           self.get_debug_name(),
                           name);
                    self.handle_node_added(name);
                }
                Event::NodeLost(name, _routing_table) => {
                    trace!("{} Received NodeLost event {:?}",
                           self.get_debug_name(),
                           name);
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
                    self.node = unwrap!(Node::builder().create(MIN_SECTION_SIZE));
                }
                Event::SectionSplit(prefix) => {
                    trace!("{} Received SectionSplit event {:?}",
                           self.get_debug_name(),
                           prefix);
                    self.handle_split(prefix);
                }
                Event::SectionMerge(prefix) => {
                    trace!("{} Received SectionMerge event {:?}",
                           self.get_debug_name(),
                           prefix);
                    let pfx = Prefix::new(prefix.bit_count() + 1, *unwrap!(self.node.id()).name());
                    self.send_refresh(MessageId::from_lost_node(pfx.lower_bound()));
                }
                event => {
                    trace!("{} Received {:?} event", self.get_debug_name(), event);
                }
            }
        }
    }

    fn handle_request(&mut self,
                      request: Request,
                      src: Authority<XorName>,
                      dst: Authority<XorName>) {
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
            Request::Append(_, _) => {
                warn!("{:?} ExampleNode: Append unimplemented.",
                      self.get_debug_name());
            }
        }
    }

    fn handle_response(&mut self,
                       response: Response,
                       _src: Authority<XorName>,
                       dst: Authority<XorName>) {
        match (response, dst) {
            (Response::PutSuccess(data_id, id), Authority::ClientManager(_name)) => {
                if let Some((src, dst)) = self.put_request_cache.remove(&id) {
                    unwrap!(self.node.send_put_success(src, dst, data_id, id));
                }
            }
            _ => unreachable!(),
        }
    }

    fn handle_get_request(&mut self,
                          data_id: DataIdentifier,
                          id: MessageId,
                          src: Authority<XorName>,
                          dst: Authority<XorName>) {
        match (src, dst) {
            (src @ Authority::Client { .. }, dst @ Authority::NaeManager(_)) => {
                if let Some(data) = self.db.get(&data_id) {
                    unwrap!(self.node.send_get_success(dst, src, data.clone(), id))
                } else {
                    trace!("{:?} GetDataRequest failed for {:?}.",
                           self.get_debug_name(),
                           data_id.name());
                    let text = "Data not found".to_owned().into_bytes();
                    unwrap!(self.node.send_get_failure(dst, src, data_id, text, id));
                    return;
                }
            }
            (src, dst) => unreachable!("Wrong Src and Dest Authority {:?} - {:?}", src, dst),
        }
    }

    fn handle_put_request(&mut self,
                          data: Data,
                          id: MessageId,
                          src: Authority<XorName>,
                          dst: Authority<XorName>) {
        match dst {
            Authority::NaeManager(_) => {
                trace!("{:?} Storing : key {:?}, value {:?}",
                       self.get_debug_name(),
                       data.name(),
                       data);
                let _ = self.node
                    .send_put_success(dst, src, data.identifier(), id);
                let _ = self.db.insert(data.identifier(), data);
            }
            Authority::ClientManager(_) => {
                trace!("{:?} Put Request: Updating ClientManager: key {:?}, value {:?}",
                       self.get_debug_name(),
                       data.name(),
                       data);
                {
                    let src = dst;
                    let dst = Authority::NaeManager(*data.name());
                    unwrap!(self.node.send_put_request(src, dst, data, id));
                }
                if self.put_request_cache.insert(id, (dst, src)).is_some() {
                    warn!("Overwrote message {:?} in put_request_cache.", id);
                }
            }
            _ => unreachable!("ExampleNode: Unexpected dst ({:?})", dst),
        }
    }

    fn handle_node_added(&mut self, name: XorName) {
        self.send_refresh(MessageId::from_added_node(name));
    }

    fn handle_split(&mut self, prefix: Prefix<XorName>) {
        let deleted_clients: Vec<_> = self.client_accounts
            .iter()
            .filter(|&(client_name, _)| !prefix.matches(client_name))
            .map(|(client_name, _)| *client_name)
            .collect();
        for client in &deleted_clients {
            let _ = self.client_accounts.remove(client);
        }

        let deleted_data: Vec<_> = self.db
            .iter()
            .filter(|&(data_id, _)| !prefix.matches(data_id.name()))
            .map(|(data_id, _)| *data_id)
            .collect();
        for data_id in &deleted_data {
            let _ = self.db.remove(data_id);
        }
    }

    fn send_refresh(&mut self, id: MessageId) {
        for (client_name, stored) in &self.client_accounts {
            let refresh_content = RefreshContent::Client {
                client_name: *client_name,
                data: *stored,
            };

            let content = unwrap!(serialise(&refresh_content));

            let auth = Authority::ClientManager(*client_name);
            unwrap!(self.node.send_refresh_request(auth, auth, content, id));
        }

        for (data_id, data) in &self.db {
            let refresh_content = RefreshContent::NaeManager {
                data_id: *data_id,
                data: data.clone(),
            };
            let content = unwrap!(serialise(&refresh_content));
            let auth = Authority::NaeManager(*data.name());
            unwrap!(self.node.send_refresh_request(auth, auth, content, id));
        }
    }

    /// Receiving a refresh message means that a quorum has been reached: Enough other members in
    /// the section agree, so we need to update our data accordingly.
    fn handle_refresh(&mut self, content: Vec<u8>, _id: MessageId) {
        match unwrap!(deserialise(&content)) {
            RefreshContent::Client { client_name, data } => {
                trace!("{:?} handle_refresh for ClientManager. client - {:?}",
                       self.get_debug_name(),
                       client_name);
                let _ = self.client_accounts.insert(client_name, data);
            }
            RefreshContent::NaeManager { data_id, data } => {
                trace!("{:?} handle_refresh for NaeManager. data - {:?}",
                       self.get_debug_name(),
                       data_id);
                let _ = self.db.insert(data_id, data);
            }
        }
    }

    fn get_debug_name(&self) -> String {
        match self.node.id() {
            Ok(id) => format!("Node({:?})", id.name()),
            Err(err) => {
                error!("Could not get node name - {:?}", err);
                "Node(unknown)".to_owned()
            }
        }
    }
}

/// Refresh messages.
#[derive(Serialize, Deserialize)]
// FIXME - See https://maidsafe.atlassian.net/browse/MAID-2026 for info on removing this exclusion.
#[cfg_attr(feature="cargo-clippy", allow(large_enum_variant))]
enum RefreshContent {
    /// A message to a `ClientManager` to insert a new client.
    Client { client_name: XorName, data: u64 },
    /// A message to an `NaeManager` to add a new data chunk.
    NaeManager { data_id: DataIdentifier, data: Data },
}
