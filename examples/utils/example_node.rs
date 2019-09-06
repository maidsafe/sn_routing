// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use lru_time_cache::LruCache;
// use maidsafe_utilities::serialisation::{deserialise, serialise};
use routing::{
    Authority, Event, EventStream, MessageId, Node,
    Prefix, Request, Response, XorName,
};
use std::collections::HashMap;
use std::fs::File;
use std::time::Duration;

/// A simple example node implementation for a network based on the Routing library.
pub struct ExampleNode {
    /// The node interface to the Routing library.
    node: Node,
    data_store: HashMap<XorName, Vec<u8>>,
    request_cache: LruCache<MessageId, (Authority<XorName>, Authority<XorName>)>,
    file: Option<File>,
}

impl ExampleNode {
    /// Creates a new node and attempts to establish a connection to the network.
    pub fn new(first: bool) -> ExampleNode {
        let node = unwrap!(Node::builder().first(first).create());

        ExampleNode {
            node,
            data_store: HashMap::new(),
            request_cache: LruCache::with_expiry_duration(Duration::from_secs(60 * 10)),
            file: None,
        }
    }

    /// Runs the event loop, handling events raised by the Routing library.
    pub fn run(&mut self) {
        while let Ok(event) = self.node.next_ev() {
            match event {
                Event::RequestReceived { request, src, dst } => {
                    self.handle_request(request, src, dst)
                }
                Event::ResponseReceived { response, src, dst } => {
                    self.handle_response(response, src, dst)
                }
                Event::NodeAdded(name) => {
                    trace!(
                        "{} Received NodeAdded event {:?}",
                        self.get_debug_name(),
                        name
                    );
                    self.handle_node_added(name);
                }
                Event::NodeLost(name) => {
                    trace!(
                        "{} Received NodeLost event {:?}",
                        self.get_debug_name(),
                        name
                    );
                }
                Event::Connected => {
                    trace!("{} Received connected event", self.get_debug_name());
                    println!("{} Received connected event", self.get_debug_name());
                    self.file = Some(
                        File::create(format!("{:?}", self.node.id().unwrap().name()))
                            .expect("Could not create file"),
                    );
                }
                Event::Terminated => {
                    info!("{} Received Terminated event", self.get_debug_name());
                    break;
                }
                Event::RestartRequired => {
                    info!("{} Received RestartRequired event", self.get_debug_name());
                    self.node = unwrap!(Node::builder().create());
                }
                Event::SectionSplit(prefix) => {
                    trace!(
                        "{} Received SectionSplit event {:?}",
                        self.get_debug_name(),
                        prefix
                    );
                    self.handle_split(prefix);
                }
                event => {
                    trace!("{} Received {:?} event", self.get_debug_name(), event);
                }
            }
        }
    }

    fn handle_request(
        &mut self,
        request: Request,
        src: Authority<XorName>,
        dst: Authority<XorName>,
    ) {
        match request {
            Request::Refresh(payload, msg_id) => self.handle_refresh(&payload, msg_id),

            _ => {
                warn!(
                    "{:?} ExampleNode: handle for {:?} unimplemented.",
                    self.get_debug_name(),
                    request
                );
            }
        }
    }

    fn handle_response(
        &mut self,
        response: Response,
        _src: Authority<XorName>,
        dst: Authority<XorName>,
    ) {
        match (response, dst) {
            (Response::PutIData { res, msg_id }, Authority::ClientManager(_)) => {
                if let Some((src, dst)) = self.request_cache.remove(&msg_id) {
                    unwrap!(self.node.send_put_idata_response(src, dst, res, msg_id));
                }
            }
                     _ => unreachable!(),
        }
    }

    fn handle_vault_request(
        &mut self,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        name: XorName,
        msg_id: MessageId,
    ) {
        match (src, dst) {
            (src @ Authority::Client { .. }, dst @ Authority::NaeManager(_)) => {
                let res = if let Some(data) = self.idata_store.get(&name) {
                    Ok(data.clone())
                } else {
                    trace!(
                        "{:?} GetIData request failed for {:?}.",
                        self.get_debug_name(),
                        name
                    );
                   Err("Error")
                };

                unwrap!(self.node.send_get_idata_response(dst, src, res, msg_id))
            }
            (src, dst) => unreachable!("Wrong Src and Dest Authority {:?} - {:?}", src, dst),
        }
    }


    fn handle_node_added(&mut self, name: XorName) {
        self.send_refresh(MessageId::from_added_node(name));
    }

    fn handle_split(&mut self, prefix: Prefix<XorName>) {
        let deleted_clients: Vec<_> = self
            .client_accounts
            .iter()
            .filter(|&(client_name, _)| !prefix.matches(client_name))
            .map(|(client_name, _)| *client_name)
            .collect();
        for client in &deleted_clients {
            let _ = self.client_accounts.remove(client);
        }

        let deleted_data: Vec<_> = self
            .idata_store
            .iter()
            .filter(|&(name, _)| !prefix.matches(name))
            .map(|(name, _)| *name)
            .collect();
        for id in &deleted_data {
            let _ = self.idata_store.remove(id);
        }

        let deleted_data: Vec<_> = self
            .mdata_store
            .iter()
            .filter(|&(&(ref name, _), _)| !prefix.matches(name))
            .map(|(id, _)| *id)
            .collect();
        for id in &deleted_data {
            let _ = self.mdata_store.remove(id);
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
