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

use lru_time_cache::LruCache;
use xor_name::{XorName, closer_to_target};
use routing::{RequestMessage, ResponseMessage, RequestContent, ResponseContent, MessageId,
              Authority, Node, Event, Data, DataRequest};
use maidsafe_utilities::serialisation::{serialise, deserialise};
use std::collections::HashMap;
use rustc_serialize::{Encoder, Decoder};
use time;

#[allow(unused)]
const STORE_REDUNDANCY: usize = 2;

/// Network ExampleNode.
#[allow(unused)]
pub struct ExampleNode {
    node: Node,
    receiver: ::std::sync::mpsc::Receiver<Event>,
    sender: ::std::sync::mpsc::Sender<Event>,
    db: HashMap<XorName, Data>,
    dm_accounts: HashMap<XorName, Vec<XorName>>, // DataName vs Vec<PmidNodes>
    client_accounts: HashMap<XorName, u64>,
    connected: bool,
    client_request_cache: LruCache<XorName, Vec<Authority>>, /* DataName vs List of ClientAuth asking for data */
    lost_node_cache: LruCache<XorName, (XorName, MessageId)>, // DataName vs (LostNode, Churn MessageId)
}

#[allow(unused)]
impl ExampleNode {
    /// Construct a new node.
    pub fn new() -> ExampleNode {
        let (sender, receiver) = ::std::sync::mpsc::channel::<Event>();
        let node = unwrap_result!(Node::new(sender.clone()));

        ExampleNode {
            node: node,
            receiver: receiver,
            sender: sender,
            db: HashMap::new(),
            dm_accounts: HashMap::new(),
            client_accounts: HashMap::new(),
            connected: false,
            client_request_cache: LruCache::with_expiry_duration(time::Duration::minutes(10)),
            lost_node_cache: LruCache::with_expiry_duration(time::Duration::minutes(10)),
        }
    }

    /// Run event loop.
    pub fn run(&mut self) {
        while let Ok(event) = self.receiver.recv() {
            match event {
                Event::Request(msg) => self.handle_request(msg),
                Event::Response(msg) => self.handle_response(msg),
                Event::Churn { id, lost_close_node } => {
                    trace!("Received churn event {:?}", id);
                    self.handle_churn(id, lost_close_node)
                }
                // Event::Bootstrapped => trace!("Received bootstraped event"),
                Event::Connected => {
                    trace!("Received connected event");
                    self.connected = true;
                }
                Event::Disconnected => trace!("Received disconnected event"),
                Event::Terminated => {
                    trace!("Received terminate event");
                    self.stop();
                    break;
                }
            }
        }
    }

    /// Allows external tests to send events.
    pub fn get_sender(&self) -> ::std::sync::mpsc::Sender<Event> {
        self.sender.clone()
    }

    /// Terminate event loop.
    pub fn stop(&mut self) {
        trace!("ExampleNode terminating.");
        self.node.stop();
    }

    fn handle_request(&mut self, msg: RequestMessage) {
        match msg.content {
            RequestContent::Get(data_request, id) => {
                self.handle_get_request(data_request, id, msg.src, msg.dst);
            }
            RequestContent::Put(data, id) => {
                self.handle_put_request(data, id, msg.dst);
            }
            RequestContent::Post(..) => {
                trace!("ExampleNode: Post unimplemented.");
            }
            RequestContent::Delete(..) => {
                trace!("ExampleNode: Delete unimplemented.");
            }
            RequestContent::Refresh(content) => {
                self.handle_refresh(content);
            }
            _ => (),
        }
    }

    fn handle_response(&mut self, msg: ResponseMessage) {
        match (msg.content, msg.dst.clone()) {
            (ResponseContent::GetSuccess(data, id),
             Authority::NaeManager(_)) => {
                self.handle_get_success(data, id, msg.dst);
            }
            (ResponseContent::GetFailure { .. }, Authority::NaeManager(_)) => {
                unreachable!("Handle this - Repeat get request from different managed node and \
                              start the chunk relocation process");
            }
            _ => unimplemented!(),
        }
    }

    fn handle_get_request(&mut self,
                          data_request: DataRequest,
                          id: MessageId,
                          src: Authority,
                          dst: Authority) {
        match dst {
            Authority::NaeManager(_) => {
                if let Some(managed_nodes) = self.dm_accounts.get(&data_request.name()) {
                    trace!("Handle get request for NaeManager: data {:?} from {:?}",
                           data_request.name(),
                           managed_nodes[0]);
                    let _ = self.client_request_cache
                                .entry(data_request.name())
                                .or_insert(Vec::new())
                                .push(src);
                    unwrap_result!(self.node
                                       .send_get_request(dst,
                                                         Authority::ManagedNode(managed_nodes[0]
                                                                                    .clone()),
                                                         data_request,
                                                         id));
                }
                // TODO Send GetFailure back to Client
            }
            Authority::ManagedNode(_) => {
                trace!("Handle get request for ManagedNode: data {:?}",
                       data_request.name());
                match self.db.get(&data_request.name()) {
                    Some(data) => {
                        unwrap_result!(self.node
                                           .send_get_success(dst, src, data.clone(), id))
                    }
                    None => {
                        trace!("GetDataRequest failed for {:?}.", data_request.name());
                        return;
                    }
                }
            }
            _ => unreachable!("Wrong Destination Authority {:?}", dst),
        }
    }

    fn handle_put_request(&mut self, data: Data, id: MessageId, dst: Authority) {
        match dst {
            Authority::NaeManager(_) => {
                let mut close_grp = unwrap_result!(self.node.close_group());
                close_grp.push(unwrap_result!(self.node.name()));

                close_grp.sort_by(|lhs, rhs| {
                    if closer_to_target(lhs, rhs, &data.name()) {
                        ::std::cmp::Ordering::Less
                    } else {
                        ::std::cmp::Ordering::Greater
                    }
                });

                close_grp.truncate(STORE_REDUNDANCY);

                let src = dst;
                for i in 0..STORE_REDUNDANCY {
                    let dst = Authority::ManagedNode(close_grp[i].clone());
                    unwrap_result!(self.node.send_put_request(src.clone(),
                                                              dst,
                                                              data.clone(),
                                                              id.clone()));
                }
                // TODO currently we assume these msgs are saved by managed nodes we should wait for put success to
                // confirm the same
                let _ = self.dm_accounts.insert(data.name(), close_grp.clone());
                trace!("Put Request: Updating NaeManager: data {:?}, nodes {:?}",
                       data.name(),
                       close_grp);
            }
            Authority::ClientManager(_) => {
                trace!("Put Request: Updating ClientManager: key {:?}, value {:?}",
                       data.name(),
                       data);
                let src = dst;
                let dst = Authority::NaeManager(data.name());
                unwrap_result!(self.node.send_put_request(src, dst, data, id));
            }
            Authority::ManagedNode(_) => {
                trace!("Storing as ManagedNode: key {:?}, value {:?}",
                       data.name(),
                       data);
                let _ = self.db.insert(data.name(), data);
                // TODO Send PutSuccess here ??
            }
            _ => unreachable!("ExampleNode: Unexpected dst ({:?})", dst),
        }
    }

    fn handle_get_success(&mut self, data: Data, id: MessageId, dst: Authority) {
        if let Some(client_auths) = self.client_request_cache.remove(&data.name()) {
            let src = dst;
            for client_auth in client_auths {
                let _ = self.node
                            .send_get_success(src.clone(), client_auth, data.clone(), id.clone());
            }
            return;
        }

        if let Some((_, churn_id)) = self.lost_node_cache.remove(&data.name()) {
            let mut close_grp = unwrap_result!(self.node.close_group());
            close_grp.push(unwrap_result!(self.node.name()));

            close_grp.sort_by(|lhs, rhs| {
                if closer_to_target(lhs, rhs, &data.name()) {
                    ::std::cmp::Ordering::Less
                } else {
                    ::std::cmp::Ordering::Greater
                }
            });

            if let Some(node) = close_grp.into_iter().find(|outer| {
                !unwrap_option!(self.dm_accounts.get(&data.name()), "")
                     .iter()
                     .any(|inner| *inner == *outer)
            }) {
                let src = dst;
                let dst = Authority::ManagedNode(node.clone());
                unwrap_result!(self.node
                                   .send_put_request(src.clone(), dst, data.clone(), id));

                // TODO currently we assume these msgs are saved by managed nodes we should wait for put success to
                // confirm the same
                unwrap_option!(self.dm_accounts.get_mut(&data.name()), "").push(node);
                trace!("Replicating chunk {:?} to {:?}",
                       data.name(),
                       unwrap_option!(self.dm_accounts.get(&data.name()), ""));

                // Send Refresh message with updated storage locations in DataManager
                self.send_data_manager_refresh_messages(churn_id);
            }
        }
    }

    // While handling churn messages, we first "action" it ourselves and then
    // send the corresponding refresh messages out to our close group.
    fn handle_churn(&mut self, id: MessageId, lost_close_node: Option<XorName>) {
        for (client_name, stored) in self.client_accounts.iter() {
            let refresh_content = RefreshContent::ForMaidManager {
                id: id.clone(),
                client_name: client_name.clone(),
                data: stored.clone(),
            };

            let content = unwrap_result!(serialise(&refresh_content));

            unwrap_result!(self.node
                               .send_refresh_request(Authority::ClientManager(client_name.clone()),
                                                     content));
        }

        if let Some(lost_close_node) = lost_close_node {
            self.process_lost_close_node(lost_close_node, id);
        } else {
            self.send_data_manager_refresh_messages(id);
        }
    }

    fn process_lost_close_node(&mut self, lost_node: XorName, id: MessageId) {
        let mut vec_lost_chunks = Vec::<usize>::with_capacity(self.dm_accounts.len());
        for dm_account in self.dm_accounts.iter_mut() {
            if let Some(lost_node_pos) = dm_account.1.iter().position(|elt| *elt == lost_node) {
                let _ = self.lost_node_cache
                            .insert(dm_account.0.clone(), (lost_node.clone(), id.clone()));
                let _ = dm_account.1.remove(lost_node_pos);
                if dm_account.1.is_empty() {
                    error!("Chunk lost - No valid nodes left to retrieve chunk");
                    continue;
                }

                let src = Authority::NaeManager(dm_account.0.clone());
                let dst = Authority::ManagedNode(dm_account.1[0].clone());

                trace!("Example - process_lost_close_node. recovering data - {:?}",
                       dm_account.0.clone());

                if let Err(err) =
                       self.node
                           .send_get_request(src,
                                             dst,
                                             DataRequest::PlainData(dm_account.0.clone()),
                                             MessageId::from_xor_name(lost_node)) {
                    error!("Failed to send get request to retrieve chunk - {:?}", err);
                }
            }
        }
    }

    fn send_data_manager_refresh_messages(&mut self, id: MessageId) {
        for (data_name, managed_nodes) in self.dm_accounts.iter() {
            let refresh_content = RefreshContent::ForDataManager {
                id: id.clone(),
                data_name: data_name.clone(),
                pmid_nodes: managed_nodes.clone(),
            };

            let content = unwrap_result!(serialise(&refresh_content));

            unwrap_result!(self.node
                               .send_refresh_request(Authority::NaeManager(data_name.clone()),
                                                     content));
        }
    }

    fn handle_refresh(&mut self, content: Vec<u8>) {
        match unwrap_result!(deserialise(&content)) {
            RefreshContent::ForMaidManager { client_name, data, .. } => {
                trace!("handle_refresh for MaidManager. client - {:?}", client_name);
                let _ = self.client_accounts.insert(client_name, data);
            }
            RefreshContent::ForDataManager { data_name, pmid_nodes, .. } => {
                let old_val = self.dm_accounts.insert(data_name, pmid_nodes.clone());
                trace!("DataManager Refreshed. data_name - {:?} From - {:?} To - {:?}",
                       data_name,
                       old_val,
                       pmid_nodes);
            }
        }
    }
}

/// This can get defined for each of the personas in other crates
#[allow(unused)]
#[derive(RustcEncodable, RustcDecodable)]
enum RefreshContent {
    ForMaidManager {
        id: MessageId,
        client_name: XorName,
        data: u64,
    },
    ForDataManager {
        id: MessageId,
        data_name: XorName,
        pmid_nodes: Vec<XorName>,
    },
}

