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
use routing::{RequestMessage, ResponseMessage, RequestContent, ResponseContent, ChurnEventId,
              RefreshAccumulatorValue, Authority, Node, Event, Data, DataRequest};
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
    lost_node_cache: LruCache<XorName, XorName>, // DataName vs LostNode
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
                Event::Refresh(nonce, values) => {
                    trace!("Received refresh event");
                    self.handle_refresh(nonce, values);
                }
                Event::Churn(churn_id) => {
                    trace!("Received churn event {:?}", churn_id);
                    self.handle_churn(churn_id)
                }
                Event::LostCloseNode(name) => {
                    trace!("Received LostCloseNode {:?}", name);
                    self.handle_lost_close_node(name);
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
            RequestContent::Get(data_request) => {
                self.handle_get_request(data_request, msg.src, msg.dst);
            }
            RequestContent::Put(data) => {
                self.handle_put_request(data, msg.dst);
            }
            RequestContent::Post(_) => {
                trace!("ExampleNode: Post unimplemented.");
            }
            RequestContent::Delete(_) => {
                trace!("ExampleNode: Delete unimplemented.");
            }
            _ => (),
        }
    }

    fn handle_get_request(&mut self, data_request: DataRequest, src: Authority, dst: Authority) {
        match dst {
            Authority::NaeManager(_) => {
                if let Some(managed_nodes) = self.dm_accounts.get(&data_request.name()) {
                    let _ = self.client_request_cache
                                .entry(data_request.name())
                                .or_insert(Vec::new())
                                .push(src);
                    unwrap_result!(self.node
                                       .send_get_request(dst,
                                                         Authority::ManagedNode(managed_nodes[0]
                                                                                    .clone()),
                                                         data_request));
                }
                // TODO Send GetFailure back to Client
            }
            Authority::ManagedNode(_) => {
                match self.db.get(&data_request.name()) {
                    Some(data) => {
                        unwrap_result!(self.node.send_get_success(dst, src, data.clone()))
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

    fn handle_put_request(&mut self, data: Data, dst: Authority) {
        match dst {
            Authority::NaeManager(_) => {
                trace!("Storing: key {:?}, value {:?}", data.name(), data);
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
                    unwrap_result!(self.node.send_put_request(src.clone(), dst, data.clone()));
                }
                // TODO currently we assume these msgs are saved by managed nodes we should wait for put success to
                // confirm the same
                let _ = self.dm_accounts.insert(data.name(), close_grp);
            }
            Authority::ClientManager(_) => {
                trace!("Sending: key {:?}, value {:?}", data.name(), data);
                let src = dst;
                let dst = Authority::NaeManager(data.name());
                unwrap_result!(self.node.send_put_request(src, dst, data));
            }
            Authority::ManagedNode(_) => {
                let _ = self.db.insert(data.name(), data);
            }
            _ => unreachable!("ExampleNode: Unexpected dst ({:?})", dst),
        }
    }

    fn handle_churn(&mut self, churn_id: ChurnEventId) {
        for (client_name, stored) in self.client_accounts.iter() {
            let refresh_nonce = RefreshNonce::ForMaidManager {
                churn_id: churn_id.clone(),
                client_name: client_name.clone(),
            };

            let nonce = unwrap_result!(serialise(&refresh_nonce));
            let content = unwrap_result!(serialise(&stored));

            unwrap_result!(self.node
                               .send_refresh_request(Authority::ClientManager(client_name.clone()),
                                                     nonce,
                                                     content));
        }

        for (data_name, managed_nodes) in self.dm_accounts.iter() {
            let refresh_nonce = RefreshNonce::ForDataManager {
                churn_id: churn_id.clone(),
                data_name: data_name.clone(),
            };

            let nonce = unwrap_result!(serialise(&refresh_nonce));
            let content = unwrap_result!(serialise(&managed_nodes));

            unwrap_result!(self.node
                               .send_refresh_request(Authority::NaeManager(data_name.clone()),
                                                     nonce,
                                                     content));
        }
    }

    fn handle_refresh(&mut self, nonce: Vec<u8>, values: Vec<RefreshAccumulatorValue>) {
        match unwrap_result!(deserialise(&nonce)) {
            RefreshNonce::ForMaidManager { client_name, .. } => {
                let mut records = Vec::<u64>::with_capacity(values.len());
                for refresh_acc_val in values {
                    let record = unwrap_result!(deserialise(&refresh_acc_val.content));
                    records.push(record)
                }
                let median = median(records.clone());
                let _ = self.client_accounts.insert(client_name, median);
            }
            RefreshNonce::ForDataManager { data_name, .. } => {
                let mut hash_container = HashMap::<Vec<XorName>, usize>::with_capacity(20);
                for refresh_acc_val in values {
                    let mut managed_nodes: Vec<XorName> =
                        unwrap_result!(deserialise(&refresh_acc_val.content));
                    *hash_container.entry(managed_nodes).or_insert(0) += 1;
                }

                let mut vec_container: Vec<(Vec<XorName>, usize)> = hash_container.into_iter()
                                                                                  .collect();
                vec_container.sort_by(|&(_, ref freq_lhs), &(_, ref freq_rhs)| {
                    freq_rhs.cmp(freq_lhs)
                });

                if vec_container[0].1 >= unwrap_result!(self.node.quorum_size()) {
                    let _ = self.dm_accounts.insert(data_name, vec_container[0].0.clone());
                }
            }
        }
    }

    fn handle_lost_close_node(&mut self, lost_node: XorName) {
        let mut vec_lost_chunks = Vec::<usize>::with_capacity(self.dm_accounts.len());
        for dm_account in self.dm_accounts.iter_mut() {
            if let Some(lost_node_pos) = dm_account.1.iter().position(|elt| *elt == lost_node) {
                let _ = self.lost_node_cache.insert(dm_account.0.clone(), lost_node.clone());
                let _ = dm_account.1.remove(lost_node_pos);
                if dm_account.1.is_empty() {
                    error!("Chunk lost - No valid nodes left to retrieve chunk");
                    continue;
                }

                let src = Authority::NaeManager(dm_account.0.clone());
                let dst = Authority::ManagedNode(dm_account.1[0].clone());
                if let Err(err) =
                       self.node
                           .send_get_request(src, dst, DataRequest::PlainData(dm_account.0.clone())) {
                    error!("Failed to send get request to retrieve chunk - {:?}", err);
                }
            }
        }
    }

    fn handle_response(&mut self, msg: ResponseMessage) {
        match (msg.content, msg.dst.clone()) {
            (ResponseContent::GetSuccess(data), Authority::NaeManager(_)) => {
                self.handle_get_success(data, msg.dst);
            }
            (ResponseContent::GetFailure { .. }, Authority::NaeManager(_)) => {
                unreachable!("Handle this - Repeat get request from different managed node and \
                              start the chunk relocation process");
            }
            _ => unimplemented!(),
        }
    }

    fn handle_get_success(&mut self, data: Data, dst: Authority) {
        if let Some(client_auths) = self.client_request_cache.remove(&data.name()) {
            let src = dst;
            for client_auth in client_auths {
                let _ = self.node.send_get_success(src.clone(), client_auth, data.clone());
            }
            return;
        }

        if self.lost_node_cache.remove(&data.name()).is_some() {
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
                unwrap_result!(self.node.send_put_request(src.clone(), dst, data.clone()));

                // TODO currently we assume these msgs are saved by managed nodes we should wait for put success to
                // confirm the same
                unwrap_option!(self.dm_accounts.get_mut(&data.name()), "").push(node);
            }

        }
    }
}

/// This can get defined for each of the personas in other crates
#[allow(unused)]
#[derive(RustcEncodable, RustcDecodable)]
enum RefreshNonce {
    ForMaidManager {
        churn_id: ChurnEventId,
        client_name: XorName,
    },
    ForDataManager {
        churn_id: ChurnEventId,
        data_name: XorName,
    },
}

/// Returns the median (rounded down to the nearest integral value) of `values` which can be
/// unsorted.  If `values` is empty, returns `0`.
#[allow(unused)]
fn median(mut values: Vec<u64>) -> u64 {
    match values.len() {
        0 => 0u64,
        1 => values[0],
        len if len % 2 == 0 => {
            values.sort();
            let lower_value = values[(len / 2) - 1];
            let upper_value = values[len / 2];
            (lower_value + upper_value) / 2
        }
        len => {
            values.sort();
            values[len / 2]
        }
    }
}
