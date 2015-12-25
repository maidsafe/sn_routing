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

use xor_name::XorName;
use routing::{RequestMessage, ResponseMessage, RequestContent, ChurnEventId,
              RefreshAccumulatorValue, Authority, Node, Event, Data, DataRequest};
use maidsafe_utilities::serialisation::{serialise, deserialise};
use std::collections::{BTreeMap, HashMap};
use rustc_serialize::{Encoder, Decoder};

/// Network ExampleNode.
#[allow(unused)]
pub struct ExampleNode {
    node: Node,
    receiver: ::std::sync::mpsc::Receiver<Event>,
    sender: ::std::sync::mpsc::Sender<Event>,
    db: BTreeMap<XorName, Data>,
    dm_accounts: BTreeMap<XorName, Vec<XorName>>, // DataName vs Vec<PmidNodes>
    client_accounts: BTreeMap<XorName, u64>,
    connected: bool,
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
            db: BTreeMap::new(),
            dm_accounts: BTreeMap::new(),
            client_accounts: BTreeMap::new(),
            connected: false,
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
                Event::LostCloseNode(name) => trace!("Received LostCloseNode {:?}", name),
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
                self.handle_put_request(data, msg.src, msg.dst);
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
        match self.db.get(&data_request.name()) {
            Some(data) => unwrap_result!(self.node.send_get_success(src, dst, data.clone())),
            None => {
                trace!("GetDataRequest failed for {:?}.", data_request.name());
                return;
            }
        }
    }

    fn handle_put_request(&mut self, data: Data, src: Authority, _dst: Authority) {
        match src {
            Authority::NaeManager(_) => {
                trace!("Storing: key {:?}, value {:?}", data.name(), data);
                let _ = self.db.insert(data.name(), data);
            }
            Authority::ClientManager(_) => {
                trace!("Sending: key {:?}, value {:?}", data.name(), data);
                let dst = Authority::NaeManager(data.name());
                unwrap_result!(self.node.send_put_request(src, dst, data));
            }
            _ => {
                trace!("ExampleNode: Unexpected src ({:?})", src);
                assert!(false);
            }
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
                let mut hash_container = HashMap::<Vec<XorName>, usize>::with_capacity(100);
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

    fn handle_response(&mut self, _msg: ResponseMessage) {
        unimplemented!()
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
