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

extern crate log;
extern crate time;
extern crate routing;
extern crate sodiumoxide;
extern crate xor_name;
extern crate maidsafe_utilities;

use self::xor_name::XorName;
use self::routing::{RequestMessage, ResponseMessage, RequestContent, ChurnEventId,
                    RefreshAccumulatorValue, Authority, Node, Event, Data, DataRequest};
use self::sodiumoxide::crypto::hash::sha512;
use self::maidsafe_utilities::serialisation::{serialise, deserialise};
use std::collections::{BTreeMap, HashMap};

/// Network ExampleNode.
#[allow(unused)]
pub struct ExampleNode {
    node: Node,
    receiver: ::std::sync::mpsc::Receiver<Event>,
    sender: ::std::sync::mpsc::Sender<Event>,
    db: BTreeMap<XorName, Data>,
    db_immut_data: BTreeMap<XorName, Vec<XorName>>, // DataName vs Vec<PmidNodes>
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
            db_immut_data: BTreeMap::new(),
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
            let to_hash = churn_id.id
                                  .0
                                  .iter()
                                  .chain(client_name.0.iter())
                                  .cloned()
                                  .collect::<Vec<_>>();
            let nonce = mux(sha512::hash(&to_hash), RefreshNonceHandler::ClientManager);
            let content = unwrap_result!(serialise(&stored));

            unwrap_result!(self.node.send_refresh_request(Authority::ClientManager(client_name.clone()),
                                                             nonce,
                                                             content));
        }

        for (data_name, managed_nodes) in self.db_immut_data.iter() {
            let to_hash = churn_id.id
                                  .0
                                  .iter()
                                  .chain(data_name.0.iter())
                                  .cloned()
                                  .collect::<Vec<_>>();
            let nonce = mux(sha512::hash(&to_hash), RefreshNonceHandler::NaeManager);
            let content = unwrap_result!(serialise(&managed_nodes));

            unwrap_result!(self.routing
                               .send_refresh_request(Authority::NaeManager(data_name.clone()),
                                                     nonce,
                                                     content));
        }
    }

    fn handle_refresh(&mut self, nonce: sha512::Digest, values: Vec<RefreshAccumulatorValue>) {
        match demux(nonce) {
            RefreshNonceHandler::ClientManager => {
                // let mut records: Vec<u64> = Vec::new();
                // let mut fail_parsing_count = 0usize;
                // for bytes in vec_of_bytes {
                //     match ::maidsafe_utilities::serialisation::deserialise(&bytes) {
                //         Ok(record) => records.push(record),
                //         Err(_) => fail_parsing_count += 1usize,
                //     }
                // }
                // let median = median(records.clone());
                // trace!("Refresh for {:?}: median {:?} from {:?} (errs {:?})",
                //        src,
                //        median,
                //        records,
                //        fail_parsing_count);
                // if let ClientManager(client_name) = src {
                //     let _ = self.client_accounts.insert(client_name, median);
                // }
            }
            RefreshNonceHandler::NaeManager => {
                let mut container = HashMap::<XorName, HashMap<XorName, u8>>::with_capacity(100);
                for refresh_acc_val in values {
                    let managed_nodes: Vec<XorName> =
                        unwrap_result!(deserialise(&refresh_acc_val.content));
                    for node in managed_nodes {
                        *container.entry(refresh_acc_val.src_name)
                                  .or_insert(HashMap::with_capacity(20))
                                  .entry(node)
                                  .or_insert(0) += 1;
                    }
                }

                self.db_immut_data = BTreeMap::new();
                for (key, value) in container {
                    let mut vec: Vec<(XorName, u8)> = Vec::with_capacity(value.len());
                    for (managed_node, freq) in value {
                        vec.push((managed_node, freq));
                    }
                    vec.sort_by(|&(_, ref freq_lhs), &(_, ref freq_rhs)| freq_rhs.cmp(freq_lhs));

                    let _ = self.db_immut_data.insert(key, vec![vec[0].0, vec[1].0]);
                }
            }
        }
    }

    fn handle_response(&mut self, _msg: ResponseMessage) {
        unimplemented!()
    }
}

#[allow(unused)]
enum RefreshNonceHandler {
    ClientManager,
    NaeManager,
}

#[allow(unused)]
fn mux(mut nonce: sha512::Digest, nonce_handler: RefreshNonceHandler) -> sha512::Digest {
    match nonce_handler {
        RefreshNonceHandler::ClientManager => nonce.0[0] = 0,
        RefreshNonceHandler::NaeManager => nonce.0[0] = 1,
    }

    nonce
}

#[allow(unused)]
fn demux(nonce: sha512::Digest) -> RefreshNonceHandler {
    match nonce.0[0] {
        0 => RefreshNonceHandler::ClientManager,
        1 => RefreshNonceHandler::NaeManager,
        _ => unreachable!("Unknown Symbol for demultiplexing!"),
    }
}

// Returns the median (rounded down to the nearest integral value) of `values` which can be
// unsorted.  If `values` is empty, returns `0`.
// fn median(mut values: Vec<u64>) -> u64 {
//     match values.len() {
//         0 => 0u64,
//         1 => values[0],
//         len if len % 2 == 0 => {
//             values.sort();
//             let lower_value = values[(len / 2) - 1];
//             let upper_value = values[len / 2];
//             (lower_value + upper_value) / 2
//         }
//         len => {
//             values.sort();
//             values[len / 2]
//         }
//     }
// }
