// Copyright 2015 MaidSafe.net limited.
//
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

use time::Duration;
use std::sync::mpsc;
use std::collections::BTreeMap;
use sodiumoxide::crypto::hash;
use routing::Routing;
use xor_name::XorName;
use authority::Authority;
use authority::Authority::{NaeManager, ClientManager, Client};
use messages::{RequestMessage, ResponseMessage, RequestContent, ResponseContent};
use maidsafe_utilities::serialisation::{serialise, deserialise};
use accumulator::Accumulator;
use data::{Data, DataRequest};
use event::Event;

/// Network Node.
pub struct Node {
    routing: Routing,
    receiver: mpsc::Receiver<Event>,
    sender: mpsc::Sender<Event>,
    db: BTreeMap<XorName, Data>,
    client_accounts: BTreeMap<XorName, u64>,
    connected: bool,
    our_close_group: Vec<XorName>,
    refresh_accumulator: Accumulator<(Authority, XorName), (Vec<u8>, XorName)>,
    dynamic_quorum: usize,
}

impl Node {
    /// Construct a new node.
    pub fn new() -> Node {
        let (sender, receiver) = mpsc::channel::<Event>();
        let routing = unwrap_result!(Routing::new(sender.clone()));

        Node {
            routing: routing,
            receiver: receiver,
            sender: sender,
            db: BTreeMap::new(),
            client_accounts: BTreeMap::new(),
            connected: false,
            our_close_group: Vec::new(),
            refresh_accumulator: Accumulator::with_duration(0, Duration::minutes(5)),
            dynamic_quorum: 0
        }
    }

    /// Run event loop.
    pub fn run(&mut self) {
        while let Ok(event) = self.receiver.recv() {
            match event {
                Event::Request(msg) => self.handle_request(msg),
                Event::Response(msg) => self.handle_response(msg),
                Event::Refresh{ dst, raw_bytes, cause, sender } => {
                    println!("Received refresh event");
                    self.handle_refresh(dst, raw_bytes, cause, sender);
                }
                Event::Churn(close_group, cause) => {
                    println!("Received churn event");
                    self.handle_churn(close_group, cause)
                }
                Event::DynamicQuorum(dynamic_quorum) => {
                    println!("Received DynamicQuorum event {:?}", dynamic_quorum);
                    self.dynamic_quorum = dynamic_quorum;
                    self.refresh_accumulator.set_quorum_size(dynamic_quorum)
                }
                Event::Connected => {
                    println!("Received connected event");
                    self.connected = true;
                }
                Event::Disconnected => println!("Received disconnected event"),
                Event::Terminated => {
                    println!("Received terminate event");
                    self.stop();
                    break;
                }
            }
        }
    }

    /// Allows external tests to send events.
    pub fn get_sender(&self) -> mpsc::Sender<Event> {
        self.sender.clone()
    }

    /// Terminate event loop.
    pub fn stop(&mut self) {
        println!("Node terminating.");
        self.routing.stop();
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
                println!("Node: Post unimplemented.");
            }
            RequestContent::Delete(_) => {
                println!("Node: Delete unimplemented.");
            }
            _ => (),
        }
    }

    fn handle_get_request(&mut self, data_request: DataRequest, src: Authority, dst: Authority) {
        let name = match data_request {
            DataRequest::PlainData(name) => name,
            _ => {
                println!("Node: Only serving plain data in this example");
                return;
            }
        };

        let data = match self.db.get(&name) {
            Some(data) => data.clone(),
            None => return,
        };

        let response_content = ResponseContent::GetSuccess(data);

        unwrap_result!(self.routing.send_get_response(dst, src, response_content))
    }

    fn handle_put_request(&mut self, data: Data, src: Authority, dst: Authority) {
        match dst {
            NaeManager(_) => {
                println!("Storing: key {:?}, value {:?}", data.name(), data);
                let _ = self.db.insert(data.name(), data);
            }
            ClientManager(_) => {
                match src {
                    Client { client_key, .. } => {
                        let client_name = XorName::new(hash::sha512::hash(&client_key[..]).0);
                        *self.client_accounts.entry(client_name).or_insert(0u64) += data.payload_size() as u64;
                        println!("Client ({:?}) stored {:?} bytes",
                                 client_name,
                                 self.client_accounts.get(&client_name));
                        println!("Sending: key {:?}, value {:?}", data.name(), data);
                        let name = data.name();
                        let request_content = RequestContent::Put(data);
                        unwrap_result!(self.routing.send_put_request(dst, NaeManager(name), request_content));
                    }
                    _ => {
                        println!("Node: Unexpected src ({:?})", src);
                        assert!(false);
                    }
                }
            }
            _ => {
                println!("Node: Unexpected dst ({:?})", dst);
                assert!(false);
            }
        }
    }

    fn handle_churn(&mut self, our_close_group: Vec<XorName>, cause: XorName) {
        println!("Handle churn for cause {:?}", cause);
        self.routing.get_dynamic_quorum();
        self.our_close_group = our_close_group;

        for (client_name, stored) in self.client_accounts.iter() {
            println!("Send refresh {:?} - {:?}", client_name, stored);
            let request_content = RequestContent::Refresh {
                raw_bytes: unwrap_result!(serialise(&stored)),
                cause: cause,
            };

            unwrap_result!(self.routing.send_refresh_request(ClientManager(client_name.clone()), request_content));
        }
    }

    fn handle_refresh(&mut self, dst: Authority, raw_bytes: Vec<u8>, cause: XorName, sender: XorName) {
        if let Some(values) = self.refresh_accumulator.add((dst.clone(), cause), (raw_bytes, sender)) {
            let mut records: Vec<u64> = Vec::new();
            let mut fail_parsing_count = 0usize;
            for (raw_bytes, _) in values {
                match deserialise(&raw_bytes) {
                    Ok(record) => records.push(record),
                    Err(_) => fail_parsing_count += 1usize,
                }
            }
            let median = median(records.clone());
            println!("Refresh for {:?}: median {:?} on quorum {:?} from {:?} (errs {:?})",
                     dst,
                     median,
                     self.dynamic_quorum,
                     records,
                     fail_parsing_count);
            if let ClientManager(client_name) = dst {
                let _ = self.client_accounts.insert(client_name, median);
            }
            self.refresh_accumulator.delete(&(dst.clone(), cause));
        }
    }

    fn handle_response(&mut self, _msg: ResponseMessage) {
        unimplemented!()
    }
}

/// Returns the median (rounded down to the nearest integral value) of `values` which can be
/// unsorted.  If `values` is empty, returns `0`.
pub fn median(mut values: Vec<u64>) -> u64 {
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
