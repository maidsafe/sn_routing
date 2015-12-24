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

extern crate log;
extern crate time;
extern crate routing;
extern crate sodiumoxide;
extern crate xor_name;
extern crate maidsafe_utilities;

use self::xor_name::XorName;
use self::routing::{RequestMessage, ResponseMessage, RequestContent, ResponseContent,
                    ChurnEventId, RefreshAccumulatorValue, Authority, Routing, Event, Data,
                    DataRequest};
use self::sodiumoxide::crypto::hash::sha512;
use self::maidsafe_utilities::serialisation::serialise;

/// Network Node.
#[allow(unused)]
pub struct Node {
    routing: Routing,
    receiver: ::std::sync::mpsc::Receiver<Event>,
    sender: ::std::sync::mpsc::Sender<Event>,
    db: ::std::collections::BTreeMap<XorName, Data>,
    client_accounts: ::std::collections::BTreeMap<XorName, u64>,
    connected: bool,
}

#[allow(unused)]
impl Node {
    /// Construct a new node.
    pub fn new() -> Node {
        let (sender, receiver) = ::std::sync::mpsc::channel::<Event>();
        let routing = unwrap_result!(Routing::new(sender.clone()));

        Node {
            routing: routing,
            receiver: receiver,
            sender: sender,
            db: ::std::collections::BTreeMap::new(),
            client_accounts: ::std::collections::BTreeMap::new(),
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
        trace!("Node terminating.");
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
                trace!("Node: Post unimplemented.");
            }
            RequestContent::Delete(_) => {
                trace!("Node: Delete unimplemented.");
            }
            _ => (),
        }
    }

    fn handle_get_request(&mut self, data_request: DataRequest, src: Authority, dst: Authority) {
        match self.db.get(&data_request.name()) {
            Some(data) => {
                unwrap_result!(self.routing
                                   .send_get_response(src,
                                                      dst,
                                                      ResponseContent::GetSuccess(data.clone())))
            }
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
                let request_content = RequestContent::Put(data);
                unwrap_result!(self.routing.send_put_request(src, dst, request_content));
            }
            _ => {
                trace!("Node: Unexpected src ({:?})", src);
                assert!(false);
            }
        }
    }

    fn handle_churn(&mut self, churn_id: ChurnEventId) {
        for (client_name, stored) in self.client_accounts.iter() {
            let persona_bytes = "ClientManager".to_owned().into_bytes();
            let to_hash = churn_id.id
                                  .0
                                  .iter()
                                  .chain(client_name.0.iter().chain(persona_bytes.iter()))
                                  .cloned()
                                  .collect::<Vec<_>>();
            let nonce = sha512::hash(&to_hash[..]);
            let content = unwrap_result!(serialise(&stored));

            unwrap_result!(self.routing.send_refresh_request(Authority::ClientManager(client_name.clone()),
                                                             nonce,
                                                             content));
        }
    }

    fn handle_refresh(&mut self, _nonce: sha512::Digest, _values: Vec<RefreshAccumulatorValue>) {
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

    fn handle_response(&mut self, _msg: ResponseMessage) {
        unimplemented!()
    }
}

/// Returns the median (rounded down to the nearest integral value) of `values` which can be
/// unsorted.  If `values` is empty, returns `0`.
#[allow(unused)]
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
