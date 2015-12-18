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

use xor_name::XorName;
use authority::Authority;
use messages::{RequestMessage, ResponseMessage, RequestContent, ResponseContent};
use maidsafe_utilities::serialisation::{serialise, deserialise};

/// Network Node.
pub struct Node {
    routing: ::routing::Routing,
    receiver: ::std::sync::mpsc::Receiver<::event::Event>,
    sender: ::std::sync::mpsc::Sender<::event::Event>,
    db: ::std::collections::BTreeMap<XorName, ::data::Data>,
    client_accounts: ::std::collections::BTreeMap<XorName, u64>,
    connected: bool,
    our_close_group: Vec<XorName>,
}

impl Node {
    /// Construct a new node.
    pub fn new() -> Node {
        let (sender, receiver) = ::std::sync::mpsc::channel::<::event::Event>();
        let routing = unwrap_result!(::routing::Routing::new(sender.clone()));

        Node {
            routing: routing,
            receiver: receiver,
            sender: sender,
            db: ::std::collections::BTreeMap::new(),
            client_accounts: ::std::collections::BTreeMap::new(),
            connected: false,
            our_close_group: Vec::new(),
        }
    }

    /// Run event loop.
    pub fn run(&mut self) {
        while let Ok(event) = self.receiver.recv() {
            match event {
                ::event::Event::Request(msg) => self.handle_request(msg),
                ::event::Event::Response(msg) => self.handle_response(msg),
                ::event::Event::Refresh{ dst, raw_bytes, cause, public_id } => {
                    debug!("Received refresh event");
                    self.handle_refresh(dst, raw_bytes, cause, public_id);
                }
                ::event::Event::Churn(close_group, cause) => {
                    debug!("Received churn event");
                    self.handle_churn(close_group, cause)
                }
                // ::event::Event::Bootstrapped => debug!("Received bootstraped event"),
                ::event::Event::Connected => {
                    debug!("Received connected event");
                    self.connected = true;
                }
                ::event::Event::Disconnected => debug!("Received disconnected event"),
                ::event::Event::Terminated => {
                    debug!("Received terminate event");
                    self.stop();
                    break;
                }
            }
        }
    }

    /// Allows external tests to send events.
    pub fn get_sender(&self) -> ::std::sync::mpsc::Sender<::event::Event> {
        self.sender.clone()
    }

    /// Terminate event loop.
    pub fn stop(&mut self) {
        debug!("Node terminating.");
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
                debug!("Node: Post unimplemented.");
            }
            RequestContent::Delete(_) => {
                debug!("Node: Delete unimplemented.");
            }
            _ => (),
        }
    }

    fn handle_get_request(&mut self,
                          data_request: ::data::DataRequest,
                          src: Authority,
                          dst: Authority) {
        match self.db.get(&data_request.name()) {
            Some(data) => {
                unwrap_result!(self.routing
                                   .send_get_response(src,
                                                      dst,
                                                      ResponseContent::GetSuccess(data.clone())))
            }
            None => {
                debug!("GetDataRequest failed for {:?}.", data_request.name());
                return;
            }
        }
    }

    fn handle_put_request(&mut self, data: ::data::Data, src: Authority, _dst: Authority) {
        match src {
            Authority::NaeManager(_) => {
                debug!("Storing: key {:?}, value {:?}", data.name(), data);
                let _ = self.db.insert(data.name(), data);
            }
            Authority::ClientManager(_) => {
                debug!("Sending: key {:?}, value {:?}", data.name(), data);
                let dst = Authority::NaeManager(data.name());
                let request_content = RequestContent::Put(data);
                unwrap_result!(self.routing.send_put_request(src, dst, request_content));
            }
            _ => {
                debug!("Node: Unexpected src ({:?})", src);
                assert!(false);
            }
        }
    }

    fn handle_churn(&mut self, our_close_group: Vec<XorName>, cause: XorName) {
        // Not having access to our close group on startup means refresh won't
        // be called for the first node that goes offline.
        if self.our_close_group.len() == 0 {
            self.our_close_group = our_close_group.clone();
            return
        }

        debug!("Handle churn for close group size {:?}", our_close_group.len());

        for (client_name, stored) in self.client_accounts.iter() {
            let mut updated = false;
            for close_node in self.our_close_group.iter() {
                if !our_close_group.contains(&close_node) {
                    println!("Refresh {:?} - {:?}", client_name, stored);
                    let request_content = RequestContent::Refresh {
                        type_tag: 1u64,
                        message: unwrap_result!(serialise(&stored)),
                        cause: close_node.clone(),
                    };
                    updated = true;
                    unwrap_result!(self.routing.send_refresh_request(
                        Authority::ClientManager(client_name.clone()),
                        request_content));
                }
            }
            if updated {
                self.our_close_group = our_close_group.clone();
            }
        }
    }

    fn handle_refresh(&mut self, src: Authority, vec_of_bytes: Vec<Vec<u8>>) {
        let mut records: Vec<u64> = Vec::new();
        let mut fail_parsing_count = 0usize;
        for bytes in vec_of_bytes {
            match deserialise(&bytes) {
                Ok(record) => records.push(record),
                Err(_) => fail_parsing_count += 1usize,
            }
        }
        let median = median(records.clone());
        debug!("Refresh for {:?}: median {:?} from {:?} (errs {:?})",
               src,
               median,
               records,
               fail_parsing_count);
        if let Authority::ClientManager(client_name) = src {
            let _ = self.client_accounts.insert(client_name, median);
        }
    }

    fn handle_do_refresh(&self, src: Authority, cause: XorName) {
        if let Authority::ClientManager(client_name) = src {
            match self.client_accounts.get(&client_name) {
                Some(stored) => {
                    debug!("DoRefresh for client {:?} storing {:?} caused by {:?}",
                           client_name,
                           stored,
                           cause);

                    let request_content = RequestContent::Refresh {
                        type_tag: 1u64,
                        message: unwrap_result!(serialise(&stored)),
                        cause: cause,
                    };
                    unwrap_result!(self.routing.send_refresh_request(
                        Authority::ClientManager(client_name.clone()),
                        request_content));
                },
                None => (),
            }
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
