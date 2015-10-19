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

/// Network Node.
pub struct Node {
    routing: ::routing::Routing,
    receiver: ::std::sync::mpsc::Receiver<::event::Event>,
    sender: ::std::sync::mpsc::Sender<::event::Event>,
    db: ::std::collections::BTreeMap<::NameType, ::data::Data>,
    client_accounts: ::std::collections::BTreeMap<::NameType, u64>,
    connected: bool,
}

impl Node {

    /// Construct a new node.
    pub fn new() -> Node {
        let (sender, receiver) = ::std::sync::mpsc::channel::<::event::Event>();
        let routing = ::routing::Routing::new(sender.clone());

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
            debug!("Node: Received event {:?}", event);
            match event {
                ::event::Event::Request{ request, our_authority, from_authority, response_token } =>
                    self.handle_request(request, our_authority, from_authority, response_token),
                ::event::Event::Response{ response, our_authority, from_authority } => {
                    debug!("Received response event");
                    self.handle_response(response, our_authority, from_authority)
                },
                ::event::Event::Refresh(type_tag, our_authority, vec_of_bytes) => {
                    debug!("Received refresh event");
                    if type_tag != 1u64 { error!("Received refresh for tag {:?} from {:?}",
                        type_tag, our_authority); continue; };
                    self.handle_refresh(our_authority, vec_of_bytes);
                },
                ::event::Event::DoRefresh(type_tag, our_authority, cause) => {
                    debug!("Received do refresh event");
                    if type_tag != 1u64 { error!("Received DoRefresh for tag {:?} from {:?}",
                        type_tag, our_authority); continue; };
                    self.handle_do_refresh(our_authority, cause);
                },
                ::event::Event::Churn(close_group, cause) => {
                    debug!("Received churn event");
                    self.handle_churn(close_group, cause)
                },
                ::event::Event::Bootstrapped => debug!("Received bootstraped event"),
                ::event::Event::Connected => {
                    debug!("Received connected event");
                    self.connected = true;
                },
                ::event::Event::Disconnected => debug!("Received disconnected event"),
                ::event::Event::FailedRequest{ request, our_authority, location, interface_error } => {
                    debug!("Received failed request event");
                    self.handle_failed_request(request, our_authority, location, interface_error)
                },
                ::event::Event::FailedResponse{ response, our_authority, location, interface_error } => {
                    debug!("Received failed response event");
                    self.handle_failed_response(response, our_authority, location, interface_error)
                },
                ::event::Event::Terminated => {
                    debug!("Received terminate event");
                    self.stop();
                    break
                },
            };
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

    fn handle_request(&mut self, request: ::ExternalRequest,
                                 our_authority: ::authority::Authority,
                                 from_authority: ::authority::Authority,
                                 response_token: Option<::SignedToken>) {
        match request {
            ::ExternalRequest::Get(data_request, _) => {
                self.handle_get_request(data_request, our_authority, from_authority, response_token);
            },
            ::ExternalRequest::Put(data) => {
                self.handle_put_request(data, our_authority, from_authority, response_token);
            },
            ::ExternalRequest::Post(_) => {
                debug!("Node: Post unimplemented.");
            },
            ::ExternalRequest::Delete(_) => {
                debug!("Node: Delete unimplemented.");
            },
        }
    }

    fn handle_get_request(&mut self, data_request: ::data::DataRequest,
                                     our_authority: ::authority::Authority,
                                     from_authority: ::authority::Authority,
                                     response_token: Option<::SignedToken>) {
        let data = match self.db.get(&data_request.name()) {
            Some(data) => data.clone(),
            None => {
                debug!("GetDataRequest failed for {:?}.", data_request.name());
                return
            }
        };

        self.routing.get_response(our_authority, from_authority, data, data_request, response_token);
    }

    fn handle_put_request(&mut self, data: ::data::Data,
                                     our_authority: ::authority::Authority,
                                     _from_authority: ::authority::Authority,
                                     _response_token: Option<::SignedToken>) {
        match our_authority {
            ::authority::Authority::NaeManager(_) => {
                debug!("Storing: key {:?}, value {:?}", data.name(), data);
                let _ = self.db.insert(data.name(), data);
            },
            ::authority::Authority::ClientManager(_) => {
                debug!("Sending: key {:?}, value {:?}", data.name(), data);
                self.routing.put_request(
                    our_authority, ::authority::Authority::NaeManager(data.name()), data); 
            },
            _ => {
                debug!("Node: Unexpected our_authority ({:?})", our_authority);
                assert!(false);
            }
        }
    }

    fn handle_churn(&mut self, our_close_group: Vec<::NameType>, cause: ::NameType) {
        let mut exit = false;
        if our_close_group.len() < ::types::GROUP_SIZE {
            if self.connected {
                debug!("Close group ({:?}) has fallen below group size {:?}, terminating node",
                    our_close_group.len(), ::types::GROUP_SIZE);
                exit = true;
            } else {
                debug!("Ignoring churn as we are not yet connected.");
                return;
            }
        }

        debug!("Handle churn for close group size {:?}", our_close_group.len());

        for (client_name, stored) in self.client_accounts.iter() {
            debug!("REFRESH {:?} - {:?}", client_name, stored);
            self.routing.refresh_request(1u64,
                ::authority::Authority::ClientManager(client_name.clone()),
                ::utils::encode(&stored).unwrap(), cause.clone());
        }
        if exit { self.routing.stop(); };
    }

    fn handle_refresh(&mut self, our_authority: ::authority::Authority, vec_of_bytes: Vec<Vec<u8>>) {
        let mut records : Vec<u64> = Vec::new();
        let mut fail_parsing_count = 0usize;
        for bytes in vec_of_bytes {
            match ::utils::decode(&bytes) {
                Ok(record) => records.push(record),
                Err(_) => fail_parsing_count += 1usize,
            };
        }
        let median = median(records.clone());
        debug!("Refresh for {:?}: median {:?} from {:?} (errs {:?})", our_authority, median,
            records, fail_parsing_count);
        match our_authority {
             ::authority::Authority::ClientManager(client_name) => {
                 let _ = self.client_accounts.insert(client_name, median);
             },
             _ => {},
        };
    }

    fn handle_do_refresh(&self, our_authority: ::authority::Authority, cause: ::NameType) {
        match our_authority {
            ::authority::Authority::ClientManager(client_name) => {
                match self.client_accounts.get(&client_name) {
                    Some(stored) => {
                        debug!("DoRefresh for client {:?} storing {:?} caused by {:?}",
                            client_name, stored, cause);
                        self.routing.refresh_request(1u64,
                            ::authority::Authority::ClientManager(client_name.clone()),
                            ::utils::encode(&stored).unwrap(), cause.clone());
                    },
                    None => {},
                };
            },
            _ => {},
        };
    }

    fn handle_response(&mut self, _response: ::ExternalResponse,
                                  _our_authority: ::authority::Authority,
                                  _from_authority: ::authority::Authority,) {
        unimplemented!();
    }

    fn handle_failed_request(&mut self, _request: ::ExternalRequest,
                                        _our_authority: Option<::authority::Authority>,
                                        _location: ::authority::Authority,
                                        _interface_error: ::error::InterfaceError) {
        unimplemented!();
    }

    fn handle_failed_response(&mut self, _response: ::ExternalResponse,
                                         _our_authority: Option<::authority::Authority>,
                                         _location: ::authority::Authority,
                                         _interface_error: ::error::InterfaceError) {
        unimplemented!();
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
