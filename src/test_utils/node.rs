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

pub struct Node {
    routing: ::routing::Routing,
    receiver: ::std::sync::mpsc::Receiver<::event::Event>,
    db: ::std::collections::BTreeMap<::NameType, ::data::Data>,
}

impl Node {
    pub fn new() -> Node {
        let (sender, receiver) = ::std::sync::mpsc::channel::<::event::Event>();
        let routing = ::routing::Routing::new(sender);

        Node {
            routing: routing,
            receiver: receiver,
            db: ::std::collections::BTreeMap::new(),
        }
    }

    pub fn run(&mut self) {
        while let Ok(event) = self.receiver.recv() {
            debug!("Node: Received event {:?}", event);
            match event {
                ::event::Event::Request{ request, our_authority, from_authority, response_token } =>
                    self.handle_request(request, our_authority, from_authority, response_token),
                // Event::Response{ response, our_authority, from_authority } =>
                //     self.on_response(response, our_authority, from_authority),
                // Event::Refresh(type_tag, group_name, accounts) =>
                //     self.on_refresh(type_tag, group_name, accounts),
                // Event::Churn(close_group) => self.on_churn(close_group),
                ::event::Event::Bootstrapped => debug!("Received bootstraped event"),
                ::event::Event::Connected => debug!("Received connected event"),
                ::event::Event::Disconnected => debug!("Received disconnected event"),
                // Event::FailedRequest{ request, our_authority, location, interface_error } =>
                //     self.on_failed_request(request, our_authority, location, interface_error),
                // Event::FailedResponse{ response, our_authority, location, interface_error } =>
                //     self.on_failed_response(response, our_authority, location, interface_error),
                ::event::Event::Terminated => break,
                _ => debug!("Received unhandled event"),
            };
        }
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
                println!("Node: Unexpected our_authority ({:?})", our_authority);
                assert!(false);
            }
        }
    }
}
