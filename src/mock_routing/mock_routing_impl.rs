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

pub struct MockRoutingImpl {
    sender: ::std::sync::mpsc::Sender<::routing::event::Event>,
    client_sender: ::std::sync::mpsc::Sender<::routing::data::Data>,
    network_delay_ms: u32,
    get_requests_given: Vec<super::api_calls::GetRequest>,
    get_responses_given: Vec<super::api_calls::GetResponse>,
    put_requests_given: Vec<super::api_calls::PutRequest>,
    put_responses_given: Vec<super::api_calls::PutResponse>,
    refresh_requests_given: Vec<super::api_calls::RefreshRequest>,
}

impl MockRoutingImpl {
    pub fn new(sender: ::std::sync::mpsc::Sender<(::routing::event::Event)>) -> MockRoutingImpl {
        let (client_sender, _) = ::std::sync::mpsc::channel();

        MockRoutingImpl {
            sender: sender,
            client_sender: client_sender,
            network_delay_ms: 200,
            get_requests_given: vec![],
            get_responses_given: vec![],
            put_requests_given: vec![],
            put_responses_given: vec![],
            refresh_requests_given: vec![],
        }
    }

    pub fn get_client_receiver(&mut self) -> ::std::sync::mpsc::Receiver<::routing::data::Data> {
        let (client_sender, client_receiver) = ::std::sync::mpsc::channel();
        self.client_sender = client_sender;
        client_receiver
    }

    // -----------  the following methods are for testing purpose only   ------------- //
    pub fn client_get(&mut self,
                      client_address: XorName,
                      client_pub_key: ::sodiumoxide::crypto::sign::PublicKey,
                      data_request: ::routing::data::DataRequest) {
        let (_name, our_authority) = match data_request {
            ::routing::data::DataRequest::ImmutableData(name, _) =>
                (name.clone(), ::data_manager::Authority(name)),
            ::routing::data::DataRequest::StructuredData(name, _) =>
                (name.clone(), ::sd_manager::Authority(name)),
            _ => panic!("unexpected"),
        };
        let cloned_sender = self.sender.clone();
        let _ = ::std::thread::spawn(move || {
            let _ = cloned_sender.send(::routing::event::Event::Request {
                request: ::routing::ExternalRequest::Get(data_request, 0),
                our_authority: our_authority,
                from_authority: ::routing::Authority::Client(client_address, client_pub_key),
                response_token: None,
            });
        });
    }

    pub fn client_put(&mut self,
                      client_address: XorName,
                      client_pub_key: ::sodiumoxide::crypto::sign::PublicKey,
                      data: ::routing::data::Data) {
        let delay_ms = self.network_delay_ms;
        let cloned_sender = self.sender.clone();
        let _ = ::std::thread::spawn(move || {
            ::std::thread::sleep(::std::time::Duration::from_millis(delay_ms as u64));
            let _ = cloned_sender.send(::routing::event::Event::Request {
                request: ::routing::ExternalRequest::Put(data),
                our_authority: ::maid_manager::Authority(client_address),
                from_authority: ::routing::Authority::Client(client_address, client_pub_key),
                response_token: None,
            });
        });
    }

    pub fn client_post(&mut self,
                       client_address: XorName,
                       client_pub_key: ::sodiumoxide::crypto::sign::PublicKey,
                       data: ::routing::data::Data) {
        let delay_ms = self.network_delay_ms;
        let cloned_sender = self.sender.clone();
        let _ = ::std::thread::spawn(move || {
            ::std::thread::sleep(::std::time::Duration::from_millis(delay_ms as u64));
            let _ = cloned_sender.send(::routing::event::Event::Request {
                request: ::routing::ExternalRequest::Post(data.clone()),
                our_authority: ::sd_manager::Authority(data.name()),
                from_authority: ::routing::Authority::Client(client_address, client_pub_key),
                response_token: None,
            });
        });
    }

    pub fn churn_event(&mut self, nodes: Vec<XorName>,
                       churn_node: XorName) {
        let cloned_sender = self.sender.clone();
        let _ = ::std::thread::spawn(move || {
            let _ = cloned_sender.send(::routing::event::Event::Churn(nodes, churn_node));
        });
    }

    pub fn get_requests_given(&self) -> Vec<super::api_calls::GetRequest> {
        self.get_requests_given.clone()
    }

    pub fn get_responses_given(&self) -> Vec<super::api_calls::GetResponse> {
        self.get_responses_given.clone()
    }

    pub fn put_requests_given(&self) -> Vec<super::api_calls::PutRequest> {
        self.put_requests_given.clone()
    }

    pub fn put_responses_given(&self) -> Vec<super::api_calls::PutResponse> {
        self.put_responses_given.clone()
    }

    pub fn refresh_requests_given(&self) -> Vec<super::api_calls::RefreshRequest> {
        self.refresh_requests_given.clone()
    }

    // -----------  the following methods are expected to be API functions   ------------- //
    pub fn get_request(&mut self,
                       our_authority: ::routing::Authority,
                       location: ::routing::Authority,
                       request_for: ::routing::data::DataRequest) {
        self.get_requests_given.push(super::api_calls::GetRequest::new(our_authority.clone(),
                                                                       location.clone(),
                                                                       request_for.clone()));
        let delay_ms = self.network_delay_ms;
        let cloned_sender = self.sender.clone();
        let _ = ::std::thread::spawn(move || {
            ::std::thread::sleep(::std::time::Duration::from_millis(delay_ms as u64));
            let _ = cloned_sender.send(::routing::event::Event::Request {
                request: ::routing::ExternalRequest::Get(request_for, 0),
                our_authority: location,
                from_authority: our_authority,
                response_token: None,
            });
        });
    }

    pub fn get_response(&mut self,
                        our_authority: ::routing::Authority,
                        location: ::routing::Authority,
                        data: ::routing::data::Data,
                        data_request: ::routing::data::DataRequest,
                        response_token: Option<::routing::SignedToken>) {
        self.get_responses_given.push(super::api_calls::GetResponse::new(our_authority.clone(),
                                                                         location.clone(),
                                                                         data.clone(),
                                                                         data_request.clone(),
                                                                         response_token.clone()));
        let delay_ms = self.network_delay_ms;
        let cloned_sender = self.sender.clone();
        let cloned_client_sender = self.client_sender.clone();
        let _ = ::std::thread::spawn(move || {
            ::std::thread::sleep(::std::time::Duration::from_millis(delay_ms as u64));
            match location.clone() {
                ::routing::Authority::NaeManager(_) => {
                    let _ = cloned_sender.send(::routing::event::Event::Response {
                        response: ::routing::ExternalResponse::Get(data.clone(), data_request,
                                                                   response_token),
                        our_authority: location,
                        from_authority: our_authority,
                    });
                }
                ::routing::Authority::Client{ .. } => {
                    let _ = cloned_client_sender.send(data);
                }
                _ => {}
            }
        });
    }

    pub fn put_request(&mut self,
                       our_authority: ::routing::Authority,
                       location: ::routing::Authority,
                       data: ::routing::data::Data) {
        self.put_requests_given.push(super::api_calls::PutRequest::new(our_authority.clone(),
                                                                       location.clone(),
                                                                       data.clone()));
        let delay_ms = self.network_delay_ms;
        let cloned_sender = self.sender.clone();
        let _ = ::std::thread::spawn(move || {
            ::std::thread::sleep(::std::time::Duration::from_millis(delay_ms as u64));
            let _ = cloned_sender.send(::routing::event::Event::Request {
                request: ::routing::ExternalRequest::Put(data.clone()),
                our_authority: location,
                from_authority: our_authority,
                response_token: None,
            });
        });
    }

    pub fn put_response(&mut self,
                        our_authority: ::routing::Authority,
                        location: ::routing::Authority,
                        response_error: ::routing::error::ResponseError,
                        signed_token: Option<::routing::SignedToken>) {
        self.put_responses_given.push(super::api_calls::PutResponse::new(our_authority.clone(),
                                                                         location.clone(),
                                                                         response_error.clone(),
                                                                         signed_token.clone()));
        let delay_ms = self.network_delay_ms;
        let cloned_sender = self.sender.clone();
        let _ = ::std::thread::spawn(move || {
            ::std::thread::sleep(::std::time::Duration::from_millis(delay_ms as u64));
            let _ = cloned_sender.send(::routing::event::Event::Response {
                response: ::routing::ExternalResponse::Put(response_error, signed_token),
                our_authority: location,
                from_authority: our_authority,
            });
        });
    }

    pub fn refresh_request(&mut self,
                           type_tag: u64,
                           our_authority: ::routing::Authority,
                           content: Vec<u8>,
                           churn_node: XorName) {
        self.refresh_requests_given.push(super::api_calls::RefreshRequest::new(
                type_tag, our_authority.clone(), content.clone(), churn_node));
        // routing is expected to accumulate the refresh requests
        // for the same group into one event request to vault
        let delay_ms = self.network_delay_ms;
        let cloned_sender = self.sender.clone();
        let _ = ::std::thread::spawn(move || {
            ::std::thread::sleep(::std::time::Duration::from_millis(delay_ms as u64));
            let mut refresh_contents = vec![content.clone()];
            for _ in 2..::data_manager::REPLICANTS {
                refresh_contents.push(content.clone());
            }
            let _ = cloned_sender.send(::routing::event::Event::Refresh(type_tag,
                                                                        our_authority,
                                                                        refresh_contents));
        });
    }

    pub fn stop(&mut self) {
        let _ = self.sender.send(::routing::event::Event::Terminated);
    }
}
