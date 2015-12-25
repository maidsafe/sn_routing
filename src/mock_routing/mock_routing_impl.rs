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

use kademlia_routing_table::{group_size, optimal_table_size};
use rand::random;
use routing::{Authority, Data, DataRequest, Event, InterfaceError, RequestContent, RequestMessage, ResponseContent,
              ResponseMessage};
use sodiumoxide::crypto::hash;
use std::cmp::Ordering;
use std::sync::mpsc;
use std::thread::sleep;
use std::time::Duration;
use xor_name::{XorName, closer_to_target};

pub struct MockRoutingImpl {
    our_id: XorName,
    peers: Vec<XorName>,
    sender: mpsc::Sender<Event>,
    client_sender: mpsc::Sender<Event>,
    simulated_latency: Duration,
    get_requests_given: Vec<RequestMessage>,
    put_requests_given: Vec<RequestMessage>,
    post_requests_given: Vec<RequestMessage>,
    delete_requests_given: Vec<RequestMessage>,
    get_responses_given: Vec<ResponseMessage>,
    put_responses_given: Vec<ResponseMessage>,
    post_responses_given: Vec<ResponseMessage>,
    delete_responses_given: Vec<ResponseMessage>,
    refresh_requests_given: Vec<RequestMessage>,
}

impl MockRoutingImpl {
    pub fn new(sender: mpsc::Sender<Event>) -> MockRoutingImpl {
        let (client_sender, _) = mpsc::channel();
        let our_id: XorName = random();
        let mut peers = Vec::with_capacity(optimal_table_size());
        for _ in 0..optimal_table_size() {
            peers.push(random());
        }
        peers.sort_by(|a, b| {
            match closer_to_target(&a, &b, &our_id) {
                true => Ordering::Less,
                false => Ordering::Greater,
            }
        });

        MockRoutingImpl {
            our_id: our_id,
            peers: peers,
            sender: sender,
            client_sender: client_sender,
            simulated_latency: Duration::from_millis(200),
            get_requests_given: vec![],
            put_requests_given: vec![],
            post_requests_given: vec![],
            delete_requests_given: vec![],
            get_responses_given: vec![],
            put_responses_given: vec![],
            post_responses_given: vec![],
            delete_responses_given: vec![],
            refresh_requests_given: vec![],
        }
    }

    pub fn get_client_receiver(&mut self) -> mpsc::Receiver<Event> {
        let (client_sender, client_receiver) = mpsc::channel();
        self.client_sender = client_sender;
        client_receiver
    }

    // -----------  the following methods are for testing purpose only   ------------- //
    pub fn client_get(&mut self, src: Authority, data_request: DataRequest) {
        let _ = self.send_request(src,
                                  Authority::NaeManager(data_request.name()),
                                  RequestContent::Get(data_request),
                                  "Mock Client Get Request");
    }

    pub fn client_put(&mut self, src: Authority, data: Data) {
        let _ = self.send_request(src,
                                  Authority::ClientManager(data.name()),
                                  RequestContent::Put(data),
                                  "Mock Client Put Request");
    }

    pub fn client_post(&mut self, src: Authority, data: Data) {
        let _ = self.send_request(src,
                                  Authority::NaeManager(data.name()),
                                  RequestContent::Post(data),
                                  "Mock Client Post Request");
    }

    pub fn client_delete(&mut self, src: Authority, data: Data) {
        let _ = self.send_request(src,
                                  Authority::ClientManager(data.name()),
                                  RequestContent::Delete(data),
                                  "Mock Client Delete Request");
    }

    pub fn churn_event(&mut self, nodes: Vec<XorName>, churn_node: XorName) {
        let cloned_sender = self.sender.clone();
        let _ = thread!("Mock Churn Event", move || {
            let _ = cloned_sender.send(Event::Churn(nodes /* , churn_node */));
        });
    }

    pub fn get_requests_given(&self) -> Vec<RequestMessage> {
        self.get_requests_given.clone()
    }

    pub fn put_requests_given(&self) -> Vec<RequestMessage> {
        self.put_requests_given.clone()
    }

    pub fn post_requests_given(&self) -> Vec<RequestMessage> {
        self.post_requests_given.clone()
    }

    pub fn delete_requests_given(&self) -> Vec<RequestMessage> {
        self.delete_requests_given.clone()
    }

    pub fn get_responses_given(&self) -> Vec<ResponseMessage> {
        self.get_responses_given.clone()
    }

    pub fn put_responses_given(&self) -> Vec<ResponseMessage> {
        self.put_responses_given.clone()
    }

    pub fn post_responses_given(&self) -> Vec<ResponseMessage> {
        self.post_responses_given.clone()
    }

    pub fn delete_responses_given(&self) -> Vec<ResponseMessage> {
        self.delete_responses_given.clone()
    }

    pub fn refresh_requests_given(&self) -> Vec<RequestMessage> {
        self.refresh_requests_given.clone()
    }

    // -----------  the following methods are expected to be API functions   ------------- //
    pub fn send_get_request(&mut self,
                            src: Authority,
                            dst: Authority,
                            content: RequestContent)
                            -> Result<(), InterfaceError> {
        let message = self.send_request(src, dst, content, "Mock Get Request");
        Ok(self.get_requests_given.push(message))
    }

    pub fn send_put_request(&mut self,
                            src: Authority,
                            dst: Authority,
                            content: RequestContent)
                            -> Result<(), InterfaceError> {
        let message = self.send_request(src, dst, content, "Mock Put Request");
        Ok(self.put_requests_given.push(message))
    }

    pub fn send_post_request(&mut self,
                             src: Authority,
                             dst: Authority,
                             content: RequestContent)
                             -> Result<(), InterfaceError> {
        let message = self.send_request(src, dst, content, "Mock Post Request");
        Ok(self.post_requests_given.push(message))
    }

    pub fn send_delete_request(&mut self,
                               src: Authority,
                               dst: Authority,
                               content: RequestContent)
                               -> Result<(), InterfaceError> {
        let message = self.send_request(src, dst, content, "Mock Delete Request");
        Ok(self.delete_requests_given.push(message))
    }

    pub fn send_get_response(&mut self,
                             src: Authority,
                             dst: Authority,
                             content: ResponseContent)
                             -> Result<(), InterfaceError> {
        let message = self.send_response(src, dst, content, "Mock Get Response");
        Ok(self.get_responses_given.push(message))
    }

    pub fn send_put_response(&mut self,
                             src: Authority,
                             dst: Authority,
                             content: ResponseContent)
                             -> Result<(), InterfaceError> {
        let message = self.send_response(src, dst, content, "Mock Put Response");
        Ok(self.put_responses_given.push(message))
    }

    pub fn send_post_response(&mut self,
                              src: Authority,
                              dst: Authority,
                              content: ResponseContent)
                              -> Result<(), InterfaceError> {
        let message = self.send_response(src, dst, content, "Mock Post Response");
        Ok(self.post_responses_given.push(message))
    }

    pub fn send_delete_response(&mut self,
                                src: Authority,
                                dst: Authority,
                                content: ResponseContent)
                                -> Result<(), InterfaceError> {
        let message = self.send_response(src, dst, content, "Mock Delete Response");
        Ok(self.delete_responses_given.push(message))
    }

    pub fn send_refresh_request(&mut self,
                                src: Authority,
                                nonce: hash::sha512::Digest,
                                content: Vec<u8>)
                                -> Result<(), InterfaceError> {
        let request_content = RequestContent::Refresh {
            nonce: nonce,
            content: content,
        };
        let message = self.send_request(src.clone(), src, request_content, "Mock Refresh Request");
        Ok(self.refresh_requests_given.push(message))
    }

    pub fn stop(&mut self) {
        let _ = self.sender.send(Event::Terminated);
    }

    pub fn close_group_including_self(&self) -> Vec<XorName> {
        let mut peers_and_us = Vec::with_capacity(group_size() + 1);
        peers_and_us.push(self.our_id.clone());
        peers_and_us.append(&mut self.peers.clone());
        peers_and_us
    }

    fn send_request(&self,
                    src: Authority,
                    dst: Authority,
                    content: RequestContent,
                    thread_name: &str)
                    -> RequestMessage {
        let message = RequestMessage {
            src: src,
            dst: dst,
            content: content,
        };
        let cloned_message = message.clone();
        let simulated_latency = self.simulated_latency.clone();
        let sender = self.sender.clone();
        let _ = thread!(thread_name, move || {
            sleep(simulated_latency);
            let _ = unwrap_result!(sender.send(Event::Request(cloned_message)));
        });
        message
    }

    fn send_response(&self,
                     src: Authority,
                     dst: Authority,
                     content: ResponseContent,
                     thread_name: &str)
                     -> ResponseMessage {
        let sender = match &dst {
            &Authority::Client{ .. } => self.client_sender.clone(),
            _ => self.sender.clone(),
        };
        let message = ResponseMessage {
            src: src,
            dst: dst,
            content: content,
        };
        let cloned_message = message.clone();
        let simulated_latency = self.simulated_latency.clone();
        let _ = thread!(thread_name, move || {
            sleep(simulated_latency);
            let _ = unwrap_result!(sender.send(Event::Response(cloned_message)));
        });
        message
    }
}
