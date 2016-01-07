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
use routing::{Authority, Data, DataRequest, Event, InterfaceError, MessageId, RequestContent, RequestMessage,
              ResponseContent, ResponseMessage};
use sodiumoxide::crypto::hash::sha512;
use std::cmp::{Ordering, min};
use std::sync::mpsc;
use std::thread::sleep;
use std::time::Duration;
use xor_name::{XorName, closer_to_target};

pub struct MockRoutingNodeImpl {
    name: XorName,
    peers: Vec<XorName>,
    sender: mpsc::Sender<Event>,
    client_sender: mpsc::Sender<Event>,
    simulated_latency: Duration,
    get_requests_given: Vec<RequestMessage>,
    put_requests_given: Vec<RequestMessage>,
    post_requests_given: Vec<RequestMessage>,
    delete_requests_given: Vec<RequestMessage>,
    get_successes_given: Vec<ResponseMessage>,
    get_failures_given: Vec<ResponseMessage>,
    put_successes_given: Vec<ResponseMessage>,
    put_failures_given: Vec<ResponseMessage>,
    post_successes_given: Vec<ResponseMessage>,
    post_failures_given: Vec<ResponseMessage>,
    delete_successes_given: Vec<ResponseMessage>,
    delete_failures_given: Vec<ResponseMessage>,
    refresh_requests_given: Vec<RequestMessage>,
}

impl MockRoutingNodeImpl {
    pub fn new(sender: mpsc::Sender<Event>) -> MockRoutingNodeImpl {
        let (client_sender, _) = mpsc::channel();
        let name: XorName = random();
        let mut peers = Vec::with_capacity(optimal_table_size());
        for _ in 0..optimal_table_size() {
            peers.push(random());
        }
        peers.sort_by(|a, b| {
            match closer_to_target(&a, &b, &name) {
                true => Ordering::Less,
                false => Ordering::Greater,
            }
        });

        MockRoutingNodeImpl {
            name: name,
            peers: peers,
            sender: sender,
            client_sender: client_sender,
            simulated_latency: Duration::from_millis(200),
            get_requests_given: vec![],
            put_requests_given: vec![],
            post_requests_given: vec![],
            delete_requests_given: vec![],
            get_successes_given: vec![],
            get_failures_given: vec![],
            put_successes_given: vec![],
            put_failures_given: vec![],
            post_successes_given: vec![],
            post_failures_given: vec![],
            delete_successes_given: vec![],
            delete_failures_given: vec![],
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
                                  RequestContent::Get(data_request, MessageId::new()),
                                  "Mock Client Get Request");
    }

    pub fn client_put(&mut self, src: Authority, data: Data) {
        let _ = self.send_request(src,
                                  Authority::ClientManager(data.name()),
                                  RequestContent::Put(data, MessageId::new()),
                                  "Mock Client Put Request");
    }

    pub fn client_post(&mut self, src: Authority, data: Data) {
        let _ = self.send_request(src,
                                  Authority::NaeManager(data.name()),
                                  RequestContent::Post(data, MessageId::new()),
                                  "Mock Client Post Request");
    }

    pub fn client_delete(&mut self, src: Authority, data: Data) {
        let _ = self.send_request(src,
                                  Authority::ClientManager(data.name()),
                                  RequestContent::Delete(data, MessageId::new()),
                                  "Mock Client Delete Request");
    }

    pub fn churn_event(&mut self, event_id: MessageId, lost_close_node: Option<XorName>) {
        let cloned_sender = self.sender.clone();
        let _ = thread!("Mock Churn Event", move || {
            let _ = cloned_sender.send(Event::Churn {
                id: event_id,
                lost_close_node: lost_close_node,
            });
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

    pub fn get_successes_given(&self) -> Vec<ResponseMessage> {
        self.get_successes_given.clone()
    }

    pub fn get_failures_given(&self) -> Vec<ResponseMessage> {
        self.get_failures_given.clone()
    }

    pub fn put_successes_given(&self) -> Vec<ResponseMessage> {
        self.put_successes_given.clone()
    }

    pub fn put_failures_given(&self) -> Vec<ResponseMessage> {
        self.put_failures_given.clone()
    }

    pub fn post_successes_given(&self) -> Vec<ResponseMessage> {
        self.post_successes_given.clone()
    }

    pub fn post_failures_given(&self) -> Vec<ResponseMessage> {
        self.post_failures_given.clone()
    }

    pub fn delete_successes_given(&self) -> Vec<ResponseMessage> {
        self.delete_successes_given.clone()
    }

    pub fn delete_failures_given(&self) -> Vec<ResponseMessage> {
        self.delete_failures_given.clone()
    }

    pub fn refresh_requests_given(&self) -> Vec<RequestMessage> {
        self.refresh_requests_given.clone()
    }

    // -----------  the following methods are expected to be API functions   ------------- //
    pub fn send_get_request(&mut self,
                            src: Authority,
                            dst: Authority,
                            data_request: DataRequest,
                            id: MessageId)
                            -> Result<(), InterfaceError> {
        let content = RequestContent::Get(data_request, id);
        let message = self.send_request(src, dst, content, "Mock Get Request");
        Ok(self.get_requests_given.push(message))
    }

    pub fn send_put_request(&mut self,
                            src: Authority,
                            dst: Authority,
                            data: Data,
                            id: MessageId)
                            -> Result<(), InterfaceError> {
        let content = RequestContent::Put(data, id);
        let message = self.send_request(src, dst, content, "Mock Put Request");
        Ok(self.put_requests_given.push(message))
    }

    pub fn send_post_request(&mut self,
                             src: Authority,
                             dst: Authority,
                             data: Data,
                             id: MessageId)
                             -> Result<(), InterfaceError> {
        let content = RequestContent::Post(data, id);
        let message = self.send_request(src, dst, content, "Mock Post Request");
        Ok(self.post_requests_given.push(message))
    }

    pub fn send_delete_request(&mut self,
                               src: Authority,
                               dst: Authority,
                               data: Data,
                               id: MessageId)
                               -> Result<(), InterfaceError> {
        let content = RequestContent::Delete(data, id);
        let message = self.send_request(src, dst, content, "Mock Delete Request");
        Ok(self.delete_requests_given.push(message))
    }

    pub fn send_get_success(&mut self,
                            src: Authority,
                            dst: Authority,
                            data: Data,
                            id: MessageId)
                            -> Result<(), InterfaceError> {
        let content = ResponseContent::GetSuccess(data, id);
        let message = self.send_response(src, dst, content, "Mock Get Success");
        Ok(self.get_successes_given.push(message))
    }

    pub fn send_get_failure(&mut self,
                            src: Authority,
                            dst: Authority,
                            request: RequestMessage,
                            external_error_indicator: Vec<u8>,
                            id: MessageId)
                            -> Result<(), InterfaceError> {
        let content = ResponseContent::GetFailure {
            id: id,
            request: request,
            external_error_indicator: external_error_indicator,
        };
        let message = self.send_response(src, dst, content, "Mock Get Failure");
        Ok(self.get_failures_given.push(message))
    }

    pub fn send_put_success(&mut self,
                            src: Authority,
                            dst: Authority,
                            request_hash: sha512::Digest,
                            id: MessageId)
                            -> Result<(), InterfaceError> {
        let content = ResponseContent::PutSuccess(request_hash, id);
        let message = self.send_response(src, dst, content, "Mock Put Success");
        Ok(self.put_successes_given.push(message))
    }

    pub fn send_put_failure(&mut self,
                            src: Authority,
                            dst: Authority,
                            request: RequestMessage,
                            external_error_indicator: Vec<u8>,
                            id: MessageId)
                            -> Result<(), InterfaceError> {
        let content = ResponseContent::PutFailure {
            id: id,
            request: request,
            external_error_indicator: external_error_indicator,
        };
        let message = self.send_response(src, dst, content, "Mock Put Failure");
        Ok(self.put_failures_given.push(message))
    }

    pub fn send_post_success(&mut self,
                             src: Authority,
                             dst: Authority,
                             request_hash: sha512::Digest,
                             id: MessageId)
                             -> Result<(), InterfaceError> {
        let content = ResponseContent::PostSuccess(request_hash, id);
        let message = self.send_response(src, dst, content, "Mock Post Success");
        Ok(self.post_successes_given.push(message))
    }

    pub fn send_post_failure(&mut self,
                             src: Authority,
                             dst: Authority,
                             request: RequestMessage,
                             external_error_indicator: Vec<u8>,
                             id: MessageId)
                             -> Result<(), InterfaceError> {
        let content = ResponseContent::PostFailure {
            id: id,
            request: request,
            external_error_indicator: external_error_indicator,
        };
        let message = self.send_response(src, dst, content, "Mock Post Failure");
        Ok(self.post_failures_given.push(message))
    }

    pub fn send_delete_success(&mut self,
                               src: Authority,
                               dst: Authority,
                               request_hash: sha512::Digest,
                               id: MessageId)
                               -> Result<(), InterfaceError> {
        let content = ResponseContent::DeleteSuccess(request_hash, id);
        let message = self.send_response(src, dst, content, "Mock Delete Success");
        Ok(self.delete_successes_given.push(message))
    }

    pub fn send_delete_failure(&mut self,
                               src: Authority,
                               dst: Authority,
                               request: RequestMessage,
                               external_error_indicator: Vec<u8>,
                               id: MessageId)
                               -> Result<(), InterfaceError> {
        let content = ResponseContent::DeleteFailure {
            id: id,
            request: request,
            external_error_indicator: external_error_indicator,
        };
        let message = self.send_response(src, dst, content, "Mock Delete Failure");
        Ok(self.delete_failures_given.push(message))
    }

    pub fn send_refresh_request(&mut self, src: Authority, content: Vec<u8>) -> Result<(), InterfaceError> {
        let content = RequestContent::Refresh(content);
        let message = self.send_request(src.clone(), src, content, "Mock Refresh Request");
        Ok(self.refresh_requests_given.push(message))
    }

    pub fn name(&self) -> Result<XorName, InterfaceError> {
        Ok(self.name.clone())
    }

    pub fn close_group(&self) -> Result<Vec<XorName>, InterfaceError> {
        Ok(self.peers.iter().take(group_size()).cloned().collect())
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
