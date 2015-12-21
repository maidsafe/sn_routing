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

#![cfg(all(test, feature = "use-mock-routing"))]

#![allow(unused)]

mod mock_routing_impl;

use self::mock_routing_impl::MockRoutingImpl;
use routing::{Authority, Data, DataRequest, Event, ImmutableData, ImmutableDataType, InterfaceError, RequestContent, RequestMessage,
              ResponseContent, ResponseMessage, RoutingError};
use sodiumoxide::crypto::sign::PublicKey;
use std::sync::{Arc, Mutex, mpsc};
use xor_name::XorName;

pub struct MockRouting {
    pimpl: Arc<Mutex<MockRoutingImpl>>,
}

impl MockRouting {
    pub fn new(event_sender: mpsc::Sender<Event>) -> Result<MockRouting, RoutingError> {
        Ok(MockRouting { pimpl: Arc::new(Mutex::new(MockRoutingImpl::new(event_sender))) })
    }

    pub fn get_client_receiver(&mut self) -> mpsc::Receiver<Event> {
        unwrap_result!(self.pimpl.lock()).get_client_receiver()
    }

    // -----------  the following methods are for testing purpose only   ------------- //
    pub fn client_get(&mut self, client_address: XorName, client_pub_key: PublicKey, data_request: DataRequest) {
        let src = Authority::Client{client_key: client_pub_key, proxy_node_name: client_address};
        unwrap_result!(self.pimpl.lock()).client_get(src, data_request)
    }

    pub fn client_put(&mut self, client_address: XorName, client_pub_key: PublicKey, data: Data) {
        let src = Authority::Client{client_key: client_pub_key, proxy_node_name: client_address};
        unwrap_result!(self.pimpl.lock()).client_put(src, data)
    }

    pub fn client_post(&mut self, client_address: XorName, client_pub_key: PublicKey, data: Data) {
        let src = Authority::Client{client_key: client_pub_key, proxy_node_name: client_address};
        unwrap_result!(self.pimpl.lock()).client_post(src, data)
    }

    pub fn client_delete(&mut self, client_address: XorName, client_pub_key: PublicKey, data: Data) {
        let src = Authority::Client{client_key: client_pub_key, proxy_node_name: client_address};
        unwrap_result!(self.pimpl.lock()).client_delete(src, data)
    }

    pub fn churn_event(&mut self, nodes: Vec<XorName>, churn_node: XorName) {
        unwrap_result!(self.pimpl.lock()).churn_event(nodes, churn_node)
    }

    #[allow(dead_code)]
    pub fn get_requests_given(&self) -> Vec<RequestMessage> {
        unwrap_result!(self.pimpl.lock()).get_requests_given()
    }

    pub fn put_requests_given(&self) -> Vec<RequestMessage> {
        unwrap_result!(self.pimpl.lock()).put_requests_given()
    }

    pub fn post_requests_given(&self) -> Vec<RequestMessage> {
        unwrap_result!(self.pimpl.lock()).post_requests_given()
    }

    pub fn delete_requests_given(&self) -> Vec<RequestMessage> {
        unwrap_result!(self.pimpl.lock()).delete_requests_given()
    }

    #[allow(dead_code)]
    pub fn get_responses_given(&self) -> Vec<ResponseMessage> {
        unwrap_result!(self.pimpl.lock()).get_responses_given()
    }

    #[allow(dead_code)]
    pub fn put_responses_given(&self) -> Vec<ResponseMessage> {
        unwrap_result!(self.pimpl.lock()).put_responses_given()
    }

    pub fn post_responses_given(&self) -> Vec<ResponseMessage> {
        unwrap_result!(self.pimpl.lock()).post_responses_given()
    }

    pub fn delete_responses_given(&self) -> Vec<ResponseMessage> {
        unwrap_result!(self.pimpl.lock()).delete_responses_given()
    }

    #[allow(dead_code)]
    pub fn refresh_requests_given(&self) -> Vec<RequestMessage> {
        unwrap_result!(self.pimpl.lock()).refresh_requests_given()
    }



    // -----------  the following methods are expected to be API functions   ------------- //
    pub fn send_get_request(&self,
                            src: Authority,
                            dst: Authority,
                            content: RequestContent)
                            -> Result<(), InterfaceError> {
        unwrap_result!(self.pimpl.lock()).send_get_request(src, dst, content)
    }

    pub fn send_put_request(&self,
                            src: Authority,
                            dst: Authority,
                            content: RequestContent)
                            -> Result<(), InterfaceError> {
        unwrap_result!(self.pimpl.lock()).send_put_request(src, dst, content)
    }

    pub fn send_post_request(&self,
                             src: Authority,
                             dst: Authority,
                             content: RequestContent)
                             -> Result<(), InterfaceError> {
        unwrap_result!(self.pimpl.lock()).send_post_request(src, dst, content)
    }

    pub fn send_delete_request(&self,
                               src: Authority,
                               dst: Authority,
                               content: RequestContent)
                               -> Result<(), InterfaceError> {
        unwrap_result!(self.pimpl.lock()).send_delete_request(src, dst, content)
    }

    pub fn send_get_response(&self,
                             src: Authority,
                             dst: Authority,
                             content: ResponseContent)
                             -> Result<(), InterfaceError> {
        unwrap_result!(self.pimpl.lock()).send_get_response(src, dst, content)
    }

    pub fn send_put_response(&self,
                             src: Authority,
                             dst: Authority,
                             content: ResponseContent)
                             -> Result<(), InterfaceError> {
        unwrap_result!(self.pimpl.lock()).send_put_response(src, dst, content)
    }

    pub fn send_post_response(&self,
                              src: Authority,
                              dst: Authority,
                              content: ResponseContent)
                              -> Result<(), InterfaceError> {
        unwrap_result!(self.pimpl.lock()).send_post_response(src, dst, content)
    }

    pub fn send_delete_response(&self,
                                src: Authority,
                                dst: Authority,
                                content: ResponseContent)
                                -> Result<(), InterfaceError> {
        unwrap_result!(self.pimpl.lock()).send_delete_response(src, dst, content)
    }

    pub fn send_refresh_request(&self,
                                type_tag: u64,
                                src: Authority,
                                content: Vec<u8>,
                                cause: XorName)
                                -> Result<(), InterfaceError> {
        unwrap_result!(self.pimpl.lock()).send_refresh_request(type_tag, src, content, cause)
    }

    pub fn stop(&self) {
        unwrap_result!(self.pimpl.lock()).stop()
    }
}
