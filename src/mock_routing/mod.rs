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

mod api_calls;
mod mock_routing_impl;

pub struct MockRouting {
    pimpl: ::std::sync::Arc<::std::sync::Mutex<mock_routing_impl::MockRoutingImpl>>,
}

impl MockRouting {
    pub fn new(event_sender: ::std::sync::mpsc::Sender<(::routing::event::Event)>) -> MockRouting {
        MockRouting {
            pimpl: ::std::sync::Arc::new(::std::sync::Mutex::new(
                mock_routing_impl::MockRoutingImpl::new(event_sender))),
        }
    }

    pub fn get_client_receiver(&mut self) -> ::std::sync::mpsc::Receiver<::routing::data::Data> {
        evaluate_result!(self.pimpl.lock()).get_client_receiver()
    }

    // -----------  the following methods are for testing purpose only   ------------- //
    pub fn client_get(&mut self,
                      client_address: XorName,
                      client_pub_key: ::sodiumoxide::crypto::sign::PublicKey,
                      data_request: ::routing::data::DataRequest) {
        evaluate_result!(self.pimpl.lock()).client_get(client_address, client_pub_key, data_request)
    }

    pub fn client_put(&mut self,
                      client_address: XorName,
                      client_pub_key: ::sodiumoxide::crypto::sign::PublicKey,
                      data: ::routing::data::Data) {
        evaluate_result!(self.pimpl.lock()).client_put(client_address, client_pub_key, data)
    }

    pub fn client_post(&mut self,
                       client_address: XorName,
                       client_pub_key: ::sodiumoxide::crypto::sign::PublicKey,
                       data: ::routing::data::Data) {
        evaluate_result!(self.pimpl.lock()).client_post(client_address, client_pub_key, data)
    }

    pub fn churn_event(&mut self, nodes: Vec<XorName>,
                       churn_node: XorName) {
        evaluate_result!(self.pimpl.lock()).churn_event(nodes, churn_node)
    }

    #[allow(dead_code)]
    pub fn get_requests_given(&self) -> Vec<api_calls::GetRequest> {
        evaluate_result!(self.pimpl.lock()).get_requests_given()
    }

    #[allow(dead_code)]
    pub fn get_responses_given(&self) -> Vec<api_calls::GetResponse> {
        evaluate_result!(self.pimpl.lock()).get_responses_given()
    }

    pub fn put_requests_given(&self) -> Vec<api_calls::PutRequest> {
        evaluate_result!(self.pimpl.lock()).put_requests_given()
    }

    #[allow(dead_code)]
    pub fn put_responses_given(&self) -> Vec<api_calls::PutResponse> {
        evaluate_result!(self.pimpl.lock()).put_responses_given()
    }

    #[allow(dead_code)]
    pub fn refresh_requests_given(&self) -> Vec<api_calls::RefreshRequest> {
        evaluate_result!(self.pimpl.lock()).refresh_requests_given()
    }



    // -----------  the following methods are expected to be API functions   ------------- //
    pub fn get_request(&self,
                       our_authority: ::routing::Authority,
                       location: ::routing::Authority,
                       request_for: ::routing::data::DataRequest) {
        evaluate_result!(self.pimpl.lock()).get_request(our_authority, location, request_for)
    }

    pub fn get_response(&self,
                        our_authority: ::routing::Authority,
                        location: ::routing::Authority,
                        data: ::routing::data::Data,
                        data_request: ::routing::data::DataRequest,
                        response_token: Option<::routing::SignedToken>) {
        evaluate_result!(self.pimpl.lock())
            .get_response(our_authority, location, data, data_request, response_token)
    }

    pub fn put_request(&mut self,
                       our_authority: ::routing::Authority,
                       location: ::routing::Authority,
                       data: ::routing::data::Data) {
        evaluate_result!(self.pimpl.lock()).put_request(our_authority, location, data)
    }

    pub fn put_response(&self,
                        our_authority: ::routing::Authority,
                        location: ::routing::Authority,
                        response_error: ::routing::error::ResponseError,
                        signed_token: Option<::routing::SignedToken>) {
        evaluate_result!(self.pimpl.lock())
            .put_response(our_authority, location, response_error, signed_token)
    }

    pub fn refresh_request(&self,
                           type_tag: u64,
                           our_authority: ::routing::Authority,
                           content: Vec<u8>,
                           churn_node: XorName) {
        evaluate_result!(self.pimpl.lock()).refresh_request(type_tag, our_authority,
                                                   content, churn_node)
    }

    pub fn stop(&self) {
        evaluate_result!(self.pimpl.lock()).stop()
    }
}
