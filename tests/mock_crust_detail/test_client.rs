// Copyright 2016 MaidSafe.net limited.
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

use std::sync::mpsc::{self, Receiver};

use maidsafe_utilities::serialisation;
use rand::random;
use routing::{self, Authority, Data, DataRequest, Event, FullId, MessageId, PublicId,
              RequestContent, ResponseContent, ResponseMessage, StructuredData};
use routing::mock_crust::{self, Config, Network, ServiceHandle};
use safe_network_common::client_errors::MutationError;
use sodiumoxide::crypto::sign;
use xor_name::XorName;

use super::test_node::TestNode;
use super::poll;

pub struct TestClient {
    _handle: ServiceHandle,
    routing_client: routing::Client,
    routing_rx: Receiver<Event>,
    full_id: FullId,
    public_id: PublicId,
    name: XorName,
}

impl TestClient {
    pub fn new(network: &Network, config: Option<Config>) -> Self {
        let (routing_tx, routing_rx) = mpsc::channel();

        let full_id = FullId::new();
        let public_id = full_id.public_id().clone();

        let handle = network.new_service_handle(config, None);
        let client = mock_crust::make_current(&handle, || {
            unwrap_result!(routing::Client::new(routing_tx, Some(full_id.clone()), false))
        });

        TestClient {
            _handle: handle,
            routing_client: client,
            routing_rx: routing_rx,
            full_id: full_id,
            public_id: public_id,
            name: *public_id.name(),
        }
    }

    pub fn poll(&mut self) -> bool {
        let mut result = false;

        while self.routing_client.poll() {
            result = true;
        }

        result
    }

    pub fn ensure_connected(&mut self, nodes: &mut [TestNode]) {
        poll::nodes_and_client(nodes, self);

        match self.routing_rx.try_recv() {
            Ok(Event::Connected) => (),
            e => panic!("Expected Ok(Event::Connected), got {:?}", e),
        }
    }

    pub fn create_account(&mut self, nodes: &mut [TestNode]) {
        let account = unwrap_result!(StructuredData::new(0,
                                                         random(),
                                                         0,
                                                         vec![],
                                                         vec![],
                                                         vec![],
                                                         None));

        unwrap_result!(self.put_and_verify(Data::Structured(account), nodes));
    }

    fn flush(&mut self) {
        while let Ok(_) = self.routing_rx.try_recv() {}
    }

    pub fn get(&mut self, request: DataRequest, nodes: &mut [TestNode]) -> Data {
        let dst = Authority::NaeManager(request.name());
        let request_message_id = MessageId::new();
        self.flush();

        unwrap_result!(self.routing_client.send_get_request(dst, request, request_message_id));
        poll::nodes_and_client(nodes, self);

        loop {
            match self.routing_rx.try_recv() {
                Ok(Event::Response(ResponseMessage{
                    content: ResponseContent::GetSuccess(data, response_message_id),
                    ..
                })) => {
                    if request_message_id == response_message_id {
                        return data;
                    } else {
                        println!("{:?}  --   {:?}", request_message_id, response_message_id);
                    }
                }
                event => panic!("Expected GetSuccess, got: {:?}", event),
            }
        }
    }

    pub fn post(&mut self, data: Data) {
        let dst = Authority::ClientManager(*self.public_id.name());
        let request_message_id = MessageId::new();
        unwrap_result!(self.routing_client.send_post_request(dst, data, request_message_id));
    }

    pub fn put(&mut self, data: Data) {
        let dst = Authority::ClientManager(*self.public_id.name());
        let request_message_id = MessageId::new();
        unwrap_result!(self.routing_client.send_put_request(dst, data, request_message_id));
    }

    pub fn put_and_verify(&mut self,
                          data: Data,
                          nodes: &mut [TestNode])
                          -> Result<(), MutationError> {
        let dst = Authority::ClientManager(*self.public_id.name());
        let request_message_id = MessageId::new();
        unwrap_result!(self.routing_client.send_put_request(dst, data.clone(), request_message_id));
        poll::nodes_and_client(nodes, self);

        match self.routing_rx.try_recv() {
            Ok(Event::Response(ResponseMessage{
                content: ResponseContent::PutSuccess(_, response_message_id),
                ..
            })) => {
                assert_eq!(request_message_id, response_message_id);
                Ok(())
            }
            Ok(Event::Response(ResponseMessage{
                content: ResponseContent::PutFailure{ id: response_id, request, external_error_indicator: response_error },
                ..
            })) => {
                assert_eq!(request_message_id, response_id);
                if let RequestContent::Put(returned_data, returned_id) = request.content {
                    assert!(data == returned_data);
                    assert_eq!(request_message_id, returned_id);
                } else {
                    panic!("Got wrong request included in Put response");
                }
                let parsed_error = unwrap_result!(serialisation::deserialise(&response_error));
                Err(parsed_error)
            }
            event => panic!("Expected Put response got: {:?}", event),
        }
    }

    pub fn signing_private_key(&self) -> &sign::SecretKey {
        self.full_id.signing_private_key()
    }

    pub fn name(&self) -> &XorName {
        &self.name
    }
}
