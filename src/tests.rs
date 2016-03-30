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

#![cfg(all(test, feature = "use-mock-crust"))]

use rand::{random, thread_rng, Rng};
use routing::{self, Authority, Data, DataRequest, Event, FullId, ImmutableData,
              ImmutableDataType, MessageId, PublicId, ResponseContent,
              ResponseMessage, StructuredData};
use routing::mock_crust::{self, Config, Endpoint, Network, ServiceHandle};
use std::cmp;
use std::iter;
use std::sync::mpsc::{self, Receiver};

use vault::Vault;

struct TestNode {
    handle: ServiceHandle,
    vault: Vault,
}

impl TestNode {
    fn new(network: &Network, config: Option<Config>) -> Self {
        let handle = network.new_service_handle(config, None);
        let vault = mock_crust::make_current(&handle, || {
            unwrap_result!(Vault::new(None))
        });

        TestNode {
            handle: handle,
            vault: vault,
        }
    }

    fn poll(&mut self) -> bool {
        let mut result = false;

        while self.vault.poll() {
            result = true;
        }

        result
    }

    fn endpoint(&self) -> Endpoint {
        self.handle.endpoint()
    }
}

struct TestClient {
    handle: ServiceHandle,
    routing_client: routing::Client,
    routing_rx: Receiver<Event>,
    public_id: PublicId,
}

impl TestClient {
    fn new(network: &Network,  config: Option<Config>) -> Self {
        let (routing_tx, routing_rx) = mpsc::channel();

        let full_id = FullId::new();
        let public_id = full_id.public_id().clone();

        let handle = network.new_service_handle(config, None);
        let client = mock_crust::make_current(&handle, || {
            unwrap_result!(routing::Client::new(routing_tx, Some(full_id)))
        });

        TestClient {
            handle: handle,
            routing_client: client,
            routing_rx: routing_rx,
            public_id: public_id,
        }
    }

    fn poll(&mut self) -> bool {
        let mut result = false;

        while self.routing_client.poll() {
            result = true;
        }

        result
    }

    fn ensure_connected(&mut self, nodes: &mut [TestNode]) {
        poll_nodes_and_client(nodes, self);

        match self.routing_rx.try_recv() {
            Ok(Event::Connected) => (),
            e => panic!("Expected Ok(Event::Connected), got {:?}", e),
        }
    }

    fn create_account(&mut self, nodes: &mut [TestNode]) {
        let account = unwrap_result!(StructuredData::new(0,
                                                         random(),
                                                         0,
                                                         vec![],
                                                         vec![],
                                                         vec![],
                                                         None));

        self.put(Data::Structured(account), nodes);
    }

    fn get(&mut self, request: DataRequest, nodes: &mut [TestNode]) -> Data {
        let dst = Authority::NaeManager(request.name());
        let request_message_id = MessageId::new();

        unwrap_result!(self.routing_client.send_get_request(dst, request, request_message_id));
        poll_nodes_and_client(nodes, self);

        match self.routing_rx.try_recv() {
            Ok(Event::Response(ResponseMessage{
                content: ResponseContent::GetSuccess(data, response_message_id),
                ..
            })) => {
                assert_eq!(request_message_id, response_message_id);
                return data;
            }

            r => panic!("Expected GetSuccess, got: {:?}", r),
        }
    }

    fn put(&mut self, data: Data, nodes: &mut [TestNode]) {
        let dst = Authority::ClientManager(*self.public_id.name());
        let request_message_id = MessageId::new();

        unwrap_result!(self.routing_client.send_put_request(dst, data, request_message_id));
        poll_nodes_and_client(nodes, self);

        match self.routing_rx.try_recv() {
            Ok(Event::Response(ResponseMessage{
                content: ResponseContent::PutSuccess(_, response_message_id),
                ..
            })) => {
                assert_eq!(request_message_id, response_message_id);
            }

            r => panic!("Expected PutSuccess, got: {:?}", r),
        }
    }
}

fn poll_nodes(nodes: &mut [TestNode]) {
    loop {
        let mut next = false;

        for node in nodes.iter_mut() {
            if node.poll() {
                next = true;
                break;
            }
        }

        if !next {
            break;
        }
    }
}

fn poll_nodes_and_client(nodes: &mut [TestNode], client: &mut TestClient) {
    loop {
        let mut next = false;

        for node in nodes.iter_mut() {
            if node.poll() {
                next = true;
                break;
            }
        }

        if client.poll() {
            next = true;
        }

        if !next {
            break;
        }
    }
}

fn create_nodes(network:& Network, size: usize) -> Vec<TestNode> {
    let mut nodes = Vec::new();

    // Create the seed node.
    nodes.push(TestNode::new(network, None));
    while nodes[0].poll() {}

    let config = Config::with_contacts(&[nodes[0].endpoint()]);

    // Create other nodes using the seed node endpoint as bootstrap contact.
    for i in 1..size {
        nodes.push(TestNode::new(network, Some(config.clone())));
        poll_nodes(&mut nodes);
    }

    nodes
}

#[test]
fn plain_data_put_and_get() {
    let network = Network::new();
    let mut nodes = create_nodes(&network, 8);
    let config = Config::with_contacts(&[nodes[0].endpoint()]);

    let mut client = TestClient::new(&network, Some(config));
    client.ensure_connected(&mut nodes);
    client.create_account(&mut nodes);

    let mut content = vec![0; 8];
    thread_rng().fill_bytes(&mut content);
    let orig_data = ImmutableData::new(ImmutableDataType::Normal, content);

    client.put(Data::Immutable(orig_data.clone()), &mut nodes);

    match client.get(DataRequest::Immutable(orig_data.name(), ImmutableDataType::Normal), &mut nodes) {
        Data::Immutable(data) => {
            assert_eq!(data.name(), orig_data.name());
            assert_eq!(data.value(), orig_data.value());
        },

        d => panic!("Got unexpected data: {:?}", d),
    }
}
