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
use rand::{Rng, XorShiftRng};
use routing::{self, Authority, Data, DataIdentifier, Event, FullId, MessageId, PublicId, Response,
              StructuredData, XorName};
use routing::mock_crust::{self, Config, Network, ServiceHandle};
use routing::client_errors::{GetError, MutationError};

use super::test_node::TestNode;
use super::poll;

/// Client for use in tests only
pub struct TestClient {
    _handle: ServiceHandle,
    routing_client: routing::Client,
    routing_rx: Receiver<Event>,
    full_id: FullId,
    public_id: PublicId,
    name: XorName,
    rng: XorShiftRng,
}

impl TestClient {
    /// Create a test client for the mock network
    pub fn new(network: &Network, config: Option<Config>) -> Self {
        let (routing_tx, routing_rx) = mpsc::channel();

        let full_id = FullId::new();
        let public_id = *full_id.public_id();

        let handle = network.new_service_handle(config, None);
        let client = mock_crust::make_current(&handle, || {
            unwrap_result!(routing::Client::new(routing_tx, Some(full_id.clone())))
        });

        TestClient {
            _handle: handle,
            routing_client: client,
            routing_rx: routing_rx,
            full_id: full_id,
            public_id: public_id,
            name: *public_id.name(),
            rng: network.new_rng(),
        }
    }
    /// empty this client event loop
    pub fn poll(&mut self) -> usize {
        let mut result = 0;

        while self.routing_client.poll() {
            result += 1;
        }

        result
    }

    /// Resend all unacknowledged messages.
    pub fn resend_unacknowledged(&self) -> bool {
        self.routing_client.resend_unacknowledged()
    }

    /// check client successfully connected to mock network
    pub fn ensure_connected(&mut self, nodes: &mut [TestNode]) {
        let _ = poll::nodes_and_client(nodes, self);

        match self.routing_rx.try_recv() {
            Ok(Event::Connected) => (),
            e => panic!("Expected Ok(Event::Connected), got {:?}", e),
        }
    }

    /// create an account and store it
    pub fn create_account(&mut self, nodes: &mut [TestNode]) {
        let account =
            unwrap_result!(StructuredData::new(0, self.rng.gen(), 0, vec![], vec![], vec![], None));

        unwrap_result!(self.put_and_verify(Data::Structured(account), nodes));
    }

    fn flush(&mut self) {
        while let Ok(_) = self.routing_rx.try_recv() {}
    }

    /// Try and get data from nodes provided.
    pub fn get(&mut self, request: DataIdentifier, nodes: &mut [TestNode]) -> Data {
        self.get_with_src(request, nodes).0
    }

    /// Try to get data from the given nodes. Returns the retrieved data and
    /// the source authority the data was sent by.
    pub fn get_with_src(&mut self,
                        request: DataIdentifier,
                        nodes: &mut [TestNode])
                        -> (Data, Authority) {
        let dst = Authority::NaeManager(*request.name());
        let request_message_id = MessageId::new();
        self.flush();

        unwrap_result!(self.routing_client.send_get_request(dst, request, request_message_id));
        let _ = poll::nodes_and_client(nodes, self);

        loop {
            match self.routing_rx.try_recv() {
                Ok(Event::Response {
                    response: Response::GetSuccess(data, response_message_id),
                    src,
                    ..
                }) => {
                    if request_message_id == response_message_id {
                        return (data, src);
                    } else {
                        warn!("{:?}  --   {:?}", request_message_id, response_message_id);
                    }
                }
                event => panic!("Expected GetSuccess, got: {:?}", event),
            }
        }
    }

    /// Sends a Get request, polls the mock network and expects a Get response
    pub fn get_response(&mut self,
                        request: DataIdentifier,
                        nodes: &mut [TestNode])
                        -> Result<Data, Option<GetError>> {
        let dst = Authority::NaeManager(*request.name());
        let request_message_id = MessageId::new();
        self.flush();
        unwrap_result!(self.routing_client
            .send_get_request(dst.clone(), request, request_message_id));
        let events_count = poll::nodes_and_client(nodes, self);
        trace!("totally {} events got processed during the get_response",
               events_count);
        loop {
            match self.routing_rx.try_recv() {
                Ok(Event::Response {
                    response: Response::GetSuccess(data, response_message_id),
                    ..
                }) => {
                    assert_eq!(request_message_id, response_message_id);
                    return Ok(data);
                }
                Ok(Event::Response {
                    response: Response::GetFailure { id, external_error_indicator, .. },
                    src,
                    ..
                }) => {
                    assert_eq!(request_message_id, id);
                    assert_eq!(src, dst);
                    let parsed_error: GetError =
                        unwrap_result!(serialisation::deserialise(&external_error_indicator));
                    return Err(Some(parsed_error));
                }
                Ok(response) => panic!("Unexpected Get response : {:?}", response),
                Err(err) => panic!("Unexpected error : {:?}", err),
            }
        }
    }

    /// Sends a Post request, polls the mock network and expects a Post response
    pub fn post_response(&mut self,
                         data: Data,
                         nodes: &mut [TestNode])
                         -> Result<DataIdentifier, Option<MutationError>> {
        let dst = Authority::NaeManager(*data.name());
        let request_message_id = MessageId::new();
        unwrap_result!(self.routing_client
            .send_post_request(dst.clone(), data, request_message_id));
        let events_count = poll::nodes_and_client(nodes, self);
        trace!("totally {} events got processed during the post_response",
               events_count);
        loop {
            match self.routing_rx.try_recv() {
                Ok(Event::Response {
                    response: Response::PostSuccess(data_id, response_message_id),
                    ..
                }) => {
                    assert_eq!(request_message_id, response_message_id);
                    return Ok(data_id);
                }
                Ok(Event::Response {
                    response: Response::PostFailure { id, external_error_indicator, .. },
                    src,
                    ..
                }) => {
                    assert_eq!(request_message_id, id);
                    assert_eq!(src, dst);
                    let parsed_error: MutationError =
                        unwrap_result!(serialisation::deserialise(&external_error_indicator));
                    return Err(Some(parsed_error));
                }
                Ok(response) => panic!("Unexpected Post response : {:?}", response),
                Err(err) => panic!("Unexpected error : {:?}", err),
            }
        }
    }

    /// Sends a Delete request, polls the mock network and expects a Delete response
    pub fn delete_response(&mut self,
                           data: Data,
                           nodes: &mut [TestNode])
                           -> Result<DataIdentifier, Option<MutationError>> {
        let dst = Authority::NaeManager(*data.name());
        let request_message_id = MessageId::new();
        unwrap_result!(self.routing_client
            .send_delete_request(dst.clone(), data, request_message_id));
        let events_count = poll::nodes_and_client(nodes, self);
        trace!("totally {} events got processed during the delete_response",
               events_count);
        loop {
            match self.routing_rx.try_recv() {
                Ok(Event::Response {
                    response: Response::DeleteSuccess(data_id, response_id),
                    ..
                }) => {
                    assert_eq!(request_message_id, response_id);
                    return Ok(data_id);
                }
                Ok(Event::Response {
                    response: Response::DeleteFailure { id, external_error_indicator, .. },
                    src,
                    ..
                }) => {
                    assert_eq!(request_message_id, id);
                    assert_eq!(src, dst);
                    let parsed_error: MutationError =
                        unwrap_result!(serialisation::deserialise(&external_error_indicator));
                    return Err(Some(parsed_error));
                }
                Ok(response) => panic!("Unexpected Delete response : {:?}", response),
                Err(err) => panic!("Unexpected error : {:?}", err),
            }
        }
    }

    /// Sends a GetAccountInfo request, polls the mock network and expects a GetAccountInfo response
    pub fn get_account_info_response(&mut self,
                                     nodes: &mut [TestNode])
                                     -> Result<(u64, u64), Option<GetError>> {
        let request_message_id = MessageId::new();
        self.flush();
        let dst = Authority::ClientManager(*self.public_id.name());
        unwrap_result!(self.routing_client
            .send_get_account_info_request(dst, request_message_id));
        let events_count = poll::nodes_and_client(nodes, self);
        trace!("totally {} events got processed during the get_account_info_response",
               events_count);
        loop {
            match self.routing_rx.try_recv() {
                Ok(Event::Response { response: Response::GetAccountInfoSuccess { id,
                                                                       data_stored,
                                                                       space_available },
                                     .. }) => {
                    assert_eq!(request_message_id, id);
                    return Ok((data_stored, space_available));
                }
                Ok(Event::Response {
                    response: Response::GetAccountInfoFailure { id, external_error_indicator },
                    ..
                }) => {
                    assert_eq!(request_message_id, id);
                    let parsed_error: GetError =
                        unwrap_result!(serialisation::deserialise(&external_error_indicator));
                    return Err(Some(parsed_error));
                }
                Ok(response) => panic!("Unexpected GetAccountInfo response : {:?}", response),
                Err(err) => panic!("Unexpected error : {:?}", err),
            }
        }
    }

    /// Post request
    pub fn post(&mut self, data: Data) {
        let dst = Authority::NaeManager(*data.name());
        let request_message_id = MessageId::new();
        unwrap_result!(self.routing_client.send_post_request(dst, data, request_message_id));
    }
    /// Put request
    pub fn put(&mut self, data: Data) {
        let dst = Authority::ClientManager(*self.public_id.name());
        let request_message_id = MessageId::new();
        unwrap_result!(self.routing_client.send_put_request(dst, data, request_message_id));
    }
    /// Delete request
    pub fn delete(&mut self, data: Data) {
        let dst = Authority::NaeManager(*data.name());
        let request_message_id = MessageId::new();
        unwrap_result!(self.routing_client.send_delete_request(dst, data, request_message_id));
    }
    /// Put data and read from mock network
    pub fn put_and_verify(&mut self,
                          data: Data,
                          nodes: &mut [TestNode])
                          -> Result<(), Option<MutationError>> {
        let dst = Authority::ClientManager(*self.public_id.name());
        let request_message_id = MessageId::new();
        unwrap_result!(self.routing_client.send_put_request(dst, data.clone(), request_message_id));
        let _ = poll::poll_and_resend_unacknowledged(nodes, self);

        match self.routing_rx.try_recv() {
            Ok(Event::Response { response: Response::PutSuccess(_, response_message_id), .. }) => {
                assert_eq!(request_message_id, response_message_id);
                Ok(())
            }
            Ok(Event::Response { response: Response::PutFailure {
                    id: response_id,
                    data_id,
                    external_error_indicator: response_error
                }, .. }) => {
                assert_eq!(request_message_id, response_id);
                assert!(data.identifier() == data_id);
                let parsed_error = unwrap_result!(serialisation::deserialise(&response_error));
                Err(Some(parsed_error))
            }
            Ok(response) => panic!("Unexpected Put response : {:?}", response),
            // TODO: Once the network guarantees that every request gets a response, panic!
            Err(_) => Err(None),
        }
    }
    /// Return a full id for this client
    pub fn full_id(&self) -> &FullId {
        &self.full_id
    }
    /// Return client's network name
    pub fn name(&self) -> &XorName {
        &self.name
    }
}
