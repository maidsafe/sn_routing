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

use std::fmt::{self, Debug, Formatter};
use std::sync::mpsc::{self, TryRecvError};
use std::thread;
use std::time::Duration;
use sodiumoxide::crypto;
use maidsafe_utilities::serialisation::{deserialise, serialise};
use rand::random;
use routing::{self, Authority, Data, DataRequest, Event, FullId, MessageId, PlainData,
              RequestMessage, RequestContent, ResponseContent, ResponseMessage, StructuredData};
use xor_name::XorName;
use mpid_messaging::{MpidHeader, MpidMessage, MpidMessageWrapper};

// TODO: These are a duplicate of those in src/error.rs until we get a crate for the types which are
// common to Vaults and Core.
#[derive(Debug, RustcEncodable, RustcDecodable)]
pub enum ClientError {
    NoSuchAccount,
    AccountExists,
    NoSuchData,
    DataExists,
    LowBalance,
}

/// A simple example client implementation for a network based on the Routing library.
pub struct Client {
    /// The client interface to the Routing library.
    routing_client: routing::Client,
    /// The receiver through which the Routing library will send events.
    receiver: mpsc::Receiver<Event>,
    /// This client's ID.
    full_id: FullId,
}

impl Client {
    /// Creates a new client and attempts to establish a connection to the network.
    pub fn new() -> Client {
        let (sender, receiver) = mpsc::channel::<Event>();

        // Generate new key pairs. The client's name will be computed from them. This is a
        // requirement for clients: If the name does not match the keys, it will be rejected by the
        // network.
        let sign_keys = crypto::sign::gen_keypair();
        let encrypt_keys = crypto::box_::gen_keypair();
        let full_id = FullId::with_keys(encrypt_keys.clone(), sign_keys.clone());
        info!("Creating Client({:?})", full_id.public_id().name());
        let routing_client = unwrap_result!(routing::Client::new(sender, Some(full_id)));

        let client = Client {
            routing_client: routing_client,
            receiver: receiver,
            full_id: FullId::with_keys(encrypt_keys, sign_keys),
        };

        // Wait for a `Connected` event, notifying us that we are now ready to send requests to the
        // network.
        info!("Waiting for {:?} to connect to network", client);
        let event = client.wait_for_event();
        if let Some(Event::Connected) = event {
            return client;
        }
        panic!("{:?} failed to connect: {:?}", client, event);
    }

    /// Create an account
    pub fn create_account(&mut self) {
        let account = unwrap_result!(StructuredData::new(0,
                                                         random::<XorName>(),
                                                         0,
                                                         vec![],
                                                         vec![],
                                                         vec![],
                                                         None));
        if let ResponseMessage { content: ResponseContent::PutSuccess(..), .. } =
               unwrap_option!(self.put(Data::Structured(account)), "") {
            info!("{:?} created account", self);
        } else {
            panic!("{:?} failed to create account", self)
        }
    }

    /// Send a `Get` request to the network and return the received response.
    pub fn get(&mut self, request: DataRequest) -> Option<ResponseMessage> {
        let message_id = MessageId::new();
        unwrap_result!(self.routing_client
                           .send_get_request(Authority::NaeManager(request.name()),
                                             request.clone(),
                                             message_id));
        self.wait_for_response()
    }

    /// Send a `Put` request to the network.
    pub fn put(&self, data: Data) -> Option<ResponseMessage> {
        let message_id = MessageId::new();
        unwrap_result!(self.routing_client
                           .send_put_request(Authority::ClientManager(*self.name()),
                                             data,
                                             message_id));
        self.wait_for_response()
    }

    /// Post data onto the network.
    pub fn post(&self, data: Data) -> Option<ResponseMessage> {
        let message_id = MessageId::new();
        unwrap_result!(self.routing_client
                           .send_post_request(Authority::NaeManager(data.name()),
                                              data,
                                              message_id));
        self.wait_for_response()
    }

    /// Delete data from the network.
    pub fn delete(&self, data: Data) -> Option<ResponseMessage> {
        let message_id = MessageId::new();
        unwrap_result!(self.routing_client
                           .send_delete_request(Authority::NaeManager(data.name()),
                                                data,
                                                message_id));
        self.wait_for_response()
    }

    /// Register client online.
    pub fn register_online(&self) {
        let wrapper = MpidMessageWrapper::Online;
        let value = unwrap_result!(serialise(&wrapper));
        let data = Data::Plain(PlainData::new(*self.name(), value));
        let message_id = MessageId::new();
        unwrap_result!(self.routing_client
                           .send_post_request(Authority::ClientManager(*self.name()),
                                              data,
                                              message_id));

        if let ResponseMessage { content: ResponseContent::PostSuccess(..), .. } =
               unwrap_option!(self.wait_for_response(), "") {
            trace!("{:?} successfully sent online message", self);
        } else {
            panic!("{:?} failed to send online message", self);
        }
    }

    /// Generate an `MpidMessage` targeting the specified recipient, and its corresponding
    /// PutMessage wrapper.
    pub fn generate_mpid_message(&self, receiver: &XorName) -> (MpidMessage, Data) {
        let metadata = super::generate_random_vec_u8(128);
        let body = super::generate_random_vec_u8(128);
        let mpid_message = unwrap_result!(MpidMessage::new(self.name().clone(),
                                                           metadata,
                                                           receiver.clone(),
                                                           body,
                                                           &self.full_id.signing_private_key()));
        let wrapper = MpidMessageWrapper::PutMessage(mpid_message.clone());
        let name = unwrap_result!(mpid_message.header().name());
        let value = unwrap_result!(serialise(&wrapper));
        let data = Data::Plain(PlainData::new(name, value));
        (mpid_message, data)
    }

    /// Wait to receive an `MpidMessage`.
    pub fn get_mpid_message(&self) -> Option<MpidMessage> {
        if let MpidMessageWrapper::PutMessage(mpid_message) = self.wait_for_wrapper() {
            trace!("{:?} received message {:?}", self, mpid_message);
            Some(mpid_message)
        } else {
            panic!("Unexpected message")
        }
    }

    /// Expect nothing.
    pub fn expect_timeout(&self, timeout: Duration) -> Option<MpidMessage> {
        match self.timed_wait_for_event(timeout) {
            Some(_) => panic!("Unexpected event."),
            None => None,
        }
    }

    /// Delete mpid_header.
    pub fn delete_mpid_header(&self, header_name: XorName) {
        self.messaging_delete_request(*self.name(),
                                      header_name,
                                      MpidMessageWrapper::DeleteHeader(header_name))
    }

    /// Delete mpid_message.
    pub fn delete_mpid_message(&self, target_account: XorName, msg_name: XorName) {
        self.messaging_delete_request(target_account,
                                      msg_name,
                                      MpidMessageWrapper::DeleteMessage(msg_name))
    }

    fn messaging_delete_request(&self,
                                target_account: XorName,
                                name: XorName,
                                wrapper: MpidMessageWrapper) {
        let value = unwrap_result!(serialise(&wrapper));
        let data = Data::Plain(PlainData::new(name, value));
        let message_id = MessageId::new();
        unwrap_result!(self.routing_client
                           .send_delete_request(Authority::ClientManager(target_account),
                                                data,
                                                message_id));
    }

    /// Query outbox.
    pub fn query_outbox(&self) -> Vec<MpidHeader> {
        let name = self.name();
        let value = unwrap_result!(serialise(&MpidMessageWrapper::GetOutboxHeaders));
        let data = Data::Plain(PlainData::new(*name, value));
        let message_id = MessageId::new();
        unwrap_result!(self.routing_client
                           .send_post_request(Authority::ClientManager(*self.name()),
                                              data,
                                              message_id));
        if let MpidMessageWrapper::GetOutboxHeadersResponse(mpid_headers) =
               self.wait_for_wrapper() {
            trace!("{:?} outbox has following mpid_headers {:?}",
                   self,
                   mpid_headers);
            mpid_headers
        } else {
            panic!("Unexpected message")
        }
    }

    /// Query whether outbox has particular message.
    pub fn outbox_has(&self, msg_names: Vec<XorName>) -> Vec<MpidHeader> {
        let name = self.name();
        let value = unwrap_result!(serialise(&MpidMessageWrapper::OutboxHas(msg_names)));
        let data = Data::Plain(PlainData::new(*name, value));
        let message_id = MessageId::new();
        unwrap_result!(self.routing_client
                           .send_post_request(Authority::ClientManager(*self.name()),
                                              data,
                                              message_id));
        if let MpidMessageWrapper::OutboxHasResponse(mpid_headers) = self.wait_for_wrapper() {
            trace!("{:?} outbox has following mpid_headers {:?}",
                   self,
                   mpid_headers);
            mpid_headers
        } else {
            panic!("Unexpected message")
        }
    }

    /// Return network name.
    pub fn name(&self) -> &XorName {
        self.full_id.public_id().name()
    }

    /// Return public signing key.
    pub fn signing_public_key(&self) -> crypto::sign::PublicKey {
        *self.full_id.public_id().signing_public_key()
    }

    /// Return secret signing key.
    pub fn signing_private_key(&self) -> &crypto::sign::SecretKey {
        self.full_id.signing_private_key()
    }

    fn wait_for_wrapper(&self) -> MpidMessageWrapper {
        if let RequestMessage { content: RequestContent::Post(Data::Plain(msg), _), .. } =
               unwrap_option!(self.wait_for_request(), "") {
            let wrapper: MpidMessageWrapper = unwrap_result!(deserialise(&msg.value()));
            wrapper
        } else {
            panic!("{:?} failed to receive outbox query response", self)
        }
    }

    fn wait_for_request(&self) -> Option<RequestMessage> {
        self.wait_for_event().and_then(|event| {
            if let Event::Request(request_message) = event {
                Some(request_message)
            } else {
                panic!("{:?} unexpected event {:?}", self, event)
            }
        })
    }

    fn wait_for_response(&self) -> Option<ResponseMessage> {
        self.wait_for_event().and_then(|event| {
            if let Event::Response(response_message) = event {
                Some(response_message)
            } else {
                panic!("{:?} unexpected event {:?}", self, event)
            }
        })
    }

    fn wait_for_event(&self) -> Option<Event> {
        self.receiver.recv().ok()
    }

    fn timed_wait_for_event(&self, timeout: Duration) -> Option<Event> {
        let interval = Duration::from_millis(100);
        let mut elapsed = Duration::new(0, 0);

        loop {
            match self.receiver.try_recv() {
                Ok(value) => return Some(value),
                Err(TryRecvError::Disconnected) => break,
                _ => (),
            }

            thread::sleep(interval);
            elapsed = elapsed + interval;

            if elapsed > timeout {
                break;
            }
        }

        None
    }
}

impl Debug for Client {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "Client({:?})", self.name())
    }
}

impl Default for Client {
    fn default() -> Client {
        Client::new()
    }
}
