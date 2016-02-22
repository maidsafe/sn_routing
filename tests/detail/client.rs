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

#![allow(unused)]

use std::fmt::{self, Debug, Formatter};
use std::sync::mpsc::{self, TryRecvError};
use std::thread;
use std::time::Duration;
use sodiumoxide::crypto;
use maidsafe_utilities::serialisation::{deserialise, serialise};
use rand::{random, Rng, thread_rng};
use routing::{self, Authority, Data, DataRequest, Event, FullId, PlainData, RequestMessage,
              RequestContent, ResponseContent, ResponseMessage, StructuredData};
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
        let routing_client = routing::Client::new(sender, Some(full_id)).unwrap();

        let client = Client {
            routing_client: routing_client,
            receiver: receiver,
            full_id: FullId::with_keys(encrypt_keys, sign_keys),
        };

        // Wait indefinitely for a `Connected` event, notifying us that we are now ready to send
        // requests to the network.
        info!("Waiting for {:?} to connect to network", client);
        if let Some(Event::Connected) = client.wait_for_event() {
            return client
        }
        panic!("{:?} failed to connect.");
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
        match unwrap_option!(self.put(Data::StructuredData(account)), "") {
            ResponseMessage { content: ResponseContent::PutSuccess(..), .. } => {
                info!("{:?} created account", self);
            }
            _ => panic!("{:?} failed to create account", self),
        }
    }

    /// Send a `Get` request to the network and return the received response.
    pub fn get(&mut self, request: DataRequest) -> Option<ResponseMessage> {
        unwrap_result!(self.routing_client
                           .send_get_request(Authority::NaeManager(request.name()),
                                             request.clone()));
        self.wait_for_response()
    }

    /// Send a `Put` request to the network.
    pub fn put(&self, data: Data) -> Option<ResponseMessage> {
        unwrap_result!(self.routing_client
                           .send_put_request(Authority::ClientManager(*self.name()), data));
        self.wait_for_response()
    }

    /// Post data onto the network.
    pub fn post(&self, data: Data) -> Option<ResponseMessage> {
        unwrap_result!(self.routing_client
                           .send_post_request(Authority::NaeManager(data.name()), data));
        self.wait_for_response()
    }

    /// Delete data from the network.
    pub fn delete(&self, data: Data) -> Option<ResponseMessage> {
        unwrap_result!(self.routing_client
                           .send_delete_request(Authority::NaeManager(data.name()), data));
        self.wait_for_response()
    }

    /// Register client online.
    pub fn register_online(&self) {
        let wrapper = MpidMessageWrapper::Online;
        let value = unwrap_result!(serialise(&wrapper));
        let data = Data::PlainData(PlainData::new(*self.name(), value));
        unwrap_result!(self.routing_client
                           .send_post_request(Authority::ClientManager(*self.name()), data));

        match unwrap_option!(self.wait_for_response(), "") {
            ResponseMessage { content: ResponseContent::PostSuccess(..), .. } => {
                trace!("{:?} successfully sent online message", self);
            }
            _ => panic!("{:?} failed to send online message", self),
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
        let data = Data::PlainData(PlainData::new(name.clone(), value));
        (mpid_message, data)
    }

    /// Wait to receive an `MpidMessage`.
    pub fn get_mpid_message(&self) -> Option<MpidMessage> {
        match self.wait_for_wrapper() {
            MpidMessageWrapper::PutMessage(mpid_message) => {
                trace!("{:?} received message {:?}", self, mpid_message);
                Some(mpid_message)
            }
            _ => panic!("{:?} unexpected message"),
        }
    }

    /// Delete mpid_header.
    pub fn delete_mpid_header(&self, header_name: XorName) {
        self.messaging_delete_request(self.name().clone(), header_name.clone(),
                                      MpidMessageWrapper::DeleteHeader(header_name))
    }

    /// Delete mpid_message.
    pub fn delete_mpid_message(&self, target_account: XorName, msg_name: XorName) {
        self.messaging_delete_request(target_account, msg_name.clone(),
                                      MpidMessageWrapper::DeleteMessage(msg_name))
    }

    fn messaging_delete_request(&self, target_account: XorName, name: XorName, wrapper: MpidMessageWrapper) {
        let value = unwrap_result!(serialise(&wrapper));
        let data = Data::PlainData(PlainData::new(name, value));
        let _ = unwrap_result!(self.routing_client
                           .send_delete_request(Authority::ClientManager(target_account), data));
    }

    /// Query outbox.
    pub fn query_outbox(&self) -> Vec<MpidHeader> {
        self.send_wrapper(MpidMessageWrapper::GetOutboxHeaders);
        match self.wait_for_wrapper() {
            MpidMessageWrapper::GetOutboxHeadersResponse(mpid_headers) => {
                trace!("{:?} outbox has following mpid_headers {:?}",
                       self,
                       mpid_headers);
                mpid_headers
            }
            _ => panic!("{:?} unexpected message"),
        }
    }

    /// Query whether outbox has particular message.
    pub fn outbox_has(&self, msg_names: Vec<XorName>) -> Vec<MpidHeader> {
        self.send_wrapper(MpidMessageWrapper::OutboxHas(msg_names));
        match self.wait_for_wrapper() {
            MpidMessageWrapper::OutboxHasResponse(mpid_headers) => {
                trace!("{:?} outbox has following mpid_headers {:?}",
                       self,
                       mpid_headers);
                mpid_headers
            }
            _ => panic!("{:?} unexpected message"),
        }
    }
    /// Return network name.
    pub fn name(&self) -> &XorName {
        self.full_id.public_id().name()
    }

    /// Return public signing key.
    pub fn signing_public_key(&self) -> crypto::sign::PublicKey {
        self.full_id.public_id().signing_public_key().clone()
    }

    /// Return secret signing key.
    pub fn signing_private_key(&self) -> &crypto::sign::SecretKey {
        self.full_id.signing_private_key()
    }

    fn send_wrapper(&self, wrapper: MpidMessageWrapper) {
        let name = self.name().clone();
        let value = unwrap_result!(serialise(&wrapper));
        let data = Data::PlainData(PlainData::new(name.clone(), value));
        unwrap_result!(self.routing_client
                           .send_put_request(Authority::ClientManager(*self.name()), data));
    }

    fn wait_for_wrapper(&self) -> MpidMessageWrapper {
        match unwrap_option!(self.wait_for_request(), "") {
            RequestMessage { src, dst, content: RequestContent::Post(Data::PlainData(msg), _) } => {
                let wrapper: MpidMessageWrapper = unwrap_result!(deserialise(&msg.value()));
                wrapper
            }
            _ => panic!("{:?} failed to receive outbox query response", self),
        }
    }

    fn wait_for_request(&self) -> Option<RequestMessage> {
        self.wait_for_event().and_then(|event| {
            match event {
                Event::Request(request_message) => Some(request_message),
                _ => panic!("{:?} unexpected event {:?}", self, event),
            }
        })
    }

    fn wait_for_response(&self) -> Option<ResponseMessage> {
        self.wait_for_event().and_then(|event| {
            match event {
                Event::Response(response_message) => Some(response_message),
                _ => panic!("{:?} unexpected event {:?}", self, event),
            }
        })
    }

    fn wait_for_event(&self) -> Option<Event> {
        let timeout = Duration::from_secs(10);
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
