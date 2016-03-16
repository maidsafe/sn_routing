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
use std::sync::mpsc;
use sodiumoxide::crypto;
use rand::random;
use routing::{self, Authority, Data, DataRequest, Event, FullId, MessageId, ResponseContent,
              ResponseMessage, StructuredData};
use xor_name::XorName;

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
