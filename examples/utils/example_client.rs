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

extern crate log;
extern crate routing;
extern crate sodiumoxide;
extern crate maidsafe_utilities;

use std::sync::mpsc;
use sodiumoxide::crypto;
use routing::{FullId, Event, Data, DataIdentifier, Authority, Response, Client, MessageId, XorName};

/// A simple example client implementation for a network based on the Routing library.
#[allow(unused)]
pub struct ExampleClient {
    /// The client interface to the Routing library.
    routing_client: Client,
    /// The receiver through which the Routing library will send events.
    receiver: mpsc::Receiver<Event>,
    /// This client's ID.
    full_id: FullId,
}

#[allow(unused)]
impl ExampleClient {
    /// Creates a new client and attempts to establish a connection to the network.
    pub fn new() -> ExampleClient {
        let (sender, receiver) = mpsc::channel::<Event>();

        // Generate new key pairs. The client's name will be computed from them. This is a
        // requirement for clients: If the name does not match the keys, it will be rejected by the
        // network.
        let sign_keys = crypto::sign::gen_keypair();
        let encrypt_keys = crypto::box_::gen_keypair();
        let full_id = FullId::with_keys(encrypt_keys.clone(), sign_keys.clone());
        let routing_client = unwrap_result!(Client::new(sender, Some(full_id), false));

        // Wait indefinitely for a `Connected` event, notifying us that we are now ready to send
        // requests to the network.
        for it in receiver.iter() {
            if let Event::Connected = it {
                println!("Client Connected to network");
                break;
            }
        }

        ExampleClient {
            routing_client: routing_client,
            receiver: receiver,
            full_id: FullId::with_keys(encrypt_keys, sign_keys),
        }
    }

    /// Send a `Get` request to the network and return the data received in the response.
    ///
    /// This is a blocking call and will wait indefinitely for the response.
    pub fn get(&mut self, request: DataIdentifier) -> Option<Data> {
        let message_id = MessageId::new();
        unwrap_result!(self.routing_client
            .send_get_request(Authority::NaeManager(request.name()),
                              request.clone(),
                              message_id));

        // Wait for Get success event from Routing
        for it in self.receiver.iter() {
            match it {
                Event::Response { response: Response::GetSuccess(data, id), .. } => {
                    if message_id != id {
                        error!("GetSuccess for {:?}, but with wrong message_id {:?} instead of \
                                {:?}.",
                               data.name(),
                               id,
                               message_id);
                    }
                    return Some(data);
                }
                Event::Response {
                    response: Response::GetFailure { external_error_indicator, .. },
                .. } => {
                    error!("Failed to Get {:?}: {:?}",
                           request.name(),
                           unwrap_result!(String::from_utf8(external_error_indicator)));
                    return None;
                }
                Event::Disconnected => self.disconnected(),
                _ => (),
            }
        }

        None
    }

    /// Send a `Put` request to the network.
    ///
    /// This is a blocking call and will wait indefinitely for a `PutSuccess` or `PutFailure`
    /// response.
    pub fn put(&self, data: Data) -> Result<(), ()> {
        let data_id = data.identifier();
        let message_id = MessageId::new();
        unwrap_result!(self.routing_client
            .send_put_request(Authority::ClientManager(*self.name()), data, message_id));

        // Wait for Put success event from Routing
        for it in self.receiver.iter() {
            match it {
                Event::Response { response: Response::PutSuccess(rec_data_id, id), .. } => {
                    if message_id != id {
                        error!("Stored {:?}, but with wrong message_id {:?} instead of {:?}.",
                               data_id.name(),
                               id,
                               message_id);
                        return Err(());
                    } else if data_id == rec_data_id {
                        trace!("Successfully stored {:?}", data_id.name());
                        return Ok(());
                    } else {
                        error!("Stored {:?}, but with wrong name {:?}.",
                               data_id.name(),
                               rec_data_id.name());
                        return Err(());
                    }
                }
                Event::Response { response: Response::PutFailure { .. }, .. } => {
                    error!("Received PutFailure for {:?}.", data_id.name());
                    return Err(());
                }
                Event::Disconnected => self.disconnected(),
                _ => (),
            }
        }
        Err(())
    }

    fn disconnected(&self) {
        panic!("Disconnected from the network.");
    }

    /// Post data onto the network.
    #[allow(unused)]
    pub fn post(&self) {
        unimplemented!()
    }

    /// Delete data from the network.
    #[allow(unused)]
    pub fn delete(&self) {
        unimplemented!()
    }

    /// Return network name.
    pub fn name(&self) -> &XorName {
        self.full_id.public_id().name()
    }
}

impl Default for ExampleClient {
    fn default() -> ExampleClient {
        ExampleClient::new()
    }
}
