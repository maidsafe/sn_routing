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

use std::sync::mpsc::{self, TryRecvError};
use std::thread;
use std::time::Duration;
use routing::{self, Authority, Data, DataRequest, Event, FullId, ResponseContent, ResponseMessage};
use sodiumoxide::crypto;
use xor_name::XorName;

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
        println!("Starting Client");
        let (sender, receiver) = mpsc::channel::<Event>();

        // Generate new key pairs. The client's name will be computed from them. This is a
        // requirement for clients: If the name does not match the keys, it will be rejected by the
        // network.
        let sign_keys = crypto::sign::gen_keypair();
        let encrypt_keys = crypto::box_::gen_keypair();
        let full_id = FullId::with_keys(encrypt_keys.clone(), sign_keys.clone());
        let routing_client = routing::Client::new(sender, Some(full_id)).unwrap();

        // Wait indefinitely for a `Connected` event, notifying us that we are now ready to send
        // requests to the network.
        println!("Waiting for Client to connect");
        for it in receiver.iter() {
            if let Event::Connected = it {
                println!("Client Connected to network");
                break;
            }
        }

        Client {
            routing_client: routing_client,
            receiver: receiver,
            full_id: FullId::with_keys(encrypt_keys, sign_keys),
        }
    }

    /// Send a `Get` request to the network and return the received response.
    ///
    /// This is a blocking call and will wait indefinitely for the response.
    pub fn get(&mut self, request: DataRequest) -> Option<ResponseMessage> {
        unwrap_result!(self.routing_client
                           .send_get_request(Authority::NaeManager(request.name()), request.clone()));

        // Wait for Get response event from Routing
        for it in self.receiver.iter() {
            if let Event::Response(response_message) = it {
                return Some(response_message)
            } else {
                panic!("Unexpected event {:?}", it);
            }
        }

        None
    }

    /// Send a `Put` request to the network.
    ///
    /// This is a blocking call and will wait indefinitely for a response.
    pub fn put(&self, data: Data) -> Option<ResponseMessage> {
        unwrap_result!(self.routing_client
                           .send_put_request(Authority::ClientManager(*self.name()), data));

        // Wait for Put response event from Routing
        for it in self.receiver.iter() {
            if let Event::Response(response_message) = it {
                return Some(response_message)
            } else {
                panic!("Unexpected event {:?}", it);
            }
        }

        None
    }

    /// Post data onto the network.
    pub fn post(&self, data: Data) -> Option<ResponseMessage> {
        unwrap_result!(self.routing_client
                           .send_post_request(Authority::NaeManager(data.name()), data));

        let timeout = Duration::from_millis(10000);
        let interval = Duration::from_millis(100);
        let mut elapsed = Duration::from_millis(0);

        loop {
            match self.receiver.try_recv() {
                Ok(value) => {
                    if let Event::Response(response_message) = value {
                        return Some(response_message)
                    }
                }
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

    /// Delete data from the network.
    pub fn delete(&self) {
        unimplemented!()
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
}
