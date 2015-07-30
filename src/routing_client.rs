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


use rand;
use sodiumoxide;
use sodiumoxide::crypto::sign;
use std::sync::{Mutex, Arc, mpsc};
use std::sync::mpsc::Receiver;

use client_interface::Interface;
use crust;
use messages;
use name_type::NameType;
use error::RoutingError;
use messages::{RoutingMessage, SignedMessage, MessageType, ErrorReturn};
use types::{MessageId, DestinationAddress, SourceAddress, Address};
use id::Id;
use public_id::PublicId;
use authority::Authority;
use utils::*;
use data::{Data, DataRequest};
use cbor::{CborError};
use who_are_you::IAm;

pub use crust::Endpoint;

type Bytes = Vec<u8>;
type ConnectionManager = crust::ConnectionManager;
type Event = crust::Event;
type PortAndProtocol = crust::Port;

static MAX_BOOTSTRAP_CONNECTIONS : usize = 3;

pub struct RoutingClient<F: Interface> {
    interface          : Arc<Mutex<F>>,
    event_input        : Receiver<Event>,
    connection_manager : ConnectionManager,
    id                 : Id,
    public_id          : PublicId,
    bootstrap          : Option<(Endpoint, Option<NameType>)>,
    next_message_id    : MessageId
}

impl<F> Drop for RoutingClient<F> where F: Interface {
    fn drop(&mut self) {
        // self.connection_manager.stop(); // TODO This should be coded in ConnectionManager once Peter
        // implements it.
    }
}

impl<F> RoutingClient<F> where F: Interface {
    pub fn new(my_interface: Arc<Mutex<F>>, id: Id) -> RoutingClient<F> {
        sodiumoxide::init();  // enable shared global (i.e. safe to multithread now)
        let (tx, rx) = mpsc::channel::<Event>();
        RoutingClient {
            interface          : my_interface,
            event_input        : rx,
            connection_manager : crust::ConnectionManager::new(tx),
            public_id          : PublicId::new(&id),
            id                 : id,
            bootstrap          : None,
            next_message_id    : rand::random::<MessageId>()
        }
    }

    fn bootstrap_name(&self) -> Result<NameType, RoutingError> {
        match self.bootstrap {
            Some((_, Some(name))) => Ok(name),
            _                     => Err(RoutingError::NotBootstrapped),
        }
    }

    fn source_address(&self) -> Result<SourceAddress, RoutingError> {
        Ok(SourceAddress::RelayedForClient(try!(self.bootstrap_name()),
                                           self.public_id.signing_public_key()))
    }

    fn public_sign_key(&self) -> sign::PublicKey { self.id.signing_public_key() }

    /// Retrieve something from the network (non mutating) - Direct call
    pub fn get(&mut self, location: NameType, data : DataRequest) -> Result<(), RoutingError> {
        let message = RoutingMessage {
            destination : DestinationAddress::Direct(location),
            source      : try!(self.source_address()),
            orig_message: None,
            message_type: MessageType::GetData(data),
            message_id  : self.get_next_message_id(),
            authority   : Authority::Client(self.id.signing_public_key()),
            };

        match self.send_to_bootstrap_node(&message){
            Ok(_) => Ok(()),
            //FIXME(ben) should not expose these errors to user 16/07/2015
            Err(e) => Err(RoutingError::Cbor(e))
        }
    }

    /// Add something to the network, will always go via ClientManager group
    pub fn put(&mut self, location: NameType, data : Data) -> Result<(), RoutingError> {
        let message = RoutingMessage {
            destination : DestinationAddress::Direct(location),
            source      : try!(self.source_address()),
            orig_message: None,
            message_type: MessageType::PutData(data),
            message_id  : self.get_next_message_id(),
            authority   : Authority::Client(self.id.signing_public_key()),
        };

        match self.send_to_bootstrap_node(&message){
            Ok(_) => Ok(()),
            //FIXME(ben) should not expose these errors to user 16/07/2015
            Err(e) => Err(RoutingError::Cbor(e))
        }
    }

    /// Mutate something one the network (you must own it and provide a proper update)
    pub fn post(&mut self, location: NameType, data : Data) -> Result<(), RoutingError> {
        let message = RoutingMessage {
            destination : DestinationAddress::Direct(location),
            source      : try!(self.source_address()),
            orig_message: None,
            message_type: MessageType::Post(data),
            message_id  : self.get_next_message_id(),
            authority   : Authority::Client(self.id.signing_public_key()),
        };

        match self.send_to_bootstrap_node(&message){
            Ok(_) => Ok(()),
            //FIXME(ben) should not expose these errors to user 16/07/2015
            Err(e) => Err(RoutingError::Cbor(e))
        }
    }

    /// Mutate something one the network (you must own it and provide a proper update)
    pub fn delete(&mut self, location: NameType, data : DataRequest) -> Result<(), RoutingError> {
        let message = RoutingMessage {
            destination : DestinationAddress::Direct(location),
            source      : try!(self.source_address()),
            orig_message: None,
            message_type: MessageType::DeleteData(data),
            message_id  : self.get_next_message_id(),
            authority   : Authority::Client(self.id.signing_public_key()),
        };

        match self.send_to_bootstrap_node(&message){
            Ok(_) => Ok(()),
            //FIXME(ben) should not expose these errors to user 16/07/2015
            Err(e) => Err(RoutingError::Cbor(e))
        }
    }

    pub fn poll_one(&mut self) {
        match self.event_input.try_recv() {
            Err(_) => (),
            Ok(crust::connection_manager::Event::NewMessage(endpoint, bytes)) => {
                match decode::<IAm>(&bytes) {
                    Ok(_msg) => {
                        // Ignore, should have been handled while bootstrapping.
                        return;
                    },
                    Err(_)  => {;}
                }

                let signed_msg = match decode::<SignedMessage>(&bytes) {
                    Ok(msg) => msg,
                    Err(_) => { debug_assert!(false); return }
                };

                let routing_msg = match signed_msg.get_routing_message() {
                    Ok(m) => m,
                    Err(_)  => { debug_assert!(false); return }
                };

                debug!("received a {:?} from {:?}", routing_msg.message_type, endpoint);

                match self.bootstrap {
                    Some((ref bootstrap_endpoint, _)) => {
                        // only accept messages from our bootstrap endpoint
                        if bootstrap_endpoint == &endpoint {
                            match routing_msg.message_type {
                                MessageType::GetDataResponse(result) => {
                                    self.handle_get_data_response(result);
                                },
                                MessageType::PutDataResponse(put_response, _) => {
                                    self.handle_put_data_response(put_response);
                                },
                                _ => {}
                            }
                        }
                    },
                    _ => { debug!("Received message but not fully bootstrapped"); }
                }
            },
            _ => { // as a client, shall not handle any connection related change
                   // TODO : try to re-bootstrap when lost the connection to the bootstrap node ?
            }
        };
    }

    /// Use bootstrap to attempt connecting the client to previously known nodes,
    /// or use CRUST self-discovery options.
    pub fn bootstrap(&mut self) -> Result<(), RoutingError> {
        try!(self.connection_manager.start_accepting(vec![]));
        self.connection_manager.bootstrap(MAX_BOOTSTRAP_CONNECTIONS);

        loop {
            match self.event_input.recv() {
                Err(_) => return Err(RoutingError::FailedToBootstrap),
                Ok(crust::Event::NewBootstrapConnection(endpoint)) => {
                    self.bootstrap = Some((endpoint.clone(), None));

                    let i_am_msg = IAm {
                        address   : Address::Client(self.public_id.signing_public_key()),
                        public_id : self.public_id.clone(),
                    };

                    try!(self.connection_manager.send(endpoint, try!(encode(&i_am_msg))));
                },
                Ok(crust::Event::NewMessage(endpoint, bytes)) => {
                    if let Ok(msg) = decode::<IAm>(&bytes) {
                        self.handle_i_am(endpoint, msg);
                        return Ok(());
                    }
                },
                _ => {}
            }
        }
    }

    fn handle_i_am(&mut self, _endpoint: Endpoint, message: IAm) {
        let node_name = match message.address {
            Address::Node(n) => n,
            // We don't care about clients.
            Address::Client(_) => {
                // TODO: Remove from self.bootstrap if endpoint (arg)
                // is the bootstrap endpoint (self.bootstrap.0).
                return;
            }
        };

        self.bootstrap = match self.bootstrap {
            // TODO: Endpoints are currently non comparable(?)
            Some((ref ep, None)) /* if ep == endpoint */ => {
                Some((ep.clone(), Some(node_name)))
            },
            _ => self.bootstrap.clone()
        }
    }

    fn send_to_bootstrap_node(&mut self, message: &RoutingMessage)
            -> Result<(), CborError> {

        match self.bootstrap {
            Some((ref bootstrap_endpoint, _)) => {
                let priv_key        = self.id.signing_private_key();
                let signed_message  = try!(SignedMessage::new(message, priv_key));
                let encoded_message = try!(encode(&signed_message));

                let _ = self.connection_manager.send(bootstrap_endpoint.clone(),
                                                     encoded_message);
            },
            None => {}
        };
        Ok(())
    }

    fn get_next_message_id(&mut self) -> MessageId {
        self.next_message_id = self.next_message_id.wrapping_add(1);
        self.next_message_id
    }

    fn handle_get_data_response(&self, response: messages::GetDataResponse) {
        if !response.verify_request_came_from(&self.public_sign_key()) {
            return;
        }

        let orig_request = match response.orig_request.get_routing_message() {
            Ok(l) => l,
            Err(_) => return
        };

        let location = orig_request.non_relayed_destination();

        let mut interface = self.interface.lock().unwrap();
        interface.handle_get_response(location, response.data);
    }

    fn handle_put_data_response(&self, signed_error: ErrorReturn) {
        if !signed_error.verify_request_came_from(&self.public_sign_key()) {
            return;
        }

        let orig_request = match signed_error.orig_request.get_routing_message() {
            Ok(l)  => l,
            Err(_) => return
        };

        // The request must have been a PUT message.
        let orig_put_data = match orig_request.message_type {
            MessageType::PutData(data) => data,
            _                          => return
        };

        let mut interface = self.interface.lock().unwrap();
        interface.handle_put_response(signed_error.error, orig_put_data);
    }
}

// #[cfg(test)]
// mod test {
//     extern crate cbor;
//     extern crate rand;
//
//     use super::*;
//     use std::sync::{Mutex, Arc};
//     use types::*;
//     use client_interface::Interface;
//     use Action;
//     use ResponseError;
//     use maidsafe_types::Random;
//     use maidsafe_types::Maid;
//
//     struct TestInterface;
//
//     impl Interface for TestInterface {
//         fn handle_get(&mut self, type_id: u64, our_authority: Authority, from_authority: Authority,from_address: NameType , data: Vec<u8>)->Result<Action, ResponseError> { unimplemented!(); }
//         fn handle_put(&mut self, our_authority: Authority, from_authority: Authority,
//                       from_address: NameType, dest_address: DestinationAddress, data: Vec<u8>)->Result<Action, ResponseError> { unimplemented!(); }
//         fn handle_post(&mut self, our_authority: Authority, from_authority: Authority, from_address: NameType, data: Vec<u8>)->Result<Action, ResponseError> { unimplemented!(); }
//         fn handle_get_response(&mut self, from_address: NameType , response: Result<Vec<u8>, ResponseError>) { unimplemented!() }
//         fn handle_put_response(&mut self, from_authority: Authority,from_address: NameType , response: Result<Vec<u8>, ResponseError>) { unimplemented!(); }
//         fn handle_post_response(&mut self, from_authority: Authority,from_address: NameType , response: Result<Vec<u8>, ResponseError>) { unimplemented!(); }
//         fn add_node(&mut self, node: NameType) { unimplemented!(); }
//         fn drop_node(&mut self, node: NameType) { unimplemented!(); }
//     }
//
//     pub fn generate_random(size : usize) -> Vec<u8> {
//         let mut content: Vec<u8> = vec![];
//         for _ in (0..size) {
//             content.push(rand::random::<u8>());
//         }
//         content
//     }
//
//     // #[test]
//     // fn routing_client_put() {
//     //     let interface = Arc::new(Mutex::new(TestInterface));
//     //     let maid = Maid::generate_random();
//     //     let dht_id = NameType::generate_random();
//     //     let mut routing_client = RoutingClient::new(interface, maid, dht_id);
//     //     let name = NameType::generate_random();
//     //     let content = generate_random(1024);
//     //
//     //     let put_result = routing_client.put(name, content);
//     //     // assert_eq!(put_result.is_err(), false);
//     // }
// }
