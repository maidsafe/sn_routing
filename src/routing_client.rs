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
use sodiumoxide::crypto;
use std::io::Error as IoError;
use std::sync::{Mutex, Arc, mpsc};
use std::sync::mpsc::Receiver;

use client_interface::Interface;
use crust;
use messages;
use name_type::NameType;
use sendable::Sendable;
use types;
use error::{RoutingError, ResponseError, ClientError};
use messages::{SignedMessage, RoutingMessage, MessageType,
               ConnectResponse, ConnectRequest};
use types::{MessageId, DestinationAddress, SourceAddress};
use id::Id;
use public_id::PublicId;
use authority::Authority;
use utils::*;
use data::{Data, DataRequest};
use cbor::{CborError};

pub use crust::Endpoint;

type Bytes = Vec<u8>;
type ConnectionManager = crust::ConnectionManager;
type Event = crust::Event;
type PortAndProtocol = crust::Port;

pub enum CryptoError {
    Unknown
}

pub struct RoutingClient<F: Interface> {
    interface: Arc<Mutex<F>>,
    event_input: Receiver<Event>,
    connection_manager: ConnectionManager,
    id: Id,
    public_id: PublicId,
    bootstrap_address: (Option<NameType>, Option<Endpoint>),
    next_message_id: MessageId
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
            interface: my_interface,
            event_input: rx,
            connection_manager: crust::ConnectionManager::new(tx),
            public_id: PublicId::new(&id),
            id: id,
            bootstrap_address: (None, None),
            next_message_id: rand::random::<MessageId>()
        }
    }

    fn bootstrap_name(&self) -> Result<NameType, ClientError> {
        match self.bootstrap_address.0 {
            Some(name) => Ok(name),
            None       => Err(ClientError::NotBootstrapped),
        }
    }

    fn source_address(&self) -> Result<SourceAddress, ClientError> {
        Ok(SourceAddress::RelayedForClient(try!(self.bootstrap_name()),
                                           self.public_id.signing_public_key()))
    }

    /// Retrieve something from the network (non mutating) - Direct call
    pub fn get(&mut self, location: NameType, data : DataRequest) -> Result<MessageId, ClientError> {
        let message_id = self.get_next_message_id();

        let message = RoutingMessage {
            destination : DestinationAddress::Direct(location),
            source      : try!(self.source_address()),
            orig_message: None,
            message_type: MessageType::GetData(data),
            message_id  : message_id.clone(),
            authority   : Authority::Client(self.id.signing_public_key()),
            };

        self.send_to_bootstrap_node(&message);
        Ok(message_id)
    }

    /// Add something to the network, will always go via ClientManager group
    pub fn put(&mut self, location: NameType, data : Data) -> Result<MessageId, ClientError> {
        let message_id = self.get_next_message_id();

        let message = RoutingMessage {
            destination : DestinationAddress::Direct(self.public_id.client_name()),
            source      : try!(self.source_address()),
            orig_message: None,
            message_type: MessageType::PutData(data),
            message_id  : message_id.clone(),
            authority   : Authority::Client(self.id.signing_public_key()),
        };

        self.send_to_bootstrap_node(&message);
        Ok(message_id)
    }

    /// Mutate something one the network (you must own it and provide a proper update)
    pub fn post(&mut self, location: NameType, data : Data) -> Result<MessageId, ClientError> {
        let message_id = self.get_next_message_id();

        let message = RoutingMessage {
            destination : DestinationAddress::Direct(location),
            source      : try!(self.source_address()),
            orig_message: None,
            message_type: MessageType::Post(data),
            message_id  : message_id.clone(),
            authority   : Authority::Client(self.id.signing_public_key()),
        };

        self.send_to_bootstrap_node(&message);
        Ok(message_id)
    }

    /// Mutate something one the network (you must own it and provide a proper update)
    pub fn delete(&mut self, location: NameType, data : DataRequest) -> Result<MessageId, ClientError> {
        let message_id = self.get_next_message_id();
        let message = RoutingMessage {
            destination : DestinationAddress::Direct(location),
            source      : try!(self.source_address()),
            orig_message: None,
            message_type: MessageType::DeleteData(data),
            message_id  : message_id.clone(),
            authority   : Authority::Client(self.id.signing_public_key()),
        };

        self.send_to_bootstrap_node(&message);
        Ok(message_id)
    }

//######################################## API ABOVE this point ##################


    pub fn run(&mut self) {
        match self.event_input.try_recv() {
            Err(_) => (),
            Ok(crust::connection_manager::Event::NewMessage(endpoint, bytes)) => {
                // The received id is Endpoint(i.e. ip + socket) which is no use to upper layer
                // println!("received a new message from {}",
                //          match endpoint.clone() { Tcp(socket_addr) => socket_addr });
                let routing_msg = match decode::<RoutingMessage>(&bytes) {
                    Ok(routing_msg) => routing_msg,
                    Err(_) => return
                };
                println!("received a {:?} from {:?}", routing_msg.message_type,
                         endpoint );
                match self.bootstrap_address.1.clone() {
                    Some(ref bootstrap_endpoint) => {
                        // only accept messages from our bootstrap endpoint
                        if bootstrap_endpoint == &endpoint {
                            match routing_msg.message_type {
                                MessageType::ConnectResponse(connect_response) => {
                                    self.handle_connect_response(endpoint,
                                                                 connect_response);
                                },
                                MessageType::GetDataResponse(result) => {
                                    self.handle_get_data_response(routing_msg.message_id, result);
                                },
                                MessageType::PutDataResponse(put_response) => {
                                    self.handle_put_data_response(routing_msg.message_id,
                                                                  put_response);
                                },
                                _ => {}
                            }
                        }
                    },
                    None => { println!("Client is not connected to a node."); }
                }
            },
            _ => { // as a client, shall not handle any connection related change
                   // TODO : try to re-bootstrap when lost the connection to the bootstrap node ?
            }
        };
    }

    /// Use bootstrap to attempt connecting the client to previously known nodes,
    /// or use CRUST self-discovery options.
    pub fn bootstrap(&mut self, bootstrap_list: Option<Vec<Endpoint>>) -> Result<(), RoutingError> {
         // FIXME: bootstrapping a relay should fully rely on WhoAreYou,
         // then it is not need for CM to start listening;
         // but currently connect_request requires endpoint to connect back on to.
         let ports_and_protocols : Vec<PortAndProtocol> = Vec::new();
         let beacon_port = Some(5483u16);
         let listeners = match self.connection_manager
             .start_listening2(ports_and_protocols, beacon_port) {
             Err(reason) => {
                 println!("Failed to start listening: {:?}", reason);
                 (vec![], None)
             }
             Ok(listeners_and_beacon) => listeners_and_beacon
         };
         println!("trying to bootstrapped client");
         let bootstrapped_to = try!(self.connection_manager.bootstrap(bootstrap_list, beacon_port)
                                    .map_err(|_|RoutingError::FailedToBootstrap));
         self.bootstrap_address.1 = Some(bootstrapped_to);
         println!("bootstrapped client");
         // starts swapping ID with the bootstrap peer
         self.send_bootstrap_connect_request(listeners.0);
         Ok(())
    }

    fn send_bootstrap_connect_request(&mut self, accepting_on: Vec<Endpoint>) {
        match self.bootstrap_address.clone() {
            (_, Some(_)) => {
                println!("Sending connect request");

                let message = RoutingMessage {
                    destination : DestinationAddress::Direct(self.public_id.name()),
                    source      : SourceAddress::RelayedForClient(self.bootstrap_address.0, self.public_id.name()),
                    message_type: MessageType::ConnectRequest(messages::ConnectRequest {
                        local_endpoints: accepting_on,
                        external_endpoints: vec![],
                        requester_id: self.public_id.name(),
                        // FIXME: this field is ignored; again fixed on WhoAreYou approach
                        receiver_id: self.public_id.name(),
                        requester_fob: self.public_id.clone()
                    }),
                    message_id  : self.get_next_message_id(),
                    authority   : Authority::Client(self.id.signing_public_key()),
                };

                let _ = self.send_to_bootstrap_node(&message);
            },
            _ => {}
        }
    }

    fn handle_connect_response(&mut self, peer_endpoint: Endpoint, bytes: Bytes) {
        match decode::<ConnectResponse>(&bytes) {
            Err(_) => return,
            Ok(connect_response_msg) => {
                assert!(self.bootstrap_address.0.is_none());
                assert_eq!(self.bootstrap_address.1, Some(peer_endpoint.clone()));
                self.bootstrap_address.0 = Some(connect_response_msg.receiver_fob.name());
            }
        };
    }

    fn send_to_bootstrap_node(&mut self, message: &RoutingMessage)
            -> Result<(), CborError> {

        match self.bootstrap_address.1 {
            Some(ref bootstrap_endpoint) => {
                let encoded_message = try!(encode(&message));

                let _ = self.connection_manager.send(bootstrap_endpoint.clone(),
                                                     encoded_message);
            },
            None => {}
        };
    }

    fn get_next_message_id(&mut self) -> MessageId {
        self.next_message_id = self.next_message_id.wrapping_add(1);
        self.next_message_id
    }

    fn handle_get_data_response(&self, message_id: MessageId, result: Result<Data, ResponseError>) {
        let mut interface = self.interface.lock().unwrap();
        interface.handle_get_response(message_id, result);
    }

    fn handle_put_data_response(&self, message_id: MessageId, result: Result<Data, ResponseError>) {
        let mut interface = self.interface.lock().unwrap();
        interface.handle_put_response(message_id, result);
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
