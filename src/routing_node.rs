// Copyright 2015 MaidSafe.net limited.
//
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

use cbor::{Decoder, Encoder, CborError};
use rand;
use rustc_serialize::{Decodable, Encodable};
use sodiumoxide;
use std::sync::mpsc;
use std::boxed::Box;
use std::thread;
use std::marker::PhantomData;

use crust;
use NameType;
use node_interface::{Interface, CreatePersonas};
use routing_membrane::RoutingMembrane;
use types;
use types::{MessageId, Bytes};
use authority::{Authority};
use messages::connect_request::ConnectRequest;
use messages::put_public_id::PutPublicId;
use messages::put_public_id_response::PutPublicIdResponse;
use messages::{RoutingMessage, MessageTypeTag};
use message_header::MessageHeader;
use error::{RoutingError};
use std::thread::spawn;

type ConnectionManager = crust::ConnectionManager;
type Event = crust::Event;
pub type Endpoint = crust::Endpoint;
type PortAndProtocol = crust::Port;

type RoutingResult = Result<(), RoutingError>;

/// DHT node
pub struct RoutingNode<F, G> where F : Interface + 'static,
                                   G : CreatePersonas<F> {
    genesis: Box<G>,
    phantom_data: PhantomData<F>,
    id: types::Id,
    own_name: NameType,
    next_message_id: MessageId,
    bootstrap_endpoint: Option<Endpoint>,
    bootstrap_node_id: Option<NameType>,
}

impl<F, G> RoutingNode<F, G> where F : Interface + 'static,
                                   G : CreatePersonas<F> {
    pub fn new(genesis: G) -> RoutingNode<F, G> {
        sodiumoxide::init();  // enable shared global (i.e. safe to multithread now)
        let id = types::Id::new();
        let own_name = id.get_name();
        RoutingNode { genesis: Box::new(genesis),
                      phantom_data: PhantomData,
                      id : id,
                      own_name : own_name.clone(),
                      next_message_id: rand::random::<MessageId>(),
                      bootstrap_endpoint: None,
                      bootstrap_node_id: None,
                    }
    }

    /// Starts a node without requiring responses from the network.
    /// Starts the routing membrane without looking to bootstrap.
    /// It will relocate its own address with the hash of twice its name.
    /// This allows the network to later reject this zero node
    /// when the routing_table is full.
    ///
    /// A zero_membrane will not be able to connect to an existing network,
    /// and as a special node, it will be rejected by the network later on.
    pub fn run_zero_membrane(&mut self) {
        let (event_output, event_input) = mpsc::channel();
        let mut cm = crust::ConnectionManager::new(event_output);
        // TODO: Default Protocol and Port need to be passed down
        let ports_and_protocols : Vec<PortAndProtocol> = Vec::new();
        // TODO: Beacon port should be passed down
        let beacon_port = Some(5483u16);
        let listeners = match cm.start_listening2(ports_and_protocols, beacon_port) {
            Err(reason) => {
                println!("Failed to start listening: {:?}", reason);
                (vec![], None)
            }
            Ok(listeners_and_beacon) => listeners_and_beacon
        };
        let original_name = self.id.get_name();
        let self_relocated_name = types::calculate_self_relocated_name(
            &self.id.get_crypto_public_sign_key(),
            &self.id.get_crypto_public_key(),
            &self.id.get_validation_token());
        println!("ZERO listening on {:?}, named {:?}", listeners.0.first(),
            self_relocated_name);
        self.id.assign_relocated_name(self_relocated_name);

        let mut membrane = RoutingMembrane::<F>::new(
            cm, event_input, None,
            listeners.0, self.id.clone(),
            self.genesis.create_personas());
        // TODO: currently terminated by main, should be signalable to terminate
        // and join the routing_node thread.
        spawn(move || membrane.run());
    }

    /// Bootstrap the node to an existing (or zero) node on the network.
    /// If a bootstrap list is provided those will be used over the beacon support from CRUST.
    /// Spawns a new thread and moves a newly constructed Membrane into this thread.
    /// Routing node uses the genesis object to create a new instance of the personas to embed
    /// inside the membrane.
    //  TODO: a (two-way) channel should be passed in to control the membrane.
    pub fn bootstrap(&mut self,
            bootstrap_list: Option<Vec<Endpoint>>,
            beacon_port: Option<u16>) -> Result<(), RoutingError>  {
        let (event_output, event_input) = mpsc::channel();
        let mut cm = crust::ConnectionManager::new(event_output);
        // TODO: Default Protocol and Port need to be passed down
        let ports_and_protocols : Vec<PortAndProtocol> = Vec::new();
        // TODO: Beacon port should be passed down
        let beacon_port = Some(5483u16);
        let listeners = match cm.start_listening2(ports_and_protocols, beacon_port) {
            Err(reason) => {
                println!("Failed to start listening: {:?}", reason);
                (vec![], None)
            }
            Ok(listeners_and_beacon) => listeners_and_beacon
        };

        // CRUST bootstrap
        let bootstrapped_to = try!(cm.bootstrap(bootstrap_list, beacon_port)
            .map_err(|_|RoutingError::FailedToBootstrap));
        println!("BOOTSTRAP to {:?}", bootstrapped_to);
        println!("NODE listening on {:?}", listeners.0.first());
        self.bootstrap_endpoint = Some(bootstrapped_to.clone());
        cm.connect(vec![bootstrapped_to.clone()]);
        // allow CRUST to connect
        thread::sleep_ms(100);

        let unrelocated_id = self.id.clone();
        let relocated_name : Option<NameType>;

        // FIXME: connect request should not require the knowledge of the name you're connecting to
        let connect_msg = self.construct_connect_request_msg(&unrelocated_id.get_name(),
            listeners.0.clone());
        let serialised_message = try!(encode(&connect_msg));

        ignore(cm.send(bootstrapped_to.clone(), serialised_message));

        // FIXME: for now just write out explicitly in this function the bootstrapping loop
        // - fully check match of returned public id with ours
        // - break from loop if unsuccessful; no response; retry
        // - this initial bootstrap should only use the WhoAreYou paradigm,
        //   not the unknown_connect_request as currently used.
        println!("Waiting for responses from network");
        loop {
            match event_input.recv() {
                Err(_) => {},
                Ok(crust::Event::NewMessage(endpoint, bytes)) => {
                    match decode::<RoutingMessage>(&bytes) {
                        Ok(message) => {
                            match message.message_type {
                                MessageTypeTag::ConnectResponse => {
                                    // for now, ignore the actual response message
                                    // bootstrap node responded, try to put our id to the network
                                    println!("Received connect response");
                                    let put_public_id_msg
                                        = self.construct_put_public_id_msg(
                                        &types::PublicId::new(&unrelocated_id));
                                    let serialised_message = try!(encode(&put_public_id_msg));
                                    ignore(cm.send(bootstrapped_to.clone(), serialised_message));
                                },
                                MessageTypeTag::PutPublicIdResponse => {
                                    let put_public_id_response =
                                        try!(decode::<PutPublicIdResponse>(&message.serialised_body));
                                    relocated_name = Some(put_public_id_response.public_id.name());
                                    debug_assert!(put_public_id_response.public_id.is_relocated());
                                    if put_public_id_response.public_id.validation_token
                                        != self.id.get_validation_token() {
                                        return Err(RoutingError::FailedToBootstrap); }
                                    println!("Received PutPublicId relocated name {:?} from {:?}",
                                        relocated_name, self.id.get_name());
                                    break;
                                },
                                _ => {
                                    println!("Received unexpected message {:?}",
                                        message.message_type);
                                }
                            }
                        },
                        Err(_) => {
                          // WhoAreYou/IAm messages fall in here.
                        }
                    };
                },
                Ok(crust::Event::NewConnection(endpoint)) => {
                    println!("NewConnection on {:?} while waiting on network.", endpoint);
                },
                Ok(crust::Event::LostConnection(endpoint)) => {
                    return Err(RoutingError::FailedToBootstrap);
                }
            }
        };

        match relocated_name {
            Some(relocated_name) => {
                self.id.assign_relocated_name(relocated_name);
                debug_assert!(self.id.is_relocated());
                let mut membrane = RoutingMembrane::<F>::new(
                    cm, event_input, Some(bootstrapped_to.clone()),
                    listeners.0, self.id.clone(),
                    self.genesis.create_personas());
                spawn(move || membrane.run());
            },
            _ => panic!("DEBUG: did not relocate the publicId.") // failed to bootstrap
        };
        Ok(())
    }

    fn construct_connect_request_msg(&mut self, destination: &NameType,
        accepting_on: Vec<Endpoint>) -> RoutingMessage {
        let header = MessageHeader::new(self.get_next_message_id(),
            types::DestinationAddress {dest: destination.clone(), relay_to: None },
            self.our_source_address(), Authority::ManagedNode);

        // FIXME: We're sending all accepting connections as local since we don't differentiate
        // between local and external yet.
        let connect_request = ConnectRequest {
            local_endpoints: accepting_on,
            external_endpoints: vec![],
            requester_id: self.own_name.clone(),
            receiver_id: destination.clone(),
            requester_fob: types::PublicId::new(&self.id),
        };

        RoutingMessage::new(MessageTypeTag::ConnectRequest, header, connect_request,
            &self.id.get_crypto_secret_sign_key())
    }

    fn construct_put_public_id_msg(&mut self,
        our_unrelocated_id: &types::PublicId) -> RoutingMessage {
        let header = MessageHeader::new(self.get_next_message_id(),
            types::DestinationAddress{dest: our_unrelocated_id.name(), relay_to: None},
            self.our_source_address(), Authority::ManagedNode);
        let put_public_id = PutPublicId { public_id : our_unrelocated_id.clone() };
        RoutingMessage::new(MessageTypeTag::PutPublicId, header, put_public_id,
            &self.id.get_crypto_secret_sign_key())
    }

    fn our_source_address(&self) -> types::SourceAddress {
        types::SourceAddress{ from_node: self.id.get_name(),
                              from_group: None,
                              reply_to: None,
                              // FIXME: relay node should fill this field
                              relayed_for: Some(self.id.get_name()) }
    }

    fn get_next_message_id(&mut self) -> MessageId {
        let temp = self.next_message_id;
        self.next_message_id = self.next_message_id.wrapping_add(1);
        return temp;
    }
}

fn encode<T>(value: &T) -> Result<Bytes, CborError> where T: Encodable {
    let mut enc = Encoder::from_memory();
    try!(enc.encode(&[value]));
    Ok(enc.into_bytes())
}

fn decode<T>(bytes: &Bytes) -> Result<T, CborError> where T: Decodable {
    let mut dec = Decoder::from_bytes(&bytes[..]);
    match dec.decode().next() {
        Some(result) => result,
        None => Err(CborError::UnexpectedEOF)
    }
}

fn ignore<R,E>(_: Result<R,E>) {}

#[cfg(test)]
mod test {

}
