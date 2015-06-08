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
// use std::collections::{BTreeMap, HashMap};
use std::sync::mpsc;
use std::boxed::Box;
// use std::sync::mpsc::Receiver;
// use time::{Duration, SteadyTime};

use crust;
// use lru_time_cache::LruCache;
// use message_filter::MessageFilter;
use NameType;
use node_interface::{Interface, CreatePersonas};
use routing_membrane::RoutingMembrane;
use types;
use types::{MessageId, Bytes};
use authority::{Authority};
use messages::connect_request::ConnectRequest;
// use messages::connect_response::ConnectResponse;
// use messages::put_public_id::PutPublicId;
// use messages::put_public_id_response::PutPublicIdResponse;
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
pub struct RoutingNode<G : CreatePersonas> {
    genesis: Box<G>,
    id: types::Id,
    own_name: NameType,
    // event_input: Receiver<Event>,
    // connection_manager: ConnectionManager,
    // accepting_on: Vec<Endpoint>,
    next_message_id: MessageId,
    bootstrap_endpoint: Option<Endpoint>,
    bootstrap_node_id: Option<NameType>,
    // membrane_handle: Option<JoinHandle<_>>
}

impl<G : CreatePersonas> RoutingNode<G> {
    pub fn new(genesis: G) -> RoutingNode<G> {
        sodiumoxide::init();  // enable shared global (i.e. safe to multithread now)
        let id = types::Id::new();
        let own_name = id.get_name();
        RoutingNode { genesis: Box::new(genesis),
                      phantom: PhantomData,
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

        // self-relocate our id
        let original_name = self.id.get_name();
        let self_relocated_name = match types::calculate_relocated_name(
            vec![original_name.clone()], &original_name) {
            Ok(self_relocated_name) => self_relocated_name,
            Err(_) => panic!("Could not self-relocate our name.") // unreachable
        };
        self.id.assign_relocated_name(self_relocated_name);

        let mut membrane = RoutingMembrane::new(
            cm, event_input, None,
            listeners.0, self.id.clone(),
            self.genesis.create_personas());
        // TODO: currently terminated by main, should be signalable to terminate
        // and join the routing_node thread.
        spawn(move || membrane.run());
    }

    /// Bootstrap the node to an existing (or zero) node on the network.
    /// If a bootstrap list is provided those will be used over the beacon support from CRUST.
    pub fn bootstrap(&mut self, bootstrap_list: Option<Vec<Endpoint>>,
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
        let bootstrapped_to = try!(cm.bootstrap(bootstrap_list, beacon_port)
            .map_err(|_|RoutingError::FailedToBootstrap));
        println!("bootstrap {:?}", bootstrapped_to);
        self.bootstrap_endpoint = Some(bootstrapped_to);
        // send_connect_request_msg
        // FIXME: for now just write out explicitly in this function the bootstrapping loop
        loop {
            match event_input.recv() {
                Err(_) => (),
                Ok(crust::Event::NewMessage(endpoint, bytes)) => {
                  break;
                },
                Ok(crust::Event::NewConnection(endpoint)) => {

                },
                Ok(crust::Event::LostConnection(endpoint)) => {

                }
            }
        };
        Ok(())
    }

    fn construct_connect_request_msg(&mut self, bootstrap_name: &NameType,
        accepting_on: Vec<Endpoint>) -> RoutingMessage {
        let header = MessageHeader::new(self.get_next_message_id(),
            types::DestinationAddress {dest: bootstrap_name.clone(), relay_to: None },
            self.our_source_address(), Authority::ManagedNode);

        // FIXME: We're sending all accepting connections as local since we don't differentiate
        // between local and external yet.
        let connect_request = ConnectRequest {
            local_endpoints: accepting_on,
            external_endpoints: vec![],
            requester_id: self.own_name.clone(),
            receiver_id: bootstrap_name.clone(),
            requester_fob: types::PublicId::new(&self.id),
        };

        RoutingMessage::new(MessageTypeTag::ConnectRequest, header, connect_request,
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

    /// run_membrane spawns a new thread and moves a newly constructed Membrane into this thread.
    /// Routing node uses the genesis object to create a new instance of the personas to embed
    /// inside the membrane.
    //  TODO: a (two-way) channel should be passed in to control the membrane.
    //        connection_manager should also be moved into the membrane;
    //        firstly moving most ownership of the constructor into this function.
    fn run_membrane<T: Interface + 'static>(&mut self)  {

        // let mut membrane = RoutingMembrane::<T>::new(self.genesis.create_personas());
        // spawn(move || membrane.run());
        // ---------
        // let relocated_id = self.bootstrap();
        // // for now just write out explicitly in this function the bootstrapping
        // loop {
        //     match event_input.recv() {
        //         Err(_) => (),
        //         Ok(crust::Event::NewMessage(endpoint, bytes)) => {
        //
        //         },
        //         Ok(crust::Event::NewConnection(endpoint)) => {
        //
        //         },
        //         Ok(crust::Event::LostConnection(endpoint)) => {
        //
        //         }
        //     }
        // }
        //
        // match (self.bootstrap_node_id.clone(), self.bootstrap_endpoint.clone()) {
        //     (Some(name), Some(endpoint)) => {
        //         let mut membrane = RoutingMembrane::new(
        //             cm, event_input, Some((name, endpoint)),
        //             listeners.0, relocated_id,
        //             self.genesis.create_personas());
        //         spawn(move || membrane.run());
        //     },
        //     _ => () // failed to bootstrap
        // }
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
