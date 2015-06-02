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

//! This is a fresh start of routing_node.rs and should upon successful completion replace
//! the original routing_node.rs file, which in turn then is the owner of routing membrane and
//! routing core.
//! Routing membrane is a single thread responsible for the in- and outgoing messages.
//! It accepts messages received from CRUST.
//! The membrane evaluates whether a message is to be forwarded, or
//! accepted into the membrane as a request where Sentinel holds it until verified and resolved.
//! Requests resolved by Sentinel, will be handed on to the Interface for actioning.
//! A limited number of messages are deliberatly for Routing and network management purposes.
//! Some network management messages are directly handled without Sentinel resolution.
//! Other network management messages are handled by Routing after Sentinel resolution.

#[allow(unused_imports)]
use cbor::{Decoder, Encoder, CborError};
use rand;
use rustc_serialize::{Decodable, Encodable};
use sodiumoxide;
use sodiumoxide::crypto::sign::verify_detached;
use std::collections::{BTreeMap, HashMap};
use std::sync::mpsc;
use std::boxed::Box;
// use std::ops::DerefMut;
use std::sync::mpsc::Receiver;
use time::{Duration, SteadyTime};

use crust;
use lru_time_cache::LruCache;
use message_filter::MessageFilter;
use NameType;
use name_type::{closer_to_target_or_equal, NAME_TYPE_LEN};
use node_interface;
use node_interface::Interface;
use routing_table::{RoutingTable, NodeInfo};
use relay::RelayMap;
use sendable::Sendable;
use types;
use types::{MessageId, NameAndTypeId, Signature, Bytes};
use authority::{Authority, our_authority};
use message_header::MessageHeader;
// use messages::bootstrap_id_request::BootstrapIdRequest;
// use messages::bootstrap_id_response::BootstrapIdResponse;
use messages::get_data::GetData;
use messages::get_data_response::GetDataResponse;
use messages::put_data::PutData;
use messages::put_data_response::PutDataResponse;
use messages::connect_request::ConnectRequest;
use messages::connect_response::ConnectResponse;
// use messages::connect_success::ConnectSuccess;
use messages::find_group::FindGroup;
use messages::find_group_response::FindGroupResponse;
use messages::get_group_key::GetGroupKey;
use messages::get_group_key_response::GetGroupKeyResponse;
use messages::post::Post;
use messages::get_client_key::GetKey;
use messages::get_client_key_response::GetKeyResponse;
use messages::put_public_id::PutPublicId;
use messages::{RoutingMessage, MessageTypeTag};
use types::{MessageAction};
use error::{RoutingError, InterfaceError, ResponseError};

// use std::convert::From;


type ConnectionManager = crust::ConnectionManager;
type Event = crust::Event;
type Endpoint = crust::Endpoint;
type PortAndProtocol = crust::Port;

type RoutingResult = Result<(), RoutingError>;

enum ConnectionName {
    Unknown(NameType),
    Relay(NameType),
    Routing(NameType)
}

/// Routing Membrane
pub struct RoutingMembrane<F: Interface> {
    // for CRUST
    event_input: Receiver<Event>,
    connection_manager: ConnectionManager,
    accepting_on: Vec<Endpoint>,
    // for Routing
    id: types::Id,
    own_name: NameType,
    routing_table: RoutingTable,
    relay_map: RelayMap,
    next_message_id: MessageId,
    filter: MessageFilter<types::FilterType>,
    public_id_cache: LruCache<NameType, types::PublicId>,
    connection_cache: BTreeMap<NameType, SteadyTime>,
    // for interface
    interface: Box<F>
}

impl<F> RoutingMembrane<F> where F: Interface {
    pub fn new(my_interface: F) -> RoutingMembrane<F> {
        sodiumoxide::init();  // enable shared global (i.e. safe to multithread now)
        let (event_output, event_input) = mpsc::channel();
        let id = types::Id::new();
        let own_name = id.get_name();
        let mut cm = crust::ConnectionManager::new(event_output);
        // TODO: Default Protocol and Port need to be passed down
        let ports_and_protocols : Vec<PortAndProtocol> = Vec::new();
        // TODO: Beacon port should be passed down
        let beacon_port = Some(5483u16);
        let listeners = match cm.start_listening(ports_and_protocols, beacon_port) {
            Err(reason) => {
                println!("Failed to start listening: {:?}", reason);
                (vec![], None)
            }
            Ok(listeners_and_beacon) => listeners_and_beacon
        };
        println!("{:?}  -- listening on : {:?}", own_name, listeners.0);
        RoutingMembrane { interface: Box::new(my_interface),
                      id : id,
                      own_name : own_name.clone(),
                      event_input: event_input,
                      connection_manager: cm,
                      routing_table : RoutingTable::new(&own_name),
                      relay_map: RelayMap::new(&own_name),
                      accepting_on: listeners.0,
                      next_message_id: rand::random::<MessageId>(),
                      filter: MessageFilter::with_expiry_duration(Duration::minutes(20)),
                      public_id_cache: LruCache::with_expiry_duration(Duration::minutes(10)),
                      connection_cache: BTreeMap::new(),
                    }
    }

    /// Retrieve something from the network (non mutating) - Direct call
    pub fn get(&mut self, type_id: u64, name: NameType) {
        let destination = types::DestinationAddress{ dest: NameType::new(name.get_id()),
                                                     reply_to: None };
        let header = MessageHeader::new(self.get_next_message_id(),
                                        destination, self.our_source_address(),
                                        Authority::Client);
        let request = GetData{ requester: self.our_source_address(),
                               name_and_type_id: NameAndTypeId{name: NameType::new(name.get_id()),
                                                               type_id: type_id} };
        let message = RoutingMessage::new(MessageTypeTag::GetData, header,
                                          request, &self.id.get_crypto_secret_sign_key());

        // FIXME: We might want to return the result.
        ignore(encode(&message).map(|msg| self.send_swarm_or_parallel(&name, &msg)));
    }

    /// Add something to the network, will always go via ClientManager group
    pub fn put(&mut self, destination: NameType, content: Box<Sendable>) {
        let destination = types::DestinationAddress{ dest: destination, reply_to: None };
        let request = PutData{ name: content.name(), data: content.serialised_contents() };
        let header = MessageHeader::new(self.get_next_message_id(),
                                        destination, self.our_source_address(),
                                        Authority::ManagedNode);
        let message = RoutingMessage::new(MessageTypeTag::PutData, header,
                request, &self.id.get_crypto_secret_sign_key());

        // FIXME: We might want to return the result.
        ignore(encode(&message).map(|msg| self.send_swarm_or_parallel(&self.own_name, &msg)));
    }

    /// Add something to the network
    pub fn unauthorised_put(&mut self, destination: NameType, content: Box<Sendable>) {
        let destination = types::DestinationAddress{ dest: destination, reply_to: None };
        let request = PutData{ name: content.name(), data: content.serialised_contents() };
        let header = MessageHeader::new(self.get_next_message_id(), destination,
                                        self.our_source_address(), Authority::Unknown);
        let message = RoutingMessage::new(MessageTypeTag::UnauthorisedPut, header,
                request, &self.id.get_crypto_secret_sign_key());

        // FIXME: We might want to return the result.
        ignore(encode(&message).map(|msg| self.send_swarm_or_parallel(&self.own_name, &msg)));
    }

    /// RoutingMembrane::Run starts the membrane
    pub fn run(&mut self) {
        // TODO: v0.1.70 wrap this into internal loop, such that ::run can be spawned off into thread
        match self.event_input.try_recv() {
            Err(_) => (),
            Ok(crust::Event::NewMessage(endpoint, bytes)) => {
                match self.lookup_endpoint(&endpoint) {
                    // we have an active connection to this endpoint,
                    // mapped to a name in our routing_table
                    Some(ConnectionName::Routing(name)) => {
                        self.message_received(&name, bytes);
                    },
                    Some(ConnectionName::Relay(name)) => {},
                    Some(_) => {},
                    None => {
                        // for now just drop the message if we don't know the sender
                //         // if self.handle_challenge_request(&endpoint, &bytes) {
                //         //     return;
                //         // }
                //         // if self.handle_challenge_response(&endpoint, &bytes) {
                //         //     return;
                //         // }
                //         // ignore(self.handle_bootstrap_message(endpoint, bytes));
                    }
                }
            },
            Ok(crust::Event::NewConnection(endpoint)) => {
                self.handle_new_connection(endpoint);
            },
            Ok(crust::Event::LostConnection(endpoint)) => {
                self.handle_lost_connection(endpoint);
            }
        };
    }

    fn handle_new_connection(&mut self, endpoint : Endpoint) {
        // self.lookup_endpoint
    }

    fn handle_lost_connection(&mut self, endpoint : Endpoint) {

    }

    fn message_received(&mut self, name : &NameType, serialised_msg : Bytes) {

    }

    fn send_swarm_or_parallel(&self, target: &NameType, msg: &Bytes) {

    }

    // TODO: add optional group; fix bootstrapping/relay
    fn our_source_address(&self) -> types::SourceAddress {
        // if self.bootstrap_endpoint.is_some() {
        //     let id = self.all_connections.0.get(&self.bootstrap_endpoint.clone().unwrap());
        //     if id.is_some() {
        //         return types::SourceAddress{ from_node: id.unwrap().clone(),
        //                                      from_group: None,
        //                                      reply_to: Some(self.own_name.clone()) }
        //     }
        // }
        return types::SourceAddress{ from_node: self.own_name.clone(),
                                     from_group: None,
                                     reply_to: None }
    }

    fn get_next_message_id(&mut self) -> MessageId {
        let temp = self.next_message_id;
        self.next_message_id = self.next_message_id.wrapping_add(1);
        return temp;
    }

    fn lookup_endpoint(&self, endpoint: &Endpoint) -> Option<ConnectionName> {
        match self.routing_table.lookup_endpoint(&endpoint) {
            Some(name) => Some(ConnectionName::Routing(name)),
            None => match self.relay_map.lookup_endpoint(&endpoint) {
                Some(name) => Some(ConnectionName::Relay(name)),
                None => None
            }
        }
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
