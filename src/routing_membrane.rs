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
    Relay(NameType),
    Routing(NameType)
}

/// Routing Membrane
pub struct RoutingMembrane {
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
}

impl RoutingMembrane {
    pub fn new() -> RoutingMembrane {
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
        RoutingMembrane {
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
        loop {
            match self.event_input.recv() {
                Err(_) => (),
                Ok(crust::Event::NewMessage(endpoint, bytes)) => {
                    match self.lookup_endpoint(&endpoint) {
                        // we hold an active connection to this endpoint,
                        // mapped to a name in our routing table
                        Some(ConnectionName::Routing(name)) => {
                            self.message_received(&name, bytes);
                        },
                        // we hold an active connection to this endpoint,
                        // mapped to a name in our relay map
                        Some(ConnectionName::Relay(name)) => {},
                        None => {
                            // If we don't know the sender, only accept a connect request
                            self.handle_unknown_connect_request(&endpoint, bytes);
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
    }

    ///
    fn handle_unknown_connect_request(&mut self, endpoint: &Endpoint, serialised_msg : Bytes)
        -> RoutingResult {
        let message = try!(decode::<RoutingMessage>(&serialised_msg));
        let header = message.message_header;
        let body = message.serialised_body;
        let signature = message.signature;
        // only accept ConnectRequest messages from unknown endpoints
        let connect_request = try!(decode::<ConnectRequest>(&body));
        // first verify that the message is correctly self-signed
        if !verify_detached(&signature.get_crypto_signature(),
                            &body[..], &connect_request.requester_fob.public_sign_key
                                                       .get_crypto_public_sign_key()) {
            return Err(RoutingError::Response(ResponseError::InvalidRequest));
        }
        // match on the relocation status of the fob
        match connect_request.requester_fob.is_relocated() {
          // if the PublicId claims to be relocated,
          // check whether we have a temporary record of his relocated Id,
          // which we would have stored after the sentinel group consensus
          // of the relocated Id.
          true => {
              match self.public_id_cache.remove(&connect_request.requester_fob.name()) {
                  Some(public_id) => {
                      if public_id == connect_request.requester_fob {
                          let mut peer_endpoints = connect_request.local_endpoints.clone();
                          peer_endpoints.extend(connect_request.external_endpoints.clone().into_iter());
                          let peer_node_info =
                              NodeInfo::new(connect_request.requester_fob.clone(), peer_endpoints, None);
                          let (added, _) = self.routing_table.add_node(peer_node_info);
                          println!("RT (size : {:?}) added relocated {:?}", self.routing_table.size(),
                              connect_request.requester_fob.name());
                          if added {
                              let routing_msg = self.construct_connect_response_msg(&header, &body,
                                  &signature, &connect_request);
                              let serialised_message = try!(encode(&routing_msg));
                              self.connection_manager.connect(connect_request.external_endpoints);
                              self.connection_manager.connect(connect_request.local_endpoints);
                              // Send the response containing our details.
                              self.send_single(endpoint.clone(), serialised_message);
                          }
                      }
                  },
                  None => {
                      println!("FAILED to add relocated {:?}, different Id cached for this name.",
                          connect_request.requester_fob.name());
                      return Err(RoutingError::FailedToBootstrap); }
              }
          },
          // if the PublicId is not relocated,
          // only accept the connection into the RelayMap.
          // This will enable this connection to bootstrap or act as a client.
          false => {
              let routing_msg = self.construct_connect_response_msg(&header, &body,
                  &signature, &connect_request);
              let serialised_message = try!(encode(&routing_msg));
              // Try to connect to the peer.
              // when CRUST succeeds at establishing a connection,
              // we use this register to retrieve the PublicId
              self.relay_map.register_accepted_connect_request(&connect_request.external_endpoints,
                  &connect_request.requester_fob);
              self.connection_manager.connect(connect_request.external_endpoints);
              self.relay_map.register_accepted_connect_request(&connect_request.local_endpoints,
                  &connect_request.requester_fob);
              self.connection_manager.connect(connect_request.local_endpoints);
              // Send the response containing our details.
              self.send_single(endpoint.clone(), serialised_message);
          }
        }

        Ok(())
    }

    /// When CRUST establishes a two-way connection
    /// after exchanging details in ConnectRequest and ConnectResponse
    ///  - we can either add it to RelayMap (if the id was not-relocated,
    ///    and cached in relay_map)
    ///  - or we can add it to routing table (if the id was relocated,
    ///    and stored in public_id_cache after successful put_public_id handler)
    fn handle_new_connection(&mut self, endpoint : Endpoint) {
        match self.lookup_endpoint(&endpoint) {
            Some(ConnectionName::Routing(name)) => {},
            Some(ConnectionName::Relay(name)) => {},
            None => {}
        };
    }

    /// TODO: handle a lost connection
    fn handle_lost_connection(&mut self, endpoint : Endpoint) {
        match self.lookup_endpoint(&endpoint) {
            Some(ConnectionName::Routing(name)) => {},
            Some(ConnectionName::Relay(name)) => {},
            None => {}
        };
    }

    fn message_received(&mut self, name : &NameType, serialised_msg : Bytes) {

    }

    // Main send function, pass iterator of targets and message to clone.
    // FIXME: CRUST does not provide delivery promise.
    fn send<'a, I>(&self, targets: I, message: &Bytes) where I: Iterator<Item=&'a Endpoint> {
        for target in targets {
            ignore(self.connection_manager.send(target.clone(), message.clone()));
        }
    }

    // Send function to send message to single target.
    fn send_single(&self, target: Endpoint, message: Bytes) {
        ignore(self.connection_manager.send(target, message));
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
        // prioritise routing table
        match self.routing_table.lookup_endpoint(&endpoint) {
            Some(name) => Some(ConnectionName::Routing(name)),
            // secondly look in the relay_map
            None => match self.relay_map.lookup_endpoint(&endpoint) {
                Some(name) => Some(ConnectionName::Relay(name)),
                None => None
            }
        }
    }

    // -----Message Constructors-----------------------------------------------

    fn construct_connect_response_msg(&mut self, original_header : &MessageHeader, body: &Bytes, signature: &Signature,
                                      connect_request: &ConnectRequest) -> RoutingMessage {
        println!("{:?} construct_connect_response_msg ", self.own_name);
        debug_assert!(connect_request.receiver_id == self.own_name, format!("{:?} == {:?} failed", self.own_name, connect_request.receiver_id));

        // FIXME: re-use message_id
        let header = MessageHeader::new(self.get_next_message_id(),
            original_header.send_to(), self.our_source_address(),
            Authority::ManagedNode);

        // FIXME: We're sending all accepting connections as local since we don't differentiate
        // between local and external yet.
        let connect_response = ConnectResponse {
            requester_local_endpoints: connect_request.local_endpoints.clone(),
            requester_external_endpoints: connect_request.external_endpoints.clone(),
            receiver_local_endpoints: self.accepting_on.clone(),
            receiver_external_endpoints: vec![],
            requester_id: connect_request.requester_id.clone(),
            receiver_id: self.own_name.clone(),
            receiver_fob: types::PublicId::new(&self.id),
            serialised_connect_request: body.clone(),
            connect_request_signature: signature.clone() };

        RoutingMessage::new(MessageTypeTag::ConnectResponse, header,
            connect_response, &self.id.get_crypto_secret_sign_key())
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
