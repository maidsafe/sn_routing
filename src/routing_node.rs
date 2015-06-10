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
use sodiumoxide::crypto::sign::verify_detached;
use std::collections::{BTreeMap, HashMap};
use std::sync::mpsc;
use std::boxed::Box;
use std::ops::DerefMut;
use std::sync::mpsc::Receiver;
use time::{Duration, SteadyTime};

use challenge::{ChallengeRequest, ChallengeResponse, validate};
use crust;
use lru_time_cache::LruCache;
use message_filter::MessageFilter;
use NameType;
use name_type::{closer_to_target_or_equal, NAME_TYPE_LEN};
use node_interface;
use node_interface::Interface;
use routing_table::{RoutingTable, NodeInfo};
use sendable::Sendable;
use types;
use types::{MessageId, NameAndTypeId, Signature, Bytes};
use authority::{Authority, our_authority};
use message_header::MessageHeader;
use messages::bootstrap_id_request::BootstrapIdRequest;
use messages::bootstrap_id_response::BootstrapIdResponse;
use messages::get_data::GetData;
use messages::get_data_response::GetDataResponse;
use messages::put_data::PutData;
use messages::put_data_response::PutDataResponse;
use messages::connect_request::ConnectRequest;
use messages::connect_response::ConnectResponse;
use messages::connect_success::ConnectSuccess;
use messages::find_group::FindGroup;
use messages::find_group_response::FindGroupResponse;
use messages::get_group_key::GetGroupKey;
use messages::get_group_key_response::GetGroupKeyResponse;
use messages::post::Post;
use messages::get_client_key::GetKey;
use messages::get_client_key_response::GetKeyResponse;
use messages::put_public_id::PutPublicId;
use messages::put_public_id_response::PutPublicIdResponse;
use messages::{RoutingMessage, MessageTypeTag};
use types::{MessageAction};
use error::{RoutingError, InterfaceError, ResponseError};

use std::convert::From;

type ConnectionManager = crust::ConnectionManager;
type Event = crust::Event;
pub type Endpoint = crust::Endpoint;
type PortAndProtocol = crust::Port;

type RoutingResult = Result<(), RoutingError>;

/// DHT node
pub struct RoutingNode<F: Interface> {
    interface: Box<F>,
    id: types::Id,
    own_name: NameType,
    event_input: Receiver<Event>,
    connection_manager: ConnectionManager,
    all_connections: (HashMap<Endpoint, NameType>, BTreeMap<NameType, Vec<Endpoint>>),
    routing_table: RoutingTable,
    accepting_on: Vec<Endpoint>,
    next_message_id: MessageId,
    bootstrap_endpoint: Option<Endpoint>,
    bootstrap_node_id: Option<NameType>,
    filter: MessageFilter<types::FilterType>,
    public_id_cache: LruCache<NameType, types::PublicId>,
    connection_cache: BTreeMap<NameType, SteadyTime>
}

impl<F> RoutingNode<F> where F: Interface {
    pub fn new(my_interface: F) -> RoutingNode<F> {
        sodiumoxide::init();  // enable shared global (i.e. safe to multithread now)
        let (event_output, event_input) = mpsc::channel();
        let id = types::Id::new();
        let own_name = id.get_name();
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
        println!("{:?}  -- listening on : {:?}", own_name, listeners.0);
        RoutingNode { interface: Box::new(my_interface),
                      id : id,
                      own_name : own_name.clone(),
                      event_input: event_input,
                      connection_manager: cm,
                      all_connections: (HashMap::new(), BTreeMap::new()),
                      routing_table : RoutingTable::new(&own_name),
                      accepting_on: listeners.0,
                      next_message_id: rand::random::<MessageId>(),
                      bootstrap_endpoint: None,
                      bootstrap_node_id: None,
                      filter: MessageFilter::with_expiry_duration(Duration::minutes(20)),
                      public_id_cache: LruCache::with_expiry_duration(Duration::minutes(10)),
                      connection_cache: BTreeMap::new(),
                    }
    }

    /// Retrieve something from the network (non mutating) - Direct call
    pub fn get(&mut self, type_id: u64, name: NameType) {
        let destination = types::DestinationAddress{ dest: name.clone(), relay_to: None };
        let header = MessageHeader::new(self.get_next_message_id(),
                                        destination, self.our_source_address(),
                                        Authority::Client);
        let request = GetData{ requester: self.our_source_address(),
                               name_and_type_id: NameAndTypeId{name: name.clone(),
                                                               type_id: type_id} };
        let message = RoutingMessage::new(MessageTypeTag::GetData, header,
                                          request, &self.id.get_crypto_secret_sign_key());

        // FIXME: We might want to return the result.
        ignore(encode(&message).map(|msg| self.send_swarm_or_parallel(&name, &msg)));
    }

    /// Add something to the network, will always go via ClientManager group
    pub fn put(&mut self, destination: NameType, content: Box<Sendable>) {
        let destination = types::DestinationAddress{ dest: destination, relay_to: None };
        let request = PutData{ name: content.name(), data: content.serialised_contents() };
        let header = MessageHeader::new(self.get_next_message_id(),
                                        destination, self.our_source_address(),
                                        Authority::ManagedNode);
        let message = RoutingMessage::new(MessageTypeTag::PutData, header,
                request, &self.id.get_crypto_secret_sign_key());

        // FIXME: We might want to return the result.
        let _ = encode(&message).map(|msg| self.send_swarm_or_parallel(&self.id(), &msg));
    }

    /// Add something to the network
    pub fn unauthorised_put(&mut self, destination: NameType, content: Box<Sendable>) {
        let destination = types::DestinationAddress{ dest: destination, relay_to: None };
        let request = PutData{ name: content.name(), data: content.serialised_contents() };
        let header = MessageHeader::new(self.get_next_message_id(), destination,
                                        self.our_source_address(), Authority::Unknown);
        let message = RoutingMessage::new(MessageTypeTag::UnauthorisedPut, header,
                request, &self.id.get_crypto_secret_sign_key());

        // FIXME: We might want to return the result.
        let _ = encode(&message).map(|msg| self.send_swarm_or_parallel(&self.id(), &msg));
    }

    /// Refresh the content in the close group nodes of group address content::name.
    /// This method needs to be called when churn is triggered.
    /// all the group members need to call this, otherwise it will not be resolved as a valid
    /// content.
    pub fn refresh(&mut self, content: Box<Sendable>) {
        self.put(content.name(), content);
    }

    /// Mutate something on the network (you must prove ownership) - Direct call
    pub fn post(&self, destination: NameType, content: Vec<u8>) { unimplemented!() }

    pub fn bootstrap(&mut self, bootstrap_list: Option<Vec<Endpoint>>,
                     beacon_port: Option<u16>) -> Result<(), RoutingError> {
        let bootstrapped_to = try!(self.connection_manager.bootstrap(bootstrap_list, beacon_port)
                                   .map_err(|_|RoutingError::FailedToBootstrap));
        println!("bootstrap {:?}", bootstrapped_to);

        self.bootstrap_endpoint = Some(bootstrapped_to);
        // starts swapping ID with the bootstrap peer
        self.send_bootstrap_id_request()
    }

    pub fn run(&mut self) {
        let event = self.event_input.try_recv();
        if event.is_err() {
            return;
        }
        match event.unwrap() {
            crust::Event::NewMessage(endpoint, bytes) => {
                match self.endpoint_to_name(&endpoint).map(|n|n.clone()) {
                    Some(name) => {
                        ignore(self.message_received(&name, bytes));
                    },
                    None => {
                        if self.handle_challenge_request(&endpoint, &bytes) {
                            return;
                        }
                        if self.handle_challenge_response(&endpoint, &bytes) {
                            return;
                        }
                        ignore(self.handle_bootstrap_message(endpoint, bytes));
                    }
                }
            },
            crust::Event::NewConnection(endpoint) => {
                self.handle_new_connect_event(endpoint);
            },
            crust::Event::LostConnection(endpoint) => {
                self.handle_lost_connection_event(endpoint);
            }
        }
    }

    fn handle_challenge_request(&mut self, peer_endpoint: &Endpoint,
                                serialised_message: &Bytes) -> bool {
        let message = match decode::<ChallengeRequest>(serialised_message) {
            Err(err) => return false,
            Ok(message) => message,
        };
        let signature = sodiumoxide::crypto::sign::sign(serialised_message,
                                                        &self.id.get_crypto_secret_sign_key());
        let response = ChallengeResponse{ name: self.own_name.clone(), signature: signature,
                                          request: message };
        let _ = encode(&response).map(
            |serialised_message| self.connection_manager.send(peer_endpoint.clone(),
                                                              serialised_message));
        true
    }

    fn handle_challenge_response(&mut self, peer_endpoint: &Endpoint,
                                 serialised_message: &Bytes) -> bool {
        let message = match decode::<ChallengeResponse>(serialised_message) {
            Err(err) => return false,
            Ok(message) => message,
        };
        if let Some(peer_public_id) = self.routing_table.public_id(&message.name) {
            if !validate(&peer_public_id.public_sign_key.get_crypto_public_sign_key(), &message) {
                // Even though this fails, we should return true as this has parsed as a
                // ChallengeResponse.
                return true;
            }
            self.all_connections.0.insert(peer_endpoint.clone(), peer_public_id.name());
            let found = if let Some(peer_endpoints) =
                    self.all_connections.1.get_mut(&peer_public_id.name()) {
                assert!(!peer_endpoints.is_empty());
                peer_endpoints.push(peer_endpoint.clone());
                true
            } else {
                false
            };
            if !found {
                self.all_connections.1.insert(peer_public_id.name(), vec![peer_endpoint.clone()]);
            }
            true
        } else {
            // TODO - handle client response here maybe?
            false
        }
    }


    fn generate_bootstrap_header(&self, message_id: MessageId) -> MessageHeader {
        MessageHeader::new( message_id,
                            types::DestinationAddress{ dest: NameType::new([0u8; NAME_TYPE_LEN]), relay_to: None },
                            types::SourceAddress{ from_node: self.id(), from_group: None, reply_to: None, relayed_for: None },
                            Authority::ManagedNode)
    }

    fn send_bootstrap_id_request(&mut self) -> RoutingResult {
        let message_id = self.get_next_message_id();
        let message = RoutingMessage::new(MessageTypeTag::BootstrapIdRequest,
                                          self.generate_bootstrap_header(message_id),
                                          BootstrapIdRequest { sender_id: self.id() },
                                          &self.id.get_crypto_secret_sign_key());

        self.send_to_bootstrap_node(&try!(encode(&message)));
        Ok(())
    }

    fn send_bootstrap_id_response(&mut self, peer_endpoint: Endpoint) {
        let message_id = self.get_next_message_id();
        let message = RoutingMessage::new(MessageTypeTag::BootstrapIdResponse,
                                          self.generate_bootstrap_header(message_id),
                                          BootstrapIdResponse { sender_id: self.id() },
                                          &self.id.get_crypto_secret_sign_key());

        // need to send to bootstrap node as we are not yet connected to anyone else
        ignore(encode(&message).map(|msg| self.send(Some(peer_endpoint).iter(), &msg)));
    }


    fn handle_bootstrap_id_response(&mut self, peer_endpoint: Endpoint, bytes: Bytes, is_client: bool) {
        if self.all_connections.0.contains_key(&peer_endpoint) {
            // ignore further request once added or not in sequence (not recorded as pending)
            return;
        }
        let bootstrap_id_response_msg = decode::<BootstrapIdResponse>(&bytes);
        if bootstrap_id_response_msg.is_err() {  // TODO handle non routing connection here
            return;
        }
        let bootstrap_id_response_msg = bootstrap_id_response_msg.unwrap();
        assert!(self.bootstrap_node_id.is_none());
        assert_eq!(self.bootstrap_endpoint, Some(peer_endpoint.clone()));
        self.bootstrap_node_id = Some(bootstrap_id_response_msg.sender_id.clone());

        self.all_connections.0.insert(peer_endpoint.clone(),
                                      bootstrap_id_response_msg.sender_id.clone());
        self.all_connections.1.insert(bootstrap_id_response_msg.sender_id, vec![peer_endpoint]);

        // put our public id so that our connect requests are validated
        //self.put_own_public_id(); // FIXME enable this with sentinel

        // connect to close group
        let find_group_msg = self.construct_find_group_msg();
        ignore(encode(&find_group_msg).map(|msg|self.send_to_bootstrap_node(&msg)));
    }

    fn put_own_public_id(&mut self) {
        let our_public_id: types::PublicId = types::PublicId::new(&self.id);
        let message_id = self.get_next_message_id();
        let destination = types::DestinationAddress{ dest: our_public_id.name(), relay_to: None };
        let source = types::SourceAddress{ from_node: self.id(), from_group: None,
                                           reply_to: self.bootstrap_node_id.clone(), relayed_for: None };
        let authority = Authority::ManagedNode;
        let request = PutPublicId{ public_id: our_public_id };
        let header = MessageHeader::new(message_id, destination, source, authority);
        let message = RoutingMessage::new(MessageTypeTag::PutPublicId, header,
            request, &self.id.get_crypto_secret_sign_key());
        ignore(encode(&message).map(|msg|self.send_to_bootstrap_node(&msg)));
    }

    fn handle_new_connect_event(&mut self, peer_endpoint: Endpoint) {
        println!(" handle_new_connect_event peer_ep : {:?}", peer_endpoint);
        match self.routing_table.mark_as_connected(&peer_endpoint) {
            Some(peer_id) => {
                // If the peer is already in our routing table, just add its endpoint to
                // `all_connections`
                println!("RT (size : {:?}) Marked connected peer_id : {:?} , peer_ep : {:?}",
                         self.routing_table.size(), peer_id, peer_endpoint);
                self.all_connections.0.insert(peer_endpoint.clone(), peer_id.clone());
                let found = if let Some(peer_endpoints) = self.all_connections.1.get_mut(&peer_id) {
                    assert!(!peer_endpoints.is_empty());
                    peer_endpoints.push(peer_endpoint.clone());
                    true
                } else {
                    false
                };
                if !found {
                    self.all_connections.1.insert(peer_id, vec![peer_endpoint]);
                }
            },
            None => {
                // This is an unexpected connection - send a challenge_request to get the peer's ID
                let challenge_request = ChallengeRequest{ name: self.own_name.clone() };
                let _ = encode(&challenge_request).map(
                    |serialised_message| self.connection_manager.send(peer_endpoint,
                                                                      serialised_message));
            },
        }
    }

    fn handle_lost_connection_event(&mut self, peer_endpoint: Endpoint) {
        println!(" handle_lost_connection_event peer_ep : {:?}", peer_endpoint);
        let removed_entry = self.all_connections.0.remove(&peer_endpoint);
        if removed_entry.is_some() {
            let peer_id = removed_entry.unwrap();
            self.routing_table.drop_node(&peer_id);
            println!("RT (size : {:?})", self.routing_table.size());
            match self.all_connections.1.get(&peer_id) {
                Some(peer_endpoints) => {
                    for endpoint in peer_endpoints {
                        let _ = self.all_connections.0.remove(&endpoint);
                        self.connection_manager.drop_node(endpoint.clone());
                    }
                }
                None => (),
            }
            self.all_connections.1.remove(&peer_id);
          // FIXME call handle_churn here
        }
    }

    //TODO(team) This method needs to be triggered when routing table close group changes
    fn on_churn(&mut self, close_group: Vec<NameType>) {
        let actions = self.interface.handle_churn(close_group);
        self.invoke_routing_actions(actions);
    }

    fn invoke_routing_actions(&mut self, routing_actions: Vec<node_interface::MethodCall>) {
        for routing_action in routing_actions {
            match routing_action {
                node_interface::MethodCall::Put { destination: x, content: y, } => self.put(x, y),
                node_interface::MethodCall::Get { type_id: x, name: y, } => self.get(x, y),
                node_interface::MethodCall::Refresh { content: x, } => self.refresh(x),
                node_interface::MethodCall::Post => unimplemented!(),
                node_interface::MethodCall::None => (),
                // TODO
                node_interface::MethodCall::SendOn { destination: _ } => unimplemented!(),
            }
        }
    }

    fn message_received(&mut self, peer_id: &NameType, serialised_msg: Bytes) -> RoutingResult {
        // Parse
        let message = try!(decode::<RoutingMessage>(&serialised_msg));
        let header = message.message_header;
        let body = message.serialised_body;

        // filter check
        if self.filter.check(&header.get_filter()) {
            // should just return quietly
            return Err(RoutingError::FilterCheckFailed);
        }
        // add to filter
        self.filter.add(header.get_filter());

        // check if we can add source to rt
        self.refresh_routing_table(&header.source.from_node);

        // add to cache
        if message.message_type == MessageTypeTag::GetDataResponse {
            let get_data_response = try!(decode::<GetDataResponse>(&body));
            let _ = get_data_response.data.map(|data| {
                if data.len() != 0 {
                    let _ = self.mut_interface().handle_cache_put(
                        header.from_authority(), header.from(), data);
                }
            });
        }

        // cache check / response
        if message.message_type == MessageTypeTag::GetData {
            let get_data = try!(decode::<GetData>(&body));

            let retrieved_data = self.mut_interface().handle_cache_get(
                get_data.name_and_type_id.type_id.clone() as u64,
                get_data.name_and_type_id.name.clone(),
                header.from_authority(),
                header.from());

            match retrieved_data {
                Ok(action) => match action {
                    MessageAction::Reply(data) => {
                        let reply = self.construct_get_data_response_msg(&header, &get_data, data);
                        return encode(&reply).map(|reply| {
                            self.send_swarm_or_parallel(&header.send_to().dest, &reply);
                        }).map_err(From::from);
                    },
                    _ => (),
                },
                Err(_) => (),
            };
        }

        self.send_swarm_or_parallel(&header.destination.dest, &serialised_msg);

        // handle relay request/response
        if header.destination.dest == self.own_name {
            self.send_by_name(header.destination.relay_to.iter(), serialised_msg);
        }

        if !self.address_in_close_group_range(&header.destination.dest) {
            println!("{:?} not for us ", self.own_name);
            return Ok(());
        }

        // Drop message before Sentinel check if it is a direct message type (Connect, ConnectResponse)
        // and this node is in the group but the message destination is another group member node.
        if message.message_type == MessageTypeTag::ConnectRequest || message.message_type == MessageTypeTag::ConnectResponse {
            if header.destination.dest != self.own_name &&
                (header.destination.relay_to.is_none() ||
                 header.destination.relay_to != Some(self.own_name.clone())) { // "not for me"
                return Ok(());
            }
        }

        // pre-sentinel message handling
        match message.message_type {
            MessageTypeTag::UnauthorisedPut => self.handle_put_data(header, body),
            MessageTypeTag::GetKey => self.handle_get_key(header, body),
            MessageTypeTag::GetGroupKey => self.handle_get_group_key(header, body),
            _ => {
                // Sentinel check

                // switch message type
                match message.message_type {
                    MessageTypeTag::ConnectRequest => self.handle_connect_request(header, body, message.signature),
                    MessageTypeTag::ConnectResponse => self.handle_connect_response(body),
                    MessageTypeTag::FindGroup => self.handle_find_group(header, body),
                    MessageTypeTag::FindGroupResponse => self.handle_find_group_response(header, body),
                    MessageTypeTag::GetData => self.handle_get_data(header, body),
                    MessageTypeTag::GetDataResponse => self.handle_get_data_response(header, body),
                    MessageTypeTag::Post => self.handle_post(header, body),
                    MessageTypeTag::PostResponse => self.handle_post_response(header, body),
                    MessageTypeTag::PutData => self.handle_put_data(header, body),
                    MessageTypeTag::PutDataResponse => self.handle_put_data_response(header, body),
                    MessageTypeTag::PutPublicId => self.handle_put_public_id(header, body),
                    //PutKey,
                    _ => {
                        println!("unhandled message from {:?}", peer_id);
                        Err(RoutingError::UnknownMessageType)
                    }
                }
            }
        }
    }

    fn refresh_routing_table(&mut self, from_node : &NameType) {
      if self.routing_table.check_node(from_node) {
          // FIXME: (ben) this implementation of connection_cache is far from optimal
          //        it is a quick patch and can be improved.
          let mut next_connect_request : Option<NameType> = None;
          let time_now = SteadyTime::now();
          self.connection_cache.entry(from_node.clone())
                               .or_insert(time_now);
          for (new_node, time) in self.connection_cache.iter() {
              // note that the first method to establish the close group
              // is through explicit FindGroup messages.
              // This refresh on scanning messages is secondary, hence the long delay.
              if time_now - *time > Duration::seconds(5) {
                  next_connect_request = Some(new_node.clone());
                  break;
              }
          }
          match next_connect_request {
              Some(connect_to_node) => {
                  self.connection_cache.remove(&connect_to_node);
                  // check whether it is still valid to add this node.
                  if self.routing_table.check_node(&connect_to_node) {
                      ignore(self.send_connect_request_msg(&connect_to_node));
                  }
              },
              None => ()
          }
       }
    }


    fn handle_bootstrap_message(&mut self, peer_endpoint: Endpoint, serialised_msg: Bytes) -> RoutingResult {
        let message = try!(decode::<RoutingMessage>(&serialised_msg));

        if message.message_type == MessageTypeTag::BootstrapIdRequest {
            let request = try!(decode::<BootstrapIdRequest>(&message.serialised_body));
            if self.bootstrap_node_id.is_none() {
                self.bootstrap_node_id = Some(request.sender_id.clone());
                self.bootstrap_endpoint = Some(peer_endpoint.clone());
            }
            self.all_connections.0.insert(peer_endpoint.clone(), request.sender_id.clone());
            self.all_connections.1.insert(request.sender_id, vec![peer_endpoint.clone()]);
            self.send_bootstrap_id_response(peer_endpoint);
        } else if message.message_type == MessageTypeTag::BootstrapIdResponse {
            self.handle_bootstrap_id_response(peer_endpoint, message.serialised_body,
                message.message_header.authority == Authority::Client);
        }
        Ok(())
    }

    /// This method sends a GetGroupKeyResponse message on receiving the GetGroupKey request.
    /// It collects and replies with all the public signature keys from its close group.
    fn handle_get_group_key(&mut self, original_header : MessageHeader, body : Bytes) -> RoutingResult {
        let get_group_key = try!(decode::<GetGroupKey>(&body));

        let group_keys = self.routing_table.our_close_group()
                         .into_iter()
                         .map(|node| (node.fob.name(), node.fob.public_sign_key))
                         // add our own signature key
                         .chain(Some((self.id.get_name(), self.id.get_public_sign_key())).into_iter())
                         .collect::<Vec<_>>();

        let routing_msg = self.construct_get_group_key_response_msg(&original_header,
                                                                    &get_group_key,
                                                                    group_keys);
        let encoded_msg = try!(encode(&routing_msg));
        let original_group = original_header.from_group();
        original_group.map(|group| self.send_swarm_or_parallel(&group, &encoded_msg));
        Ok(())
    }

    fn handle_connect_request(&mut self, original_header: MessageHeader, body: Bytes, signature: Signature) -> RoutingResult {
        println!("{:?} received ConnectRequest ", self.own_name);
        let connect_request = try!(decode::<ConnectRequest>(&body));
        // Collect the local and external endpoints into a single vector to construct a NodeInfo
        let mut peer_endpoints = connect_request.local_endpoints.clone();
        peer_endpoints.extend(connect_request.external_endpoints.clone().into_iter());
        let peer_node_info =
            NodeInfo::new(connect_request.requester_fob.clone(), peer_endpoints, None);

        // Try to add to the routing table.  If unsuccessful, no need to continue.
        let (added, _) = self.routing_table.add_node(peer_node_info.clone());
        if !added {
            return Err(RoutingError::AlreadyConnected);  // FIXME can also be not added to rt
        }
        println!("RT (size : {:?}) added {:?} ", self.routing_table.size(), peer_node_info.fob.name());

        // Try to connect to the peer.
        self.connection_manager.connect(connect_request.local_endpoints.clone());
        self.connection_manager.connect(connect_request.external_endpoints.clone());

        // Send the response containing our details.
        let routing_msg = self.construct_connect_response_msg(&original_header, &body, &signature, &connect_request);
        let serialised_message = try!(encode(&routing_msg));

        self.send_swarm_or_parallel(&connect_request.requester_id, &serialised_message);
        self.send_to_bootstrap_node(&serialised_message);
        self.send_by_name(original_header.source.reply_to.iter(), serialised_message);

        Ok(())
    }

    fn handle_connect_response(&mut self, body: Bytes) -> RoutingResult {
        println!("{:?} received ConnectResponse", self.own_name);
        let connect_response = try!(decode::<ConnectResponse>(&body));

        // Verify a connect request was initiated by us.
        let connect_request = try!(decode::<ConnectRequest>(&connect_response.serialised_connect_request));
        if connect_request.requester_id != self.id.get_name() ||
           !verify_detached(&connect_response.connect_request_signature.get_crypto_signature(),
                            &connect_response.serialised_connect_request[..],
                            &self.id.get_crypto_public_sign_key()) {
            return Err(RoutingError::Response(ResponseError::InvalidRequest));
        }

        // Collect the local and external endpoints into a single vector to construct a NodeInfo
        let mut peer_endpoints = connect_response.receiver_local_endpoints.clone();
        peer_endpoints.extend(connect_response.receiver_external_endpoints.clone().into_iter());
        let peer_node_info =
            NodeInfo::new(connect_response.receiver_fob.clone(), peer_endpoints, None);

        // Try to add to the routing table.  If unsuccessful, no need to continue.
        let (added, _) = self.routing_table.add_node(peer_node_info.clone());
        if !added {
           return Ok(());
        }
        println!("RT (size : {:?}) added {:?}", self.routing_table.size(), peer_node_info.fob.name());

        // Try to connect to the peer.
        self.connection_manager.connect(connect_response.receiver_local_endpoints.clone());
        self.connection_manager.connect(connect_response.receiver_external_endpoints.clone());
        Ok(())
    }

    fn handle_find_group(&mut self, original_header: MessageHeader, body: Bytes) -> RoutingResult {
        println!("{:?} received FindGroup {:?}", self.own_name, original_header.message_id);
        let find_group = try!(decode::<FindGroup>(&body));

        let group = self.routing_table.our_close_group().into_iter()
                    .map(|x|x.fob)
                    // add ourselves
                    .chain(Some(types::PublicId::new(&self.id)).into_iter())
                    .collect::<Vec<_>>();

        let routing_msg = self.construct_find_group_response_msg(&original_header, &find_group, group);

        let serialised_msg = try!(encode(&routing_msg));

        self.send_swarm_or_parallel(&original_header.send_to().dest, &serialised_msg);
        // if node is in my group && in non routing list send it to non_routing list as well
        self.send_by_name(original_header.source.relayed_for.iter(), serialised_msg);

        Ok(())
    }

    fn handle_find_group_response(&mut self, original_header: MessageHeader, body: Bytes) -> RoutingResult {
        println!("{:?} received FindGroupResponse", self.own_name);
        let find_group_response = try!(decode::<FindGroupResponse>(&body));
        for peer in find_group_response.group {
            if self.routing_table.check_node(&peer.name()) {
                ignore(self.send_connect_request_msg(&peer.name()));
            }
        }
        Ok(())
    }

    //FIXME  not sure if we need to return a RoutingResult or a generic error
    fn send_connect_request_msg(&mut self, peer_id: &NameType) -> RoutingResult {
        let routing_msg = self.construct_connect_request_msg(&peer_id);
        let serialised_message = try!(encode(&routing_msg));

        self.send_swarm_or_parallel(peer_id, &serialised_message);
        self.send_to_bootstrap_node(&serialised_message);
        Ok(())
    }

    fn handle_get_data(&mut self, header: MessageHeader, body: Bytes) -> RoutingResult {
        let get_data = try!(decode::<GetData>(&body));
        let type_id = get_data.name_and_type_id.type_id.clone();
        let name = get_data.name_and_type_id.name.clone();
        let our_authority = our_authority(&name, &header, &self.routing_table);
        let from_authority = header.from_authority();
        let from = header.from();

        match self.mut_interface().handle_get(type_id, name, our_authority.clone(), from_authority, from) {
            Ok(action) => match action {
                MessageAction::Reply(data) => {
                    let routing_msg = RoutingMessage::new(MessageTypeTag::GetDataResponse, header.create_reply(&self.own_name, &our_authority),
                        GetDataResponse{ name_and_type_id :get_data.name_and_type_id, data: Ok(data) },
                        &self.id.get_crypto_secret_sign_key());
                    let encoded_msg = try!(encode(&routing_msg));
                    self.send_swarm_or_parallel(&header.send_to().dest, &encoded_msg);
                },
                MessageAction::SendOn(dest_nodes) => {
                    for dest_node in dest_nodes {
                        let send_on_header = header.create_send_on(&self.own_name, &our_authority, &dest_node);
                        let routing_msg = RoutingMessage::new(MessageTypeTag::GetData, send_on_header,
                            get_data.clone(), &self.id.get_crypto_secret_sign_key());
                        let encoded_msg = try!(encode(&routing_msg));
                        self.send_swarm_or_parallel(&dest_node, &encoded_msg);
                    }
                }
            },
            Err(InterfaceError::Abort) => {;},
            Err(InterfaceError::Response(error)) => {
                let routing_msg = RoutingMessage::new(MessageTypeTag::GetDataResponse, header.create_reply(&self.own_name, &our_authority),
                    GetDataResponse{ name_and_type_id :get_data.name_and_type_id, data: Err(error) },
                    &self.id.get_crypto_secret_sign_key());
                let encoded_msg = try!(encode(&routing_msg));
                self.send_swarm_or_parallel(&header.send_to().dest, &encoded_msg);
            }
        }
        Ok(())
    }

    fn handle_get_key(&mut self, header: MessageHeader, body: Bytes) -> RoutingResult {
        let get_key = try!(decode::<GetKey>(&body));
        let type_id = 106u64;
        let our_authority = our_authority(&get_key.target_id, &header, &self.routing_table);
        let from_authority = header.from_authority();
        let from = header.from();
        let name = get_key.target_id.clone();

        let action = try!(self.mut_interface().handle_get_key(type_id, name, our_authority.clone(), from_authority, from));

        match action {
            MessageAction::Reply(data) => {
                let public_key = try!(decode::<types::PublicSignKey>(&data));
                let routing_msg = RoutingMessage::new(MessageTypeTag::GetKeyResponse, header.create_reply(&self.own_name, &our_authority),
                    GetKeyResponse{ address : get_key.target_id.clone(), public_sign_key : public_key },
                    &self.id.get_crypto_secret_sign_key());
                let encoded_msg = try!(encode(&routing_msg));
                self.send_swarm_or_parallel(&header.send_to().dest, &encoded_msg);
                },
            MessageAction::SendOn(dest_nodes) => {
                for dest_node in dest_nodes {
                    let send_on_header = header.create_send_on(&self.own_name, &our_authority, &dest_node);
                    let routing_msg = RoutingMessage::new(MessageTypeTag::GetKey, send_on_header,
                        get_key.clone(), &self.id.get_crypto_secret_sign_key());
                    let encoded_msg = try!(encode(&routing_msg));
                    self.send_swarm_or_parallel(&dest_node, &encoded_msg);
                }
            }
        }
        Ok(())
    }

    fn handle_get_data_response(&mut self, header: MessageHeader, body: Bytes) -> RoutingResult {
        let get_data_response = try!(decode::<GetDataResponse>(&body));
        let from = header.from();
        self.mut_interface().handle_get_response(from, get_data_response.data);
        Ok(())
    }

    fn handle_post(&mut self, header : MessageHeader, body : Bytes) -> RoutingResult {
        let post = try!(decode::<Post>(&body));
        let our_authority = our_authority(&post.name, &header, &self.routing_table);
        match try!(self.mut_interface().handle_post(our_authority.clone(),
                                                    header.authority.clone(),
                                                    header.from(),
                                                    post.name.clone(),
                                                    post.data.clone())) {
            MessageAction::Reply(data) => {
                Ok(()) // TODO: implement post_response
            },
            MessageAction::SendOn(destinations) => {
                for destination in destinations {
                    let send_on_header = header.create_send_on(&self.own_name,
                        &our_authority, &destination);
                    let routing_msg = RoutingMessage::new(MessageTypeTag::Post,
                        send_on_header, post.clone(), &self.id.get_crypto_secret_sign_key());
                    self.send_swarm_or_parallel(&destination, &try!(encode(&routing_msg)));
                }
                Ok(())
            },
        }
    }

    fn handle_post_response(&self, header : MessageHeader, body : Bytes) -> RoutingResult {
        // currently no post_response object; out of sprint (2015-04-30)
        Ok(())
    }


    /// On bootstrapping a node can temporarily publish its PublicId in the group.
    /// Sentinel will query this pool. No handle_get_public_id is needed.
    // TODO (Ben): check whether to accept id into group;
    // restrict on minimal similar number of leading bits.
    fn handle_put_public_id(&mut self, header: MessageHeader, body: Bytes) -> RoutingResult {
        let put_public_id = try!(decode::<PutPublicId>(&body));
        let our_authority = our_authority(&put_public_id.public_id.name(), &header, &self.routing_table);

        match (header.from_authority(), our_authority.clone(), put_public_id.public_id.is_relocated()) {
            (Authority::ManagedNode, Authority::NaeManager, false) => {
                let mut put_public_id_relocated = put_public_id.clone();

                let mut close_group_node_ids : Vec<NameType> = Vec::new();
                for node_info in self.routing_table.our_close_group() {
                    close_group_node_ids.push(node_info.id());
                }

                let relocated_name =  try!(types::calculate_relocated_name(
                                            close_group_node_ids,
                                            &put_public_id.public_id.name()));
                // assign_relocated_name
                put_public_id_relocated.public_id.assign_relocated_name(relocated_name.clone());

                //  SendOn to relocated_name group, which will actually store the relocated public id
                let send_on_header = header.create_send_on(&self.own_name, &our_authority, &relocated_name);
                let routing_msg = RoutingMessage::new(MessageTypeTag::PutPublicId,
                                                      send_on_header, put_public_id_relocated,
                                                      &self.id.get_crypto_secret_sign_key());
                self.send_swarm_or_parallel(&relocated_name, &try!(encode(&routing_msg)));
                Ok(())
            },
            (Authority::NaeManager, Authority::NaeManager, true) => {
                // Note: The "if" check is workaround for absense of sentinel. This avoids redundant PutPublicIdResponse responses.
                if !self.public_id_cache.check(&put_public_id.public_id.name()) {
                  self.public_id_cache.add(put_public_id.public_id.name(), put_public_id.public_id.clone());
                  // Reply with PutPublicIdResponse to the reply_to address
                  let routing_msg = RoutingMessage::new(MessageTypeTag::PutPublicIdResponse,
                                                        header.create_reply(&self.own_name, &our_authority),
                                                        PutPublicIdResponse{ public_id :put_public_id.public_id.clone() },
                                                        &self.id.get_crypto_secret_sign_key());
                  let encoded_msg = try!(encode(&routing_msg));
                  self.send_swarm_or_parallel(&put_public_id.public_id.name(), &encoded_msg);
                }
                Ok(())
            },
            _ => {
                Err(RoutingError::BadAuthority)
            }
        }
    }

    fn handle_put_public_id_reponse(&mut self, header: MessageHeader, body: Bytes) -> RoutingResult {
        let put_public_id_response = try!(decode::<PutPublicIdResponse>(&body));
        // TODO (Ben) connect this to refactored code (as discussed)
        Ok(())
    }

    // // for clients, below methods are required
    fn handle_put_data(&mut self, header: MessageHeader, body: Bytes) -> RoutingResult {
        let put_data = try!(decode::<PutData>(&body));
        let our_authority = our_authority(&put_data.name, &header, &self.routing_table);
        let from_authority = header.from_authority();
        let from = header.from();
        let to = header.send_to();

        match try!(self.mut_interface().handle_put(our_authority.clone(), from_authority, from,
                                                   to, put_data.data.clone())) {
            MessageAction::Reply(reply_data) => {
                let reply_header = header.create_reply(&self.own_name, &our_authority);
                let reply_to = match our_authority {
                    Authority::ClientManager => match header.reply_to() {
                        Some(client) => client,
                        None => header.from()
                    },
                    _ => header.from()
                };
                let put_data_response = PutDataResponse {
                    name : put_data.name.clone(),
                    data : Ok(reply_data),
                };
                let routing_msg = RoutingMessage::new(MessageTypeTag::PutDataResponse,
                    reply_header, put_data_response, &self.id.get_crypto_secret_sign_key());
                self.send_swarm_or_parallel(&reply_to, &try!(encode(&routing_msg)));
                Ok(())
            },
            MessageAction::SendOn(destinations) => {
                for destination in destinations {
                    let send_on_header = header.create_send_on(&self.own_name,
                        &our_authority, &destination);
                    let routing_msg = RoutingMessage::new(MessageTypeTag::PutData,
                        send_on_header, put_data.clone(), &self.id.get_crypto_secret_sign_key());
                    self.send_swarm_or_parallel(&destination, &try!(encode(&routing_msg)));
                }
                Ok(())
            },
        }
    }

    fn handle_put_data_response(&mut self, header: MessageHeader, body: Bytes) -> RoutingResult {
        let put_data_response = try!(decode::<PutDataResponse>(&body));
        let from_authority = header.from_authority();
        let from = header.from();
        // TODO: result verification
        self.mut_interface().handle_put_response(from_authority, from, put_data_response.data);
        Ok(())
    }

    fn our_source_address(&self) -> types::SourceAddress {
        if self.bootstrap_endpoint.is_some() {
            let id = self.all_connections.0.get(&self.bootstrap_endpoint.clone().unwrap());
            if id.is_some() {
                return types::SourceAddress{ from_node: id.unwrap().clone(),
                                             from_group: None,
                                             reply_to: None,
                                             relayed_for: Some(self.own_name.clone()) }
            }
        }
        return types::SourceAddress{ from_node: self.own_name.clone(), from_group: None, reply_to: None, relayed_for: None }
    }

    fn group_address_for_group(&self, group_address : &types::GroupAddress) -> types::SourceAddress {
        types::SourceAddress {
          from_node : self.own_name.clone(),
          from_group : Some(group_address.clone()),
          reply_to : None,
          relayed_for: None
        }
    }

    fn our_group_address(&self, group_id: NameType) -> types::SourceAddress {
        types::SourceAddress{ from_node: self.own_name.clone(), from_group: Some(group_id.clone()),
                              reply_to: None, relayed_for: None }
    }

    fn construct_get_group_key_response_msg(&mut self, original_header : &MessageHeader,
                                            get_group_key : &GetGroupKey,
                                            group_keys : Vec<(NameType, types::PublicSignKey)>)
                                            -> RoutingMessage {
        let header = MessageHeader::new(
            // Sentinel accumulates on the same MessageId to be returned.
            original_header.message_id.clone(),
            original_header.send_to(),
            self.our_group_address(get_group_key.target_id.clone()),
            Authority::NaeManager);

        RoutingMessage::new(MessageTypeTag::GetGroupKeyResponse, header,
            GetGroupKeyResponse{ public_sign_keys  : group_keys },
            &self.id.get_crypto_secret_sign_key()
        )
    }

    fn construct_find_group_msg(&mut self) -> RoutingMessage {
        let header = MessageHeader::new(
            self.get_next_message_id(),
            types::DestinationAddress {
                 dest:     self.own_name.clone(),
                 relay_to: None
            },
            self.our_source_address(),
            Authority::ManagedNode);

        RoutingMessage::new(MessageTypeTag::FindGroup, header,
            FindGroup{ requester_id: self.own_name.clone(),
                       target_id:    self.own_name.clone()},
            &self.id.get_crypto_secret_sign_key())
    }

    fn construct_find_group_response_msg(&mut self, original_header : &MessageHeader,
                                         find_group: &FindGroup,
                                         group: Vec<types::PublicId>) -> RoutingMessage {
        let header = MessageHeader::new(self.get_next_message_id(),
            original_header.send_to(),
            self.our_group_address(find_group.target_id.clone()),
            Authority::NaeManager);

        RoutingMessage::new(MessageTypeTag::FindGroupResponse, header,
            FindGroupResponse{ group: group }, &self.id.get_crypto_secret_sign_key())
    }

    // TODO(Ben): this function breaks consistency and does not return RoutingMessage
    fn construct_success_msg(&mut self) -> ConnectSuccess {
        let connect_success = ConnectSuccess {
                                                peer_id: self.own_name.clone(),
                                                peer_fob: types::PublicId::new(&self.id),
                                              };
        return connect_success
    }

    fn construct_connect_request_msg(&mut self, peer_id: &NameType) -> RoutingMessage {
        let header = MessageHeader::new(self.get_next_message_id(),
            types::DestinationAddress {dest: peer_id.clone(), relay_to: None },
            self.our_source_address(), Authority::ManagedNode);

        // FIXME: We're sending all accepting connections as local since we don't differentiate
        // between local and external yet.
        let connect_request = ConnectRequest {
            local_endpoints: self.accepting_on.clone(),
            external_endpoints: vec![],
            requester_id: self.own_name.clone(),
            receiver_id: peer_id.clone(),
            requester_fob: types::PublicId::new(&self.id),
        };

        RoutingMessage::new(MessageTypeTag::ConnectRequest, header, connect_request,
            &self.id.get_crypto_secret_sign_key())
    }

    fn construct_connect_response_msg(&mut self, original_header : &MessageHeader, body: &Bytes, signature: &Signature,
                                      connect_request: &ConnectRequest) -> RoutingMessage {
        println!("{:?} construct_connect_response_msg ", self.own_name);
        debug_assert!(connect_request.receiver_id == self.own_name, format!("{:?} == {:?} failed", self.own_name, connect_request.receiver_id));

        let header = MessageHeader::new(original_header.message_id,
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

    fn construct_get_data_response_msg(&mut self, original_header: &MessageHeader,
                                       get_data: &GetData, data: Vec<u8>) -> RoutingMessage {
        let header = MessageHeader::new(self.get_next_message_id(),
            original_header.send_to(), self.our_source_address(),
            Authority::ManagedNode);
        let get_data_response = GetDataResponse {
            name_and_type_id: get_data.name_and_type_id.clone(), data: Ok(data)
        };
        RoutingMessage::new(MessageTypeTag::GetDataResponse, header,
            get_data_response, &self.id.get_crypto_secret_sign_key())
    }

    fn get_next_message_id(&mut self) -> MessageId {
        let temp = self.next_message_id;
        self.next_message_id += 1;
        return temp;
    }

    fn send<'a, I>(&self, targets: I, message: &Bytes) where I: Iterator<Item=&'a Endpoint> {
        for target in targets {
            ignore(self.connection_manager.send(target.clone(), message.clone()));
        }
    }

    fn send_by_name<'a, I>(&self, peers: I, serialised_msg: Bytes) where I: Iterator<Item=&'a NameType> {
        for peer in peers {
            self.send(self.name_to_endpoint(peer).into_iter(), &serialised_msg);
        }
    }

    fn name_to_endpoint(&self, name: &NameType) -> Option<&Endpoint> {
        match self.all_connections.1.get(name) {
            Some(endpoints) => {
                                   assert!(!endpoints.is_empty());
                                   Some(&endpoints[0])
                               },
            None => None
        }
    }

    fn endpoint_to_name(&self, endpoint: &Endpoint) -> Option<&NameType> {
        self.all_connections.0.get(&endpoint)
    }

    fn send_to_bootstrap_node(&mut self, msg: &Bytes) {
        self.send(self.bootstrap_endpoint.iter(), &msg);
    }

    fn send_swarm_or_parallel(&self, target: &NameType, msg: &Bytes) {
        for peer in self.routing_table.target_nodes(target) {
            match self.all_connections.1.get(&peer.id()) {
                Some(peer_endpoints) => {
                    assert!(!peer_endpoints.is_empty());
                    if self.connection_manager.send(peer_endpoints[0].clone(),
                                                    msg.clone()).is_err() {
                        println!("{:?} failed to send to {:?}", self.own_name, peer.id());
                    }
                }
                None => ()
            }
        }
        //FIXME (prakash) use this
//      self.send(self.routing_table.target_nodes(target).iter().filter_map(|node_info|self.name_to_endpoint(node_info.id)), msg);
    }

    fn address_in_close_group_range(&self, address: &NameType) -> bool {
        if self.routing_table.size() < RoutingTable::get_group_size() {
            return true;
        }

        match self.routing_table.our_close_group().pop() {
            Some(furthest_close_node) => {
                closer_to_target_or_equal(&address, &furthest_close_node.id(), &self.own_name)
            },
            None => false  // ...should never reach here
        }
    }

    pub fn id(&self) -> NameType { self.own_name.clone() }

    fn mut_interface(&mut self) -> &mut F { self.interface.deref_mut() }
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
    use routing_node::{RoutingNode};
    use node_interface::*;
    use name_type::NameType;
    use super::encode;
    use types::MessageAction;
    use error::{ResponseError, InterfaceError};
    use sendable::Sendable;
    use messages::put_data::PutData;
    use messages::put_data_response::PutDataResponse;
    use messages::get_data::GetData;
    use messages::get_data_response::GetDataResponse;
    use messages::get_client_key::GetKey;
    use messages::post::Post;
    use messages::put_public_id::PutPublicId;
    use messages::{RoutingMessage, MessageTypeTag};
    use message_header::MessageHeader;
    use std::sync::{Arc, Mutex};
    use routing_table;
    use test_utils::Random;
    use rand::random;
    use name_type::{closer_to_target};
    use types;
    use types::{Id, PublicId};
    use authority::Authority;
    use rustc_serialize::{Encodable, Decodable};
    use cbor::{Encoder};
    use std::thread;
    use test_utils::{random_endpoint, random_endpoints};

    struct NullInterface;

    #[derive(Clone)]
    struct Stats {
        call_count: u32,
        data: Vec<u8>
    }

    struct TestInterface {
        stats: Arc<Mutex<Stats>>
    }

    struct TestData {
        data: Vec<u8>
    }

    impl TestData {
        fn new(in_data: Vec<u8>) -> TestData {
            TestData { data: in_data }
        }
    }

    impl Sendable for TestData {
        fn name(&self) -> NameType { Random::generate_random() }

        fn type_tag(&self)->u64 { unimplemented!() }

        fn serialised_contents(&self)->Vec<u8> { self.data.clone() }

        fn refresh(&self)->bool {
            false
        }

        fn merge(&self, responses: Vec<Box<Sendable>>) -> Option<Box<Sendable>> { None }
    }

    impl Interface for TestInterface {
        fn handle_get_key(&mut self, type_id: u64, name : NameType, our_authority: Authority,
                          from_authority: Authority, from_address: NameType) -> Result<MessageAction, InterfaceError> {
            let stats = self.stats.clone();
            let mut stats_value = stats.lock().unwrap();
            stats_value.call_count += 1;
            let data = stats_value.data.clone();
            Ok(MessageAction::Reply(data))
        }
        fn handle_get(&mut self, type_id: u64, name : NameType, our_authority: Authority,
                      from_authority: Authority, from_address: NameType) -> Result<MessageAction, InterfaceError> {
            let stats = self.stats.clone();
            let mut stats_value = stats.lock().unwrap();
            stats_value.call_count += 1;
            Ok(MessageAction::Reply("handle_get called".to_string().into_bytes()))
        }
        fn handle_put(&mut self, our_authority: Authority, from_authority: Authority,
                    from_address: NameType, dest_address: types::DestinationAddress,
                    data: Vec<u8>) -> Result<MessageAction, InterfaceError> {
            let stats = self.stats.clone();
            let mut stats_value = stats.lock().unwrap();
            stats_value.call_count += 1;
            stats_value.data = match from_authority {
                Authority::Unknown => "UnauthorisedPut".to_string().into_bytes(),
                _   => "AuthorisedPut".to_string().into_bytes(),
            };
            Ok(MessageAction::Reply(data))
        }
        fn handle_post(&mut self, our_authority: Authority, from_authority: Authority,
                       from_address: NameType, name: NameType, data: Vec<u8>) -> Result<MessageAction, InterfaceError> {
            let stats = self.stats.clone();
            let mut stats_value = stats.lock().unwrap();
            stats_value.call_count += 1;
            stats_value.data = data.clone();
            Ok(MessageAction::Reply(data))
        }
        fn handle_get_response(&mut self, from_address: NameType, response: Result<Vec<u8>,
                               ResponseError>) -> MethodCall {
            let stats = self.stats.clone();
            let mut stats_value = stats.lock().unwrap();
            stats_value.call_count += 1;
            stats_value.data = "handle_get_response called".to_string().into_bytes();
            MethodCall::None
        }
        fn handle_put_response(&mut self, from_authority: Authority, from_address: NameType,
                               response: Result<Vec<u8>, ResponseError>) -> MethodCall {
            let stats = self.stats.clone();
            let mut stats_value = stats.lock().unwrap();
            stats_value.call_count += 1;
            stats_value.data = match response {
               Ok(data) => data,
                Err(_) => vec![]
            };
            MethodCall::None
        }
        fn handle_post_response(&mut self, from_authority: Authority, from_address: NameType,
                                response: Result<Vec<u8>, ResponseError>) {
            unimplemented!();
        }
        fn handle_churn(&mut self, close_group: Vec<NameType>)
            -> Vec<MethodCall> {
            unimplemented!();
        }
        fn handle_cache_get(&mut self, type_id: u64, name : NameType, from_authority: Authority,
                            from_address: NameType) -> Result<MessageAction, InterfaceError> {
            Err(InterfaceError::Abort)
        }
        fn handle_cache_put(&mut self, from_authority: Authority, from_address: NameType,
                            data: Vec<u8>) -> Result<MessageAction, InterfaceError> {
            Err(InterfaceError::Abort)
        }
    }

    #[test]
    fn check_next_id() {
      let mut routing_node = RoutingNode::new(TestInterface { stats: Arc::new(Mutex::new(Stats {call_count: 0, data: vec![]})) });
      assert_eq!(routing_node.get_next_message_id() + 1, routing_node.get_next_message_id());
    }

    fn call_operation<T>(operation: T, message_type: MessageTypeTag, stats: Arc<Mutex<Stats>>) -> Stats where T: Encodable, T: Decodable {
        let stats_copy = stats.clone();
        let mut n1 = RoutingNode::new(TestInterface { stats: stats_copy });
        let header = MessageHeader {
            message_id:  n1.get_next_message_id(),
            destination: types::DestinationAddress { dest: n1.own_name.clone(), relay_to: None },
            source:      types::SourceAddress { from_node: Random::generate_random(), from_group: None, reply_to: None, relayed_for: None },
            authority:   match message_type {
                MessageTypeTag::UnauthorisedPut => Authority::Unknown,
                _ => Authority::NaeManager
                }
        };

        let message = RoutingMessage::new( message_type, header.clone(),
            operation, &n1.id.get_crypto_secret_sign_key());

        let serialised_msssage = encode(&message).unwrap();

        let _ = n1.message_received(&header.source.from_node, serialised_msssage);
        let stats = stats.clone();
        let stats_value = stats.lock().unwrap();
        stats_value.clone()
    }

#[test]
    fn call_put() {
        let data = "this is a known string".to_string().into_bytes();
        let chunk = Box::new(TestData::new(data));
        let mut n1 = RoutingNode::new(TestInterface { stats: Arc::new(Mutex::new(Stats {call_count: 0, data: vec![]})) });
        let name: NameType = Random::generate_random();
        n1.put(name, chunk);
    }

#[test]
    fn call_unauthorised_put() {
        let data = "this is a known string".to_string().into_bytes();
        let chunk = Box::new(TestData::new(data));
        let mut n1 = RoutingNode::new(TestInterface { stats: Arc::new(Mutex::new(Stats {call_count: 0, data: vec![]})) });
        let name: NameType = Random::generate_random();
        n1.unauthorised_put(name, chunk);
    }

#[test]
    fn call_handle_put() {
        let stats = Arc::new(Mutex::new(Stats {call_count: 0, data: vec![]}));
        let put_data: PutData = Random::generate_random();
        assert_eq!(call_operation(put_data, MessageTypeTag::PutData, stats).call_count, 1u32);
    }

#[test]
    fn call_handle_authorised_put() {
        let stats = Arc::new(Mutex::new(Stats {call_count: 0, data: vec![]}));
        let unauthorised_put: PutData = Random::generate_random();
        let result_stats = call_operation(unauthorised_put, MessageTypeTag::UnauthorisedPut, stats);
        assert_eq!(result_stats.call_count, 1u32);
        assert_eq!(result_stats.data, "UnauthorisedPut".to_string().into_bytes());
    }

#[test]
    fn call_handle_put_response() {
        let stats = Arc::new(Mutex::new(Stats {call_count: 0, data: vec![]}));
        let put_data_response: PutDataResponse = Random::generate_random();
        assert_eq!(call_operation(put_data_response, MessageTypeTag::PutDataResponse, stats).call_count, 1u32);
    }

#[test]
    fn call_get() {
        let mut n1 = RoutingNode::new(TestInterface { stats: Arc::new(Mutex::new(Stats {call_count: 0, data: vec![]})) });
        let name: NameType = Random::generate_random();
        n1.get(100u64, name);
    }

#[test]
    fn call_handle_get_data() {
        let stats = Arc::new(Mutex::new(Stats {call_count: 0, data: vec![]}));
        let get_data: GetData = Random::generate_random();
        assert_eq!(call_operation(get_data, MessageTypeTag::GetData, stats).call_count, 1u32);
    }

#[test]
    fn call_handle_get_data_response() {
        let stats = Arc::new(Mutex::new(Stats {call_count: 0, data: vec![]}));
        let get_data: GetDataResponse = Random::generate_random();
        assert_eq!(call_operation(get_data, MessageTypeTag::GetDataResponse, stats).call_count, 1u32);
    }

#[test]
    fn call_handle_get_key() {
        let stats = Arc::new(Mutex::new(Stats {call_count: 0, data: vec![]}));
        let get_key: GetKey = Random::generate_random();
        let public_key: types::PublicSignKey = Random::generate_random();
        let mut enc = Encoder::from_memory();
        let _ = enc.encode(&[public_key]);
        stats.lock().unwrap().data = enc.into_bytes();
        assert_eq!(call_operation(get_key, MessageTypeTag::GetKey, stats).call_count, 1u32);
    }

#[test]
    fn call_handle_post() {
        let stats = Arc::new(Mutex::new(Stats {call_count: 0, data: vec![]}));
        let post: Post = Random::generate_random();
        assert_eq!(call_operation(post, MessageTypeTag::Post, stats).call_count, 1u32);
    }

#[test]
    fn network() {
        let network_size = 2usize;
        let node = Arc::new(Mutex::new(RoutingNode::new(TestInterface { stats: Arc::new(Mutex::new(Stats {call_count: 0, data: vec![]})) })));
        let use_node = node.clone();
        let mut runners = Vec::new();
        runners.push(thread::spawn(move || loop {
                let mut use_node = use_node.lock().unwrap();
                use_node.run();
                if use_node.routing_table.size() == network_size - 1 {
                    break;
                }
            }));
        let listening_endpoints = node.lock().unwrap().accepting_on.clone();
        println!("network: {:?},  {:?}", &listening_endpoints, node.lock().unwrap().id());
        for _ in 0..(network_size - 1) {
            let node = Arc::new(Mutex::new(RoutingNode::new(TestInterface { stats: Arc::new(Mutex::new(Stats {call_count: 0, data: vec![]})) })));
            let use_node = node.clone();
            runners.push(thread::spawn(move || loop {
                    let mut use_node = use_node.lock().unwrap();
                    use_node.run();
                    if use_node.routing_table.size() == network_size - 1 {
                        break;
                    }
                }));
            let mut use_node2 = node.lock().unwrap();
            match use_node2.bootstrap(Some(listening_endpoints.clone()), None) {
                Ok(_) => { assert!(true) },
                Err(_)  => { assert!(false); }
            }
            thread::sleep_ms(1000);
        }

        for runner in runners {
            assert!(runner.join().is_ok());
        }
    }

    // TODO(Team) consider reusing this method at other places
    fn populate_routing_node() -> RoutingNode<TestInterface> {
        let mut routing_node = RoutingNode::new(TestInterface {
                stats: Arc::new(Mutex::new(Stats {call_count: 0, data: vec![]})) });

        let mut count : usize = 0;
        loop {
            routing_node.routing_table.add_node(routing_table::NodeInfo::new(
                                       PublicId::new(&Id::new()), random_endpoints(),
                                       Some(random_endpoint())));
            count += 1;
            if routing_node.routing_table.size() >=
                routing_table::RoutingTable::get_optimal_size() { break; }
            if count >= 2 * routing_table::RoutingTable::get_optimal_size() {
                panic!("Routing table does not fill up."); }
        }
        routing_node
    }

    #[test]
    fn relocate_original_public_id() {
        let mut routing_node = populate_routing_node();
        let furthest_closest_node = routing_node.routing_table.our_close_group().last().unwrap().id();
        let our_name = routing_node.own_name.clone();

        let total_inside : u32 = 50;
        let limit_attempts : u32 = 200;
        let mut stored_public_ids : Vec<PublicId> = Vec::with_capacity(total_inside as usize);

        let mut count_inside : u32 = 0;
        let mut count_total : u32 = 0;
        loop {
            let put_public_id = PutPublicId{ public_id :  PublicId::new(&Id::new()) };
            let put_public_id_header : MessageHeader = MessageHeader {
                message_id : random::<u32>(),
                destination : types::DestinationAddress {
                    dest : put_public_id.public_id.name(), relay_to : None },
                source : types::SourceAddress {
                    from_node : Random::generate_random(),  // Bootstrap node or ourself
                    from_group : None, reply_to : None, relayed_for : None },
                authority : Authority::ManagedNode
            };
            let serialised_msg = encode(&put_public_id).unwrap();
            let result = routing_node.handle_put_public_id(put_public_id_header,
                serialised_msg);
            if closer_to_target(&put_public_id.public_id.name(),
                                &furthest_closest_node,
                                &our_name) {
                assert!(result.is_ok());
                stored_public_ids.push(put_public_id.public_id);
                count_inside += 1;
            } else {
                assert!(result.is_err());
            }
            count_total += 1;
            if count_inside >= total_inside {
                break; // succcess
            }
            if count_total >= limit_attempts {
                if count_inside > 0 {
                    println!("Could only verify {} successful public_ids inside
                            our group before limit reached.", count_inside);
                    break;
                } else { panic!("No PublicIds were found inside our close group!"); }
            }
        }
        // no original public_ids should be cached
        for public_id in stored_public_ids {
            assert!(!routing_node.public_id_cache.check(&public_id.name()));
        }
        // assert no original ids were cached
        assert_eq!(routing_node.public_id_cache.len(), 0usize);
    }

    #[test]
    fn cache_relocated_public_id() {
        let mut routing_node = populate_routing_node();
        let furthest_closest_node = routing_node.routing_table.our_close_group().last().unwrap().id();
        let our_name = routing_node.own_name.clone();

        let total_inside : u32 = 50;
        let limit_attempts : u32 = 200;
        let mut stored_public_ids : Vec<PublicId> = Vec::with_capacity(total_inside as usize);

        let mut count_inside : u32 = 0;
        let mut count_total : u32 = 0;
        loop {
            let original_public_id = PublicId::generate_random();
            let mut close_nodes_to_original_name : Vec<NameType> = Vec::new();
            for i in 0..types::GROUP_SIZE {
                close_nodes_to_original_name.push(Random::generate_random());
            }
            let relocated_name = types::calculate_relocated_name(close_nodes_to_original_name.clone(),
                                    &original_public_id.name()).unwrap();
            let mut relocated_public_id = original_public_id.clone();
            assert!(relocated_public_id.assign_relocated_name(relocated_name.clone()));

            let put_public_id = PutPublicId{ public_id :  relocated_public_id };

            let put_public_id_header : MessageHeader = MessageHeader {
                message_id : random::<u32>(),
                destination : types::DestinationAddress {
                    dest : put_public_id.public_id.name(), relay_to : None },
                source : types::SourceAddress {
                    from_node : close_nodes_to_original_name[0].clone(),  // from original name group member
                    from_group : Some(original_public_id.name()), reply_to : None, relayed_for : None },
                authority : Authority::NaeManager
            };
            let serialised_msg = encode(&put_public_id).unwrap();
            let result = routing_node.handle_put_public_id(put_public_id_header, serialised_msg);
            if closer_to_target(&put_public_id.public_id.name(),
                                &furthest_closest_node,
                                &our_name) {
                assert!(result.is_ok());
                stored_public_ids.push(put_public_id.public_id);
                count_inside += 1;
            } else {
                assert!(result.is_err());
            }
            count_total += 1;
            if count_inside >= total_inside {
                break; // succcess
            }
            if count_total >= limit_attempts {
                if count_inside > 0 {
                    println!("Could only verify {} successful public_ids inside
                            our group before limit reached.", count_inside);
                    break;
                } else { panic!("No PublicIds were found inside our close group!"); }
            }
        }
        for public_id in stored_public_ids {
            assert!(routing_node.public_id_cache.check(&public_id.name()));
        }
        // assert no outside keys were cached
        assert_eq!(routing_node.public_id_cache.len(), total_inside as usize);
    }

    //#[test]
    //fn test_routing_node() {
    //    let f1 = NullInterface;
    //    let f2 = NullInterface;
    //    let f3 = NullInterface;
    //    let n1 = RoutingNode::new(NameType::generate_random(), f1);
    //    let n2 = RoutingNode::new(NameType::generate_random(), f2);
    //    let n3 = RoutingNode::new(NameType::generate_random(), f3);

    //    println!("{:?}->Alice", n1.id());
    //    println!("{:?}->Betty", n2.id());
    //    println!("{:?}->Casey", n3.id());
    //    let n1_ep = n1.accepting_on().unwrap();
    //    let n2_ep = n2.accepting_on().unwrap();
    //    let n3_ep = n3.accepting_on().unwrap();

    //    fn run_node(n: RoutingNode<NullInterface>, my_ep: SocketAddr, his_ep: SocketAddr)
    //        -> thread::JoinHandle
    //    {
    //        thread::spawn(move || {
    //            let mut n = n;
    //            let bootstrap_ep = SocketAddr::from_str(&format!("127.0.0.1:{}", 5483u16)).unwrap();
    //            if my_ep.port() != bootstrap_ep.port() {
    //                n.add_bootstrap(bootstrap_ep);
    //            }
    //            n.run();
    //        })
    //    }

    //    let t1 = run_node(n1, n1_ep.clone(), n2_ep.clone());
    //    let t2 = run_node(n2, n2_ep.clone(), n1_ep.clone());
    //    thread::sleep_ms(1000);
    //    println!("Starting node 3 ... ");
    //    let t3 = run_node(n3, n3_ep.clone(), n1_ep.clone());
    //    assert!(t1.join().is_ok());
    //    assert!(t2.join().is_ok());
    //    assert!(t3.join().is_ok());
    //}
}
