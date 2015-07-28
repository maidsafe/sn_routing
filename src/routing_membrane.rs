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

//! Routing membrane is a single thread responsible for the in- and outgoing messages.
//! It accepts messages received from CRUST.
//! The membrane evaluates whether a message is to be forwarded, or
//! accepted into the membrane as a request where Sentinel holds it until verified and resolved.
//! Requests resolved by Sentinel, will be handed on to the Interface for actioning.
//! A limited number of messages are deliberatly for Routing and network management purposes.
//! Some network management messages are directly handled without Sentinel resolution.
//! Other network management messages are handled by Routing after Sentinel resolution.

use rand;
use sodiumoxide::crypto::sign::{verify_detached};
use sodiumoxide::crypto::sign;
use std::collections::{BTreeMap};
use std::boxed::Box;
use std::ops::DerefMut;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::mpsc::Sender;
use std::sync::mpsc::Receiver;
use time::{Duration, SteadyTime};

use crust;
use crust::{ConnectionManager, Endpoint};
use crust::Event as CrustEvent;
use lru_time_cache::LruCache;
use message_filter::MessageFilter;
use NameType;
use name_type::{closer_to_target_or_equal};
use node_interface::Interface;
use routing_table::{RoutingTable, NodeInfo};
use relay::{RelayMap, IdType};
use sendable::Sendable;
use data::{Data, DataRequest};
use types;
use types::{MessageId, Bytes, DestinationAddress, SourceAddress, Address};
use authority::{Authority, our_authority};
use who_are_you::{WhoAreYou, IAm};
use messages::{RoutingMessage, SignedMessage, MessageType,
               ConnectRequest, ConnectResponse, ErrorReturn, GetDataResponse};
use error::{RoutingError, ResponseError, InterfaceError};
use node_interface::MethodCall;
use refresh_accumulator::RefreshAccumulator;
use id::Id;
use public_id::PublicId;
use utils;
use utils::{encode, decode};
use sentinel::pure_sentinel::{PureSentinel, AddResult};
use event::Event;

type RoutingResult = Result<(), RoutingError>;

enum ConnectionName {
    Relay(IdType),
    Routing(NameType),
    OurBootstrap(NameType),
    ReflectionOnToUs,
    UnidentifiedConnection,
    // ClaimedConnection(PublicId),
}

fn get_reflective_endpoint() -> Endpoint {
    match SocketAddr::from_str(&format!("127.0.0.1:{}", 0u16)) {
        Ok(socket_address) => Endpoint::Tcp(socket_address),
        Err(_) => panic!("TESTING!!!!!! FIXME")
    }
}

/// Routing Membrane
pub struct RoutingMembrane<F : Interface> {
    // for CRUST
    sender_clone: Sender<CrustEvent>,
    event_input: Receiver<CrustEvent>,
    connection_manager: crust::ConnectionManager,
    reflective_endpoint : crust::Endpoint,
    accepting_on: Vec<crust::Endpoint>,
    bootstrap: Option<(crust::Endpoint, NameType)>,
    // for Routing
    id: Id,
    routing_table: RoutingTable,
    relay_map: RelayMap,
    next_message_id: MessageId,
    filter: MessageFilter<types::FilterType>,
    public_id_cache: LruCache<NameType, PublicId>,
    connection_cache: BTreeMap<NameType, SteadyTime>,
    refresh_accumulator: RefreshAccumulator,
    // for Persona logic
    interface: Box<F>,
    put_response_sentinel: PureSentinel<Event, NameType>,
    get_data_response_sentinel: PureSentinel<Event, NameType>,
    put_sentinel: PureSentinel<Event, NameType>
}

impl<F> RoutingMembrane<F> where F: Interface {
    // TODO: clean ownership transfer up with proper structure
    pub fn new(cm: crust::ConnectionManager,
               sender_clone: Sender<CrustEvent>,
               event_input: Receiver<CrustEvent>,
               bootstrap: Option<(crust::Endpoint, NameType)>,
               relocated_id: Id,
               personas: F) -> RoutingMembrane<F> {
        debug_assert!(relocated_id.is_relocated());
        RoutingMembrane {
            sender_clone: sender_clone,
            event_input: event_input,
            connection_manager: cm,
            reflective_endpoint: get_reflective_endpoint(),
            accepting_on: vec![],
            bootstrap: bootstrap,
            routing_table : RoutingTable::new(&relocated_id.name()),
            relay_map: RelayMap::new(&relocated_id),
            id : relocated_id,
            next_message_id: rand::random::<MessageId>(),
            filter: MessageFilter::with_expiry_duration(Duration::minutes(20)),
            public_id_cache: LruCache::with_expiry_duration(Duration::minutes(10)),
            connection_cache: BTreeMap::new(),
            refresh_accumulator: RefreshAccumulator::new(),
            interface : Box::new(personas),
            put_response_sentinel: PureSentinel::new(),
            get_data_response_sentinel: PureSentinel::new(),
            put_sentinel: PureSentinel::new()
        }
    }

    /// Retrieve something from the network (non mutating) - Direct call
    pub fn get(&mut self, location: NameType, data : DataRequest) {
        let message_id = self.get_next_message_id();
        let message =  RoutingMessage {
            destination : DestinationAddress::Direct(location),
            source      : SourceAddress::Direct(self.id.name()),
            orig_message: None,
            message_type: MessageType::GetData(data),
            message_id  : message_id,
            authority   : Authority::Unknown
        };

        ignore(self.send_swarm_or_parallel(&message));
    }

    /// Add something to the network, will always go via ClientManager group
    pub fn put(&mut self, destination: NameType, data : Data) {
        let message_id = self.get_next_message_id();
        let message = RoutingMessage {
            destination : DestinationAddress::Direct(destination),
            source      : SourceAddress::Direct(self.id.name()),
            orig_message: None,
            message_type: MessageType::PutData(data),
            message_id  : message_id,
            authority   : Authority::Unknown,
        };

        ignore(self.send_swarm_or_parallel(&message));
    }

    /// Add something to the network, will always go via ClientManager group
    pub fn post(&mut self, destination: NameType, data : Data) {
        let message_id = self.get_next_message_id();
        let message = RoutingMessage {
            destination : DestinationAddress::Direct(destination),
            source      : SourceAddress::Direct(self.id.name()),
            orig_message: None,
            message_type: MessageType::Post(data),
            message_id  : message_id,
            authority   : Authority::Unknown,
        };

        ignore(self.send_swarm_or_parallel(&message));
    }

    pub fn delete(&mut self, _destination: NameType, _data : Data) {
        unimplemented!()
    }

    /// Refresh the content in the close group nodes of group address content::name.
    /// This method needs to be called when churn is triggered.
    /// all the group members need to call this, otherwise it will not be resolved as a valid
    /// content.
    pub fn refresh(&mut self, type_tag: u64, from_group: NameType, content: Bytes) {
        let message_id = self.get_next_message_id();
        let message = RoutingMessage {
            destination : DestinationAddress::Direct(from_group.clone()),
            source      : SourceAddress::Direct(self.id.name()),
            orig_message: None,
            message_type: MessageType::Refresh(type_tag, content),
            message_id  : message_id,
            authority   : Authority::Unknown,
        };

        ignore(self.send_swarm_or_parallel(&message));
    }

    /// RoutingMembrane::Run starts the membrane
    pub fn run(&mut self) {
        // First send FindGroup request
        match self.bootstrap.clone() {
            Some((ref bootstrap_endpoint, _)) => {
                let find_group_msg = self.construct_find_group_msg();
                // FIXME: act on error to send; don't over clone bootstrap_endpoint
                ignore(encode(&find_group_msg).map(|msg|self.connection_manager
                    .send(bootstrap_endpoint.clone(), msg)));
            },
            None => {
                // routing_table is still empty now, but check
                // should never happen
                if self.routing_table.size() == 0 {
                    // only for a self-relocated node is this a normal situation.
                    if !self.id.is_self_relocated() {
                        panic!("No connections to get started.");
                    }
                }
            }
        }

        info!("Started Membrane loop");
        loop {
            match self.event_input.recv() {
                Err(_) => (),
                Ok(CrustEvent::NewMessage(endpoint, bytes)) => {
                    let message = match decode::<SignedMessage>(&bytes) {
                        Ok(message) => message,
                        Err(_)      => continue,
                    };

                    match self.lookup_endpoint(&endpoint) {
                        // We sent this message to ourselves
                        // as we are part of the effective close group
                        Some(ConnectionName::ReflectionOnToUs) => {
                            ignore(self.message_received(message));
                        },
                        // we hold an active connection to this endpoint,
                        // mapped to a name in our routing table
                        Some(ConnectionName::Routing(name)) => {
                            ignore(self.message_received(message));
                        },
                        // we hold an active connection to this endpoint,
                        // mapped to a name in our relay map
                        Some(ConnectionName::Relay(_)) => {
                            let message = match message.get_routing_message() {
                                Ok(message) => message,
                                Err(_)      => continue,
                            };

                            // Forward
                            ignore(self.send_swarm_or_parallel_or_relay(&message));
                        },
                        Some(ConnectionName::OurBootstrap(bootstrap_node_name)) => {
                            ignore(self.message_received(message));
                        },
                        Some(ConnectionName::UnidentifiedConnection) => {
                            // only expect WhoAreYou or IAm message
                            match self.handle_unknown_connect_request(&endpoint, message) {
                                Ok(_) => {},
                                Err(_) => {
                                    // on any error, handle as WhoAreYou/IAm
                                    let _ = self.handle_who_are_you(&endpoint, bytes);
                                },
                            }

                        },
                        None => {
                            // FIXME: probably the 'unidentified connection' is useless state;
                            // only good for pruning later on.
                            // If we don't know the sender, only accept a connect request
                            match self.handle_unknown_connect_request(&endpoint, message) {
                                Ok(_) => {},
                                Err(_) => {
                                    // on any error, handle as WhoAreYou/IAm
                                    let _ = self.handle_who_are_you(&endpoint, bytes);
                                },
                            }
                        }
                    }
                },
                Ok(CrustEvent::NewConnection(endpoint)) => {
                    self.handle_new_connection(endpoint);
                },
                Ok(CrustEvent::LostConnection(endpoint)) => {
                    self.handle_lost_connection(endpoint);
                },
                Ok(CrustEvent::NewBootstrapConnection(endpoint)) => {
                    // TODO(ben 23/07/2015): drop and stop crust bootstrapping
                }
            };
        }
    }

    fn my_source_address(&self) -> SourceAddress {
        self.bootstrap.clone().map(|(_, name)| {
            SourceAddress::RelayedForNode(name, self.id.name().clone())
        })
        .unwrap_or(SourceAddress::Direct(self.id.name().clone()))
    }

    ///
    fn handle_unknown_connect_request(&mut self, endpoint: &Endpoint, message: SignedMessage)
            -> RoutingResult {

        //let (serialised_connect_request, signature) = match message.clone() {
        //    Message::Signed(serialised_cr, signature) => (serialised_cr, signature),
        //    Message::Unsigned(_) => return Err(RoutingError::NotEnoughSignatures)
        //};

        let routing_message = try!(message.get_routing_message());
        let connect_request = match routing_message.message_type {
            MessageType::ConnectRequest(ref request) => request.clone(),
            _ => return Ok(()), // To be changed to Parse error
        };

        let our_authority = our_authority(&routing_message, &self.routing_table);

        // only accept unrelocated Ids from unknown connections
        if connect_request.requester_fob.is_relocated() {
            return Err(RoutingError::RejectedPublicId);
        }

        // if the PublicId is not relocated,
        // only accept the connection into the RelayMap.
        // This will enable this connection to bootstrap or act as a client.
        let mut routing_msg = try!(routing_message.create_reply(&self.id.name(), &our_authority));
        routing_msg.message_type = MessageType::ConnectResponse(ConnectResponse {
                    requester_local_endpoints: connect_request.local_endpoints.clone(),
                    requester_external_endpoints: connect_request.external_endpoints.clone(),
                    receiver_local_endpoints: self.accepting_on.clone(),
                    receiver_external_endpoints: vec![],
                    requester_id: connect_request.requester_id.clone(),
                    receiver_id: self.id.name().clone(),
                    receiver_fob: PublicId::new(&self.id),
                    serialised_connect_request: message.encoded_body().clone(),
                    connect_request_signature: message.signature().clone()
                });

        let signed_message = try!(SignedMessage::new(&routing_msg, self.id.signing_private_key()));
        let serialised_msg = try!(encode(&signed_message));

        self.relay_map.add_ip_node(connect_request.requester_fob, endpoint.clone());
        self.relay_map.remove_unknown_connection(endpoint);

        debug_assert!(self.relay_map.contains_endpoint(&endpoint));

        match self.connection_manager.send(endpoint.clone(), serialised_msg) {
            Ok(_)  => Ok(()),
            Err(e) => Err(RoutingError::Io(e))
        }
    }

    /// When CRUST receives a connect to our listening port and establishes a new connection,
    /// the endpoint is given here as new connection
    fn handle_new_connection(&mut self, endpoint : Endpoint) {
      info!("CRUST::NewConnection on {:?}", endpoint);
        self.drop_bootstrap();
        match self.lookup_endpoint(&endpoint) {
            Some(ConnectionName::ReflectionOnToUs) => {
                info!("UNEXPECTED: NewConnection {:?} on 127.0.0.1:0 (reflection endpoint).",
                    endpoint);
            }
            Some(_) => {
                info!("UNEXPECTED: NewConnection {:?} on already connected endpoint.",
                    endpoint);
            },
            None => {
                self.relay_map.register_unknown_connection(endpoint.clone());
                // Send "Who are you?" message
                ignore(self.send_who_are_you_msg(endpoint));
            }
      }
    }

    /// When CRUST reports a lost connection, ensure we remove the endpoint anywhere
    /// TODO: A churn event might be triggered
    fn handle_lost_connection(&mut self, endpoint : Endpoint) {
        // Make sure the endpoint is dropped anywhere
        // The relay map will automatically drop the Name if the last endpoint to it is dropped
        self.relay_map.remove_unknown_connection(&endpoint);
        self.relay_map.drop_endpoint(&endpoint);
        let mut trigger_handle_churn = false;
        match self.routing_table.lookup_endpoint(&endpoint) {
            Some(name) => {
                trigger_handle_churn = self.routing_table
                    .address_in_our_close_group_range(&name);
                self.routing_table.drop_node(&name);
                info!("RT (size : {:?}) connection {:?} disconnected for {:?}.",
                    self.routing_table.size(), endpoint, name);
            },
            None => {}
        };
        let mut drop_bootstrap = false;
        match self.bootstrap {
            Some((ref bootstrap_endpoint, _)) => {
                if &endpoint == bootstrap_endpoint {
                    info!("Bootstrap connection disconnected by relay node.");
                    self.connection_manager.drop_node(endpoint);
                    drop_bootstrap = true;
                }
            },
            None => {}
        };
        if drop_bootstrap { self.bootstrap = None; }

        if trigger_handle_churn {
            info!("Handle CHURN lost node");
            let mut close_group : Vec<NameType> = self.routing_table
                .our_close_group().iter()
                .map(|node_info| node_info.fob.name())
                .collect::<Vec<NameType>>();
            close_group.insert(0, self.id.name().clone());
            let churn_actions = self.mut_interface().handle_churn(close_group);
            for action in churn_actions {
                match action {
                    MethodCall::Put { destination: x, content: y, } => self.put(x, y),
                    MethodCall::Get { name: x, data_request: y } => self.get(x, y),
                    MethodCall::Refresh { type_tag, from_group, payload } => self.refresh(type_tag, from_group, payload),
                    MethodCall::Post { destination: x, content: y, } => self.post(x, y),
                    MethodCall::Delete { name: x, data : y } => self.delete(x, y),
                    MethodCall::Forward { destination } =>
                        info!("IGNORED: on handle_churn MethodCall:Forward {} is not a Valid action", destination),
                    MethodCall::Reply { data: _data } =>
                        info!("IGNORED: on handle_churn MethodCall:Reply is not a Valid action")
                };
            }
        };
    }

    fn construct_find_group_msg(&mut self) -> RoutingMessage {
        let name   = self.id.name().clone();
        let message_id = self.get_next_message_id();

        RoutingMessage {
            destination  : DestinationAddress::Direct(name.clone()),
            source       : SourceAddress::Direct(name.clone()),
            orig_message : None,
            message_type : MessageType::FindGroup,
            message_id   : message_id,
            authority    : Authority::ManagedNode,
        }
    }

    /// This the fundamental functional function in routing.
    /// It only handles messages received from connections in our routing table;
    /// i.e. this is a pure SAFE message (and does not function as the start of a relay).
    /// If we are the relay node for a message from the SAFE network to a node we relay for,
    /// then we will pass out the message to the client or bootstrapping node;
    /// no relay-messages enter the SAFE network here.
    fn message_received(&mut self,
                        message_wrap        : SignedMessage,
                       ) -> RoutingResult {

        let message = try!(message_wrap.get_routing_message());

        // filter check
        if self.filter.check(&message.get_filter()) {
            // should just return quietly
            return Err(RoutingError::FilterCheckFailed);
        }
        // add to filter
        self.filter.add(message.get_filter());

        // Caching on GetData and GetDataRequest
        match message.message_type {
            // Add to cache, only for ImmutableData; For StructuredData caching
            // can result in old versions being returned.
            MessageType::GetDataResponse(ref response) => {
                match response.data {
                    Data::ImmutableData(ref immutable_data) => {
                        let from = message.from_group()
                                          .unwrap_or(message.non_relayed_source());

                        ignore(self.mut_interface().handle_cache_put(
                            message.from_authority(),
                            from,
                            Data::ImmutableData(immutable_data.clone())));
                    },
                    _ => {}
                }
            },
            // check cache
            MessageType::GetData(ref data_request) => {
                let from = message.from_group()
                                  .unwrap_or(message.non_relayed_source());

                let method_call = self.mut_interface().handle_cache_get(
                                data_request.clone(),
                                message.non_relayed_destination(),
                                from);

                match method_call {
                    Ok(MethodCall::Reply { data }) => {
                        let response = GetDataResponse {
                            data           : data,
                            orig_request   : message_wrap.clone(),
                            group_pub_keys : BTreeMap::new()
                        };
                        let our_authority = our_authority(&message, &self.routing_table);
                        ignore(self.send_reply(
                            &message, our_authority, MessageType::GetDataResponse(response)));
                    },
                    _ => (),

                }
            },
            _ => {}
        }

        // Forward
        ignore(self.send_swarm_or_parallel_or_relay(&message));

        let address_in_close_group_range =
            self.address_in_close_group_range(&message.non_relayed_destination());

        // Handle FindGroupResponse
        match  message.message_type {
            MessageType::FindGroupResponse(ref vec_of_public_ids) =>
                ignore(self.handle_find_group_response(
                            vec_of_public_ids.clone(),
                            address_in_close_group_range.clone())),
             _ => (),
        };

        if !address_in_close_group_range {
            return Ok(());
        }

        // Drop message before Sentinel check if it is a direct message type (Connect, ConnectResponse)
        // and this node is in the group but the message destination is another group member node.
        match  message.message_type {
            MessageType::ConnectRequest(_) |
            MessageType::ConnectResponse(_) =>
                            if message.non_relayed_destination() != self.id.name()  {
                                // "not for me"
                                return Ok(()); },
            _ => (),
        }
        //
        // pre-sentinel message handling
        match message.message_type {
            // MessageType::GetKey => self.handle_get_key(header, body),
            // MessageType::GetGroupKey => self.handle_get_group_key(header, body),
            MessageType::ConnectRequest(request) => self.handle_connect_request(request, message_wrap),
            _ => {
                // Sentinel check

                // switch message type
                match message.message_type {
                    MessageType::ConnectResponse(response) => self.handle_connect_response(response),
                    MessageType::FindGroup => self.handle_find_group(message),
                    // Handled above for some reason.
                    //MessageType::FindGroupResponse(find_group_response) => self.handle_find_group_response(find_group_response),
                    MessageType::GetData(ref request) => self.handle_get_data(message_wrap,
                        message.clone(), request.clone()),
                    MessageType::GetDataResponse(ref response) => {
                        match message.actual_source() {
                            Address::Node(_)
                                => self.handle_node_get_data_response(message_wrap,
                                                                      message.clone(),
                                                                      response.clone()),
                           Address::Client(_) =>
                               self.handle_client_get_data_response(message_wrap, message.clone(),
                                                                    response.clone()),
                        }
                    },
                    MessageType::PutDataResponse(ref response, ref _map) => {
                        match message.actual_source() {
                            Address::Node(_) =>
                                self.handle_node_put_data_response(message_wrap, message.clone(),
                                                                   response.clone()),
                            Address::Client(_) =>
                                self.handle_client_put_data_response(message_wrap, message.clone(),
                                                                     response.clone()),
                        }
                    },
                    MessageType::PutData(ref data) => {
                        match message.source.actual_source() {
                            Address::Node(name) =>
                                self.handle_node_put_data(message_wrap, message.clone(),
                                                          data.clone(), name),
                            Address::Client(name) =>
                                self.handle_client_put_data(message_wrap, message.clone(),
                                                            data.clone(), name),
                        }
                    },
                    MessageType::PutPublicId(ref id) =>
                        self.handle_put_public_id(message_wrap, message.clone(), id.clone()),
                    MessageType::Refresh(ref tag, ref data) =>
                        self.handle_refresh(message.clone(), tag.clone(), data.clone()),
                    MessageType::Post(ref data) =>
                        self.handle_post(message_wrap, message.clone(), data.clone()),
                    MessageType::PostResponse(ref response, _)
                        => self.handle_post_response(message_wrap,
                                                     message.clone(),
                                                     response.clone()),
                    _ => {
                        Err(RoutingError::UnknownMessageType)
                    }
                }
            }
        }
    }

    /// Scan all passing messages for the existance of nodes in the address space.
    /// If a node is detected with a name that would improve our routing table,
    /// then try to connect.  During a delay of 5 seconds, we collapse
    /// all re-occurances of this name, and block a new connect request
    /// TODO: The behaviour of this function has been adapted to serve as a filter
    /// to cover for the lack of a filter on FindGroupResponse
    fn refresh_routing_table(&mut self, from_node : &NameType) {
      // disable refresh when scanning on small routing_table size
      let time_now = SteadyTime::now();
      if !self.connection_cache.contains_key(from_node) {
          if self.routing_table.check_node(from_node) {
              ignore(self.send_connect_request_msg(&from_node));
          }
          self.connection_cache.entry(from_node.clone())
              .or_insert(time_now);
       }

       let mut prune_blockage : Vec<NameType> = Vec::new();
       for (blocked_node, time) in self.connection_cache.iter_mut() {
           // clear block for nodes
           if time_now - *time > Duration::seconds(10) {
               prune_blockage.push(blocked_node.clone());
           }
       }
       for prune_name in prune_blockage {
           self.connection_cache.remove(&prune_name);
       }
    }

    // -----Name-based Send Functions----------------------------------------

    fn send_out_as_relay(&mut self, name: &IdType, msg: Bytes) {
        let mut failed_endpoints : Vec<Endpoint> = Vec::new();
        match self.relay_map.get_endpoints(name) {
            Some(&(_, ref endpoints)) => {
                for endpoint in endpoints {
                    match self.connection_manager.send(endpoint.clone(), msg.clone()) {
                        Ok(_) => break,
                        Err(_) => {
                            info!("Dropped relay connection {:?} on failed attempt
                                to relay for node {:?}", endpoint, name);
                            failed_endpoints.push(endpoint.clone());
                        }
                    };
                }
            },
            None => {}
        };
        for failed_endpoint in failed_endpoints {
            self.relay_map.drop_endpoint(&failed_endpoint);
            self.connection_manager.drop_node(failed_endpoint);
        }
    }

    fn send_swarm_or_parallel(&self, msg : &RoutingMessage) -> Result<(), RoutingError> {
        let name = msg.non_relayed_destination();

        if self.routing_table.size() > 0 {
            let signed_message = try!(SignedMessage::new(&msg, self.id.signing_private_key()));
            let bytes = try!(encode(&signed_message));

            for peer in self.routing_table.target_nodes(&name) {
                match peer.connected_endpoint {
                    Some(peer_endpoint) => {
                        ignore(self.connection_manager.send(peer_endpoint, bytes.clone()));
                    },
                    None => {}
                };
            }

            // FIXME(ben 24/07/2015)
            // if the destination is within range for us,
            // we are also part of the effective close group for destination.
            // RoutingTable does not include ourselves in the target nodes,
            // so we should check the filter (to avoid eternal looping)
            // and also handle it ourselves.
            // Instead we can for now rely on swarming to send it back to us.
            Ok(())
        } else {
            // FIXME(ben 24/07/2015)
            // This is a patch for the above: if we have no routing table connections,
            // we are the only member of the effective close group for the target.
            // In this case we can reflect it back to ourselves
            // - and take the risk of piling up the stack; or holding other messages;
            // afterall we are the only node on the network, as far as we know.

            // if routing table size is zero any target is in range, so no need to check
            self.send_reflective_to_us(msg)
        }

        // TODO(ben 24/07/2015) this can be removed. It is also not "wrong" but the crux
        // of the rust-2 routing refactor was clearly separating the genuine routing network
        // from bootstrap noise, so if such a functionality is needed, then it should go in
        // a very explicit function.
        // else {
        //     match self.bootstrap {
        //         Some((ref bootstrap_endpoint, _)) => {
        //
        //             let msg = try!(SignedMessage::new(msg, &self.id.signing_private_key()));
        //             let msg = try!(encode(&msg));
        //
        //             match self.connection_manager.send(bootstrap_endpoint.clone(), msg) {
        //                 Ok(_)  => Ok(()),
        //                 Err(e) => Err(RoutingError::Io(e))
        //             }},
        //         None => Err(RoutingError::FailedToBootstrap)
        //     }
        // }
    }

    // When we swarm a message, we are also part of the effective close group.
    // This is catered for under normal swarm, as our neighbours will send the message back,
    // when we have no routing table connections, we explicitly have no choice, but to loop
    // it back to ourselves
    // this is the logically correct behaviour.
    fn send_reflective_to_us(&self, msg: &RoutingMessage) -> Result<(), RoutingError> {
        let signed_message = try!(SignedMessage::new(&msg, self.id.signing_private_key()));
        let bytes = try!(encode(&signed_message));
        let new_event = CrustEvent::NewMessage(self.reflective_endpoint.clone(), bytes);
        match self.sender_clone.send(new_event) {
            Ok(_) => {},
            // FIXME(ben 24/07/2015) we have a broken channel with crust,
            // should terminate node
            Err(_) => return Err(RoutingError::FailedToBootstrap)
        };
        Ok(())
    }

    fn send_swarm_or_parallel_or_relay(&mut self, msg: &RoutingMessage)
        -> Result<(), RoutingError> {

        let dst = msg.destination_address();

        if dst.non_relayed_destination() == self.id.name() {
            let msg = try!(SignedMessage::new(msg, &self.id.signing_private_key()));
            let msg = try!(encode(&msg));

            match dst {
                DestinationAddress::RelayToClient(_, public_key) => {
                    self.send_out_as_relay(&IdType::Client(public_key), msg.clone());
                },
                DestinationAddress::RelayToNode(_, node_address) => {
                    self.send_out_as_relay(&IdType::Node(node_address), msg.clone());
                },
                DestinationAddress::Direct(_) => {},
            }
            Ok(())
        }
        else {
            self.send_swarm_or_parallel(msg)
        }
    }

    fn send_connect_request_msg(&mut self, peer_id: &NameType) -> RoutingResult {
        // FIXME: We're sending all accepting connections as local since we don't differentiate
        // between local and external yet.
        let connect_request = ConnectRequest {
            local_endpoints: self.accepting_on.clone(),
            external_endpoints: vec![],
            requester_id: self.id.name().clone(),
            receiver_id: peer_id.clone(),
            requester_fob: PublicId::new(&self.id),
        };

        let message =  RoutingMessage {
            destination  : DestinationAddress::Direct(peer_id.clone()),
            source       : self.my_source_address(),
            orig_message : None,
            message_type : MessageType::ConnectRequest(connect_request),
            message_id   : self.get_next_message_id(),
            authority    : Authority::ManagedNode
        };

        self.send_swarm_or_parallel(&message)
    }

    // ---- Who Are You ---------------------------------------------------------

    fn handle_who_are_you(&mut self, endpoint: &Endpoint, serialised_message: Bytes)
        -> RoutingResult {
        match decode::<WhoAreYou>(&serialised_message) {
            Ok(who_are_you_msg) => {
                ignore(self.send_i_am_msg(endpoint.clone(), who_are_you_msg.nonce));
                Ok(())
            },
            Err(_) => match decode::<IAm>(&serialised_message) {
                Ok(i_am_msg) => {
                    // FIXME: validate signature of nonce
                    ignore(self.handle_i_am(endpoint.clone(), i_am_msg));
                    Ok(())
                },
                Err(_) => Err(RoutingError::UnknownMessageType)
            }
        }
    }

    fn handle_i_am(&mut self, endpoint: Endpoint, i_am: IAm) -> RoutingResult {
        let mut trigger_handle_churn = false;
        match i_am.public_id.is_relocated() {
            // if it is relocated, we consider the connection for our routing table
            true => {
                // check we have a cache for his public id from the relocation procedure
                match self.public_id_cache.get(&i_am.public_id.name()) {
                    Some(cached_public_id) => {
                        // check the full fob received corresponds, not just the names
                        if cached_public_id == &i_am.public_id {
                            let peer_endpoints = vec![endpoint.clone()];
                            let peer_node_info = NodeInfo::new(i_am.public_id.clone(), peer_endpoints,
                                Some(endpoint.clone()));
                            // FIXME: node info cloned for debug printout below
                            let (added, _) = self.routing_table.add_node(peer_node_info.clone());
                            // TODO: drop dropped node in connection_manager
                            if !added {
                                info!("RT (size : {:?}) refused connection on {:?} as {:?}
                                    from routing table.", self.routing_table.size(),
                                    endpoint, i_am.public_id.name());
                                self.relay_map.remove_unknown_connection(&endpoint);
                                self.connection_manager.drop_node(endpoint);
                                return Err(RoutingError::RefusedFromRoutingTable); }
                            info!("RT (size : {:?}) added connected node {:?} on {:?}",
                                self.routing_table.size(), peer_node_info.fob.name(), endpoint);
                            trigger_handle_churn = self.routing_table
                                .address_in_our_close_group_range(&peer_node_info.fob.name());
                        } else {
                            info!("I Am, relocated name {:?} conflicted with cached fob.",
                                i_am.public_id.name());
                            self.relay_map.remove_unknown_connection(&endpoint);
                            self.connection_manager.drop_node(endpoint);
                        }
                    },
                    None => {
                        // if we are connecting to an existing group
      // FIXME: ConnectRequest had target name signed by us; so no state held on response
      // I Am by default just has a nonce; now we will accept everyone, but we can avoid state,
      // by repeating the Who Are You message, this time with the nonce as his name.
      // So we check if the doubly signed nonce is his name, if so, add him to RT;
      // if not do second WhoAreYou as above;
      // we can do 512 + 1 bit to flag and break an endless loop
                        match self.routing_table.check_node(&i_am.public_id.name()) {
                            true => {
                                let peer_endpoints = vec![endpoint.clone()];
                                let peer_node_info = NodeInfo::new(i_am.public_id.clone(),
                                    peer_endpoints, Some(endpoint.clone()));
                                // FIXME: node info cloned for debug printout below
                                let (added, _) = self.routing_table.add_node(
                                    peer_node_info.clone());
                                // TODO: drop dropped node in connection_manager
                                if !added {
                                    info!("RT (size : {:?}) refused connection on {:?} as {:?}
                                        from routing table.", self.routing_table.size(),
                                        endpoint, i_am.public_id.name());
                                    self.relay_map.remove_unknown_connection(&endpoint);
                                    self.connection_manager.drop_node(endpoint);
                                    return Err(RoutingError::RefusedFromRoutingTable); }
                                info!("RT (size : {:?}) added connected node {:?} on {:?}",
                                    self.routing_table.size(), peer_node_info.fob.name(), endpoint);
                                trigger_handle_churn = self.routing_table
                                    .address_in_our_close_group_range(&peer_node_info.fob.name());
                            },
                            false => {
                                info!("Dropping connection on {:?} as {:?} is relocated,
                                    but not cached, or marked in our RT.",
                                    endpoint, i_am.public_id.name());
                                self.relay_map.remove_unknown_connection(&endpoint);
                                self.connection_manager.drop_node(endpoint);
                            }
                        };
                    }
                }
            },
            // if it is not relocated, we consider the connection for our relay_map
            // but with unknown connect request we already successfully relay for an relocated node
            false => {
                info!("I Am unrelocated {:?} on {:?}. Not Acting on this result.",
                    i_am.public_id.name(), endpoint);
            }
        };
        if trigger_handle_churn {
            info!("Handle CHURN new node {:?}", i_am.public_id.name());
            let mut close_group : Vec<NameType> = self.routing_table
                    .our_close_group().iter()
                    .map(|node_info| node_info.fob.name())
                    .collect::<Vec<NameType>>();
            close_group.insert(0, self.id.name().clone());
            let churn_actions = self.mut_interface().handle_churn(close_group);
            for action in churn_actions {
                match action {
                    MethodCall::Put { destination: x, content: y, } => self.put(x, y),
                    MethodCall::Get { name: x, data_request: y, } => self.get(x, y),
                    MethodCall::Refresh { type_tag, from_group, payload } => self.refresh(type_tag, from_group, payload),
                    MethodCall::Post { destination: x, content: y } => self.post(x, y),
                    MethodCall::Delete { name: x, data : y } => self.delete(x, y),
                    MethodCall::Forward { destination } =>
                        info!("IGNORED: on handle_churn MethodCall:Forward {} is not a Valid action", destination),
                    MethodCall::Reply { data: _data } =>
                        info!("IGNORED: on handle_churn MethodCall:Reply is not a Valid action")
                };
            }
        }
        Ok(())
    }

    fn send_who_are_you_msg(&mut self, endpoint: Endpoint) -> RoutingResult {
        let message = try!(encode(&WhoAreYou {nonce : 0u8}));
        ignore(self.connection_manager.send(endpoint, message));
        Ok(())
    }

    fn send_i_am_msg(&mut self, endpoint: Endpoint, _nonce : u8) -> RoutingResult {
        // FIXME: sign proper nonce
        let message = try!(encode(&IAm {public_id : PublicId::new(&self.id)}));
        ignore(self.connection_manager.send(endpoint, message));
        Ok(())
    }

    // -----Address and various functions----------------------------------------

    fn drop_bootstrap(&mut self) {
        match self.bootstrap {
            Some((ref endpoint, name)) => {
                if self.routing_table.size() > 0 {
                    info!("Dropped bootstrap on {:?} {:?}", endpoint, name);
                    self.connection_manager.drop_node(endpoint.clone());
                }
            },
            None => {}
        };
        self.bootstrap = None;
    }

    fn address_in_close_group_range(&self, address: &NameType) -> bool {
        if self.routing_table.size() < types::QUORUM_SIZE  ||
           *address == self.id.name().clone()
        {
            return true;
        }

        match self.routing_table.our_close_group().last() {
            Some(furthest_close_node) => {
                closer_to_target_or_equal(&address, &furthest_close_node.id(), &self.id.name())
            },
            None => false  // ...should never reach here
        }
    }

    fn get_next_message_id(&mut self) -> MessageId {
        let temp = self.next_message_id;
        self.next_message_id = self.next_message_id.wrapping_add(1);
        return temp;
    }

    fn lookup_endpoint(&self, endpoint: &Endpoint) -> Option<ConnectionName> {
        // first check whether it is reflected from us to us (bypassing CRUST)
        if endpoint == &self.reflective_endpoint {
            return Some(ConnectionName::ReflectionOnToUs);
        }
        // prioritise routing table
        match self.routing_table.lookup_endpoint(&endpoint) {
            Some(name) => Some(ConnectionName::Routing(name)),
            // secondly look in the relay_map
            None => match self.relay_map.lookup_endpoint(&endpoint) {
                Some(name) => Some(ConnectionName::Relay(name)),
                // check to see if it is our bootstrap_endpoint
                None => match self.bootstrap {
                    Some((ref bootstrap_ep, ref bootstrap_name)) => {
                        if bootstrap_ep == endpoint {
                            Some(ConnectionName::OurBootstrap(bootstrap_name.clone()))
                        } else {
                            None
                        }
                    },
                    None => match self.relay_map.lookup_unknown_connection(&endpoint) {
                        true => Some(ConnectionName::UnidentifiedConnection),
                        false => None
                    }
                }
            }
        }
    }

    // -----Message Handlers from Routing Table connections----------------------------------------

    // Routing handle put_data
    fn handle_node_put_data(&mut self, signed_message: SignedMessage, message: RoutingMessage,
                       data: Data, source: NameType) -> RoutingResult {
        let our_authority = our_authority(&message, &self.routing_table);
        let from_authority = message.from_authority();
        let from = message.source_address();
        //let to = message.send_to();
        let to = message.destination_address();
        let mut quorum = types::QUORUM_SIZE;

        if self.routing_table.size() < types::QUORUM_SIZE {
            quorum = self.routing_table.size();
        }

        let source_group = match message.authority.clone() {
            Authority::ClientManager(name) => name,
            Authority::NaeManager(name)    => name,
            Authority::NodeManager(name)   => name,
            Authority::ManagedNode      => return Err(RoutingError::BadAuthority),
            Authority::ManagedClient(_) => return Err(RoutingError::BadAuthority),
            Authority::Client(_)        => return Err(RoutingError::BadAuthority),
            Authority::Unknown          => return Err(RoutingError::BadAuthority),
        };

        // Temporarily pretend that the sentinel passed, later implement
        // sentinel.
        let resolved = Event::PutDataRequest(signed_message.clone(), data.clone(), source_group,
                                             message.destination.non_relayed_destination(),
                                             message.authority.clone(), our_authority.clone(),
                                             message.message_id.clone());

        match self.mut_interface().handle_put(our_authority.clone(), from_authority, from, to,
                                              data.clone()) {
            Ok(method_calls) => {
                for method_call in method_calls {
                    match method_call {
                        MethodCall::Put { destination: x, content: y, } => self.put(x, y),
                        MethodCall::Get { name: x, data_request: y, } => self.get(x, y),
                        MethodCall::Refresh { type_tag, from_group, payload }
                            => self.refresh(type_tag, from_group, payload),
                        MethodCall::Post { destination: x, content: y, } => self.post(x, y),
                        MethodCall::Delete { name: x, data: y } => self.delete(x, y),
                        MethodCall::Forward { destination } => {
                            let data = try!(resolved.get_data());
                            let msg = try!(resolved.create_forward(
                                MessageType::PutData(data), self.id.name(), destination,
                                self.get_next_message_id()));
                            ignore(self.send_swarm_or_parallel(&msg));
                        },
                        MethodCall::Reply { data } => {
                            let msg = try!(resolved.create_reply(MessageType::PutData(data)));
                            ignore(self.send_swarm_or_parallel(&msg));
                        }
                    }
                }
            },
            Err(InterfaceError::Abort) => {},
            Err(InterfaceError::Response(error)) => {
                let signed_error = ErrorReturn {
                    error: error,
                    orig_request: try!(resolved.get_orig_message())
                };
                let group_pub_keys = if our_authority.is_group() {
                    self.group_pub_keys()
                }
                else {
                    BTreeMap::new()
                };
                let msg = MessageType::PutDataResponse(signed_error, group_pub_keys);
                let msg = try!(resolved.create_reply(msg));
                ignore(self.send_swarm_or_parallel(&msg));
            }
        }
        Ok(())
    }

    // Routing handle put_data
    fn handle_client_put_data(&mut self, signed_message: SignedMessage, message: RoutingMessage,
                       data: Data, source: sign::PublicKey) -> RoutingResult {
        let our_authority = our_authority(&message, &self.routing_table);
        let from_authority = message.from_authority();
        let from = message.source_address();
        //let to = message.send_to();
        let to = message.destination_address();

        if !signed_message.verify_signature(&source) {
            return Err(RoutingError::FailedSignature);
        }

        match self.mut_interface().handle_put(our_authority.clone(), from_authority, from, to, data) {
            Ok(method_calls) => {
                for method_call in method_calls {
                    match method_call {
                        MethodCall::Put { destination: x, content: y, } => self.put(x, y),
                        MethodCall::Get { name: x, data_request: y, } => self.get(x, y),
                        MethodCall::Refresh { type_tag, from_group, payload } => self.refresh(type_tag, from_group, payload),
                        MethodCall::Post { destination: x, content: y, } => self.post(x, y),
                        MethodCall::Delete { name: x, data : y } => self.delete(x, y),
                        MethodCall::Forward { destination } =>
                            ignore(self.forward(&signed_message, &message, destination)),
                        MethodCall::Reply { data } =>
                            ignore(self.send_reply(&message, our_authority.clone(), MessageType::PutData(data))),
                    }
                }
            },
            Err(InterfaceError::Abort) => {},
            Err(InterfaceError::Response(error)) => {
                let signed_error = ErrorReturn {
                    error: error,
                    orig_request: signed_message
                };

                let group_pub_keys = if our_authority.is_group() {
                    self.group_pub_keys()
                }
                else {
                    BTreeMap::new()
                };

                try!(self.send_reply(&message,
                                     our_authority.clone(),
                                     MessageType::PutDataResponse(signed_error,
                                                                  group_pub_keys)));
            }
        }
        Ok(())
    }

    fn handle_post(&mut self, signed_message: SignedMessage, message: RoutingMessage, data: Data)
            -> RoutingResult {
        let our_authority = our_authority(&message, &self.routing_table);
        let from_authority = message.from_authority();
        let from = message.source_address();
        let to = message.destination_address();

        match self.mut_interface().handle_post(our_authority.clone(), from_authority, from, to, data) {
            Ok(method_calls) => {
                for method_call in method_calls {
                    match method_call {
                        MethodCall::Put { destination: x, content: y, } => self.put(x, y),
                        MethodCall::Get { name: x, data_request: y, } => self.get(x, y),
                        MethodCall::Refresh { type_tag, from_group, payload } => self.refresh(type_tag, from_group, payload),
                        MethodCall::Post { destination: x, content: y, } => self.post(x, y),
                        MethodCall::Delete { name: x, data : y } => self.delete(x, y),
                        MethodCall::Forward { destination } =>
                            ignore(self.forward(&signed_message, &message, destination)),
                        MethodCall::Reply { data } =>
                            ignore(self.send_reply(&message, our_authority.clone(), MessageType::Post(data))),
                    }
                }
            },
            Err(InterfaceError::Abort) => {},
            Err(InterfaceError::Response(error)) => {
                let signed_error = ErrorReturn {
                    error        : error,
                    orig_request : signed_message
                };

                let group_pub_keys = if our_authority.is_group() {
                    self.group_pub_keys()
                }
                else {
                    BTreeMap::new()
                };

                try!(self.send_reply(&message,
                                     our_authority.clone(),
                                     MessageType::PostResponse(signed_error,
                                                               group_pub_keys)));
            }
        }
        Ok(())
    }

    fn handle_node_put_data_response(&mut self, signed_message: SignedMessage,
            message: RoutingMessage, response: ErrorReturn) -> RoutingResult {
        info!("Handle group PUT data response.");
        let our_authority = our_authority(&message, &self.routing_table);
        let from_authority = message.from_authority();
        let from = message.source.clone();
        let mut quorum = types::QUORUM_SIZE;

        let source = match message.source.actual_source() {
            Address::Node(name) => name,
            _ => return Err(RoutingError::BadAuthority),
        };

        if self.routing_table.size() < types::QUORUM_SIZE {
            quorum = self.routing_table.size();
        }

        let resolved = Event::PutDataResponse(signed_message.clone(), response.clone(), source,
                                              message.destination.non_relayed_destination(),
                                              message.authority.clone(), our_authority.clone(),
                                              message.message_id.clone());

        //let resolved = match self.put_response_sentinel.add_claim(
        //    SentinelPutResponse::new(message.clone(), response.clone(), our_authority.clone()),
        //    source, signed_message.signature().clone(),
        //    signed_message.encoded_body().clone(), quorum, quorum) {
        //        Some(result) =>  match  result {
        //            AddResult::RequestKeys(_) => {
        //                // Get Key Request
        //                return Ok(())
        //            },
        //            AddResult::Resolved(request, serialised_claim) => (request, serialised_claim)
        //        },
        //        None => return Ok(())
        //};

        for method_call in self.mut_interface().handle_put_response(from_authority, from,
                                                                    response.error.clone()) {
            match method_call {
                MethodCall::Put { destination: x, content: y, } => self.put(x, y),
                MethodCall::Get { name: x, data_request: y, } => self.get(x, y),
                MethodCall::Refresh { type_tag, from_group, payload }
                    => self.refresh(type_tag, from_group, payload),
                MethodCall::Post { destination: x, content: y, } => self.post(x, y),
                MethodCall::Delete { name: x, data : y } => self.delete(x, y),
                MethodCall::Forward { destination } => {
                    let response = try!(resolved.get_response());
                    let message_type = MessageType::PutDataResponse(response,
                                                                    self.group_pub_keys());
                    let msg = try!(resolved.create_forward(message_type, self.id.name(), destination,
                                                           self.get_next_message_id()));
                    ignore(self.send_swarm_or_parallel(&msg));
                }
                MethodCall::Reply { data: _data } =>
                    info!("IGNORED: on handle_put_data_response MethodCall:Reply is not a Valid action")
            }
        }
        Ok(())
    }

    fn handle_client_put_data_response(&mut self, signed_message: SignedMessage,
            message: RoutingMessage, response: ErrorReturn) -> RoutingResult {
        info!("Handle client PUT data response.");
        let our_authority = our_authority(&message, &self.routing_table);
        let from_authority = message.from_authority();
        let from = message.source.clone();

        match from.actual_source() {
            Address::Client(public_key) => {
                if !signed_message.verify_signature(&public_key) {
                    return Err(RoutingError::FailedSignature);
                }
            },
            _ => { return Err(RoutingError::BadAuthority); }
        }

        for method_call in self.mut_interface().handle_put_response(from_authority, from, response.error.clone()) {
            match method_call {
                MethodCall::Put { destination: x, content: y, } => self.put(x, y),
                MethodCall::Get { name: x, data_request: y, } => self.get(x, y),
                MethodCall::Refresh { type_tag, from_group, payload } => self.refresh(type_tag, from_group, payload),
                MethodCall::Post { destination: x, content: y, } => self.post(x, y),
                MethodCall::Delete { name: x, data : y } => self.delete(x, y),
                MethodCall::Forward { destination } => {
                    let message_id = self.get_next_message_id();
                    let message = RoutingMessage {
                        destination  : DestinationAddress::Direct(destination),
                        source       : SourceAddress::Direct(self.id.name()),
                        orig_message : None,
                        message_type : MessageType::PutDataResponse(response.clone(), BTreeMap::<NameType, sign::PublicKey>::new()),
                        message_id   : message_id,
                        authority    : our_authority.clone(),
                    };
                    ignore(self.forward(&try!(SignedMessage::new(&message, self.id.signing_private_key())), &message, destination));
                }
                MethodCall::Reply { data: _data } =>
                    info!("IGNORED: on handle_put_data_response MethodCall:Reply is not a Valid action")
            }
        }
        Ok(())
    }

    fn handle_post_response(&mut self, signed_message: SignedMessage,
                                       message: RoutingMessage,
                                       response: ErrorReturn) -> RoutingResult {
        info!("Handle POST response.");
        let from_authority = message.from_authority();
        let from = message.source.clone();

        for method_call in self.mut_interface().handle_post_response(from_authority, from, response.error.clone()) {
            match method_call {
                MethodCall::Put { destination: x, content: y, } => self.put(x, y),
                MethodCall::Get { name: x, data_request: y, } => self.get(x, y),
                MethodCall::Refresh { type_tag, from_group, payload } => self.refresh(type_tag, from_group, payload),
                MethodCall::Post { destination: x, content: y, } => self.post(x, y),
                MethodCall::Delete { name: x, data : y } => self.delete(x, y),
                MethodCall::Forward { destination } =>
                    ignore(self.forward(&signed_message, &message, destination)),
                MethodCall::Reply { data: _data } =>
                    info!("IGNORED: on handle_put_data_response MethodCall:Reply is not a Valid action")
            }
        }
        Ok(())
    }

    fn handle_connect_request(&mut self,
                              connect_request: ConnectRequest,
                              message:         SignedMessage
                             ) -> RoutingResult {
        if !connect_request.requester_fob.is_relocated() {
            return Err(RoutingError::RejectedPublicId);
        }
        // first verify that the message is correctly self-signed
        if message.verify_signature(&self.id.signing_public_key()) {
            return Err(RoutingError::FailedSignature);
        }
        // if the PublicId claims to be relocated,
        // check whether we have a temporary record of this relocated Id,
        // which we would have stored after the sentinel group consensus
        // of the relocated Id. If the fobs match, add it to routing_table.
        match self.public_id_cache.get(&connect_request.requester_fob.name()) {
            Some(public_id) => {
                // check the full fob received corresponds, not just the names
                if public_id == &connect_request.requester_fob {
/* FIXME: we will add this node to the routing table on WhoAreYou
                    // Collect the local and external endpoints into a single vector to construct a NodeInfo
                    let mut peer_endpoints = connect_request.local_endpoints.clone();
                    peer_endpoints.extend(connect_request.external_endpoints.clone().into_iter());
                    let peer_node_info =
                        NodeInfo::new(connect_request.requester_fob.clone(), peer_endpoints, None);
                    // Try to add to the routing table.  If unsuccessful, no need to continue.
                    let (added, _) = self.routing_table.add_node(peer_node_info.clone());
                    if !added {
                        return Err(RoutingError::RefusedFromRoutingTable); }
                    info!("RT (size : {:?}) added {:?} ", self.routing_table.size(), peer_node_info.fob.name());
*/
                    // Try to connect to the peer.
                    self.connection_manager.connect(connect_request.local_endpoints.clone());
                    self.connection_manager.connect(connect_request.external_endpoints.clone());
                    self.connection_cache.entry(public_id.name())
                        .or_insert(SteadyTime::now());
                    // Send the response containing our details,
                    // and add the original signature as proof of the request
// FIXME: for TCP rendez-vous connect is not needed
/*                    let routing_msg = self.construct_connect_response_msg(&original_header, &body, &signature, &connect_request);
                    let serialised_message = try!(encode(&routing_msg));

                    // intercept if we can relay it directly
                    match (routing_msg.message_header.destination.dest.clone(),
                        routing_msg.message_header.destination.relay_to.clone()) {
                        (dest, Some(relay)) => {
                            // if we should directly respond to this message, do so
                            if dest == self.id.name()
                                && self.relay_map.contains_relay_for(&relay) {
                                info!("Sending ConnectResponse directly to relay {:?}", relay);
                                self.send_out_as_relay(&relay, serialised_message);
                                return Ok(());
                            }
                        },
                        _ => {}
                    };

                    self.send_swarm_or_parallel(&routing_msg.message_header.destination.dest,
                        &serialised_message);
*/
                }
            },
            None => {}
        };
        Ok(())
    }

    fn handle_refresh(&mut self, message: RoutingMessage, tag: u64, payload: Vec<u8>) -> RoutingResult {
        let group = match message.from_group() {
            Some(g) => g,
            None    => return Err(RoutingError::RefreshNotFromGroup),
        };

        let threshold = (self.routing_table.size() as f32) * 0.8; // 80% chosen arbitrary
        let opt_payloads = self.refresh_accumulator.add_message(threshold as usize,
                                                                tag,
                                                                message.non_relayed_source(),
                                                                group.clone(),
                                                                payload);
        opt_payloads.map(|payload| {
            self.mut_interface().handle_refresh(tag, group, payload);
        });
        Ok(())
    }

    fn handle_connect_response(&mut self, connect_response: ConnectResponse) -> RoutingResult {

        // Verify a connect request was initiated by us.
        let connect_request = try!(decode::<ConnectRequest>(&connect_response.serialised_connect_request));
        if connect_request.requester_id != self.id.name() ||
           !verify_detached(&connect_response.connect_request_signature,
                                  &connect_response.serialised_connect_request[..],
                                  &self.id.signing_public_key()) {
            return Err(RoutingError::Response(ResponseError::InvalidRequest));
        }
        // double check if fob is relocated;
        // this should be okay as we check this before sending out a connect_request
        if !connect_response.receiver_fob.is_relocated() {
            return Err(RoutingError::RejectedPublicId); }
        // Collect the local and external endpoints into a single vector to construct a NodeInfo
        let mut peer_endpoints = connect_response.receiver_local_endpoints.clone();
        peer_endpoints.extend(connect_response.receiver_external_endpoints.clone().into_iter());
  // info!("ConnectResponse from {:?}",  )
  // for peer in peer_endpoint {
  //     info!("")
  // }
        let peer_node_info =
            NodeInfo::new(connect_response.receiver_fob.clone(), peer_endpoints, None);

        // Try to add to the routing table.  If unsuccessful, no need to continue.
        let (added, _) = self.routing_table.add_node(peer_node_info.clone());
        if !added {
           return Err(RoutingError::RefusedFromRoutingTable); }
        info!("RT (size : {:?}) added {:?} on connect response", self.routing_table.size(),
            peer_node_info.fob.name());
        // Try to connect to the peer.
        self.connection_manager.connect(connect_response.receiver_local_endpoints.clone());
        self.connection_manager.connect(connect_response.receiver_external_endpoints.clone());
        Ok(())
    }

    /// On bootstrapping a node can temporarily publish its PublicId in the group.
    /// No handle_get_public_id is needed - this is handled by routing_node
    /// before the membrane instantiates.
    // TODO (Ben): check whether to accept id into group;
    // restrict on minimal similar number of leading bits.
    fn handle_put_public_id(&mut self, signed_message: SignedMessage, message: RoutingMessage,
        public_id: PublicId) -> RoutingResult {
        let our_authority = our_authority(&message, &self.routing_table);
        match (message.from_authority(), our_authority.clone(), public_id.is_relocated()) {
            (Authority::ManagedNode, Authority::NaeManager(_), false) => {
                let mut put_public_id_relocated = public_id.clone();

                let close_group =
                    self.routing_table.our_close_group().into_iter()
                    .map(|node_info| node_info.id())
                    .chain(Some(self.id.name().clone()).into_iter())
                    .collect::<Vec<NameType>>();

                let relocated_name = try!(utils::calculate_relocated_name(close_group,
                                                                          &public_id.name()));
                // assign_relocated_name
                put_public_id_relocated.assign_relocated_name(relocated_name.clone());

                info!("RELOCATED {:?} to {:?}", public_id.name(), relocated_name);
                // Forward to relocated_name group, which will actually store the relocated public id
                try!(self.forward(&signed_message, &message, relocated_name));
                Ok(())
            },
            (Authority::NaeManager(_), Authority::NaeManager(_), true) => {
                // Note: The "if" check is workaround for absense of sentinel. This avoids redundant PutPublicIdResponse responses.
                if !self.public_id_cache.contains_key(&public_id.name()) {
                  self.public_id_cache.add(public_id.name(), public_id.clone());
                  info!("CACHED RELOCATED {:?}", public_id.name());
                  // Reply with PutPublicIdResponse to the reply_to address
                  //let reply_message = message.create_reply(&self.id.name(), &our_authority);
                  let routing_msg = RoutingMessage { destination  : message.reply_destination(),
                                                     source       : SourceAddress::Direct(self.id.name().clone()),
                                                     orig_message : None, // TODO: Check this
                                                     message_type : MessageType::PutPublicIdResponse(public_id.clone()),
                                                     message_id   : message.message_id,
                                                     authority    : our_authority.clone(),
                                                   };

                  ignore(self.send_swarm_or_parallel(&routing_msg));
                }
                Ok(())
            },
            _ => Err(RoutingError::BadAuthority)
        }
    }

    fn handle_find_group(&mut self, original_message: RoutingMessage) -> RoutingResult {
        let group = self.routing_table.our_close_group().into_iter()
                    .map(|x|x.fob)
                    // add ourselves
                    .chain(Some(PublicId::new(&self.id)).into_iter())
                    .collect::<Vec<_>>();

        let message = RoutingMessage {
            destination  : original_message.reply_destination(),
            source       : SourceAddress::Direct(self.id.name().clone()),
            orig_message : None,
            message_type : MessageType::FindGroupResponse(group),
            message_id   : original_message.message_id,
            authority    : Authority::Unknown,
        };

        self.send_swarm_or_parallel(&message)
    }

    fn handle_find_group_response(&mut self,
                                  find_group_response: Vec<PublicId>,
                                  refresh_our_own_group: bool) -> RoutingResult {
        for peer in find_group_response {
            self.refresh_routing_table(&peer.name());
        }
        if refresh_our_own_group {
            let our_name = self.id.name().clone();
            if !self.connection_cache.contains_key(&our_name) {
                let find_group_msg = self.construct_find_group_msg();
                ignore(self.send_swarm_or_parallel(&find_group_msg));
                self.connection_cache.entry(our_name)
                    .or_insert(SteadyTime::now());
            }
        }
        Ok(())
    }

    fn handle_get_data(&mut self, orig_message: SignedMessage,
                                  message: RoutingMessage,
                                  data_request: DataRequest) -> RoutingResult {
        let our_authority  = our_authority(&message, &self.routing_table);
        let from_authority = message.from_authority();
        let from           = message.source_address();

        match self.mut_interface().handle_get(
                data_request.clone(), our_authority.clone(), from_authority, from) {
            Ok(method_calls) => {
                for method_call in method_calls {
                    match method_call {
                        MethodCall::Put { destination: x, content: y, } => self.put(x, y),
                        MethodCall::Get { name: x, data_request: y, } => self.get(x, y),
                        MethodCall::Refresh { type_tag, from_group, payload } => self.refresh(type_tag, from_group, payload),
                        MethodCall::Post { destination: x, content: y, } => self.post(x, y),
                        MethodCall::Delete { name: x, data : y } => self.delete(x, y),
                        MethodCall::Forward { destination } =>
                            ignore(self.forward(&orig_message, &message, destination)),
                        MethodCall::Reply { data } => {

                            let group_pub_keys = if our_authority.is_group() {
                                self.group_pub_keys()
                            }
                            else {
                                BTreeMap::new()
                            };

                            let response = GetDataResponse {
                                data           : data,
                                orig_request   : orig_message.clone(),
                                group_pub_keys : group_pub_keys
                            };

                            ignore(self.send_reply(&message, our_authority.clone(),
                                                   MessageType::GetDataResponse(response)))
                        },
                    }
                }
            },
            Err(..) => {;},
        }
        Ok(())
    }

    fn forward(&self, orig_message: &SignedMessage, routing_message: &RoutingMessage,
            destination: NameType) -> RoutingResult {
        let our_authority = our_authority(&routing_message, &self.routing_table);
        let message = routing_message.create_forward(self.id.name().clone(),
                                                     our_authority,
                                                     destination,
                                                     orig_message.clone());
        ignore(self.send_swarm_or_parallel(&message));
        Ok(())
    }

    fn send_reply(&mut self,
                  routing_message : &RoutingMessage,
                  our_authority   : Authority,
                  msg             : MessageType) -> RoutingResult {
        let mut message = try!(routing_message.create_reply(&self.id.name(), &our_authority));

        message.message_type = msg;
        message.authority    = our_authority;

        self.send_swarm_or_parallel_or_relay(&message)
    }

    fn handle_node_get_data_response(&mut self, signed_message : SignedMessage,
            message: RoutingMessage, response: GetDataResponse) -> RoutingResult {
        let our_authority = our_authority(&message, &self.routing_table);
        let from = message.source.non_relayed_source();
        let mut quorum = types::QUORUM_SIZE;

        let source = match message.source.actual_source() {
            Address::Node(name) => name,
            _ => return Err(RoutingError::BadAuthority),
        };

        if self.routing_table.size() < types::QUORUM_SIZE {
            quorum = self.routing_table.size();
        }

        let resolved = Event::GetDataResponse(signed_message.clone(), response.clone(), source,
                                              message.destination.non_relayed_destination(),
                                              message.authority.clone(), our_authority.clone(),
                                              message.message_id.clone());


        //let resolved = match self.get_data_response_sentinel.add_claim(
        //    SentinelGetDataResponse::new(message.clone(), response.clone(), our_authority.clone()),
        //    source, signed_message.signature().clone(),
        //    signed_message.encoded_body().clone(), quorum, quorum) {
        //        Some(result) =>  match  result {
        //            AddResult::RequestKeys(_) => {
        //                // Get Key Request
        //                return Ok(())
        //            },
        //            AddResult::Resolved(request, serialised_claim) => (request, serialised_claim)
        //        },
        //        None => return Ok(())
        //};
        let data_response = try!(resolved.get_data_response());
        for method_call in self.mut_interface().handle_get_response(from,
                                                                    data_response.data.clone()) {
            match method_call {
                MethodCall::Put { destination: x, content: y, } => self.put(x, y),
                MethodCall::Get { name: x, data_request: y, } => self.get(x, y),
                MethodCall::Refresh { type_tag, from_group, payload } => self.refresh(type_tag, from_group, payload),
                MethodCall::Post { destination: x, content: y, } => self.post(x, y),
                MethodCall::Delete { name: x, data : y } => self.delete(x, y),
                MethodCall::Forward { destination } => {
                    let message_type = MessageType::GetDataResponse(data_response.clone());
                    let msg = try!(resolved.create_forward(message_type, self.id.name(), destination,
                                                           self.get_next_message_id()));
                    ignore(self.send_swarm_or_parallel(&msg));
                },
                MethodCall::Reply { data: _data } =>
                    info!("IGNORED: on handle_get_data_response MethodCall:Reply is not a Valid action")
            }
        }
        Ok(())
    }

    fn handle_client_get_data_response(&mut self, _orig_message : SignedMessage,
            message: RoutingMessage, response: GetDataResponse) -> RoutingResult {
        if !response.verify_request_came_from(&self.id.signing_public_key()) {
            return Err(RoutingError::FailedSignature);
        }

        let our_authority = our_authority(&message, &self.routing_table);
        let from = message.source.non_relayed_source();

        for method_call in self.mut_interface().handle_get_response(from, response.data.clone()) {
            match method_call {
                MethodCall::Put { destination: x, content: y, } => self.put(x, y),
                MethodCall::Get { name: x, data_request: y, } => self.get(x, y),
                MethodCall::Refresh { type_tag, from_group, payload } => self.refresh(type_tag, from_group, payload),
                MethodCall::Post { destination: x, content: y, } => self.post(x, y),
                MethodCall::Delete { name: x, data : y } => self.delete(x, y),
                MethodCall::Forward { destination } => {
                    let message_id = self.get_next_message_id();
                    let message = RoutingMessage {
                        destination  : DestinationAddress::Direct(destination),
                        source       : SourceAddress::Direct(self.id.name()),
                        orig_message : None,
                        message_type : MessageType::GetDataResponse(response.clone()),
                        message_id   : message_id,
                        authority    : our_authority.clone(),
                    };
                    ignore(self.forward(&try!(SignedMessage::new(&message, self.id.signing_private_key())) , &message, destination));
                },
                MethodCall::Reply { data: _data } =>
                    info!("IGNORED: on handle_get_data_response MethodCall:Reply is not a Valid action")
            }
        }
        Ok(())
    }

    fn group_pub_keys(&self) -> BTreeMap<NameType, sign::PublicKey> {
        let name_and_key_from_info = |node_info : NodeInfo| {
            (node_info.fob.name(), node_info.fob.signing_public_key())
        };

        let ourselves = (self.id.name(), self.id.signing_public_key());

        self.routing_table.our_close_group()
                          .into_iter()
                          .map(name_and_key_from_info)
                          .chain(Some(ourselves).into_iter())
                          .collect()
    }

    fn mut_interface(&mut self) -> &mut F { self.interface.deref_mut() }
}


fn ignore<R,E>(_result: Result<R,E>) {}

#[cfg(test)]
mod test {

use super::*;
use super::ConnectionName;
use authority::Authority;
use crust;
use data::{Data, DataRequest};
use error::{ResponseError, InterfaceError};
use id::Id;
use event::Event;
use immutable_data::{ImmutableData, ImmutableDataType};
use structured_data::StructuredData;
use messages::{ErrorReturn, RoutingMessage, MessageType, SignedMessage, GetDataResponse};
use name_type::{NameType, closer_to_target, NAME_TYPE_LEN};
use node_interface::{Interface, MethodCall};
use public_id::PublicId;
use rand::{random, Rng, thread_rng};
use routing_table;
use sendable::Sendable;
use sodiumoxide::crypto;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use test_utils::Random;
use types::{DestinationAddress, MessageId, SourceAddress, GROUP_SIZE, Address};
use utils;
use crust::Endpoint;
use rand::distributions::{IndependentSample, Range};
use std::collections::BTreeMap;


// TODO: This duplicate must use the available code
pub fn random_endpoint() -> Endpoint {
    use std::net::{Ipv4Addr, SocketAddrV4, SocketAddr};
    Endpoint::Tcp(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(random::<u8>(),
        random::<u8>(), random::<u8>(),random::<u8>()), random::<u16>())))
}

// TODO: This duplicate must use the available code
pub fn random_endpoints() -> Vec<Endpoint> {
    let range = Range::new(1, 10);
    let mut rng = thread_rng();
    let count = range.ind_sample(&mut rng);
    let mut endpoints = vec![];
    for _ in 0..count {
        endpoints.push(random_endpoint());
    }
    endpoints
}

#[derive(Clone)]
struct Stats {
    call_count: usize,
    data: Vec<u8>
}

impl Stats {
    pub fn new() -> Stats {
        Stats {call_count: 0, data: vec![]}
    }
}

struct TestInterface {
    stats: Arc<Mutex<Stats>>
}

impl Interface for TestInterface {
    fn handle_get(&mut self, _data_request: DataRequest, _our_authority: Authority,
                  _from_authority: Authority, _from_address   : SourceAddress)
        -> Result<Vec<MethodCall>, InterfaceError> {
        let stats = self.stats.clone();
        let mut stats_value = stats.lock().unwrap();
        stats_value.call_count += 1;
        let data = Data::ImmutableData(
                ImmutableData::new(ImmutableDataType::Normal,
                "handle_get called".to_string().into_bytes().iter().map(|&x| x).collect::<Vec<_>>()));
        let mut method_calls = Vec::<MethodCall>::new();
        method_calls.push(MethodCall::Reply { data: data });
        Ok(method_calls)
    }

    fn handle_put(&mut self, _our_authority: Authority, from_authority: Authority,
                  _from_address: SourceAddress, _dest_address: DestinationAddress,
                  data: Data) -> Result<Vec<MethodCall>, InterfaceError> {
        let stats = self.stats.clone();
        let mut stats_value = stats.lock().unwrap();
        stats_value.call_count += 1;
        stats_value.data = match from_authority {
            Authority::Unknown => "UnauthorisedPut".to_string().into_bytes(),
            _   => "AuthorisedPut".to_string().into_bytes(),
        };
        let mut method_calls = Vec::<MethodCall>::new();
        method_calls.push(MethodCall::Reply { data: data });
        Ok(method_calls)
    }

    fn handle_refresh(&mut self, _type_tag: u64, _from_group: NameType, payloads: Vec<Vec<u8>>) {
        let stats = self.stats.clone();
        let mut stats_value = stats.lock().unwrap();
        stats_value.call_count += 1;
        stats_value.data = payloads[0].clone();
    }

    fn handle_post(&mut self, _our_authority: Authority, _from_authority: Authority,
                   _from_address: SourceAddress, _dest_address: DestinationAddress,
                   data: Data) -> Result<Vec<MethodCall>, InterfaceError> {
        let stats = self.stats.clone();
        let mut stats_value = stats.lock().unwrap();
        stats_value.call_count += 1;
        stats_value.data = "handle_post called".to_string().into_bytes();
        let mut method_calls = Vec::<MethodCall>::new();
        method_calls.push(MethodCall::Reply { data: data });
        Ok(method_calls)
    }

    fn handle_get_response(&mut self, _from_address: NameType,
                           _response: Data) -> Vec<MethodCall> {
        let stats = self.stats.clone();
        let mut stats_value = stats.lock().unwrap();
        stats_value.call_count += 1;
        stats_value.data = "handle_get_response called".to_string().into_bytes();
        Vec::<MethodCall>::new()
    }

    fn handle_put_response(&mut self, _from_authority: Authority, _from_address: SourceAddress,
                           _response: ResponseError) -> Vec<MethodCall> {
        let stats = self.stats.clone();
        let mut stats_value = stats.lock().unwrap();
        stats_value.call_count += 1;
        stats_value.data = "handle_put_response".to_string().into_bytes();
        Vec::<MethodCall>::new()
    }

    fn handle_post_response(&mut self, _from_authority: Authority, _from_address: SourceAddress,
                           _response: ResponseError) -> Vec<MethodCall> {
        let stats = self.stats.clone();
        let mut stats_value = stats.lock().unwrap();
        stats_value.call_count += 1;
        stats_value.data = "handle_post_response".to_string().into_bytes();
        Vec::<MethodCall>::new()
    }

    fn handle_churn(&mut self, _close_group: Vec<NameType>)
        -> Vec<MethodCall> {
        unimplemented!();
    }

    fn handle_cache_get(&mut self, _data_request   : DataRequest,
                                   _from_authority : NameType,
                                   _from_address   : NameType)
        -> Result<MethodCall, InterfaceError> {
        Err(InterfaceError::Abort)
    }

    fn handle_cache_put(&mut self, _from_authority: Authority, _from_address: NameType,
                        _data: Data) -> Result<MethodCall, InterfaceError> {
        Err(InterfaceError::Abort)
    }
}

fn create_membrane(stats: Arc<Mutex<Stats>>) -> RoutingMembrane<TestInterface> {
    //FIXME(ben): review whether this is correct and wanted 23/07/2015
    let mut id = Id::new();
    let (event_output, event_input) = mpsc::channel();
    let mut cm = crust::ConnectionManager::new(event_output.clone());
    cm.start_accepting(vec![]);

    // Hack: assign a name which is not a hash of the public sign
    // key, so that the membrane thinks it is a relocated id.
    id.assign_relocated_name(NameType([0;NAME_TYPE_LEN]));

    RoutingMembrane::<TestInterface>::new(cm, event_output, event_input, None, id.clone(), TestInterface {stats : stats})
}

struct Tester {
    pub stats    : Arc<Mutex<Stats>>,
    pub membrane : RoutingMembrane<TestInterface>
}

impl Tester {
    pub fn new() -> Tester {
        let stats = Arc::new(Mutex::new(Stats::new()));
        Tester {
            stats    : stats.clone(),
            membrane : create_membrane(stats),
        }
    }

    pub fn call_operation(&mut self,
                          message_type : MessageType,
                          source       : SourceAddress,
                          destination  : DestinationAddress,
                          authority    : Authority) -> Stats {
        let message = RoutingMessage {
            destination : destination,
            source      : source.clone(),
            orig_message: None,
            message_type: message_type,
            message_id  : self.membrane.get_next_message_id(),
            authority   : authority,
        };

        let signed_message = SignedMessage::new(&message, self.membrane.id.signing_private_key());
        let connection_name = ConnectionName::Routing(match source.actual_source() {
            Address::Node(name) => name,
            _                   => Random::generate_random()
        });

        let _ = self.membrane.message_received(signed_message.unwrap());
        let stats = self.stats.clone();
        let stats_value = stats.lock().unwrap();
        stats_value.clone()
    }
}

fn populate_routing_node() -> RoutingMembrane<TestInterface> {
    let stats = Arc::new(Mutex::new(Stats::new()));
    let mut membrane = create_membrane(stats);

    let mut count : usize = 0;
    loop {
        membrane.routing_table.add_node(routing_table::NodeInfo::new(
                                        PublicId::new(&Id::new()),
                                        random_endpoints(),
                                        Some(random_endpoint())));
        count += 1;
        if membrane.routing_table.size() >=
            routing_table::RoutingTable::get_optimal_size() { break; }
        if count >= 2 * routing_table::RoutingTable::get_optimal_size() {
            panic!("Routing table does not fill up."); }
    }
    membrane
}

    #[test]
    fn check_next_id() {
        let mut membrane = create_membrane(Arc::new(Mutex::new(Stats::new())));
        assert_eq!(membrane.get_next_message_id() + 1, membrane.get_next_message_id());
    }

    #[test]
    fn call_put() {
        let mut array = [0u8; 64];
        thread_rng().fill_bytes(&mut array);
        let chunk = Data::ImmutableData(
            ImmutableData::new(ImmutableDataType::Normal, array.iter().map(|&x| x).collect::<Vec<_>>()));
        let mut membrane = create_membrane(Arc::new(Mutex::new(Stats::new())));
        let name: NameType = Random::generate_random();
        membrane.put(name, chunk);
    }

    #[test]
    fn call_post() {
        let mut array = [0u8; 64];
        thread_rng().fill_bytes(&mut array);
        let chunk = Data::ImmutableData(
            ImmutableData::new(ImmutableDataType::Normal, array.iter().map(|&x| x).collect::<Vec<_>>()));
        let mut membrane = create_membrane(Arc::new(Mutex::new(Stats::new())));
        let name: NameType = Random::generate_random();
        membrane.post(name, chunk);
    }

    #[test]
    fn call_get() {
        let mut membrane = create_membrane(Arc::new(Mutex::new(Stats::new())));
        let name: NameType = Random::generate_random();
        membrane.get(name, DataRequest::ImmutableData(ImmutableDataType::Normal));
    }

    #[test]
    fn call_refresh() {
        let mut array = [0u8; 64];
        thread_rng().fill_bytes(&mut array);
        let content = array.into_iter().map(|&value| value).collect::<Vec<_>>();
        let mut membrane = create_membrane(Arc::new(Mutex::new(Stats::new())));
        let name: NameType = Random::generate_random();
        membrane.refresh(100u64, name, content);
    }

    //Ignored because it expects that sentinel is in place.
    #[test]
    #[ignore]
    fn call_handle_put() {
        let mut array = [0u8; 64];
        thread_rng().fill_bytes(&mut array);
        let data = Data::ImmutableData(
            ImmutableData::new(ImmutableDataType::Normal,
                               array.iter().map(|&x|x).collect::<Vec<_>>()));
        let put_data = MessageType::PutData(data.clone());
        let source_name_type1: NameType = Random::generate_random();
        let source_name_type2: NameType = Random::generate_random();
        let dest_name_type: NameType = Random::generate_random();
        let authority = Authority::NodeManager(data.name());
        let message_id = random::<MessageId>();
        let message1 = RoutingMessage {
            destination : DestinationAddress::Direct(dest_name_type),
            source      : SourceAddress::Direct(source_name_type1.clone()),
            orig_message: None,
            message_type: put_data.clone(),
            message_id  : message_id,
            authority   : authority.clone(),
        };

        let message2 = RoutingMessage {
            destination : DestinationAddress::Direct(dest_name_type),
            source      : SourceAddress::Direct(source_name_type2.clone()),
            orig_message: None,
            message_type: put_data,
            message_id  : message_id,
            authority   : authority.clone(),
        };

        let mut name_key_pairs = Vec::new();
        let sign_keys1 =  crypto::sign::gen_keypair();
        let sign_keys2 =  crypto::sign::gen_keypair();
        name_key_pairs.push((source_name_type1.clone(), sign_keys1.0.clone()));
        name_key_pairs.push((source_name_type2.clone(), sign_keys2.0.clone()));
        let signed_message1 = SignedMessage::new(&message1, &sign_keys1.1).unwrap();
        let signed_message2 = SignedMessage::new(&message2, &sign_keys1.1).unwrap();

        let request1 = Event::PutDataRequest(signed_message1.clone(), data.clone(),
                                             source_name_type1,
                                             message1.destination.non_relayed_destination(),
                                             Authority::NodeManager(dest_name_type),
                                             authority.clone(),
                                             message1.message_id.clone());

        let request2 = Event::PutDataRequest(signed_message1.clone(), data.clone(),
                                             source_name_type1,
                                             message2.destination.non_relayed_destination(),
                                             Authority::NodeManager(dest_name_type),
                                             authority.clone(),
                                             message2.message_id.clone());

        let mut tester = Tester::new();

        let connection_name1 = ConnectionName::Routing(source_name_type1);
        let connection_name2 = ConnectionName::Routing(source_name_type2);

        let _ = tester.membrane.message_received(signed_message1);
        assert!(tester.membrane.put_sentinel.add_keys(
            request1.clone(), Random::generate_random(), name_key_pairs.clone(), 2usize).is_none());
        assert!(tester.membrane.put_sentinel.add_keys(
            request2.clone(), Random::generate_random(), name_key_pairs, 2usize).is_none());
        let _ = tester.membrane.message_received(signed_message2);
        let stats = tester.stats.clone();
        let stats_value = stats.lock().unwrap();
        assert_eq!(stats_value.call_count, 1usize);
    }

    #[test]
    fn call_handle_put_response() {
        let mut array = [0u8; 64];
        thread_rng().fill_bytes(&mut array);
        let keys = crypto::sign::gen_keypair();
        let put_data = MessageType::PutData(
            Data::ImmutableData(
                ImmutableData::new(ImmutableDataType::Normal,
                                   array.iter().map(|&x|x).collect::<Vec<_>>())));
        let message = RoutingMessage {
            destination : DestinationAddress::Direct(Random::generate_random()),
            source      : SourceAddress::Direct(Random::generate_random()),
            orig_message: None,
            message_type: put_data,
            message_id  : random::<u32>(),
            authority   : Authority::NaeManager(Random::generate_random())
        };

        let signed_message = SignedMessage::new(&message, &keys.1);

        let put_data_response = MessageType::PutDataResponse(
                                    ErrorReturn::new(ResponseError::NoData,
                                                     signed_message.unwrap()),
                                    BTreeMap::new());

        assert_eq!(Tester::new().call_operation(put_data_response,
            SourceAddress::Direct(Random::generate_random()),
            DestinationAddress::Direct(Random::generate_random()),
            Authority::NaeManager(Random::generate_random())).call_count, 1usize);
    }

    #[test]
    fn call_handle_get_data() {
        let get_data = MessageType::GetData(DataRequest::ImmutableData(ImmutableDataType::Normal));
        assert_eq!(Tester::new().call_operation(get_data,
            SourceAddress::Direct(Random::generate_random()),
            DestinationAddress::Direct(Random::generate_random()),
            Authority::NaeManager(Random::generate_random())).call_count, 1usize);
    }

    #[test]
    fn call_handle_get_data_response() {
        let mut tester = Tester::new();

        let mut array = [0u8; 64];
        thread_rng().fill_bytes(&mut array);

        let get_data = MessageType::GetData(
                           DataRequest::ImmutableData(ImmutableDataType::Normal));

        let message = RoutingMessage {
            destination : DestinationAddress::Direct(Random::generate_random()),
            source      : SourceAddress::Direct(Random::generate_random()),
            orig_message: None,
            message_type: get_data,
            message_id  : random::<u32>(),
            authority   : Authority::NaeManager(Random::generate_random())
        };

        let signed_message = SignedMessage::new(&message, &tester.membrane.id.signing_private_key()).unwrap();

        let get_data_response = MessageType::GetDataResponse(
            GetDataResponse {
                data: Data::ImmutableData(
                        ImmutableData::new(ImmutableDataType::Normal,
                                           array.iter().map(|&x|x).collect::<Vec<_>>())),
                orig_request   : signed_message,
                group_pub_keys : BTreeMap::new(),
            });

        assert_eq!(tester.call_operation(get_data_response,
            SourceAddress::Direct(Random::generate_random()),
            DestinationAddress::Direct(Random::generate_random()),
            Authority::NaeManager(Random::generate_random())).call_count, 1usize);
    }

    #[test]
    fn call_handle_post() {
        let mut array = [0u8; 64];
        thread_rng().fill_bytes(&mut array);
        let keys = crypto::sign::gen_keypair();
        let post_data = MessageType::Post(
            Data::StructuredData(
                StructuredData::new(0,
                                    Random::generate_random(),
                                    vec![],
                                    vec![keys.0],
                                    0,
                                    vec![],
                                    vec![])));
        assert_eq!(Tester::new().call_operation(post_data,
                   SourceAddress::Direct(Random::generate_random()),
                   DestinationAddress::Direct(Random::generate_random()),
                   Authority::NaeManager(Random::generate_random())).call_count, 1usize);
    }

    #[test]
    fn call_handle_post_response() {
        let mut array = [0u8; 64];
        thread_rng().fill_bytes(&mut array);
        let keys = crypto::sign::gen_keypair();
        let post_data = MessageType::Post(
            Data::StructuredData(
                StructuredData::new(0,
                                    Random::generate_random(),
                                    vec![],
                                    vec![keys.0],
                                    0,
                                    vec![],
                                    vec![])));
        let message = RoutingMessage {
            destination : DestinationAddress::Direct(Random::generate_random()),
            source      : SourceAddress::Direct(Random::generate_random()),
            orig_message: None,
            message_type: post_data,
            message_id  : random::<u32>(),
            authority   : Authority::NaeManager(Random::generate_random())
        };

        let signed_message = SignedMessage::new(&message, &keys.1);

        let post_response = MessageType::PostResponse(
                                ErrorReturn::new(ResponseError::NoData,
                                                 signed_message.unwrap()),
                                BTreeMap::new());

        assert_eq!(Tester::new().call_operation(post_response,
            SourceAddress::Direct(Random::generate_random()),
            DestinationAddress::Direct(Random::generate_random()),
            Authority::NaeManager(Random::generate_random())).call_count, 1usize);
    }

    #[test]
    fn call_handle_refresh() {
        let mut array = [0u8; 64];
        thread_rng().fill_bytes(&mut array);
        let refresh = MessageType::Refresh(random::<u64>(), array.iter().map(|&x|x).collect::<Vec<_>>());
        assert_eq!(Tester::new().call_operation(refresh,
                   SourceAddress::Direct(Random::generate_random()),
                   DestinationAddress::Direct(Random::generate_random()),
                   Authority::NaeManager(Random::generate_random())).call_count, 1usize);
    }

    #[test]
    fn relocate_original_public_id() {
        let mut routing_node = populate_routing_node();
        let furthest_closest_node = routing_node.routing_table.our_close_group().last().unwrap().id();
        let our_name = routing_node.id.name().clone();
        let total_inside : u32 = 5;
        let limit_attempts : u32 = 300;
        let mut stored_public_ids : Vec<PublicId> = Vec::with_capacity(total_inside as usize);
        let mut count_inside : u32 = 0;
        let mut count_total : u32 = 0;
        loop {
            let public_id = PublicId::new(&Id::new());
            let put_public_id = MessageType::PutPublicId(public_id.clone());
            let message = RoutingMessage {
                destination : DestinationAddress::Direct(public_id.name()),
                source      : SourceAddress::Direct(Random::generate_random()),
                orig_message: None,
                message_type: put_public_id,
                message_id  : random::<u32>(),
                authority   : Authority::ManagedNode,
            };
            let signed_message = SignedMessage::new(&message, routing_node.id.signing_private_key());
            let result = routing_node.handle_put_public_id(signed_message.unwrap(), message, public_id.clone());
            if closer_to_target(&public_id.name(),
                                &furthest_closest_node,
                                &our_name) {
                assert!(result.is_ok());
                stored_public_ids.push(public_id);
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
                    info!("Could only verify {} successful public_ids inside
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
        let our_name = routing_node.id.name().clone();
        let total_inside : u32 = 5;
        let limit_attempts : u32 = 300;
        let mut stored_public_ids : Vec<PublicId> = Vec::with_capacity(total_inside as usize);
        let mut count_inside : u32 = 0;
        let mut count_total : u32 = 0;
        loop {
            let original_public_id = PublicId::generate_random();
            let mut close_nodes_to_original_name : Vec<NameType> = Vec::new();
            for _ in 0..GROUP_SIZE {
                close_nodes_to_original_name.push(Random::generate_random());
            }
            let relocated_name = utils::calculate_relocated_name(close_nodes_to_original_name.clone(),
                                    &original_public_id.name()).unwrap();
            let mut relocated_public_id = original_public_id.clone();
            relocated_public_id.assign_relocated_name(relocated_name.clone());

            let put_public_id = MessageType::PutPublicId(relocated_public_id.clone());

            let message = RoutingMessage {
                destination : DestinationAddress::Direct(relocated_public_id.name()),
                source      : SourceAddress::Direct(Random::generate_random()),
                orig_message: None,
                message_type: put_public_id,
                message_id  : random::<u32>(),
                authority   : Authority::NaeManager(original_public_id.name()),
            };

            let signed_message = SignedMessage::new(&message, routing_node.id.signing_private_key());
            let result = routing_node.handle_put_public_id(signed_message.unwrap(), message, relocated_public_id.clone());
            if closer_to_target(&relocated_public_id.name(),
                                &furthest_closest_node,
                                &our_name) {
                assert!(result.is_ok());
                stored_public_ids.push(relocated_public_id);
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
                    info!("Could only verify {} successful public_ids inside
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
}
