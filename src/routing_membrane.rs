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

use cbor::{Decoder, Encoder, CborError};
use rand;
use rustc_serialize::{Decodable, Encodable};
use sodiumoxide::crypto::sign::{Signature, verify_detached, sign_detached};
use std::collections::{BTreeMap};
use std::boxed::Box;
use std::ops::DerefMut;
use std::sync::mpsc::Receiver;
use time::{Duration, SteadyTime};

use crust;
use crust::{ConnectionManager, Event, Endpoint};
use lru_time_cache::LruCache;
use message_filter::MessageFilter;
use NameType;
use name_type::{closer_to_target_or_equal};
use node_interface::Interface;
use routing_table::{RoutingTable, NodeInfo};
use relay::RelayMap;
use sendable::Sendable;
use data::{Data, DataRequest};
use types;
use types::{MessageId, NameAndTypeId, Bytes, DestinationAddress, SourceAddress};
use authority::{Authority, our_authority};
use who_are_you::{WhoAreYou, IAm};
use messages::{Message, RoutingMessage, SignedRoutingMessage, MessageType, ConnectRequest, ConnectResponse};
use error::{RoutingError, ResponseError, InterfaceError};
use node_interface::{MethodCall, MessageAction};
use refresh_accumulator::RefreshAccumulator;
use id::Id;
use public_id::PublicId;
use utils;


type RoutingResult = Result<(), RoutingError>;

enum ConnectionName {
    Relay(NameType),
    Routing(NameType),
    OurBootstrap,
    UnidentifiedConnection,
    // ClaimedConnection(PublicId),
}

/// Routing Membrane
pub struct RoutingMembrane<F : Interface> {
    // for CRUST
    event_input: Receiver<crust::Event>,
    connection_manager: crust::ConnectionManager,
    accepting_on: Vec<crust::Endpoint>,
    bootstrap_endpoint: Option<crust::Endpoint>,
    // for Routing
    id: Id,
    own_name: NameType,
    routing_table: RoutingTable,
    relay_map: RelayMap,
    next_message_id: MessageId,
    filter: MessageFilter<types::FilterType>,
    public_id_cache: LruCache<NameType, PublicId>,
    connection_cache: BTreeMap<NameType, SteadyTime>,
    refresh_accumulator: RefreshAccumulator,
    // for Persona logic
    interface: Box<F>
}

impl<F> RoutingMembrane<F> where F: Interface {
    // TODO: clean ownership transfer up with proper structure
    pub fn new(cm: crust::ConnectionManager,
               event_input: Receiver<crust::Event>,
               bootstrap_endpoint: Option<crust::Endpoint>,
               accepting_on: Vec<crust::Endpoint>,
               relocated_id: Id,
               personas: F) -> RoutingMembrane<F> {
        debug_assert!(relocated_id.is_relocated());
        let own_name = relocated_id.get_name();
        RoutingMembrane {
                      event_input: event_input,
                      connection_manager: cm,
                      accepting_on: accepting_on,
                      bootstrap_endpoint: bootstrap_endpoint,
                      routing_table : RoutingTable::new(&own_name),
                      relay_map: RelayMap::new(&relocated_id),
                      own_name: own_name,
                      id : relocated_id,
                      next_message_id: rand::random::<MessageId>(),
                      filter: MessageFilter::with_expiry_duration(Duration::minutes(20)),
                      public_id_cache: LruCache::with_expiry_duration(Duration::minutes(10)),
                      connection_cache: BTreeMap::new(),
                      refresh_accumulator: RefreshAccumulator::new(),
                      interface : Box::new(personas)
                    }
    }

    /// Retrieve something from the network (non mutating) - Direct call
    pub fn get(&mut self, location: NameType, data : DataRequest) {
        let message_id = self.get_next_message_id();
        let message =  Message::Unsigned(RoutingMessage {
            destination : DestinationAddress::Direct(location),
            source      : SourceAddress::Direct(self.own_name()),
            message_type: MessageType::GetData(data),
            message_id  : message_id.clone(),
            authority   : Authority::Unknown
        });
        ignore(encode(&message).map(|msg| self.send_swarm_or_parallel(data.unwrap().name(), &msg)));
    }

    /// Add something to the network, will always go via ClientManager group
    pub fn put(&mut self, destination: NameType, data : Data) {
        let message_id = self.get_next_message_id();
        let message = RoutingMessage {
            destination : DestinationAddress::Direct(destination),
            source      : SourceAddress::Direct(self.own_name()),
            message_type: MessageType::PutData(data),
            message_id  : message_id.clone(),
            authority   : Authority::Unknown,
        };

        let signed_message = SignedRoutingMessage::new(message, &self.id.secret_keys.0);
        ignore(encode(&message).map(|msg| self.send_swarm_or_parallel(data.unwrap().name(), &msg)));
    }

    /// Refresh the content in the close group nodes of group address content::name.
    /// This method needs to be called when churn is triggered.
    /// all the group members need to call this, otherwise it will not be resolved as a valid
    /// content.
    pub fn refresh(&mut self, type_tag: u64, from_group: NameType, content: Bytes) {
        let message_id = self.get_next_message_id();
        let message = RoutingMessage {
            destination : DestinationAddress::Direct(from_group.clone()),
            source      : SourceAddress::Direct(self.own_name()),
            message_type: MessageType::Refresh(type_tag, content),
            message_id  : message_id.clone(),
            authority   : Authority::Unknown,
        };

        let signed_message = SignedRoutingMessage::new(message, &self.id.secret_keys.0);
        ignore(encode(&message).map(|msg| self.send_swarm_or_parallel(from_group, &msg)));
    }

    /// RoutingMembrane::Run starts the membrane
    pub fn run(&mut self) {
        // First send FindGroup request
        let our_name = self.own_name.clone();
        match self.bootstrap_endpoint.clone() {
            Some(ref bootstrap_endpoint) => {
                let find_group_msg = self.construct_find_group_msg(&our_name);
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

        println!("Started Membrane loop");
        loop {
            match self.event_input.recv() {
                Err(_) => (),
                Ok(crust::Event::NewMessage(endpoint, bytes)) => {
                    let message = match decode::<Message>(&bytes) {
                        Ok(message) => message,
                        Err(_)      => continue,
                    };

                    match self.lookup_endpoint(&endpoint) {
                        // we hold an active connection to this endpoint,
                        // mapped to a name in our routing table
                        Some(ConnectionName::Routing(name)) => {
                            ignore(self.message_received(&ConnectionName::Routing(name),
                                                         message,
                                                         false));
                        },
                        // we hold an active connection to this endpoint,
                        // mapped to a name in our relay map
                        Some(ConnectionName::Relay(name)) => {
                            // For a relay connection, parse and forward
                            // FIXME: later limit which messages are sent forward,
                            // limiting our exposure.
                            let _ = self.relay_message_received(
                                &ConnectionName::Relay(name), message, endpoint);
                        },
                        Some(ConnectionName::OurBootstrap) => {
                            // FIXME: This is a short-cut and should be improved upon.
                            // note: the name is not actively used by message_received.
                            // note: the destination address of header needs
                            // to be pointed to our relocated name; bypassed with flag
                            let placeholder_name = self.own_name.clone();
                            ignore(self.message_received(
                                       &ConnectionName::Routing(placeholder_name),
                                       message, true));
                        },
                        Some(ConnectionName::UnidentifiedConnection) => {
                            // only expect WhoAreYou or IAm message
                            match self.handle_unknown_connect_request(&endpoint, message) {
                                Ok(_) => {
                                    },
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
    fn handle_unknown_connect_request(&mut self, endpoint: &Endpoint, message: Message) -> RoutingResult {
        let (serialised_connect_request, signature) = match message.clone() {
            Message::Signed(serialised_cr, signature) => (serialised_cr, signature),
            Message::Unsigned(_) => return Err(RoutingError::NotEnoughSignatures)
        };

        let routing_message = try!(message.routing_message());
        let connect_request = match routing_message.message_type {
            MessageType::ConnectRequest(request) => request,
            _ => Err(InterfaceError::Abort), // To be changed to Parse error
        };
        let our_authority = our_authority(&routing_message, &self.routing_table);

        // only accept unrelocated Ids from unknown connections
        if connect_request.requester_fob.is_relocated() {
            return Err(RoutingError::RejectedPublicId);
        }

        // if the PublicId is not relocated,
        // only accept the connection into the RelayMap.
        // This will enable this connection to bootstrap or act as a client.
        let routing_msg = routing_message.create_reply(self.own_name(), our_authority);
        routing_msg.message_type = MessageType::ConnectResponse {
                    requester_local_endpoints: connect_request.local_endpoints.clone(),
                    requester_external_endpoints: connect_request.external_endpoints.clone(),
                    receiver_local_endpoints: self.accepting_on.clone(),
                    receiver_external_endpoints: vec![],
                    requester_id: connect_request.requester_id.clone(),
                    receiver_id: self.own_name.clone(),
                    receiver_fob: PublicId::new(&self.id),
                    serialised_connect_request: serialised_connect_request,
                    connect_request_signature: signature.clone()
                };

        let signed_message = SignedRoutingMessage::new(routing_msg, &self.id.secret_keys.0);
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
      println!("CRUST::NewConnection on {:?}", endpoint);
        self.drop_bootstrap();
        match self.lookup_endpoint(&endpoint) {
            Some(ConnectionName::Routing(name)) => {
                // should not occur; if the endpoint is in the lookup map of routing table,
                // it was already marked online.
                println!("DEBUG: NewConnection {:?} on already connected endpoint {:?} in RT.",
                    endpoint, name);
                match self.routing_table.mark_as_connected(&endpoint) {
                    Some(peer_name) => {
                        println!("RT (size : {:?}) Marked peer {:?} as connected on endpoint {:?}",
                                 self.routing_table.size(), peer_name, endpoint);
                        // FIXME: the presence of this debug assert indicates
                        // that the logic for unconnected RT nodes is not quite right.
                        debug_assert!(peer_name == name);
                    },
                    None => { }
                };
            },
            Some(ConnectionName::Relay(_)) => {
                // this endpoint is already present in the relay lookup_map
                // nothing to do
            },
            Some(ConnectionName::OurBootstrap) => {
                // FIXME: for now do nothing
            },
            Some(ConnectionName::UnidentifiedConnection) => {
                // again, already connected so examine later
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
                println!("RT (size : {:?}) connection {:?} disconnected for {:?}.",
                    self.routing_table.size(), endpoint, name);
            },
            None => {}
        };
        let mut drop_bootstrap = false;
        match self.bootstrap_endpoint {
            Some(ref bootstrap_endpoint) => {
                if &endpoint == bootstrap_endpoint {
                    println!("Bootstrap connection disconnected by relay node.");
                    self.connection_manager.drop_node(endpoint);
                    drop_bootstrap = true;
                }
            },
            None => {}
        };
        if drop_bootstrap { self.bootstrap_endpoint = None; }

        if trigger_handle_churn {
            println!("Handle CHURN lost node");
            let mut close_group : Vec<NameType> = self.routing_table
                .our_close_group().iter()
                .map(|node_info| node_info.fob.name())
                .collect::<Vec<NameType>>();
            close_group.insert(0, self.own_name.clone());
            let churn_actions = self.mut_interface().handle_churn(close_group);
            for action in churn_actions {
                match action {
                    MethodCall::Put { destination: x, content: y, } => self.put(x, y),
                    MethodCall::Get { name: x, data: y } => self.get(x, y),
                    MethodCall::Refresh { type_tag, from_group, payload } => self.refresh(type_tag, from_group, payload),
                    MethodCall::Post { destination: x, content: y, } => self.post(x, y),
                    MethodCall::None => (),
                    MethodCall::SendOn { destination } =>
                        println!("IGNORED: on handle_churn MethodCall:SendOn {} is not a Valid action", destination)
                };
            }
        };
    }

    /// Parse and update the header with us as a relay node;
    /// Intercept PutPublicId messages if we are the only zero node.
    fn relay_message_received(&mut self, received_from: &ConnectionName,
                                         message: Message,
                                         endpoint: Endpoint) -> RoutingResult {
        match received_from {
            &ConnectionName::Relay(ref name) => {
                // Parse as mutable to change header
                let mut routing_message = try!(message.routing_message());

                // intercept PutPublicId for zero node without connections
                if routing_message.message_type == MessageType::PutPublicId
                    && self.relay_map.zero_node()
                    && self.routing_table.size() == 0 {
                    let header = message.message_header;
                    let body = message.serialised_body;
                    // FIXME: check signature
                    ignore(self.handle_put_public_id_zero_node(header, body, &endpoint));
                    return Ok(());
                }

                ignore(self.message_received(&ConnectionName::Routing(name.clone()),
                                             message,
                                             false));
            },
            _ => return Err(RoutingError::Response(ResponseError::InvalidRequest))
        };
        Ok(())
    }

    /// This the fundamental functional function in routing.
    /// It only handles messages received from connections in our routing table;
    /// i.e. this is a pure SAFE message (and does not function as the start of a relay).
    /// If we are the relay node for a message from the SAFE network to a node we relay for,
    /// then we will pass out the message to the client or bootstrapping node;
    /// no relay-messages enter the SAFE network here.
    fn message_received(&mut self, received_from : &ConnectionName,
        message_wrap: Message, received_from_relay: bool) -> RoutingResult {
        match received_from {
            &ConnectionName::Routing(_) => { },
            _ => return Err(RoutingError::Response(ResponseError::InvalidRequest))
        };
        let message = try!(message_wrap.routing_message());
        if received_from_relay {
            // then this message was explicitly for us
            message.destination = DestinationAddress::Direct(self.own_name.clone());
        }
        // filter check
        if self.filter.check(&message.get_filter()) {
            // should just return quietly
            return Err(RoutingError::FilterCheckFailed);
        }
        // add to filter
        self.filter.add(message.get_filter());

        // add to cache
        match message.message_type {
            MessageType::GetDataResponse(result) => {
                result.map(|data| {
                    if data.is_empty() { return; }

                    let from = message.from_group()
                                      .unwrap_or(message.non_relayed_source());

                    ignore(self.mut_interface().handle_cache_put(
                           message.authority, from, data));
                })
            },
            _ => {}
        }

        // cache check / response
        match message.message_type {
            MessageType::GetData(data_request) => {
                let from = message.from_group()
                                  .unwrap_or(message.non_relayed_source());

                match self.mut_interface().handle_cache_get(data_request,
                                                            message.authority(),
                                                            from) {
                    Ok(action) => match action {
                        MessageAction::Reply(data) => {
                            let reply = message.create_reply(self.own_name(), Authority::NodeManager(self.own_name()));
                            self.send_reply(&message, our_authority.clone(), MessageType::GetDataResponse(data));
                            return Ok();
                        },
                        _ => (),
                    },
                    Err(_) => (),
                }
            }
        }

        // Forward
        self.send_swarm_or_parallel_or_relay(&message.destination, message_wrap);

        let address_in_close_group_range =
            self.address_in_close_group_range(&message.non_relayed_destination());

        // Handle FindGroupResponse
        if message.message_type == MessageType::FindGroupResponse {
            ignore(self.handle_find_group_response(body, &address_in_close_group_range));
            return Ok(());
        }

        if !address_in_close_group_range {
            return Ok(());
        }

        // Drop message before Sentinel check if it is a direct message type (Connect, ConnectResponse)
        // and this node is in the group but the message destination is another group member node.
        if message.message_type == MessageType::ConnectRequest
            || message.message_type == MessageType::ConnectResponse {
            if header.destination.dest != self.own_name  {
                // "not for me"
                return Ok(());
            }
        }
        //
        // pre-sentinel message handling
        match message.message_type {
            // FIXME: Unauthorised Put needs review
            MessageType::UnauthorisedPut => self.handle_put_data(header, body),
            // MessageType::GetKey => self.handle_get_key(header, body),
            // MessageType::GetGroupKey => self.handle_get_group_key(header, body),
            MessageType::ConnectRequest => self.handle_connect_request(body, message.signature),
            _ => {
                // Sentinel check

                // switch message type
                match message.message_type {
                    MessageType::ConnectResponse => self.handle_connect_response(body),
                    MessageType::FindGroup => self.handle_find_group(header, body),
                    // MessageType::FindGroupResponse => self.handle_find_group_response(header, body),
                    MessageType::GetData => self.handle_get_data(header, body),
                    MessageType::GetDataResponse => self.handle_get_data_response(header, body),
        //             MessageType::Post => self.handle_post(header, body),
        //             MessageType::PostResponse => self.handle_post_response(header, body),
                    MessageType::PutData => self.handle_put_data(header, body),
                    MessageType::PutDataResponse => self.handle_put_data_response(header, body),
                    MessageType::PutPublicId => self.handle_put_public_id(header, body),
                    MessageType::Refresh => { self.handle_refresh(header, body) },
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

    fn send_out_as_relay(&mut self, name: &NameType, msg: Bytes) {
        let mut failed_endpoints : Vec<Endpoint> = Vec::new();
        match self.relay_map.get_endpoints(name) {
            Some(&(_, ref endpoints)) => {
                for endpoint in endpoints {
                    match self.connection_manager.send(endpoint.clone(), msg.clone()) {
                        Ok(_) => break,
                        Err(_) => {
                            println!("Dropped relay connection {:?} on failed attempt
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

    fn send_swarm_or_parallel(&self, name : &NameType, msg: &Message) {
        for peer in self.routing_table.target_nodes(name) {
            match peer.connected_endpoint {
                Some(peer_endpoint) => {
                    ignore(encode(&msg).map(|msg|self.connection_manager.send(peer_endpoint, msg)));
                },
                None => {}
            };
        }
    }

    fn send_swarm_or_parallel_or_relay(&self, dst : &DestinationAddress, msg: &Message) {
        if dst.non_relayed_destination() == self.own_name {
            match dst {
                DestinationAddress::RelayToClient(_, public_key) => {
                    self.send_out_as_relay(&public_key, serialised_msg.clone());
                },
                DestinationAddress::RelayToNode(_, node_address) => {
                    self.send_out_as_relay(&node_address, serialised_msg.clone());
                },
                DestinationAddress::Direct(_) => {},
            }
        }
        else {
            send_swarm_or_parallel(dst.non_relayed_destination(), msg);
        }
    }

    fn send_connect_request_msg(&mut self, peer_id: &NameType) -> RoutingResult {
        let routing_msg = self.construct_connect_request_msg(&peer_id);
        let serialised_message = try!(encode(&routing_msg));
        match self.routing_table.size() > 0 {
            true => {
                self.send_swarm_or_parallel(peer_id, &serialised_message);
                Ok(()) },
            false => match self.bootstrap_endpoint.clone() {
                Some(ref bootstrap_endpoint) => {
                    match self.connection_manager.send(bootstrap_endpoint.clone(),
                    serialised_message) {
                        Ok(_) => Ok(()),
                        Err(e) => Err(RoutingError::Io(e))
                    }},
                None => Err(RoutingError::FailedToBootstrap)
            }
        }
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
                                println!("RT (size : {:?}) refused connection on {:?} as {:?}
                                    from routing table.", self.routing_table.size(),
                                    endpoint, i_am.public_id.name());
                                self.relay_map.remove_unknown_connection(&endpoint);
                                self.connection_manager.drop_node(endpoint);
                                return Err(RoutingError::RefusedFromRoutingTable); }
                            println!("RT (size : {:?}) added connected node {:?} on {:?}",
                                self.routing_table.size(), peer_node_info.fob.name(), endpoint);
                            trigger_handle_churn = self.routing_table
                                .address_in_our_close_group_range(&peer_node_info.fob.name());
                        } else {
                            println!("I Am, relocated name {:?} conflicted with cached fob.",
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
                                    println!("RT (size : {:?}) refused connection on {:?} as {:?}
                                        from routing table.", self.routing_table.size(),
                                        endpoint, i_am.public_id.name());
                                    self.relay_map.remove_unknown_connection(&endpoint);
                                    self.connection_manager.drop_node(endpoint);
                                    return Err(RoutingError::RefusedFromRoutingTable); }
                                println!("RT (size : {:?}) added connected node {:?} on {:?}",
                                    self.routing_table.size(), peer_node_info.fob.name(), endpoint);
                                trigger_handle_churn = self.routing_table
                                    .address_in_our_close_group_range(&peer_node_info.fob.name());
                            },
                            false => {
                                println!("Dropping connection on {:?} as {:?} is relocated,
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
                println!("I Am unrelocated {:?} on {:?}. Not Acting on this result.",
                    i_am.public_id.name(), endpoint);
            }
        };
        if trigger_handle_churn {
            println!("Handle CHURN new node {:?}", i_am.public_id.name());
            let mut close_group : Vec<NameType> = self.routing_table
                    .our_close_group().iter()
                    .map(|node_info| node_info.fob.name())
                    .collect::<Vec<NameType>>();
            close_group.insert(0, self.own_name.clone());
            let churn_actions = self.mut_interface().handle_churn(close_group);
            for action in churn_actions {
                match action {
                    MethodCall::Put { destination: x, content: y, } => self.put(x, y),
                    MethodCall::Get { type_id: x, name: y, } => self.get(x, y),
                    MethodCall::Refresh { type_tag, from_group, payload } => self.refresh(type_tag, from_group, payload),
                    MethodCall::Post => unimplemented!(),
                    MethodCall::None => (),
                    MethodCall::SendOn { destination } =>
                        println!("IGNORED: on handle_churn MethodCall:SendOn {} is not a Valid action", destination)
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
        let mut clear_bootstrap = false;
        match self.bootstrap_endpoint {
            Some(ref connected_bootstrap_endpoint) => {
                if self.routing_table.size() > 0 {
                    println!("Dropped bootstrap on {:?}", connected_bootstrap_endpoint);
                    self.connection_manager.drop_node(connected_bootstrap_endpoint.clone());
                    clear_bootstrap = true;
                }
            },
            None => {}
        };
        if clear_bootstrap { self.bootstrap_endpoint = None; }
    }

    fn address_in_close_group_range(&self, address: &NameType) -> bool {
        if self.routing_table.size() < RoutingTable::get_group_size() {
            return true;
        }

        match self.routing_table.our_close_group().last() {
            Some(furthest_close_node) => {
                closer_to_target_or_equal(&address, &furthest_close_node.id(), &self.own_name)
            },
            None => false  // ...should never reach here
        }
    }

    fn our_source_address(&mut self, from_group: Option<NameType>) -> types::SourceAddress {
        types::SourceAddress{ from_node: self.own_name.clone(),
                              from_group: from_group,
                              reply_to: None,
                              relayed_for: None
        }
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
                // check to see if it is our bootstrap_endpoint
                None => match self.bootstrap_endpoint {
                    Some(ref our_bootstrap) => {
                        if our_bootstrap == endpoint {
                            Some(ConnectionName::OurBootstrap)
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
    fn handle_put_data(&mut self, message: RoutingMessage) -> RoutingResult {
        let data = match message.message_type {
            MessageType::PutData(put_data) => put_data,
            _ => Err(InterfaceError::Abort), // To be changed to Parse error
        };
        let our_authority = our_authority(data.name, &message, &self.routing_table);
        let from_authority = message.authority();
        let from = message.source;
        let to = header.send_to();

        match self.mut_interface().handle_put(our_authority.clone(), from_authority, from, to, message.data) {
            Ok(action) => match action {
                MessageAction::Reply(reply_data) => {
                    // different pattern to accommodate for "PUT reply only from CM goes to client"
                    // FIXME: such a different pattern needs to be activated for disabling PutResponse
                    //        can be revised an handled better at different places in code
                    // let reply_to = match our_authority {
                    //     Authority::ClientManager => match header.reply_to() {
                    //         Some(client) => client,
                    //         None => header.from()
                    //     },
                    //     _ => header.from()
                    // };
                    try!(self.send_reply(&message, our_authority.clone(), Ok(reply_data)));
                },
                MessageAction::SendOn(destinations) => {
                    for destination in destinations {
                        ignore(self.send_on(&data.name, &message, destination, data.clone()));
                    }
                },
            },
            Err(InterfaceError::Abort) => {},
            Err(InterfaceError::Response(ResponseError::FailedToStoreData(_))) => {
                try!(self.send_reply(&message, our_authority.clone(),
                        Err(ResponseError::FailedToStoreData(data))));
            },
            Err(InterfaceError::Response(error)) => {
                try!(self.send_reply(&message, our_authority.clone(), Err(error)));
            }
        }
        Ok(())
    }

    fn send_reply(&mut self, routing_message: &RoutingMessage, our_authority: Authority,
                  reply_data: Result<Data, ResponseError>) -> RoutingResult {
        let message = routing_message.create_reply(self.own_name(), our_authority);
        message.message_type = reply_data;
        message.authority = our_authority;

        let encoded_routing_message = encode(&message);
        let signature = sign_detached(&message, &self.id.secret_keys.0);

        let signed_message = Message::SignedRoutingMessage(SignedRoutingMessage {
            encoded_routing_message : encoded_routing_message,
            signature               : signature,
        });

        let serialised_msg = try!(encode(&signed_message));
        self.send_swarm_or_parallel_or_relay(&message.destination, &serialised_msg);
        Ok(())
    }

    fn handle_put_data_response(&mut self, message: RoutingMessage) -> RoutingResult {
        println!("Handle PUT data response.");
        let put_response = match message.message_type {
            MessageType::PutDataResponse(response) => response,
            _ => Err(InterfaceError::Abort), // To be changed to Parse error
        };
        let our_authority = our_authority(put_response.name(), &message, &self.routing_table);
        let from_authority = message.authority();
        let from = message.source;
        let to = header.send_to();

        let method_call = self.mut_interface().handle_put_response(from_authority, from, put_response);

        match method_call {
            MethodCall::Put { destination: x, content: y, } => self.put(x, y),
            MethodCall::Get { type_id: x, name: y, } => self.get(x, y),
            MethodCall::Refresh { type_tag, from_group, payload } => self.refresh(type_tag, from_group, payload),
            MethodCall::Post => unimplemented!(),
            MethodCall::None => (),
            MethodCall::SendOn { destination } =>
                ignore(self.send_on(&message, our_authority, destination)),
        }
        Ok(())
    }

    fn handle_connect_request(&mut self, body: Bytes, signature: Signature) -> RoutingResult {
        let connect_request = try!(decode::<ConnectRequest>(&body));
        if !connect_request.requester_fob.is_relocated() {
            return Err(RoutingError::RejectedPublicId); }
        // first verify that the message is correctly self-signed
        if !verify_detached(&signature,
                            &body[..], &connect_request.requester_fob.public_sign_key
                                                       .get_crypto_public_sign_key()) {
            return Err(RoutingError::Response(ResponseError::InvalidRequest));
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
                    println!("RT (size : {:?}) added {:?} ", self.routing_table.size(), peer_node_info.fob.name());
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
                            if dest == self.own_name
                                && self.relay_map.contains_relay_for(&relay) {
                                println!("Sending ConnectResponse directly to relay {:?}", relay);
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

    fn handle_refresh(&mut self, header: MessageHeader, body: Bytes) -> RoutingResult {
        let refresh = try!(decode::<Refresh>(&body));
        let from_group = try!(header.from_group().ok_or(RoutingError::RefreshNotFromGroup));
        if from_group != refresh.from_group {
            return Err(RoutingError::BadAuthority);
        }
        let our_authority = our_authority(from_group, &header, &self.routing_table);
        if our_authority != Authority::OurCloseGroup(from_group) {
            return Err(RoutingError::BadAuthority);
        }
        let threshold = (self.routing_table.size() as f32) * 0.8; // 80% chosen arbitrary
        let opt_payloads = self.refresh_accumulator.add_message(threshold as usize,
                                                                refresh.type_tag,
                                                                header.from_node(),
                                                                from_group.clone(),
                                                                refresh.payload);
        let type_tag = refresh.type_tag;
        opt_payloads.map(|payloads| {
            self.mut_interface().handle_refresh(type_tag, from_group, payloads);
        });
        Ok(())
    }

    fn handle_connect_response(&mut self, body: Bytes) -> RoutingResult {
        let connect_response = try!(decode::<ConnectResponse>(&body));

        // Verify a connect request was initiated by us.
        let connect_request = try!(decode::<ConnectRequest>(&connect_response.serialised_connect_request));
        if connect_request.requester_id != self.id.get_name() ||
           !verify_detached(&connect_response.connect_request_signature,
                            &connect_response.serialised_connect_request[..],
                            &self.id.get_crypto_public_sign_key()) {
            return Err(RoutingError::Response(ResponseError::InvalidRequest));
        }
        // double check if fob is relocated;
        // this should be okay as we check this before sending out a connect_request
        if !connect_response.receiver_fob.is_relocated() {
            return Err(RoutingError::RejectedPublicId); }
        // Collect the local and external endpoints into a single vector to construct a NodeInfo
        let mut peer_endpoints = connect_response.receiver_local_endpoints.clone();
        peer_endpoints.extend(connect_response.receiver_external_endpoints.clone().into_iter());
  // println!("ConnectResponse from {:?}",  )
  // for peer in peer_endpoint {
  //     println!("")
  // }
        let peer_node_info =
            NodeInfo::new(connect_response.receiver_fob.clone(), peer_endpoints, None);

        // Try to add to the routing table.  If unsuccessful, no need to continue.
        let (added, _) = self.routing_table.add_node(peer_node_info.clone());
        if !added {
           return Err(RoutingError::RefusedFromRoutingTable); }
        println!("RT (size : {:?}) added {:?} on connect response", self.routing_table.size(),
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
    fn handle_put_public_id(&mut self, header: MessageHeader, body: Bytes) -> RoutingResult {
        let put_public_id = try!(decode::<MessageType::PutPublicId>(&body));
        let our_authority = our_authority(put_public_id.public_id.name(), &header, &self.routing_table);
        match (header.from_authority(), our_authority.clone(), put_public_id.public_id.is_relocated()) {
            (Authority::ManagedNode, Authority::NaeManager(_), false) => {
                let mut put_public_id_relocated = put_public_id.clone();

                // FIXME: we should add ourselves
                let mut close_group : Vec<NameType> =
                    self.routing_table.our_close_group().into_iter()
                    .map(|node_info| node_info.id())
                    .collect::<Vec<NameType>>();
                close_group.insert(0, self.own_name.clone());
                let relocated_name = try!(utils::calculate_relocated_name(
                    close_group, &put_public_id.public_id.name()));
                // assign_relocated_name
                put_public_id_relocated.public_id.assign_relocated_name(relocated_name.clone());

                println!("RELOCATED {:?} to {:?}",
                    put_public_id.public_id.name(), relocated_name);
                // SendOn to relocated_name group, which will actually store the relocated public id
                try!(self.send_on(&put_public_id.public_id.name(),
                                  &header,
                                  relocated_name,
                                  MessageType::PutPublicId,
                                  put_public_id_relocated));
                Ok(())
            },
            (Authority::NaeManager(_), Authority::NaeManager(_), true) => {
                // Note: The "if" check is workaround for absense of sentinel. This avoids redundant PutPublicIdResponse responses.
                if !self.public_id_cache.contains_key(&put_public_id.public_id.name()) {
                  self.public_id_cache.add(put_public_id.public_id.name(), put_public_id.public_id.clone());
                  println!("CACHED RELOCATED {:?}",
                      put_public_id.public_id.name());
                  // Reply with PutPublicIdResponse to the reply_to address
                  let reply_header = header.create_reply(&self.own_name, &our_authority);
                  let destination = reply_header.destination.dest.clone();
                  let routing_msg = RoutingMessage::new(MessageType::PutPublicIdResponse,
                                                        reply_header,
                                                        PutPublicIdResponse{ public_id :put_public_id.public_id.clone() },
                                                        &self.id.get_crypto_secret_sign_key());
                  let encoded_msg = try!(encode(&routing_msg));

                  // intercept if we can relay it directly
                  match (routing_msg.message_header.destination.dest.clone(),
                      routing_msg.message_header.destination.relay_to.clone()) {
                      (dest, Some(relay)) => {
                          // if we should directly respond to this message, do so
                          if dest == self.own_name
                              && self.relay_map.contains_relay_for(&relay) {
                              self.send_out_as_relay(&relay, encoded_msg);
                              return Ok(());
                          }
                      },
                      _ => {}
                  };

                  // Send this to the relay node as specified in the reply_header
                  self.send_swarm_or_parallel(&destination, &encoded_msg);
                }
                Ok(())
            },
            _ => {
                Err(RoutingError::BadAuthority)
            }
        }
    }

    fn handle_find_group(&mut self, original_header: MessageHeader, body: Bytes) -> RoutingResult {
        let find_group = try!(decode::<MessageType::FindGroup>(&body));
        let group = self.routing_table.our_close_group().into_iter()
                    .map(|x|x.fob)
                    // add ourselves
                    .chain(Some(PublicId::new(&self.id)).into_iter())
                    .collect::<Vec<_>>();

        let routing_response = self.construct_find_group_response_msg(&original_header, &find_group, group);

        let serialised_response = try!(encode(&routing_response));

        self.send_swarm_or_parallel_or_relay(&routing_response.destination, &serialised_response);

        Ok(())
    }

    fn handle_find_group_response(&mut self,
                                  body: Bytes,
                                  refresh_our_own_group: &bool) -> RoutingResult {
        let find_group_response = try!(decode::<MessageType::FindGroupResponse>(&body));
        for peer in find_group_response.group {
            self.refresh_routing_table(&peer.name());
        }
        if *refresh_our_own_group {
            let our_name = self.own_name.clone();
            if !self.connection_cache.contains_key(&our_name) {
                let find_group_msg = self.construct_find_group_msg(&our_name);
                let serialised_msg = try!(encode(&find_group_msg));
                println!("REFLECT OUR GROUP");
                self.send_swarm_or_parallel(&our_name, &serialised_msg);
                self.connection_cache.entry(our_name)
                    .or_insert(SteadyTime::now());
            }
        }
        Ok(())
    }

    fn handle_get_data(&mut self, message: RoutingMessage) -> RoutingResult {
        let data_request = match message.message_type {
            GetData(request) => request,
            _ => Err(InterfaceError::Abort), // To be changed to Parse error
        };
        let our_authority = our_authority(&message, &self.routing_table);
        let from_authority = message.authority();
        let from = header.source();

        match self.mut_interface().handle_get(data_request, our_authority.clone(), from_authority, from) {
            Ok(action) => match action {
                MessageAction::Reply(data) => {
                    self.send_reply(message, our_authority, GetDataResponse(Ok(data)));
                },
                MessageAction::SendOn(dest_nodes) => {
                    for destination in dest_nodes {
                        ignore(self.send_on(message, our_authority, destination));
                    }
                }
            },
            Err(InterfaceError::Abort) => {;},
            Err(InterfaceError::Response(error)) => {
                self.send_reply(message, our_authority, GetDataResponse(Err(error)));
            }
        }
        Ok(())
    }

    fn send_on<T>(&self,
                  name: &NameType,
                  orig_header: &MessageHeader,
                  destination: NameType,
                  tag: MessageType,
                  body: T) -> RoutingResult
        where T: Encodable + Decodable
    {
        let our_authority = our_authority(name.clone(), &orig_header, &self.routing_table);
        let header = orig_header.create_send_on(&self.own_name, &our_authority, &destination);
        let msg = RoutingMessage::new(tag, header, body, &self.id.get_crypto_secret_sign_key());
        self.send_swarm_or_parallel(&destination, &try!(encode(&msg)));
        Ok(())
    }

    fn handle_get_data_response(&mut self, message: RoutingMessage) -> RoutingResult {
        let get_response = match message.message_type {
            MessageType::GetData(response) => response,
            _ => Err(InterfaceError::Abort), // To be changed to Parse error
        };
        let our_authority = our_authority(&message, &self.routing_table);
        let from_authority = message.authority();
        let from = header.source();

        match self.mut_interface().handle_get_response(from, get_response) {
            MethodCall::Put { destination: x, content: y, } => self.put(x, y),
            MethodCall::Get { type_id: x, name: y, } => self.get(x, y),
            MethodCall::Refresh { type_tag, from_group, payload } => self.refresh(type_tag, from_group, payload),
            MethodCall::Post => unimplemented!(),
            MethodCall::None => (),
            MethodCall::SendOn { destination } =>
                ignore(self.send_on(message, our_authority, destination)),
        }
        Ok(())
    }

    ///  Only use this handler if we have a self-relocated id, and our routing table is empty
    // FIXME: we can (very likely) completely drop this special case; in relay_message_received
    // just treat this PutPublicId as any other message, but in the normal handlers for PutPublicId,
    // also add our own name.
    fn handle_put_public_id_zero_node(&mut self, header: MessageHeader, body: Bytes,
        send_to: &Endpoint) -> RoutingResult {
        println!("FIRST NODE BOOSTRAPS OFF OF ZERO NODE");
        let put_public_id = try!(decode::<MessageType::PutPublicId>(&body));
        if put_public_id.public_id.is_relocated() {
            return Err(RoutingError::RejectedPublicId); }
        let mut relocated_public_id = put_public_id.public_id.clone();

        let relocated_name =  try!(utils::calculate_relocated_name(
                                    vec![self.own_name.clone()],
                                    &put_public_id.public_id.name()));
        // assign_relocated_name
        relocated_public_id.assign_relocated_name(relocated_name.clone());

        if !self.public_id_cache.contains_key(&relocated_name) {
            self.public_id_cache.add(relocated_name, relocated_public_id.clone());
            // Reply with PutPublicIdResponse to the reply_to address
            let reply_header = header.create_reply(&self.own_name, &Authority::NaeManager(self.own_name.clone()));
            let routing_msg = RoutingMessage::new(MessageType::PutPublicIdResponse,
                                                  reply_header,
                                                  PutPublicIdResponse {
                                                      public_id: relocated_public_id },
                                                  &self.id.get_crypto_secret_sign_key());
            let encoded_msg = try!(encode(&routing_msg));
            // Send this directly back to the bootstrapping node
            match self.connection_manager.send(send_to.clone(), encoded_msg) {
                Ok(_) => Ok(()),
                Err(e) => Err(RoutingError::Io(e))
            }
        } else { Err(RoutingError::RejectedPublicId) }
    }

    // -----Message Constructors-----------------------------------------------

    fn construct_find_group_response_msg(&mut self, original_header : &MessageHeader,
                                         find_group: &FindGroup,
                                         group: Vec<types::PublicId>) -> RoutingMessage {

        let header = MessageHeader::new(original_header.message_id(),
                                        original_header.send_to(),
                                        self.our_source_address(Some(find_group.target_id.clone())),
                                        Authority::NaeManager(find_group.target_id.clone()));

        RoutingMessage::new(MessageType::FindGroupResponse,
                            header,
                            FindGroupResponse{ group: group },
                            &self.id.get_crypto_secret_sign_key())
    }

    fn construct_connect_request_msg(&mut self, peer_id: &NameType) -> RoutingMessage {
        let header = MessageHeader::new(self.get_next_message_id(),
            types::DestinationAddress {dest: peer_id.clone(), relay_to: None },
            self.our_source_address(None), Authority::ManagedNode);

        // FIXME: We're sending all accepting connections as local since we don't differentiate
        // between local and external yet.
        let connect_request = ConnectRequest {
            local_endpoints: self.accepting_on.clone(),
            external_endpoints: vec![],
            requester_id: self.own_name.clone(),
            receiver_id: peer_id.clone(),
            requester_fob: types::PublicId::new(&self.id),
        };

        RoutingMessage::new(MessageType::ConnectRequest, header, connect_request,
            &self.id.get_crypto_secret_sign_key())
    }

    fn construct_get_data_response_msg(&self,
                                       our_authority: Authority,
                                       orig_header: &MessageHeader,
                                       orig_message: GetData,
                                       reply_data: Result<Vec<u8>, ResponseError>) -> RoutingMessage {
        RoutingMessage::new(MessageType::GetDataResponse,
                            orig_header.create_reply(&self.own_name, &our_authority),
                            GetDataResponse{ name_and_type_id: orig_message.name_and_type_id,
                                             data: reply_data },
                            &self.id.get_crypto_secret_sign_key())
    }

    fn construct_find_group_msg(&mut self, node : &NameType) -> Message {
        let message_id = self.get_next_message_id();
        let message = RoutingMessage {
            destination : DestinationAddress::Direct(self.own_name.clone()),
            source      : SourceAddress::Direct(self.own_name.clone()),
            message_type: MessageType::FindGroup(node.clone()),
            message_id  : message_id.clone(),
            authority   : Authority::ManagedNode,
        };

        SignedRoutingMessage::new(message, &self.id.secret_key.0)
    }

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

fn ignore<R,E>(_restul: Result<R,E>) {}

#[cfg(test)]
mod test {

use super::*;
use super::encode;
use super::ConnectionName;
use authority::Authority;
use cbor::{Encoder};
use crust;
use error::{ResponseError, InterfaceError};
use messages::{RoutingMessage, MessageType};
use message_header::MessageHeader;
use messages::get_data::GetData;
use messages::get_data_response::GetDataResponse;
use messages::get_client_key::GetKey;
use messages::post::Post;
use messages::put_data::PutData;
use messages::put_data_response::PutDataResponse;
use messages::put_public_id::PutPublicId;
use messages::refresh::Refresh;
use name_type::{NameType, closer_to_target};
use node_interface::{Interface, MethodCall};
use rand::{random, Rng, thread_rng};
use routing_table;
use rustc_serialize::{Encodable, Decodable};
use sendable::Sendable;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use test_utils::{Random, random_endpoint, random_endpoints};
use types;
use types::{DestinationAddress, Id, MessageAction, PublicId};

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

struct TestData {
    data: Vec<u8>
}

impl TestData {
    fn new(in_data: Vec<u8>) -> TestData {
        TestData { data: in_data }
    }
}

struct TestInterface {
    stats: Arc<Mutex<Stats>>
}

impl Sendable for TestData {
    fn name(&self) -> NameType { Random::generate_random() }
    fn type_tag(&self)->u64 { unimplemented!() }
    fn serialised_contents(&self)->Vec<u8> { self.data.clone() }
    fn refresh(&self)->bool { false }
    fn merge(&self, _responses: Vec<Box<Sendable>>) -> Option<Box<Sendable>> { None }
}

impl Interface for TestInterface {
    fn handle_get(&mut self, _type_id: u64, _name : NameType, _our_authority: Authority,
                  _from_authority: Authority, _from_address: NameType) -> Result<MessageAction, InterfaceError> {
        let stats = self.stats.clone();
        let mut stats_value = stats.lock().unwrap();
        stats_value.call_count += 1;
        Ok(MessageAction::Reply("handle_get called".to_string().into_bytes()))
    }

    fn handle_put(&mut self, _our_authority: Authority, from_authority: Authority,
                _from_address: NameType, _dest_address: DestinationAddress,
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

    fn handle_refresh(&mut self, type_tag: u64, _from_group: NameType, payloads: Vec<Vec<u8>>) {
        let stats = self.stats.clone();
        let mut stats_value = stats.lock().unwrap();
        stats_value.call_count += type_tag as usize;
        stats_value.data = payloads[0].clone();
    }

    fn handle_post(&mut self, _our_authority: Authority, _from_authority: Authority,
                   _from_address: NameType, _name: NameType, data: Vec<u8>) -> Result<MessageAction, InterfaceError> {
        let stats = self.stats.clone();
        let mut stats_value = stats.lock().unwrap();
        stats_value.call_count += 1;
        stats_value.data = data.clone();
        Ok(MessageAction::Reply(data))
    }

    fn handle_get_response(&mut self, _from_address: NameType, _response: Result<Vec<u8>,
                           ResponseError>) -> MethodCall {
        let stats = self.stats.clone();
        let mut stats_value = stats.lock().unwrap();
        stats_value.call_count += 1;
        stats_value.data = "handle_get_response called".to_string().into_bytes();
        MethodCall::None
    }

    fn handle_put_response(&mut self, _from_authority: Authority, _from_address: NameType,
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

    fn handle_post_response(&mut self, _from_authority: Authority, _from_address: NameType,
                            _response: Result<Vec<u8>, ResponseError>) {
        unimplemented!();
    }

    fn handle_churn(&mut self, _close_group: Vec<NameType>)
        -> Vec<MethodCall> {
        unimplemented!();
    }

    fn handle_cache_get(&mut self, _type_id: u64, _name : NameType, _from_authority: Authority,
                        _from_address: NameType) -> Result<MessageAction, InterfaceError> {
        Err(InterfaceError::Abort)
    }

    fn handle_cache_put(&mut self, _from_authority: Authority, _from_address: NameType,
                        _data: Vec<u8>) -> Result<MessageAction, InterfaceError> {
        Err(InterfaceError::Abort)
    }
}

fn create_mmebrane(stats: Arc<Mutex<Stats>>) -> RoutingMembrane<TestInterface> {
    let mut id = Id::new();
    let (event_output, event_input) = mpsc::channel();
    let mut cm = crust::ConnectionManager::new(event_output);
    let ports_and_protocols : Vec<crust::Port> = Vec::new();
    let beacon_port = Some(5483u16);
    let listeners = match cm.start_listening2(ports_and_protocols, beacon_port) {
        Err(reason) => {
            println!("Failed to start listening: {:?}", reason);
            (vec![], None)
        }
        Ok(listeners_and_beacon) => listeners_and_beacon
    };

    let self_relocated_name = types::calculate_self_relocated_name(
        &id.get_crypto_public_sign_key(),
        &id.get_crypto_public_key(),
        &id.get_validation_token());
    id.assign_relocated_name(self_relocated_name);
    RoutingMembrane::<TestInterface>::new(cm, event_input, None, listeners.0, id.clone(), TestInterface {stats : stats})
}

fn call_operation<T>(operation: T, message_type: MessageType, stats: Arc<Mutex<Stats>>,
                     authority: Authority, from_group: Option<NameType>,
                     destination: Option<NameType>) -> Stats where T: Encodable, T: Decodable {
    let mut membrane = create_mmebrane(stats.clone());
    let header = MessageHeader {
        message_id:  membrane.get_next_message_id(),
        destination: types::DestinationAddress { dest: match destination { Some(dest) => dest, None => membrane.own_name.clone() }, relay_to: None },
        source: types::SourceAddress { from_node: Random::generate_random(),
             from_group: from_group, reply_to: None, relayed_for: None },
        authority: authority };

    let message = RoutingMessage::new( message_type, header.clone(), operation, &membrane.id.get_crypto_secret_sign_key());
    let serialised_msssage = encode(&message).unwrap();
    let connection_name = ConnectionName::Routing(header.source.from_node);
    let _ = membrane.message_received(&connection_name, serialised_msssage, false);
    let stats = stats.clone();
    let stats_value = stats.lock().unwrap();
    stats_value.clone()
}

fn populate_routing_node() -> RoutingMembrane<TestInterface> {
    let stats = Arc::new(Mutex::new(Stats::new()));
    let mut membrane = create_mmebrane(stats);

    let mut count : usize = 0;
    loop {
        membrane.routing_table.add_node(routing_table::NodeInfo::new(
                                        PublicId::new(&Id::new()), random_endpoints(),
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
        let mut membrane = create_mmebrane(Arc::new(Mutex::new(Stats::new())));
        assert_eq!(membrane.get_next_message_id() + 1, membrane.get_next_message_id());
    }

#[test]
#[ignore]
    fn call_handle_get_key() {
        let stats = Arc::new(Mutex::new(Stats::new()));
        let get_key: GetKey = Random::generate_random();
        let public_key: types::PublicSignKey = Random::generate_random();
        let mut enc = Encoder::from_memory();
        let _ = enc.encode(&[public_key]);
        stats.lock().unwrap().data = enc.into_bytes();
        assert_eq!(call_operation(get_key, MessageType::GetKey, stats, Authority::NaeManager(Random::generate_random()), None, None).call_count, 1usize);
    }

#[test]
    fn call_put() {
        let mut array = [0u8; 64];
        thread_rng().fill_bytes(&mut array);
        let chunk = Box::new(TestData::new(array.into_iter().map(|&value| value).collect::<Vec<_>>()));
        let mut membrane = create_mmebrane(Arc::new(Mutex::new(Stats::new())));
        let name: NameType = Random::generate_random();
        membrane.put(name, chunk);
    }

#[test]
    fn call_get() {
        let mut membrane = create_mmebrane(Arc::new(Mutex::new(Stats::new())));
        let name: NameType = Random::generate_random();
        membrane.get(100u64, name);
    }

#[test]
    fn call_unauthorised_put() {
        let mut array = [0u8; 64];
        thread_rng().fill_bytes(&mut array);
        let chunk = Box::new(TestData::new(array.into_iter().map(|&value| value).collect::<Vec<_>>()));
        let mut membrane = create_mmebrane(Arc::new(Mutex::new(Stats::new())));
        let name: NameType = Random::generate_random();
        membrane.unauthorised_put(name, chunk);
    }

#[test]
    fn call_refresh() {
        let mut array = [0u8; 64];
        thread_rng().fill_bytes(&mut array);
        let content = array.into_iter().map(|&value| value).collect::<Vec<_>>();
        let mut membrane = create_mmebrane(Arc::new(Mutex::new(Stats::new())));
        let name: NameType = Random::generate_random();
        membrane.refresh(100u64, name, content);
    }

#[test]
    fn call_handle_put() {
        let put_data: PutData = Random::generate_random();
        assert_eq!(call_operation(put_data,
            MessageType::PutData, Arc::new(Mutex::new(Stats::new())),
            Authority::NaeManager(Random::generate_random()), None, None).call_count, 1usize);
    }

#[test]
#[ignore]
    fn call_handle_authorised_put() {
        let unauthorised_put: PutData = Random::generate_random();
        let result_stats = call_operation(unauthorised_put, MessageType::UnauthorisedPut,
             Arc::new(Mutex::new(Stats::new())), Authority::Unknown, None, None);
        assert_eq!(result_stats.call_count, 1usize);
        assert_eq!(result_stats.data, "UnauthorisedPut".to_string().into_bytes());
    }

#[test]
    fn call_handle_put_response() {
        let put_data_response: PutDataResponse = Random::generate_random();
        assert_eq!(call_operation(put_data_response, MessageType::PutDataResponse,
             Arc::new(Mutex::new(Stats::new())), Authority::NaeManager(Random::generate_random()), None, None).call_count, 1usize);
    }

#[test]
    fn call_handle_get_data() {
        let get_data: GetData = Random::generate_random();
        assert_eq!(call_operation(get_data, MessageType::GetData,
            Arc::new(Mutex::new(Stats::new())), Authority::NaeManager(Random::generate_random()), None, None).call_count, 1usize);
    }

#[test]
    fn call_handle_get_data_response() {
        let get_data: GetDataResponse = Random::generate_random();
        assert_eq!(call_operation(get_data, MessageType::GetDataResponse,
            Arc::new(Mutex::new(Stats::new())), Authority::NaeManager(Random::generate_random()), None, None).call_count, 1usize);
    }

#[test]
#[ignore]
    fn call_handle_post() {
        let post: Post = Random::generate_random();
        assert_eq!(call_operation(post, MessageType::Post, Arc::new(Mutex::new(Stats::new())),
                   Authority::NaeManager(Random::generate_random()), None, None).call_count, 1usize);
    }

#[test]
    fn call_handle_refresh() {
        let refresh: Refresh = Random::generate_random();
        assert_eq!(call_operation(refresh.clone(), MessageType::Refresh,
            Arc::new(Mutex::new(Stats::new())), Authority::OurCloseGroup(Random::generate_random()),
            Some(refresh.from_group.clone()), Some(refresh.from_group)).call_count, refresh.type_tag as usize);
    }

#[test]
    fn relocate_original_public_id() {
        let mut routing_node = populate_routing_node();
        let furthest_closest_node = routing_node.routing_table.our_close_group().last().unwrap().id();
        let our_name = routing_node.own_name.clone();
        let total_inside : u32 = 5;
        let limit_attempts : u32 = 300;
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
        let total_inside : u32 = 5;
        let limit_attempts : u32 = 300;
        let mut stored_public_ids : Vec<PublicId> = Vec::with_capacity(total_inside as usize);
        let mut count_inside : u32 = 0;
        let mut count_total : u32 = 0;
        loop {
            let original_public_id = PublicId::generate_random();
            let mut close_nodes_to_original_name : Vec<NameType> = Vec::new();
            for _ in 0..types::GROUP_SIZE {
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
                authority : Authority::NaeManager(Random::generate_random())
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
}
