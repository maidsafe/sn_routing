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

use std::sync::mpsc;
use std::thread::spawn;
use std::collections::BTreeMap;
use sodiumoxide::crypto::sign::{verify_detached, Signature};
use sodiumoxide::crypto::sign;
use sodiumoxide::crypto;
use time::{Duration, SteadyTime};

use crust;
use crust::{ConnectionManager, Endpoint};
use lru_time_cache::LruCache;

use action::Action;
use event::Event;
use NameType;
use name_type::{closer_to_target_or_equal};
use routing_core::{RoutingCore, ConnectionName};
use id::Id;
use public_id::PublicId;
use hello::Hello;
use types;
use types::{MessageId, Bytes, Address};
use utils::{encode, decode};
use utils;
use data::{Data, DataRequest};
use authority::{Authority, our_authority};
use std::cmp::min;

use messages::{RoutingMessage,
               SignedMessage, SignedToken,
               ConnectRequest,
               ConnectResponse,
               Content,
               ExternalRequest, ExternalResponse,
               InternalRequest, InternalResponse };

use error::{RoutingError, ResponseError};
use refresh_accumulator::RefreshAccumulator;
use message_filter::MessageFilter;
use message_accumulator::MessageAccumulator;


type RoutingResult = Result<(), RoutingError>;

static MAX_BOOTSTRAP_CONNECTIONS : usize = 1;

/// Routing Node
pub struct RoutingNode {
    // for CRUST
    crust_receiver      : mpsc::Receiver<crust::Event>,
    connection_manager  : crust::ConnectionManager,
    accepting_on        : Vec<crust::Endpoint>,
    // for RoutingNode
    client_restriction  : bool,
    action_sender       : mpsc::Sender<Action>,
    action_receiver     : mpsc::Receiver<Action>,
    event_sender        : mpsc::Sender<Event>,
    filter              : MessageFilter<types::FilterType>,
    core                : RoutingCore,
    public_id_cache     : LruCache<NameType, PublicId>,
    connection_cache    : BTreeMap<NameType, SteadyTime>,
    accumulator         : MessageAccumulator,
    // refresh_accumulator : RefreshAccumulator,
}

impl RoutingNode {
    pub fn new(action_sender      : mpsc::Sender<Action>,
               action_receiver    : mpsc::Receiver<Action>,
               event_sender       : mpsc::Sender<Event>,
               client_restriction : bool) -> RoutingNode {

        let (crust_sender, crust_receiver) = mpsc::channel::<crust::Event>();
        let mut cm = crust::ConnectionManager::new(crust_sender);
        let _ = cm.start_accepting(vec![]);
        let accepting_on = cm.get_own_endpoints();

        RoutingNode {
            crust_receiver      : crust_receiver,
            connection_manager  : cm,
            accepting_on        : accepting_on,
            client_restriction  : client_restriction,
            action_sender       : action_sender,
            action_receiver     : action_receiver,
            event_sender        : event_sender.clone(),
            filter              : MessageFilter::with_expiry_duration(Duration::minutes(20)),
            core                : RoutingCore::new(event_sender),
            public_id_cache     : LruCache::with_expiry_duration(Duration::minutes(10)),
            connection_cache    : BTreeMap::new(),
            accumulator         : MessageAccumulator::new(),
        }
    }

    pub fn run(&mut self) {
        loop {
            match self.crust_receiver.recv() {
                Err(_) => {},
                Ok(crust::Event::NewMessage(endpoint, bytes)) => {
                    match decode::<SignedMessage>(&bytes) {
                        Ok(message) => {
                            // handle SignedMessage for any identified endpoint
                            match self.core.lookup_endpoint(&endpoint) {
                                Some(ConnectionName::Unidentified(_, _)) => {},
                                None => {},
                                _ => ignore(self.message_received(message)),
                            };
                        },
                        // The message received is not a Signed Routing Message,
                        // expect it to be an Hello message to identify a connection
                        Err(_) => {
                            let _ = self.handle_hello(&endpoint, bytes);
                        },
                    }
                },
                Ok(crust::Event::NewConnection(endpoint)) => {
                    self.handle_new_connection(endpoint);
                },
                Ok(crust::Event::LostConnection(endpoint)) => {
                    self.handle_lost_connection(endpoint);
                },
                Ok(crust::Event::NewBootstrapConnection(endpoint)) => {
                    self.handle_new_bootstrap_connection(endpoint);
                }
            };
            match self.action_receiver.try_recv() {
                Err(_) => {},
                Ok(Action::SendMessage(signed_message)) => {

                },
                Ok(Action::SendContent(to_authority, content)) => {

                },
                Ok(Action::Terminate) => {

                },
            }
        }
    }

    /// When CRUST receives a connect to our listening port and establishes a new connection,
    /// the endpoint is given here as new connection
    fn handle_new_connection(&mut self, endpoint : Endpoint) {
        // only accept new connections if we are a full node
        let has_bootstrap_endpoints = self.core.has_bootstrap_endpoints();
        if !self.core.is_node() {
            if has_bootstrap_endpoints {
                // we are bootstrapping, refuse all normal connections
                self.connection_manager.drop_node(endpoint);
                return;
            } else {
                let assigned_name = NameType::new(crypto::hash::sha512::hash(
                    &self.core.id().name().0).0);
                let _ = self.core.assign_name(&assigned_name);
            }
        }

        if !self.core.add_peer(ConnectionName::Unidentified(endpoint.clone(), false),
            endpoint.clone(), None) {
            // only fails if relay_map is full for unidentified connections
            self.connection_manager.drop_node(endpoint.clone());
        }
        ignore(self.send_hello(endpoint));
    }

    /// When CRUST reports a lost connection, ensure we remove the endpoint anywhere
    fn handle_lost_connection(&mut self, endpoint : Endpoint) {
        //unimplemented!()
    }

    fn handle_new_bootstrap_connection(&mut self, endpoint : Endpoint) {
        if !self.core.is_node() {
            if !self.core.add_peer(ConnectionName::Unidentified(endpoint.clone(), true),
                endpoint.clone(), None) {
                // only fails if relay_map is full for unidentified connections
                self.connection_manager.drop_node(endpoint.clone());
                return;
            }
        } else {
            // if core is a full node, don't accept new bootstrap connections
            self.connection_manager.drop_node(endpoint);
            return;
        }
        ignore(self.send_hello(endpoint));
    }

    // ---- Hello connection identification -------------------------------------------------------

    fn send_hello(&mut self, endpoint: Endpoint) -> RoutingResult {
        let message = try!(encode(&Hello {
            address   : self.core.our_address(),
            public_id : PublicId::new(self.core.id())}));
        ignore(self.connection_manager.send(endpoint, message));
        Ok(())
    }

    fn handle_hello(&mut self, endpoint: &Endpoint, serialised_message: Bytes)
        -> RoutingResult {
        match decode::<Hello>(&serialised_message) {
            Ok(hello) => {
                let old_identity = match self.core.lookup_endpoint(&endpoint) {
                    // if already connected through the routing table, just confirm or destroy
                    Some(ConnectionName::Routing(known_name)) => {
                        match hello.address {
                            // FIXME (ben 11/08/2015) Hello messages need to be signed and
                            // we also need to check the match with the PublicId stored in RT
                            Address::Node(known_name) =>
                                return Ok(()),
                            _ => {
                                // the endpoint does not match with the routing information
                                // we know about it; drop it
                                let _ = self.core.drop_peer(&ConnectionName::Routing(known_name));
                                self.connection_manager.drop_node(endpoint.clone());
                                return Err(RoutingError::RejectedPublicId);
                            },
                        }
                    },
                    // a connection should have been labeled as Unidentified
                    None => None,
                    Some(relay_connection_name) => Some(relay_connection_name),
                };
                let new_identity = match (hello.address, self.core.our_address()) {
                    (Address::Node(his_name), Address::Node(our_name)) => {
                    // He is a node, and we are a node, establish a routing table connection
                    // FIXME (ben 11/08/2015) we need to check his PublicId against the network
                    // but this requires an additional RFC so currently leave out such check
                    // refer to https://github.com/maidsafe/routing/issues/387
                        ConnectionName::Routing(his_name)
                    },
                    (Address::Client(his_public_key), Address::Node(our_name)) => {
                    // He is a client, we are a node, establish a relay connection
                        ConnectionName::Relay(Address::Client(his_public_key))
                    },
                    (Address::Node(his_name), Address::Client(our_public_key)) => {
                    // He is a node, we are a client, establish a bootstrap connection
                        ConnectionName::Bootstrap(his_name)
                    },
                    (Address::Client(his_public_key), Address::Client(our_public_key)) => {
                    // He is a client, we are a client, no-go
                        match old_identity {
                            Some(old_connection_name) => {
                                let _ = self.core.drop_peer(&old_connection_name); },
                            None => {},
                        };
                        self.connection_manager.drop_node(endpoint.clone());
                        return Err(RoutingError::BadAuthority);
                    },
                };
                if self.core.add_peer(new_identity.clone(), endpoint.clone(),
                    Some(hello.public_id)) {
                    match new_identity {
                        ConnectionName::Bootstrap(bootstrap_name) => {
                            ignore(self.request_network_name(&bootstrap_name, endpoint));
                        },
                        _ => {},
                    };
                } else {
                    self.connection_manager.drop_node(endpoint.clone());
                };
                match old_identity {
                    Some(ConnectionName::Routing(_)) => unreachable!(),
                    // drop any relay connection in favour of the routing connection
                    Some(old_connection_name) => {
                        let _ = self.core.drop_peer(&old_connection_name); },
                    None => {},
                };
                Ok(())
            },
            Err(_) => Err(RoutingError::UnknownMessageType)
        }
    }


    /// This the fundamental functional function in routing.
    /// It only handles messages received from connections in our routing table;
    /// i.e. this is a pure SAFE message (and does not function as the start of a relay).
    /// If we are the relay node for a message from the SAFE network to a node we relay for,
    /// then we will pass out the message to the client or bootstrapping node;
    /// no relay-messages enter the SAFE network here.
    fn message_received(&mut self, message_wrap : SignedMessage) -> RoutingResult {

        let message = message_wrap.get_routing_message().clone();

        // filter check
        if self.filter.check(message_wrap.signature()) {
            // should just return quietly
            debug!("FILTER BLOCKED message {:?} from {:?} to {:?}", message.content,
                message.source(), message.destination());
            return Err(RoutingError::FilterCheckFailed);
        }
        debug!("message {:?} from {:?} to {:?}", message.content,
            message.source(), message.destination());
        // add to filter
        self.filter.add(message_wrap.signature().clone());

        // Forward
        ignore(self.send(message_wrap.clone()));

        if !self.core.name_in_range(&message.destination().get_location()) {
            return Ok(()); };

        // check if our calculated authority matches the destination authority of the message
        if self.core.our_authority(&message)
            .map(|our_auth| message.to_authority == our_auth).unwrap_or(false) {
            return Err(RoutingError::BadAuthority);
        }

        // Accumulate message
        let (message, opt_token) = match self.accumulate(message_wrap) {
            Some((message, opt_token)) => (message, opt_token),
            None => return Ok(()),
        };

        match message.content {
            Content::InternalRequest(request) => {
                match request {
                    InternalRequest::Connect(_) => {
                        match opt_token {
                            Some(response_token) => self.handle_connect_request(request,
                                message.from_authority, message.to_authority, response_token),
                            None => return Err(RoutingError::UnknownMessageType),
                        }
                    },
                    InternalRequest::RequestNetworkName(_) => {
                        match opt_token {
                            Some(response_token) => self.handle_request_network_name(request,
                                message.from_authority, message.to_authority, response_token),
                            None => return Err(RoutingError::UnknownMessageType),
                        }
                    },
                    InternalRequest::CacheNetworkName(_, _) => {
                        self.handle_cache_network_name(request, message.from_authority,
                            message.to_authority)
                    },
                    InternalRequest::Refresh(_, _) => {
                        Ok(())
                        // TODO (ben 13/08/2015) implement self.handle_refresh()
                    },
                }
            },
            Content::InternalResponse(response) => {
                match response {
                    InternalResponse::Connect(_, _) => {
                        self.handle_connect_response(response, message.from_authority,
                            message.to_authority)
                    },
                    InternalResponse::CacheNetworkName(_, _, _) => {
                        self.handle_cache_network_name_response(response, message.from_authority,
                            message.to_authority)
                    }
                }
            },
            Content::ExternalRequest(request) => {
                self.send_to_user(Event::Request {
                    request        : request,
                    our_authority  : message.to_authority,
                    from_authority : message.from_authority,
                    response_token : opt_token,
                });
                Ok(())
            }
            Content::ExternalResponse(response) => {
                self.handle_external_response(response, message.to_authority,
                    message.from_authority)
            }
        }
    }

    fn accumulate(&mut self, signed_message: SignedMessage) -> Option<(RoutingMessage, Option<SignedToken>)> {
        let message = signed_message.get_routing_message().clone();

        if !message.from_authority.is_group() {
            // TODO: If not from a group, then use client's public key to check
            // the signature.
            let token = match signed_message.as_token() {
                Ok(token) => token,
                Err(_)    => return None
            };
            return Some((message, Some(token)));
        }

        let skip_accumulator = match message.content {
            Content::InternalResponse(ref response) => {
                match *response {
                    InternalResponse::CacheNetworkName(_,_,_) => true,
                    _ => false,
                }
            },
            _ => false
        };

        if skip_accumulator { return Some((message, None)); }

        let threshold = min(types::GROUP_SIZE,
                            (self.core.routing_table_size() as f32 * 0.8) as usize);

        let claimant : NameType = match *signed_message.claimant() {
            Address::Node(ref claimant) => claimant.clone(),
            Address::Client(_) => {
                debug_assert!(false);
                return None;
            }
        };

        self.accumulator.add_message(threshold as usize, claimant, message)
                        .map(|msg| (msg, None))
    }

    // ---- Request Network Name ------------------------------------------------------------------

    fn request_network_name(&mut self, bootstrap_name : &NameType,
        bootstrap_endpoint : &Endpoint) -> RoutingResult {
        // if RoutingNode is restricted from becoming a node,
        // it suffices to never request a network name.
        if self.client_restriction { return Ok(()) }
        if self.core.is_node() { return Err(RoutingError::AlreadyConnected); };
        let core_id = self.core.id();
        let routing_message = RoutingMessage {
            from_authority : Authority::Client(bootstrap_name.clone(),
                core_id.signing_public_key()),
            to_authority   : Authority::NaeManager(core_id.name()),
            content        : Content::InternalRequest(InternalRequest::RequestNetworkName(
                PublicId::new(core_id))),
        };
        match SignedMessage::new(Address::Client(core_id.signing_public_key()),
            routing_message, core_id.signing_private_key()) {
            Ok(signed_message) => ignore(self.send(signed_message)),
            Err(e) => return Err(RoutingError::Cbor(e)),
        };
        Ok(())
    }

    fn handle_request_network_name(&self, request        : InternalRequest,
                                          from_authority : Authority,
                                          to_authority   : Authority,
                                          response_token : SignedToken) -> RoutingResult {
        match request {
            InternalRequest::RequestNetworkName(public_id) => {
                match (from_authority, &to_authority) {
                    (Authority::Client(_, public_key), &Authority::NaeManager(name)) => {
                        let mut network_public_id = public_id.clone();
                        match self.core.our_close_group() {
                            Some(close_group) => {
                                let relocated_name = try!(utils::calculate_relocated_name(
                                    close_group, &public_id.name()));
                                network_public_id.assign_relocated_name(relocated_name.clone());
                                let routing_message = RoutingMessage {
                                    from_authority : to_authority,
                                    to_authority   : Authority::NaeManager(relocated_name.clone()),
                                    content        : Content::InternalRequest(
                                        InternalRequest::CacheNetworkName(network_public_id,
                                        response_token)),
                                };
                                match SignedMessage::new(Address::Node(self.core.id().name()),
                                    routing_message, self.core.id().signing_private_key()) {
                                    Ok(signed_message) => ignore(self.send(signed_message)),
                                    Err(e) => return Err(RoutingError::Cbor(e)),
                                };
                                Ok(())
                            },
                            None => return Err(RoutingError::BadAuthority),
                        }
                    },
                    _ => return Err(RoutingError::BadAuthority),
                }
            },
            _ => return Err(RoutingError::BadAuthority),
        }
    }

    fn handle_cache_network_name(&mut self, request        : InternalRequest,
                                            from_authority : Authority,
                                            to_authority   : Authority,
                                            ) -> RoutingResult {
        match request {
            InternalRequest::CacheNetworkName(network_public_id, response_token) => {
                match (from_authority, &to_authority) {
                    (Authority::NaeManager(from_name), &Authority::NaeManager(name)) => {
                        let request_network_name = try!(SignedMessage::new_from_token(
                            response_token.clone()));
                        let _ = self.public_id_cache.insert(network_public_id.name(),
                            network_public_id.clone());
                        match self.core.our_close_group_with_public_ids() {
                            Some(close_group) => {
                                let routing_message = RoutingMessage {
                                    from_authority : to_authority,
                                    to_authority   : request_network_name.get_routing_message().destination(),
                                    content        : Content::InternalResponse(
                                        InternalResponse::CacheNetworkName(network_public_id,
                                        close_group, response_token)),
                                };
                                match SignedMessage::new(Address::Node(self.core.id().name()),
                                    routing_message, self.core.id().signing_private_key()) {
                                    Ok(signed_message) => ignore(self.send(signed_message)),
                                    Err(e) => return Err(RoutingError::Cbor(e)),
                                };
                                Ok(())
                            },
                            None => return Err(RoutingError::BadAuthority),
                        }
                    },
                    _ => return Err(RoutingError::BadAuthority),
                }
            },
            _ => return Err(RoutingError::BadAuthority),
        }
    }

    fn handle_cache_network_name_response(&mut self,
                                          response       : InternalResponse,
                                          from_authority : Authority,
                                          to_authority   : Authority) -> RoutingResult {
        // An additional blockage on acting to restrict RoutingNode from becoming a full node
        if self.client_restriction { return Ok(()) };
        match response {
            InternalResponse::CacheNetworkName(network_public_id, group, signed_token) => {
                if !signed_token.verify_signature(&self.core.id().signing_public_key()) {
                    return Err(RoutingError::FailedSignature)};
                let request = try!(SignedMessage::new_from_token(signed_token));
                match request.get_routing_message().content {
                    Content::InternalRequest(InternalRequest::RequestNetworkName(ref original_public_id)) => {
                        let mut our_public_id = PublicId::new(self.core.id());
                        if &our_public_id != original_public_id { return Err(RoutingError::BadAuthority); };
                        our_public_id.set_name(network_public_id.name());
                        if our_public_id != network_public_id { return Err(RoutingError::BadAuthority); };
                        let _ = self.core.assign_network_name(&network_public_id.name());
                        for peer in group {
                            // TODO (ben 12/08/2015) self.public_id_cache.insert()
                            // or hold off till RFC on removing public_id_cache
                            self.refresh_routing_table(peer.name());
                        }
                        Ok(())
                    },
                    _ => return Err(RoutingError::UnknownMessageType),
                }
            },
            _ => return Err(RoutingError::BadAuthority),
        }
    }

    // ---- Connect Requests and Responses --------------------------------------------------------

    /// Scan all passing messages for the existance of nodes in the address space.
    /// If a node is detected with a name that would improve our routing table,
    /// then try to connect.  During a delay of 5 seconds, we collapse
    /// all re-occurances of this name, and block a new connect request
    /// TODO: The behaviour of this function has been adapted to serve as a filter
    /// to cover for the lack of a filter on FindGroupResponse
    fn refresh_routing_table(&mut self, from_node : NameType) {
      // disable refresh when scanning on small routing_table size
      let time_now = SteadyTime::now();
      if !self.connection_cache.contains_key(&from_node) {
          if self.core.check_node(&ConnectionName::Routing(from_node)) {
              ignore(self.send_connect_request(&from_node));
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

    fn send_connect_request(&mut self, peer_name: &NameType) -> RoutingResult {
        // FIXME (ben) We're sending all accepting connections as local since we don't differentiate
        // between local and external yet.
        // FIXME (ben 13/08/2015) We are forced to make this split as the routing message
        // needs to contain a relay name if we are not yet connected to routing nodes
        // under our own name.
        match self.core.bootstrap_endpoints() {
            Some(bootstrap_peers) => {
                // TODO (ben 13/08/2015) for now just take the first bootstrap peer as our relay
                match bootstrap_peers.first() {
                    Some(bootstrap_peer) => {
                        match *bootstrap_peer.identity() {
                            ConnectionName::Bootstrap(bootstrap_name) => {
                                let routing_message = RoutingMessage {
                                    from_authority : Authority::Client(bootstrap_name,
                                        self.core.id().signing_public_key()),
                                    to_authority   : Authority::ManagedNode(peer_name.clone()),
                                    content        : Content::InternalRequest(
                                        InternalRequest::Connect(ConnectRequest {
                                            local_endpoints    : self.accepting_on.clone(),
                                            external_endpoints : vec![],
                                            requester_fob      : PublicId::new(self.core.id()),
                                        }
                                    )),
                                };
                                match SignedMessage::new(Address::Client(
                                    self.core.id().signing_public_key()), routing_message,
                                    self.core.id().signing_private_key()) {
                                    Ok(signed_message) => ignore(self.send(signed_message)),
                                    Err(e) => return Err(RoutingError::Cbor(e)),
                                };
                                Ok(())
                            },
                            _ => return Err(RoutingError::NotBootstrapped),
                        }
                    },
                    None => return Err(RoutingError::NotBootstrapped),
                }
            },
            None => {
                let routing_message = RoutingMessage {
                    from_authority : Authority::ManagedNode(self.core.id().name()),
                    to_authority   : Authority::ManagedNode(peer_name.clone()),
                    content        : Content::InternalRequest(
                        InternalRequest::Connect(ConnectRequest {
                            local_endpoints    : self.accepting_on.clone(),
                            external_endpoints : vec![],
                            requester_fob      : PublicId::new(self.core.id()),
                        }
                    )),
                };
                match SignedMessage::new(Address::Node(self.core.id().name()),
                    routing_message, self.core.id().signing_private_key()) {
                    Ok(signed_message) => ignore(self.send(signed_message)),
                    Err(e) => return Err(RoutingError::Cbor(e)),
                };
                Ok(())
            },
        }
    }

    fn handle_connect_request(&mut self,
                              request        : InternalRequest,
                              from_authority : Authority,
                              to_authority   : Authority,
                              response_token : SignedToken) -> RoutingResult {
        match request {
            InternalRequest::Connect(connect_request) => {
                if !connect_request.requester_fob.is_relocated() {
                    return Err(RoutingError::RejectedPublicId); };
                // first verify that the message is correctly self-signed
                if !response_token.verify_signature(&connect_request.requester_fob
                    .signing_public_key()) {
                    return Err(RoutingError::FailedSignature); };
                if !self.core.check_node(&ConnectionName::Routing(
                    connect_request.requester_fob.name())) {
                    return Err(RoutingError::RefusedFromRoutingTable); };
                // TODO (ben 13/08/2015) use public_id_cache or result of future RFC
                // to validate the public_id from the network
                self.connection_manager.connect(connect_request.local_endpoints.clone());
                self.connection_manager.connect(connect_request.external_endpoints.clone());
                self.connection_cache.entry(connect_request.requester_fob.name())
                    .or_insert(SteadyTime::now());
                let routing_message = RoutingMessage {
                    from_authority : Authority::ManagedNode(self.core.id().name()),
                    to_authority   : Authority::ManagedNode(from_authority.get_location().clone()),
                    content        : Content::InternalResponse(
                        InternalResponse::Connect(ConnectResponse {
                            local_endpoints    : self.accepting_on.clone(),
                            external_endpoints : vec![],
                            receiver_fob       : PublicId::new(self.core.id()),
                        }, response_token)
                    ),
                };
                match SignedMessage::new(Address::Node(self.core.id().name()),
                    routing_message, self.core.id().signing_private_key()) {
                    Ok(signed_message) => ignore(self.send(signed_message)),
                    Err(e) => return Err(RoutingError::Cbor(e)),
                };
                Ok(())
            },
            _ => return Err(RoutingError::BadAuthority),
        }
    }

    fn handle_connect_response(&mut self,
                               response       : InternalResponse,
                               from_authority : Authority,
                               to_authority   : Authority) -> RoutingResult {
        match response {
            InternalResponse::Connect(connect_response, signed_token) => {
                if !signed_token.verify_signature(&self.core.id().signing_public_key()) {
                    return Err(RoutingError::FailedSignature); };
                let connect_request = try!(SignedMessage::new_from_token(signed_token));
                if connect_request.get_routing_message().from_authority.get_location()
                    != &self.core.id().name() { return Err(RoutingError::BadAuthority); };
                if !self.core.check_node(&ConnectionName::Routing(
                    connect_response.receiver_fob.name())) {
                    return Err(RoutingError::RefusedFromRoutingTable); };
                self.connection_manager.connect(connect_response.local_endpoints.clone());
                self.connection_manager.connect(connect_response.external_endpoints.clone());
                self.connection_cache.entry(connect_response.receiver_fob.name())
                    .or_insert(SteadyTime::now());
                Ok(())
            },
            _ => return Err(RoutingError::BadAuthority),
        }
    }

    // ----- Send Functions -----------------------------------------------------------------------

    fn send_to_user(&self, event: Event) {
        if self.event_sender.send(event).is_err() {
            let _ = self.action_sender.send(Action::Terminate);
        }
    }

    /// Send a SignedMessage out to the destination
    /// 1. if it can be directly relayed to a Client, then it will
    /// 2. if we can forward it to nodes closer to the destination, it will be sent in parallel
    /// 3. if the destination is in range for us, then send it to all our close group nodes
    /// 4. if all the above failed, try sending it over all available bootstrap connections
    /// 5. finally, if we are a node and the message concerns us, queue it for processing later.
    fn send(&self, signed_message : SignedMessage) -> RoutingResult {
        let destination = signed_message.get_routing_message().destination();
        let bytes = try!(encode(&signed_message));
        // query the routing table for parallel or swarm
        let endpoints = self.core.target_endpoints(&destination);
        if !endpoints.is_empty() {
            for endpoint in endpoints {
                // TODO(ben 10/08/2015) drop endpoints that fail to send
                ignore(self.connection_manager.send(endpoint, bytes.clone()));
            }
        }

        match self.core.bootstrap_endpoints() {
            Some(bootstrap_peers) => {
                // TODO (ben 10/08/2015) Strictly speaking we do not have to validate that
                // the relay_name in from_authority Client(relay_name, client_public_key) is
                // the name of the bootstrap connection we're sending it on.  Although this might
                // open a window for attacking a node, in v0.3.* we can leave this unresolved.
                for bootstrap_peer in bootstrap_peers {
                    // TODO(ben 10/08/2015) drop bootstrap endpoints that fail to send
                    ignore(self.connection_manager.send(bootstrap_peer.endpoint().clone(),
                        bytes.clone()));
                }
                return Ok(());
            },
            None => {},
        }

        // If we need handle this message, move this copy into the channel for later processing.
        if self.core.name_in_range(&destination.get_location()) {
            ignore(self.action_sender.send(Action::SendMessage(signed_message)));
        }
        Ok(())
    }

    // -----Message Handlers from Routing Table connections----------------------------------------

    fn handle_external_response(&self, response       : ExternalResponse,
                                       to_authority   : Authority,
                                       from_authority : Authority) -> RoutingResult {

        let orig_request_msg = try!(response.get_orig_request());

        if !orig_request_msg.verify_signature(&self.core.id().signing_public_key()) {
            return Err(RoutingError::FailedSignature)
        }

        let orig_request = match orig_request_msg.get_routing_message().content {
            Content::ExternalRequest(ref request) => request.clone(),
            _ => return Err(RoutingError::UnknownMessageType)
        };

        self.send_to_user(Event::Response {
            response       : response,
            our_authority  : to_authority,
            from_authority : from_authority,
            orig_request   : orig_request,
        });

        Ok(())
    }

    fn handle_refresh(&mut self, message: RoutingMessage, tag: u64, payload: Vec<u8>) -> RoutingResult {
        unimplemented!()
    }
}

fn ignore<R,E>(_result: Result<R,E>) {}
