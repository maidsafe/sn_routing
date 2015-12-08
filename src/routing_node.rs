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

use crust;

use kademlia_routing_table::{RoutingTable, NodeInfo};

use sodiumoxide::crypto;

use lru_time_cache::LruCache;

use action::Action;
use event::Event;
use XorName;
use id::FullId;
use id::PublicId;
use types::Address;
use utils::{encode, decode};
use utils;
use authority::{Authority, our_authority};

use messages::{RoutingMessage, SignedMessage, SignedRequest, Content, ExternalResponse,
               InternalRequest, InternalResponse};

use error::{RoutingError, InterfaceError};


type RoutingResult = Result<(), RoutingError>;

const MAX_RELAYS: usize = 100;
const ROUTING_NODE_THREAD_NAME: &'static str = "RoutingNodeThread";
const CRUST_DEFAULT_BEACON_PORT: u16 = 5484;
const CRUST_DEFAULT_TCP_ACCEPTING_PORT: ::crust::Port = ::crust::Port::Tcp(5483);
const CRUST_DEFAULT_UTP_ACCEPTING_PORT: ::crust::Port = ::crust::Port::Utp(5483);

#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
enum State {
    Disconnected,
    // Transition state while validating proxy node
    Bootstrapping,
    // We are Bootstrapped
    Client,
    // We have been Relocated and now a node
    Node,
}

/// Routing Node
pub struct RoutingNode {
    // for CRUST
    crust_service: ::crust::Service,
    accepting_on: Vec<::crust::Endpoint>,
    connection_counter: u32,
    // for RoutingNode
    client_restriction: bool,
    crust_rx: ::std::sync::mpsc::Receiver<::crust::Event>,
    action_rx: ::std::sync::mpsc::Receiver<Action>,
    event_sender: ::std::sync::mpsc::Sender<Event>,
    signed_message_filter: ::message_filter::MessageFilter<::messages::SignedMessage>,
    connection_filter: ::message_filter::MessageFilter<::XorName>,
    node_id_cache: LruCache<XorName, PublicId>,
    message_accumulator: ::accumulator::Accumulator<RoutingMessage,
                                                      ::sodiumoxide::crypto::sign::PublicKey>,
    refresh_accumulator: ::refresh_accumulator::RefreshAccumulator,
    refresh_causes: ::message_filter::MessageFilter<::XorName>,
    // Messages which have been accumulated and then actioned
    handled_messages: ::message_filter::MessageFilter<RoutingMessage>,
    // cache_options: ::data_cache_options::DataCacheOptions,
    data_cache: ::data_cache::DataCache,
    relocation_quorum_size: usize,

    full_id: FullId,
    state: State,
    routing_table: RoutingTable<::id::PublicId, ::crust::Connection>,
    // our bootstrap connections
    proxy_map: ::std::collections::HashMap<::crust::Connection, ::XorName>,
    // any clients we have proxying through us
    client_map: ::std::collections::HashMap<crypto::sign::PublicKey, ::crust::Connection>,
}

impl RoutingNode {
    pub fn new(event_sender: ::std::sync::mpsc::Sender<Event>,
               client_restriction: bool,
               keys: Option<FullId>)
               -> Result<(::types::RoutingActionSender,
                          ::maidsafe_utilities::thread::RaiiThreadJoiner),
                         RoutingError> {
        let (crust_tx, crust_rx) = ::std::sync::mpsc::channel();
        let (action_tx, action_rx) = ::std::sync::mpsc::channel();
        let (category_tx, category_rx) = ::std::sync::mpsc::channel();

        let routing_event_category =
            ::maidsafe_utilities::event_sender::MaidSafeEventCategory::RoutingEvent;
        let action_sender = ::types::RoutingActionSender::new(action_tx,
                                                              routing_event_category,
                                                              category_tx.clone());

        let crust_event_category =
            ::maidsafe_utilities::event_sender::MaidSafeEventCategory::CrustEvent;
        let crust_sender = ::crust::CrustEventSender::new(crust_tx,
                                                          crust_event_category,
                                                          category_tx);

        let crust_service = match ::crust::Service::new(crust_sender) {
            Ok(service) => service,
            Err(what) => panic!(format!("Unable to start crust::Service {}", what)),
        };

        let full_id = match keys {
            Some(full_id) => full_id,
            None => FullId::new(),
        };
        let our_name = *full_id.public_id().name();

        let joiner = thread!(ROUTING_NODE_THREAD_NAME, move || {
            let mut routing_node = RoutingNode {
                crust_service: crust_service,
                accepting_on: vec![],
            // Counter starts at 1, 0 is reserved for bootstrapping.
                connection_counter: 1u32,
                client_restriction: client_restriction,
                crust_rx: crust_rx,
                action_rx: action_rx,
                event_sender: event_sender,
                signed_message_filter: ::message_filter
                                       ::MessageFilter
                                       ::with_expiry_duration(::time::Duration::minutes(20)),
                connection_filter: ::message_filter::MessageFilter::with_expiry_duration(
                    ::time::Duration::seconds(20)),
                node_id_cache: LruCache::with_expiry_duration(::time::Duration::minutes(10)),
                message_accumulator: ::accumulator::Accumulator::with_duration(1,
                    ::time::Duration::minutes(5)),
                refresh_accumulator:
                    ::refresh_accumulator::RefreshAccumulator::with_expiry_duration(
                        ::time::Duration::minutes(5)),
                refresh_causes: ::message_filter::MessageFilter::with_expiry_duration(
                    ::time::Duration::minutes(5)),
                handled_messages: ::message_filter::MessageFilter::with_expiry_duration(
                    ::time::Duration::minutes(20)),
            // cache_options: ::data_cache_options::DataCacheOptions::new(),
                data_cache: ::data_cache::DataCache::new(),
                relocation_quorum_size: 0,
                full_id: full_id,
                state: State::Disconnected,
                routing_table: RoutingTable::new(&our_name),
                proxy_map: ::std::collections::HashMap::new(),
                client_map: ::std::collections::HashMap::new(),
            };

            routing_node.run(category_rx);

            debug!("Exiting thread {:?}", ROUTING_NODE_THREAD_NAME);
        });

        Ok((action_sender,
            ::maidsafe_utilities::thread::RaiiThreadJoiner::new(joiner)))
    }

    pub fn run(&mut self,
               category_rx: ::std::sync::mpsc::Receiver<
                   ::maidsafe_utilities::event_sender::MaidSafeEventCategory>) {
        self.crust_service.bootstrap(0u32, Some(CRUST_DEFAULT_BEACON_PORT));
        debug!("{}RoutingNode started running and started bootstrap",
               self.us());
        for it in category_rx.iter() {
            if self.state == State::Node {
                trace!("{}Routing Table size: {}",
                       self.us(),
                       self.routing_table.len());
            };
            match it {
                ::maidsafe_utilities::event_sender::MaidSafeEventCategory::RoutingEvent => {
                    if let Ok(action) = self.action_rx.try_recv() {
                        match action {
                            Action::SendContent(source_authority,
                                                destination_authority,
                                                content) => {
                                let _ = self.send_content(source_authority,
                                                          destination_authority,
                                                          content);
                            },
                            Action::ClientSendContent(destination_authority, content) => {
                                debug!("{}ClientSendContent received for {:?}", self.us(), content);
                                self.client_send_content(destination_authority, content);
                            },
                            Action::SetDataCacheOptions(cache_options) => {
                                self.data_cache.set_cache_options(cache_options);
                            }
                            Action::Terminate => {
                                debug!("{}routing node terminated", self.us());
                                let _ = self.event_sender.send(Event::Terminated);
                                self.crust_service.stop();
                                break;
                            }
                        }
                    }
                }
                ::maidsafe_utilities::event_sender::MaidSafeEventCategory::CrustEvent => {
                    if let Ok(crust_event) = self.crust_rx.try_recv() {
                        match crust_event {
                            ::crust::Event::BootstrapFinished => self.handle_bootstrap_finished(),
                            ::crust::Event::OnAccept(connection) => {
                                self.handle_on_accept(connection)
                            }

                            // TODO (Fraser) This needs to restart if we are left with 0 connections
                            ::crust::Event::LostConnection(connection) => {
                                self.handle_lost_connection(connection)
                            }

                            ::crust::Event::NewMessage(connection, bytes) => {
                                self.handle_new_message(connection, bytes)
                            }
                            ::crust::Event::OnConnect(connection, connection_token) => {
                                self.handle_on_connect(connection, connection_token)
                            }
                            ::crust::Event::ExternalEndpoints(external_endpoints) => {
                                for external_endpoint in external_endpoints {
                                    debug!("{}Adding external endpoint {:?}",
                                           self.us(),
                                           external_endpoint);
                                    self.accepting_on.push(external_endpoint);
                                }
                            }
                            ::crust::Event::OnHolePunched(_hole_punch_result) => unimplemented!(),
                            ::crust::Event::OnUdpSocketMapped(_mapped_udp_socket) => unimplemented!(),
                            ::crust::Event::OnRendezvousConnect(_connection, _signed_request) => unimplemented!(),
                        }
                    }
                }
            } // Category Match
        } // Category Rx
    }

    fn handle_bootstrap_finished(&mut self) {
        debug!("{}Finished bootstrapping.", self.us());
        // If we have no connections, we should start listening to allow incoming connections
        if self.state == State::Disconnected {
            debug!("{}Bootstrap finished with no connections. Start Listening to allow incoming \
                    connections.",
                   self.us());
            self.start_listening();
        }
    }

    fn start_listening(&mut self) {
        match self.crust_service.start_beacon(CRUST_DEFAULT_BEACON_PORT) {
            Ok(port) => {
                info!("{}Running Crust beacon listener on port {}",
                      self.us(),
                      port)
            }
            Err(error) => {
                warn!("{}Crust beacon failed to listen on port {}: {:?}",
                      self.us(),
                      CRUST_DEFAULT_BEACON_PORT,
                      error)
            }
        }
        match self.crust_service.start_accepting(CRUST_DEFAULT_TCP_ACCEPTING_PORT) {
            Ok(endpoint) => {
                info!("{}Running TCP listener on {:?}", self.us(), endpoint);
                self.accepting_on.push(endpoint);
            }
            Err(error) => {
                warn!("{}Failed to listen on {:?}: {:?}",
                      self.us(),
                      CRUST_DEFAULT_TCP_ACCEPTING_PORT,
                      error)
            }
        }
        match self.crust_service.start_accepting(CRUST_DEFAULT_UTP_ACCEPTING_PORT) {
            Ok(endpoint) => {
                info!("{}Running uTP listener on {:?}", self.us(), endpoint);
                self.accepting_on.push(endpoint);
            }
            Err(error) => {
                warn!("{}Failed to listen on {:?}: {:?}",
                      self.us(),
                      CRUST_DEFAULT_UTP_ACCEPTING_PORT,
                      error)
            }
        }

        // The above commands will give us only internal endpoints on which we're accepting. The
        // next command will try to find external endpoints. The result shall be returned async
        // through the Crust::ExternalEndpoints event.
        self.crust_service.get_external_endpoints();
    }

    fn handle_new_message(&mut self, connection: ::crust::Connection, bytes: Vec<u8>) {
        match decode::<SignedMessage>(&bytes) {
            Ok(message) => {
                let _ = self.handle_routing_message(message);
            }
            // The message is not a SignedMessage, expect it to be a DirectMessage
            Err(_) => {
                match decode::<::direct_messages::DirectMessage>(&bytes) {
                    Ok(direct_message) => self.handle_direct_message(direct_message, connection),
                    // TODO(Fraser): Drop the connection if we can't parse a message? (dirvine not sure)
                    _ => {
                        error!("{}Unparsable message received on {:?}",
                               self.us(),
                               connection)
                    }
                };
            }
        }
    }

    fn handle_on_connect(&mut self,
                         connection: ::std::io::Result<::crust::Connection>,
                         connection_token: u32) {
        match connection {
            Ok(connection) => {
                debug!("{}New connection via OnConnect {:?} with token {}",
                       self.us(),
                       connection,
                       connection_token);
                if let State::Disconnected = *self.state() {
                    // Established connection. Pending Validity checks
                    self.state = State::Bootstrapping;
                    let _ = self.client_identify(connection);
                    return;
                }

                let _ = self.node_identify(connection);
            }
            Err(error) => {
                warn!("{}Failed to make connection with token {} - {}",
                      self.us(),
                      connection_token,
                      error);
            }
        }
    }

    fn handle_on_accept(&mut self, connection: ::crust::Connection) {
        debug!("{}New connection via OnAccept {:?}", self.us(), connection);
        if let State::Disconnected = *self.state() {
            // I am the first node in the network, and I got an incoming connection so I'll
            // promote myself as a node.
            let new_name = XorName::new(crypto::hash::sha512::hash(&self.full_id
                                                                        .public_id()
                                                                        .name()
                                                                        .0)
                                            .0);

            // This will give me a new RT and set state to Relocated
            self.assign_network_name(new_name);
            self.state = State::Node;
        }
    }

    /// When CRUST reports a lost connection, ensure we remove the endpoint everywhere
    fn handle_lost_connection(&mut self, connection: ::crust::Connection) {
        debug!("{}Lost connection on {:?}", self.us(), connection);
        self.dropped_routing_node_connection(&connection);
        self.dropped_client_connection(&connection);
        self.dropped_bootstrap_connection(&connection);
    }

    fn bootstrap_identify(&mut self, connection: ::crust::Connection) -> RoutingResult {
        let direct_message = ::direct_messages::DirectMessage::BootstrapIdentify {
            public_id: self.full_id.public_id().clone(),
        // Current quorum size should also include ourselves when sending this message. Thus
        // the '+ 1'
            current_quorum_size: self.routing_table.dynamic_quorum_size() + 1,

        };
        // TODO impl convert trait for RoutingError
        let bytes = try!(::maidsafe_utilities::serialisation::serialise(&direct_message));

        Ok(self.crust_service.send(connection, bytes))
    }

    fn client_identify(&mut self, connection: ::crust::Connection) -> RoutingResult {
        let serialised_public_id =
            try!(::maidsafe_utilities::serialisation::serialise(self.full_id.public_id()));
        let signature = ::sodiumoxide::crypto::sign::sign_detached(&serialised_public_id,
                                                                   self.full_id
                                                                       .signing_private_key());

        let direct_message = ::direct_messages::DirectMessage::ClientIdentify {
            serialised_public_id: serialised_public_id,
            signature: signature,
        };
        let bytes = try!(::maidsafe_utilities::serialisation::serialise(&direct_message));

        Ok(self.crust_service.send(connection, bytes))
    }

    fn node_identify(&mut self, connection: ::crust::Connection) -> RoutingResult {
        let serialised_public_id =
            try!(::maidsafe_utilities::serialisation::serialise(self.full_id.public_id()));
        let signature = ::sodiumoxide::crypto::sign::sign_detached(&serialised_public_id,
                                                                   self.full_id
                                                                       .signing_private_key());

        let direct_message = ::direct_messages::DirectMessage::NodeIdentify {
            serialised_public_id: serialised_public_id,
            signature: signature,
        };
        let bytes = try!(::maidsafe_utilities::serialisation::serialise(&direct_message));

        Ok(self.crust_service.send(connection, bytes))
    }

    fn handle_identify(&mut self, connection: ::crust::Connection, peer_public_id: &PublicId) {
        debug!("{}Peer {:?} has identified itself on {:?}",
               self.us(),
               peer_public_id,
               connection);
        match self.state {
            State::Disconnected => {
                unreachable!("Should not be Disconnected when handling incoming identify message");
            }
            State::Bootstrapping => {
                assert!(self.proxy_map.is_empty());
                // I think this `add_peer` function is doing some validation of the ID, but I
                // haven't looked fully.  I guess it can't do proper validation until the PublicId
                // type is fixed to be validatable.  We should at least for now avoid (or assert
                // that we're not) adding a client ID here as the peer.

                // TODO(Fraser) - if this returns false, we probably need to restart
                let _ = self.proxy_map.insert(connection, peer_public_id.name().clone());
                info!("{}Routing Client bootstrapped", self.us());
                self.state = State::Client;
                let _ = self.event_sender.send(Event::Bootstrapped);
                let _ = self.relocate();
            }
            State::Client => {
                if self.client_restriction {
                    // Just now we only allow one bootstrap connection, so if we're already in
                    // Client state, we shouldn't receive further identifiers from peers.
                    error!("{}We're bootstrapped already, but have received another identifier from \
                           {:?} on {:?} - closing this connection now.", self.us(), peer_public_id,
                           connection);
                    self.drop_crust_connection(connection);
                } else if &::sodiumoxide::crypto::hash::sha512::hash(&peer_public_id.signing_public_key().0).0[..] !=
                          &peer_public_id.name().0[..] {
                    // FIXME
                    self.add_node(connection, peer_public_id.clone());
                } else {
                    error!("{}We're bootstrapped already, but have received another identifier from {:?} on {:?} - \
                        closing this connection now.", self.us(), peer_public_id, connection);
                    self.drop_crust_connection(connection);
                }
            }
            State::Node => {
                if &::sodiumoxide::crypto::hash::sha512::hash(&peer_public_id.signing_public_key().0).0[..] !=
                   &peer_public_id.name().0[..] {
                    self.add_node(connection, peer_public_id.clone());
                } else {
                    self.add_client(connection, peer_public_id.clone());
                }
            }
        }
    }

    /// This the fundamental functional function in routing.
    /// It only handles messages received from connections in our routing table;
    /// i.e. this is a pure SAFE message (and does not function as the start of a proxy).
    /// If we are the proxy node for a message from the SAFE network to a node we proxy for,
    /// then we will pass out the message to the client or bootstrapping node;
    /// no proxy-messages enter the SAFE network here.
    fn handle_routing_message(&mut self, signed_message: SignedMessage) -> RoutingResult {
        debug!("{}Signed Message Received - {:?}",
               self.us(),
               signed_message);

        // Prevents 1) someone sending messages repeatedly to us and 2) swarm messages generated by
        // us reaching us again
        if self.signed_message_filter.check(&signed_message) {
            return Err(RoutingError::FilterCheckFailed);
        }

        self.signed_message_filter.add(signed_message.clone());

        let routing_message = try!(signed_message.get_routing_message());

        if self.handled_messages.check(&routing_message) {
            debug!("{}This message has already been actioned.", self.us());
            return Err(RoutingError::FilterCheckFailed);
        }

        // Cache a response if from a GetRequest and caching is enabled for the Data type.
        self.data_cache.handle_cache_put(&routing_message);
        // Get from cache if it's there.
        if let Some(content) = self.data_cache.handle_cache_get(&routing_message) {
            let source_authority = ::authority::Authority::ManagedNode(*self.full_id
                                                                            .public_id()
                                                                            .name());
            return self.send_content(source_authority, routing_message.source_authority, content);
        }

        // Scan for remote names.
        if self.state == State::Node {
            // Node Harvesting
            // FIXME(dirvine) The name here is not a node we cannot harvest it :07/12/2015
            // match routing_message.from_authority {
            //     ::authority::Authority::ClientManager(ref name) |
            //     ::authority::Authority::NaeManager(ref name)  |
            //     ::authority::Authority::NodeManager(ref name) |
            //     ::authority::Authority::ManagedNode(ref name) => self.refresh_routing_table(&name),
            //     ::authority::Authority::Client(_, _) => {}
            // };

            // Forward the message.
            debug!("{}Forwarding signed message", self.us());
            // Swarm
            self.send(signed_message.clone());
        }

        // TODO Needs discussion as to what this block does
        // check if our calculated authority matches the destination authority of the message
        let our_authority = self.our_authority(&routing_message);
        if our_authority.clone()
                        .map_or(true, |our_auth| &routing_message.destination_authority != &our_auth) {
            // Either the message is directed at a group, and the target should be in range,
            // or it should be aimed directly at us.
            if routing_message.destination_authority.is_group() {
                if !self.name_in_range(routing_message.destination_authority.get_location()) {
                    debug!("{}Name {:?} not in range",
                           self.us(),
                           routing_message.destination_authority.get_location());
                    return Err(RoutingError::BadAuthority);
                };
                debug!("{}Received an in-range group message", self.us());
            } else {
                match routing_message.destination_authority.get_address() {
                    Some(ref address) => {
                        if !self.is_us(address) {
                            debug!("{}Destination address {:?} is not us", self.us(), address);
                            return Err(RoutingError::BadAuthority);
                        }
                    }
                    None => return Err(RoutingError::BadAuthority),
                }
            }
        }

        // Accumulate message
        debug!("{}Accumulating signed message", self.us());

        // If the message is not from a group then don't accumulate
        let (accumulated_message, opt_token) = if routing_message.source_authority.is_group() {
            match self.accumulate(&routing_message,
                                  signed_message.signing_public_key().clone()) {
                Some(output_message) => (output_message, None),
                None => {
                    debug!("{}Not enough signatures. Not processing request yet",
                           self.us());
                    return Err(::error::RoutingError::NotEnoughSignatures);
                }
            }
        } else {
            (routing_message, Some(signed_message.as_signed_request()))
        };
        self.handle_accumulated_message(accumulated_message, opt_token)
    }

    fn handle_accumulated_message(&mut self,
                                  accumulated_message: ::messages::RoutingMessage,
                                  opt_token: Option<SignedRequest>)
                                  -> RoutingResult {
        let result = match accumulated_message.content {
            Content::InternalRequest(request) => {
                match request {
                    InternalRequest::GetNetworkName { current_id, } => {
                       self.handle_get_network_name_request(opt_token,
                                                            current_id,
                                                            accumulated_message.source_authority,
                                                            accumulated_message.destination_authority)
                    }
                    InternalRequest::ExpectCloseNode { expect_id, } => {
                        self.handle_expect_close_node_request(opt_token, expect_id)
                    }
                    InternalRequest::GetCloseGroup => {
                        self.handle_get_close_group_request(opt_token,
                                                            accumulated_message.source_authority,
                                                            accumulated_message.destination_authority)
                    }
                    InternalRequest::Endpoints { encrypted_endpoints, nonce_bytes } => {
                        self.handle_endpoints(opt_token,
                                              encrypted_endpoints,
                                              nonce_bytes,
                                              accumulated_message.source_authority,
                                              accumulated_message.destination_authority)
                    }
                    InternalRequest::Connect => {
                        if let ::authority::Authority::ManagedNode(name) =
                                accumulated_message.source_authority {
                            self.handle_connect_request(opt_token, name)
                        } else {
                            return Err(RoutingError::BadAuthority);
                        }
                    }
                    InternalRequest::GetPublicId => {
                        if let (::authority::Authority::ManagedNode(from_name),
                                ::authority::Authority::NodeManager(to_name)) =
                                (accumulated_message.source_authority,
                                 accumulated_message.destination_authority) {
                            self.handle_get_public_id(opt_token, from_name, to_name)
                        } else {
                            return Err(RoutingError::BadAuthority);
                        }
                    }
                    InternalRequest::GetPublicIdWithEndpoints { .. } => {
                        if let (::authority::Authority::ManagedNode(from_name),
                                ::authority::Authority::NodeManager(to_name)) =
                                (accumulated_message.source_authority,
                                 accumulated_message.destination_authority) {
                            self.handle_get_public_id_with_endpoints(opt_token, from_name, to_name)
                        } else {
                            return Err(RoutingError::BadAuthority);
                        }
                    }
                    // From Group
                    InternalRequest::Refresh { type_tag, message, cause, } => {
                        if accumulated_message.source_authority.is_group() {
                            self.handle_refresh(type_tag,
                                                accumulated_message.source_authority
                                                                   .get_location()
                                                                   .clone(),
                                                message,
                                                accumulated_message.destination_authority,
                                                cause)
                        } else {
                            return Err(RoutingError::BadAuthority);
                        }
                    }
                }
            }
            Content::InternalResponse(response) => {
                match response {
                    InternalResponse::GetNetworkName { relocated_id, signed_request, } => {
                        self.handle_get_network_name_response(relocated_id, signed_request)
                    }
                    InternalResponse::GetCloseGroup { close_group_ids, signed_request, } => {
                        self.handle_get_close_group_response(accumulated_message.destination_authority,
                                                             close_group_ids,
                                                             signed_request)
                    }
                    InternalResponse::GetPublicId { public_id, signed_request } => {
                        self.handle_get_public_id_response(public_id, signed_request)
                    }
                    InternalResponse::GetPublicIdWithEndpoints { public_id, signed_request } => {
                        self.handle_get_public_id_with_endpoints_response(public_id, signed_request)
                    }
                }
            }
            Content::ExternalRequest(request) => {
                self.send_to_user(Event::Request {
                    request: request,
                    our_authority: accumulated_message.destination_authority,
                    from_authority: accumulated_message.source_authority,
                    signed_request: opt_token,
                });
                Ok(())
            }
            Content::ExternalResponse(response) => {
                self.handle_external_response(response,
                                              accumulated_message.destination_authority,
                                              accumulated_message.source_authority)
            }
        };

        // TODO Remove this if not required
        match result {
            Ok(()) => {
                // self.signed_message_filter.add((routing_message, public_sign_key.clone()));
                Ok(())
            }
            Err(RoutingError::UnknownMessageType) => {
                // self.signed_message_filter.add((routing_message, public_sign_key.clone()));
                Err(RoutingError::UnknownMessageType)
            }
            Err(e) => Err(e),
        }

    }

    fn accumulate(&mut self,
                  message: &::messages::RoutingMessage,
                  public_sign_key: ::sodiumoxide::crypto::sign::PublicKey)
                  -> Option<RoutingMessage> {
        // TODO(Fraser) Use this properly
        utils::bucket_index_range_confidence();

        debug!("{}Adding message with public key {:?} to message_accumulator",
               self.us(),
               public_sign_key);

        self.message_accumulator.set_quorum_size(self.routing_table.dynamic_quorum_size());
        if self.message_accumulator.add(message.clone(), public_sign_key.clone()).is_some() {
            self.handled_messages.add(message.clone());
            Some(message.clone())
        } else {
            None
        }
    }

    // ---- Direct Messages -----------------------------------------------------------------------
    fn verify_signed_public_id(serialised_public_id: &[u8],
                               signature: &::sodiumoxide::crypto::sign::Signature)
                               -> Result<::id::PublicId, RoutingError> {
        let public_id: ::id::PublicId =
            try!(::maidsafe_utilities::serialisation::deserialise(serialised_public_id));
        if ::sodiumoxide::crypto::sign::verify_detached(signature,
                                                        serialised_public_id,
                                                        public_id.signing_public_key()) {
            Ok(public_id)
        } else {
            Err(RoutingError::FailedSignature)
        }
    }

    fn handle_direct_message(&mut self,
                             direct_message: ::direct_messages::DirectMessage,
                             connection: ::crust::Connection) {
        debug!("{}Direct Message Received - {:?}",
               self.us(),
               direct_message);
        match direct_message {
            ::direct_messages::DirectMessage::BootstrapIdentify { ref public_id, current_quorum_size } => {
                if *public_id.name() == ::XorName::new(::sodiumoxide
                                                        ::crypto
                                                        ::hash::sha512::hash(&public_id.signing_public_key().0).0) {
                    warn!("{}Incoming Connection not validated as a proper node - dropping", self.us());
                    self.crust_service.drop_node(connection);

                    // Probably look for other bootstrap connections
                    return
                }

                if let Some(previous_name) = self.proxy_map.insert(connection, public_id.name().clone()) {
                    warn!("{}Adding bootstrap node to proxy map caused a prior id to eject. \
                          Previous name: {:?}", self.us(), previous_name);
                    warn!("{}Dropping this connection {:?}", self.us(), connection);
                    self.crust_service.drop_node(connection);
                    let _ = self.proxy_map.remove(&connection);

                    // Probably look for other bootstrap connections
                    return
                }

                self.state = State::Client;
                self.relocation_quorum_size = current_quorum_size;

                // Only if we started as a client but eventually want to be a node
                if !self.client_restriction {
                    self.relocate();
                }
            }
            ::direct_messages::DirectMessage::ClientIdentify { ref serialised_public_id, ref signature } => {
                let public_id = match RoutingNode::verify_signed_public_id(serialised_public_id, signature) {
                    Ok(public_id) => public_id,
                    Err(error) => {
                        warn!("{}Signature check failed in NodeIdentify - Dropping connection {:?}",
                              self.us(), connection);
                        self.crust_service.drop_node(connection);

                        return
                    }
                };

                if *public_id.name() != ::XorName::new(::sodiumoxide
                                                        ::crypto
                                                        ::hash::sha512::hash(&public_id.signing_public_key().0).0) {
                    warn!("{}Incoming Connection not validated as a proper client - dropping", self.us());
                    self.crust_service.drop_node(connection);
                    return
                }

                if let Some(prev_conn) = self.client_map.insert(public_id.signing_public_key().clone(), connection) {
                    debug!("{}Found previous connection against client key - Dropping {:?}",
                           self.us(), prev_conn);
                    self.crust_service.drop_node(prev_conn);
                }

                let _ = self.bootstrap_identify(connection);
            }
            ::direct_messages::DirectMessage::NodeIdentify { ref serialised_public_id, ref signature } => {
                let public_id = match RoutingNode::verify_signed_public_id(serialised_public_id, signature) {
                    Ok(public_id) => public_id,
                    Err(error) => {
                        warn!("{}Signature check failed in NodeIdentify - Dropping connection {:?}",
                              self.us(), connection);
                        self.crust_service.drop_node(connection);

                        return
                    }
                };

                if let Some(their_public_id) = self.node_id_cache.get(public_id.name()).cloned() {
                    if their_public_id != public_id {
                        warn!("{}Given Public ID and Public ID in cache don't match - Given {:?} :: In cache {:?} \
                               Dropping connection {:?}", self.us(), public_id, their_public_id, connection);

                        self.crust_service.drop_node(connection);
                        return
                    }

                    let node_info = ::kademlia_routing_table::NodeInfo::new(public_id.clone(), vec![connection]);
                    if self.routing_table.has_node(public_id.name()) {
                        if !self.routing_table.add_connection(public_id.name(), connection) {
                            // We already sent an identify down this connection
                            return
                        }
                    } else {
                        let (is_added, node_removed) = self.routing_table.add_node(node_info);

                        if !is_added {
                            debug!("{}Node rejected by Routing table - Closing {:?}", self.us(), connection);
                            self.crust_service.drop_node(connection);
                            let _ = self.node_id_cache.remove(public_id.name());

                            return
                        }

                        if let Some(node_to_drop) = node_removed {
                            debug!("{}Node ejected by routing table on an add. Dropping node {:?}",
                                   self.us(), node_to_drop);

                            for it in node_to_drop.connections.into_iter() {
                                self.crust_service.drop_node(it);
                            }
                        }
                    }

                    let _ = self.node_identify(connection);
                } else {
                    debug!("{}PublicId not found in node_id_cache - Dropping Connection {:?}", self.us(), connection);
                    self.crust_service.drop_node(connection);
                }
            }
            ::direct_messages::DirectMessage::Churn { ref close_group } => {
                // TODO (ben 26/08/2015) verify the signature with the public_id
                // from our routing table.
                self.handle_churn(close_group);
            }
        }
    }

    fn handle_churn(&mut self, close_group: &[::XorName]) {
        debug!("{}CHURN: received {} names", self.us(), close_group.len());
        for close_node in close_group {
            self.refresh_routing_table(close_node);
        }
    }

    // Constructed by A; From A -> X
    fn relocate(&mut self) -> RoutingResult {
        debug!("{}Requesting a network name", self.us());
        debug_assert!(self.state == State::Client);

        let destination_authority = ::authority::Authority::NaeManager(*self.full_id.public_id().name());

        let internal_request = ::messages::InternalRequest::GetNetworkName {
            current_id: self.full_id.public_id().clone(),
        };

        let content = ::messages::Content::InternalRequest(internal_request);
        let routing_message = RoutingMessage {
            source_authority: try!(self.get_client_authority()),
            destination_authority: destination_authority,
            content: content,
            group_keys: None,
        };

        let signed_message = try!(SignedMessage::new(&routing_message, &self.full_id));

        Ok(self.send(signed_message))
    }

    // Received by X; From A -> X
    fn handle_get_network_name_request(&mut self,
                                       opt_token: Option<::messages::SignedRequest>,
                                       mut their_public_id: ::id::PublicId,
                                       request_source: Authority,
                                       request_destination: Authority) -> RoutingResult {
        let signed_request = match opt_token {
            Some(signed_request) => signed_request,
            None => {
                error!("{}Programming Error - Shouldn't be encountered. Investigate",
                       self.us());
                return Err(::error::RoutingError::UnknownMessageType);
            }
        };

        match (&request_source, &request_destination) {
            (&Authority::Client(_bootstrap_node, key), &Authority::NaeManager(name)) => {
                let hashed_key = ::sodiumoxide::crypto::hash::sha512::hash(&key.0);
                let close_group_to_client = XorName::new(hashed_key.0);

                if !(self.name_in_range(&close_group_to_client) && close_group_to_client == name) {
                    // TODO(Spandan) Create a better error
                    return Err(RoutingError::BadAuthority);
                }

                let mut close_group = self.routing_table
                                          .our_close_group()
                                          .iter()
                                          .map(|node_info| node_info.public_id.name().clone())
                                          .collect::<Vec<XorName>>();
                close_group.push(*self.full_id.public_id().name());

                let relocated_name = try!(utils::calculate_relocated_name(close_group,
                                                                          &their_public_id.name()));

                debug!("{}Got a request for network name from {:?}, assigning {:?}",
                       self.us(),
                       request_source,
                       relocated_name);

                their_public_id.set_name(relocated_name.clone());

                // From X -> A (via B)
                {
                    let response = ::messages::InternalResponse::GetNetworkName {
                        relocated_id: their_public_id.clone(),
                        signed_request: signed_request,
                    };

                    let routing_message = RoutingMessage {
                        source_authority: request_destination.clone(),
                        destination_authority: request_source,
                        content: ::messages::Content::InternalResponse(response),
                        group_keys: None,
                    };

                    let signed_message = try!(SignedMessage::new(&routing_message, &self.full_id));
                    self.send(signed_message);
                }

                // From X -> Y; Send to close group of the relocated name
                {
                    let request = ::messages::InternalRequest::ExpectCloseNode {
                        expect_id: their_public_id.clone(),
                    };

                    let routing_message = RoutingMessage {
                        source_authority: request_destination,
                        destination_authority: Authority::NodeManager(relocated_name),
                        content: ::messages::Content::InternalRequest(request),
                        group_keys: None,
                    };

                    let signed_message = try!(SignedMessage::new(&routing_message, &self.full_id));

                    Ok(self.send(signed_message))
                }
            }
            _ => Err(RoutingError::BadAuthority),
        }
    }

    // Received by Y; From X -> Y
    fn handle_expect_close_node_request(&mut self,
                                        opt_token: Option<::messages::SignedRequest>,
                                        expect_id: ::id::PublicId)
                                        -> RoutingResult {
        trace!("{}[fn handle_expect_close_node_request]", self.us());

        if opt_token.is_some() {
            error!("{}Programming Error - Shouldn't be encountered. Investigate",
                   self.us());
            return Err(::error::RoutingError::UnknownMessageType);
        }

        if let Some(prev_id) = self.node_id_cache.insert(*expect_id.name(), expect_id) {
            warn!("{}Previous id {:?} with same name found during \
                   handle_expect_close_node_request. Ignoring that",
                  self.us(),
                  prev_id);
        }

        Ok(())
    }

    // Received by A; From X -> A
    fn handle_get_network_name_response(&mut self,
                                        relocated_id: ::id::PublicId,
                                        signed_request: ::messages::SignedRequest)
                                        -> RoutingResult {
        trace!("{}[fn handle_get_network_name_response]", self.us());

        let signed_message = SignedMessage::from_signed_request(signed_request.clone(),
                                                                self.full_id
                                                                    .public_id()
                                                                    .signing_public_key()
                                                                    .clone());
        let routing_message = try!(signed_message.get_routing_message());

        match routing_message.content {
            Content::InternalRequest(InternalRequest::GetNetworkName { current_id, }) => {
                if *self.full_id.public_id() != current_id {
                    return Err(RoutingError::BadAuthority);
                }

                self.assign_network_name(*relocated_id.name());

                // From A -> Y
                let source_authority = try!(self.get_client_authority());

                let request = ::messages::InternalRequest::GetCloseGroup;

                let routing_msg = ::messages::RoutingMessage {
                    source_authority: source_authority,
                    destination_authority: ::authority::Authority::NodeManager(*relocated_id.name()),
                    content: ::messages::Content::InternalRequest(request),
                    group_keys: None,
                };

                let signed_msg = try!(::messages::SignedMessage::new(&routing_msg, &self.full_id));

                Ok(self.send(signed_msg))
            }
            _ => Err(RoutingError::UnknownMessageType),
        }
    }

    // Received by Y; From A -> Y
    fn handle_get_close_group_request(&mut self,
                                      opt_token: Option<::messages::SignedRequest>,
                                      request_source: ::authority::Authority,
                                      request_destination: ::authority::Authority)
                                      -> RoutingResult {
        let signed_request = match opt_token {
            Some(signed_request) => signed_request,
            None => {
                error!("{}Programming Error - Shouldn't be encountered. Investigate",
                       self.us());
                return Err(::error::RoutingError::UnknownMessageType);
            }
        };

        let mut public_ids: Vec<PublicId> = self.routing_table
                                                .our_close_group()
                                                .into_iter()
                                                .map(|node_info| node_info.public_id)
                                                .collect();

        // Also add our own full_id to the close_group list getting sent
        public_ids.push(self.full_id.public_id().clone());

        let response = ::messages::InternalResponse::GetCloseGroup {
            close_group_ids: public_ids,
            signed_request: signed_request,
        };

        let routing_message = ::messages::RoutingMessage {
            source_authority: request_destination,
            destination_authority: request_source,
            content: ::messages::Content::InternalResponse(response),
            group_keys: None,
        };

        let signed_message = try!(::messages::SignedMessage::new(&routing_message, &self.full_id));

        Ok(self.send(signed_message))
    }

    // Received by A; From Y -> A
    fn handle_get_close_group_response(&mut self,
                                       response_destination: ::authority::Authority,
                                       close_group_ids: Vec<::id::PublicId>,
                                       signed_request: ::messages::SignedRequest)
                                       -> RoutingResult {
        trace!("{}[fn handle_get_close_group_response]", self.us());

        self.start_listening();

        let signed_message = SignedMessage::from_signed_request(signed_request.clone(),
                                                                self.full_id
                                                                    .public_id()
                                                                    .signing_public_key()
                                                                    .clone());
        let routing_message = try!(signed_message.get_routing_message());

        // From A -> Each in Y
        for peer_id in close_group_ids {
            try!(self.send_endpoints(&peer_id,
                                     response_destination.clone(),
                                     ::authority::Authority::ManagedNode(*peer_id.name())));

            if let Some(prev_id) = self.node_id_cache.insert(*peer_id.name(), peer_id) {
                debug!("{}Previously added ID {:?} was removed from node_id_cache",
                       self.us(),
                       prev_id);
            }
        }

        Ok(())
    }

    fn send_endpoints(&mut self,
                      their_public_id: &::id::PublicId,
                      source_authority: ::authority::Authority,
                      destination_authority: ::authority::Authority)
                      -> RoutingResult {
        // TODO(Brian) validate accepting_on has valid entries in future
        let encoded_endpoints =
            try!(::maidsafe_utilities::serialisation::serialise(&self.accepting_on));
        let nonce = ::sodiumoxide::crypto::box_::gen_nonce();
        let encrypted_endpoints =
            ::sodiumoxide::crypto::box_::seal(&encoded_endpoints,
                                              &nonce,
                                              their_public_id.encrypting_public_key(),
                                              self.full_id.encrypting_private_key());

        let request = ::messages::InternalRequest::Endpoints {
            encrypted_endpoints: encrypted_endpoints,
            nonce_bytes: nonce.0,
        };

        let routing_message = ::messages::RoutingMessage {
            source_authority: source_authority,
            destination_authority: destination_authority,
            content: ::messages::Content::InternalRequest(request),
            group_keys: None,
        };

        let signed_message = try!(::messages::SignedMessage::new(&routing_message, &self.full_id));

        Ok(self.send(signed_message))
    }

    fn handle_endpoints(&mut self,
                        opt_token: Option<::messages::SignedRequest>,
                        encrypted_endpoints: Vec<u8>,
                        nonce_bytes: [u8; ::sodiumoxide::crypto::box_::NONCEBYTES],
                        request_source: ::authority::Authority,
                        request_destination: ::authority::Authority)
                        -> RoutingResult {
        let signed_request = match opt_token {
            Some(signed_request) => signed_request,
            None => {
                error!("{}Programming Error - Shouldn't be encountered. Investigate",
                       self.us());
                return Err(::error::RoutingError::UnknownMessageType);
            }
        };

        match request_source {
            ::authority::Authority::Client(_bootstrap_node, public_key) => {
                self.handle_endpoints_from_client(encrypted_endpoints,
                                                  nonce_bytes,
                                                  public_key,
                                                  request_source,
                                                  request_destination,
                                                  signed_request)
            }
            ::authority::Authority::ManagedNode(name) => {
                self.handle_endpoints_from_node(encrypted_endpoints,
                                                nonce_bytes,
                                                request_source,
                                                request_destination,
                                                signed_request)
            }
            _ => {
                warn!("{}Invalid authority for handle_endpoints", self.us());
                Err(::error::RoutingError::BadAuthority)
            }
        }
    }

    fn handle_endpoints_from_client(&mut self,
                                    encrypted_endpoints: Vec<u8>,
                                    nonce_bytes: [u8; ::sodiumoxide::crypto::box_::NONCEBYTES],
                                    client_key: ::sodiumoxide::crypto::sign::PublicKey,
                                    request_source: ::authority::Authority,
                                    request_destination: ::authority::Authority,
                                    signed_request: ::messages::SignedRequest)
                                    -> RoutingResult {
        match self.node_id_cache
                  .retrieve_all()
                  .iter()
                  .find(|elt| *elt.1.signing_public_key() == client_key) {
            Some(&(ref name, ref their_public_id)) => {
                if self.routing_table.want_to_add(&name) {
                    try!(self.connect(encrypted_endpoints,
                                      nonce_bytes,
                                      their_public_id.encrypting_public_key()));
                    self.send_endpoints(their_public_id, request_destination, request_source)
                } else {
                    debug!("{}No longer want to connect to relocating node although present in \
                            our node_id_cache",
                           self.us());

                    Err(RoutingError::RefusedFromRoutingTable)
                }
            }
            None => {
                debug!("{}Key was not previously cached. Ignoring Endpoint request from unknown \
                        relocating node",
                       self.us());
                Err(RoutingError::RejectedPublicId)
            }
        }
    }

    fn handle_endpoints_from_node(&mut self,
                                  encrypted_endpoints: Vec<u8>,
                                  nonce_bytes: [u8; ::sodiumoxide::crypto::box_::NONCEBYTES],
                                  request_source: ::authority::Authority,
                                  request_destination: ::authority::Authority,
                                  signed_request: ::messages::SignedRequest) -> RoutingResult {
        let name = request_source.get_location();
        if self.routing_table.want_to_add(name) {
            if let Some(their_public_id) = self.node_id_cache.get(name).cloned() {
                self.connect(encrypted_endpoints,
                             nonce_bytes,
                             their_public_id.encrypting_public_key())
            } else if let ::authority::Authority::Client(..) = request_destination {
                Err(RoutingError::RejectedPublicId)
            } else {
                let request = ::messages::InternalRequest::GetPublicIdWithEndpoints {
                    encrypted_endpoints: encrypted_endpoints,
                    nonce_bytes: nonce_bytes,
                };

                let routing_message = ::messages::RoutingMessage {
                    source_authority: ::authority::Authority::ManagedNode(self.full_id
                                                                    .public_id()
                                                                    .name()
                                                                    .clone()),
                    destination_authority: ::authority::Authority::NodeManager(name.clone()),
                    content: ::messages::Content::InternalRequest(request),
                    group_keys: None,
                };

                let signed_message = try!(SignedMessage::new(&routing_message, &self.full_id));

                Ok(self.send(signed_message))
            }
        } else {
            debug!("{}No longer want to connect to node although present in our node_id_cache",
                   self.us());
            let _ = self.node_id_cache.remove(name);

            Err(RoutingError::RefusedFromRoutingTable)
        }
    }

    // ---- Connect Requests and Responses --------------------------------------------------------

    /// Scan all passing messages for the existence of nodes in the address space.  If a node is
    /// detected with a name that would improve our routing table, then try to connect.  We ignore
    /// all re-occurrences of this name for one second if we make the attempt to connect.
    fn refresh_routing_table(&mut self, from_node: &XorName) {
        if !self.connection_filter.check(from_node) {
            if self.routing_table.want_to_add(from_node) {
                debug!("{}Refresh routing table for peer {:?}",
                       self.us(),
                       from_node);
                match self.send_connect_request(from_node) {
                    Ok(()) => debug!("{}Sent connect request to {:?}", self.us(), from_node),
                    Err(error) => {
                        error!("{}Failed to send connect request to {:?} - {:?}",
                               self.us(),
                               from_node,
                               error)
                    }
                }
            }
            self.connection_filter.add(from_node.clone());
        }
    }

    fn send_connect_request(&mut self, peer_name: &XorName) -> RoutingResult {
        let request = ::messages::InternalRequest::Connect;

        let routing_message = ::messages::RoutingMessage {
            source_authority: ::authority::Authority::ManagedNode(self.full_id.public_id().name().clone()),
            destination_authority: ::authority::Authority::ManagedNode(peer_name.clone()),
            content: ::messages::Content::InternalRequest(request),
            group_keys: None,
        };

        let signed_message = try!(SignedMessage::new(&routing_message, &self.full_id));

        Ok(self.send(signed_message))
    }

    fn handle_connect_request(&mut self,
                              opt_token: Option<::messages::SignedRequest>,
                              name: ::XorName)
                              -> RoutingResult {
        trace!("{}Handle ConnectRequest", self.us());

        if opt_token.is_none() {
            // Carry on because presence of this signed_request would not have affected our flow of
            // messages, but log it as a programming error because we should have got it.
            error!("{}Programming Error - Shouldn't be encountered. Investigate",
                   self.us());
        }

        if !self.routing_table.want_to_add(&name) {
            debug!("{}Connect request failed - Don't want to add", self.us());
            return Err(RoutingError::RefusedFromRoutingTable);
        }

        // TODO(Spandan) Update get in LRU to refresh the time to live and use only get()
        if let Some(public_id) = self.node_id_cache.remove(&name) {
            let source_authority = ::authority::Authority::ManagedNode(self.full_id
                                                                 .public_id()
                                                                 .name()
                                                                 .clone());
            try!(self.send_endpoints(&public_id,
                                     source_authority,
                                     ::authority::Authority::ManagedNode(name.clone())));
            let _ = self.node_id_cache.insert(name, public_id.clone());

            return Ok(());
        }

        let request = ::messages::InternalRequest::GetPublicId;

        let routing_message = ::messages::RoutingMessage {
            source_authority: ::authority::Authority::ManagedNode(self.full_id.public_id().name().clone()),
            destination_authority: ::authority::Authority::NodeManager(name),
            content: ::messages::Content::InternalRequest(request),
            group_keys: None,
        };

        let signed_message = try!(SignedMessage::new(&routing_message, &self.full_id));

        Ok(self.send(signed_message))
    }

    fn send_public_id_for_close_node(&mut self,
                                     response: ::messages::InternalResponse,
                                     from_name: ::XorName,
                                     to_name: ::XorName)
                                     -> RoutingResult {
        let routing_message = ::messages::RoutingMessage {
            source_authority: ::authority::Authority::NodeManager(to_name),
            destination_authority: ::authority::Authority::ManagedNode(from_name),
            content: ::messages::Content::InternalResponse(response),
            group_keys: None,
        };

        let signed_message = try!(SignedMessage::new(&routing_message, &self.full_id));

        Ok(self.send(signed_message))
    }

    fn handle_get_public_id(&mut self,
                            opt_token: Option<::messages::SignedRequest>,
                            from_name: ::XorName,
                            to_name: ::XorName)
                            -> RoutingResult {
        trace!("{}Handle get public id", self.us());

        let signed_request = match opt_token {
            Some(signed_request) => signed_request,
            None => {
                error!("{}Programming Error - Shouldn't be encountered. Investigate",
                       self.us());
                return Err(::error::RoutingError::UnknownMessageType);
            }
        };

        if let Some(node_info) = self.routing_table
                                     .our_close_group()
                                     .into_iter()
                                     .find(|elt| *elt.name() == to_name) {
            let response = ::messages::InternalResponse::GetPublicId {
                public_id: node_info.public_id,
                signed_request: signed_request,
            };

            self.send_public_id_for_close_node(response, from_name, to_name)
        } else {
            debug!("{}Node not found in the close group. Unable to retrieve PublicId",
                   self.us());
            // TODO Invent error for this
            Err(::error::RoutingError::RejectedPublicId)
        }
    }

    fn handle_get_public_id_response(&mut self,
                                     public_id: ::id::PublicId,
                                     signed_request: ::messages::SignedRequest)
                                     -> RoutingResult {
        let orig_signed_message =
            ::messages::SignedMessage::from_signed_request(signed_request,
                                                           self.full_id
                                                               .public_id()
                                                               .signing_public_key()
                                                               .clone());
        let orig_routing_message = try!(orig_signed_message.get_routing_message());

        if ::messages::Content::InternalRequest(::messages::InternalRequest::GetPublicId) !=
           orig_routing_message.content {
            // TODO Invent error for this
            return Err(::error::RoutingError::BadAuthority);
        }

        if !self.routing_table.want_to_add(public_id.name()) {
            debug!("{}No longer want to add {:?} to routing table",
                   self.us(),
                   public_id);
            return Err(::error::RoutingError::RefusedFromRoutingTable);
        }

        try!(self.send_endpoints(&public_id,
                                 orig_routing_message.source_authority,
                                 ::authority::Authority::ManagedNode(public_id.name().clone())));
        let _ = self.node_id_cache.insert(public_id.name().clone(), public_id);

        Ok(())
    }

    fn handle_get_public_id_with_endpoints(&mut self,
                                           opt_token: Option<::messages::SignedRequest>,
                                           from_name: ::XorName,
                                           to_name: ::XorName)
                                           -> RoutingResult {
        trace!("{}Handle get public id with endpoints", self.us());

        let signed_request = match opt_token {
            Some(signed_request) => signed_request,
            None => {
                error!("{}Programming Error - Shouldn't be encountered. Investigate",
                       self.us());
                return Err(::error::RoutingError::UnknownMessageType);
            }
        };

        if let Some(node_info) = self.routing_table
                                     .our_close_group()
                                     .into_iter()
                                     .find(|elt| *elt.name() == to_name) {
            let response = ::messages::InternalResponse::GetPublicIdWithEndpoints {
                public_id: node_info.public_id,
                signed_request: signed_request,
            };

            self.send_public_id_for_close_node(response, from_name, to_name)
        } else {
            debug!("{}Node not found in the close group. Unable to retrieve PublicId",
                   self.us());
            // TODO Invent error for this
            Err(::error::RoutingError::RejectedPublicId)
        }
    }

    fn handle_get_public_id_with_endpoints_response(&mut self,
                                                    public_id: ::id::PublicId,
                                                    signed_request: ::messages::SignedRequest)
                                                    -> RoutingResult {
        let orig_signed_message =
            ::messages::SignedMessage::from_signed_request(signed_request,
                                                           self.full_id
                                                               .public_id()
                                                               .signing_public_key()
                                                               .clone());
        let orig_routing_message = try!(orig_signed_message.get_routing_message());

        // TODO Can be better ?
        let (encrypted_endpoints, nonce_bytes) = if let ::messages
                                                        ::Content
                                                        ::InternalRequest(::messages
                                                                          ::InternalRequest
                                                                          ::GetPublicIdWithEndpoints {
                                                                              encrypted_endpoints,
                                                                              nonce_bytes,
                                                                          }) = orig_routing_message.content {
            (encrypted_endpoints, nonce_bytes)
        } else {
        // TODO Invent error for this
            return Err(::error::RoutingError::BadAuthority)
        };

        let nonce = ::sodiumoxide::crypto::box_::Nonce(nonce_bytes);
        let decrypt_result = ::sodiumoxide::crypto::box_::open(&encrypted_endpoints,
                                                               &nonce,
                                                               public_id.encrypting_public_key(),
                                                               self.full_id
                                                                   .encrypting_private_key());
        let serialised_endpoints = try!(decrypt_result.map_err(|()| {
            ::error::RoutingError::AsymmetricDecryptionFailure
        }));

        if !self.routing_table.want_to_add(public_id.name()) {
            debug!("{}No longer want to add {:?} to routing table",
                   self.us(),
                   public_id);
            return Err(::error::RoutingError::RefusedFromRoutingTable);
        }

        try!(self.send_endpoints(&public_id,
                                 orig_routing_message.source_authority,
                                 ::authority::Authority::ManagedNode(public_id.name().clone())));
        let _ = self.node_id_cache.insert(public_id.name().clone(), public_id);

        Ok(())
    }

    fn connect(&mut self,
               encrypted_endpoints: Vec<u8>,
               nonce_bytes: [u8; ::sodiumoxide::crypto::box_::NONCEBYTES],
               their_public_key: &::sodiumoxide::crypto::box_::PublicKey)
               -> RoutingResult {
        let decipher_result =
            ::sodiumoxide::crypto::box_::open(&encrypted_endpoints,
                                              &::sodiumoxide::crypto::box_::Nonce(nonce_bytes),
                                              their_public_key,
                                              self.full_id.encrypting_private_key());

        let serialised_endpoints = try!(decipher_result.map_err(|()| {
            ::error::RoutingError::AsymmetricDecryptionFailure
        }));
        let endpoints =
            try!(::maidsafe_utilities::serialisation::deserialise(&serialised_endpoints));

        debug!("{}Connect: requesting crust connect to {:?}",
               self.us(),
               endpoints);
        self.crust_service.connect(self.connection_counter, endpoints);

        self.connection_counter = self.connection_counter.wrapping_add(1u32);

        // 0 is reserved for Bootstrap
        if self.connection_counter == 0u32 {
            self.connection_counter = 1u32;
        }

        Ok(())
    }

    // ----- Send Functions -----------------------------------------------------------------------

    fn send_to_user(&self, event: Event) {
        debug!("{}Send to user event {:?}", self.us(), event);
        if self.event_sender.send(event).is_err() {
            error!("{}Channel to user is broken;", self.us());
        }
    }

    fn send_content(&mut self,
                    source_authority: Authority,
                    destination_authority: Authority,
                    content: Content) -> RoutingResult {
        let routing_message = RoutingMessage {
            source_authority: source_authority,
            destination_authority: destination_authority,
            content: content,
            group_keys: None,
        };

        let signed_message = try!(SignedMessage::new(&routing_message, &self.full_id));

        Ok(self.send(signed_message))
    }

    fn client_send_content(&mut self, destination_authority: Authority, content: Content) {
        match self.get_client_authority() {
            Ok(client_authority) => {
                let routing_message = RoutingMessage {
                    source_authority: client_authority,
                    destination_authority: destination_authority.clone(),
                    content: content.clone(),
                    group_keys: None,
                };

                match SignedMessage::new(&routing_message, &self.full_id) {
                    Ok(signed_message) => self.send(signed_message),
                    // FIXME (ben 24/08/2015) find an elegant way to give the message back to user
                    Err(error) => {
                        self.send_failed_message_to_user(destination_authority, content);
                        error!("{}Failed to serialise signed message: {:?}",
                               self.us(),
                               error);
                    }
                };
            }
            Err(_) => {
                self.send_failed_message_to_user(destination_authority, content);
                error!("{}Failed to get a client authority", self.us());
            }
        }
    }

    fn send_failed_message_to_user(&self, destination_authority: Authority, content: Content) {
        match content {
            Content::ExternalRequest(external_request) => {
                self.send_to_user(Event::FailedRequest {
                    request: external_request,
                    our_authority: None,
                    location: destination_authority,
                    interface_error: InterfaceError::NotConnected,
                });
            }
            Content::ExternalResponse(external_response) => {
                self.send_to_user(Event::FailedResponse {
                    response: external_response,
                    our_authority: None,
                    location: destination_authority,
                    interface_error: InterfaceError::NotConnected,
                });
            }
            _ => {
                error!("{}InternalRequest/Response was sent back to user {:?}",
                       self.us(),
                       content)
            }
        }
    }

    /// Send a SignedMessage out to the destination
    /// 1. if it can be directly sent to a Client, then it will
    /// 2. if we can forward it to nodes closer to the destination, it will be sent in parallel
    /// 3. if the destination is in range for us, then send it to all our close group nodes
    /// 4. if all the above failed, try sending it over all available bootstrap connections
    /// 5. finally, if we are a node and the message concerns us, queue it for processing later.
    fn send(&mut self, signed_message: SignedMessage) {
        let message = match signed_message.get_routing_message() {
            Ok(routing_message) => routing_message,
            Err(error) => {
                debug!("{}Signature failed. {:?}", self.us(), error);
                return;
            }
        };

        let destination_authority = message.destination_authority;
        debug!("{}Send request to {:?}", self.us(), destination_authority);
        let bytes = match encode(&signed_message) {
            Ok(bytes) => bytes,
            Err(error) => {
                error!("{}Failed to serialise {:?} - {:?}",
                       self.us(),
                       signed_message,
                       error);
                return;
            }
        };

        // If we're a client going to be a node, send via our bootstrap connection
        if self.state == State::Client {
            let bootstrap_connections: Vec<&::crust::Connection> = self.proxy_map.keys().collect();
            if bootstrap_connections.is_empty() {
                unreachable!("{}Target connections for send is empty", self.us());
            }
            for connection in bootstrap_connections {
                self.crust_service.send(connection.clone(), bytes.clone());
                debug!("{}Sent {:?} to bootstrap connection {:?}",
                       self.us(),
                       signed_message,
                       connection);
            }
            return;
        }

        // Handle if we have a client connection as the destination_authority
        if let Authority::Client(_, ref client_public_key) = destination_authority {
            debug!("{}Looking for client target {:?}", self.us(),
                   ::XorName::new(
                       ::sodiumoxide::crypto::hash::sha512::hash(&client_public_key[..]).0));
            if let Some(client_connection) = self.client_map.get(client_public_key) {
                self.crust_service.send(client_connection.clone(), bytes);
            } else {
                warn!("{}Failed to find client contact for {:?}", self.us(),
                      ::XorName::new(
                          ::sodiumoxide::crypto::hash::sha512::hash(&client_public_key[..]).0));
            }
            return;
        }

        // Query routing table to send it out parallel or to our close group (ourselves excluded)
        let targets = self.routing_table.target_nodes(destination_authority.get_location());
        targets.iter().all(|node_info| {
            node_info.connections.iter().all(|connection| {
                self.crust_service.send(connection.clone(), bytes.clone());
                true
            })
        });

        // If we need to handle this message, handle it.
        if self.name_in_range(destination_authority.get_location()) {
            if let Err(error) = self.handle_routing_message(signed_message) {
                error!("{}Failed to handle message ourself: {:?}", self.us(), error)
            }
        }
    }

    // ----- Message Handlers that return to the event channel ------------------------------------

    fn handle_external_response(&mut self,
                                response: ExternalResponse,
                                response_destination_authority: Authority,
                                response_source_authority: Authority)
                                -> RoutingResult {

        // Request token is only set if it came from a non-group entity.
        // If it came from a group, then sentinel guarantees message validity.
        if let Some(ref token) = *response.get_signed_token() {
            let signed_message = SignedMessage::from_signed_request(token.clone(),
                                                                    self.full_id
                                                                        .public_id()
                                                                        .signing_public_key()
                                                                        .clone());
            let _ = try!(signed_message.get_routing_message());
        } else {
            if !self.name_in_range(response_destination_authority.get_location()) {
                return Err(RoutingError::BadAuthority);
            };
        };

        self.send_to_user(Event::Response {
            response: response,
            our_authority: response_destination_authority,
            from_authority: response_source_authority,
        });

        Ok(())
    }

    fn handle_refresh(&mut self,
                      type_tag: u64,
                      sender: XorName,
                      payload: Vec<u8>,
                      our_authority: Authority,
                      cause: ::XorName)
                      -> RoutingResult {
        debug_assert!(our_authority.is_group());
        let threshold = self.routing_table.dynamic_quorum_size();
        let unknown_cause = !self.refresh_causes.check(&cause);
        let (is_new_request, payloads) = self.refresh_accumulator
                                             .add_message(threshold,
                                                          type_tag.clone(),
                                                          sender,
                                                          our_authority.clone(),
                                                          payload,
                                                          cause);
        // If this is a new refresh instance, notify user to perform refresh.
        if unknown_cause && is_new_request {
            let _ = self.event_sender.send(::event::Event::DoRefresh(type_tag,
                                                                     our_authority.clone(),
                                                                     cause.clone()));
        }
        match payloads {
            Some(payloads) => {
                let _ = self.event_sender.send(Event::Refresh(type_tag, our_authority, payloads));
                Ok(())
            }
            None => Err(::error::RoutingError::NotEnoughSignatures),
        }
    }

    fn get_client_authority(&self) -> Result<Authority, RoutingError> {
        match self.proxy_map.iter().next() {
            Some(bootstrap_name) => {
                Ok(Authority::Client(bootstrap_name.1.clone(),
                                     *self.full_id.public_id().signing_public_key()))
            }
            None => Err(RoutingError::NotBootstrapped),
        }
    }


    // Returns our name and state for logging
    fn us(&self) -> String {
        format!("{:?}({:?}) - ", self.state, self.full_id.public_id().name())
    }

    /// Returns true if Client(public_key) matches our public signing key, even if we are a full
    /// node; or returns true if Node(name) is our current name.  Note that there is a difference to
    /// using core::us, as that would fail to assert an (old) Client identification after
    /// we were assigned a network name.
    pub fn is_us(&self, address: &Address) -> bool {
        match *address {
            Address::Client(public_key) => {
                public_key == *self.full_id.public_id().signing_public_key()
            }
            Address::Node(name) => name == *self.full_id.public_id().name(),
        }
    }

    /// Returns a borrow of the current state
    pub fn state(&self) -> &State {
        &self.state
    }

    /// Assigning a network received name to the core.  If a name is already assigned, the function
    /// returns false and no action is taken.  After a name is assigned, Routing connections can be
    /// accepted.
    fn assign_network_name(&mut self, new_name: ::XorName) {
        match self.state {
            State::Disconnected | State::Client => {
                debug!("{}Assigning name {:?}", self.us(), new_name)
            }
            _ => unreachable!("{}This should not be called", self.us()),
        }

        debug!("{}Re-creating routing table after relocation", self.us());
        self.routing_table = RoutingTable::new(&new_name);
        self.full_id.public_id_mut().set_name(new_name);
    }

    /// check client_map for a client and remove from map
    fn dropped_client_connection(&mut self, connection: &::crust::Connection) {
        let public_key = self.client_map
                             .iter()
                             .find(|&(_, client)| client == connection)
                             .map(|entry| entry.0.clone());
        if let Some(public_key) = public_key {
            let _ = self.client_map.remove(&public_key);
        }
    }

    fn dropped_bootstrap_connection(&mut self, connection: &::crust::Connection) {
        let _ = self.proxy_map.remove(connection);
    }

    fn dropped_routing_node_connection(&mut self, connection: &::crust::Connection) {
        if let Some(node_name) = self.routing_table.drop_connection(connection) {
            for _node in &self.routing_table.our_close_group() {
                // trigger churn
                // if close node
            }
            self.routing_table.drop_node(&node_name);
        }
    }

    // Add a client to our client map
    fn add_client(&mut self, connection: crust::Connection, public_id: PublicId) {
        if self.client_map.len() == MAX_RELAYS {
            warn!("{}Client map full ({} connections) so won't add {:?} to the client map - \
                   dropping {:?}",
                  self.us(),
                  MAX_RELAYS,
                  public_id,
                  connection);
            self.drop_crust_connection(connection);
        }

        match self.client_map.insert(public_id.signing_public_key().clone(), connection) {
            Some(old_connection) => {
                warn!("{}Found existing entry {:?} for {:?} found while adding to client map",
                      self.us(),
                      old_connection,
                      public_id);
                self.drop_crust_connection(old_connection);
            }
            None => {
                debug!("{}Added client {:?} to client map; {:?}",
                       self.us(),
                       public_id,
                       connection)
            }
        }
    }

    // Add a node to our routing table.
    fn add_node(&mut self, connection: crust::Connection, public_id: PublicId) {
        let peer_name = public_id.name().clone();

        if self.routing_table.has_node(&peer_name) {
            let _ = self.routing_table.add_connection(&peer_name, connection);
            return;
        }

        let connection_clone = connection.clone();
        let node_info = NodeInfo::new(public_id, vec![connection]);
        let should_trigger_churn = self.name_in_range(node_info.name());
        let add_node_result = self.routing_table.add_node(node_info);

        match add_node_result.1 {
            Some(node) => {
                for connection in node.connections {
                    self.drop_crust_connection(connection);
                }
            }
            None => {
                info!("{}No node removed from RT as a result of node addition",
                      self.us())
            }
        }

        if !add_node_result.0 {
            debug!("{}Failed to add {:?} to the routing table - dropping {:?}",
                   self.us(),
                   peer_name,
                   connection_clone);
            self.drop_crust_connection(connection_clone);
            return;
        }

        if self.routing_table.len() == 1 {
            self.state = State::Node;
        } else if self.routing_table.len() == ::kademlia_routing_table::group_size() {
            info!("{}Routing Node has connected to {} nodes",
                  self.us(),
                  self.routing_table.len());
            if let Err(err) = self.event_sender.send(Event::Connected) {
                error!("{}Error sending {:?} to event_sender", self.us(), err.0);
            }
            // Drop the bootstrap connections
            for (connection, _) in self.proxy_map.clone().into_iter() {
                info!("{}Dropping bootstrap connection {:?}",
                      self.us(),
                      connection);
                self.drop_crust_connection(connection);
            }
            self.proxy_map = ::std::collections::HashMap::new();
        }

        if should_trigger_churn {
            if let Err(err) = self.trigger_churn() {
                warn!("{}Churn failed - {:?}", self.us(), err);
            }
        }
    }

    fn trigger_churn(&mut self) -> RoutingResult {
        let target_group = self.routing_table.target_nodes(self.full_id.public_id().name());
        let target_group_connections = target_group.iter()
                                                   .flat_map(|node_info| {
                                                       node_info.connections.iter().cloned()
                                                   })
                                                   .collect::<Vec<_>>();

        let mut close_group: Vec<::XorName> = target_group.iter()
                                                          .map(|node_info| {
                                                              node_info.name().clone()
                                                          })
                                                          .collect();

        close_group.push(self.full_id.public_id().name().clone());

        let churn_message = ::direct_messages::DirectMessage::Churn {
            close_group: close_group.clone(),
        };

        // send Churn to all our close group nodes
        let bytes = try!(::maidsafe_utilities::serialisation::serialise(&churn_message));
        for endpoint in target_group_connections {
            self.crust_service.send(endpoint, bytes.clone());
        }

        // notify the user
        let _ = self.event_sender.send(::event::Event::Churn(close_group));

        Ok(())
    }

    /// Returns true if a name is in range for our close group.
    /// If the core is not a full node, this always returns false.
    pub fn name_in_range(&self, name: &XorName) -> bool {
        self.routing_table.is_close(name)
    }

    /// Our authority is defined by the routing message, if we are a full node;  if we are a client,
    /// this always returns Client authority (where the proxy name is taken from the routing message
    /// destination_authority)
    pub fn our_authority(&self, message: &RoutingMessage) -> Option<Authority> {
        if self.state == State::Node {
            our_authority(message, &self.routing_table)
        } else {
            // if the message reached us as a client, then destination_authority.get_location()
            // was our proxy's name
            Some(Authority::Client(message.destination_authority.get_location().clone(),
                                   *self.full_id.public_id().signing_public_key()))
        }
    }

    fn drop_crust_connection(&mut self, connection: ::crust::Connection) {
        debug!("{}Dropping Crust Connection - {:?}", self.us(), connection);
        self.crust_service.drop_node(connection);
        self.handle_lost_connection(connection);
    }
}

//
// #[cfg(test)]
// mod test {
// use action::Action;
// use data::{Data, DataRequest};
// use event::Event;
// use immutable_data::{ImmutableData, ImmutableDataType};
// use messages::{ExternalRequest, ExternalResponse, RoutingMessage, Content};
// use rand::{thread_rng, Rng};
// use std::sync::mpsc;
// use super::RoutingNode;
// use XorName;
// use authority::Authority;
// use data_cache_options::DataCacheOptions;
//
// fn create_routing_node() -> RoutingNode {
//    let (action_sender, action_receiver) = mpsc::channel::<Action>();
//    let (event_sender, _) = mpsc::channel::<Event>();
//    RoutingNode::new(action_sender.clone(),
//                     action_receiver,
//                     event_sender,
//                     false,
//                     None)
// }
//
// RoutingMessage's for ImmutableData Get request/response.
// fn generate_routing_messages() -> (RoutingMessage, RoutingMessage) {
// let mut data = [0u8; 64];
// thread_rng().fill_bytes(&mut data);
//
// let immutable = ImmutableData::new(ImmutableDataType::Normal,
// data.iter().cloned().collect());
// let immutable_data = Data::ImmutableData(immutable.clone());
// let data_request = DataRequest::ImmutableData(immutable.name().clone(),
// immutable.get_type_tag().clone());
// let request = ExternalRequest::Get(data_request.clone(), 0u8);
// let response = ExternalResponse::Get(immutable_data, data_request, None);
//
// let routing_message_request = RoutingMessage {
// source_authority: Authority::ClientManager(XorName::new([1u8; 64])),
// destination_authority: Authority::NaeManager(XorName::new(data)),
// content: Content::ExternalRequest(request),
// group_keys: None,
// };
//
// let routing_message_response = RoutingMessage {
// source_authority: Authority::NaeManager(XorName::new(data)),
// destination_authority: Authority::ClientManager(XorName::new([1u8; 64])),
// content: Content::ExternalResponse(response),
// group_keys: None,
// };
//
// (routing_message_request, routing_message_response)
// }
//
// #[test]
// fn no_caching() {
// let mut node = create_routing_node();
// Get request/response RoutingMessage's for ImmutableData.
// let (message_request, message_response) = generate_routing_messages();
//
// assert!(node.data_cache.handle_cache_get(&message_request).is_none());
// node.data_cache.handle_cache_put(&message_response);
// assert!(node.data_cache.handle_cache_get(&message_request).is_none());
// }
//
// #[test]
// fn enable_immutable_data_caching() {
// let mut node = create_routing_node();
// Enable caching for ImmutableData, disable for other Data types.
// let cache_options = DataCacheOptions::with_caching(false, false, true);
// let _ = node.data_cache.set_cache_options(cache_options);
// Get request/response RoutingMessage's for ImmutableData.
// let (message_request, message_response) = generate_routing_messages();
//
// assert!(node.data_cache.handle_cache_get(&message_request).is_none());
// node.data_cache.handle_cache_put(&message_response);
// assert!(node.data_cache.handle_cache_get(&message_request).is_some());
// }
//
// #[test]
// fn disable_immutable_data_caching() {
// let mut node = create_routing_node();
// Disable caching for ImmutableData, enable for other Data types.
// let cache_options = DataCacheOptions::with_caching(true, true, false);
// let _ = node.data_cache.set_cache_options(cache_options);
// Get request/response RoutingMessage's for ImmutableData.
// let (message_request, message_response) = generate_routing_messages();
//
// assert!(node.data_cache.handle_cache_get(&message_request).is_none());
// node.data_cache.handle_cache_put(&message_response);
// assert!(node.data_cache.handle_cache_get(&message_request).is_none());
// }
// }
//
