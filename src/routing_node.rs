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

use routing_table::{RoutingTable, NodeInfo};

use sodiumoxide::crypto;

use lru_time_cache::LruCache;

use action::Action;
use event::Event;
use NameType;
use id::FullId;
use id::PublicId;
use types::Address;
use utils::{encode, decode};
use utils;
use authority::{Authority, our_authority};

use messages::{RoutingMessage, SignedMessage, SignedRequest,
               Content, ExternalResponse, InternalRequest, InternalResponse};

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
    message_public_key_filter: ::message_filter::MessageFilter<(RoutingMessage,
            ::sodiumoxide::crypto::sign::PublicKey)>,
    connection_filter: ::message_filter::MessageFilter<::NameType>,
    public_id_cache: LruCache<NameType, PublicId>,
    message_accumulator: ::accumulator::Accumulator<RoutingMessage,
            ::sodiumoxide::crypto::sign::PublicKey>,
    refresh_accumulator: ::refresh_accumulator::RefreshAccumulator,
    refresh_causes: ::message_filter::MessageFilter<::NameType>,
    // Messages which have been accumulated and then actioned
    handled_messages: ::message_filter::MessageFilter<RoutingMessage>,
    // cache_options: ::data_cache_options::DataCacheOptions,
    data_cache: ::data_cache::DataCache,

    full_id: FullId,
    state: State,
    network_name: Option<NameType>,
    routing_table: RoutingTable,
    // our bootstrap connections
    proxy_map: ::std::collections::HashMap<::crust::Connection, ::NameType>,
    // any clients we have proxying through us
    client_map: ::std::collections::HashMap<crypto::sign::PublicKey, ::crust::Connection>,
}

impl RoutingNode {
    pub fn new(event_sender: ::std::sync::mpsc::Sender<Event>,
               client_restriction: bool,
               keys: Option<FullId>) -> Result<(::types::RoutingActionSender,
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
                message_public_key_filter: ::message_filter
                                           ::MessageFilter
                                           ::with_expiry_duration(::time::Duration::minutes(20)),
                connection_filter: ::message_filter::MessageFilter::with_expiry_duration(
                    ::time::Duration::seconds(20)),
                public_id_cache: LruCache::with_expiry_duration(::time::Duration::minutes(10)),
                message_accumulator: ::accumulator::Accumulator::with_duration(1,
                    ::time::Duration::minutes(5)),
                refresh_accumulator:
                    ::refresh_accumulator::RefreshAccumulator::with_expiry_duration(
                        ::time::Duration::minutes(5)),
                refresh_causes: ::message_filter::MessageFilter::with_expiry_duration(
                    ::time::Duration::minutes(5)),
                handled_messages: ::message_filter::MessageFilter::with_expiry_duration(
                    ::time::Duration::minutes(20)),
//                cache_options: ::data_cache_options::DataCacheOptions::new(),
                data_cache: ::data_cache::DataCache::new(),
                full_id: full_id,
                state: State::Disconnected,
                network_name: None,
                routing_table: RoutingTable::new(&our_name),
                proxy_map: ::std::collections::HashMap::new(),
                client_map: ::std::collections::HashMap::new(),
            };

            routing_node.run(category_rx);

            debug!("Exiting thread {:?}", ROUTING_NODE_THREAD_NAME);
        });

        Ok((action_sender, ::maidsafe_utilities::thread::RaiiThreadJoiner::new(joiner)))
    }

    pub fn run(&mut self,
               category_rx: ::std::sync::mpsc::Receiver<
                   ::maidsafe_utilities::event_sender::MaidSafeEventCategory>) {
        self.crust_service.bootstrap(0u32, Some(CRUST_DEFAULT_BEACON_PORT));
        debug!("{}RoutingNode started running and started bootstrap", self.us());
        for it in category_rx.iter() {
            if self.state == State::Node {
                trace!("{}Routing Table size: {}", self.us(), self.routing_table.len());
            };
            match it {
                ::maidsafe_utilities::event_sender::MaidSafeEventCategory::RoutingEvent => {
                    if let Ok(action) = self.action_rx.try_recv() {
                        match action {
                            Action::SendContent(our_authority, to_authority, content) => {
                                let _ = self.send_content(our_authority, to_authority, content);
                            },
                            Action::ClientSendContent(to_authority, content) => {
                                debug!("{}ClientSendContent received for {:?}", self.us(), content);
                                self.client_send_content(to_authority, content);
                            },
                            Action::SetDataCacheOptions(cache_options) => {
                                self.data_cache.set_cache_options(cache_options);
                            },
                            Action::Terminate => {
                                debug!("{}routing node terminated", self.us());
                                let _ = self.event_sender.send(Event::Terminated);
                                self.crust_service.stop();
                                break;
                            },
                        }
                    }
                },
                ::maidsafe_utilities::event_sender::MaidSafeEventCategory::CrustEvent => {
                    if let Ok(crust_event) = self.crust_rx.try_recv() {
                        match crust_event {
                            ::crust::Event::BootstrapFinished => self.handle_bootstrap_finished(),
                            ::crust::Event::OnAccept(connection) =>
                                self.handle_on_accept(connection),

                            // TODO (Fraser) This needs to restart if we are left with 0 connections
                            ::crust::Event::LostConnection(connection) =>
                                self.handle_lost_connection(connection),

                            ::crust::Event::NewMessage(connection, bytes) =>
                                self.handle_new_message(connection, bytes),
                            ::crust::Event::OnConnect(connection, connection_token) =>
                                self.handle_on_connect(connection, connection_token),
                            ::crust::Event::ExternalEndpoints(external_endpoints) => {
                                for external_endpoint in external_endpoints {
                                    debug!("{}Adding external endpoint {:?}", self.us(),
                                           external_endpoint);
                                    self.accepting_on.push(external_endpoint);
                                }
                            },
                            ::crust::Event::OnHolePunched(_hole_punch_result) => unimplemented!(),
                            ::crust::Event::OnUdpSocketMapped(_mapped_udp_socket) =>
                                unimplemented!(),
                            ::crust::Event::OnRendezvousConnect(_connection, _response_token) =>
                                unimplemented!(),
                        }
                    }
                },
            } // Category Match
        } // Category Rx
    }

    fn handle_bootstrap_finished(&mut self) {
        debug!("{}Finished bootstrapping.", self.us());
        // If we have no connections, we should start listening to allow incoming connections
        if self.state == State::Disconnected {
            debug!("{}Bootstrap finished with no connections. Start Listening to allow \
                    incoming connections.", self.us());
            self.start_listening();
        }
    }

    fn start_listening(&mut self) {
        match self.crust_service.start_beacon(CRUST_DEFAULT_BEACON_PORT) {
            Ok(port) => info!("{}Running Crust beacon listener on port {}", self.us(), port),
            Err(error) => warn!("{}Crust beacon failed to listen on port {}: {:?}", self.us(),
                                CRUST_DEFAULT_BEACON_PORT, error),
        }
        match self.crust_service.start_accepting(CRUST_DEFAULT_TCP_ACCEPTING_PORT) {
            Ok(endpoint) => {
                info!("{}Running TCP listener on {:?}", self.us(), endpoint);
                self.accepting_on.push(endpoint);
            },
            Err(error) => warn!("{}Failed to listen on {:?}: {:?}", self.us(),
                                CRUST_DEFAULT_TCP_ACCEPTING_PORT, error),
        }
        match self.crust_service.start_accepting(CRUST_DEFAULT_UTP_ACCEPTING_PORT) {
            Ok(endpoint) => {
                info!("{}Running uTP listener on {:?}", self.us(), endpoint);
                self.accepting_on.push(endpoint);
            },
            Err(error) => warn!("{}Failed to listen on {:?}: {:?}", self.us(),
                                CRUST_DEFAULT_UTP_ACCEPTING_PORT, error),
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
            },
            // The message is not a SignedMessage, expect it to be a DirectMessage
            Err(_) => {
                match decode::<::direct_messages::DirectMessage>(&bytes) {
                    Ok(direct_message) => self.handle_direct_message(direct_message, connection),
                    // TODO(Fraser): Drop the connection if we can't parse a message? (dirvine not sure)
                    _ => error!("{}Unparsable message received on {:?}", self.us(), connection),
                };
            }
        }
    }

    fn handle_on_connect(&mut self,
                         connection: ::std::io::Result<::crust::Connection>,
                         connection_token: u32) {
        match connection {
            Ok(connection) => {
                debug!("{}New connection via OnConnect {:?} with token {}", self.us(), connection,
                       connection_token);
                if let State::Disconnected = *self.state() {
                        // Established connection. Pending Validity checks
                        self.state = State::Bootstrapping;
                };
                let _ = self.identify(connection);
            },
            Err(error) => {
                warn!("{}Failed to make connection with token {} - {}", self.us(),
                      connection_token, error);
            }
        }
    }

    fn handle_on_accept(&mut self, connection: ::crust::Connection) {
        debug!("{}New connection via OnAccept {:?}", self.us(), connection);
        if let State::Disconnected = *self.state() {
            // I am the first node in the network, and I got an incoming connection so I'll
            // promote myself as a node.
            let new_name =
                NameType::new(crypto::hash::sha512::hash(&self.full_id.public_id().name().0).0);
            // This will give me a new RT and set state to Relocated
            self.assign_network_name(new_name);
            self.state = State::Node;
        }
        let _ = self.identify(connection);
    }

    /// When CRUST reports a lost connection, ensure we remove the endpoint everywhere
    fn handle_lost_connection(&mut self, connection: ::crust::Connection) {
        debug!("{}Lost connection on {:?}", self.us(), connection);
        self.dropped_routing_node_connection(&connection);
        self.dropped_client_connection(&connection);
        self.dropped_bootstrap_connection(&connection);
    }

    fn identify(&mut self, connection: ::crust::Connection) -> RoutingResult {
        debug!("{}Identifying myself via {:?}", self.us(), connection);
        let direct_message = try!(::direct_messages::DirectMessage::new_identify(
                                      self.full_id.public_id().clone(),
                                      self.full_id.signing_private_key()));
        let bytes = try!(::utils::encode(&direct_message));
        self.crust_service.send(connection, bytes);
        Ok(())
    }

    fn handle_identify(&mut self, connection: ::crust::Connection, peer_public_id: &PublicId) {
        debug!("{}Peer {:?} has identified itself on {:?}", self.us(), peer_public_id, connection);
        match self.state {
            State::Disconnected => {
                unreachable!("Should not be Disconnected when handling incoming identify message");
            },
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
                let _ = self.request_network_name();
            },
            State::Client => {
                if self.client_restriction {
                    // Just now we only allow one bootstrap connection, so if we're already in
                    // Client state, we shouldn't receive further identifiers from peers.
                    error!("{}We're bootstrapped already, but have received another identifier from \
                           {:?} on {:?} - closing this connection now.", self.us(), peer_public_id,
                           connection);
                    self.drop_crust_connection(connection);
                } else if /*peer_public_id.is_node()*/&::sodiumoxide::crypto::hash::sha512::hash(&peer_public_id.signing_public_key().0).0[..] != &peer_public_id.name().0[..] {
                    // FIXME
                    self.add_node(connection, peer_public_id.clone());
                } else {
                    error!("{}We're bootstrapped already, but have received another identifier from \
                           {:?} on {:?} - closing this connection now.", self.us(), peer_public_id,
                           connection);
                    self.drop_crust_connection(connection);
                }
            },
            State::Node => {
                if /*peer_public_id.is_node()*/&::sodiumoxide::crypto::hash::sha512::hash(&peer_public_id.signing_public_key().0).0[..] != &peer_public_id.name().0[..] {
                    self.add_node(connection, peer_public_id.clone());
                } else {
                    self.add_client(connection, peer_public_id.clone());
                }
            },
        }
    }

    /// This the fundamental functional function in routing.
    /// It only handles messages received from connections in our routing table;
    /// i.e. this is a pure SAFE message (and does not function as the start of a proxy).
    /// If we are the proxy node for a message from the SAFE network to a node we proxy for,
    /// then we will pass out the message to the client or bootstrapping node;
    /// no proxy-messages enter the SAFE network here.
    fn handle_routing_message(&mut self, signed_message: SignedMessage) -> RoutingResult {
        debug!("{}Signed Message Received - {:?}", self.us(), signed_message);

        let (message, public_sign_key) = match signed_message.get_routing_message() {
            Some(routing_message) => (routing_message, signed_message.signing_public_key()),
            None => {
                debug!("Signature failed.\n");
                return Err(RoutingError::FailedSignature)
            }
        };

        if self.message_public_key_filter.check(&(message.clone(), public_sign_key.clone())) {
            return Err(RoutingError::FilterCheckFailed);
        }

        if self.handled_messages.check(&message) {
            debug!("{}This message has already been actioned.", self.us());
            return Err(RoutingError::FilterCheckFailed)
        }

        // Cache a response if from a GetRequest and caching is enabled for the Data type.
        self.data_cache.handle_cache_put(&message);
        // Get from cache if it's there.
        if let Some(content) = self.data_cache.handle_cache_get(&message) {
            let our_authority =
                ::authority::Authority::ManagedNode(*self.full_id.public_id().name());
            return self.send_content(our_authority, message.source(), content)
        }

        // Scan for remote names.
        if self.state == State::Node {
            match message.from_authority {
                ::authority::Authority::ClientManager(ref name) => self.refresh_routing_table(&name),
                ::authority::Authority::NaeManager(ref name) => self.refresh_routing_table(&name),
                ::authority::Authority::NodeManager(ref name) => self.refresh_routing_table(&name),
                ::authority::Authority::ManagedNode(ref name) => self.refresh_routing_table(&name),
                ::authority::Authority::Client(_, _) => {}
            };

            // Forward the message.
            debug!("{}Forwarding signed message", self.us());
            self.message_public_key_filter.add((message.clone(), public_sign_key.clone()));
            self.send(signed_message.clone());
        };

        // check if our calculated authority matches the destination authority of the message
        let our_authority = self.our_authority(&message);
        if our_authority.clone()
                        .map(|our_auth| &message.to_authority != &our_auth)
                        .unwrap_or(true) {
            // Either the message is directed at a group, and the target should be in range,
            // or it should be aimed directly at us.
            if message.destination().is_group() {
                if !self.name_in_range(message.destination().get_location()) {
                    debug!("{}Name {:?} not in range", self.us(),
                           message.destination().get_location());
                    return Err(RoutingError::BadAuthority);
                };
                debug!("{}Received an in-range group message", self.us());
            } else {
                match message.destination().get_address() {
                    Some(ref address) => if !self.is_us(address) {
                        debug!("{}Destination address {:?} is not us", self.us(), address);
                        return Err(RoutingError::BadAuthority);
                    },
                    None => return Err(RoutingError::BadAuthority),
                }
            };
        }

        // Accumulate message
        debug!("{}Accumulating signed message", self.us());
        let (accumulated_message, opt_token) = match self.accumulate(&signed_message) {
            Some((output_message, opt_token)) => (output_message, opt_token),
            None => {
                debug!("{}Not enough signatures. Not processing request yet", self.us());
                return Err(::error::RoutingError::NotEnoughSignatures)
            },
        };

        let result = match accumulated_message.content {
            Content::InternalRequest(request) => {
                match request {
                    InternalRequest::RequestNetworkName(_) => {
                        match opt_token {
                            Some(response_token) =>
                                self.handle_request_network_name(request,
                                                                 accumulated_message.from_authority,
                                                                 accumulated_message.to_authority,
                                                                 response_token),
                            None => return Err(RoutingError::UnknownMessageType),
                        }
                    }
                    InternalRequest::RelocatedNetworkName(relocated_id, response_token) => {
                        // Validate authorities
                        match (accumulated_message.from_authority,
                               accumulated_message.to_authority) {
                            (Authority::NaeManager(_), Authority::NaeManager(target_name)) => {
                                if self.name_in_range(&target_name) {
                                    self.handle_relocated_network_name(relocated_id, response_token)
                                } else {
                                    debug!("{}Ignoring RelocatedNetworkName Request as we are not \
                                           close to the relocated name", self.us());
                                    Err(RoutingError::BadAuthority)
                                }
                            },
                            _ => {
                                debug!("{}Ignoring bad RelocatedNetworkName Request", self.us());
                                Err(RoutingError::BadAuthority)
                            },
                        }

                    },
                    InternalRequest::Connect { endpoints, public_id } => {
                        match opt_token {
                            Some(response_token) =>
                                self.handle_connect_request(endpoints,
                                                            public_id,
                                                            accumulated_message.from_authority,
                                                            response_token),
                            None => return Err(RoutingError::UnknownMessageType),
                        }
                    }
                    InternalRequest::Refresh(type_tag, bytes, cause) => {
                        let refresh_authority = match our_authority {
                            Some(authority) => {
                                if !authority.is_group() {
                                    return Err(RoutingError::BadAuthority);
                                };
                                authority
                            }
                            None => return Err(RoutingError::BadAuthority),
                        };
                        if accumulated_message.from_authority.is_group() {
                            self.handle_refresh(type_tag,
                                accumulated_message.from_authority.get_location().clone(),
                                bytes, refresh_authority, cause)
                        } else {
                            return Err(RoutingError::BadAuthority);
                        }
                    }
                }
            }
            Content::InternalResponse(response) => {
                match response {
                    InternalResponse::RelocatedNetworkName(relocated_id,
                                                           close_group_ids,
                                                           original_signed_token) => {
                        debug!("{}Handling relocation response Relocated Name: {:?}, Close Group: \
                               {:?}", self.us(), relocated_id, close_group_ids);
                        self.handle_relocation_response(relocated_id,
                                                        close_group_ids,
                                                        original_signed_token,
                                                        accumulated_message.from_authority,
                                                        accumulated_message.to_authority)
                    }
                    InternalResponse::Connect {..} => {
                        debug!("{}Handling connect response {:?} ourselves", self.us(), response);
                        self.handle_connect_response(response,
                                                     accumulated_message.from_authority,
                                                     accumulated_message.to_authority)
                    }
                }
            }
            Content::ExternalRequest(request) => {
                self.send_to_user(Event::Request {
                    request: request,
                    our_authority: accumulated_message.to_authority,
                    from_authority: accumulated_message.from_authority,
                    signed_request: opt_token,
                });
                Ok(())
            }
            Content::ExternalResponse(response) => {
                self.handle_external_response(response,
                                              accumulated_message.to_authority,
                                              accumulated_message.from_authority)
            }
        };

        match result {
            Ok(()) => {
                self.message_public_key_filter.add((message, public_sign_key.clone()));
                Ok(())
            }
            Err(RoutingError::UnknownMessageType) => {
                self.message_public_key_filter.add((message, public_sign_key.clone()));
                Err(RoutingError::UnknownMessageType)
            }
            Err(e) => Err(e),
        }
    }

    fn accumulate(&mut self, signed_message: &SignedMessage)
            -> Option<(RoutingMessage, Option<SignedRequest>)> {
        let (message, public_sign_key) = match signed_message.get_routing_message() {
            Some(routing_message) => (routing_message, signed_message.signing_public_key()),
            None => return None,
        };

        let mut is_relocation_response_msg = false;
        if let Content::InternalResponse(InternalResponse::RelocatedNetworkName(..)) =
                                         message.content {
            is_relocation_response_msg = true;
        }

        // If the message is not from a group then don't accumulate
        if !message.from_authority.is_group() || is_relocation_response_msg {
            debug!("{}Message from {:?}, returning with SignedRequest", self.us(),
                   message.from_authority);
            return Some((message, Some(signed_message.as_signed_request())));
        }

        debug!("{}Adding message with public key {:?} to message_accumulator", self.us(),
            public_sign_key);
        let dynamic_quorum_size = self.routing_table_quorum_size();
        self.message_accumulator.set_quorum_size(dynamic_quorum_size);
        if self.message_accumulator.add(message.clone(), public_sign_key.clone()).is_some() {
            self.handled_messages.add(message.clone());
            Some((message, None))
        } else {
            None
        }
    }

    // ---- Direct Messages -----------------------------------------------------------------------

    fn handle_direct_message(&mut self,
                             direct_message: ::direct_messages::DirectMessage,
                             connection: ::crust::Connection) {
        debug!("{}Direct Message Received - {:?}", self.us(), direct_message);
        match *direct_message.content() {
            ::direct_messages::Content::Identify{ ref public_id, } => {
                // verify signature
                if !direct_message.verify_signature(public_id.signing_public_key()) {
                    warn!("{}Failed signature verification on {:?} - dropping connection",
                          self.us(), connection);
                    self.drop_crust_connection(connection);
                    return
                };
                self.handle_identify(connection, public_id);
            }
            ::direct_messages::Content::Churn(ref his_close_group) => {
                // TODO (ben 26/08/2015) verify the signature with the public_id
                // from our routing table.
                self.handle_churn(his_close_group);
            }
        };
    }

    // ---- Churn ---------------------------------------------------------------------------------

    fn generate_churn(&mut self,
                      churn: ::direct_messages::Churn,
                      target: Vec<::crust::Connection>)
                      -> RoutingResult {
        debug!("{}CHURN: sending {} names to {} close nodes", self.us(), churn.close_group.len(),
               target.len());
        // send Churn to all our close group nodes
        let direct_message = match ::direct_messages::DirectMessage::new(
            ::direct_messages::Content::Churn(churn.clone()),
            self.full_id.signing_private_key()) {
                Ok(x) => x,
                Err(e) => return Err(RoutingError::Cbor(e)),
            };
        let bytes = try!(::utils::encode(&direct_message));
        for endpoint in target {
            self.crust_service.send(endpoint, bytes.clone());
        }
        // notify the user
        let _ = self.event_sender.send(::event::Event::Churn(churn.close_group));
        Ok(())
    }

    fn handle_churn(&mut self, churn: &::direct_messages::Churn) {
        debug!("{}CHURN: received {} names", self.us(), churn.close_group.len());
        for his_close_node in &churn.close_group {
            self.refresh_routing_table(his_close_node);
        }
    }

    // ---- Request Network Name ------------------------------------------------------------------
    fn request_network_name(&mut self) -> RoutingResult {
        debug!("{}Requesting a network name", self.us());
        debug_assert!(self.state == State::Client);
        if self.client_restriction {
            debug!("{}Not requesting a network name we are a Client", self.us());
            return Ok(());
        };

        let to_authority = ::authority::Authority::NaeManager(*self.full_id.public_id().name());
        let internal_request =
            ::messages::InternalRequest::RequestNetworkName(self.full_id.public_id().clone());
        let content = ::messages::Content::InternalRequest(internal_request);
        let routing_message = RoutingMessage {
            from_authority: try!(self.get_client_authority()),
            to_authority: to_authority,
            content: content,
            group_keys: None,
        };

        match SignedMessage::new(&routing_message, &self.full_id) {
            Ok(signed_message) => self.send(signed_message),
            // FIXME (ben 24/08/2015) find an elegant way to give the message back to user
            Err(error) => {
                error!("{}Failed to serialise RequestNetworkName: {:?}", self.us(), error);
                return Err(RoutingError::Cbor(error))
            },
        };
        Ok(())
    }

    fn handle_request_network_name(&mut self,
                                   request: InternalRequest,
                                   from_authority: Authority,
                                   to_authority: Authority,
                                   response_token: SignedRequest)
                                   -> RoutingResult {
        if self.client_restriction {
            debug!("{}Client restricted not requesting network name", self.us());
            return Ok(());
        }

        match request {
            InternalRequest::RequestNetworkName(public_id) => {
                match (&from_authority, &to_authority) {
                    (&Authority::Client(_bootstrap_node, key), &Authority::NaeManager(name)) => {
                        let hashed_key = ::sodiumoxide::crypto::hash::sha512::hash(&key.0);
                        let close_group_to_client = NameType::new(hashed_key.0);

                        if !(self.name_in_range(&close_group_to_client) &&
                             close_group_to_client == name) {
                            // TODO(Spandan) Create a better error
                            return Err(RoutingError::BadAuthority)
                        }

                        let mut network_public_id = public_id.clone();

                        let mut close_group =
                            self.routing_table
                                .our_close_group()
                                .iter()
                                .map(|node_info| node_info.public_id.name().clone())
                                .collect::<Vec<NameType>>();
                        close_group.insert(0, *self.full_id.public_id().name());

                        let relocated_name = try!(utils::calculate_relocated_name(
                            close_group, &public_id.name()));

                        debug!("{}Got a request for network name from {:?}, assigning {:?}",
                               self.us(), from_authority, relocated_name);
                        network_public_id.set_name(relocated_name.clone());

                        let routing_message = RoutingMessage {
                            from_authority: to_authority,
                            to_authority: Authority::NaeManager(relocated_name.clone()),
                            content: Content::InternalRequest(
                                InternalRequest::RelocatedNetworkName(network_public_id,
                                response_token)),
                            group_keys: None,
                        };

                        match SignedMessage::new(&routing_message, &self.full_id) {
                            Ok(signed_message) => self.send(signed_message),
                            Err(e) => return Err(RoutingError::Cbor(e)),
                        }

                        Ok(())
                    }
                    _ => Err(RoutingError::BadAuthority),
                }
            }
            _ => Err(RoutingError::BadAuthority),
        }
    }

    fn handle_relocated_network_name(&mut self,
                                     relocated_id: PublicId,
                                     response_token: SignedRequest) -> RoutingResult {
        debug!("{}Handling Relocated Network Name", self.us());

        let signed_message = SignedMessage::from_signed_request(
                response_token.clone(), relocated_id.signing_public_key().clone());
        let message = match signed_message.get_routing_message() {
            Some(routing_message) => routing_message,
            None => {
                debug!("Signature failed.\n");
                return Err(RoutingError::FailedSignature)
            }
        };
        let target_client_authority = message.source();
        let from_authority = Authority::NaeManager(self.full_id.public_id().name().clone());
        let mut public_ids : Vec<PublicId> = self.routing_table
                                                 .our_close_group()
                                                 .iter()
                                                 .map(|node_info| node_info.public_id.clone())
                                                 .collect();

        // Also add our own full_id to the close_group list getting sent
        public_ids.push(self.full_id.public_id().clone());

        debug!("{}Network request to accept name {:?}, replying with our close group {:?} to {:?}",
               self.us(), relocated_id.name(), public_ids, target_client_authority);

        let _ = self.public_id_cache.insert(relocated_id.name().clone(), relocated_id.clone());
        let internal_response = InternalResponse::RelocatedNetworkName(relocated_id,
                                                                       public_ids,
                                                                       response_token);
        let routing_message = RoutingMessage {
            from_authority: from_authority,
            to_authority: target_client_authority,
            content: Content::InternalResponse(internal_response),
            group_keys: None,
        };

        match SignedMessage::new(&routing_message, &self.full_id) {
            Ok(signed_message) => Ok(self.send(signed_message)),
            Err(e) => Err(RoutingError::Cbor(e)),
        }
    }

    fn handle_relocation_response(&mut self,
                                  relocated_id: ::id::PublicId,
                                  close_group_ids: Vec<::id::PublicId>,
                                  signed_request: SignedRequest,
                                  _from_authority: Authority,
                                  _to_authority: Authority) -> RoutingResult {
        let signed_message = SignedMessage::from_signed_request(
                signed_request.clone(), self.full_id.public_id().signing_public_key().clone());
        let message = match signed_message.get_routing_message() {
            Some(routing_message) => routing_message,
            None => {
                debug!("Signature failed.\n");
                return Err(RoutingError::FailedSignature)
            }
        };

        match message.content {
            Content::InternalRequest(InternalRequest::RequestNetworkName(ref original_public_id)) => {
                if *self.full_id.public_id() != *original_public_id {
                    return Err(RoutingError::BadAuthority)
                }

                self.full_id.public_id_mut().set_name(relocated_id.name().clone());

                debug!("{}Assigned network name {:?}", self.us(), relocated_id.name());

                self.assign_network_name(relocated_id.name().clone());
                self.start_listening();

                // Send connect request as a client
                for peer in close_group_ids {
                    // TODO (ben 12/08/2015) self.public_id_cache.insert()
                    // or hold off till RFC on removing public_id_cache
                    let _ = self.send_connect_request(&peer.name());
                }

                Ok(())
            }
            _ => Err(RoutingError::UnknownMessageType),
        }
    }

    // ---- Connect Requests and Responses --------------------------------------------------------

    /// Scan all passing messages for the existence of nodes in the address space.  If a node is
    /// detected with a name that would improve our routing table, then try to connect.  We ignore
    /// all re-occurrences of this name for one second if we make the attempt to connect.
    fn refresh_routing_table(&mut self, from_node: &NameType) {
        if !self.connection_filter.check(from_node) {
            if self.routing_table.want_to_add(from_node) {
                debug!("{}Refresh routing table for peer {:?}", self.us(), from_node);
                match self.send_connect_request(from_node) {
                    Ok(()) => debug!("{}Sent connect request to {:?}", self.us(), from_node),
                    Err(error) => error!("{}Failed to send connect request to {:?} - {:?}",
                                         self.us(), from_node, error)
                }
            }
            self.connection_filter.add(from_node.clone());
        }
    }

    /// 1. ManagedNode(us) -> NodeManager(us) (connecting to our close group) they
    ///    will have us already in their group or relocation cache (5 min cache) when we
    ///    are initially connecting to our close group
    /// 2. ManagedNode(us) -> ManagedNode(them) direct message to a node who will
    ///    require to get our real FullId from our close group and accumulate this
    ///    before accpeting us as a valid connection / full_id
    fn send_connect_request(&mut self, peer_name: &NameType) -> RoutingResult {
        let from_authority = match *self.state() {
            State::Disconnected => return Err(RoutingError::NotBootstrapped),
            State::Client => {
                try!(self.get_client_authority())
            }
            _ => {
                Authority::ManagedNode(self.full_id.public_id().name().clone())
            }
        };

        debug!("{}Sending connect request from {:?} to {:?}", self.us(), from_authority, peer_name);
        let routing_message = RoutingMessage {
            from_authority: from_authority,
            to_authority: Authority::ManagedNode(peer_name.clone()),
            content: Content::InternalRequest(InternalRequest::Connect {
                endpoints: self.accepting_on.clone(),
                public_id: self.full_id.public_id().clone(),
            }),
            group_keys: None,
        };

        match SignedMessage::new(&routing_message, &self.full_id) {
            Ok(signed_message) => self.send(signed_message),
            Err(e) => return Err(RoutingError::Cbor(e)),
        };

        Ok(())
    }

    /// 1. ManagedNode(them) -> NodeManager(them) (we are their close group) they
    ///    must be in our relocation cache or known to our group memebers
    ///    ao we may have to send a get_id to our group
    /// 2. ManagedNode(them) -> ManagedNode(us) direct message to us
    ///    we must ask their NodeManagers for their full_id
    fn handle_connect_request(&mut self,
                              endpoints: Vec<::crust::Endpoint>,
                              public_id: PublicId,
                              from_authority: Authority,
                              response_token: SignedRequest) -> RoutingResult {
        debug!("{}Handle ConnectRequest", self.us());

        // TODO(Fraser:David) How do you validate/fetch/get public key for a node ?

        if let Authority::Client(_, ref public_key) = from_authority {
            let us = self.us();
            match self.public_id_cache.get(public_id.name()) {
                Some(cached_public_id) => if cached_public_id.signing_public_key() != public_key {
                    warn!("{}Cached Public key does not match in ConnectRequest", us);
                    return Err(RoutingError::BadAuthority)
                },
                None => {
                    debug!("{}Public FullId not cached", us);
                    return Err(RoutingError::BadAuthority)
                },
            }
        }

        if !self.routing_table.want_to_add(public_id.name()) {
            debug!("{}Connect request {:?} failed - Don't want to add", self.us(), public_id);
            return Err(RoutingError::RefusedFromRoutingTable)
        }

        let routing_message = RoutingMessage {
            from_authority: Authority::ManagedNode(*self.full_id.public_id().name()),
            to_authority: from_authority,
            content: Content::InternalResponse(InternalResponse::Connect {
                endpoints: self.accepting_on.clone(),
                public_id: self.full_id.public_id().clone(),
                signed_request: response_token,
            }),
            group_keys: None,
        };

        match SignedMessage::new(&routing_message, &self.full_id) {
            Ok(signed_message) => {
                self.send(signed_message);
                let connection_token = self.get_connection_token();
                debug!("{}Connecting on validated ConnectRequest with connection token {:?}",
                       self.us(), connection_token);
                self.connect(connection_token, &endpoints);
                self.connection_filter.add(public_id.name().clone());
            },
            Err(error) => return Err(RoutingError::Cbor(error)),
        }

        Ok(())
    }

    /// 1. NodeManager(us) -> ManagedNode(us), this is a close group connect, goes in routing_table
    ///    regardless if we can connect or not.
    /// 2. ManagedNode(them)-> ManagedNode(us), this is a node we wanted to connect to
    ///    and we check we still want to and make the crust connection and only if successful
    ///    put this node in our routing_table
    fn handle_connect_response(&mut self,
                               response: InternalResponse,
                               from_authority: Authority,
                               _to_authority: Authority) -> RoutingResult {
        debug!("{}Handle ConnectResponse", self.us());
        match response {
            InternalResponse::Connect { public_id, endpoints, signed_request } => {
                let signed_message = SignedMessage::from_signed_request(
                        signed_request.clone(),
                        self.full_id.public_id().signing_public_key().clone());
                let message = match signed_message.get_routing_message() {
                    Some(routing_message) => routing_message,
                    None => {
                        debug!("Signature failed.\n");
                        return Err(RoutingError::FailedSignature)
                    }
                };

                match message.from_authority.get_address() {
                    Some(address) => if !self.is_us(&address) {
                        error!("{}Connect response contains request that was not from us",
                               self.us());
                        return Err(RoutingError::BadAuthority);
                    },
                    None => return Err(RoutingError::BadAuthority),
                }

                // Are we already connected, or still interested?
                if !self.routing_table.want_to_add(public_id.name()) {
                    error!("{}ConnectResponse already connected to {:?}", self.us(),
                           from_authority);
                    return Err(RoutingError::RefusedFromRoutingTable);
                }

                let connection_token = self.get_connection_token();
                debug!("{}Connecting on validated ConnectResponse from {:?} with connection token \
                       {:?}", self.us(), from_authority, connection_token);
                self.connect(connection_token, &endpoints);
                self.connection_filter.add(public_id.name().clone());
                Ok(())
            }
            _ => Err(RoutingError::BadAuthority),
        }
    }

    fn connect(&mut self, connection_token: u32, endpoints: &[::crust::Endpoint]) {
        debug!("{}Connect: requesting crust connect to {:?}", self.us(), endpoints);
        self.crust_service.connect(connection_token, endpoints.to_owned());
    }

    fn get_connection_token(&mut self) -> u32 {
        let connection_token = self.connection_counter.clone();
        self.connection_counter = self.connection_counter.wrapping_add(1u32);
        if self.connection_counter == 0u32 {
            self.connection_counter == 1u32;
        }
        connection_token
    }

    // ----- Send Functions -----------------------------------------------------------------------

    fn send_to_user(&self, event: Event) {
        debug!("{}Send to user event {:?}", self.us(), event);
        if self.event_sender.send(event).is_err() {
            error!("{}Channel to user is broken;", self.us());
        }
    }

    fn send_content(&mut self,
                    our_authority: Authority,
                    to_authority: Authority,
                    content: Content)
                    -> RoutingResult {
        let routing_message = RoutingMessage {
            from_authority: our_authority,
            to_authority: to_authority,
            content: content,
            group_keys: None,
        };

        match SignedMessage::new(&routing_message, &self.full_id) {
            Ok(signed_message) => self.send(signed_message),
            Err(e) => return Err(RoutingError::Cbor(e)),
        };
        Ok(())
    }

    fn client_send_content(&mut self, to_authority: Authority, content: Content) {
        match self.get_client_authority() {
            Ok(client_authority) => {
                let routing_message = RoutingMessage {
                    from_authority: client_authority,
                    to_authority: to_authority.clone(),
                    content: content.clone(),
                    group_keys: None,
                };

                match SignedMessage::new(&routing_message, &self.full_id) {
                    Ok(signed_message) => self.send(signed_message),
                    // FIXME (ben 24/08/2015) find an elegant way to give the message back to user
                    Err(error) => {
                        self.send_failed_message_to_user(to_authority, content);
                        error!("{}Failed to serialise signed message: {:?}", self.us(), error);
                    }
                };
            },
            Err(_) => {
                self.send_failed_message_to_user(to_authority, content);
                error!("{}Failed to get a client authority", self.us());
            },
        }
    }

    fn send_failed_message_to_user(&self, to_authority: Authority, content: Content) {
        match content {
            Content::ExternalRequest(external_request) => {
                self.send_to_user(Event::FailedRequest {
                    request: external_request,
                    our_authority: None,
                    location: to_authority,
                    interface_error: InterfaceError::NotConnected,
                });
            }
            Content::ExternalResponse(external_response) => {
                self.send_to_user(Event::FailedResponse {
                    response: external_response,
                    our_authority: None,
                    location: to_authority,
                    interface_error: InterfaceError::NotConnected,
                });
            }
            _ => error!("{}InternalRequest/Response was sent back to user {:?}", self.us(),
                        content),
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
            Some(routing_message) => routing_message,
            None => {
                debug!("Signature failed.\n");
                return
            }
        };
        let destination = message.destination();
        debug!("{}Send request to {:?}", self.us(), destination);
        let bytes = match encode(&signed_message) {
            Ok(bytes) => bytes,
            Err(error) => {
                error!("{}Failed to serialise {:?} - {:?}", self.us(), signed_message, error);
                return
            },
        };

        // If we're a client going to be a node, send via our bootstrap connection
        if self.state == State::Client {
            let bootstrap_connections: Vec<&::crust::Connection> =
                self.proxy_map.keys().collect();
            if bootstrap_connections.is_empty() {
                unreachable!("{}Target connections for send is empty", self.us());
            }
            for connection in bootstrap_connections {
                self.crust_service.send(connection.clone(), bytes.clone());
                debug!("{}Sent {:?} to bootstrap connection {:?}", self.us(), signed_message,
                       connection);
            }
            return
        }

        // Handle if we have a client connection as the destination
        if let Authority::Client(_, ref client_public_key) = destination {
            debug!("{}Looking for client target {:?}", self.us(),
                   ::NameType::new(
                       ::sodiumoxide::crypto::hash::sha512::hash(&client_public_key[..]).0));
            if let Some(client_connection) = self.client_map.get(client_public_key) {
                self.crust_service.send(client_connection.clone(), bytes);
            } else {
                warn!("{}Failed to find client contact for {:?}", self.us(),
                      ::NameType::new(
                          ::sodiumoxide::crypto::hash::sha512::hash(&client_public_key[..]).0));
            }
            return
        }

        // Query routing table to send it out parallel or to our close group (ourselves excluded)
        let targets = self.routing_table.target_nodes(destination.get_location());
        targets.iter().all(
            |node_info| {
                node_info.connections.iter().all(
                |connection| {
                    self.crust_service.send(connection.clone(), bytes.clone());
                    true
                })
            });

        // If we need to handle this message, handle it.
        if self.name_in_range(destination.get_location()) {
            if let Err(error) = self.handle_routing_message(signed_message) {
                error!("{}Failed to handle message ourself: {:?}", self.us(), error)
            }
        }
    }

    // ----- Message Handlers that return to the event channel ------------------------------------

    fn handle_external_response(&mut self,
                                response: ExternalResponse,
                                to_authority: Authority,
                                from_authority: Authority)
                                -> RoutingResult {

        // Request token is only set if it came from a non-group entity.
        // If it came from a group, then sentinel guarantees message validity.
        if let Some(ref token) = *response.get_signed_token() {
            let signed_message = SignedMessage::from_signed_request(
                    token.clone(), self.full_id.public_id().signing_public_key().clone());
            match signed_message.get_routing_message() {
                Some(_) => {},
                None => return Err(RoutingError::FailedSignature),
            };
        } else {
            if !self.name_in_range(to_authority.get_location()) {
                return Err(RoutingError::BadAuthority);
            };
        };

        self.send_to_user(Event::Response {
            response: response,
            our_authority: to_authority,
            from_authority: from_authority,
        });

        Ok(())
    }

    fn handle_refresh(&mut self,
                      type_tag: u64,
                      sender: NameType,
                      payload: Vec<u8>,
                      our_authority: Authority,
                      cause: ::NameType)
                      -> RoutingResult {
        debug_assert!(our_authority.is_group());
        let threshold = self.routing_table_quorum_size();
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
            Some(bootstrap_name) => Ok(Authority::Client(
                                           bootstrap_name.1.clone(),
                                           *self.full_id.public_id().signing_public_key())),
            None => Err(RoutingError::NotBootstrapped),
        }
    }


    fn routing_table_quorum_size(&self) -> usize {
        ::std::cmp::min(self.routing_table.len(), ::types::QUORUM_SIZE)
    }

    // Returns our name and state for logging
    fn us(&self) -> String {
        match self.network_name {
            Some(name) => {
                format!("{:?}({:?}) - ", self.state, name)
            },
            None => {
                format!("{:?}({:?}) - ", self.state,
                        ::NameType::new(::sodiumoxide::crypto::hash::sha512::hash(
                            &self.full_id.public_id().signing_public_key()[..]).0))
            },
        }
    }

    /// Returns true if Client(public_key) matches our public signing key, even if we are a full
    /// node; or returns true if Node(name) is our current name.  Note that there is a difference to
    /// using core::us, as that would fail to assert an (old) Client identification after
    /// we were assigned a network name.
    pub fn is_us(&self, address: &Address) -> bool {
        match *address {
            Address::Client(public_key) =>
                public_key == *self.full_id.public_id().signing_public_key(),
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
    fn assign_network_name(&mut self, new_name: ::NameType) {
        match self.state {
            State::Disconnected => debug!("{}Assigning name {:?}", self.us(), new_name),
            State::Client => debug!("{}Assigning name {:?}", self.us(), new_name),
            _ => {
                debug!("{}We have already assigned a network name", self.us());
                return
            }
        }

        debug_assert!(self.network_name.is_none());

        self.full_id.public_id_mut().set_name(new_name.clone());

        debug!("{}Re-creating routing table after relocation", self.us());
        self.routing_table = RoutingTable::new(&new_name);
        self.network_name = Some(new_name);
    }

    /// check client_map for a client and remove from map
    fn dropped_client_connection(&mut self,
                                 connection: &::crust::Connection) {
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
            for _node in &self.routing_table.our_close_group() { // trigger churn
                                                                      // if close node
                                                                    };
            self.routing_table.drop_node(&node_name);
        }
    }

    // Add a client to our client map
    fn add_client(&mut self, connection: crust::Connection, public_id: PublicId) {
        if self.client_map.len() == MAX_RELAYS {
            warn!("{}Client map full ({} connections) so won't add {:?} to the client map - \
                  dropping {:?}", self.us(), MAX_RELAYS, public_id, connection);
            self.drop_crust_connection(connection);
        }

        match self.client_map.insert(public_id.signing_public_key().clone(), connection) {
            Some(old_connection) => {
                warn!("{}Found existing entry {:?} for {:?} found while adding to client map",
                      self.us(), old_connection, public_id);
                self.drop_crust_connection(old_connection);
            },
            None => debug!("{}Added client {:?} to client map; {:?}", self.us(),
                            public_id, connection),
        }
    }

    // Add a node to our routing table.
    fn add_node(&mut self, connection: crust::Connection, public_id: PublicId) {
        let peer_name = public_id.name().clone();

        if self.routing_table.has_node(&peer_name) {
            return self.routing_table.add_connection(&peer_name, connection)
        }

        let connection_clone = connection.clone();
        let node_info = NodeInfo::new(public_id,
                                      vec![connection]);
        let should_trigger_churn = self.name_in_range(node_info.id());
        let add_node_result = self.routing_table.add_node(node_info);

        match add_node_result.1 {
            Some(node) => {
                for connection in node.connections {
                    self.drop_crust_connection(connection);
                }
            },
            None => info!("{}No node removed from RT as a result of node addition", self.us()),
        }

        if !add_node_result.0 {
            debug!("{}Failed to add {:?} to the routing table - dropping {:?}", self.us(),
                   peer_name, connection_clone);
            self.drop_crust_connection(connection_clone);
            return
        }

        if self.routing_table.len() == 1 {
            self.state = State::Node;
        } else if self.routing_table.len() == ::types::GROUP_SIZE {
            info!("{}Routing Node has connected to {} nodes", self.us(),
                  self.routing_table.len());
            if let Err(err) = self.event_sender.send(Event::Connected) {
                error!("{}Error sending {:?} to event_sender", self.us(), err.0);
            }
            // Drop the bootstrap connections
            for (connection, _) in self.proxy_map.clone().into_iter() {
                info!("{}Dropping bootstrap connection {:?}", self.us(), connection);
                self.drop_crust_connection(connection);
            }
            self.proxy_map = ::std::collections::HashMap::new();
        }

        if should_trigger_churn {
            self.trigger_churn();
        }
    }

    fn trigger_churn(&mut self) {
        let our_close_group = self.routing_table.our_close_group();
        let mut close_group: Vec<::NameType> =
            our_close_group.iter()
            .map(|node_info| node_info.id().clone())
            .collect();

        close_group.insert(0, *self.full_id.public_id().name());
        let close_group_connections =
            our_close_group.iter().flat_map(
                |node_info| node_info.connections.iter().cloned()).collect::<Vec<_>>();

        let churn_message = ::direct_messages::Churn { close_group: close_group };

        if let Err(err) = self.generate_churn(churn_message, close_group_connections) {
            error!("{}Unsuccessful Churn {:?}", self.us(), err);
        }
    }

    /// Returns true if a name is in range for our close group.
    /// If the core is not a full node, this always returns false.
    pub fn name_in_range(&self, name: &NameType) -> bool {
        self.routing_table.address_in_our_close_group_range(name)
    }

    /// Our authority is defined by the routing message, if we are a full node;  if we are a client,
    /// this always returns Client authority (where the proxy name is taken from the routing message
    /// destination)
    pub fn our_authority(&self, message: &RoutingMessage) -> Option<Authority> {
        if self.state == State::Node {
            our_authority(message, &self.routing_table)
        } else {
            // if the message reached us as a client, then destination.get_location()
            // was our proxy's name
            Some(Authority::Client(message.destination().get_location().clone(),
                                   *self.full_id.public_id().signing_public_key()))
        }
    }

    fn drop_crust_connection(&mut self, connection: ::crust::Connection) {
        debug!("{}Dropping Crust Connection - {:?}", self.us(), connection);
        self.crust_service.drop_node(connection);
        self.handle_lost_connection(connection);
    }
}

/*
#[cfg(test)]
mod test {
    use action::Action;
    use data::{Data, DataRequest};
    use event::Event;
    use immutable_data::{ImmutableData, ImmutableDataType};
    use messages::{ExternalRequest, ExternalResponse, RoutingMessage, Content};
    use rand::{thread_rng, Rng};
    //use std::sync::mpsc;
    //use super::RoutingNode;
    use NameType;
    use authority::Authority;
    use data_cache_options::DataCacheOptions;

    //fn create_routing_node() -> RoutingNode {
    //    let (action_sender, action_receiver) = mpsc::channel::<Action>();
    //    let (event_sender, _) = mpsc::channel::<Event>();
    //    RoutingNode::new(action_sender.clone(),
    //                     action_receiver,
    //                     event_sender,
    //                     false,
    //                     None)
    //}

    // RoutingMessage's for ImmutableData Get request/response.
    fn generate_routing_messages() -> (RoutingMessage, RoutingMessage) {
        let mut data = [0u8; 64];
        thread_rng().fill_bytes(&mut data);

        let immutable = ImmutableData::new(ImmutableDataType::Normal,
                                           data.iter().cloned().collect());
        let immutable_data = Data::ImmutableData(immutable.clone());
        let data_request = DataRequest::ImmutableData(immutable.name().clone(),
                                                      immutable.get_type_tag().clone());
        let request = ExternalRequest::Get(data_request.clone(), 0u8);
        let response = ExternalResponse::Get(immutable_data, data_request, None);

        let routing_message_request = RoutingMessage {
            from_authority: Authority::ClientManager(NameType::new([1u8; 64])),
            to_authority: Authority::NaeManager(NameType::new(data)),
            content: Content::ExternalRequest(request),
            group_keys: None,
        };

        let routing_message_response = RoutingMessage {
            from_authority: Authority::NaeManager(NameType::new(data)),
            to_authority: Authority::ClientManager(NameType::new([1u8; 64])),
            content: Content::ExternalResponse(response),
            group_keys: None,
        };

        (routing_message_request, routing_message_response)
    }

    #[test]
    fn no_caching() {
        let mut node = create_routing_node();
        // Get request/response RoutingMessage's for ImmutableData.
        let (message_request, message_response) = generate_routing_messages();

        assert!(node.data_cache.handle_cache_get(&message_request).is_none());
        node.data_cache.handle_cache_put(&message_response);
        assert!(node.data_cache.handle_cache_get(&message_request).is_none());
    }

    #[test]
    fn enable_immutable_data_caching() {
        let mut node = create_routing_node();
        // Enable caching for ImmutableData, disable for other Data types.
        let cache_options = DataCacheOptions::with_caching(false, false, true);
        let _ = node.data_cache.set_cache_options(cache_options);
        // Get request/response RoutingMessage's for ImmutableData.
        let (message_request, message_response) = generate_routing_messages();

        assert!(node.data_cache.handle_cache_get(&message_request).is_none());
        node.data_cache.handle_cache_put(&message_response);
        assert!(node.data_cache.handle_cache_get(&message_request).is_some());
    }

    #[test]
    fn disable_immutable_data_caching() {
        let mut node = create_routing_node();
        // Disable caching for ImmutableData, enable for other Data types.
        let cache_options = DataCacheOptions::with_caching(true, true, false);
        let _ = node.data_cache.set_cache_options(cache_options);
        // Get request/response RoutingMessage's for ImmutableData.
        let (message_request, message_response) = generate_routing_messages();

        assert!(node.data_cache.handle_cache_get(&message_request).is_none());
        node.data_cache.handle_cache_put(&message_response);
        assert!(node.data_cache.handle_cache_get(&message_request).is_none());
    }
}
*/
