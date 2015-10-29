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

use sodiumoxide::crypto;
use std::cmp::min;

use lru_time_cache::LruCache;

use action::Action;
use event::Event;
use NameType;
use routing_core::{RoutingCore, ConnectionName};
use id::Id;
use public_id::PublicId;
use types;
use types::{Bytes, Address, CacheOptions};
use utils::{encode, decode};
use utils;
use data::{Data, DataRequest};
use authority::{Authority, our_authority};

use messages::{RoutingMessage, SignedMessage, SignedToken, ConnectRequest, ConnectResponse,
               Content, ExternalRequest, ExternalResponse, InternalRequest, InternalResponse};

use error::{RoutingError, InterfaceError};


type RoutingResult = Result<(), RoutingError>;

/// Routing Node
pub struct RoutingNode {
    // for CRUST
    crust_receiver: ::std::sync::mpsc::Receiver<::crust::Event>,
    crust_service: ::crust::Service,
    accepting_on: Vec<::crust::Endpoint>,
    connection_counter: u32,
    // for RoutingNode
    client_restriction: bool,
    action_sender: ::std::sync::mpsc::Sender<Action>,
    action_receiver: ::std::sync::mpsc::Receiver<Action>,
    event_sender: ::std::sync::mpsc::Sender<Event>,
    filter: ::filter::Filter,
    connection_filter: ::message_filter::MessageFilter<::NameType>,
    core: RoutingCore,
    public_id_cache: LruCache<NameType, PublicId>,
    accumulator: ::message_accumulator::MessageAccumulator,
    refresh_accumulator: ::refresh_accumulator::RefreshAccumulator,
    cache_options: CacheOptions,
    data_cache: Option<LruCache<NameType, Data>>,
}

impl RoutingNode {
    pub fn new(action_sender: ::std::sync::mpsc::Sender<Action>,
               action_receiver: ::std::sync::mpsc::Receiver<Action>,
               event_sender: ::std::sync::mpsc::Sender<Event>,
               client_restriction: bool,
               keys: Option<Id>)
               -> RoutingNode {

        let (crust_sender, crust_receiver) = ::std::sync::mpsc::channel::<::crust::Event>();
        let mut crust_service = match ::crust::Service::new(crust_sender) {
            Ok(service) => service,
            Err(what) => panic!(format!("Unable to start crust::Service {}", what)),
        };

        let accepting_on = crust_service.start_default_acceptors().into_iter()
                           .filter_map(|ep|ep.ok())
                           .flat_map(::crust::ifaddrs_if_unspecified)
                           .collect();

        // The above command will give us only internal endpoints on which
        // we're accepting. The next command will try to contact an IGD device
        // and create external mapping to those endpoints. The result
        // shall be returned async through the ExternalEndpoints event.
        crust_service.get_external_endpoints();

        let core = RoutingCore::new(event_sender.clone(), action_sender.clone(), keys);
        info!("RoutingNode {:?} listens on {:?}", core.our_address(), accepting_on);

        RoutingNode {
            crust_receiver: crust_receiver,
            crust_service: crust_service,
            accepting_on: accepting_on,
            // connection counter starts at 1, 0 is reserved for bootstrapping
            connection_counter: 1u32,
            client_restriction: client_restriction,
            action_sender: action_sender.clone(),
            action_receiver: action_receiver,
            event_sender: event_sender.clone(),
            filter: ::filter::Filter::with_expiry_duration(::time::Duration::minutes(20)),
            connection_filter: ::message_filter::MessageFilter::with_expiry_duration(
                ::time::Duration::seconds(20)),
            core: core,
            public_id_cache: LruCache::with_expiry_duration(::time::Duration::minutes(10)),
            accumulator: ::message_accumulator::MessageAccumulator::with_expiry_duration(
                ::time::Duration::minutes(5)),
            refresh_accumulator: ::refresh_accumulator::RefreshAccumulator::with_expiry_duration(
                ::time::Duration::minutes(5), event_sender),
            cache_options: CacheOptions::no_caching(),
            data_cache: None,
        }
    }

    pub fn run(&mut self) {
        self.crust_service.bootstrap(0u32);
        debug!("run: RoutingNode started running and started crust bootstrapping.");
        loop {
            match self.action_receiver.try_recv() {
                Err(_) => {}
                Ok(Action::SendMessage(signed_message)) => {
                    ignore(self.message_received(signed_message));
                }
                Ok(Action::SendContent(our_authority, to_authority, content)) => {
                    let _ = self.send_content(our_authority, to_authority, content);
                },
                Ok(Action::SendConfirmationHello(connection, address)) => {
                    let _ = self.send_hello(connection, Some(address), None);
                },
                Ok(Action::ClientSendContent(to_authority, content)) => {
                    debug!("ClientSendContent received for {:?}", content);
                    let _ = self.client_send_content(to_authority, content);
                },
                Ok(Action::Churn(our_close_group, targets, cause)) => {
                    let _ = self.generate_churn(our_close_group, targets, cause);
                },
                Ok(Action::SetCacheOptions(cache_options)) => {
                    self.set_cache_options(cache_options);
                },
                Ok(Action::DropConnections(connections)) => {
                    self.drop_connections(connections);
                },
                Ok(Action::MatchConnection(expected_connection, unknown_connection)) => {
                    self.core.match_connection(expected_connection, unknown_connection);
                },
                Ok(Action::Rebootstrap) => {
                    self.reset();
                    ::std::thread::sleep_ms(100);
                    self.crust_service.bootstrap(0u32);
                },
                Ok(Action::Terminate) => {
                    debug!("routing node terminated");
                    let _ = self.event_sender.send(Event::Terminated);
                    self.crust_service.stop();
                    break;
                }
            };
            match self.crust_receiver.try_recv() {
                Err(_) => {
                    // FIXME (ben 16/08/2015) other reasons could induce an error
                    // main error assumed now to be no new crust events
                    // break;
                }
                Ok(::crust::Event::NewMessage(connection, bytes)) => {
                    match decode::<SignedMessage>(&bytes) {
                        Ok(message) => {
                            // handle SignedMessage for any identified connection
                            match self.core.lookup_connection(&connection) {
                                Some(ConnectionName::Unidentified(_, _)) => debug!("message
                                        from unidentified connection {:?}", connection),
                                None => debug!("message from unknown connection {:?}",
                                    connection),
                                _ => ignore(self.message_received(message)),
                            };
                        }
                        // The message received is not a Signed Routing Message,
                        // expect it to be an Hello message to identify a connection
                        Err(_) => {
                            match decode::<::direct_messages::DirectMessage>(&bytes) {
                                Ok(direct_message) => self.direct_message_received(
                                        direct_message, connection),
                                    _ => error!("Unparsable message received on {:?}", connection),
                            };
                        }
                    };
                }
                Ok(::crust::Event::OnConnect(connection, _response_token)) => {
                    self.handle_on_connect(connection);
                }
                Ok(::crust::Event::OnAccept(connection)) => {
                    self.handle_on_accept(connection);
                }
                Ok(::crust::Event::OnRendezvousConnect(_connection, _response_token)) => {
                    unimplemented!()
                }
                Ok(::crust::Event::LostConnection(connection)) => {
                    self.handle_lost_connection(connection);
                }
                Ok(::crust::Event::BootstrapFinished) => {
                    match self.core.state() {
                        &::routing_core::State::Disconnected => {
                            self.reset();
                            ::std::thread::sleep_ms(100);
                            self.crust_service.bootstrap(0u32);
                        },
                        _ => {},
                    };
                }
                Ok(::crust::Event::ExternalEndpoints(external_endpoints)) => {
                    for external_endpoint in external_endpoints {
                        self.accepting_on.push(external_endpoint);
                    }
                }
                _ => {}
            };
            ::std::thread::sleep_ms(1);
        }
    }

    /// reset keeps the persistant state, but drops all connections
    /// and restarts the cycle from disconnected.
    fn reset(&mut self) {
          let open_connections = self.core.reset(self.client_restriction);
          for connection in open_connections {
              self.crust_service.drop_node(connection);
          }
          self.filter = ::filter::Filter::with_expiry_duration(::time::Duration::minutes(20));
          self.connection_filter = ::message_filter::MessageFilter::with_expiry_duration(
              ::time::Duration::seconds(20));
          self.public_id_cache = LruCache::with_expiry_duration(::time::Duration::minutes(10));
          self.accumulator = ::message_accumulator::MessageAccumulator::with_expiry_duration(
              ::time::Duration::minutes(5));
          self.refresh_accumulator = ::refresh_accumulator::RefreshAccumulator
              ::with_expiry_duration(::time::Duration::minutes(5), self.event_sender.clone());
          self.data_cache = None;
          let preserve_cache_options = self.cache_options.clone();
          self.set_cache_options(preserve_cache_options);
    }

    fn handle_on_connect(&mut self, connection: ::crust::Connection) {
        // FIXME (ben 29/10/2015) this is a possible crust bug, refer to routing/issue-757
        // on_connect if the connection states that we connected to ourselves, drop asap.
        if self.accepting_on.contains(&connection.peer_endpoint()) {
            error!("handle_on_connect: peer endpoint {:?} is in our accepting endpoints {:?}. \
                Refer to routing/issue-757. Dropping {:?}", connection.peer_endpoint(),
                self.accepting_on, connection);
            self.crust_service.drop_node(connection);
            return;
        };
        match self.core.state() {
            &::routing_core::State::Disconnected => {
                // This is our first connection, add as bootstrap and send hello.
                debug!("handle_on_connect: Disconnected adding unknown bootstrap {:?}", connection);
                let _ = self.core.add_unknown_bootstrap_connection(connection.clone());
                ignore(self.send_hello(connection, None, None));
                return;
            },
            &::routing_core::State::Bootstrapped => {
                // We're bootstrapped at our side but haven't received hello response and relocated,
                // so drop this connection.
                debug!("handle_on_connect: Bootstrapped so dropping {:?}", connection);
                self.crust_service.drop_node(connection);
                return;
            },
            // We have at least one connection, so continue unless terminate has been received.
            &::routing_core::State::Relocated => {},
            &::routing_core::State::Connected => {},
            &::routing_core::State::GroupConnected => {},
            &::routing_core::State::Terminated => {
                // Terminate has been called don't act on any further events.
                debug!("handle_on_connect: Terminated so dropping {:?}", connection);
                self.crust_service.drop_node(connection);
                return;
            },
        };

        debug!("handle_on_accept: {:?} matching {:?} against expected connections",
            self.core.state(), connection);
        match self.core.match_expected_connection(&connection) {
            Some(expected_connection) => {
                // We've received a ConnectRequest from a peer, send an unconfirmed Hello.
                debug!("handle_on_connect: {:?} matched expected connection {:?} on {:?}, \
                    sending hello", self.core.state(), expected_connection, connection);
                ignore(self.send_hello(connection, None, Some(expected_connection)))
            },
            None => {},
        }
    }

    fn handle_on_accept(&mut self, connection: ::crust::Connection) {
        match self.core.state() {
            &::routing_core::State::Disconnected => {
                let assigned_name = NameType::new(crypto::hash::sha512::hash(
                    &self.core.id().name().0).0);
                debug!("handle_on_accept: Disconnected so self-assigning name {:?}",
                    assigned_name);
                self.core.assign_name(&assigned_name);
            },
            &::routing_core::State::Bootstrapped => {
                debug!("handle_on_accept: Bootstrapped so not accepting {:?}. Dropping",
                    connection);
                self.crust_service.drop_node(connection);
                return;
            },
            &::routing_core::State::Relocated => {},
            &::routing_core::State::Connected => {},
            &::routing_core::State::GroupConnected => {},
            &::routing_core::State::Terminated => {
                self.crust_service.drop_node(connection);
                return;
            },
        };

        debug!("handle_on_accept: {:?} adding unknown connection {:?} on accept.",
            self.core.state(), connection);
        let _ = self.core.add_unknown_connection(connection);
    }

    /// When CRUST reports a lost connection, ensure we remove the endpoint anywhere
    fn handle_lost_connection(&mut self, connection: ::crust::Connection) {
        debug!("Lost connection on {:?}", connection);
        let connection_name = self.core.lookup_connection(&connection);
        if connection_name.is_some() {
            self.core.drop_peer(&connection_name.unwrap());
        }
    }

    // ---- Hello connection identification -------------------------------------------------------

    fn send_hello(&mut self,
                  connection: ::crust::Connection,
                  confirmed_address: Option<Address>,
                  expected_connection: Option<::routing_core::ExpectedConnection>)
                  -> RoutingResult {
        debug!("Saying hello I am {:?} on {:?}, confirming {:?}", self.core.our_address(),
            connection, confirmed_address);
        let direct_message = match ::direct_messages::DirectMessage::new(
                ::direct_messages::Content::Hello( ::direct_messages::Hello {
                    address: self.core.our_address(),
                    public_id: PublicId::new(self.core.id()),
                    confirmed_you: confirmed_address,
                    expected_connection: expected_connection
                }), self.core.id().signing_private_key()) {
            Ok(x) => x,
            Err(e) => return Err(RoutingError::Cbor(e)),
        };
        let bytes = try!(::utils::encode(&direct_message));
        self.crust_service.send(connection, bytes);
        Ok(())
    }

    fn handle_hello(&mut self, connection: ::crust::Connection, hello: &::direct_messages::Hello) {
        debug!("handle_hello: {:?} on {:?}", hello.address, connection);
        self.core.match_unknown_connection(&connection, &hello)
    }

    /// This the fundamental functional function in routing.
    /// It only handles messages received from connections in our routing table;
    /// i.e. this is a pure SAFE message (and does not function as the start of a relay).
    /// If we are the relay node for a message from the SAFE network to a node we relay for,
    /// then we will pass out the message to the client or bootstrapping node;
    /// no relay-messages enter the SAFE network here.
    fn message_received(&mut self, signed_message: SignedMessage) -> RoutingResult {

        // filter check, should just return quietly
        if !self.filter.check(&signed_message) {
            return Err(RoutingError::FilterCheckFailed);
        }

        let message = signed_message.get_routing_message().clone();

        // Cache a response if from a GetRequest and caching is enabled for the Data type.
        self.handle_cache_put(&message);
        // Get from cache if it's there.
        match self.handle_cache_get(&message) {
            Some(content) => {
                return self.send_content(
                    Authority::ManagedNode(self.core.id().name()), message.source(), content);
            },
            None => {}
        }

        // scan for remote names
        if self.core.is_connected_node() {
            match signed_message.claimant() {
                &::types::Address::Node(ref name) => self.refresh_routing_table(&name),
                _ => {},
            };
        };

        // Forward
        if self.core.is_connected_node() {
            ignore(self.send(signed_message.clone()));
        }

        // check if our calculated authority matches the destination authority of the message
        let our_authority = self.core.our_authority(&message);
        if our_authority.clone().map(|our_auth| &message.to_authority != &our_auth).unwrap_or(true) {
            // Either the message is directed at a group, and the target should be in range,
            // or it should be aimed directly at us.
            if message.destination().is_group() {
                if !self.core.name_in_range(message.destination().get_location()) {
                    return Err(RoutingError::BadAuthority);
                };
            } else {
                match message.destination().get_address() {
                    Some(ref address) => if !self.core.is_us(address) {
                        return Err(RoutingError::BadAuthority);
                    },
                    None => return Err(RoutingError::BadAuthority),
                }
            };
        }

        // Accumulate message
        let (message, opt_token) = match self.accumulate(&signed_message) {
            Some((message, opt_token)) => (message, opt_token),
            None => return Err(::error::RoutingError::NotEnoughSignatures),
        };

        let message_backup = message.clone();
        let result = match message.content {
            Content::InternalRequest(request) => {
                match request {
                    InternalRequest::RequestNetworkName(_) => {
                        match opt_token {
                            Some(response_token) => self.handle_request_network_name(request,
                                message.from_authority, message.to_authority, response_token),
                            None => return Err(RoutingError::UnknownMessageType),
                        }
                    }
                    InternalRequest::CacheNetworkName(_, _) => {
                        self.handle_cache_network_name(request, message.from_authority,
                            message.to_authority)
                    }
                    InternalRequest::Connect(_) => {
                        match opt_token {
                            Some(response_token) => self.handle_connect_request(request,
                                message.from_authority, message.to_authority, response_token),
                            None => return Err(RoutingError::UnknownMessageType),
                        }
                    }
                    InternalRequest::Refresh(type_tag, bytes, cause) => {
                        let refresh_authority = match our_authority {
                            Some(authority) => {
                                if !authority.is_group() { return Err(RoutingError::BadAuthority) };
                                authority
                            },
                            None => return Err(RoutingError::BadAuthority),
                        };
                        match *signed_message.claimant() {
                            // TODO (ben 23/08/2015) later consider whether we need to restrict it
                            // to only from nodes within our close group
                            Address::Node(name) => self.handle_refresh(type_tag, name, bytes,
                                refresh_authority, cause),
                            Address::Client(_) => Err(RoutingError::BadAuthority),
                        }
                    }
                }
            }
            Content::InternalResponse(response) => {
                match response {
                    InternalResponse::CacheNetworkName(_, _, _) => {
                        self.handle_cache_network_name_response(response, message.from_authority,
                            message.to_authority)
                    }
                    InternalResponse::Connect(_, _) => {
                        self.handle_connect_response(response, message.from_authority,
                            message.to_authority)
                    }
                }
            }
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
        };


        match result {
            Ok(()) => {
                self.filter.block(&message_backup);
                Ok(())
            },
            Err(RoutingError::UnknownMessageType) => {
                self.filter.block(&message_backup);
                Err(RoutingError::UnknownMessageType)
            },
            Err(e) => Err(e),
        }
    }

    fn accumulate(&mut self,
                  signed_message: &SignedMessage)
                  -> Option<(RoutingMessage, Option<SignedToken>)> {
        let message = signed_message.get_routing_message().clone();

        if !message.from_authority.is_group() {
            debug!("Message from {:?}, returning with SignedToken",
                message.from_authority);
            // TODO: If not from a group, then use client's public key to check
            // the signature.
            let token = match signed_message.as_token() {
                Ok(token) => token,
                Err(_) => {
                    error!("Failed to generate signed token, message {:?} is dropped.",
                      message);
                    return None;
                }
            };
            return Some((message, Some(token)));
        }

        let skip_accumulator = match message.content {
            Content::InternalRequest(ref request) => {
                match *request {
                    InternalRequest::Refresh(_, _, _) => {
                        true
                    },
                    _ => false,
                }
            },
            Content::InternalResponse(ref response) => {
                match *response {
                    InternalResponse::CacheNetworkName(_,_,_) => true,
                    _ => false,
                }
            },
            _ => false,
        };

        if skip_accumulator {
            debug!("Skipping accumulator for message {:?}", message);
            return Some((message, None));
        }

        let threshold = self.group_threshold();
        debug!("Accumulator threshold is at {:?}", threshold);

        let claimant: NameType = match *signed_message.claimant() {
            Address::Node(ref claimant) => claimant.clone(),
            Address::Client(_) => {
                error!("Claimant is a Client, but passed into accumulator for a group, dropping.");
                // debug_assert!(false);
                return None;
            }
        };

        debug!("Adding message from {:?} to accumulator", claimant);
        self.accumulator.add_message(threshold, claimant, message).map(|msg| (msg, None))
    }

    // ---- Direct Messages -----------------------------------------------------------------------

    fn direct_message_received(&mut self, direct_message: ::direct_messages::DirectMessage,
        connection: ::crust::Connection) {

        match direct_message.content() {
            &::direct_messages::Content::Hello(ref hello) => {
                // verify signature of hello
                if !direct_message.verify_signature(&hello.public_id.signing_public_key()) {
                    error!("DirectMessage::Hello failed signature verification on {:?}",
                        connection);
                    self.crust_service.drop_node(connection); };
                let _ = self.handle_hello(connection, hello);
            },
            &::direct_messages::Content::Churn(ref his_close_group) => {
                // TODO (ben 26/08/2015) verify the signature with the public_id
                // from our routing table.
                self.handle_churn(his_close_group);
            },
        };
    }

    // ---- Churn ---------------------------------------------------------------------------------

    fn generate_churn(&mut self, churn: ::direct_messages::Churn, target: Vec<::crust::Connection>,
        cause: ::NameType) -> RoutingResult {
        debug!("CHURN: sending {:?} names to {:?} close nodes",
            churn.close_group.len(), target.len());
        self.refresh_accumulator.register_cause(&cause);
        // send Churn to all our close group nodes
        let direct_message = match ::direct_messages::DirectMessage::new(
            ::direct_messages::Content::Churn(churn.clone()),
            self.core.id().signing_private_key()) {
                Ok(x) => x,
                Err(e) => return Err(RoutingError::Cbor(e)),
            };
        let bytes = try!(::utils::encode(&direct_message));
        for endpoint in target {
            self.crust_service.send(endpoint, bytes.clone());
        }
        // notify the user
        let _ = self.event_sender.send(::event::Event::Churn(churn.close_group, cause));
        Ok(())
    }

    fn handle_churn(&mut self, churn: &::direct_messages::Churn) {
        debug!("CHURN: received {:?} names", churn.close_group.len());
        for his_close_node in churn.close_group.iter() {
            self.refresh_routing_table(his_close_node);
        }
    }

    // ---- Request Network Name ------------------------------------------------------------------

    fn handle_request_network_name(&self, request: InternalRequest,
                                   from_authority: Authority,
                                   to_authority: Authority,
                                   response_token: SignedToken)
                                   -> RoutingResult {
        match request {
            InternalRequest::RequestNetworkName(public_id) => {
                match (&from_authority, &to_authority) {
                    (&Authority::Client(_, _), &Authority::NaeManager(_)) => {
                        let mut network_public_id = public_id.clone();
                        match self.core.our_close_group() {
                            Some(close_group) => {
                                let relocated_name = try!(utils::calculate_relocated_name(
                                    close_group, &public_id.name()));
                                debug!("Got a request for a network name from {:?}, assigning {:?}",
                                    from_authority, relocated_name);
                                network_public_id.assign_relocated_name(relocated_name.clone());
                                let routing_message = RoutingMessage {
                                    from_authority: to_authority,
                                    to_authority: Authority::NaeManager(relocated_name.clone()),
                                    content: Content::InternalRequest(
                                        InternalRequest::CacheNetworkName(network_public_id,
                                        response_token)),
                                };
                                match SignedMessage::new(Address::Node(self.core.id().name()),
                                                         routing_message,
                                                         self.core.id().signing_private_key()) {
                                    Ok(signed_message) => ignore(self.send(signed_message)),
                                    Err(e) => return Err(RoutingError::Cbor(e)),
                                };
                                Ok(())
                            }
                            None => return Err(RoutingError::BadAuthority),
                        }
                    }
                    _ => return Err(RoutingError::BadAuthority),
                }
            }
            _ => return Err(RoutingError::BadAuthority),
        }
    }

    fn handle_cache_network_name(&mut self,
                                 request: InternalRequest,
                                 from_authority: Authority,
                                 to_authority: Authority)
                                 -> RoutingResult {
        match request {
            InternalRequest::CacheNetworkName(network_public_id, response_token) => {
                match (from_authority, &to_authority) {
                    (Authority::NaeManager(_), &Authority::NaeManager(_)) => {
                        let request_network_name = try!(SignedMessage::new_from_token(
                            response_token.clone()));
                        let _ = self.public_id_cache.insert(network_public_id.name(),
                            network_public_id.clone());
                        match self.core.our_close_group_with_public_ids() {
                            Some(close_group) => {
                                debug!("Network request to accept name {:?},
                                       responding with our close group {:?} to {:?}",
                                       network_public_id.name(), close_group,
                                       request_network_name.get_routing_message().source());
                                let routing_message = RoutingMessage {
                                    from_authority: to_authority,
                                    to_authority: request_network_name.get_routing_message().source(),
                                    content: Content::InternalResponse(
                                        InternalResponse::CacheNetworkName(network_public_id,
                                        close_group, response_token)),
                                };
                                match SignedMessage::new(Address::Node(self.core.id().name()),
                                                         routing_message,
                                                         self.core.id().signing_private_key()) {
                                    Ok(signed_message) => ignore(self.send(signed_message)),
                                    Err(e) => return Err(RoutingError::Cbor(e)),
                                };
                                Ok(())
                            }
                            None => return Err(RoutingError::BadAuthority),
                        }
                    }
                    _ => return Err(RoutingError::BadAuthority),
                }
            }
            _ => return Err(RoutingError::BadAuthority),
        }
    }

    fn handle_cache_network_name_response(&mut self, response: InternalResponse,
            _from_authority: Authority, _to_authority: Authority) -> RoutingResult {
        // An additional blockage on acting to restrict RoutingNode from becoming a full node
        if self.client_restriction {
            return Ok(())
        };
        match response {
            InternalResponse::CacheNetworkName(network_public_id, group, signed_token) => {
                if !signed_token.verify_signature(&self.core.id().signing_public_key()) {
                    return Err(RoutingError::FailedSignature)
                };
                let request = try!(SignedMessage::new_from_token(signed_token));
                match request.get_routing_message().content {
                    Content::InternalRequest(InternalRequest::RequestNetworkName(
                            ref original_public_id)) => {
                        let mut our_public_id = PublicId::new(self.core.id());
                        if &our_public_id != original_public_id {
                            return Err(RoutingError::BadAuthority);
                        };
                        our_public_id.set_name(network_public_id.name());
                        if our_public_id != network_public_id {
                            return Err(RoutingError::BadAuthority);
                        };
                        let _ = self.core.assign_network_name(&network_public_id.name());
                        debug!("Assigned network name {:?} and our address now is {:?}",
                            network_public_id.name(), self.core.our_address());
                        for peer in group {
                            // TODO (ben 12/08/2015) self.public_id_cache.insert()
                            // or hold off till RFC on removing public_id_cache
                            self.refresh_routing_table(&peer.name());
                        }
                        Ok(())
                    }
                    _ => return Err(RoutingError::UnknownMessageType),
                }
            }
            _ => return Err(RoutingError::BadAuthority),
        }
    }

    // ---- Connect Requests and Responses --------------------------------------------------------

    /// Scan all passing messages for the existance of nodes in the address space.
    /// If a node is detected with a name that would improve our routing table,
    /// then try to connect.  During a delay of 1 seconds, we collapse
    /// all re-occurances of this name, and block a new connect request
    fn refresh_routing_table(&mut self, from_node: &NameType) {
        if !self.connection_filter.check(from_node) {
            if self.core.check_node(&ConnectionName::Routing(from_node.clone())) {
                ignore(self.send_connect_request(from_node));
            }
            self.connection_filter.add(from_node.clone());
        }
    }

    fn send_connect_request(&mut self, peer_name: &NameType) -> RoutingResult {
        let (from_authority, address) = match self.core.state() {
            &::routing_core::State::Disconnected => return Err(RoutingError::NotBootstrapped),
            &::routing_core::State::Bootstrapped | &::routing_core::State::Relocated => {
                let name = match self.get_a_bootstrap_name() {
                    Some(name) => name,
                    // (TODO Brian 19.10.15) Shouldn't happen since we should have at least one
                    // bootstrap connection, but should be acted on explicitly if it we get here.
                    None => return Err(RoutingError::Interface(InterfaceError::NotConnected))
                };

                let signing_key = self.core.id().signing_public_key();
                (Authority::Client(name, signing_key), Address::Client(signing_key))
            },
            &::routing_core::State::Terminated => {
                // (TODO Brian 19.10.15) A new error code may be more appropriate here.
                return Err(RoutingError::Interface(InterfaceError::NotConnected))
            },
            _ => {
                let name = self.core.id().name();
                (Authority::ManagedNode(name), Address::Node(name))
            }
        };

        let routing_message = RoutingMessage {
            from_authority: from_authority,
            to_authority: Authority::ManagedNode(peer_name.clone()),
            content: Content::InternalRequest(InternalRequest::Connect(ConnectRequest {
                    local_endpoints: self.accepting_on.clone(),
                    external_endpoints: vec![],
                    requester_fob: PublicId::new(self.core.id()),
                }
            )),
        };

        match SignedMessage::new(address, routing_message, self.core.id().signing_private_key()) {
            Ok(signed_message) => ignore(self.send(signed_message)),
            Err(e) => return Err(RoutingError::Cbor(e)),
        };

        Ok(())
    }

    fn handle_connect_request(&mut self,
                              request: InternalRequest,
                              from_authority: Authority,
                              _to_authority: Authority,
                              response_token: SignedToken)
                              -> RoutingResult {
        debug!("Handle ConnectRequest");
        match request {
            InternalRequest::Connect(connect_request) => {
                if !connect_request.requester_fob.is_relocated() {
                    return Err(RoutingError::RejectedPublicId);
                };
                // First verify that the message is correctly self-signed.
                if !response_token.verify_signature(
                        &connect_request.requester_fob.signing_public_key()) {
                    return Err(RoutingError::FailedSignature);
                };
                if !self.core.check_node(&ConnectionName::Routing(
                        connect_request.requester_fob.name())) {
                    return Err(RoutingError::RefusedFromRoutingTable);
                };

                // TODO (ben 13/08/2015) use public_id_cache or result of future RFC
                // to validate the public_id from the network
                self.connect(&connect_request.local_endpoints);
                self.connect(&connect_request.external_endpoints);
                self.connection_filter.add(connect_request.requester_fob.name());
                let _ = self.core.add_expected_connection(
                        ::routing_core::ExpectedConnection::Request(connect_request));

                let routing_message = RoutingMessage {
                    from_authority: Authority::ManagedNode(self.core.id().name()),
                    to_authority: from_authority,
                    content: Content::InternalResponse(InternalResponse::Connect(ConnectResponse {
                            local_endpoints: self.accepting_on.clone(),
                            external_endpoints: vec![],
                            receiver_fob: PublicId::new(self.core.id()),
                        }, response_token)),
                };
                match SignedMessage::new(Address::Node(self.core.id().name()),
                                         routing_message,
                                         self.core.id().signing_private_key()) {
                    Ok(signed_message) => ignore(self.send(signed_message)),
                    Err(e) => return Err(RoutingError::Cbor(e)),
                };

                Ok(())
            }
            _ => return Err(RoutingError::BadAuthority),
        }
    }

    fn handle_connect_response(&mut self,
                               response: InternalResponse,
                               from_authority: Authority,
                               _to_authority: Authority)
                               -> RoutingResult {
        debug!("handle ConnectResponse");
        match response {
            InternalResponse::Connect(connect_response, signed_token) => {
                if !signed_token.verify_signature(&self.core.id().signing_public_key()) {
                    error!("ConnectResponse from {:?} failed our signature for the signed token.",
                        from_authority);
                    return Err(RoutingError::FailedSignature);
                };
                let connect_request = try!(SignedMessage::new_from_token(signed_token.clone()));
                match connect_request.get_routing_message().from_authority.get_address() {
                    Some(address) => if !self.core.is_us(&address) {
                        error!("Connect response contains request that was not from us.");
                        return Err(RoutingError::BadAuthority);
                    },
                    None => return Err(RoutingError::BadAuthority),
                }
                // Are we already connected (returns false), or still interested?
                if !self.core.check_node(&ConnectionName::Routing(
                    connect_response.receiver_fob.name())) {
                    return Err(RoutingError::RefusedFromRoutingTable);
                };

                debug!("Connecting on validated ConnectResponse to {:?}", from_authority);
                self.connect(&connect_response.local_endpoints);
                self.connect(&connect_response.external_endpoints);
                self.connection_filter.add(connect_response.receiver_fob.name());
                let _ = self.core.add_expected_connection(
                    ::routing_core::ExpectedConnection::Response(
                        connect_response, signed_token.clone()));
                Ok(())
            }
            _ => return Err(RoutingError::BadAuthority),
        }
    }

    fn connect(&mut self, endpoints: &Vec<::crust::Endpoint>) {
        let new_response_token = self.connection_counter.clone();
        self.connection_counter = self.connection_counter.wrapping_add(1u32);
        if self.connection_counter == 0u32 { self.connection_counter == 1u32; };
        debug!("connect: requesting crust connect to {:?}", endpoints);
        self.crust_service.connect(new_response_token, endpoints.clone());
    }

    fn drop_connections(&mut self, connections: Vec<::crust::Connection>) {
        for connection in connections {
            self.crust_service.drop_node(connection);
        }
    }

    // ----- Send Functions -----------------------------------------------------------------------

    fn send_to_user(&self, event: Event) {
        debug!("Send to user event {:?}", event);
        if self.event_sender.send(event).is_err() {
            error!("Channel to user is broken. Terminating.");
            let _ = self.action_sender.send(Action::Terminate);
        }
    }

    fn send_content(&self, our_authority: Authority, to_authority: Authority,
        content: Content) -> RoutingResult {
        if self.core.is_connected_node() {
            let routing_message = RoutingMessage {
                from_authority: our_authority,
                to_authority: to_authority,
                content: content,
            };
            match SignedMessage::new(Address::Node(self.core.id().name()),
                                     routing_message,
                                     self.core.id().signing_private_key()) {
                Ok(signed_message) => ignore(self.send(signed_message)),
                Err(e) => return Err(RoutingError::Cbor(e)),
            };
        } else {
            match content {
                Content::ExternalRequest(external_request) => {
                    self.send_to_user(Event::FailedRequest {
                        request: external_request,
                        our_authority: Some(our_authority),
                        location: to_authority,
                        interface_error: InterfaceError::NotConnected });
                }
                Content::ExternalResponse(external_response) => {
                    self.send_to_user(Event::FailedResponse {
                        response: external_response,
                        our_authority: Some(our_authority),
                        location: to_authority,
                        interface_error: InterfaceError::NotConnected });
                }
                // FIXME (ben 24/08/2015) InternalRequest::Refresh can pass here on failure
                _ => error!("InternalRequest/Response was sent back to user {:?}", content),
            }
        }
        Ok(())
    }

    fn client_send_content(&self, to_authority: Authority, content: Content) -> RoutingResult {
        if self.core.is_connected_node() || self.core.has_bootstrap_endpoints() {
            // FIXME (ben 14/08/2015) we need a proper function to retrieve a bootstrap_name
            let bootstrap_name = match self.get_a_bootstrap_name() {
                Some(name) => name,
                None => return Err(RoutingError::NotBootstrapped),
            };
            let routing_message = RoutingMessage {
                from_authority: Authority::Client(bootstrap_name,
                                                  self.core.id().signing_public_key()),
                to_authority: to_authority,
                content: content,
            };
            match SignedMessage::new(Address::Client(self.core.id().signing_public_key()),
                                     routing_message,
                                     self.core.id().signing_private_key()) {
                Ok(signed_message) => ignore(self.send(signed_message)),
                // FIXME (ben 24/08/2015) find an elegant way to give the message back to user
                Err(e) => return Err(RoutingError::Cbor(e)),
            };
        } else {
            match content {
                Content::ExternalRequest(external_request) => {
                    self.send_to_user(Event::FailedRequest {
                        request: external_request,
                        our_authority: None,
                        location: to_authority,
                        interface_error: InterfaceError::NotConnected });
                }
                Content::ExternalResponse(external_response) => {
                    self.send_to_user(Event::FailedResponse {
                        response: external_response,
                        our_authority: None,
                        location: to_authority,
                        interface_error: InterfaceError::NotConnected });
                }
                _ => error!("InternalRequest/Response was sent back to user {:?}", content),
            }
        }
        Ok(())
    }

    /// Send a SignedMessage out to the destination
    /// 1. if it can be directly relayed to a Client, then it will
    /// 2. if we can forward it to nodes closer to the destination, it will be sent in parallel
    /// 3. if the destination is in range for us, then send it to all our close group nodes
    /// 4. if all the above failed, try sending it over all available bootstrap connections
    /// 5. finally, if we are a node and the message concerns us, queue it for processing later.
    fn send(&self, signed_message: SignedMessage) -> RoutingResult {
        let destination = signed_message.get_routing_message().destination();
        let bytes = try!(encode(&signed_message));
        // query the routing table for parallel or swarm
        let connections = self.core.target_connections(&destination);
        debug!("Target connections for send: {:?}", connections);
        if !connections.is_empty() {
            debug!("Sending {:?} to {:?} target connection(s)",
                signed_message.get_routing_message().content, connections.len());
            for connection in connections {
                // TODO(ben 10/08/2015) drop endpoints that fail to send
                self.crust_service.send(connection, bytes.clone());
            }
        }

        match self.core.bootstrap_connections() {
            Some(bootstrap_connections) => {
                // TODO (ben 10/08/2015) Strictly speaking we do not have to validate that
                // the relay_name in from_authority Client(relay_name, client_public_key) is
                // the name of the bootstrap connection we're sending it on.  Although this might
                // open a window for attacking a node, in v0.3.* we can leave this unresolved.
                for connection in bootstrap_connections {
                    self.crust_service.send(connection.clone(), bytes.clone());
                    debug!("Sent {:?} to bootstrap connection {:?}",
                        signed_message.get_routing_message().content,
                        connection);
                    break;
                }
            }
            None => {}
        }

        // If we need handle this message, move this copy into the channel for later processing.
        if self.core.name_in_range(&destination.get_location()) {
            if let Authority::Client(_, _) = destination {
                return Ok(());
            };
            debug!("Queuing message for processing ourselves");
            ignore(self.action_sender.send(Action::SendMessage(signed_message)));
        }
        Ok(())
    }

    // ----- Message Handlers that return to the event channel ------------------------------------

    fn handle_external_response(&mut self,
                                response: ExternalResponse,
                                to_authority: Authority,
                                from_authority: Authority)
                                -> RoutingResult {

        // Request token is only set if it came from a non-group entity.
        // If it came from a group, then sentinel guarantees message validity.
        if let &Some(ref token) = response.get_signed_token() {
            if !token.verify_signature(&self.core.id().signing_public_key()) {
                return Err(RoutingError::FailedSignature);
            };
        } else {
            if !self.core.name_in_range(to_authority.get_location()) {
                return Err(RoutingError::BadAuthority);
            };
        };

        self.send_to_user(Event::Response {
            response       : response,
            our_authority  : to_authority,
            from_authority : from_authority,
        });

        Ok(())
    }

    fn handle_refresh(&mut self, type_tag: u64,
                                 sender: NameType,
                                 payload: Bytes,
                                 our_authority: Authority,
                                 cause: ::NameType) -> RoutingResult {
        debug_assert!(our_authority.is_group());
        let threshold = self.group_threshold();
        match self.refresh_accumulator.add_message(threshold,
            type_tag.clone(), sender, our_authority.clone(), payload, cause) {
            Some(vec_of_bytes) => {
                let _ = self.event_sender.send(Event::Refresh(type_tag, our_authority,
                    vec_of_bytes));
                Ok(())
            },
            None => Err(::error::RoutingError::NotEnoughSignatures),
        }
    }

    // ------ FIXME -------------------------------------------------------------------------------

    fn group_threshold(&self) -> usize {
        min(types::QUORUM_SIZE, (self.core.routing_table_size() as f32 * 0.8) as usize)
    }

    fn get_a_bootstrap_name(&self) -> Option<NameType> {
        match self.core.bootstrap_names() {
            Some(bootstrap_names) => {
                // TODO (ben 13/08/2015) for now just take the first bootstrap name as our relay
                match bootstrap_names.first() {
                    Some(bootstrap_name) => Some(bootstrap_name.clone()),
                    None => None,
                }
            },
            None => None,
        }
    }

    // ------ Cache handling ----------------------------------------------------------------------

    fn set_cache_options(&mut self, cache_options: CacheOptions) {
        self.cache_options.set_cache_options(cache_options);
        if self.cache_options.caching_enabled() {
            match self.data_cache {
                None => self.data_cache =
                    Some(LruCache::<NameType, Data>::with_expiry_duration(
                            ::time::Duration::minutes(10))),
                Some(_) => {},
            }
        } else {
            self.data_cache = None;
        }
    }

    fn handle_cache_put(&mut self, message: &RoutingMessage) {
        match self.data_cache {
            Some(ref mut data_cache) => {
                match message.content.clone() {
                    Content::ExternalResponse(response) => {
                        match response {
                            ExternalResponse::Get(data, _, _) => {
                                match data {
                                    Data::PlainData(_) => {
                                        if self.cache_options.plain_data_caching_enabled() {
                                            debug!("Caching PlainData {:?}", data.name());
                                            let _ = data_cache.insert(data.name(), data.clone());
                                        }
                                    }
                                    Data::StructuredData(_) => {
                                        if self.cache_options.structured_data_caching_enabled() {
                                            debug!("Caching StructuredData {:?}", data.name());
                                            let _ = data_cache.insert(data.name(), data.clone());
                                        }
                                    }
                                    Data::ImmutableData(_) => {
                                        if self.cache_options.immutable_data_caching_enabled() {
                                            debug!("Caching ImmutableData {:?}", data.name());
                                            // TODO verify data
                                            let _ = data_cache.insert(data.name(), data.clone());
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }

                    },
                    _ => {}
                }
            },
            None => {}
        }

    }

    fn handle_cache_get(&mut self, message: &RoutingMessage) -> Option<Content> {
        match self.data_cache {
            Some(ref mut data_cache) => {
                match message.content.clone() {
                    Content::ExternalRequest(request) => {
                        match request {
                            ExternalRequest::Get(data_request, _) => {
                                match data_request {
                                    DataRequest::PlainData(data_name) => {
                                        if self.cache_options.plain_data_caching_enabled() {
                                            match data_cache.get(&data_name) {
                                                Some(data) => {
                                                    debug!("Got PlainData {:?} from cache",
                                                           data_name);
                                                    let response =
                                                        ExternalResponse::Get(
                                                            data.clone(),
                                                            data_request,
                                                            None);
                                                    return Some(Content::ExternalResponse(response));
                                                },
                                                None => return None
                                            }
                                        }
                                        return None;
                                    }
                                    DataRequest::StructuredData(_, _) => {
                                        if self.cache_options.structured_data_caching_enabled() {
                                            match data_cache.get(&data_request.name()) {
                                                Some(data) => {
                                                    debug!("Got StructuredData {:?} from cache",
                                                           data_request.name());
                                                    let response =
                                                        ExternalResponse::Get(
                                                            data.clone(),
                                                            data_request,
                                                            None);
                                                    return Some(Content::ExternalResponse(response));
                                                },
                                                None => return None
                                            }
                                        }
                                        return None;
                                    }
                                    DataRequest::ImmutableData(data_name, _) => {
                                        if self.cache_options.immutable_data_caching_enabled() {
                                            match data_cache.get(&data_name) {
                                                Some(data) => {
                                                    debug!("Got ImmutableData {:?} from cache",
                                                           data_name);
                                                    let response =
                                                        ExternalResponse::Get(
                                                            data.clone(),
                                                            data_request,
                                                            None);
                                                    return Some(Content::ExternalResponse(response));
                                                },
                                                None => return None
                                            }
                                        }
                                        return None;
                                    }
                                }
                            }
                            _ => None,
                        }

                    },
                    _ => None,
                }

            },
            None => None,
        }
    }
}

fn ignore<R, E>(_result: Result<R, E>) {
}

#[cfg(test)]
mod test {
    use action::Action;
    use sodiumoxide::crypto;
    use data::{Data, DataRequest};
    use event::Event;
    use immutable_data::{ImmutableData, ImmutableDataType};
    use messages::{ExternalRequest, ExternalResponse, SignedToken, RoutingMessage, Content};
    use rand::{thread_rng, Rng};
    use std::sync::mpsc;
    use super::RoutingNode;
    use NameType;
    use authority::Authority;
    use types::CacheOptions;

    fn create_routing_node() -> RoutingNode {
        let (action_sender, action_receiver) = mpsc::channel::<Action>();
        let (event_sender, _) = mpsc::channel::<Event>();
        RoutingNode::new(action_sender.clone(), action_receiver, event_sender, false, None)
    }

    // RoutingMessage's for ImmutableData Get request/response.
    fn generate_routing_messages() -> (RoutingMessage, RoutingMessage) {
        let mut data = [0u8; 64];
        thread_rng().fill_bytes(&mut data);

        let immutable = ImmutableData::new(ImmutableDataType::Normal,
                                           data.iter().map(|&x|x).collect::<Vec<_>>());
        let immutable_data = Data::ImmutableData(immutable.clone());
        let key_pair = crypto::sign::gen_keypair();
        let signature = crypto::sign::sign_detached(&data, &key_pair.1);
        let sign_token = SignedToken {
            serialised_request: data.iter().map(|&x|x).collect::<Vec<_>>(),
            signature: signature,
        };

        let data_request = DataRequest::ImmutableData(immutable.name().clone(),
                                                      immutable.get_type_tag().clone());
        let request = ExternalRequest::Get(data_request.clone(), 0u8);
        let response = ExternalResponse::Get(immutable_data, data_request, Some(sign_token));

        let routing_message_request = RoutingMessage {
            from_authority: Authority::ClientManager(NameType::new([1u8; 64])),
            to_authority: Authority::NaeManager(NameType::new(data)),
            content: Content::ExternalRequest(request)
        };

        let routing_message_response = RoutingMessage {
            from_authority: Authority::NaeManager(NameType::new(data)),
            to_authority: Authority::ClientManager(NameType::new([1u8; 64])),
            content: Content::ExternalResponse(response)
        };

        (routing_message_request, routing_message_response)
    }

    #[test]
    fn no_caching() {
        let mut node = create_routing_node();
        // Get request/response RoutingMessage's for ImmutableData.
        let (message_request, message_response) = generate_routing_messages();

        assert!(node.handle_cache_get(&message_request).is_none());
        node.handle_cache_put(&message_response);
        assert!(node.handle_cache_get(&message_request).is_none());
    }

    #[test]
    fn enable_immutable_data_caching() {
        let mut node = create_routing_node();
        // Enable caching for ImmutableData, disable for other Data types.
        let cache_options = CacheOptions::with_caching(false, false, true);
        let _ = node.set_cache_options(cache_options);
        // Get request/response RoutingMessage's for ImmutableData.
        let (message_request, message_response) = generate_routing_messages();

        assert!(node.handle_cache_get(&message_request).is_none());
        node.handle_cache_put(&message_response);
        assert!(node.handle_cache_get(&message_request).is_some());
    }

    #[test]
    fn disable_immutable_data_caching() {
        let mut node = create_routing_node();
        // Disable caching for ImmutableData, enable for other Data types.
        let cache_options = CacheOptions::with_caching(true, true, false);
        let _ = node.set_cache_options(cache_options);
        // Get request/response RoutingMessage's for ImmutableData.
        let (message_request, message_response) = generate_routing_messages();

        assert!(node.handle_cache_get(&message_request).is_none());
        node.handle_cache_put(&message_response);
        assert!(node.handle_cache_get(&message_request).is_none());
    }
}
