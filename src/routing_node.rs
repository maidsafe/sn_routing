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
use id::Id;
use public_id::PublicId;
use types::{Address, CacheOptions};
use utils::{encode, decode};
use utils;
use data::{Data, DataRequest};
use authority::{Authority, our_authority};

use messages::{RoutingMessage, SignedMessage, SignedToken, ConnectRequest, ConnectResponse,
               Content, ExternalRequest, ExternalResponse, InternalRequest, InternalResponse};

use error::{RoutingError, InterfaceError};


type RoutingResult = Result<(), RoutingError>;

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct Relay {
    pub public_key: ::sodiumoxide::crypto::sign::PublicKey,
}

impl ::utilities::Identifiable for Relay {
    fn valid_public_id(&self, public_id: &::public_id::PublicId) -> bool {
        self.public_key == public_id.signing_public_key()
    }
}

impl ::std::fmt::Debug for Relay {
    fn fmt(&self, formatter: &mut ::std::fmt::Formatter) -> Result<(), ::std::fmt::Error> {
        formatter.write_str(&format!("Public Key {:?}",
            ::NameType::new(::sodiumoxide::crypto::hash::sha512::hash(&self.public_key[..]).0)))
    }
}

/// ConnectionName labels the counterparty on a connection in relation to us
#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
#[allow(unused)]
pub enum ConnectionName {
    Relay(Address),
    Routing(NameType),
    Bootstrap(NameType),
    Unidentified(crust::Connection, bool), /*                               ~|~~
                                            *                                | set true when connected as a bootstrap connection */
}


/// State determines the current state of RoutingCore based on the established connections.
/// State will start at Disconnected and for a full node under expected behaviour cycle from
/// Disconnected to Bootstrapped.  Once Bootstrapped it requires a relocated name provided by
/// the network.  Once the name has been acquired, the state is Relocated and a routing table
/// is initialised with this name.  Once routing connections with the network are established,
/// the state is Connected.  Once more than ::types::GROUP_SIZE connections have been established,
/// the state is marked as GroupConnected. If the routing connections are lost, the state returns
/// to Disconnected and the routing table is destroyed.  If the node accepts an incoming connection
/// while itself disconnected it can jump from Disconnected to Relocated (assigning itself a name).
/// For a client the cycle is reduced to Disconnected and Bootstrapped.
/// When the user calls ::stop(), the state is set to Terminated.
#[allow(unused)]
#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
pub enum State {
    /// There are no connections.
    Disconnected,
    /// There are only bootstrap connections, and we do not yet have a name.
    Bootstrapped,
    /// There are only bootstrap connections, and we have received a name.
    Relocated,
    /// There are 0 < n < GROUP_SIZE routing connections, and we have a name.
    Connected,
    /// There are n >= GROUP_SIZE routing connections, and we have a name.
    GroupConnected,
    /// ::stop() has been called.
    Terminated,
}

/// ExpectedConnection.
#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone, RustcEncodable, RustcDecodable)]
#[allow(unused)]
pub enum ExpectedConnection {
    /// A ConnectRequest was sent by peer. Store a signed message as token to return to the peer
    /// when a connection from crust event OnConnect arrives with connection token equal to the
    /// first parameter.
    Request(u32, ::messages::ConnectRequest),
    /// A ConnectResponse sent by peer with a signed token that is our original validatable
    /// ConnectRequest. Matches to the connection returned by crust event OnConnect that arrives
    /// with connection token equal to the first parameter.
    Response(u32, ::messages::ConnectResponse),
}

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
    claimant_message_filter: ::message_filter::MessageFilter<(RoutingMessage, Address)>,
    connection_filter: ::message_filter::MessageFilter<::NameType>,
    public_id_cache: LruCache<NameType, PublicId>,
    message_accumulator: ::accumulator::Accumulator<RoutingMessage, ()>,
    refresh_accumulator: ::refresh_accumulator::RefreshAccumulator,
    refresh_causes: ::message_filter::MessageFilter<::NameType>,
    // Messages which have been accumulated and then actioned
    handled_messages: ::message_filter::MessageFilter<RoutingMessage>,
    cache_options: CacheOptions,
    data_cache: Option<LruCache<NameType, Data>>,

    // START
    id: Id,
    state: State,
    network_name: Option<NameType>,
    routing_table: Option<RoutingTable>,
    bootstrap_map: Option<::utilities::ConnectionMap<::NameType>>,
    relay_map: Option<::utilities::ConnectionMap<Relay>>,
    expected_connections: ::lru_time_cache::LruCache<ExpectedConnection,
                                                     Option<::crust::Connection>>,
    unknown_connections: ::lru_time_cache::LruCache<::crust::Connection,
                                                    Option<::direct_messages::Hello>>,
    // END
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

        let accepting_on = crust_service.start_default_acceptors()
                                        .into_iter()
                                        .filter_map(|ep| ep.ok())
                                        .flat_map(::crust::ifaddrs_if_unspecified)
                                        .collect::<Vec<::crust::Endpoint>>();

        // The above command will give us only internal endpoints on which
        // we're accepting. The next command will try to contact an IGD device
        // and create external mapping to those endpoints. The result
        // shall be returned async through the ExternalEndpoints event.
        crust_service.get_external_endpoints();



        // START
        let id = match keys {
            Some(id) => id,
            None => Id::new(),
        };
        // nodes are not persistent, and a client has no network allocated name
        if id.is_relocated() {
            error!("Core terminates routing as initialised with relocated id {:?}",
                   PublicId::new(&id));
            let _ = action_sender.send(Action::Terminate);
        };
        // END

        RoutingNode {
            crust_receiver: crust_receiver,
            crust_service: crust_service,
            accepting_on: accepting_on,
            // Counter starts at 1, 0 is reserved for bootstrapping.
            connection_counter: 1u32,
            client_restriction: client_restriction,
            action_sender: action_sender,
            action_receiver: action_receiver,
            event_sender: event_sender.clone(),
            claimant_message_filter: ::message_filter
                                     ::MessageFilter
                                     ::with_expiry_duration(::time::Duration::minutes(20)),
            connection_filter: ::message_filter::MessageFilter::with_expiry_duration(
                ::time::Duration::seconds(20)),
            public_id_cache: LruCache::with_expiry_duration(::time::Duration::minutes(10)),
            message_accumulator: ::accumulator::Accumulator::with_duration(1,
                ::time::Duration::minutes(5)),
            refresh_accumulator: ::refresh_accumulator::RefreshAccumulator::with_expiry_duration(
                ::time::Duration::minutes(5)),
            refresh_causes: ::message_filter::MessageFilter::with_expiry_duration(
                ::time::Duration::minutes(5)),
            handled_messages: ::message_filter::MessageFilter::with_expiry_duration(
                ::time::Duration::minutes(20)),
            cache_options: CacheOptions::no_caching(),
            data_cache: None,
//START
            id: id,
            state: State::Disconnected,
            network_name: None,
            routing_table: None,
            bootstrap_map: Some(::utilities::ConnectionMap::new()),
            relay_map: None,
            expected_connections: ::lru_time_cache::LruCache::with_expiry_duration(
                ::time::Duration::minutes(5)),
            unknown_connections: ::lru_time_cache::LruCache::with_expiry_duration(
                ::time::Duration::minutes(5)),
//END
        }
    }

    pub fn run(&mut self) {
        self.crust_service.bootstrap(0u32);
        debug!("{:?} - RoutingNode started running and started bootstrap", self.our_address());
        let mut start = ::time::SteadyTime::now();
        loop {
            match self.action_receiver.try_recv() {
                Err(::std::sync::mpsc::TryRecvError::Disconnected) => {
                    error!("{:?} - Action Sender hung-up. Exiting event loop", self.our_address());
                    break
                },
                Err(_) => {
                    if ::time::SteadyTime::now() - start > ::time::Duration::seconds(3) {
                        start = ::time::SteadyTime::now();
                        if let Some(ref rt) = self.routing_table {
                            debug!("{:?} - Routing Table size: {}", self.our_address(), rt.size());
                        }
                    }
                }, // TODO(Spandan) Nothing is in event loop - This will be eliminated
                   // when we use EventSender
                Ok(Action::SendContent(our_authority, to_authority, content)) => {
                    let _ = self.send_content(our_authority, to_authority, content);
                },
                Ok(Action::ClientSendContent(to_authority, content)) => {
                    debug!("{:?} - ClientSendContent received for {:?}", self.our_address(),
                           content);
                    let _ = self.client_send_content(to_authority, content);
                },
                Ok(Action::SetCacheOptions(cache_options)) => {
                    self.set_cache_options(cache_options);
                },
                Ok(Action::Rebootstrap) => {
                    self.restart();
                    self.crust_service.bootstrap(0u32);
                },
                Ok(Action::Terminate) => {
                    debug!("{:?} - routing node terminated", self.our_address());
                    let _ = self.event_sender.send(Event::Terminated);
                    self.crust_service.stop();
                    break;
                },
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
                            // Handle SignedMessage for any identified connection
                            match self.lookup_connection(&connection) {
                                Some(ConnectionName::Unidentified(_, _)) =>
                                    debug!("{:?} - Message from unidentified connection {:?}",
                                           self.our_address(), connection),
                                None =>
                                    debug!("{:?} - Message from unknown connection {:?}",
                                           self.our_address(), connection),
                                _ => ignore(self.message_received(message)),
                            };
                        }
                        // The message received is not a Signed Routing Message,
                        // expect it to be an Hello message to identify a connection
                        Err(_) => {
                            match decode::<::direct_messages::DirectMessage>(&bytes) {
                                Ok(direct_message) =>
                                    self.direct_message_received(direct_message, connection),
                                _ => error!("{:?} - Unparsable message received on {:?}",
                                            self.our_address(), connection),
                            };
                        }
                    };
                }
                Ok(::crust::Event::OnConnect(connection, connection_token)) => {
                    self.handle_on_connect(connection, connection_token);
                }
                Ok(::crust::Event::OnRendezvousConnect(_connection, _response_token)) => {
                    unimplemented!()
                }
                Ok(::crust::Event::OnAccept(connection)) => {
                    self.handle_on_accept(connection);
                }
                Ok(::crust::Event::LostConnection(connection)) => {
                    self.handle_lost_connection(connection);
                }
                Ok(::crust::Event::BootstrapFinished) => {
                    // match self.state() {
                    //     &State::Disconnected => {
                    //         self.restart();
                    //         ::std::thread::sleep_ms(100);
                    //         self.crust_service.bootstrap(0u32);
                    //     },
                    //     _ => {},
                    // };
                }
                Ok(::crust::Event::ExternalEndpoints(external_endpoints)) => {
                    for external_endpoint in external_endpoints {
                        debug!("{:?} - Adding external endpoint {:?}", self.our_address(),
                               external_endpoint);
                        self.accepting_on.push(external_endpoint);
                    }
                }
                Ok(::crust::Event::OnUdpSocketMapped(_mapped_udp_socket)) => {
                    unimplemented!()
                }
                Ok(::crust::Event::OnHolePunched(_hole_punch_result)) => {
                    unimplemented!()
                }
            };

            let interval = ::std::time::Duration::from_millis(1);
            ::std::thread::sleep(interval);
        }
    }

    /// restart keeps the persistant state, but drops all connections
    /// and restarts the cycle from disconnected.
    fn restart(&mut self) {
        let client_restriction = self.client_restriction;
        let open_connections = self.restart_core(client_restriction);
        for connection in open_connections {
            self.crust_service.drop_node(connection);
        }
        self.claimant_message_filter = ::message_filter
                                       ::MessageFilter
                                       ::with_expiry_duration(::time::Duration::minutes(20));
        self.connection_filter =
            ::message_filter::MessageFilter::with_expiry_duration(::time::Duration::seconds(20));
        self.public_id_cache = LruCache::with_expiry_duration(::time::Duration::minutes(10));
        self.message_accumulator = ::accumulator::Accumulator::with_duration(1,
              ::time::Duration::minutes(5));
        self.refresh_accumulator = ::refresh_accumulator::RefreshAccumulator
              ::with_expiry_duration(::time::Duration::minutes(5));
        self.refresh_causes =
            ::message_filter::MessageFilter::with_expiry_duration(::time::Duration::minutes(5));
        self.handled_messages = ::message_filter
                                ::MessageFilter
                                ::with_expiry_duration(::time::Duration::minutes(20));
        self.data_cache = None;
        let preserve_cache_options = self.cache_options.clone();
        self.set_cache_options(preserve_cache_options);
    }

    fn handle_on_connect(&mut self, connection: ::crust::Connection, connection_token: u32) {
        match self.state() {
            &State::Disconnected => {
                // This is our first connection, add as bootstrap and send hello.
                debug!("{:?} - Adding unknown connection {:?} on connect", self.our_address(),
                       connection);
                let _ = self.add_unknown_connection(connection.clone());
                ignore(self.send_hello(connection, None));
                return;
            }
            &State::Bootstrapped => {
                // We're bootstrapped at our side but haven't received hello response and relocated,
                // so drop this connection.
                self.crust_service.drop_node(connection);
                return;
            }
            // We have at least one connection, so continue unless terminate has been received.
            &State::Relocated => {}
            &State::Connected => {}
            &State::GroupConnected => {}
            &State::Terminated => {
                // Terminate has been called don't act on any further events.
                self.crust_service.drop_node(connection);
                return;
            }
        };

        debug!("{:?} - Matching expected connection {:?} on connect, our state {:?}",
               self.our_address(), connection, self.state());
        match self.match_expected_connection(&connection, connection_token) {
            Some(_) => ignore(self.send_hello(connection, None)),
            None => {}
        }
    }

    fn handle_on_accept(&mut self, connection: ::crust::Connection) {
        match self.state() {
            &State::Disconnected => {
                // I am the first node in the network, and i got an incomming connection so i'll
                // promote myself as a node.
                let assigned_name = NameType::new(crypto::hash::sha512::hash(&self.id().name().0)
                                                      .0);
                // This will give me a new RT also
                self.assign_name(&assigned_name);
            }
            &State::Bootstrapped => {
                self.crust_service.drop_node(connection);
                return;
            }
            &State::Relocated => {}
            &State::Connected => {}
            &State::GroupConnected => {}
            &State::Terminated => {
                self.crust_service.drop_node(connection);
                return;
            }
        };

        debug!("{:?} - Adding unknown connection {:?} on accept, our state {:?}",
               self.our_address(), connection, self.state());
        self.add_unknown_connection(connection);
        // ignore(self.send_hello(connection, None))
    }

    /// When CRUST reports a lost connection, ensure we remove the endpoint anywhere
    fn handle_lost_connection(&mut self, connection: ::crust::Connection) {
        debug!("{:?} - Lost connection on {:?}", self.our_address(), connection);
        let connection_name = self.lookup_connection(&connection);
        if connection_name.is_some() {
            if let Err(err) = self.drop_peer(&connection_name.unwrap()) {
                error!("{:?} - Error dropping peer {:?}", self.our_address(), err);
            }
        }
    }

    // ---- Hello connection identification -------------------------------------------------------

    fn send_hello(&mut self,
                  connection: ::crust::Connection,
                  confirmed_address: Option<Address>)
                  -> RoutingResult {
        debug!("{:?} - Saying hello on {:?}, confirming {:?}", self.our_address(), connection,
               confirmed_address);
        let direct_message = match ::direct_messages::DirectMessage::new(
                ::direct_messages::Content::Hello( ::direct_messages::Hello {
                    address: self.our_address(),
                    public_id: PublicId::new(self.id()),
                    confirmed_you: confirmed_address
                }), self.id().signing_private_key()) {
            Ok(x) => x,
            Err(e) => return Err(RoutingError::Cbor(e)),
        };
        let bytes = try!(::utils::encode(&direct_message));
        self.crust_service.send(connection, bytes);
        Ok(())
    }

    fn handle_hello(&mut self, connection: ::crust::Connection, hello: &::direct_messages::Hello) {
        debug!("{:?} - Hello received from {:?} on {:?}", self.our_address(), hello.address,
               connection);
        self.match_unknown_connection(&connection, &hello)
    }

    /// This the fundamental functional function in routing.
    /// It only handles messages received from connections in our routing table;
    /// i.e. this is a pure SAFE message (and does not function as the start of a relay).
    /// If we are the relay node for a message from the SAFE network to a node we relay for,
    /// then we will pass out the message to the client or bootstrapping node;
    /// no relay-messages enter the SAFE network here.
    fn message_received(&mut self, signed_message: SignedMessage) -> RoutingResult {
        debug!("{:?} Signed Message Received - {:?}", self.our_address(), signed_message);

        // filter check, should just return quietly
        let message = signed_message.get_routing_message().clone();
        let claimant = signed_message.claimant().clone();

        if !self.claimant_message_filter.check(&(message.clone(), claimant.clone())) {
            return Err(RoutingError::FilterCheckFailed);
        }

        if self.handled_messages.check(&message) {
            debug!("{:?} - This message has already been actioned.", self.our_address());
            return Err(RoutingError::FilterCheckFailed)
        }

        // Cache a response if from a GetRequest and caching is enabled for the Data type.
        self.handle_cache_put(&message);
        // Get from cache if it's there.
        if let Some(content) = self.handle_cache_get(&message) {
            let to_authority = ::authority::Authority::ManagedNode(self.id().name());
            return self.send_content(to_authority, message.source(), content)
        }

        // Scan for remote names.
        if self.is_connected_node() {
            match claimant {
                ::types::Address::Node(ref name) => {
                    let authority = ::authority::Authority::ManagedNode(name.clone());
                    if self.check_relocations(&authority).is_empty() {
                        debug!("{:?} - We're connected and got message from {:?}",
                               self.our_address(), name);
                        self.refresh_routing_table(&name)
                    }
                }
                _ => {}
            };

            // Forward the message.
            debug!("{:?} - Forwarding signed message", self.our_address());
            ignore(self.send(signed_message.clone()));
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
                    debug!("{:?} - Name {:?} not in range", self.our_address(),
                           message.destination().get_location());
                    return Err(RoutingError::BadAuthority);
                };
                debug!("{:?} - Received an in-range group message", self.our_address());
            } else {
                match message.destination().get_address() {
                    Some(ref address) => if !self.is_us(address) {
                        debug!("{:?} - Destination address {:?} is not us", self.our_address(),
                               address);
                        return Err(RoutingError::BadAuthority);
                    },
                    None => return Err(RoutingError::BadAuthority),
                }
            };
        }

        // Accumulate message
        debug!("{:?} - Accumulating signed message", self.our_address());
        let (accumulated_message, opt_token) = match self.accumulate(&signed_message) {
            Some((output_message, opt_token)) => (output_message, opt_token),
            None => {
                debug!("{:?} - Not enough signatures. Not processing request yet",
                       self.our_address());
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
                                if unwrap_option!(self.routing_table.as_ref(),
                                                  "Logic Error - Report Bug - We cannot be \
                                                  relocating if we are not a node")
                                    .address_in_our_close_group_range(&target_name) {
                                    self.handle_relocated_network_name(relocated_id,
                                                                       response_token)
                                } else {
                                    debug!("{:?} - Ignoring RelocatedNetworkName Request as we are \
                                           not close to the relocated name", self.our_address());
                                    Err(RoutingError::BadAuthority)
                                }
                            },
                            _ => {
                                debug!("{:?} - Ignoring Invalid RelocatedNetworkName Request",
                                       self.our_address());
                                Err(RoutingError::BadAuthority)
                            },
                        }

                    },
                    InternalRequest::Connect(_) => {
                        match opt_token {
                            Some(response_token) =>
                                self.handle_connect_request(request,
                                                            accumulated_message.from_authority,
                                                            accumulated_message.to_authority,
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
                        match claimant.clone() {
                            // TODO (ben 23/08/2015) later consider whether we need to restrict it
                            // to only from nodes within our close group
                            Address::Node(name) =>
                                self.handle_refresh(type_tag, name, bytes, refresh_authority, cause),
                            Address::Client(_) => Err(RoutingError::BadAuthority),
                        }
                    }
                }
            }
            Content::InternalResponse(response) => {
                match response {
                    InternalResponse::RelocatedNetworkName(_, _, _) => {
                        debug!("{:?} - Handling cache network name response {:?} ourselves",
                               self.our_address(), response);
                        self.handle_cache_network_name_response(response,
                                                                accumulated_message.from_authority,
                                                                accumulated_message.to_authority)
                    }
                    InternalResponse::Connect(_, _) => {
                        debug!("{:?} - Handling connect response {:?} ourselves",
                               self.our_address(), response);
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
                    response_token: opt_token,
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
                self.claimant_message_filter.add((message, claimant));
                Ok(())
            }
            Err(RoutingError::UnknownMessageType) => {
                self.claimant_message_filter.add((message, claimant));
                Err(RoutingError::UnknownMessageType)
            }
            Err(e) => Err(e),
        }
    }

    fn accumulate(&mut self,
                  signed_message: &SignedMessage)
                  -> Option<(RoutingMessage, Option<SignedToken>)> {
        let message = signed_message.get_routing_message().clone();

        // If the message is not from a group then don't accumulate
        if !message.from_authority.is_group() {
            debug!("{:?} - Message from {:?}, returning with SignedToken", self.our_address(),
                   message.from_authority);
            // TODO: If not from a group, then use client's public key to check
            // the signature.
            let token = match signed_message.as_token() {
                Ok(token) => token,
                Err(_) => {
                    error!("{:?} - Failed to generate signed token, message {:?} is dropped",
                           self.our_address(), message);
                    return None;
                }
            };
            return Some((message, Some(token)));
        }

        let claimant: NameType = match *signed_message.claimant() {
            Address::Node(ref claimant) => claimant.clone(),
            Address::Client(_) => {
                error!("{:?} - Claimant is a Client, but passed into message_accumulator for a \
                       group; dropping", self.our_address());
                // debug_assert!(false);
                return None;
            }
        };

        debug!("{:?} - Adding message from {:?} to message_accumulator", self.our_address(),
               claimant);
        let dynamic_quorum_size = self.routing_table_quorum_size();
        self.message_accumulator.set_quorum_size(dynamic_quorum_size);
        if self.message_accumulator.add(message.clone(), ()).is_some() {
            self.handled_messages.add(message.clone());
            Some((message, None))
        } else {
            None
        }
    }

    // ---- Direct Messages -----------------------------------------------------------------------

    fn direct_message_received(&mut self,
                               direct_message: ::direct_messages::DirectMessage,
                               connection: ::crust::Connection) {

        match direct_message.content() {
            &::direct_messages::Content::Hello(ref hello) => {
                // verify signature of hello
                if !direct_message.verify_signature(&hello.public_id.signing_public_key()) {
                    error!("{:?} - DirectMessage::Hello failed signature verification on {:?}",
                           self.our_address(), connection);
                    self.crust_service.drop_node(connection);
                };
                let _ = self.handle_hello(connection, hello);
            }
            &::direct_messages::Content::Churn(ref his_close_group) => {
                // TODO (ben 26/08/2015) verify the signature with the public_id
                // from our routing table.
                self.handle_churn(his_close_group);
            }
        };
    }

    // ---- Churn ---------------------------------------------------------------------------------

    fn generate_churn(&mut self,
                      churn: ::direct_messages::Churn,
                      target: Vec<::crust::Connection>,
                      cause: ::NameType)
                      -> RoutingResult {
        debug!("{:?} - CHURN: sending {} names to {} close nodes", self.our_address(),
               churn.close_group.len(), target.len());
        self.refresh_causes.add(cause.clone());
        // send Churn to all our close group nodes
        let direct_message = match ::direct_messages::DirectMessage::new(
            ::direct_messages::Content::Churn(churn.clone()),
            self.id().signing_private_key()) {
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
        debug!("{:?} - CHURN: received {} names", self.our_address(), churn.close_group.len());
        for his_close_node in churn.close_group.iter() {
            self.refresh_routing_table(his_close_node);
        }
    }

    // ---- Request Network Name ------------------------------------------------------------------

    fn request_network_name(&mut self, to_authority: Authority, content: Content) -> RoutingResult {
        if self.client_restriction {
            debug!("{:?} - Not requesting a network name we are a Client", self.our_address());
            return Ok(());
        };
        if self.has_bootstrap_endpoints() {
            // FIXME (ben 14/08/2015) we need a proper function to retrieve a bootstrap_name
            let bootstrap_name = match self.get_a_bootstrap_name() {
                Some(name) => name,
                None => return Err(RoutingError::NotBootstrapped),
            };
            let routing_message = RoutingMessage {
                from_authority: Authority::Client(bootstrap_name, self.id().signing_public_key()),
                to_authority: to_authority,
                content: content,
            };
            match SignedMessage::new(Address::Client(self.id().signing_public_key()),
                                     routing_message,
                                     self.id().signing_private_key()) {
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
                _ => error!("{:?} - InternalRequest/Response was sent back to user {:?}",
                            self.our_address(), content),
            }
        }
        Ok(())
    }

    fn handle_request_network_name(&mut self,
                                   request: InternalRequest,
                                   from_authority: Authority,
                                   to_authority: Authority,
                                   response_token: SignedToken)
                                   -> RoutingResult {
        if self.client_restriction {
            debug!("{:?} - Client restricted not requesting network name", self.our_address());
            return Ok(());
        }

        match request {
            InternalRequest::RequestNetworkName(public_id) => {
                match (&from_authority, &to_authority) {
                    (&Authority::Client(_bootstrap_node, key), &Authority::NaeManager(name)) => {
                        let hashed_key = ::sodiumoxide::crypto::hash::sha512::hash(&key.0);
                        let close_group_to_client = NameType::new(hashed_key.0);

                        if !(unwrap_option!(self.routing_table.as_ref(), "Routing Table must be \
                                          present if we are meant to relocate a client.")
                            .address_in_our_close_group_range(&close_group_to_client) &&
                                close_group_to_client == name) {
                            // TODO(Spandan) Create a better error
                            return Err(RoutingError::BadAuthority)
                        }

                        let mut network_public_id = public_id.clone();
                        match self.our_close_group() {
                            Some(close_group) => {
                                let relocated_name = try!(utils::calculate_relocated_name(
                                    close_group, &public_id.name()));
                                debug!("{:?} - Got a request for a network name from {:?}, \
                                       assigning {:?}", self.our_address(), from_authority,
                                       relocated_name);
                                network_public_id.assign_relocated_name(relocated_name.clone());

                                // TODO(Spandan) How do we tell Y how to reach A through B

                                let routing_message = RoutingMessage {
                                    from_authority: to_authority,
                                    to_authority: Authority::NaeManager(relocated_name.clone()),
                                    content: Content::InternalRequest(
                                        InternalRequest::RelocatedNetworkName(network_public_id,
                                        response_token)),
                                };
                                match SignedMessage::new(Address::Node(self.id().name()),
                                                         routing_message,
                                                         self.id().signing_private_key()) {
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

    fn handle_relocated_network_name(&mut self,
                                     relocated_id: PublicId,
                                     response_token: SignedToken) -> RoutingResult {
        debug!("{:?} Handling Relocated Network Name", self.our_address());

        let signed_message = try!(SignedMessage::new_from_token(response_token.clone()));
        let target_client_authority = signed_message.get_routing_message().source();
        let from_authority = Authority::NaeManager(self.id.name());

        let public_ids = unwrap_option!(self.routing_table.as_ref(), "Logic Error - Report bug. \
                                                                      Cannot be handling relocation \
                                                                      if not a node.")
                         .our_close_group()
                         .iter()
                         .map(|node_info| node_info.public_id.clone())
                         .collect();

        debug!("{:?} - Network request to accept name {:?}, responding \
               with our close group {:?} to {:?}", self.our_address(),
               relocated_id.name(), public_ids, target_client_authority);

        let _ = self.public_id_cache.insert(relocated_id.name().clone(), relocated_id.clone());

        let internal_response = InternalResponse::RelocatedNetworkName(relocated_id,
                                                                       public_ids,
                                                                       response_token);
        let routing_message = RoutingMessage {
            from_authority: from_authority,
            to_authority: target_client_authority,
            content: Content::InternalResponse(internal_response),
        };

        match SignedMessage::new(Address::Node(self.id().name()),
                                 routing_message,
                                 self.id().signing_private_key()) {
            Ok(signed_message) => Ok(ignore(self.send(signed_message))),
            Err(e) => return Err(RoutingError::Cbor(e)),
        }
    }

    fn handle_cache_network_name_response(&mut self,
                                          response: InternalResponse,
                                          _from_authority: Authority,
                                          _to_authority: Authority)
                                          -> RoutingResult {
        // An additional blockage on acting to restrict RoutingNode from becoming a full node
        if self.client_restriction {
            return Ok(());
        };
        match response {
            InternalResponse::RelocatedNetworkName(network_public_id, group, signed_token) => {
                if !signed_token.verify_signature(&self.id().signing_public_key()) {
                    return Err(RoutingError::FailedSignature);
                };
                let request = try!(SignedMessage::new_from_token(signed_token));
                match request.get_routing_message().content {
                    Content::InternalRequest(InternalRequest::RequestNetworkName(
                            ref original_public_id)) => {
                        let mut our_public_id = PublicId::new(self.id());
                        if &our_public_id != original_public_id {
                            return Err(RoutingError::BadAuthority);
                        };
                        our_public_id.set_name(network_public_id.name());
                        if our_public_id != network_public_id {
                            return Err(RoutingError::BadAuthority);
                        };
                        let _ = self.assign_network_name(&network_public_id.name());
                        debug!("{:?} - Assigned network name {:?} and our address now is {:?}",
                               self.our_address(), network_public_id.name(), self.our_address());
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
            if self.check_node(&ConnectionName::Routing(from_node.clone())) {
                debug!("{:?} - Refresh routing table for peer {:?}", self.our_address(), from_node);
                match self.send_connect_request(from_node) {
                    Ok(()) => debug!("{:?} - Sent connect request to {:?}", self.our_address(),
                                     from_node),
                    Err(error) => error!("{:?} - Failed to send connect request to {:?} - {:?}",
                                         self.our_address(), from_node, error)
                }
            }
            self.connection_filter.add(from_node.clone());
        }
    }

    fn send_connect_request(&mut self, peer_name: &NameType) -> RoutingResult {
        let (from_authority, address) = match self.state() {
            &State::Disconnected => return Err(RoutingError::NotBootstrapped),
            &State::Bootstrapped => {
                let name = match self.get_a_bootstrap_name() {
                    Some(name) => name,
                    // (TODO Brian 19.10.15) Shouldn't happen since we should have at least one
                    // bootstrap connection, but should be acted on explicitly if it we get here.
                    None => return Err(RoutingError::Interface(InterfaceError::NotConnected)),
                };

                let signing_key = self.id().signing_public_key();
                (Authority::Client(name, signing_key),
                 Address::Client(signing_key))
            }
            &State::Terminated => {
                // (TODO Brian 19.10.15) A new error code may be more appropriate here.
                return Err(RoutingError::Terminated);
            }
            _ => {
                let name = self.id().name();
                (Authority::ManagedNode(name), Address::Node(name))
            }
        };

        debug!("{:?} - Sending connect request from {:?} to {:?}", self.our_address(),
               from_authority, peer_name);
        let routing_message = RoutingMessage {
            from_authority: from_authority,
            to_authority: Authority::ManagedNode(peer_name.clone()),
            content: Content::InternalRequest(InternalRequest::Connect(ConnectRequest {
                endpoints: self.accepting_on.clone(),
                public_id: PublicId::new(self.id()),
            })),
        };

        match SignedMessage::new(address, routing_message, self.id().signing_private_key()) {
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
        debug!("{:?} - Handle ConnectRequest", self.our_address());
        match request {
            InternalRequest::Connect(connect_request) => {
                if !connect_request.public_id.is_relocated() {
                    warn!("{:?} - Connect request {:?} requester is not relocated",
                          self.our_address(), connect_request);
                    return Err(RoutingError::RejectedPublicId);
                };
                // First verify that the message is correctly self-signed.
                if !response_token.verify_signature(&connect_request.public_id
                                                                    .signing_public_key()) {
                    warn!("{:?} - Connect request {:?} response token invalid",
                          self.our_address(), connect_request);
                    return Err(RoutingError::FailedSignature);
                };
                if !self.check_node(&ConnectionName::Routing(connect_request.public_id.name())) {
                    debug!("{:?} - Connect request {:?} check node failed", self.our_address(),
                           connect_request);
                    return Err(RoutingError::RefusedFromRoutingTable);
                };

                // TODO (ben 13/08/2015) use public_id_cache or result of future RFC
                // to validate the public_id from the network

                let routing_message = RoutingMessage {
                    from_authority: Authority::ManagedNode(self.id().name()),
                    to_authority: from_authority,
                    content: Content::InternalResponse(InternalResponse::Connect(ConnectResponse {
                            endpoints: self.accepting_on.clone(),
                            public_id: PublicId::new(self.id()),
                        }, response_token)),
                };
                match SignedMessage::new(Address::Node(self.id().name()),
                                         routing_message,
                                         self.id().signing_private_key()) {
                    Ok(signed_message) => {
                        ignore(self.send(signed_message));
                        let connection_token = self.get_connection_token();
                        self.add_expected_connection(ExpectedConnection::Request(
                            connection_token.clone(), connect_request.clone()));
                        debug!("{:?} - Connecting on validated ConnectRequest with connection \
                               token {:?}", self.our_address(), connection_token);
                        self.connect(connection_token, &connect_request.endpoints);
                        self.connection_filter.add(connect_request.public_id.name());
                    }
                    Err(error) => return Err(RoutingError::Cbor(error)),
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

        debug!("{:?} - Handle ConnectResponse", self.our_address());
        match response {
            InternalResponse::Connect(connect_response, signed_token) => {
                if !signed_token.verify_signature(&self.id().signing_public_key()) {
                    error!("{:?} - ConnectResponse from {:?} failed our signature for the signed \
                           token", self.our_address(), from_authority);
                    return Err(RoutingError::FailedSignature);
                };
                let connect_request = try!(SignedMessage::new_from_token(signed_token.clone()));
                match connect_request.get_routing_message().from_authority.get_address() {
                    Some(address) => if !self.is_us(&address) {
                        error!("{:?} - Connect response contains request that was not from us",
                               self.our_address());
                        return Err(RoutingError::BadAuthority);
                    },
                    None => return Err(RoutingError::BadAuthority),
                }
                // Are we already connected, or still interested?
                if !self.check_node(&ConnectionName::Routing(connect_response.public_id.name())) {
                    error!("{:?} - ConnectResponse already connected to {:?}", self.our_address(),
                           from_authority);
                    return Err(RoutingError::RefusedFromRoutingTable);
                };

                let connection_token = self.get_connection_token();
                self.add_expected_connection(ExpectedConnection::Response(
                    connection_token.clone(), connect_response.clone()));
                debug!("{:?} - Connecting on validated ConnectResponse from {:?} with connection \
                       token {:?}", self.our_address(),
                       from_authority,
                       connection_token);
                self.connect(connection_token, &connect_response.endpoints);
                self.connection_filter.add(connect_response.public_id.name());

                Ok(())
            }
            _ => return Err(RoutingError::BadAuthority),
        }
    }

    fn connect(&mut self, connection_token: u32, endpoints: &Vec<::crust::Endpoint>) {
        debug!("{:?} - Connect: requesting crust connect to {:?}", self.our_address(), endpoints);
        self.crust_service.connect(connection_token, endpoints.clone());
    }

    fn get_connection_token(&mut self) -> u32 {
        let connection_token = self.connection_counter.clone();
        self.connection_counter = self.connection_counter.wrapping_add(1u32);
        if self.connection_counter == 0u32 {
            self.connection_counter == 1u32;
        }
        connection_token
    }

    fn drop_connections(&mut self, connections: Vec<::crust::Connection>) {
        for connection in connections {
            self.crust_service.drop_node(connection);
        }
    }

    fn match_connection(&mut self,
            expected_connection: Option<(ExpectedConnection,
                                         Option<::crust::Connection>)>,
            unknown_connection: Option<(::crust::Connection, Option<::direct_messages::Hello>)>) {
        self.match_connection_core(expected_connection, unknown_connection)
    }

    // ----- Send Functions -----------------------------------------------------------------------

    fn send_to_user(&self, event: Event) {
        debug!("{:?} - Send to user event {:?}", self.our_address(), event);
        if self.event_sender.send(event).is_err() {
            error!("{:?} - Channel to user is broken; terminating", self.our_address());
            let _ = self.action_sender.send(Action::Terminate);
        }
    }

    fn send_content(&mut self,
                    our_authority: Authority,
                    to_authority: Authority,
                    content: Content)
                    -> RoutingResult {
        if self.is_connected_node() {
            let routing_message = RoutingMessage {
                from_authority: our_authority,
                to_authority: to_authority,
                content: content,
            };
            match SignedMessage::new(Address::Node(self.id().name()),
                                     routing_message,
                                     self.id().signing_private_key()) {
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
                        interface_error: InterfaceError::NotConnected,
                    });
                }
                Content::ExternalResponse(external_response) => {
                    self.send_to_user(Event::FailedResponse {
                        response: external_response,
                        our_authority: Some(our_authority),
                        location: to_authority,
                        interface_error: InterfaceError::NotConnected,
                    });
                }
                // FIXME (ben 24/08/2015) InternalRequest::Refresh can pass here on failure
                _ => error!("{:?} - InternalRequest/Response was sent back to user {:?}",
                            self.our_address(), content),
            }
        }
        Ok(())
    }

    fn client_send_content(&mut self, to_authority: Authority, content: Content) -> RoutingResult {
        if self.is_connected_node() || self.has_bootstrap_endpoints() {
            // FIXME (ben 14/08/2015) we need a proper function to retrieve a bootstrap_name
            let bootstrap_name = match self.get_a_bootstrap_name() {
                Some(name) => name,
                None => return Err(RoutingError::NotBootstrapped),
            };
            let routing_message = RoutingMessage {
                from_authority: Authority::Client(bootstrap_name, self.id().signing_public_key()),
                to_authority: to_authority,
                content: content,
            };
            match SignedMessage::new(Address::Client(self.id().signing_public_key()),
                                     routing_message,
                                     self.id().signing_private_key()) {
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
                _ => error!("{:?} - InternalRequest/Response was sent back to user {:?}",
                            self.our_address(), content),
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
    fn send(&mut self, signed_message: SignedMessage) -> RoutingResult {
        let destination = signed_message.get_routing_message().destination();
        debug!("{:?} - Send request to {:?}", self.our_address(), destination);
        let bytes = try!(encode(&signed_message));
        // query the routing table for parallel or swarm
        let connections = self.target_connections(&destination);
        debug!("{:?} - Target connections for send: {:?}", self.our_address(), connections);
        if !connections.is_empty() {
            debug!("{:?} - Sending {:?} to {:?} target connection(s)", self.our_address(),
                   signed_message.get_routing_message().content,
                   connections.len());
            for connection in connections {
                // TODO(ben 10/08/2015) drop endpoints that fail to send
                self.crust_service.send(connection, bytes.clone());
            }
        }

        match self.bootstrap_connections() {
            Some(bootstrap_connections) => {
                debug!("{:?} - Bootstrap connections for send {:?}", self.our_address(),
                       bootstrap_connections);
                // TODO (ben 10/08/2015) Strictly speaking we do not have to validate that
                // the relay_name in from_authority Client(relay_name, client_public_key) is
                // the name of the bootstrap connection we're sending it on.  Although this might
                // open a window for attacking a node, in v0.3.* we can leave this unresolved.
                for connection in bootstrap_connections {
                    self.crust_service.send(connection.clone(), bytes.clone());
                    debug!("{:?} - Sent {:?} to bootstrap connection {:?}", self.our_address(),
                           signed_message.get_routing_message().content,
                           connection);
                    break;
                }
            }
            None => {}
        }

        // If we need handle this message, move this copy into the channel for later processing.
        if self.name_in_range(&destination.get_location()) {
            if let Authority::Client(_, _) = destination {
                return Ok(());
            };
            debug!("{:?} - Queuing message for processing ourselves", self.our_address());
            try!(self.message_received(signed_message));
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
            if !token.verify_signature(&self.id().signing_public_key()) {
                return Err(RoutingError::FailedSignature);
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

    fn get_a_bootstrap_name(&self) -> Option<NameType> {
        match self.bootstrap_names() {
            Some(bootstrap_names) => {
                // TODO (ben 13/08/2015) for now just take the first bootstrap name as our relay
                match bootstrap_names.first() {
                    Some(bootstrap_name) => Some(bootstrap_name.clone()),
                    None => None,
                }
            }
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
                Some(_) => {}
            }
        } else {
            self.data_cache = None;
        }
    }

    fn handle_cache_put(&mut self, message: &RoutingMessage) {
        let our_address = self.our_address();
        match self.data_cache {
            Some(ref mut data_cache) => {
                match message.content.clone() {
                    Content::ExternalResponse(response) => {
                        match response {
                            ExternalResponse::Get(data, _, _) => {
                                match data {
                                    Data::PlainData(_) => {
                                        if self.cache_options.plain_data_caching_enabled() {
                                            debug!("{:?} - Caching PlainData {:?}", our_address,
                                                   data.name());
                                            let _ = data_cache.insert(data.name(), data.clone());
                                        }
                                    }
                                    Data::StructuredData(_) => {
                                        if self.cache_options.structured_data_caching_enabled() {
                                            debug!("{:?} - Caching StructuredData {:?}",
                                                   our_address, data.name());
                                            let _ = data_cache.insert(data.name(), data.clone());
                                        }
                                    }
                                    Data::ImmutableData(_) => {
                                        if self.cache_options.immutable_data_caching_enabled() {
                                            debug!("{:?} - Caching ImmutableData {:?}",
                                                   our_address, data.name());
                                            // TODO verify data
                                            let _ = data_cache.insert(data.name(), data.clone());
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }

                    }
                    _ => {}
                }
            }
            None => {}
        }

    }

    fn handle_cache_get(&mut self, message: &RoutingMessage) -> Option<Content> {
        let our_address = self.our_address();
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
                                                    debug!("{:?} - Got PlainData {:?} from cache",
                                                           our_address, data_name);
                                                    let response =
                                                        ExternalResponse::Get(data.clone(),
                                                                              data_request,
                                                                              None);
                                                    return Some(Content::ExternalResponse(response));
                                                }
                                                None => return None,
                                            }
                                        }
                                        return None;
                                    }
                                    DataRequest::StructuredData(_, _) => {
                                        if self.cache_options.structured_data_caching_enabled() {
                                            match data_cache.get(&data_request.name()) {
                                                Some(data) => {
                                                    debug!("{:?} - Got StructuredData {:?} from \
                                                           cache", our_address,
                                                           data_request.name());
                                                    let response =
                                                        ExternalResponse::Get(data.clone(),
                                                                              data_request,
                                                                              None);
                                                    return Some(Content::ExternalResponse(response));
                                                }
                                                None => return None,
                                            }
                                        }
                                        return None;
                                    }
                                    DataRequest::ImmutableData(data_name, _) => {
                                        if self.cache_options.immutable_data_caching_enabled() {
                                            match data_cache.get(&data_name) {
                                                Some(data) => {
                                                    debug!("{:?} - Got ImmutableData {:?} from \
                                                           cache", our_address, data_name);
                                                    let response =
                                                        ExternalResponse::Get(data.clone(),
                                                                              data_request,
                                                                              None);
                                                    return Some(Content::ExternalResponse(response));
                                                }
                                                None => return None,
                                            }
                                        }
                                        return None;
                                    }
                                }
                            }
                            _ => None,
                        }

                    }
                    _ => None,
                }

            }
            None => None,
        }
    }

    fn routing_table_quorum_size(&self) -> usize {
        return ::std::cmp::min(unwrap_option!(self.routing_table.as_ref(), "Logic Error - Report bug\
                                              . Routing Table must be present if we are working \
                                              with quorum sizes.").size(),
                               ::types::QUORUM_SIZE)
    }

    // START ==================================================================================================
    /// Borrow RoutingNode id.
    pub fn id(&self) -> &Id {
        &self.id
    }

    /// Returns Address::Node(network_given_name) or Address::Client(PublicKey) when no network name
    /// is given.
    pub fn our_address(&self) -> Address {
        match self.network_name {
            Some(name) => Address::Node(name.clone()),
            None => Address::Client(self.id.signing_public_key()),
        }
    }

    /// Returns true if Client(public_key) matches our public signing key, even if we are a full
    /// node; or returns true if Node(name) is our current name.  Note that there is a difference to
    /// using core::our_address, as that would fail to assert an (old) Client identification after
    /// we were assigned a network name.
    pub fn is_us(&self, address: &Address) -> bool {
        match *address {
            Address::Client(public_key) => public_key == self.id.signing_public_key(),
            Address::Node(name) => name == self.id().name(),
        }
    }

    /// Returns a borrow of the current state
    pub fn state(&self) -> &State {
        &self.state
    }

    /// Restarts the full routing core to a disconnected state and will return a full list of all
    /// open connections to drop, if any should linger.  Restarting with persistent identity will
    /// preserve the ID only if it has not been relocated.
    pub fn restart_core(&mut self, persistant: bool) -> Vec<::crust::Connection> {
        debug!("{:?} - Restarting", self.our_address());
        if self.id.is_relocated() || !persistant {
            self.id = ::id::Id::new();
        };
        self.state = State::Disconnected;
        let mut open_connections = Vec::new();
        let bootstrap_connections = match self.bootstrap_map {
            Some(ref bootstrap_map) => bootstrap_map.connections(),
            None => vec![],
        };
        for connection in bootstrap_connections {
            open_connections.push(connection.clone());
        }
        let relay_connections = match self.relay_map {
            Some(ref relay_map) => relay_map.connections(),
            None => vec![],
        };
        for connection in relay_connections {
            open_connections.push(connection.clone());
        }
        // routing table should be empty in all sensible use-cases of restart() already.
        // this is merely a redundancy measure.
        let routing_connections = match self.routing_table {
            Some(ref rt) => rt.all_connections(),
            None => vec![],
        };
        for connection in routing_connections {
            open_connections.push(connection.clone());
        }
        self.routing_table = None;
        self.network_name = None;
        self.relay_map = None;
        self.bootstrap_map = Some(::utilities::ConnectionMap::new());
        open_connections
    }

    /// Assigning a network received name to the core.  If a name is already assigned, the function
    /// returns false and no action is taken.  After a name is assigned, Routing connections can be
    /// accepted.
    pub fn assign_network_name(&mut self, network_name: &NameType) -> bool {
        match self.state {
            State::Disconnected => {
                debug!("{:?} - Assigning name {:?} while disconnected", self.our_address(),
                       network_name);
            }
            State::Bootstrapped => {}
            State::Relocated => return false,
            State::Connected => return false,
            State::GroupConnected => return false,
            State::Terminated => return false,
        };
        // if routing_table is constructed, reject name assignment
        match self.routing_table {
            Some(_) => {
                error!("{:?} - Attempt to assign name {:?} while status is {:?}",
                       self.our_address(), network_name, self.state);
                return false;
            }
            None => {}
        };
        if !self.id.assign_relocated_name(network_name.clone()) {
            return false;
        };
        debug!("{:?} - Creating routing table after relocation", self.our_address());
        self.routing_table = Some(RoutingTable::new(&network_name));
        self.relay_map = Some(::utilities::ConnectionMap::new());
        self.network_name = Some(network_name.clone());
        self.state = State::Relocated;
        debug!("{:?} - Our state {:?}", self.our_address(), self.state);
        true
    }

    /// Currently wraps around RoutingCore::assign_network_name
    pub fn assign_name(&mut self, name: &NameType) -> bool {
        // wrap to assign_network_name
        self.assign_network_name(name)
    }

    /// Look up a connection in the routing table and the relay map and return the ConnectionName
    fn lookup_connection(&self, connection: &crust::Connection) -> Option<ConnectionName> {
        if self.state == State::Disconnected || self.state == State::Terminated {
            return None;
        }

        match self.routing_table {
            Some(ref routing_table) => {
                match routing_table.lookup_endpoint(&connection.peer_endpoint()) {
                    Some(name) => return Some(ConnectionName::Routing(name)),
                    None => {}
                };
            }
            None => {}
        };

        match self.relay_map {
            Some(ref relay_map) => {
                match relay_map.lookup_connection(&connection) {
                    Some(public_id) => return Some(ConnectionName::Relay(
                        ::types::Address::Client(public_id.signing_public_key().clone()))),
                    None => {}
                }
            }
            None => {}
        };

        if self.state != State::Connected && self.state != State::GroupConnected {
            match self.bootstrap_map {
                Some(ref bootstrap_map) => {
                    match bootstrap_map.lookup_connection(&connection) {
                        Some(public_id) => return Some(ConnectionName::Bootstrap(public_id.name())),
                        None => {}
                    }
                }
                None => {}
            }
        }

        None
    }

    /// Drops the associated name from the relevant connection map or from routing table.
    /// If dropped from the routing table a churn event is triggered for the user
    /// if the dropped peer changed our close group and churn is generated in routing.
    /// If dropped from a connection map and multiple connections are active on the same identity
    /// all connections will be dropped asynchronously.  Removing a node from the routing table
    /// does not ensure the connection is dropped.
    pub fn drop_peer(&mut self, connection_name: &ConnectionName) -> RoutingResult {
        debug!("{:?} - Drop peer {:?} current state {:?}", self.our_address(), connection_name,
               self.state.clone());
        let current_state = self.state.clone();
        match *connection_name {
            ConnectionName::Routing(name) => {
                if self.routing_table.is_some() {
                    let trigger_churn;
                    let routing_table_count_prior;
                    {
                        let routing_table_ref = unwrap_option!(self.routing_table.as_ref(),
                                                               "Logic Error - Report bug");
                        trigger_churn = routing_table_ref.address_in_our_close_group_range(&name);
                        routing_table_count_prior = routing_table_ref.size();
                    }

                    unwrap_option!(self.routing_table.as_mut(), "Logic Error - Report bug")
                        .drop_node(&name);

                    match routing_table_count_prior {
                        1usize => {
                            error!("{:?} - Routing Node has disconnected", self.our_address());
                            self.state = State::Disconnected;
                            let _ = self.event_sender.send(Event::Disconnected);
                        }
                        ::types::GROUP_SIZE => {
                            self.state = State::Connected;
                        }
                        _ => {}
                    }

                    info!("{:?} - RT({}) dropped node {:?}", self.our_address(),
                          unwrap_option!(self.routing_table.as_ref(), "").size(), name);

                    if trigger_churn {
                        let our_close_group = unwrap_option!(self.routing_table.as_ref(),
                                                             "Logic Error - Report bug")
                                                  .our_close_group();

                        let mut close_group = our_close_group.iter()
                                                             .map(|node_info| {
                                                                 node_info.public_id.name()
                                                             })
                                                             .collect::<Vec<::NameType>>();

                        close_group.insert(0, self.id.name());

                        let target_connections =
                            our_close_group.iter()
                                           .filter_map(|node_info| node_info.connection)
                                           .collect::<Vec<::crust::Connection>>();

                        let churn_msg = ::direct_messages::Churn { close_group: close_group };
                        if let Err(err) = self.generate_churn(churn_msg, target_connections, name) {
                            return Err(err);
                        }
                    }
                }
            }
            ConnectionName::Bootstrap(name) => {
                if self.bootstrap_map.is_some() {
                    let bootstrapped_prior;
                    let connections_to_drop;
                    let bootstrap_map_len_after;
                    {
                        let bootstrap_map_ref = unwrap_option!(self.bootstrap_map.as_mut(),
                                                               "Logic Error - Report bug");
                        bootstrapped_prior = bootstrap_map_ref.identities_len() > 0;
                        connections_to_drop = bootstrap_map_ref.drop_identity(&name).1;
                        bootstrap_map_len_after = bootstrap_map_ref.identities_len();
                    }

                    if !connections_to_drop.is_empty() {
                        self.drop_connections(connections_to_drop);
                    }

                    match self.state {
                        State::Bootstrapped | State::Relocated => {
                            if bootstrap_map_len_after == 0usize && bootstrapped_prior {
                                error!("{:?} - Routing Client has disconnected",
                                       self.our_address());
                                self.state = State::Disconnected;
                                let _ = self.event_sender.send(Event::Disconnected);
                            };
                        }
                        _ =>
                            debug!("{:?} - Unhandled state {:?} in drop_peer -> \
                                   ConnectionName::Bootstrap", self.our_address(), self.state),
                    };
                }
            }
            ConnectionName::Relay(::types::Address::Client(public_key)) => {
                if self.relay_map.is_some() {
                    let (_dropped_public_id, connections_to_drop) =
                        unwrap_option!(self.relay_map.as_mut(), "Logic Error - Report bug")
                            .drop_identity(&Relay { public_key: public_key, });
                    if !connections_to_drop.is_empty() {
                        self.drop_connections(connections_to_drop);
                    }
                }
            }
            _ => debug!("{:?} - Unhandled ConnectionName {:?} in drop_peer", self.our_address(),
                        connection_name),
        }

        match self.state {
            State::Disconnected => {
                if current_state == State::Disconnected {
                    // TODO (Spandan) - This was an empty return - analyse to see if this need an
                    //                  error return or an Ok return
                    return Ok(());
                }
                self.routing_table = None;
                self.restart();
                self.crust_service.bootstrap(0u32);
            }
            _ => {}
        }

        Ok(())
    }

    /// Add a client to our relay map
    pub fn add_client(&mut self,
                      public_key: ::sodiumoxide::crypto::sign::PublicKey,
                      connection: crust::Connection,
                      public_id: PublicId) -> bool {
        let relay = Relay {
            public_key: public_key,
        };

        let relay_map = unwrap_option!(self.relay_map.as_mut(),
                                       "Logic Error - Report Bug. If this was triggered it would \
                                        mean that Client is being asked to bootstrap some other \
                                        Client.");
        relay_map.add_peer(connection,
                           relay,
                           public_id)
    }

    /// To be documented
    pub fn add_peer(&mut self,
                    identity: ConnectionName,
                    connection: crust::Connection,
                    public_id: PublicId)
                    -> bool {
        let endpoint = connection.peer_endpoint();
        let our_address = self.our_address();

        match identity {
            ConnectionName::Routing(routing_name) => {
                if public_id.name() != routing_name {
                    return false;
                }

                // TODO(Spandan) - Suspicious code - is there a possiblility of getting add_peer()
                // even if there is no routing table ? When and why would this happen ?
                //
                // - https://github.com/maidsafe/routing/pull/771
                // Ans(David in GitHub) - The routing table should always exist IMHO, I suspect the
                // creation of a routing table was used to promote to a node instead of being a
                // client. So to be clear we should not do this, we should have a routing table if
                // we are a node & only a node can get an add_peer(). To add a peer we make sure the
                // call comes only from a connect_request (if we are receiving this) or a
                // connect_response (if we are receiving this) and we add it if it passes the
                // routing_table.add(). IF we think a peer is worth connecting to we do a
                // routing_table.check() & if successful then we initiate the connect_request (or
                // connect_response).
                if self.routing_table.is_some() {
                    let trigger_churn;
                    let routing_table_count_prior;
                    let add_node_result;

                    let node_info = NodeInfo::new(public_id,
                                                  vec![endpoint.clone()],
                                                  Some(connection));

                    {
                        let routing_table_ref = unwrap_option!(self.routing_table.as_mut(),
                                                               "Logic Error - Report bug");
                        trigger_churn =
                            routing_table_ref.address_in_our_close_group_range(&routing_name);
                        routing_table_count_prior = routing_table_ref.size();
                        add_node_result = routing_table_ref.add_node(node_info);
                    }

                    match add_node_result.1 {
                        Some(node) => {
                            match node.connection {
                                Some(connection) => self.drop_connections(vec![connection]),
                                None =>
                                    debug!("{:?} - No Connection existed for a node in RT",
                                           our_address),
                            }
                        }
                        None => info!("{:?} - No node removed from RT as a result of node \
                                      addition", our_address),
                    }

                    if add_node_result.0 {
                        let size = unwrap_option!(self.routing_table.as_ref(),
                                                  "Logic Error - Report bug")
                                       .size();

                        if routing_table_count_prior == 0usize {
                            // if we transition from zero to one routing connection
                            info!("{:?} - Routing Node has connected", our_address);
                            self.state = State::Connected;
                        } else if routing_table_count_prior == ::types::GROUP_SIZE - 1usize {
                            info!("{:?} - Routing Node has connected to {} nodes", our_address,
                                  size);

                            self.state = State::GroupConnected;
                            if let Err(err) = self.event_sender.send(Event::Connected) {
                                error!("{:?} - Error sending {:?} to event_sender", our_address,
                                       err.0);
                            }
                        }

                        info!("{:?} - RT({}) added {:?}", our_address, size, routing_name);

                        if trigger_churn {
                            let our_close_group = unwrap_option!(self.routing_table.as_ref(),
                                                                 "Logic Error - Report bug")
                                                      .our_close_group();

                            let mut close_group: Vec<NameType> =
                                our_close_group.iter()
                                               .map(|node_info| node_info.public_id.name())
                                               .collect::<Vec<::NameType>>();

                            close_group.insert(0, self.id.name());
                            let targets =
                                our_close_group.iter()
                                               .filter_map(|node_info| node_info.connection)
                                               .collect::<Vec<::crust::Connection>>();

                            let churn_msg = ::direct_messages::Churn { close_group: close_group };

                            if let Err(err) = self.generate_churn(churn_msg,
                                                                  targets,
                                                                  routing_name) {
                                error!("{:?} - Unsuccessful Churn {:?}", our_address, err);
                            }
                        }
                    }

                    add_node_result.0
                } else {
                    false
                }
            }
            ConnectionName::Bootstrap(bootstrap_name) => {
                match self.bootstrap_map {
                    Some(ref mut bootstrap_map) => {
                        let bootstrapped_prior = bootstrap_map.identities_len() > 0usize;
                        let added = bootstrap_map.add_peer(connection, bootstrap_name, public_id);
                        if !bootstrapped_prior && added && self.routing_table.is_none() {
                            info!("{:?} - Routing Client bootstrapped", our_address);
                            self.state = State::Bootstrapped;
                            let _ = self.event_sender.send(Event::Bootstrapped);
                        };
                        added
                    }
                    None => false,
                }
            }
            _ => false,
        }
    }

    /// Check whether a certain identity is of interest to the core.
    /// For a Routing(NameType), the routing table will be consulted;
    /// for completeness we quote the documentation of RoutingTable::check_node below.
    /// Connections currently don't support multiple endpoints per peer,
    /// so if relay map (or routing table) already has the peer, then check_node returns false.
    /// For Relay connections it suffices that the relay map is not full to return true.
    /// For Bootstrap connections the relay map cannot be full and no routing table should exist;
    /// this logic is still under consideration [Ben 6/08/2015]
    /// For unidentified connections check_node always return true.
    /// Routing: "This is used to check whether it is worth while retrieving
    ///           a contact's public key from the PKI with a view to adding
    ///           the contact to our routing table.  The checking procedure is the
    ///           same as for 'AddNode' above, except for the lack of a public key
    ///           to check in step 1.
    /// Adds a contact to the routing table.  If the contact is added, the first return arg is true,
    /// otherwise false.  If adding the contact caused another contact to be dropped, the dropped
    /// one is returned in the second field, otherwise the optional field is empty.  The following
    /// steps are used to determine whether to add the new contact or not:
    ///
    /// 1 - if the contact is ourself, or doesn't have a valid public key, or is already in the
    ///     table, it will not be added
    /// 2 - if the routing table is not full (size < OptimalSize()), the contact will be added
    /// 3 - if the contact is within our close group, it will be added
    /// 4 - if we can find a candidate for removal (a contact in a bucket with more than BUCKET_SIZE
    ///     contacts, which is also not within our close group), and if the new contact will fit in
    ///     a bucket closer to our own bucket, then we add the new contact."
    pub fn check_node(&self, identity: &ConnectionName) -> bool {
        match *identity {
            ConnectionName::Routing(name) => {
                match self.state {
                    State::Disconnected => return false,
                    _ => {}
                };
                match self.routing_table {
                    Some(ref routing_table) => routing_table.check_node(&name),
                    None => return false,
                }
            }
            ConnectionName::Relay(_) => {
                match self.state {
                    State::Disconnected => return false,
                    _ => {}
                };
                match self.relay_map {
                    Some(ref relay_map) => !relay_map.is_full(),
                    None => return false,
                }
            }
            // TODO (ben 6/08/2015) up for debate, don't show interest for bootstrap connections,
            // after we have established a single bootstrap connection.
            ConnectionName::Bootstrap(_) => {
                match self.state {
                    State::Disconnected => {}
                    _ => return false,
                };
                match self.bootstrap_map {
                    Some(ref bootstrap_map) => !bootstrap_map.is_full(),
                    None => return false,
                }
            }
            ConnectionName::Unidentified(_, _) => true,
        }
    }

    /// Get the endpoints to send on as a node.  This will exclude the bootstrap connections
    /// we might have.  Endpoints returned here will expect us to send the message,
    /// as anything but a Client.  If to_authority is Client(_, public_key) and this client is
    /// connected, then we only return this endpoint.
    /// If the above condition is not satisfied, the routing table will either provide
    /// a set of endpoints to send parallel to or our full close group (ourselves excluded)
    /// when the destination is in range.
    /// If resulting vector is empty there are no routing connections.
    pub fn target_connections(&self, to_authority: &Authority) -> Vec<crust::Connection> {
        let mut target_connections = self.check_relocations(to_authority);
        if !target_connections.is_empty() {
            return target_connections;
        }

        // If we can relay to the client, return that client connection.
        match self.relay_map {
            Some(ref relay_map) => {
                match *to_authority {
                    Authority::Client(_, ref client_public_key) => {
                        debug!("{:?} - Looking for client target {:?}", self.our_address(),
                               *to_authority);
                        let (_, connections) = relay_map.lookup_identity(&Relay {
                            public_key: client_public_key.clone(),
                        });
                        debug!("{:?} - Got client connections {:?}", self.our_address(),
                               connections);
                        return connections;
                    }
                    _ => {
                        debug!("{:?} - Looking in relay map for {:?}", self.our_address(),
                               *to_authority);
                    }
                };
            }
            None => {}
        }

        let destination = to_authority.get_location();
        // Query routing table to send it out parallel or to our close group (ourselves excluded).
        match self.routing_table {
            Some(ref routing_table) => {
                for node_info in routing_table.target_nodes(destination) {
                    match node_info.connection {
                        Some(c) => target_connections.push(c.clone()),
                        None => {}
                    }
                }
            }
            None => {}
        };

        target_connections
    }

    /// Returns the available Boostrap connections as connections. If we are a connected node,
    /// then access to the bootstrap connections will be blocked, and None is returned.
    pub fn bootstrap_connections(&self) -> Option<Vec<::crust::Connection>> {
        // block explicitly if we are a connected node
        match self.state {
            State::Bootstrapped | State::Relocated => {
                match self.bootstrap_map {
                    Some(ref bootstrap_map) => Some(bootstrap_map.connections()),
                    None => None,
                }
            }
            _ => None,
        }
    }

    /// Returns the available Boostrap connections as names. If we are a connected node,
    /// then access to the bootstrap names will be blocked, and None is returned.
    pub fn bootstrap_names(&self) -> Option<Vec<::NameType>> {
        // block explicitly if we are a connected node
        match self.state {
            State::Bootstrapped | State::Relocated => {
                match self.bootstrap_map {
                    Some(ref bootstrap_map) => Some(bootstrap_map.identities()),
                    None => None,
                }
            }
            _ => None,
        }
    }

    /// Returns true if bootstrap connections are available. If we are a connected node, then access
    /// to the bootstrap connections will be blocked, and false is returned.  We might still receive
    /// messages from our bootstrap connections, but active usage is blocked once we are a node.
    pub fn has_bootstrap_endpoints(&self) -> bool {
        // block explicitly if routing table is available
        match self.state {
            State::Bootstrapped | State::Relocated => {
                match self.bootstrap_map {
                    Some(ref bootstrap_map) => bootstrap_map.identities_len() > 0usize,
                    None => false,
                }
            }
            _ => false,
        }
    }

    /// Returns true if the core is a full routing node and has connections
    pub fn is_connected_node(&self) -> bool {
        match self.routing_table {
            Some(ref routing_table) => routing_table.size() > 0,
            None => false,
        }
    }

    /// Returns true if a name is in range for our close group.
    /// If the core is not a full node, this always returns false.
    pub fn name_in_range(&self, name: &NameType) -> bool {
        match self.routing_table {
            Some(ref routing_table) => routing_table.address_in_our_close_group_range(name),
            None => false,
        }
    }

    /// Our authority is defined by the routing message, if we are a full node;  if we are a client,
    /// this always returns Client authority (where the relay name is taken from the routing message
    /// destination)
    pub fn our_authority(&self, message: &RoutingMessage) -> Option<Authority> {
        match self.routing_table {
            Some(ref routing_table) => {
                our_authority(message, routing_table)
            }
            // if the message reached us as a client, then destination.get_location()
            // was our relay name
            None => Some(Authority::Client(message.destination().get_location().clone(),
                                           self.id.signing_public_key())),
        }
    }

    /// Returns our close group as a vector of NameTypes, sorted from our own name;  Our own name is
    /// always included, and the first member of the result.  If we are not a full node None is
    /// returned.
    pub fn our_close_group(&self) -> Option<Vec<NameType>> {
        match self.routing_table {
            Some(ref routing_table) => {
                let mut close_group: Vec<NameType> = routing_table.our_close_group()
                                                                  .iter()
                                                                  .map(|node_info| {
                                                                      node_info.public_id.name()
                                                                  })
                                                                  .collect::<Vec<NameType>>();
                close_group.insert(0, self.id.name());
                Some(close_group)
            }
            None => None,
        }
    }

    /// Check whether the connection can be matched against a stored ConnectRequest/ConnectResponse.
    pub fn match_expected_connection(&mut self,
                                     connection: &::crust::Connection,
                                     connection_token: u32)
                                     -> Option<ExpectedConnection> {
        let expected_connections = self.expected_connections.retrieve_all();
        let by_token = |element: &&(ExpectedConnection, Option<::crust::Connection>)| {
            match element.0 {
                ExpectedConnection::Request(token, _) => connection_token == token,
                ExpectedConnection::Response(token, _) => connection_token == token,
            }
        };
        if let Some(&(ref key, mut value)) = expected_connections.iter().find(by_token) {
            match value {
                Some(crust_connection) => {
                    // If we've already matched a connection drop the new one.
                    info!("{:?} - Dropping an already matched connection {:?}", self.our_address(),
                          crust_connection);
                    self.drop_connections(vec![connection.clone()]);
                    None
                }
                None => {
                    debug!("{:?} - Expected connection {:?} matched on {:?}", self.our_address(),
                           key, connection);
                    value = Some(connection.clone());
                    *unwrap_option!(self.expected_connections.get_mut(&key),
                                    "Logic Error - Report bug") = value.clone();
                    self.match_connection(Some((key.clone(), value)), None);
                    Some(key.clone())
                }
            }
        } else {
            info!("{:?} - Could not find given connection {:?} in expected_connections map",
                  self.our_address(), connection);
            None
        }
    }

    /// Check whether the connection has been accepted.
    pub fn match_unknown_connection(&mut self,
                                    connection: &::crust::Connection,
                                    hello: &::direct_messages::Hello) {
        match hello.address {
            ::types::Address::Client(ref public_key) => {
                // It is a client, add it as a relay connection. Fails if we are also a client.
                // Because we're accepting an unknown connection, we are node A in diagram RFC-0011.
                let client_address = ::types::Address::Client(public_key.clone());
                if self.add_client(public_key.clone(),
                                   connection.clone(),
                                   hello.public_id.clone()) {
                    debug!("{:?} - Added client {:?} as relay connection on {:?}",
                           self.our_address(), client_address, connection);
                    debug!("{:?} - Sending confirmation to {:?}", self.our_address(),
                           client_address);
                    // TODO(Spandan) Handle this result
                    let _result = self.send_hello(connection.clone(), Some(client_address));
                } else {
                    debug!("{:?} - Failed to add client {:?} as relay, dropping connection {:?}",
                           self.our_address(), client_address, connection);
                    self.drop_connections(vec![connection.clone()]);
                }
            }
            ::types::Address::Node(name) => {
                // It is a node, so either we are still a client or a node, and are either
                // bootstrapping or establishing a routing connection.
                let mut found = None;
                match hello.confirmed_you {
                    None => {
                        debug!("{:?} - Unconfirmed Hello from node {:?}, our state {:?}",
                               self.our_address(), name, self.state);
                        match self.state {
                            State::Terminated => {
                                return;
                            }
                            _ => {}
                        };

                        let our_address = self.our_address();
                        if let Some(optional_hello) = self.unknown_connections.get_mut(connection) {
                            match optional_hello {
                                &mut None => {
                                    debug!("{:?} - Matched Hello {:?} to unknown connection {:?}",
                                           our_address, hello, connection);
                                    *optional_hello = Some(hello.clone());
                                    if self.state != State::Disconnected {
                                        found = Some((connection.clone(), optional_hello.clone()));
                                    }
                                },
                                &mut Some(_) =>
                                    debug!("{:?} - Already received a Hello for this connection",
                                           our_address),
                            }
                        }
                    }
                    Some(::types::Address::Client(ref _public_key)) => {
                        // We are a client, so if successfully added to bootstrap, our state will
                        // update and we need to request a network name.
                        if self.add_peer(ConnectionName::Bootstrap(name.clone()),
                                         connection.clone(),
                                         hello.public_id.clone()) {
                            debug!("{:?} - Requesting network name from {:?} on {:?}",
                                   self.our_address(), name, connection);
                            // TODO(Spandan) Handle this result
                            let _result = self.request_network_name_core(&name, &connection);
                        } else {
                            error!("{:?} - Failed to add node {:?} as bootstrap connection on \
                                   {:?}; dropping", self.our_address(), name, connection);
                            self.drop_connections(vec![connection.clone()]);
                        }
                    }
                    Some(::types::Address::Node(ref _our_name)) => {
                        // We are a node, and this is the confirmation, so we are node A on diagram
                        // RFC-0011
                        let our_address = self.our_address();
                        if let Some(optional_hello) = self.unknown_connections.get(connection) {
                            if let &Some(ref stored_hello) = optional_hello {
                                if stored_hello.address == hello.address {
                                    debug!("{:?} - Confirmed Hello received from {:?}",
                                           our_address, hello.address);
                                    found = Some((connection.clone(), Some(stored_hello.clone())));
                                }
                            }
                        }
                    }
                }
                if found.is_some() {
                    self.match_connection(None, found);
                }
            }
        };
    }

    /// Match against either an expected connection to unknown connection or vice versa.
    pub fn match_connection_core(&mut self,
            expected_connection: Option<(ExpectedConnection, Option<::crust::Connection>)>,
            unknown_connection: Option<(::crust::Connection, Option<::direct_messages::Hello>)>) {
        match (expected_connection, unknown_connection) {
            (Some((expected_connection, Some(connection))), None) => {
                debug!("{:?} - At matching from expected connection against unknown connection",
                       self.our_address());
                debug!("{:?} - Expected connection {:?}, connection {:?}", self.our_address(),
                       expected_connection, connection);
                match expected_connection {
                    ExpectedConnection::Request(_, ref request) => {
                        // We are the network-side with a ConnectRequest, Node B on diagram of
                        // RFC-0011.
                        let mut opt_hello_and_unknown_connection = None;
                        let by_public_id = |element: &&(::crust::Connection,
                                                        Option<::direct_messages::Hello>)| {
                            match element.1 {
                                Some(ref hello) => request.public_id == hello.public_id,
                                None => false,
                            }
                        };
                        if let Some(unknown_connection) =
                                self.unknown_connections.retrieve_all().iter().find(by_public_id) {
                            match unknown_connection.1 {
                                Some(ref hello) => {
                                    debug!("{:?} - Matched expected request to unknown connection",
                                           self.our_address());
                                    opt_hello_and_unknown_connection =
                                        Some((hello.clone(), unknown_connection.0.clone()));
                                },
                                None => (),  // debug!("{:?} - Not yet received hello"),
                            }
                        }

                        match opt_hello_and_unknown_connection {
                            Some((hello, unknown_connection)) => {
                                // Try adding the peer to routing table.
                                if self.add_peer(ConnectionName::Routing(hello.public_id.name()),
                                                 connection,
                                                 hello.public_id.clone()) {
                                    debug!("{:?} - Added peer {:?} on matched expected connection \
                                           request", self.our_address(), hello.public_id.name());
                                    debug!("{:?} - Connected on expected connection {:?}, so \
                                           closing unknown one {:?}", self.our_address(),
                                           connection, unknown_connection);

                                    // Remove entries from expiration maps.
                                    self.remove_expected_connection(&expected_connection);
                                    self.remove_unknown_connection(&unknown_connection);
                                    // Since this is an ExpectedConnection::Request, we treat the
                                    // incoming unknown_connection as the secondary one and drop it.
                                    self.drop_connections(vec![unknown_connection]);

                                    debug!("{:?} - Sending confirmation to {:?}",
                                           self.our_address(), hello.address);
                                    // TODO(Spandan) Handle this result
                                    let _result = self.send_hello(connection, Some(hello.address));
                                }
                            }
                            None => {}
                        }
                    }
                    ExpectedConnection::Response(_, ref response) => {
                        // We initiated a ConnectRequest, Node A on diagram of RFC-0011.
                        let mut opt_hello_and_unknown_connection = None;
                        let by_public_id = |element: &&(::crust::Connection,
                                                        Option<::direct_messages::Hello>)| {
                            match element.1 {
                                Some(ref hello) => response.public_id == hello.public_id,
                                None => false,
                            }
                        };
                        if let Some(unknown_connection) =
                                self.unknown_connections.retrieve_all().iter().find(by_public_id) {
                            match unknown_connection.1 {
                                Some(ref hello) => {
                                    debug!("{:?} - Matched expected response to unknown connection",
                                           self.our_address());
                                    opt_hello_and_unknown_connection =
                                        Some((hello.clone(), unknown_connection.0.clone()));
                                },
                                None => (),  // debug!("{:?} - Not yet received hello"),
                            }
                        }

                        match opt_hello_and_unknown_connection {
                            Some((hello, unknown_connection)) => {
                                // Since this is an ExpectedConnection::Response, we treat the
                                // incoming unknown_connection as the primary one and don't drop it.
                                // Try adding the peer to routing table.
                                if self.add_peer(ConnectionName::Routing(hello.public_id.name()),
                                                 unknown_connection,
                                                 hello.public_id.clone()) {
                                    debug!("{:?} - Added peer {:?} on matched expected connection \
                                           response", self.our_address(),
                                           hello.public_id.name());
                                    // Drop secondary, i.e., unrequired connection.
                                    self.drop_connections(vec![connection.clone()]);
                                    self.remove_expected_connection(&expected_connection);
                                    self.remove_unknown_connection(&unknown_connection);
                                }
                            }
                            None => {}
                        }
                    }
                }
            }
            (None, Some((unknown_connection, Some(hello)))) => {
                debug!("{:?} - At matching from unknown_connection against expected connection",
                       self.our_address());
                let mut opt_connection = None;
                let mut opt_expected_connection = None;
                let expected_connections = self.expected_connections.retrieve_all();
                let by_public_id = |element: &&(ExpectedConnection, Option<::crust::Connection>)| {
                    match element.0 {
                        ExpectedConnection::Request(_, ref request) =>
                            hello.public_id == request.public_id,
                        ExpectedConnection::Response(_, ref response) =>
                            hello.public_id == response.public_id,
                    }
                };
                if let Some(found) = expected_connections.iter().find(by_public_id) {
                    match found.1 {
                        Some(connection) => {
                            match found.0 {
                                ExpectedConnection::Request(_, _) => {
                                    debug!("{:?} - Consolidating expected connection {:?}",
                                           self.our_address(), connection);
                                    opt_connection = Some(connection.clone());
                                },
                                ExpectedConnection::Response(_, _) => {
                                    debug!("{:?} - Consolidating unknown connection {:?}",
                                           self.our_address(), unknown_connection);
                                    opt_connection = Some(unknown_connection.clone());
                                },
                            }
                            opt_expected_connection = Some(found.0.clone());
                        }
                        None => {}
                    }
                }

                match opt_connection {
                    Some(connection) => {
                        if self.add_peer(ConnectionName::Routing(hello.public_id.name()),
                                         connection,
                                         hello.public_id.clone()) {
                            debug!("{:?} - Added peer {:?}", self.our_address(),
                                   hello.public_id.name());
                            if connection != unknown_connection {
                                debug!("{:?} - Sending confirmation to {:?}", self.our_address(),
                                       hello.address);
                                // TODO(Spandan) Handle this result
                                let _result = self.send_hello(connection,
                                                              Some(hello.address.clone()));
                                self.drop_connections(vec![unknown_connection]);
                            } else {
                                self.drop_connections(vec![connection]);
                            }
                        } else {
                            debug!("{:?} - Failed to add peer {:?} dropping connections {:?} and \
                                   {:?}", self.our_address(), hello.public_id.name(), connection,
                                   unknown_connection);
                            self.drop_connections(vec![unknown_connection, connection]);
                        }

                        match opt_expected_connection {
                            Some(ref expected_connection) => {
                                self.remove_expected_connection(expected_connection);
                            }
                            None => {}
                        }
                        self.remove_unknown_connection(&unknown_connection);
                    }
                    None => {}
                }
            }
            _ => {}
        }
    }

    /// Add an expected connection.
    pub fn add_expected_connection(&mut self, expected_connection: ExpectedConnection) {
        match self.expected_connections.insert(expected_connection, None) {
            // The expected connection has been validated, filtered, checked for duplication and
            // contains a unique connection token. As such the insertion should always return None
            // and can be disregarded.
            Some(_) => debug_assert!(false, "Added a duplicate expected connection"),
            None => {}
        }
    }

    /// Add an unknown connection.
    pub fn add_unknown_connection(&mut self, unknown_connection: ::crust::Connection) {
        match self.unknown_connections.insert(unknown_connection, None) {
            // Inserting an unknown connection should not return a value.
            Some(_) => {
                debug_assert!(false, "Unexpected value returned")
            }
            None => {}
        }
    }

    /// Remove an expected connection.
    pub fn remove_expected_connection(&mut self, expected_connection: &ExpectedConnection) {
        let _ = self.expected_connections.remove(expected_connection);
    }

    /// Remove an unknown connection.
    pub fn remove_unknown_connection(&mut self, unknown_connection: &::crust::Connection) {
        let _ = self.unknown_connections.remove(unknown_connection);
    }

    fn request_network_name_core(&mut self,
                                 bootstrap_name: &NameType,
                                 bootstrap_connection: &::crust::Connection) -> RoutingResult {
        // If RoutingNode is restricted from becoming a node, it suffices to never request a network
        // name.
        match self.state {
            State::Relocated      |
            State::Connected      |
            State::Terminated     |
            State::Disconnected   |
            State::GroupConnected => {
                error!("{:?} - Requesting network name while disconnected or named or terminated",
                       self.our_address());
                Err(::error::RoutingError::InvalidStateForOperation)
            }
            State::Bootstrapped => {
                debug!("{:?} - Will request a network name from bootstrap node {:?} on {:?}",
                       self.our_address(), bootstrap_name, bootstrap_connection);

                let to_authority = ::authority::Authority::NaeManager(self.id.name());

                let public_id = ::public_id::PublicId::new(&self.id);
                let internal_request = ::messages::InternalRequest::RequestNetworkName(public_id);
                let content = ::messages::Content::InternalRequest(internal_request);

                self.request_network_name(to_authority, content)
            },
        }
    }

    /// Check if were involved in the relocation of a Client.
    pub fn check_relocations(&self, to_authority: &Authority) -> Vec<crust::Connection> {
        // It's possible we participated in the relocation of a client present in our relay map.
        let mut target_connections: Vec<crust::Connection> = Vec::new();
        match self.relay_map {
            Some(ref relay_map) => {
                let mut managed_node_name = None;
                match *to_authority {
                    Authority::ManagedNode(ref name) => {
                        managed_node_name = Some(name);
                    }
                    _ => {}
                };

                match managed_node_name {
                    Some(name) => {
                        for identity in relay_map.identities().iter() {
                            match self.our_close_group() {
                                Some(close_group) => {
                                    let identity_name = ::NameType::new(
                                        ::sodiumoxide::crypto::hash::sha512::hash(
                                            &identity.public_key.0[..]).0);
                                    match ::utils::calculate_relocated_name(close_group,
                                                                            &identity_name) {
                                        Ok(relocated_name) => {
                                            if relocated_name == *name {
                                                let (_, connections) =
                                                    relay_map.lookup_identity(identity);
                                                for connection in connections {
                                                    target_connections.push(connection);
                                                }
                                            }
                                        }
                                        Err(_) => {}
                                    }
                                }
                                None => {}
                            }
                        }
                    }
                    None => {}
                }
            }
            None => {}
        }
        debug!("{:?} - Found relocated client name on connections {:?}", self.our_address(),
               target_connections);
        target_connections
    }
}
// END ====================================================================================================

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
        RoutingNode::new(action_sender.clone(),
                         action_receiver,
                         event_sender,
                         false,
                         None)
    }

    // RoutingMessage's for ImmutableData Get request/response.
    fn generate_routing_messages() -> (RoutingMessage, RoutingMessage) {
        let mut data = [0u8; 64];
        thread_rng().fill_bytes(&mut data);

        let immutable = ImmutableData::new(ImmutableDataType::Normal,
                                           data.iter().map(|&x| x).collect::<Vec<_>>());
        let immutable_data = Data::ImmutableData(immutable.clone());
        let key_pair = crypto::sign::gen_keypair();
        let signature = crypto::sign::sign_detached(&data, &key_pair.1);
        let sign_token = SignedToken {
            serialised_request: data.iter().map(|&x| x).collect::<Vec<_>>(),
            signature: signature,
        };

        let data_request = DataRequest::ImmutableData(immutable.name().clone(),
                                                      immutable.get_type_tag().clone());
        let request = ExternalRequest::Get(data_request.clone(), 0u8);
        let response = ExternalResponse::Get(immutable_data, data_request, Some(sign_token));

        let routing_message_request = RoutingMessage {
            from_authority: Authority::ClientManager(NameType::new([1u8; 64])),
            to_authority: Authority::NaeManager(NameType::new(data)),
            content: Content::ExternalRequest(request),
        };

        let routing_message_response = RoutingMessage {
            from_authority: Authority::NaeManager(NameType::new(data)),
            to_authority: Authority::ClientManager(NameType::new([1u8; 64])),
            content: Content::ExternalResponse(response),
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
