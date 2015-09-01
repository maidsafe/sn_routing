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
use std::thread;
use std::collections::BTreeMap;
use sodiumoxide::crypto::sign::{verify_detached, Signature};
use sodiumoxide::crypto::sign;
use sodiumoxide::crypto;
use time::{Duration, SteadyTime};
use std::cmp::min;

use crust;
use crust::{ConnectionManager, Endpoint, Port};
use lru_time_cache::LruCache;

use action::Action;
use event::Event;
use immutable_data::{ImmutableData, ImmutableDataType};
use NameType;
use name_type::closer_to_target_or_equal;
use plain_data::PlainData;
use routing_core::{RoutingCore, ConnectionName};
use structured_data::StructuredData;
use id::Id;
use public_id::PublicId;
use types;
use types::{MessageId, Bytes, Address, CacheOptions};
use utils::{encode, decode};
use utils;
use data::{Data, DataRequest};
use authority::{Authority, our_authority};
use wake_up::WakeUpCaller;

use messages::{RoutingMessage, SignedMessage, SignedToken, ConnectRequest, ConnectResponse,
               Content, ExternalRequest, ExternalResponse, InternalRequest, InternalResponse};

use error::{RoutingError, ResponseError, InterfaceError};
use refresh_accumulator::RefreshAccumulator;
use message_filter::MessageFilter;
use message_accumulator::MessageAccumulator;


type RoutingResult = Result<(), RoutingError>;

static MAX_BOOTSTRAP_CONNECTIONS : usize = 1;
/// Routing Node
pub struct RoutingNode {
    // for CRUST
    crust_receiver: mpsc::Receiver<crust::Event>,
    connection_manager: crust::ConnectionManager,
    accepting_on: Vec<crust::Endpoint>,
    // for RoutingNode
    client_restriction: bool,
    action_sender: mpsc::Sender<Action>,
    action_receiver: mpsc::Receiver<Action>,
    event_sender: mpsc::Sender<Event>,
    wakeup: WakeUpCaller,
    filter: ::filter::Filter,
    connection_filter: ::message_filter::MessageFilter<::NameType>,
    core: RoutingCore,
    public_id_cache: LruCache<NameType, PublicId>,
    accumulator: MessageAccumulator,
    refresh_accumulator: RefreshAccumulator,
    cache_options: CacheOptions,
    data_cache: Option<LruCache<NameType, Data>>,
}

impl RoutingNode {
    pub fn new(action_sender: mpsc::Sender<Action>,
               action_receiver: mpsc::Receiver<Action>,
               event_sender: mpsc::Sender<Event>,
               client_restriction: bool,
               keys: Option<Id>)
               -> RoutingNode {

        let (crust_sender, crust_receiver) = mpsc::channel::<crust::Event>();
        let mut cm = crust::ConnectionManager::new(crust_sender);
        let _ = cm.start_accepting(vec![Port::Tcp(5483u16)]);
        let accepting_on = cm.get_own_endpoints();

        let core = RoutingCore::new(event_sender.clone(), action_sender.clone(), keys);
        info!("RoutingNode {:?} listens on {:?}", core.our_address(), accepting_on);

        RoutingNode {
            crust_receiver: crust_receiver,
            connection_manager: cm,
            accepting_on: accepting_on,
            client_restriction: client_restriction,
            action_sender: action_sender.clone(),
            action_receiver: action_receiver,
            event_sender: event_sender,
            wakeup: WakeUpCaller::new(action_sender),
            filter: ::filter::Filter::with_expiry_duration(Duration::minutes(20)),
            connection_filter: ::message_filter::MessageFilter::with_expiry_duration(
                ::time::Duration::minutes(20)),
            core: core,
            public_id_cache: LruCache::with_expiry_duration(Duration::minutes(10)),
            accumulator: MessageAccumulator::new(),
            refresh_accumulator: RefreshAccumulator::new(),
            cache_options: CacheOptions::no_caching(),
            data_cache: None,
        }
    }

    pub fn run(&mut self) {
        self.wakeup.start(10);
        self.connection_manager.bootstrap(MAX_BOOTSTRAP_CONNECTIONS);
        debug!("RoutingNode started running and started bootstrap");
        loop {
            match self.action_receiver.try_recv() {
                Err(_) => {}
                Ok(Action::SendMessage(signed_message)) => {
                    ignore(self.message_received(signed_message));
                }
                Ok(Action::SendContent(our_authority, to_authority, content)) => {
                    let _ = self.send_content(our_authority, to_authority, content);
                },
                Ok(Action::ClientSendContent(to_authority, content)) => {
                    let _ = self.client_send_content(to_authority, content);
                },
                Ok(Action::Churn(our_close_group, targets)) => {
                    let _ = self.generate_churn(our_close_group, targets);
                },
                Ok(Action::SetCacheOptions(cache_options)) => {
                    self.set_cache_options(cache_options);
                },
                Ok(Action::WakeUp) => {
                    // ensure that the loop is blocked for maximally 10ms
                },
                Ok(Action::Terminate) => {
                    debug!("routing node terminated");
                    let _ = self.event_sender.send(Event::Terminated);
                    self.connection_manager.stop();
                    break;
                }
            };
            match self.crust_receiver.try_recv() {
                Err(_) => {
                    // FIXME (ben 16/08/2015) other reasons could induce an error
                    // main error assumed now to be no new crust events
                    // break;
                }
                Ok(crust::Event::NewMessage(endpoint, bytes)) => {
                    match decode::<SignedMessage>(&bytes) {
                        Ok(message) => {
                            // handle SignedMessage for any identified endpoint
                            match self.core.lookup_endpoint(&endpoint) {
                                Some(ConnectionName::Unidentified(_, _)) => debug!("message
                                        from unidentified connection"),
                                    None => debug!("message from unknown endpoint"),
                                    _ => ignore(self.message_received(message)),
                            };
                        }
                        // The message received is not a Signed Routing Message,
                        // expect it to be an Hello message to identify a connection
                        Err(_) => {
                            match decode::<::direct_messages::DirectMessage>(&bytes) {
                                Ok(direct_message) => self.direct_message_received(
                                        direct_message, endpoint),
                                    _ => error!("Unparsable message received on {:?}", endpoint),
                            };
                        }
                    };
                }
                Ok(crust::Event::NewConnection(endpoint)) => {
                    self.handle_new_connection(endpoint);
                }
                Ok(crust::Event::LostConnection(endpoint)) => {
                    self.handle_lost_connection(endpoint);
                }
                Ok(crust::Event::NewBootstrapConnection(endpoint)) => {
                    self.handle_new_bootstrap_connection(endpoint);
                }
            };
            thread::sleep_ms(1);
        }
    }

    /// When CRUST receives a connect to our listening port and establishes a new connection,
    /// the endpoint is given here as new connection
    fn handle_new_connection(&mut self, endpoint: Endpoint) {
        debug!("New connection on {:?}", endpoint);
        // only accept new connections if we are a full node
        // FIXME(dirvine) I am not sure we should not accept connections here :16/08/2015
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
        ignore(self.send_hello(endpoint, None));
    }

    /// When CRUST reports a lost connection, ensure we remove the endpoint anywhere
    fn handle_lost_connection(&mut self, endpoint: Endpoint) {
        debug!("Lost connection on {:?}", endpoint);
        let connection_name = self.core.lookup_endpoint(&endpoint);
        if connection_name.is_some() {
            self.core.drop_peer(&connection_name.unwrap());
        }
    }

    fn handle_new_bootstrap_connection(&mut self, endpoint: Endpoint) {
        debug!("New bootstrap connection on {:?}", endpoint);
        if !self.core.is_node() {
            if !self.core.add_peer(ConnectionName::Unidentified(endpoint.clone(), true),
                endpoint.clone(), None) {
                // only fails if relay_map is full for unidentified connections
                error!("New bootstrap connection on {:?} failed to be labeled as unidentified",
                    endpoint);
                self.connection_manager.drop_node(endpoint.clone());
                return;
            }
        } else {
            // if core is a full node, don't accept new bootstrap connections
            error!("New bootstrap connection on {:?} but we are a node",
                endpoint);
            self.connection_manager.drop_node(endpoint);
            return;
        }
        ignore(self.send_hello(endpoint, None));
    }

    // ---- Hello connection identification -------------------------------------------------------

    fn send_hello(&mut self,
                  endpoint: Endpoint,
                  confirmed_address: Option<Address>)
                  -> RoutingResult {
        debug!("Saying hello I am {:?} on {:?}, confirming {:?}", self.core.our_address(),
            endpoint, confirmed_address);
        let direct_message = match ::direct_messages::DirectMessage::new(
            ::direct_messages::Content::Hello( ::direct_messages::Hello {
                address: self.core.our_address(),
                public_id: PublicId::new(self.core.id()),
                confirmed_you: confirmed_address,
                }), self.core.id().signing_private_key()) {
                    Ok(x) => x,
                    Err(e) => return Err(RoutingError::Cbor(e)),
                };
        let bytes = try!(::utils::encode(&direct_message));
        ignore(self.connection_manager.send(endpoint, bytes));
        Ok(())
    }

    fn handle_hello(&mut self, endpoint: Endpoint, hello: &::direct_messages::Hello)
        -> RoutingResult {

        debug!("Hello, it is {:?} on {:?}", hello.address, endpoint);
        let old_identity = match self.core.lookup_endpoint(&endpoint) {
            // if already connected through the routing table, just confirm or destroy
            Some(ConnectionName::Routing(known_name)) => {
                debug!("Endpoint {:?} registered to routing node {:?}", endpoint,
                    known_name);
                match hello.address {
                    // FIXME (ben 11/08/2015) Hello messages need to be signed and
                    // we also need to check the match with the PublicId stored in RT
                    Address::Node(known_name) => return Ok(()),
                    _ => {
                        // the endpoint does not match with the routing information
                        // we know about it; drop it
                        let _ = self.core.drop_peer(&ConnectionName::Routing(known_name));
                        self.connection_manager.drop_node(endpoint.clone());
                        return Err(RoutingError::RejectedPublicId);
                    }
                }
            }
            // a connection should have been labeled as Unidentified
            None => None,
            Some(relay_connection_name) => Some(relay_connection_name),
        };
        // FIXME (ben 14/08/2015) temporary copy until Debug is
        // implemented for ConnectionName
        let hello_address = hello.address.clone();
        // if set to true we will take the initiative to drop the connection,
        // if refused from core;
        // if alpha is false we will leave the connection unidentified,
        // only adding the new identity when it is confirmed by the other side
        // (hello.confirmed_you set to our address), which has to send a confirmed hello
        let mut alpha = false;
        // construct the new identity from Hello
        let new_identity = match (hello.address.clone(), self.core.our_address()) {
            (Address::Node(his_name), Address::Node(our_name)) => {
            // He is a node, and we are a node, establish a routing table connection
            // FIXME (ben 11/08/2015) we need to check his PublicId against the network
            // but this requires an additional RFC so currently leave out such check
            // refer to https://github.com/maidsafe/routing/issues/387
                alpha = &self.core.id().name() < &his_name;
                ConnectionName::Routing(his_name)
            }
            (Address::Client(his_public_key), Address::Node(our_name)) => {
            // He is a client, we are a node, establish a relay connection
                debug!("Connection {:?} will be labeled as a relay to {:?}",
                    endpoint, Address::Client(his_public_key));
                alpha = true;
                ConnectionName::Relay(Address::Client(his_public_key))
            }
            (Address::Node(his_name), Address::Client(our_public_key)) => {
            // He is a node, we are a client, establish a bootstrap connection
                debug!("Connection {:?} will be labeled as a bootstrap node name {:?}",
                    endpoint, his_name);
                ConnectionName::Bootstrap(his_name)
            }
            (Address::Client(his_public_key), Address::Client(our_public_key)) => {
            // He is a client, we are a client, no-go
                match old_identity {
                    Some(old_connection_name) => {
                        let _ = self.core.drop_peer(&old_connection_name);
                    }
                    None => {}
                };
                self.connection_manager.drop_node(endpoint.clone());
                return Err(RoutingError::BadAuthority);
            }
        };
        let confirmed = match hello.confirmed_you {
            Some(ref address) => {
                if self.core.is_us(&address) {
                    debug!("This hello message successfully confirmed our address, {:?}",
                        address);
                    true
                } else {
                    self.connection_manager.drop_node(endpoint.clone());
                    error!("Wrongfully confirmed as {:?} on {:?} and dropped the connection",
                        address, endpoint);
                    return Err(RoutingError::RejectedPublicId);
                }
            }
            None => false,
        };
        if alpha || confirmed {
            // we know it's not a routing connection, remove it from the relay map
            let dropped_peer = match &old_identity {
                &Some(ConnectionName::Routing(_)) => unreachable!(),
                // drop any relay connection in favour of new to-be-determined identity
                &Some(ref old_connection_name) => {
                    self.core.drop_peer(old_connection_name)
                }
                &None => None,
            };
            // add the new identity, or drop the connection
            if self.core.add_peer(new_identity.clone(), endpoint.clone(),
                Some(hello.public_id.clone())) {
                debug!("Added {:?} to the core on {:?}", hello_address, endpoint);
                if alpha {
                    ignore(self.send_hello(endpoint.clone(), Some(hello_address)));
                };
                match new_identity {
                    ConnectionName::Bootstrap(bootstrap_name) => {
                        ignore(self.request_network_name(&bootstrap_name, &endpoint));
                    }
                    _ => {}
                };
            } else {
                // depending on the identity of the connection, follow the rules on dropping
                // to avoid both sides drop the other connection, possibly leaving none
                self.connection_manager.drop_node(endpoint.clone());
                debug!("Core refused {:?} on {:?} and dropped the connection",
                    hello_address, endpoint);
            };
        } else {
            debug!("We are not alpha and the hello was not confirmed yet, awaiting alpha.");
        }
        Ok(())
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
            Some((message, opt_token)) => {
                self.filter.block(&message);
                (message, opt_token) },
            None => return Ok(()),
        };

        match message.content {
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
                    InternalRequest::Refresh(type_tag, bytes) => {
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
                                refresh_authority),
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
                    InternalRequest::Refresh(_, _) => true,
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

        let claimant : NameType = match *signed_message.claimant() {
            Address::Node(ref claimant) => claimant.clone(),
            Address::Client(_) => {
                error!("Claimant is a Client, but passed into accumulator for a group. dropped.");
                debug_assert!(false);
                return None;
            }
        };

        debug!("Adding message from {:?} to accumulator", claimant);
        self.accumulator.add_message(threshold as usize, claimant, message)
                        .map(|msg| (msg, None))
    }

    // ---- Direct Messages -----------------------------------------------------------------------

    fn direct_message_received(&mut self, direct_message: ::direct_messages::DirectMessage,
        endpoint: ::crust::Endpoint) {

        match direct_message.content() {
            &::direct_messages::Content::Hello(ref hello) => {
                // verify signature of hello
                if !direct_message.verify_signature(&hello.public_id.signing_public_key()) {
                    error!("DirectMessage::Hello failed signature verification on {:?}",
                        endpoint);
                    self.connection_manager.drop_node(endpoint); };
                let _ = self.handle_hello(endpoint, hello);
            },
            &::direct_messages::Content::Churn(ref his_close_group) => {
                // TODO (ben 26/08/2015) verify the signature with the public_id
                // from our routing table.
                self.handle_churn(his_close_group);
            },
        };
    }

    // ---- Churn ---------------------------------------------------------------------------------

    fn generate_churn(&self, churn: ::direct_messages::Churn, target: Vec<::crust::Endpoint>)
        -> RoutingResult {
        debug!("CHURN: sending {:?} names to {:?} close nodes",
            churn.close_group.len(), target.len());
        // send Churn to all our close group nodes
        let direct_message = match ::direct_messages::DirectMessage::new(
            ::direct_messages::Content::Churn(churn.clone()),
            self.core.id().signing_private_key()) {
                Ok(x) => x,
                Err(e) => return Err(RoutingError::Cbor(e)),
            };
        let bytes = try!(::utils::encode(&direct_message));
        for endpoint in target {
            ignore(self.connection_manager.send(endpoint, bytes.clone()));
        }
        // notify the user
        let _ = self.event_sender.send(::event::Event::Churn(churn.close_group));
        Ok(())
    }

    fn handle_churn(&mut self, churn: &::direct_messages::Churn) {
        debug!("CHURN: received {:?} names", churn.close_group.len());
        for his_close_node in churn.close_group.iter() {
            self.refresh_routing_table(his_close_node);
        }
    }

    // ---- Request Network Name ------------------------------------------------------------------

    fn request_network_name(&mut self,
                            bootstrap_name: &NameType,
                            bootstrap_endpoint: &Endpoint)
                            -> RoutingResult {
        // if RoutingNode is restricted from becoming a node,
        // it suffices to never request a network name.
        if self.client_restriction {
            return Ok(())
        }
        if self.core.is_node() {
            return Err(RoutingError::AlreadyConnected);
        };
        debug!("Will request a network name from bootstrap node {:?} on {:?}", bootstrap_name,
            bootstrap_endpoint);
        let core_id = self.core.id();
        let routing_message = RoutingMessage {
            from_authority: Authority::Client(bootstrap_name.clone(),
                                              core_id.signing_public_key()),
            to_authority: Authority::NaeManager(core_id.name()),
            content: Content::InternalRequest(InternalRequest::RequestNetworkName(
                PublicId::new(core_id))),
        };
        match SignedMessage::new(Address::Client(core_id.signing_public_key()),
                                 routing_message,
                                 core_id.signing_private_key()) {
            Ok(signed_message) => ignore(self.send(signed_message)),
            Err(e) => return Err(RoutingError::Cbor(e)),
        };
        Ok(())
    }

    fn handle_request_network_name(&self,
                                   request: InternalRequest,
                                   from_authority: Authority,
                                   to_authority: Authority,
                                   response_token: SignedToken)
                                   -> RoutingResult {
        match request {
            InternalRequest::RequestNetworkName(public_id) => {
                match (&from_authority, &to_authority) {
                    (&Authority::Client(_, ref public_key), &Authority::NaeManager(name)) => {
                        let mut network_public_id = public_id.clone();
                        match self.core.our_close_group() {
                            Some(close_group) => {
                                let relocated_name = try!(utils::calculate_relocated_name(
                                    close_group, &public_id.name()));
                                debug!("Got a request for a network name from {:?}, assigning {:?}",
                                    from_authority, relocated_name);
                                network_public_id.assign_relocated_name(relocated_name.clone());
                                let routing_message = RoutingMessage {
                                    from_authority : to_authority,
                                    to_authority   : Authority::NaeManager(relocated_name.clone()),
                                    content        : Content::InternalRequest(
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
                    (Authority::NaeManager(from_name), &Authority::NaeManager(name)) => {
                        let request_network_name = try!(SignedMessage::new_from_token(
                            response_token.clone()));
                        let _ = self.public_id_cache.insert(network_public_id.name(),
                            network_public_id.clone());
                        match self.core.our_close_group_with_public_ids() {
                            Some(close_group) => {
                                debug!("Network request to accept name {:?},
                                    responding with our close group to {:?}", network_public_id.name(),
                                    request_network_name.get_routing_message().source());
                                let routing_message = RoutingMessage {
                                    from_authority : to_authority,
                                    to_authority: request_network_name.get_routing_message().source(),
                                    content        : Content::InternalResponse(
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

    fn handle_cache_network_name_response(&mut self,
                                          response: InternalResponse,
                                          from_authority: Authority,
                                          to_authority: Authority)
                                          -> RoutingResult {
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
                    Content::InternalRequest(InternalRequest::RequestNetworkName(ref original_public_id)) => {
                        let mut our_public_id = PublicId::new(self.core.id());
                        if &our_public_id != original_public_id { return Err(RoutingError::BadAuthority); };
                        our_public_id.set_name(network_public_id.name());
                        if our_public_id != network_public_id { return Err(RoutingError::BadAuthority); };
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
        // FIXME (ben) We're sending all accepting connections as local since we don't differentiate
        // between local and external yet.
        // FIXME (ben 13/08/2015) We are forced to make this split as the routing message
        // needs to contain a relay name if we are not yet connected to routing nodes
        // under our own name.
        if !self.core.is_connected_node() {
            match self.get_a_bootstrap_name() {
                Some(bootstrap_name) => {
                    // TODO (ben 13/08/2015) for now just take the first bootstrap peer as our relay
                    let routing_message = RoutingMessage {
                        from_authority: Authority::Client(bootstrap_name,
                                                          self.core.id().signing_public_key()),
                        to_authority: Authority::ManagedNode(peer_name.clone()),
                        content: Content::InternalRequest(InternalRequest::Connect(ConnectRequest {
                                local_endpoints    : self.accepting_on.clone(),
                                external_endpoints : vec![],
                                requester_fob      : PublicId::new(self.core.id()),
                            }
                        )),
                    };
                    match SignedMessage::new(Address::Client(self.core.id().signing_public_key()),
                                             routing_message,
                                             self.core.id().signing_private_key()) {
                        Ok(signed_message) => ignore(self.send(signed_message)),
                        Err(e) => return Err(RoutingError::Cbor(e)),
                    };
                    Ok(())
                }
                None => return Err(RoutingError::NotBootstrapped),
            }
        } else {  // we are a connected node
            let routing_message = RoutingMessage {
                from_authority: Authority::ManagedNode(self.core.id().name()),
                to_authority: Authority::ManagedNode(peer_name.clone()),
                content: Content::InternalRequest(InternalRequest::Connect(ConnectRequest {
                        local_endpoints    : self.accepting_on.clone(),
                        external_endpoints : vec![],
                        requester_fob      : PublicId::new(self.core.id()),
                    }
                )),
            };
            match SignedMessage::new(Address::Node(self.core.id().name()),
                                     routing_message,
                                     self.core.id().signing_private_key()) {
                Ok(signed_message) => ignore(self.send(signed_message)),
                Err(e) => return Err(RoutingError::Cbor(e)),
            };
            Ok(())
        }
    }

    fn handle_connect_request(&mut self,
                              request: InternalRequest,
                              from_authority: Authority,
                              to_authority: Authority,
                              response_token: SignedToken)
                              -> RoutingResult {
        debug!("handle ConnectRequest");
        match request {
            InternalRequest::Connect(connect_request) => {
                if !connect_request.requester_fob.is_relocated() {
                    return Err(RoutingError::RejectedPublicId);
                };
                // first verify that the message is correctly self-signed
                if !response_token.verify_signature(&connect_request.requester_fob
                    .signing_public_key()) {
                    return Err(RoutingError::FailedSignature);
                };
                if !self.core.check_node(&ConnectionName::Routing(
                    connect_request.requester_fob.name())) {
                    return Err(RoutingError::RefusedFromRoutingTable);
                };
                // TODO (ben 13/08/2015) use public_id_cache or result of future RFC
                // to validate the public_id from the network
                self.connection_manager.connect(connect_request.local_endpoints.clone());
                self.connection_manager.connect(connect_request.external_endpoints.clone());
                self.connection_filter.add(connect_request.requester_fob.name());
                let routing_message = RoutingMessage {
                    from_authority: Authority::ManagedNode(self.core.id().name()),
                    to_authority: from_authority,
                    content: Content::InternalResponse(InternalResponse::Connect(ConnectResponse {
                            local_endpoints    : self.accepting_on.clone(),
                            external_endpoints : vec![],
                            receiver_fob       : PublicId::new(self.core.id()),
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
                               to_authority: Authority)
                               -> RoutingResult {
        debug!("handle ConnectResponse");
        match response {
            InternalResponse::Connect(connect_response, signed_token) => {
                if !signed_token.verify_signature(&self.core.id().signing_public_key()) {
                    error!("ConnectResponse from {:?} failed our signature for the signed token.",
                        from_authority);
                    return Err(RoutingError::FailedSignature);
                };
                let connect_request = try!(SignedMessage::new_from_token(signed_token));
                match connect_request.get_routing_message().from_authority.get_address() {
                    Some(address) => if !self.core.is_us(&address) {
                        error!("Connect response contains request that was not from us.");
                        return Err(RoutingError::BadAuthority);
                    },
                    None => return Err(RoutingError::BadAuthority),
                }
                // are we already connected (returns false), or still interested ?s
                if !self.core.check_node(&ConnectionName::Routing(
                    connect_response.receiver_fob.name())) {
                    return Err(RoutingError::RefusedFromRoutingTable);
                };
                debug!("Connecting on validated ConnectResponse to {:?}", from_authority);
                self.connection_manager.connect(connect_response.local_endpoints.clone());
                self.connection_manager.connect(connect_response.external_endpoints.clone());
                self.connection_filter.add(connect_response.receiver_fob.name());
                Ok(())
            }
            _ => return Err(RoutingError::BadAuthority),
        }
    }

    // ----- Send Functions -----------------------------------------------------------------------

    fn send_to_user(&self, event: Event) {
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
        if self.core.is_connected_node() ||
            self.core.has_bootstrap_endpoints() {
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
        let endpoints = self.core.target_endpoints(&destination);
        if !endpoints.is_empty() {
            debug!("Sending {:?} to {:?} target connection(s)",
                signed_message.get_routing_message().content, endpoints.len());
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
                    if self.connection_manager.send(bootstrap_peer.endpoint().clone(),
                        bytes.clone()).is_ok() {
                        debug!("Sent {:?} to bootstrap connection {:?}",
                            signed_message.get_routing_message().content,
                            bootstrap_peer.identity());
                        break;
                    };
                }
            }
            None => {}
        }

        // If we need handle this message, move this copy into the channel for later processing.
        if self.core.name_in_range(&destination.get_location()) {
            if let Authority::Client(relay, public_key) = destination {
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
                                 our_authority: Authority) -> RoutingResult {
        debug_assert!(our_authority.is_group());
        let threshold = self.group_threshold();
        let group_name = our_authority.get_location().clone();
        match self.refresh_accumulator.add_message(threshold,
            type_tag.clone(), sender, group_name.clone(), payload){
            Some(vec_of_bytes) => {
                let _ = self.event_sender.send(Event::Refresh(type_tag, group_name, vec_of_bytes));
            },
            None => {},
        };
        Ok(())
    }

    // ------ FIXME -------------------------------------------------------------------------------

    fn group_threshold(&self) -> usize {
        min(types::QUORUM_SIZE, (self.core.routing_table_size() as f32 * 0.8) as usize)
    }

    fn get_a_bootstrap_name(&self) -> Option<NameType> {
        match self.core.bootstrap_endpoints() {
            Some(bootstrap_peers) => {
                // TODO (ben 13/08/2015) for now just take the first bootstrap peer as our relay
                match bootstrap_peers.first() {
                    Some(bootstrap_peer) => {
                        match *bootstrap_peer.identity() {
                            ConnectionName::Bootstrap(bootstrap_name) => Some(bootstrap_name),
                            _ => None,
                        }
                    }
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
                    Some(LruCache::<NameType, Data>::with_expiry_duration(Duration::minutes(10))),
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
                                    Data::PlainData(ref plain_data) => {
                                        if self.cache_options.plain_data_caching_enabled() {
                                            debug!("Caching PlainData {:?}", data.name());
                                            data_cache.insert(data.name(), data.clone());
                                        }
                                    }
                                    Data::StructuredData(ref structured_data) => {
                                        if self.cache_options.structured_data_caching_enabled() {
                                            debug!("Caching StructuredData {:?}", data.name());
                                            data_cache.insert(data.name(), data.clone());
                                        }
                                    }
                                    Data::ImmutableData(ref immutable_data) => {
                                        if self.cache_options.immutable_data_caching_enabled() {
                                            debug!("Caching ImmutableData {:?}", data.name());
                                            // TODO verify data
                                            data_cache.insert(data.name(), data.clone());
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
                                    DataRequest::StructuredData(data_name, tag) => {
                                        if self.cache_options.structured_data_caching_enabled() {
                                            let name = StructuredData::compute_name(tag, &data_name);
                                            match data_cache.get(&name) {
                                                Some(data) => {
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
    use crust;
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

    fn create_node() -> RoutingNode {
        let (action_sender, action_receiver) = mpsc::channel::<Action>();
        let (event_sender, _) = mpsc::channel::<Event>();
        RoutingNode::new(action_sender.clone(), action_receiver, event_sender, false, None)
    }

    #[test]
    fn no_caching() {
        let mut node = create_node();
        let mut data = [0u8; 64];
        thread_rng().fill_bytes(&mut data);
        let immutable = ImmutableData::new(ImmutableDataType::Normal,
                                           data.iter().map(|&x|x).collect::<Vec<_>>());
        let immutable_data = Data::ImmutableData(immutable.clone());
        let key_pair = crypto::sign::gen_keypair();
        let sig = crypto::sign::sign_detached(&data, &key_pair.1);
        let sign_token = SignedToken {
            serialised_request: data.iter().map(|&x|x).collect::<Vec<_>>(),
            signature: sig,
        };

        let data_request = DataRequest::ImmutableData(immutable.name().clone(),
                                                      immutable.get_type_tag().clone());

        let response = ExternalResponse::Get(immutable_data, data_request.clone(), Some(sign_token));
        let request = ExternalRequest::Get(data_request, 0u8);

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

        assert!(node.handle_cache_get(&routing_message_request).is_none());
        node.handle_cache_put(&routing_message_response);
        assert!(node.handle_cache_get(&routing_message_request).is_none());
    }

    #[test]
    fn cache_for_type() {
        let mut node = create_node();
        let cache_options = CacheOptions::with_caching(false, false, true);
        let _ = node.set_cache_options(cache_options);
        let mut data = [0u8; 64];
        thread_rng().fill_bytes(&mut data);
        let immutable = ImmutableData::new(ImmutableDataType::Normal,
                                           data.iter().map(|&x|x).collect::<Vec<_>>());
        let immutable_data = Data::ImmutableData(immutable.clone());
        let key_pair = crypto::sign::gen_keypair();
        let sig = crypto::sign::sign_detached(&data, &key_pair.1);
        let sign_token = SignedToken {
            serialised_request: data.iter().map(|&x|x).collect::<Vec<_>>(),
            signature: sig,
        };

        let data_request = DataRequest::ImmutableData(immutable.name().clone(),
                                                      immutable.get_type_tag().clone());

        let response = ExternalResponse::Get(immutable_data, data_request.clone(), Some(sign_token));
        let request = ExternalRequest::Get(data_request, 0u8);

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

        assert!(node.handle_cache_get(&routing_message_request).is_none());
        node.handle_cache_put(&routing_message_response);
        assert!(node.handle_cache_get(&routing_message_request).is_some());
    }

    #[test]
    fn no_cache_for_type() {
        let mut node = create_node();
        let cache_options = CacheOptions::with_caching(true, true, false);
        let _ = node.set_cache_options(cache_options);
        let mut data = [0u8; 64];
        thread_rng().fill_bytes(&mut data);
        let immutable = ImmutableData::new(ImmutableDataType::Normal,
                                           data.iter().map(|&x|x).collect::<Vec<_>>());
        let immutable_data = Data::ImmutableData(immutable.clone());
        let key_pair = crypto::sign::gen_keypair();
        let sig = crypto::sign::sign_detached(&data, &key_pair.1);
        let sign_token = SignedToken {
            serialised_request: data.iter().map(|&x|x).collect::<Vec<_>>(),
            signature: sig,
        };

        let data_request = DataRequest::ImmutableData(immutable.name().clone(),
                                                      immutable.get_type_tag().clone());

        let response = ExternalResponse::Get(immutable_data, data_request.clone(), Some(sign_token));
        let request = ExternalRequest::Get(data_request, 0u8);

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

        assert!(node.handle_cache_get(&routing_message_request).is_none());
        node.handle_cache_put(&routing_message_response);
        assert!(node.handle_cache_get(&routing_message_request).is_none());
    }
}
