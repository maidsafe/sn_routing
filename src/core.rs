// Copyright 2015 MaidSafe.net limited.
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

use accumulator::Accumulator;
use crust;
use itertools::Itertools;
use kademlia_routing_table::{AddedNodeDetails, DroppedNodeDetails, GROUP_SIZE, HopType, NodeInfo,
                             RoutingTable};
use lru_time_cache::LruCache;
use maidsafe_utilities::event_sender::MaidSafeEventCategory;
use maidsafe_utilities::serialisation;
use maidsafe_utilities::thread::RaiiThreadJoiner;
use message_filter::MessageFilter;
use sodiumoxide::crypto::{box_, hash, sign};
use std::io;
use std::collections::HashMap;
use std::fmt;
use std::fmt::{Debug, Formatter};
use std::sync::mpsc;
use std::thread;
use time::Duration;
use xor_name;
use xor_name::XorName;

use acceptors::Acceptors;
use action::Action;
use authority::Authority;
use data::{Data, DataRequest};
use error::{RoutingError, InterfaceError};
use event::Event;
use id::{FullId, PublicId};
use types::RoutingActionSender;
use messages::{DirectMessage, HopMessage, Message, RequestContent, RequestMessage,
               ResponseContent, ResponseMessage, RoutingMessage, SignedMessage};
use utils;

const CRUST_DEFAULT_BEACON_PORT: u16 = 5484;
const CRUST_DEFAULT_TCP_ACCEPTING_PORT: crust::Port = crust::Port::Tcp(5483);
// const CRUST_DEFAULT_UTP_ACCEPTING_PORT: crust::Port = crust::Port::Utp(5483);

/// The maximum number of other nodes that can be in the bootstrap process with us as the proxy at
/// the same time.
const MAX_JOINING_NODES: usize = 1;

/// The state of the connection to the network.
#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
enum State {
    /// Not connected to any node.
    Disconnected,
    /// Transition state while validating proxy node.
    Bootstrapping,
    /// We are bootstrapped and connected to a valid proxy node.
    Client,
    /// We have been Relocated and now a node.
    Node,
}

/// An interface for clients and nodes that handles routing and connecting to the network.
///
///
/// # The bootstrap process
///
///
/// ## Bootstrapping a client
///
/// A newly created `Core`, A, starts in `Disconnected` state and tries to establish a connection to
/// any node B of the network via Crust. When successful, i. e. when receiving an `OnConnect` event,
/// it moves to the `Bootstrapping` state.
///
/// A now sends a `ClientIdentify` message to B, containing A's signed public ID. B verifies the
/// signature and responds with a `BootstrapIdentify`, containing B's public ID and the current
/// quorum size. Once it receives that, A goes into the `Client` state and uses B as its proxy to
/// the network.
///
/// A can now exchange messages with any `Authority`. This completes the bootstrap process for
/// clients.
///
///
/// ## Becoming a node
///
/// If A wants to become a full routing node (`client_restriction == false`), it needs to relocate,
/// i. e. change its name to a value chosen by the network, and then add its peers to its routing
/// table and get added to their routing tables.
///
///
/// ### Getting a new network name from the `NaeManager`
///
/// Once in `Client` state, A sends a `GetNetworkName` request to the `NaeManager` group authority X
/// of A's current name. X computes a new name and sends it in its response to A.
///
/// It also sends an `ExpectCloseNode` request to the `NaeManager` Y of A's new name to inform Y
/// about the new node. Each member of Y caches A's public ID.
///
///
/// ### Connecting to the close group
///
/// A now sends a `GetCloseGroup` request to Y. Each member of Y sends its own public ID and those
/// of its close group in its response to A. Those messages don't necessarily agree, as not every
/// member of Y has the same close group!
///
/// To the `ManagedNode` for each public ID it receives from members of Y, A sends its `Endpoints`.
/// It also caches the ID.
///
/// For each `Endpoints` that a node Z receives from A, it decides whether it wants A in its routing
/// table. If yes, and if A's ID is in its ID cache, Z sends its own `Endpoints` back to A and also
/// attempts to connect to A via Crust. A does the same, once it receives the `Endpoints`.
///
/// Once the connection between A and Z is established and a Crust `OnConnect` event is raised,
/// they exchange `NodeIdentify` messages and add each other to their routing tables. When A
/// receives its first `NodeIdentify`, it finally moves to the `Node` state.
pub struct Core {
    // for CRUST
    crust_service: crust::Service,
    acceptors: Acceptors,
    // for Core
    client_restriction: bool,
    is_listening: bool,
    crust_rx: mpsc::Receiver<crust::Event>,
    action_rx: mpsc::Receiver<Action>,
    event_sender: mpsc::Sender<Event>,
    signed_message_filter: MessageFilter<SignedMessage>,
    connection_filter: MessageFilter<XorName>,
    node_id_cache: LruCache<XorName, PublicId>,
    message_accumulator: Accumulator<RoutingMessage, sign::PublicKey>,
    // Group messages which have been accumulated and then actioned
    grp_msg_filter: MessageFilter<RoutingMessage>,
    full_id: FullId,
    state: State,
    routing_table: RoutingTable<PublicId, crust::Connection>,
    // our bootstrap connections
    proxy_map: HashMap<crust::Connection, PublicId>,
    // any clients we have proxying through us, and whether they have `client_restriction`
    client_map: HashMap<sign::PublicKey, (crust::Connection, bool)>,
    data_cache: LruCache<XorName, Data>,
}

impl Core {
    /// A Core instance for a client or node with the given id. Sends events to upper layer via the mpsc sender passed
    /// in.
    pub fn new(event_sender: mpsc::Sender<Event>,
               client_restriction: bool,
               keys: Option<FullId>)
               -> Result<(RoutingActionSender, RaiiThreadJoiner), RoutingError> {
        let (crust_tx, crust_rx) = mpsc::channel();
        let (action_tx, action_rx) = mpsc::channel();
        let (category_tx, category_rx) = mpsc::channel();

        let routing_event_category = MaidSafeEventCategory::RoutingEvent;
        let action_sender = RoutingActionSender::new(action_tx,
                                                     routing_event_category,
                                                     category_tx.clone());

        let crust_event_category = MaidSafeEventCategory::CrustEvent;
        let crust_sender = crust::CrustEventSender::new(crust_tx,
                                                        crust_event_category,
                                                        category_tx);

        let crust_service = match crust::Service::new(crust_sender) {
            Ok(service) => service,
            Err(what) => panic!(format!("Unable to start crust::Service {}", what)),
        };

        let full_id = match keys {
            Some(full_id) => full_id,
            None => FullId::new(),
        };
        let our_name = *full_id.public_id().name();

        let joiner = thread!("RoutingThread", move || {
            let mut core = Core {
                crust_service: crust_service,
                acceptors: Acceptors::new(),
                client_restriction: client_restriction,
                is_listening: false,
                crust_rx: crust_rx,
                action_rx: action_rx,
                event_sender: event_sender,
                signed_message_filter: MessageFilter::with_expiry_duration(Duration::minutes(20)),
                // TODO Needs further discussion on interval
                connection_filter: MessageFilter::with_expiry_duration(Duration::seconds(20)),
                node_id_cache: LruCache::with_expiry_duration(Duration::minutes(10)),
                message_accumulator: Accumulator::with_duration(1, Duration::minutes(5)),
                grp_msg_filter: MessageFilter::with_expiry_duration(Duration::minutes(20)),
                full_id: full_id,
                state: State::Disconnected,
                routing_table: RoutingTable::new(&our_name),
                proxy_map: HashMap::new(),
                client_map: HashMap::new(),
                data_cache: LruCache::with_expiry_duration(Duration::minutes(10)),
            };

            core.run(category_rx);
        });

        Ok((action_sender, RaiiThreadJoiner::new(joiner)))
    }

    /// Run the event loop for sending and receiving messages.
    pub fn run(&mut self, category_rx: mpsc::Receiver<MaidSafeEventCategory>) {
        let mut cur_routing_table_size = 0;
        self.crust_service.bootstrap(0u32, Some(CRUST_DEFAULT_BEACON_PORT));
        for it in category_rx.iter() {
            match it {
                MaidSafeEventCategory::RoutingEvent => {
                    if let Ok(action) = self.action_rx.try_recv() {
                        match action {
                            Action::NodeSendMessage { content, result_tx, } => {
                                if result_tx.send(match self.send_message(content) {
                                                Err(RoutingError::Interface(err)) => Err(err),
                                                Err(_err) => Ok(()),
                                                Ok(()) => Ok(()),
                                            })
                                            .is_err() {
                                    return;
                                }
                            }
                            Action::ClientSendRequest { content, dst, result_tx, } => {
                                if result_tx.send(if let Ok(src) = self.get_client_authority() {
                                                let request_msg = RequestMessage {
                                                    content: content,
                                                    src: src,
                                                    dst: dst,
                                                };

                                                let routing_msg =
                                                    RoutingMessage::Request(request_msg);
                                                match self.send_message(routing_msg) {
                                                    Err(RoutingError::Interface(err)) => Err(err),
                                                    Err(_err) => Ok(()),
                                                    Ok(()) => Ok(()),
                                                }
                                            } else {
                                                Err(InterfaceError::NotConnected)
                                            })
                                            .is_err() {
                                    return;
                                }
                            }
                            Action::CloseGroup{ result_tx, } => {
                                let close_group = self.close_group_names();
                                if result_tx.send(close_group).is_err() {
                                    return;
                                }
                            }
                            Action::Name{ result_tx, } => {
                                if result_tx.send(self.name().clone()).is_err() {
                                    return;
                                }
                            }
                            Action::Terminate => {
                                break;
                            }
                        }
                    }
                }
                MaidSafeEventCategory::CrustEvent => {
                    if let Ok(crust_event) = self.crust_rx.try_recv() {
                        self.handle_crust_event(crust_event);
                    }
                }
            } // Category Match

            if self.state == State::Node && cur_routing_table_size != self.routing_table.len() {
                cur_routing_table_size = self.routing_table.len();
                trace!(" -----------------------------------");
                trace!("| Routing Table size updated to: {}",
                       self.routing_table.len());
                // self.routing_table.our_close_group().iter().all(|elt| {
                //     trace!("Name: {:?} Connections {:?}  -- {:?}",
                //            elt.public_id.name(),
                //            elt.connections.len(),
                //            elt.connections);
                //     true
                // });
                trace!(" -----------------------------------");
            }
        } // Category Rx
    }

    fn handle_crust_event(&mut self, crust_event: crust::Event) {
        match crust_event {
            crust::Event::BootstrapFinished => self.handle_bootstrap_finished(),
            crust::Event::OnAccept(endpoint, connection) => {
                self.handle_on_accept(endpoint, connection)
            }
            // TODO (Fraser) This needs to restart if we are left with 0 connections
            crust::Event::LostConnection(connection) => self.handle_lost_connection(connection),
            crust::Event::NewMessage(connection, bytes) => {
                match self.handle_new_message(connection, bytes) {
                    Err(RoutingError::FilterCheckFailed) => (),
                    Err(err) => error!("{:?} {:?}", self, err),
                    Ok(_) => (),
                }
            }
            crust::Event::OnConnect(io_result, connection_token) => {
                self.handle_on_connect(io_result, connection_token)
            }
            crust::Event::ExternalEndpoints(external_endpoints) => {
                for external_endpoint in external_endpoints {
                    debug!("Adding external endpoint {:?}", external_endpoint);
                    // TODO - reimplement
                    // self.accepting_on.push(external_endpoint);
                }
            }
            crust::Event::OnHolePunched(_hole_punch_result) => unimplemented!(),
            crust::Event::OnUdpSocketMapped(_mapped_udp_socket) => unimplemented!(),
            crust::Event::OnRendezvousConnect(_connection, _signed_request) => unimplemented!(),
        }
    }

    fn handle_new_message(&mut self,
                          connection: crust::Connection,
                          bytes: Vec<u8>)
                          -> Result<(), RoutingError> {
        match serialisation::deserialise(&bytes) {
            Ok(Message::HopMessage(ref hop_msg)) => self.handle_hop_message(hop_msg, connection),
            Ok(Message::DirectMessage(direct_msg)) => {
                self.handle_direct_message(direct_msg, connection)
            }
            Err(error) => Err(RoutingError::SerialisationError(error)),
        }
    }

    fn handle_hop_message(&mut self,
                          hop_msg: &HopMessage,
                          connection: crust::Connection)
                          -> Result<(), RoutingError> {
        if self.state == State::Node {
            if let Some(&NodeInfo { ref public_id, ..}) = self.routing_table.get(hop_msg.name()) {
                try!(hop_msg.verify(public_id.signing_public_key()));
                try!(self.check_direction(hop_msg));
            } else if let Some((ref pub_key, &(_, client_restriction))) = self.client_map
                                                                       .iter()
                                                                       .find(|ref elt| {
                                                                           connection == (elt.1).0
                                                                       }) {
                try!(hop_msg.verify(pub_key));
                if client_restriction {
                    try!(self.check_not_get_network_name(hop_msg.content().content()));
                }
            } else {
                // TODO drop connection ?
                return Err(RoutingError::UnknownConnection);
            }
        } else if self.state == State::Client {
            if let Some(pub_id) = self.proxy_map.get(&connection) {
                try!(hop_msg.verify(pub_id.signing_public_key()));
            }
        } else {
            return Err(RoutingError::InvalidStateForOperation);
        }

        self.handle_signed_message(hop_msg.content(), hop_msg.name())
    }

    fn check_not_get_network_name(&self, msg: &RoutingMessage) -> Result<(), RoutingError> {
        match *msg {
            RoutingMessage::Request(RequestMessage {
                content: RequestContent::GetNetworkName { .. },
                ..
            }) => {
                trace!("Illegitimate GetNetworkName request. Refusing to relay.");
                Err(RoutingError::RejectedGetNetworkName)
            }
            _ => Ok(()),
        }
    }

    /// Returns an error if this is not a swarm message and was not sent in the right direction.
    fn check_direction(&self, hop_msg: &HopMessage) -> Result<(), RoutingError> {
        let dst = hop_msg.content().content().dst();
        if self.is_swarm(dst, hop_msg.name()) {
            Ok(())
        } else if xor_name::closer_to_target(&hop_msg.name(), self.name(), dst.name()) {
            trace!("Direction check failed in hop message from node {:?}: {:?}",
                   hop_msg.name(),
                   hop_msg.content().content());
            // TODO: Reconsider direction checks once we know whether they help secure routing.
            Ok(())
            // Err(RoutingError::DirectionCheckFailed)
        } else {
            Ok(())
        }
    }

    fn handle_signed_message(&mut self,
                             signed_msg: &SignedMessage,
                             hop_name: &XorName)
                             -> Result<(), RoutingError> {
        try!(signed_msg.check_integrity());

        // Prevents
        // 1) someone sending messages repeatedly to us
        // 2) swarm messages generated by us reaching us again
        if self.signed_message_filter.insert(signed_msg) > 0 {
            return Err(RoutingError::FilterCheckFailed);
        }

        match self.state {
            State::Node => self.handle_signed_message_for_node(signed_msg, hop_name),
            State::Client => self.handle_signed_message_for_client(signed_msg),
            _ => Err(RoutingError::InvalidStateForOperation),
        }
    }

    fn handle_signed_message_for_node(&mut self,
                                      signed_msg: &SignedMessage,
                                      hop_name: &XorName)
                                      -> Result<(), RoutingError> {
        let dst = signed_msg.content().dst();

        // Since endpoint request / GetCloseGroup response messages while relocating are sent
        // to a client we still need to accept these msgs sent to us even if we have become a node.
        if let Authority::Client { ref client_key, .. } = *dst {
            if client_key == self.full_id.public_id().signing_public_key() {
                match *signed_msg.content() {
                    RoutingMessage::Request(RequestMessage {
                        content: RequestContent::Endpoints { .. },
                        ..
                    }) => try!(self.handle_signed_message_for_client(&signed_msg)),
                    RoutingMessage::Response(ResponseMessage {
                        content: ResponseContent::GetCloseGroup { .. },
                        ..
                    }) => try!(self.handle_signed_message_for_client(&signed_msg)),
                    _ => (),
                }
            }
        }

        try!(self.harvest_node(signed_msg.public_id().name()));

        if let Authority::Client { ref client_key, .. } = *dst {
            if self.name() == dst.name() {
                // This is a message for a client we are the proxy of. Relay it.
                return self.relay_to_client(signed_msg.clone(), client_key);
            }
        }

        if self.routing_table.is_close(dst.name()) {
            try!(self.signed_msg_security_check(&signed_msg));
        }

        // Cache handling
        if let Some(routing_msg) = self.get_from_cache(signed_msg.content()) {
            let response = try!(SignedMessage::new(routing_msg, &self.full_id));
            return self.send(response);
        }
        self.add_to_cache(signed_msg.content());

        // TODO: Move more of this logic to kademlia_routing_table: Methods of the routing table
        //       should not only decide whether to handle it, but also whether to forward it.
        // Forwarding the message
        if self.routing_table.is_recipient(dst.to_destination()) {
            // If the message is for a group and not already a swarm message, send swarm messages.
            if dst.is_group() && !self.is_swarm(dst, hop_name) {
                try!(self.send(signed_msg.clone()));
            }
            self.handle_routing_message(signed_msg.content().clone(),
                                        signed_msg.public_id().clone())
        } else {
            // If it was not meant for us, forward it.
            self.send(signed_msg.clone())
        }
    }

    /// Returns `true` if a message is a swarm message.
    ///
    /// This is the case if a routing node in the destination's close group sent this message.
    fn is_swarm(&self, dst: &Authority, hop_name: &XorName) -> bool {
        dst.is_group() && self.routing_table.is_close(dst.name()) &&
        (hop_name == self.name() ||
         self.routing_table
             .closest_nodes_to(dst.name(), GROUP_SIZE - 1)
             .into_iter()
             .any(|n| n.name() == hop_name))
    }

    /// Checks if the given name is missing from our routing table and if so, tries to connect.
    fn harvest_node(&mut self, name: &XorName) -> Result<(), RoutingError> {
        if self.connection_filter.insert(name) == 0 && self.routing_table.need_to_add(name) {
            self.send_connect_request(name)
        } else {
            Ok(())
        }
    }

    fn handle_signed_message_for_client(&mut self,
                                        signed_msg: &SignedMessage)
                                        -> Result<(), RoutingError> {
        match *signed_msg.content().dst() {
            Authority::Client { ref client_key, .. } => {
                if self.full_id.public_id().signing_public_key() != client_key {
                    return Err(RoutingError::BadAuthority);
                }
            }
            _ => return Err(RoutingError::BadAuthority),
        }
        self.handle_routing_message(signed_msg.content().clone(), signed_msg.public_id().clone())
    }

    fn signed_msg_security_check(&self, signed_msg: &SignedMessage) -> Result<(), RoutingError> {
        if signed_msg.content().src().is_group() {
            // TODO validate unconfirmed node is a valid node in the network

            // FIXME This check will need to get finalised in routing table
            // if !self.routing_table
            //         .try_confirm_safe_group_distance(signed_msg.content().src().name(),
            //                                          signed_msg.public_id().name()) {
            //     return Err(RoutingError::RoutingTableBucketIndexFailed);
            // }

            Ok(())
        } else {
            match (signed_msg.content().src(), signed_msg.content().dst()) {
                (&Authority::ManagedNode(_node_name),
                 &Authority::NodeManager(_manager_name)) => {
                    // TODO confirm sender is in our routing table
                    Ok(())
                }
                // Security validation if came from a Client: This validation ensures that the
                // source authority matches the signed message's public_id. This prevents cases
                // where attacker can provide a fake SignedMessage wrapper over somebody else's
                // (Client's) RoutingMessage.
                (&Authority::Client { ref client_key, .. }, _) => {
                    if client_key != signed_msg.public_id().signing_public_key() {
                        return Err(RoutingError::FailedSignature);
                    };
                    Ok(())
                }
                _ => Ok(()),
            }
        }
    }

    /// Returns a cached response, if one is available for the given message, otherwise `None`.
    fn get_from_cache(&mut self, routing_msg: &RoutingMessage) -> Option<RoutingMessage> {
        let content = match *routing_msg {
            RoutingMessage::Request(RequestMessage {
                    content: RequestContent::Get(DataRequest::ImmutableData(ref name, _), ref id),
                    ..
                }) => {
                match self.data_cache.get(&name) {
                    Some(data) => ResponseContent::GetSuccess(data.clone(), id.clone()),
                    _ => return None,
                }
            }
            _ => return None,
        };

        let response_msg = ResponseMessage {
            src: Authority::ManagedNode(self.name().clone()),
            dst: routing_msg.src().clone(),
            content: content,
        };

        Some(RoutingMessage::Response(response_msg))
    }

    fn add_to_cache(&mut self, routing_msg: &RoutingMessage) {
        if let RoutingMessage::Response(ResponseMessage {
                    content: ResponseContent::GetSuccess(ref data @ Data::ImmutableData(_), _),
                    ..
                }) = *routing_msg {
            let _ = self.data_cache.insert(data.name().clone(), data.clone());
        }
    }

    // Needs to be commented
    fn handle_routing_message(&mut self,
                              routing_msg: RoutingMessage,
                              public_id: PublicId)
                              -> Result<(), RoutingError> {
        if routing_msg.src().is_group() {
            if self.grp_msg_filter.contains(&routing_msg) {
                return Err(RoutingError::FilterCheckFailed);
            }
            if let Some(output_msg) = self.accumulate(routing_msg.clone(), &public_id) {
                let _ = self.grp_msg_filter.insert(&output_msg);
            } else {
                return Ok(());
            }
        }
        self.dispatch_request_response(routing_msg)
    }


    fn dispatch_request_response(&mut self,
                                 routing_msg: RoutingMessage)
                                 -> Result<(), RoutingError> {
        trace!("{:?} Handling - {:?}", self, routing_msg);
        match routing_msg {
            RoutingMessage::Request(msg) => self.handle_request_message(msg),
            RoutingMessage::Response(msg) => self.handle_response_message(msg),
        }
    }

    fn accumulate(&mut self,
                  message: RoutingMessage,
                  public_id: &PublicId)
                  -> Option<RoutingMessage> {
        // For clients we already have set it on reception of BootstrapIdentify message
        if self.state == State::Node {
            self.message_accumulator.set_quorum_size(self.routing_table.dynamic_quorum_size());
        }

        if self.message_accumulator
               .add(message.clone(), public_id.signing_public_key().clone())
               .is_some() {
            Some(message)
        } else {
            None
        }
    }

    fn handle_request_message(&mut self, request_msg: RequestMessage) -> Result<(), RoutingError> {
        match (request_msg.content.clone(),
               request_msg.src.clone(),
               request_msg.dst.clone()) {
            (RequestContent::GetNetworkName { current_id, },
             Authority::Client { client_key, proxy_node_name },
             Authority::NaeManager(dst_name)) => {
                self.handle_get_network_name_request(current_id,
                                                     client_key,
                                                     proxy_node_name,
                                                     dst_name)
            }
            (RequestContent::ExpectCloseNode { expect_id, },
             Authority::NaeManager(_),
             Authority::NaeManager(_)) => self.handle_expect_close_node_request(expect_id),
            (RequestContent::GetCloseGroup,
             src,
             Authority::NaeManager(dst_name)) => self.handle_get_close_group_request(src, dst_name),
            (RequestContent::Endpoints { encrypted_endpoints, nonce_bytes },
             Authority::Client { client_key, proxy_node_name, },
             Authority::ManagedNode(dst_name)) => {
                self.handle_endpoints_from_client(encrypted_endpoints,
                                                  nonce_bytes,
                                                  client_key,
                                                  proxy_node_name,
                                                  dst_name)
            }
            (RequestContent::Endpoints { encrypted_endpoints, nonce_bytes },
             Authority::ManagedNode(src_name),
             Authority::Client { .. }) |
            (RequestContent::Endpoints { encrypted_endpoints, nonce_bytes },
             Authority::ManagedNode(src_name),
             Authority::ManagedNode(_)) => {
                self.handle_endpoints_from_node(encrypted_endpoints,
                                                nonce_bytes,
                                                src_name,
                                                request_msg.dst)
            }
            (RequestContent::Connect,
             Authority::ManagedNode(src_name),
             Authority::ManagedNode(dst_name)) => self.handle_connect_request(src_name, dst_name),
            (RequestContent::GetPublicId,
             Authority::ManagedNode(src_name),
             Authority::NodeManager(dst_name)) => self.handle_get_public_id(src_name, dst_name),
            (RequestContent::GetPublicIdWithEndpoints { encrypted_endpoints, nonce_bytes, },
             Authority::ManagedNode(src_name),
             Authority::NodeManager(dst_name)) => {
                self.handle_get_public_id_with_endpoints(encrypted_endpoints,
                                                         nonce_bytes,
                                                         src_name,
                                                         dst_name)
            }
            (RequestContent::Get(..), _, _) |
            (RequestContent::Put(..), _, _) |
            (RequestContent::Post(..), _, _) |
            (RequestContent::Delete(..), _, _) |
            (RequestContent::Refresh(_), _, _) => {
                let event = Event::Request(request_msg);
                let _ = self.event_sender.send(event);
                Ok(())
            }
            _ => {
                warn!("Unhandled request - Message {:?}", request_msg);
                Err(RoutingError::BadAuthority)
            }
        }
    }

    fn handle_response_message(&mut self,
                               response_msg: ResponseMessage)
                               -> Result<(), RoutingError> {
        match (response_msg.content.clone(),
               response_msg.src.clone(),
               response_msg.dst.clone()) {
            (ResponseContent::GetNetworkName { relocated_id, },
             Authority::NaeManager(_),
             Authority::Client { client_key, proxy_node_name, }) => {
                self.handle_get_network_name_response(relocated_id, client_key, proxy_node_name)
            }
            (ResponseContent::GetPublicId { public_id, },
             Authority::NodeManager(_),
             Authority::ManagedNode(dst_name)) => {
                self.handle_get_public_id_response(public_id, dst_name)
            }
            (ResponseContent::GetPublicIdWithEndpoints { public_id, encrypted_endpoints, nonce_bytes },
             Authority::NodeManager(_),
             Authority::ManagedNode(dst_name)) => {
                self.handle_get_public_id_with_endpoints_response(public_id, encrypted_endpoints, nonce_bytes, dst_name)
            }
            (ResponseContent::GetCloseGroup { close_group_ids },
             Authority::NaeManager(_),
             dst) => self.handle_get_close_group_response(close_group_ids, dst),
            (ResponseContent::GetSuccess(..), _, _) |
            (ResponseContent::PutSuccess(..), _, _) |
            (ResponseContent::PostSuccess(..), _, _) |
            (ResponseContent::DeleteSuccess(..), _, _) |
            (ResponseContent::GetFailure{..}, _, _) |
            (ResponseContent::PutFailure{..}, _, _) |
            (ResponseContent::PostFailure{..}, _, _) |
            (ResponseContent::DeleteFailure{..}, _, _) => {
                let event = Event::Response(response_msg);
                let _ = self.event_sender.send(event);
                Ok(())
            }
            _ => {
                warn!("Unhandled response - Message {:?}", response_msg);
                Err(RoutingError::BadAuthority)
            }
        }
    }

    fn handle_bootstrap_finished(&mut self) {
        debug!("Finished bootstrapping.");
        // If we have no connections, we should start listening to allow incoming connections
        if self.state == State::Disconnected {
            debug!("Bootstrap finished with no connections. Start Listening to allow incoming \
                    connections.");
            self.start_listening();
        }
    }

    fn start_listening(&mut self) {
        if self.is_listening {
            // TODO Implement a better call once fn
            return;
        }
        self.is_listening = true;

        match self.crust_service.start_beacon(CRUST_DEFAULT_BEACON_PORT) {
            Ok(port) => info!("Running Crust beacon listener on port {}", port),
            Err(error) => {
                warn!("Crust beacon failed to listen on port {}: {:?}",
                      CRUST_DEFAULT_BEACON_PORT,
                      error)
            }
        }
        match self.crust_service.start_accepting(CRUST_DEFAULT_TCP_ACCEPTING_PORT) {
            Ok(endpoint) => {
                info!("Running TCP listener on {:?}", endpoint);
                self.acceptors.set_tcp_accepting_port(endpoint.get_port());
                // self.accepting_on.push(endpoint);
            }
            Err(error) => {
                warn!("Failed to listen on {:?}: {:?}",
                      CRUST_DEFAULT_TCP_ACCEPTING_PORT,
                      error)
            }
        }
        // match self.crust_service.start_accepting(CRUST_DEFAULT_UTP_ACCEPTING_PORT) {
        //     Ok(endpoint) => {
        //         info!("Running uTP listener on {:?}", endpoint);
        //         self.acceptors.set_utp_accepting_port(endpoint.get_port());
        //         // self.accepting_on.push(endpoint);
        //     }
        //     Err(error) => {
        //         warn!("Failed to listen on {:?}: {:?}",
        //               CRUST_DEFAULT_UTP_ACCEPTING_PORT,
        //               error)
        //     }
        // }

        // The above commands will give us only internal endpoints on which we're accepting. The
        // next command will try to find external endpoints. The result shall be returned async
        // through the Crust::ExternalEndpoints event.
        self.crust_service.get_external_endpoints();
    }

    fn handle_on_connect(&mut self,
                         result: io::Result<(crust::Endpoint, crust::Connection)>,
                         connection_token: u32) {
        match result {
            Ok((endpoint, connection)) => {
                self.acceptors.add(endpoint.clone());
                debug!("New connection via OnConnect {:?} with token {}",
                       connection,
                       connection_token);
                if self.state == State::Disconnected {
                    // Established connection. Pending Validity checks
                    self.acceptors.set_bootstrap_ip(endpoint);
                    self.state = State::Bootstrapping;
                    let _ = self.client_identify(connection);
                    return;
                }

                let _ = self.node_identify(connection);
            }
            Err(error) => {
                warn!("Failed to make connection with token {} - {}",
                      connection_token,
                      error);
            }
        }
    }

    fn handle_on_accept(&mut self, endpoint: crust::Endpoint, connection: crust::Connection) {
        debug!("New connection via OnAccept {:?} {:?}", connection, self);
        if self.state == State::Disconnected {
            // I am the first node in the network, and I got an incoming connection so I'll
            // promote myself as a node.
            let new_name = XorName::new(hash::sha512::hash(&self.full_id
                                                                .public_id()
                                                                .name()
                                                                .0)
                                            .0);

            // This will give me a new RT and set state to Relocated
            self.set_self_node_name(new_name);
            self.state = State::Node;
        }
        self.acceptors.add(endpoint);
    }

    fn handle_lost_connection(&mut self, connection: crust::Connection) {
        debug!("Lost connection on {:?}", connection);
        self.dropped_routing_node_connection(&connection);
        self.dropped_client_connection(&connection);
        self.dropped_bootstrap_connection(&connection);
    }

    fn bootstrap_identify(&mut self, connection: crust::Connection) -> Result<(), RoutingError> {
        let direct_message = DirectMessage::BootstrapIdentify {
            public_id: self.full_id.public_id().clone(),
            current_quorum_size: self.routing_table.dynamic_quorum_size(),
        };

        let message = Message::DirectMessage(direct_message);
        let raw_bytes = try!(serialisation::serialise(&message));

        Ok(self.crust_service.send(connection, raw_bytes))
    }

    fn bootstrap_deny(&mut self, connection: crust::Connection) -> Result<(), RoutingError> {
        let message = Message::DirectMessage(DirectMessage::BootstrapDeny);
        let raw_bytes = try!(serialisation::serialise(&message));
        Ok(self.crust_service.send(connection, raw_bytes))
    }

    fn client_identify(&mut self, connection: crust::Connection) -> Result<(), RoutingError> {
        let serialised_public_id = try!(serialisation::serialise(self.full_id.public_id()));
        let signature = sign::sign_detached(&serialised_public_id,
                                            self.full_id.signing_private_key());

        let direct_message = DirectMessage::ClientIdentify {
            serialised_public_id: serialised_public_id,
            signature: signature,
            client_restriction: self.client_restriction,
        };

        let message = Message::DirectMessage(direct_message);
        let raw_bytes = try!(serialisation::serialise(&message));

        Ok(self.crust_service.send(connection, raw_bytes))
    }

    fn node_identify(&mut self, connection: crust::Connection) -> Result<(), RoutingError> {
        let serialised_public_id = try!(serialisation::serialise(self.full_id.public_id()));
        let signature = sign::sign_detached(&serialised_public_id,
                                            self.full_id
                                                .signing_private_key());

        let direct_message = DirectMessage::NodeIdentify {
            serialised_public_id: serialised_public_id,
            signature: signature,
        };

        let message = Message::DirectMessage(direct_message);
        let raw_bytes = try!(serialisation::serialise(&message));

        Ok(self.crust_service.send(connection, raw_bytes))
    }

    fn verify_signed_public_id(serialised_public_id: &[u8],
                               signature: &sign::Signature)
                               -> Result<PublicId, RoutingError> {
        let public_id: PublicId = try!(serialisation::deserialise(serialised_public_id));
        if sign::verify_detached(signature,
                                 serialised_public_id,
                                 public_id.signing_public_key()) {
            Ok(public_id)
        } else {
            Err(RoutingError::FailedSignature)
        }
    }

    fn handle_direct_message(&mut self,
                             direct_message: DirectMessage,
                             connection: crust::Connection)
                             -> Result<(), RoutingError> {
        match direct_message {
            DirectMessage::BootstrapIdentify { public_id, current_quorum_size } => {
                self.handle_bootstrap_identify(public_id, connection, current_quorum_size)
            }
            DirectMessage::BootstrapDeny => {
                if self.client_restriction {
                    warn!("Connection failed: Proxy node needs a larger routing table to accept \
                           clients.");
                } else {
                    warn!("Connection failed: Proxy node doesn't accept any more joining nodes.");
                }
                self.retry_bootstrap_with_blacklist(connection);
                Ok(())
            }
            DirectMessage::ClientIdentify {
                ref serialised_public_id,
                ref signature,
                client_restriction
            } => {
                let public_id = match Core::verify_signed_public_id(serialised_public_id,
                                                                    signature) {
                    Ok(public_id) => public_id,
                    Err(_) => {
                        warn!("Signature check failed in ClientIdentify - Dropping connection \
                               {:?}",
                              connection);
                        self.crust_service.drop_node(connection);

                        return Ok(());
                    }
                };
                self.handle_client_identify(public_id, connection, client_restriction)
            }
            DirectMessage::NodeIdentify { ref serialised_public_id, ref signature } => {
                let public_id = match Core::verify_signed_public_id(serialised_public_id,
                                                                    signature) {
                    Ok(public_id) => public_id,
                    Err(_) => {
                        warn!("Signature check failed in NodeIdentify - Dropping connection {:?}",
                              connection);
                        self.crust_service.drop_node(connection);

                        return Ok(());
                    }
                };
                self.handle_node_identify(public_id, connection)
            }
            DirectMessage::NewNode(public_id) => {
                if self.routing_table.need_to_add(public_id.name()) {
                    return self.send_connect_request(public_id.name());
                }
                Ok(())
            }
        }
    }

    fn handle_bootstrap_identify(&mut self,
                                 public_id: PublicId,
                                 connection: crust::Connection,
                                 current_quorum_size: usize)
                                 -> Result<(), RoutingError> {
        trace!("{:?} Rxd BootstrapIdentify - Quorum size: {}",
               self,
               current_quorum_size);

        if *public_id.name() ==
           XorName::new(hash::sha512::hash(&public_id.signing_public_key().0).0) {
            warn!("Incoming Connection not validated as a proper node - dropping");
            self.crust_service.drop_node(connection);

            // Probably look for other bootstrap connections
            return Ok(());
        }

        if let Some(previous_name) = self.proxy_map.insert(connection, public_id.clone()) {
            warn!("Adding bootstrap node to proxy map caused a prior id to eject. Previous name: \
                   {:?}",
                  previous_name);
            warn!("Dropping this connection {:?}", connection);
            self.crust_service.drop_node(connection);
            let _ = self.proxy_map.remove(&connection);

            // Probably look for other bootstrap connections
            return Ok(());
        }

        self.state = State::Client;
        self.message_accumulator.set_quorum_size(current_quorum_size);

        if self.client_restriction {
            let _ = self.event_sender.send(Event::Connected);
        } else {
            try!(self.relocate());
        };
        Ok(())
    }

    fn handle_client_identify(&mut self,
                              public_id: PublicId,
                              connection: crust::Connection,
                              client_restriction: bool)
                              -> Result<(), RoutingError> {
        if *public_id.name() !=
           XorName::new(hash::sha512::hash(&public_id.signing_public_key().0).0) {
            warn!("Incoming Connection not validated as a proper client - dropping");
            self.crust_service.drop_node(connection);
            return Ok(());
        }

        if client_restriction {
            if self.routing_table.len() < GROUP_SIZE {
                trace!("Client rejected: Routing table has {} entries. {} required.",
                       self.routing_table.len(),
                       GROUP_SIZE);
                return self.bootstrap_deny(connection);
            }
        } else {
            let joining_nodes_num = self.joining_nodes_num();
            // Restrict the number of simultaneously joining nodes. If the network is still
            // small, we need to accept `GROUP_SIZE` nodes, so that they can fill their
            // routing tables and drop the proxy connection.
            if !(self.routing_table.len() < GROUP_SIZE && joining_nodes_num < GROUP_SIZE) &&
               joining_nodes_num >= MAX_JOINING_NODES {
                trace!("No additional joining nodes allowed.");
                return self.bootstrap_deny(connection);
            }
        }
        if let Some((prev_conn, _)) = self.client_map
                                          .insert(public_id.signing_public_key().clone(),
                                                  (connection, client_restriction)) {
            debug!("Found previous connection against client key - Dropping {:?}",
                   prev_conn);
            self.crust_service.drop_node(prev_conn);
        }

        let _ = self.bootstrap_identify(connection);
        Ok(())
    }

    fn handle_node_identify(&mut self,
                            public_id: PublicId,
                            connection: crust::Connection)
                            -> Result<(), RoutingError> {
        if let Some(their_public_id) = self.node_id_cache.get(public_id.name()).cloned() {
            if their_public_id != public_id {
                warn!("Given Public ID and Public ID in cache don't match - Given {:?} :: In \
                       cache {:?} Dropping connection {:?}",
                      public_id,
                      their_public_id,
                      connection);

                self.crust_service.drop_node(connection);
                return Ok(());
            }

            let node_info = NodeInfo::new(public_id.clone(), Some(connection));
            if let Some(_) = self.routing_table.get(public_id.name()) {
                if !self.routing_table.add_connection(public_id.name(), connection) {
                    // We already sent an identify down this connection
                    return Ok(());
                }
            } else {
                if let Some(AddedNodeDetails { must_notify, common_groups }) =
                       self.routing_table.add_node(node_info) {
                    for node in must_notify {
                        let direct_message = DirectMessage::NewNode(node.public_id);
                        let message = Message::DirectMessage(direct_message);
                        let raw_bytes = try!(serialisation::serialise(&message));
                        self.crust_service.send(connection, raw_bytes);
                    }
                    if common_groups {
                        let event = Event::NodeAdded(public_id.name().clone());
                        if let Err(err) = self.event_sender.send(event) {
                            error!("Error sending event to routing user - {:?}", err);
                        }
                    }
                } else {
                    self.crust_service.drop_node(connection);
                    let _ = self.node_id_cache.remove(public_id.name());

                    return Ok(());
                }

                self.state = State::Node;

                if self.routing_table.len() >= GROUP_SIZE && !self.proxy_map.is_empty() {
                    trace!("Routing table reached group size. Dropping proxy.");
                    self.proxy_map
                        .keys()
                        .foreach(|&connection| self.crust_service.drop_node(connection));
                    self.proxy_map.clear();
                    // We have all close contacts now and know which bucket addresses to
                    // request IDs from: All buckets up to the one containing the furthest
                    // close node might still be not maximally filled.
                    for i in 0..(self.routing_table.furthest_close_bucket() + 1) {
                        if let Err(e) = self.request_bucket_ids(i) {
                            trace!("Failed to request endpoints from bucket {}: {:?}.", i, e);
                        }
                    }
                }
            }

            let _ = self.node_identify(connection);
            return Ok(());
        } else {
            debug!("PublicId not found in node_id_cache - Dropping Connection {:?}",
                   connection);
            self.crust_service.drop_node(connection);
            return Ok(());
        }
    }

    /// Sends a `GetCloseGroup` request to the close group with our `bucket_index`-th bucket
    /// address.
    fn request_bucket_ids(&mut self, bucket_index: usize) -> Result<(), RoutingError> {
        let bucket_address = try!(self.routing_table.our_name().with_flipped_bit(bucket_index));
        let request_msg = RequestMessage {
            src: Authority::ManagedNode(self.routing_table.our_name().clone()),
            dst: Authority::NaeManager(bucket_address),
            content: RequestContent::GetCloseGroup,
        };
        let routing_msg = RoutingMessage::Request(request_msg);
        let signed_msg = try!(SignedMessage::new(routing_msg, &self.full_id));
        self.send(signed_msg)
    }

    /// Returns the number of clients for which we act as a proxy and which intend to become a
    /// node.
    fn joining_nodes_num(&self) -> usize {
        self.client_map.values().filter(|&&(_, client_restriction)| !client_restriction).count()
    }

    fn retry_bootstrap_with_blacklist(&mut self, connection: crust::Connection) {
        let _endpoint = connection.peer_endpoint();
        self.crust_service.drop_node(connection);
        self.crust_service.stop_bootstrap();
        self.state = State::Disconnected;
        for &connection in self.proxy_map.keys() {
            self.crust_service.drop_node(connection);
        }
        self.proxy_map.clear();
        thread::sleep(::std::time::Duration::from_secs(5));
        self.crust_service.bootstrap(0u32, Some(CRUST_DEFAULT_BEACON_PORT));
        // TODO(andreas): Enable blacklisting once a solution for ci_test is found.
        //               Currently, ci_test's nodes all connect via the same beacon.
        // self.crust_service
        //    .bootstrap_with_blacklist(0u32, Some(CRUST_DEFAULT_BEACON_PORT), &[endpoint]);
    }

    // Constructed by A; From A -> X
    fn relocate(&mut self) -> Result<(), RoutingError> {
        let request_content = RequestContent::GetNetworkName {
            current_id: self.full_id.public_id().clone(),
        };

        let request_msg = RequestMessage {
            src: try!(self.get_client_authority()),
            dst: Authority::NaeManager(*self.name()),
            content: request_content,
        };

        let routing_msg = RoutingMessage::Request(request_msg);

        let signed_message = try!(SignedMessage::new(routing_msg, &self.full_id));

        self.send(signed_message)
    }

    // Received by X; From A -> X
    fn handle_get_network_name_request(&mut self,
                                       mut their_public_id: PublicId,
                                       client_key: sign::PublicKey,
                                       proxy_name: XorName,
                                       dst_name: XorName)
                                       -> Result<(), RoutingError> {
        let hashed_key = hash::sha512::hash(&client_key.0);
        let close_group_to_client = XorName::new(hashed_key.0);

        // Validate Client (relocating node) has contacted the correct Group-X
        if close_group_to_client != dst_name {
            return Err(RoutingError::InvalidDestination);
        }

        let mut close_group = self.close_group_names();
        close_group.push(self.name().clone());
        let relocated_name = try!(utils::calculate_relocated_name(close_group,
                                                                  &their_public_id.name()));

        their_public_id.set_name(relocated_name.clone());

        // From X -> A (via B)
        {
            let response_content = ResponseContent::GetNetworkName {
                relocated_id: their_public_id.clone(),
            };

            let response_msg = ResponseMessage {
                src: Authority::NaeManager(dst_name.clone()),
                dst: Authority::Client {
                    client_key: client_key,
                    proxy_node_name: proxy_name,
                },
                content: response_content,
            };

            let routing_msg = RoutingMessage::Response(response_msg);

            let signed_message = try!(SignedMessage::new(routing_msg, &self.full_id));
            try!(self.send(signed_message));
        }

        // From X -> Y; Send to close group of the relocated name
        {
            let request_content = RequestContent::ExpectCloseNode {
                expect_id: their_public_id.clone(),
            };

            let request_msg = RequestMessage {
                src: Authority::NaeManager(dst_name),
                dst: Authority::NaeManager(relocated_name),
                content: request_content,
            };

            let routing_msg = RoutingMessage::Request(request_msg);

            let signed_message = try!(SignedMessage::new(routing_msg, &self.full_id));

            self.send(signed_message)
        }
    }

    // Received by Y; From X -> Y
    fn handle_expect_close_node_request(&mut self,
                                        expect_id: PublicId)
                                        -> Result<(), RoutingError> {
        if let Some(prev_id) = self.node_id_cache.insert(*expect_id.name(), expect_id) {
            warn!("Previous id {:?} with same name found during \
                   handle_expect_close_node_request. Ignoring that",
                  prev_id);
            return Err(RoutingError::RejectedPublicId);
        }

        Ok(())
    }

    // Received by A; From X -> A
    fn handle_get_network_name_response(&mut self,
                                        relocated_id: PublicId,
                                        client_key: sign::PublicKey,
                                        proxy_name: XorName)
                                        -> Result<(), RoutingError> {
        self.set_self_node_name(*relocated_id.name());

        let request_content = RequestContent::GetCloseGroup;

        // From A -> Y
        let request_msg = RequestMessage {
            src: Authority::Client {
                client_key: client_key,
                proxy_node_name: proxy_name,
            },
            dst: Authority::NaeManager(*relocated_id.name()),
            content: request_content,
        };

        let routing_msg = RoutingMessage::Request(request_msg);

        let signed_msg = try!(SignedMessage::new(routing_msg, &self.full_id));

        self.send(signed_msg)
    }

    // Received by Y; From A -> Y, or from any node to one of its bucket addresses.
    fn handle_get_close_group_request(&mut self,
                                      src: Authority,
                                      dst_name: XorName)
                                      -> Result<(), RoutingError> {
        match src {
            Authority::Client { client_key, .. } => {
                if self.node_id_cache
                       .retrieve_all()
                       .iter()
                       .all(|elt| *elt.1.signing_public_key() != client_key) {
                    return Err(RoutingError::RejectedGetCloseGroup);
                }
            }
            Authority::ManagedNode(_) => {
                // Check that the destination is one of the sender's bucket addresses or the address
                // itself, i. e. it differs from it in 1 or 0 bits.
                if src.name().count_differing_bits(&dst_name) > 1 {
                    return Err(RoutingError::RejectedGetCloseGroup);
                }
            }
            _ => return Err(RoutingError::BadAuthority),
        }
        let mut public_ids = self.routing_table
                                 .closest_nodes_to(&dst_name, GROUP_SIZE - 1)
                                 .into_iter()
                                 .map(|node_info| node_info.public_id)
                                 .collect_vec();

        // Also add our own full_id to the close_group list getting sent
        public_ids.push(self.full_id.public_id().clone());
        public_ids.sort_by(|a, b| dst_name.cmp_distance(&a.name(), &b.name()));

        let response_content = ResponseContent::GetCloseGroup { close_group_ids: public_ids };

        let response_msg = ResponseMessage {
            src: Authority::NaeManager(dst_name),
            dst: src,
            content: response_content,
        };

        let routing_message = RoutingMessage::Response(response_msg);

        let signed_message = try!(SignedMessage::new(routing_message, &self.full_id));

        self.send(signed_message)
    }

    // Received by A; From Y -> A, or from any node close to one of the sender's bucket addresses.
    fn handle_get_close_group_response(&mut self,
                                       close_group_ids: Vec<PublicId>,
                                       dst: Authority)
                                       -> Result<(), RoutingError> {
        if self.state == State::Client {
            match dst {
                Authority::Client { .. } => (),
                _ => return Err(RoutingError::BadAuthority),
            }
            self.start_listening();
        } else {
            match dst {
                Authority::ManagedNode(..) => (),
                _ => return Err(RoutingError::BadAuthority),
            }
        }

        // From A -> Each in Y
        for peer_id in close_group_ids {
            if self.node_id_cache.insert(*peer_id.name(), peer_id.clone()).is_none() &&
               self.routing_table.allow_connection(peer_id.name()) {
                try!(self.send_endpoints(peer_id.clone(),
                                         dst.clone(),
                                         Authority::ManagedNode(*peer_id.name())));
            }
        }

        Ok(())
    }

    fn send_endpoints(&mut self,
                      their_public_id: PublicId,
                      src: Authority,
                      dst: Authority)
                      -> Result<(), RoutingError> {
        trace!("{:?} sending endpoints {:?}",
               self,
               self.acceptors.endpoints());
        let encoded_endpoints = try!(serialisation::serialise(&self.acceptors.endpoints()));
        let nonce = box_::gen_nonce();
        let encrypted_endpoints = box_::seal(&encoded_endpoints,
                                             &nonce,
                                             their_public_id.encrypting_public_key(),
                                             self.full_id.encrypting_private_key());

        let request_content = RequestContent::Endpoints {
            encrypted_endpoints: encrypted_endpoints,
            nonce_bytes: nonce.0,
        };

        let request_msg = RequestMessage {
            src: src,
            dst: dst,
            content: request_content,
        };

        let routing_msg = RoutingMessage::Request(request_msg);

        let signed_msg = try!(SignedMessage::new(routing_msg, &self.full_id));

        self.send(signed_msg)
    }

    fn handle_endpoints_from_client(&mut self,
                                    encrypted_endpoints: Vec<u8>,
                                    nonce_bytes: [u8; box_::NONCEBYTES],
                                    client_key: sign::PublicKey,
                                    proxy_name: XorName,
                                    dst_name: XorName)
                                    -> Result<(), RoutingError> {
        match self.node_id_cache
                  .retrieve_all()
                  .iter()
                  .find(|elt| *elt.1.signing_public_key() == client_key) {
            Some(&(ref name, ref their_public_id)) => {
                try!(self.check_address_for_routing_table(&name));
                try!(self.connect(encrypted_endpoints,
                                  nonce_bytes,
                                  their_public_id.encrypting_public_key()));
                self.send_endpoints(their_public_id.clone(),
                                    Authority::ManagedNode(dst_name),
                                    Authority::Client {
                                        client_key: client_key,
                                        proxy_node_name: proxy_name,
                                    })
            }
            None => Err(RoutingError::RejectedPublicId),
        }
    }

    fn handle_endpoints_from_node(&mut self,
                                  encrypted_endpoints: Vec<u8>,
                                  nonce_bytes: [u8; box_::NONCEBYTES],
                                  src_name: XorName,
                                  dst: Authority)
                                  -> Result<(), RoutingError> {
        if let Err(err) = self.check_address_for_routing_table(&src_name) {
            let _ = self.node_id_cache.remove(&src_name);
            return Err(err);
        }
        if let Some(their_public_id) = self.node_id_cache.get(&src_name).cloned() {
            self.connect(encrypted_endpoints,
                         nonce_bytes,
                         their_public_id.encrypting_public_key())
        } else {
            let request_content = RequestContent::GetPublicIdWithEndpoints {
                encrypted_endpoints: encrypted_endpoints,
                nonce_bytes: nonce_bytes,
            };

            let request_msg = RequestMessage {
                src: dst,
                dst: Authority::ManagedNode(src_name),
                content: request_content,
            };

            let routing_msg = RoutingMessage::Request(request_msg);

            let signed_message = try!(SignedMessage::new(routing_msg, &self.full_id));

            self.send(signed_message)
        }
    }

    // ---- Connect Requests and Responses --------------------------------------------------------

    fn send_connect_request(&mut self, dst_name: &XorName) -> Result<(), RoutingError> {
        let request_content = RequestContent::Connect;

        let request_msg = RequestMessage {
            src: Authority::ManagedNode(self.name().clone()),
            dst: Authority::ManagedNode(*dst_name),
            content: request_content,
        };

        let routing_msg = RoutingMessage::Request(request_msg);

        let signed_msg = try!(SignedMessage::new(routing_msg, &self.full_id));

        self.send(signed_msg)
    }

    fn handle_connect_request(&mut self,
                              src_name: XorName,
                              dst_name: XorName)
                              -> Result<(), RoutingError> {
        try!(self.check_address_for_routing_table(&src_name));

        let our_name = self.name().clone();
        if let Some(public_id) = self.node_id_cache.get(&src_name).cloned() {
            try!(self.send_endpoints(public_id,
                                     Authority::ManagedNode(our_name),
                                     Authority::ManagedNode(src_name)));
            return Ok(());
        }

        let request_content = RequestContent::GetPublicId;

        let request_msg = RequestMessage {
            src: Authority::ManagedNode(dst_name),
            dst: Authority::NodeManager(src_name),
            content: request_content,
        };

        let routing_msg = RoutingMessage::Request(request_msg);

        let signed_msg = try!(SignedMessage::new(routing_msg, &self.full_id));

        self.send(signed_msg)
    }

    fn handle_get_public_id(&mut self,
                            src_name: XorName,
                            dst_name: XorName)
                            -> Result<(), RoutingError> {
        if let Some(node_info) = self.routing_table
                                     .our_close_group()
                                     .into_iter()
                                     .find(|elt| *elt.name() == dst_name) {
            let response_content = ResponseContent::GetPublicId { public_id: node_info.public_id };

            let response_msg = ResponseMessage {
                src: Authority::NodeManager(dst_name),
                dst: Authority::ManagedNode(src_name),
                content: response_content,
            };

            let routing_msg = RoutingMessage::Response(response_msg);

            let signed_msg = try!(SignedMessage::new(routing_msg, &self.full_id));

            self.send(signed_msg)
        } else {
            Err(RoutingError::RejectedPublicId)
        }
    }

    fn handle_get_public_id_response(&mut self,
                                     public_id: PublicId,
                                     dst_name: XorName)
                                     -> Result<(), RoutingError> {
        try!(self.check_address_for_routing_table(public_id.name()));

        try!(self.send_endpoints(public_id.clone(),
                                 Authority::ManagedNode(dst_name),
                                 Authority::ManagedNode(public_id.name().clone())));
        let _ = self.node_id_cache.insert(public_id.name().clone(), public_id);

        Ok(())
    }

    fn handle_get_public_id_with_endpoints(&mut self,
                                           encrypted_endpoints: Vec<u8>,
                                           nonce_bytes: [u8; box_::NONCEBYTES],
                                           src_name: XorName,
                                           dst_name: XorName)
                                           -> Result<(), RoutingError> {
        if let Some(node_info) = self.routing_table
                                     .our_close_group()
                                     .into_iter()
                                     .find(|elt| *elt.name() == dst_name) {
            let response_content = ResponseContent::GetPublicIdWithEndpoints {
                public_id: node_info.public_id,
                encrypted_endpoints: encrypted_endpoints,
                nonce_bytes: nonce_bytes,
            };

            let response_msg = ResponseMessage {
                src: Authority::NodeManager(dst_name),
                dst: Authority::ManagedNode(src_name),
                content: response_content,
            };

            let routing_msg = RoutingMessage::Response(response_msg);

            let signed_msg = try!(SignedMessage::new(routing_msg, &self.full_id));

            self.send(signed_msg)
        } else {
            Err(RoutingError::RejectedPublicId)
        }
    }

    fn handle_get_public_id_with_endpoints_response(&mut self,
                                                    public_id: PublicId,
                                                    encrypted_endpoints: Vec<u8>,
                                                    nonce_bytes: [u8; box_::NONCEBYTES],
                                                    dst_name: XorName)
                                                    -> Result<(), RoutingError> {
        try!(self.check_address_for_routing_table(public_id.name()));

        try!(self.send_endpoints(public_id.clone(),
                                 Authority::ManagedNode(dst_name),
                                 Authority::ManagedNode(public_id.name().clone())));
        let _ = self.node_id_cache.insert(public_id.name().clone(), public_id.clone());

        self.connect(encrypted_endpoints,
                     nonce_bytes,
                     public_id.encrypting_public_key())
    }

    fn connect(&mut self,
               encrypted_endpoints: Vec<u8>,
               nonce_bytes: [u8; box_::NONCEBYTES],
               their_public_key: &box_::PublicKey)
               -> Result<(), RoutingError> {
        let decipher_result = box_::open(&encrypted_endpoints,
                                         &box_::Nonce(nonce_bytes),
                                         their_public_key,
                                         self.full_id.encrypting_private_key());

        let serialised_endpoints = try!(decipher_result.map_err(|()| {
            RoutingError::AsymmetricDecryptionFailure
        }));
        let endpoints = try!(serialisation::deserialise(&serialised_endpoints));

        self.crust_service.connect(0u32, endpoints);

        Ok(())
    }

    // ----- Send Functions -----------------------------------------------------------------------

    fn send_message(&mut self, routing_msg: RoutingMessage) -> Result<(), RoutingError> {
        // TODO crust should return the routing msg when it detects an interface error
        let signed_msg = try!(SignedMessage::new(routing_msg.clone(), &self.full_id));

        self.send(signed_msg)
    }

    fn relay_to_client(&mut self,
                       signed_msg: SignedMessage,
                       client_key: &sign::PublicKey)
                       -> Result<(), RoutingError> {
        if let Some(&(connection, _)) = self.client_map.get(client_key) {
            let hop_msg = try!(HopMessage::new(signed_msg,
                                               self.name().clone(),
                                               self.full_id.signing_private_key()));
            let message = Message::HopMessage(hop_msg);
            let raw_bytes = try!(serialisation::serialise(&message));

            return Ok(self.crust_service.send(connection.clone(), raw_bytes));
        }

        Err(RoutingError::ClientConnectionNotFound)
    }

    fn send(&mut self, signed_msg: SignedMessage) -> Result<(), RoutingError> {
        let hop_msg = try!(HopMessage::new(signed_msg.clone(),
                                           self.name().clone(),
                                           self.full_id.signing_private_key()));
        let message = Message::HopMessage(hop_msg);
        let raw_bytes = try!(serialisation::serialise(&message));

        // If we're a client going to be a node, send via our bootstrap connection.
        if self.state == State::Client {
            if let Authority::Client { ref proxy_node_name, .. } = *signed_msg.content().src() {
                if let Some((connection, _)) = self.proxy_map
                                                   .iter()
                                                   .find(|elt| elt.1.name() == proxy_node_name) {
                    return Ok(self.crust_service.send(connection.clone(), raw_bytes));
                }

                error!("{:?} Unable to find connection to proxy node in proxy map",
                       self);
                return Err(RoutingError::ProxyConnectionNotFound);
            }

            error!("{:?} Source should be client if our state is a Client",
                   self);
            return Err(RoutingError::InvalidSource);
        }

        let hop_type = if signed_msg.content().src().name() == self.routing_table.our_name() {
            HopType::OriginalSender
        } else {
            HopType::CopyNum(0) // TODO: Count copies!
        };
        let destination = signed_msg.content().dst().to_destination();
        let targets = self.routing_table.target_nodes(destination, hop_type);
        targets.iter().foreach(|node_info| {
            if let Some(connection) = node_info.connections.iter().next() {
                self.crust_service.send(connection.clone(), raw_bytes.clone());
            }
        });

        // If we need to handle this message, handle it.
        let hop_name = self.name().clone();
        if self.routing_table.is_close(signed_msg.content().dst().name()) &&
           self.signed_message_filter.insert(&signed_msg) == 0 {
            return self.handle_signed_message_for_node(&signed_msg, &hop_name);
        }

        Ok(())
    }

    fn get_client_authority(&self) -> Result<Authority, RoutingError> {
        match self.proxy_map.iter().next() {
            Some((ref _connection, ref bootstrap_pub_id)) => {
                Ok(Authority::Client {
                    client_key: *self.full_id.public_id().signing_public_key(),
                    proxy_node_name: bootstrap_pub_id.name().clone(),
                })
            }
            None => Err(RoutingError::NotBootstrapped),
        }
    }

    // set our network name while transitioning to a node
    // If called more than once with a unique name, this function will assert
    fn set_self_node_name(&mut self, new_name: XorName) {
        // Validating this function doesn't run more that once
        assert!(XorName(hash::sha512::hash(&self.full_id.public_id().signing_public_key().0).0) !=
                new_name);

        self.routing_table = RoutingTable::new(&new_name);
        self.full_id.public_id_mut().set_name(new_name);
    }

    fn dropped_client_connection(&mut self, connection: &crust::Connection) {
        if let Some(public_key) = self.client_map
                                      .iter()
                                      .find(|entry| (entry.1).0 == *connection)
                                      .map(|entry| entry.0.clone()) {
            if let Some((_, false)) = self.client_map.remove(&public_key) {
                trace!("Joining node dropped. {} remaining.",
                       self.joining_nodes_num());
            }
        }
    }

    fn dropped_bootstrap_connection(&mut self, connection: &crust::Connection) {
        let _ = self.proxy_map.remove(connection);
    }

    fn dropped_routing_node_connection(&mut self, connection: &crust::Connection) {
        if let Some(DroppedNodeDetails { name, incomplete_bucket, common_groups }) =
               self.routing_table.drop_connection(connection) {
            if common_groups {
                // If the lost node shared some close group with us, send Churn.
                let event = Event::NodeLost(name.clone());
                if let Err(err) = self.event_sender.send(event) {
                    error!("Error sending event to routing user - {:?}", err);
                }
            }
            if let Some(bucket_index) = incomplete_bucket {
                if let Err(e) = self.request_bucket_ids(bucket_index) {
                    trace!("Failed to request replacement endpoints from bucket {}: {:?}.",
                           bucket_index,
                           e);
                }
            }
        }
    }

    /// Checks whether the given `name` is allowed to be added to our routing table or is already
    /// there. If not, returns an error.
    fn check_address_for_routing_table(&self, name: &XorName) -> Result<(), RoutingError> {
        if self.routing_table.allow_connection(name) {
            Ok(())
        } else {
            Err(RoutingError::RefusedFromRoutingTable)
        }
    }

    fn close_group_names(&self) -> Vec<XorName> {
        self.routing_table
            .our_close_group()
            .iter()
            .map(|node_info| node_info.public_id.name().clone())
            .collect_vec()
    }

    /// Returns the `XorName` of this node.
    fn name(&self) -> &XorName {
        self.full_id.public_id().name()
    }
}

impl Debug for Core {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{:?}({:?}) - ", self.state, self.name())
    }
}
