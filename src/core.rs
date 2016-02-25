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

#[cfg(not(feature = "use-mock-crust"))]
use crust::{self, ConnectionInfoResult, OurConnectionInfo, PeerId, Service, TheirConnectionInfo};

#[cfg(feature = "use-mock-crust")]
use crust_mock::crust::{self, ConnectionInfoResult, OurConnectionInfo, PeerId, Service, TheirConnectionInfo};

use itertools::Itertools;
use kademlia_routing_table::{AddedNodeDetails, ContactInfo, DroppedNodeDetails, GROUP_SIZE,
                             PARALLELISM, RoutingTable};
use lru_time_cache::LruCache;
use maidsafe_utilities::event_sender::MaidSafeEventCategory;
use maidsafe_utilities::serialisation;
use maidsafe_utilities::thread::RaiiThreadJoiner;
use message_filter::MessageFilter;
use rand;
use sodiumoxide::crypto::{box_, hash, sign};
use std::io;
use std::collections::HashMap;
use std::fmt;
use std::fmt::{Debug, Formatter};
use std::sync::mpsc;
use std::thread;
use time::{Duration, PreciseTime};
use xor_name;
use xor_name::XorName;

use action::Action;
use authority::Authority;
use data::{Data, DataRequest};
use error::{RoutingError, InterfaceError};
use event::Event;
use id::{FullId, PublicId};
use timer::Timer;
use types::RoutingActionSender;
use messages::{DirectMessage, HopMessage, Message, RequestContent, RequestMessage,
               ResponseContent, ResponseMessage, RoutingMessage, SignedMessage};
use utils;

type StdDuration = ::std::time::Duration;

const CRUST_DEFAULT_BEACON_PORT: u16 = 5484;
// const CRUST_DEFAULT_TCP_ACCEPTING_PORT: u16 = 5483;
// const CRUST_DEFAULT_UTP_ACCEPTING_PORT: u16 = 5483;

/// The maximum number of other nodes that can be in the bootstrap process with us as the proxy at
/// the same time.
const MAX_JOINING_NODES: usize = 1;

/// Time (in seconds) after which a joining node will get dropped from the map
/// of joining nodes.
const JOINING_NODE_TIMEOUT_SECS: i64 = 20;

/// Time (in seconds) after which bootstrap is cancelled (and possibly retried).
const BOOTSTRAP_TIMEOUT_SECS: u64 = 20;

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

/// Info about nodes in the routing table.
#[derive(Copy, Clone, Eq, PartialEq)]
struct NodeInfo {
    public_id: PublicId,
    peer_id: PeerId,
}

impl NodeInfo {
    fn new(public_id: PublicId, peer_id: PeerId) -> Self {
        NodeInfo {
            public_id: public_id,
            peer_id: peer_id,
        }
    }
}

impl ContactInfo for NodeInfo {
    fn name(&self) -> &XorName {
        self.public_id.name()
    }
}

/// Info about client a proxy kept in a proxy node.
struct ClientInfo {
    peer_id: PeerId,
    client_restriction: bool,
    timestamp: PreciseTime,
}

impl ClientInfo {
    fn new(peer_id: PeerId, client_restriction: bool) -> Self {
        ClientInfo {
            peer_id: peer_id,
            client_restriction: client_restriction,
            timestamp: PreciseTime::now(),
        }
    }

    fn is_stale(&self) -> bool {
        !self.client_restriction &&
        self.timestamp.to(PreciseTime::now()) > Duration::seconds(JOINING_NODE_TIMEOUT_SECS)
    }
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
/// To the `ManagedNode` for each public ID it receives from members of Y, A sends its `ConnectionInfo`.
/// It also caches the ID.
///
/// For each `ConnectionInfo` that a node Z receives from A, it decides whether it wants A in its routing
/// table. If yes, and if A's ID is in its ID cache, Z sends its own `ConnectionInfo` back to A and also
/// attempts to connect to A via Crust. A does the same, once it receives the `ConnectionInfo`.
///
/// Once the connection between A and Z is established and a Crust `OnConnect` event is raised,
/// they exchange `NodeIdentify` messages and add each other to their routing tables. When A
/// receives its first `NodeIdentify`, it finally moves to the `Node` state.
pub struct Core {
    // for CRUST
    crust_service: Service,
    // for Core
    client_restriction: bool,
    is_listening: bool,
    crust_rx: mpsc::Receiver<crust::Event>,
    action_rx: mpsc::Receiver<Action>,
    event_sender: mpsc::Sender<Event>,
    crust_sender: crust::CrustEventSender,
    timer: Timer,
    signed_message_filter: MessageFilter<SignedMessage>,
    bucket_filter: MessageFilter<usize>,
    node_id_cache: LruCache<XorName, PublicId>,
    message_accumulator: Accumulator<RoutingMessage, sign::PublicKey>,
    // Group messages which have been accumulated and then actioned
    grp_msg_filter: MessageFilter<RoutingMessage>,
    full_id: FullId,
    state: State,
    routing_table: RoutingTable<NodeInfo>,

    // nodes we are trying to bootstrap against
    proxy_candidates: Vec<(PeerId, u64)>,

    // our bootstrap connections
    proxy_map: HashMap<PeerId, PublicId>,
    // any clients we have proxying through us, and whether they have `client_restriction`
    client_map: HashMap<sign::PublicKey, ClientInfo>,
    data_cache: LruCache<XorName, Data>,
    // TODO(afck): Move these three fields into their own struct.
    connection_token_map: LruCache<u32, (PublicId, Authority, Authority)>,
    our_connection_info_map: LruCache<PublicId, OurConnectionInfo>,
    their_connection_info_map: LruCache<PublicId, TheirConnectionInfo>,
    get_request_count: usize,
}

#[cfg_attr(feature="clippy", allow(new_ret_no_self))] // TODO: Maybe rename `new` to `start`?
impl Core {
    /// A Core instance for a client or node with the given id. Sends events to upper layer via the mpsc sender passed
    /// in.
    pub fn new(event_sender: mpsc::Sender<Event>,
               client_restriction: bool,
               keys: Option<FullId>)
        -> Result<(RoutingActionSender, RaiiThreadJoiner), RoutingError>
    {
        let (crust_tx, crust_rx) = mpsc::channel();
        let (action_tx, action_rx) = mpsc::channel();
        let (category_tx, category_rx) = mpsc::channel();

        let routing_event_category = MaidSafeEventCategory::Routing;
        let action_sender = RoutingActionSender::new(action_tx,
                                                     routing_event_category,
                                                     category_tx.clone());
        let action_sender2 = action_sender.clone();

        let crust_event_category = MaidSafeEventCategory::Crust;
        let crust_sender = crust::CrustEventSender::new(crust_tx,
                                                        crust_event_category,
                                                        category_tx);

        // TODO(afck): Add the listening port to the Service constructor.
        let crust_service = match Service::new(crust_sender.clone(), CRUST_DEFAULT_BEACON_PORT) {
            Ok(service) => service,
            Err(what) => panic!(format!("Unable to start crust::Service {:?}", what)),
        };

        let full_id = match keys {
            Some(full_id) => full_id,
            None => FullId::new(),
        };

        let our_info = NodeInfo::new(*full_id.public_id(), crust_service.id());

        let joiner = thread!("RoutingThread", move || {
            let mut core = Core {
                crust_service: crust_service,
                client_restriction: client_restriction,
                is_listening: false,
                crust_rx: crust_rx,
                action_rx: action_rx,
                event_sender: event_sender,
                crust_sender: crust_sender,
                timer: Timer::new(action_sender2),
                signed_message_filter: MessageFilter::with_expiry_duration(Duration::minutes(20)),
                // TODO Needs further discussion on interval
                bucket_filter: MessageFilter::with_expiry_duration(Duration::seconds(20)),
                node_id_cache: LruCache::with_expiry_duration(Duration::minutes(10)),
                message_accumulator: Accumulator::with_duration(1, Duration::minutes(5)),
                grp_msg_filter: MessageFilter::with_expiry_duration(Duration::minutes(20)),
                full_id: full_id,
                state: State::Disconnected,
                routing_table: RoutingTable::new(our_info),
                proxy_candidates: Vec::new(),
                proxy_map: HashMap::new(),
                client_map: HashMap::new(),
                data_cache: LruCache::with_expiry_duration(Duration::minutes(10)),
                connection_token_map: LruCache::with_expiry_duration(Duration::minutes(5)),
                our_connection_info_map: LruCache::with_expiry_duration(Duration::minutes(5)),
                their_connection_info_map: LruCache::with_expiry_duration(Duration::minutes(5)),
                get_request_count: 0,
            };

            core.run(category_rx);
        });

        Ok((action_sender, RaiiThreadJoiner::new(joiner)))
    }

    /// Run the event loop for sending and receiving messages.
    pub fn run(&mut self, category_rx: mpsc::Receiver<MaidSafeEventCategory>) {
        let mut cur_routing_table_size = 0;
        let mut cur_client_num = 0;
        let mut cumulative_client_num = 0;
        for it in category_rx.iter() {
            match it {
                MaidSafeEventCategory::Routing => {
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

                                                match self.send_request(request_msg) {
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
                            Action::CloseGroup { name, result_tx, } => {
                                let close_group = self.routing_table
                                                      .close_nodes(&name)
                                                      .map(|infos| {
                                                          infos.iter()
                                                               .map(NodeInfo::name)
                                                               .cloned()
                                                               .collect()
                                                      });

                                if result_tx.send(close_group).is_err() {
                                    return;
                                }
                            }

                            Action::Name { result_tx, } => {
                                if result_tx.send(*self.name()).is_err() {
                                    return;
                                }
                            }

                            Action::Timeout(token) => self.handle_timeout(token),

                            Action::Terminate => {
                                break;
                            }
                        }
                    }
                }
                MaidSafeEventCategory::Crust => {
                    if let Ok(crust_event) = self.crust_rx.try_recv() {
                        self.handle_crust_event(crust_event);
                    }
                }
            } // Category Match

            if self.state == State::Node {
                let old_client_num = cur_client_num;
                cur_client_num = self.client_map.len() - self.joining_nodes_num();
                if cur_client_num != old_client_num {
                    if cur_client_num > old_client_num {
                        cumulative_client_num += cur_client_num - old_client_num;
                    }
                    trace!("{:?} - Connected clients: {}, cumulative: {}",
                           self,
                           cur_client_num,
                           cumulative_client_num);
                }
            }
            if self.state == State::Node && cur_routing_table_size != self.routing_table.len() {
                cur_routing_table_size = self.routing_table.len();

                trace!(" ---------------------------------------");
                trace!("| {:?} - Routing Table size: {:3} |",
                       self,
                       self.routing_table.len());
                // self.routing_table.our_close_group().iter().all(|elt| {
                //     trace!("Name: {:?} Connections {:?}  -- {:?}",
                //            elt.public_id.name(),
                //            elt.connections.len(),
                //            elt.connections);
                //     true
                // });
                trace!(" ---------------------------------------");
            }
        } // Category Rx
    }

    fn handle_crust_event(&mut self, crust_event: crust::Event) {
        match crust_event {
            crust::Event::BootstrapFinished => self.handle_bootstrap_finished(),
            crust::Event::BootstrapConnect(peer_id) => self.handle_bootstrap_connect(peer_id),
            crust::Event::BootstrapAccept(peer_id) => self.handle_bootstrap_accept(peer_id),
            crust::Event::NewPeer(result, peer_id) => self.handle_new_peer(result, peer_id),
            crust::Event::LostPeer(peer_id) => self.handle_lost_peer(peer_id),
            crust::Event::NewMessage(peer_id, bytes) => {
                match self.handle_new_message(peer_id, bytes) {
                    Err(RoutingError::FilterCheckFailed) | Ok(_) => (),
                    Err(err) => error!("{:?} - {:?}", self, err),
                }
            }
            crust::Event::ConnectionInfoPrepared(ConnectionInfoResult {
                result_token,
                result,
            }) => {
                self.handle_connection_info_prepared(result_token, result);
            }
        }
    }

    fn handle_bootstrap_connect(&mut self, peer_id: PeerId) {
        self.crust_service.stop_bootstrap();
        if self.state == State::Disconnected {
            trace!("Received BootstrapConnect from {:?}.", peer_id);
            // Established connection. Pending Validity checks
            self.state = State::Bootstrapping;
            let _ = self.client_identify(peer_id);
            return;
        } else {
            warn!("Got more than one bootstrap connection. Disconnecting {:?}.", peer_id);
            self.crust_service.disconnect(&peer_id);
        }
    }

    fn handle_bootstrap_accept(&mut self, peer_id: PeerId) {
        trace!("{:?} Received BootstrapAccept from {:?}.", self, peer_id);
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
            trace!("{:?} - Started a new network as a seed node.", self)
        }
        // TODO: Keep track of that peer to make sure we receive a message from them.
    }

    fn handle_new_peer(&mut self, result: io::Result<()>, peer_id: PeerId) {
        if self.client_restriction {
            warn!("{:?} Received NewPeer event as a client.", self);
        } else {
            match result {
                Ok(()) => {
                    // TODO(afck): Keep track of this connection: Disconnect if we don't receive a
                    // NodeIdentify.
                    // TODO(afck): Make sure it cannot happen that we receive their NodeIdentify
                    // _before_ the NewPeer event.
                    if let Some(node) = self.routing_table.find(|node| node.peer_id == peer_id) {
                        warn!("Received NewPeer from {:?}, but node {:?} is already in our \
                              routing table.",
                              peer_id,
                              node.name());
                        return;
                    }
                    trace!("Received NewPeer with Ok from {:?}. Sending NodeIdentify.",
                           peer_id);
                    let _ = self.node_identify(peer_id);
                }
                Err(err) => {
                    error!("{:?} Failed to connect to peer {:?}: {:?}", self, peer_id, err);
                }
            }
        }
    }

    fn handle_connection_info_prepared(&mut self,
                                       result_token: u32,
                                       result: io::Result<OurConnectionInfo>) {
        let our_connection_info = match result {
            Err(err) => {
                error!("{:?} Failed to prepare connection info: {:?}", self, err);
                return;
            }
            Ok(connection_info) => connection_info,
        };
        let encoded_connection_info =
            match serialisation::serialise(&our_connection_info.to_their_connection_info()) {
                Err(err) => {
                    error!("Failed to serialise connection info: {:?}", err);
                    return;
                }
                Ok(encoded_connection_info) => encoded_connection_info,
            };
        let (their_public_id, src, dst) = if let Some(entry) = self.connection_token_map
                                                                   .get(&result_token) {
            entry.clone()
        } else {
            error!("Prepared connection info, but no entry found in token map.");
            return;
        };
        let nonce = box_::gen_nonce();
        let encrypted_connection_info = box_::seal(&encoded_connection_info,
                                                   &nonce,
                                                   their_public_id.encrypting_public_key(),
                                                   self.full_id.encrypting_private_key());

        if let Some(their_connection_info) = self.their_connection_info_map
                                                 .remove(&their_public_id) {
            trace!("Trying to connect to {:?}.", their_public_id.name());
            self.crust_service.connect(our_connection_info, their_connection_info);
        } else {
            let _ = self.our_connection_info_map.insert(their_public_id, our_connection_info);
        }

        let request_content = RequestContent::ConnectionInfo {
            encrypted_connection_info: encrypted_connection_info,
            nonce_bytes: nonce.0,
        };

        let request_msg = RequestMessage {
            src: src,
            dst: dst,
            content: request_content,
        };

        if let Err(err) = self.send_request(request_msg) {
            error!("Failed to send connection info: {:?}.", err);
        }
    }

    fn handle_new_message(&mut self, peer_id: PeerId, bytes: Vec<u8>) -> Result<(), RoutingError> {
        match serialisation::deserialise(&bytes) {
            Ok(Message::Hop(ref hop_msg)) => self.handle_hop_message(hop_msg, peer_id),
            Ok(Message::Direct(direct_msg)) => self.handle_direct_message(direct_msg, peer_id),
            Err(error) => Err(RoutingError::SerialisationError(error)),
        }
    }

    fn handle_hop_message(&mut self,
                          hop_msg: &HopMessage,
                          peer_id: PeerId)
                          -> Result<(), RoutingError> {
        if self.state == State::Node {
            let mut relayed_get_request = false;
            if let Some(info) = self.routing_table.get(hop_msg.name()) {
                try!(hop_msg.verify(info.public_id.signing_public_key()));
                // try!(self.check_direction(hop_msg));
            } else if let Some((pub_key, client_info)) = self.client_by_peer_id(&peer_id) {
                try!(hop_msg.verify(pub_key));
                if client_info.client_restriction {
                    try!(self.check_not_get_network_name(hop_msg.content().content()));
                }
                if let RoutingMessage::Request(RequestMessage {
                    content: RequestContent::Get(_, _),
                    ..
                }) = *hop_msg.content().content() {
                    relayed_get_request = true;
                }
            } else if let Some(pub_id) = self.proxy_map.get(&peer_id) {
                try!(hop_msg.verify(pub_id.signing_public_key()));
            } else {
                // TODO: Drop peer?
                // error!("Received hop message from unknown name {:?}. Dropping peer {:?}.",
                //        hop_msg.name(),
                //        peer_id);
                // self.crust_service.disconnect(&peer_id);
                return Err(RoutingError::UnknownConnection(*hop_msg.name()));
            }
            if relayed_get_request {
                self.get_request_count += 1;
                trace!("Total get request count: {}", self.get_request_count);
            }
        } else if self.state == State::Client {
            if let Some(pub_id) = self.proxy_map.get(&peer_id) {
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

    // TODO(afck): Direction checks are currently expected to fail in a lot of cases. To enable
    // them again, every node would need to keep track of those routing table entries which are not
    // yet fully connected. Only messages from nodes that have populated their routing tables
    // enough to satisfy the kademlia_routing_table invariant can be expected to pass direction
    // checks.
    /// Returns an error if this is not a swarm message and was not sent in the right direction.
    fn _check_direction(&self, hop_msg: &HopMessage) -> Result<(), RoutingError> {
        let dst = hop_msg.content().content().dst();
        if self._is_swarm(dst, hop_msg.name()) ||
           !xor_name::closer_to_target(&hop_msg.name(), self.name(), dst.name()) {
            Ok(())
        } else {
            trace!("Direction check failed in hop message from node {:?}: {:?}",
                   hop_msg.name(),
                   hop_msg.content().content());
            // TODO: Reconsider direction checks once we know whether they help secure routing.
            Ok(())
            // Err(RoutingError::DirectionCheckFailed)
        }
    }

    /// Returns `true` if a message is a swarm message.
    ///
    /// This is the case if a routing node in the destination's close group sent this message.
    fn _is_swarm(&self, dst: &Authority, hop_name: &XorName) -> bool {
        dst.is_group() &&
        match self.routing_table.other_close_nodes(dst.name()) {
            None => false,
            Some(close_group) => close_group.into_iter().any(|n| n.name() == hop_name),
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
        if self.signed_message_filter.insert(signed_msg) > PARALLELISM {
            return Err(RoutingError::FilterCheckFailed);
        }

        // Since endpoint request / GetCloseGroup response messages while relocating are sent
        // to a client we still need to accept these msgs sent to us even if we have become a node.
        if let Authority::Client { ref client_key, .. } = *signed_msg.content().dst() {
            if client_key == self.full_id.public_id().signing_public_key() {
                match *signed_msg.content() {
                    RoutingMessage::Request(RequestMessage {
                        content: RequestContent::ConnectionInfo { .. },
                        ..
                    }) |
                    RoutingMessage::Response(ResponseMessage {
                        content: ResponseContent::GetCloseGroup { .. },
                        ..
                    }) => return self.handle_signed_message_for_client(&signed_msg),
                    _ => (),
                }
            }
        }

        match self.state {
            State::Node => self.handle_signed_message_for_node(signed_msg, hop_name, true),
            State::Client => self.handle_signed_message_for_client(signed_msg),
            _ => Err(RoutingError::InvalidStateForOperation),
        }
    }

    fn handle_signed_message_for_node(&mut self,
                                      signed_msg: &SignedMessage,
                                      hop_name: &XorName,
                                      relay: bool)
                                      -> Result<(), RoutingError> {
        let dst = signed_msg.content().dst();

        try!(self.harvest_node(signed_msg.public_id().name(), &signed_msg.content()));

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
            return self.send_message(routing_msg);
        }
        self.add_to_cache(signed_msg.content());

        if relay {
            try!(self.send(signed_msg.clone(), hop_name, false));
        }
        if self.signed_message_filter.count(signed_msg) == 0 &&
           self.routing_table.is_recipient(dst.to_destination()) {
            self.handle_routing_message(signed_msg.content().clone(), *signed_msg.public_id())
        } else {
            Ok(())
        }
    }

    /// Checks if the given name is missing from our routing table. If so, tries to refill the
    /// bucket.
    fn harvest_node(&mut self,
                    name: &XorName,
                    routing_msg: &RoutingMessage)
                    -> Result<(), RoutingError> {
        match *routing_msg {
            RoutingMessage::Response(ResponseMessage { content: ResponseContent::GetSuccess(..), .. }) => {
                let i = self.name().bucket_index(name);
                if self.bucket_filter.insert(&i) == 0 && self.routing_table.need_to_add(name) {
                    trace!("Harvesting on {:?} in bucket index {}.", name, i);
                    self.request_bucket_ids(i)
                } else {
                    Ok(())
                }
            }
            _ => Ok(()),
        }
    }

    fn handle_signed_message_for_client(&mut self,
                                        signed_msg: &SignedMessage)
                                        -> Result<(), RoutingError> {
        if self.signed_message_filter.count(signed_msg) > 1 {
            return Err(RoutingError::FilterCheckFailed);
        }
        match *signed_msg.content().dst() {
            Authority::Client { ref client_key, .. } => {
                if self.full_id.public_id().signing_public_key() != client_key {
                    return Err(RoutingError::BadAuthority);
                }
            }
            _ => return Err(RoutingError::BadAuthority),
        }
        self.handle_routing_message(signed_msg.content().clone(), *signed_msg.public_id())
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
                    content: RequestContent::Get(DataRequest::Immutable(ref name, _), id),
                    ..
                }) => {
                match self.data_cache.get(&name) {
                    Some(data) => ResponseContent::GetSuccess(data.clone(), id),
                    _ => return None,
                }
            }
            _ => return None,
        };

        let response_msg = ResponseMessage {
            src: Authority::ManagedNode(*self.name()),
            dst: routing_msg.src().clone(),
            content: content,
        };

        Some(RoutingMessage::Response(response_msg))
    }

    fn add_to_cache(&mut self, routing_msg: &RoutingMessage) {
        if let RoutingMessage::Response(ResponseMessage {
                    content: ResponseContent::GetSuccess(ref data @ Data::Immutable(_), _),
                    ..
                }) = *routing_msg {
            let _ = self.data_cache.insert(data.name(), data.clone());
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
            // TODO(afck): Currently we don't accumulate GetCloseGroup responses, because while a
            // node is joining, the responses can disagree. Some of the group members might already
            // have the new node in their routing table and others might not. To resolve this, we
            // will need a cleaner algorithm for joining nodes: They should connect to all their
            // future routing table entries, and once these connections are established, send a
            // direct message to these contacts. Only when they receive that message, the contacts
            // should add the new node to their routing tables in turn, because only then it can
            // act as a fully functioning routing node.
            if let RoutingMessage::Response(ResponseMessage {
                    content: ResponseContent::GetCloseGroup { .. }, ..
            }) = routing_msg {
                ()
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
               .add(message.clone(), *public_id.signing_public_key())
               .is_some() {
            Some(message)
        } else {
            None
        }
    }

    fn handle_request_message(&mut self, request_msg: RequestMessage) -> Result<(), RoutingError> {
        let msg_content = request_msg.content.clone();
        let msg_src = request_msg.src.clone();
        let msg_dst = request_msg.dst.clone();
        trace!("{:?} Got request {:?} from {:?} to {:?}.",
               self,
               msg_content,
               msg_src,
               msg_dst);
        match (msg_content, msg_src, msg_dst) {
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
            (RequestContent::ConnectionInfo { encrypted_connection_info, nonce_bytes },
             Authority::Client { client_key, proxy_node_name, },
             Authority::ManagedNode(dst_name)) => {
                self.handle_connection_info_from_client(encrypted_connection_info,
                                                        nonce_bytes,
                                                        client_key,
                                                        proxy_node_name,
                                                        dst_name)
            }
            (RequestContent::ConnectionInfo { encrypted_connection_info, nonce_bytes },
             Authority::ManagedNode(src_name),
             Authority::Client { .. }) |
            (RequestContent::ConnectionInfo { encrypted_connection_info, nonce_bytes },
             Authority::ManagedNode(src_name),
             Authority::ManagedNode(_)) => {
                self.handle_connection_info_from_node(encrypted_connection_info,
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
            (RequestContent::GetPublicIdWithConnectionInfo { encrypted_connection_info, nonce_bytes, },
             Authority::ManagedNode(src_name),
             Authority::NodeManager(dst_name)) => {
                self.handle_get_public_id_with_connection_info(encrypted_connection_info,
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
        let msg_content = response_msg.content.clone();
        let msg_src = response_msg.src.clone();
        let msg_dst = response_msg.dst.clone();
        trace!("Got response {:?} from {:?} to {:?}.",
               msg_content,
               msg_src,
               msg_dst);
        match (msg_content, msg_src, msg_dst) {
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
            (ResponseContent::GetPublicIdWithConnectionInfo { public_id, encrypted_connection_info, nonce_bytes },
             Authority::NodeManager(_),
             Authority::ManagedNode(dst_name)) => {
                self.handle_get_public_id_with_connection_info_response(public_id, encrypted_connection_info, nonce_bytes, dst_name)
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
        debug!("{:?} Finished bootstrapping.", self);
        // If we have no connections, we should start listening to allow incoming connections
        if self.state == State::Disconnected {
            debug!("{:?} Bootstrap finished with no connections. Start Listening to allow incoming \
                    connections.", self);
            self.start_listening();
        }
    }

    fn start_listening(&mut self) {
        if self.is_listening {
            // TODO Implement a better call once fn
            return;
        }
        self.is_listening = true;

        self.crust_service.start_service_discovery();
        match self.crust_service
                  .start_listening_tcp()
                  .and_then(|_| self.crust_service.start_listening_utp()) {
            Ok(()) => info!("Running listener."),
            Err(err) => warn!("Failed to start listening: {:?}", err),
        }
    }

    fn handle_lost_peer(&mut self, peer_id: PeerId) {
        if !self.client_restriction {
            self.dropped_routing_node_connection(&peer_id);
            self.dropped_client_connection(&peer_id);
        }
        self.dropped_bootstrap_connection(&peer_id);
    }

    fn bootstrap_identify(&mut self, peer_id: PeerId) -> Result<(), RoutingError> {
        let direct_message = DirectMessage::BootstrapIdentify {
            public_id: *self.full_id.public_id(),
            current_quorum_size: self.routing_table.dynamic_quorum_size(),
        };

        let message = Message::Direct(direct_message);
        let raw_bytes = try!(serialisation::serialise(&message));

        try!(self.crust_service.send(&peer_id, raw_bytes));
        Ok(())
    }

    fn bootstrap_deny(&mut self, peer_id: PeerId) -> Result<(), RoutingError> {
        let message = Message::Direct(DirectMessage::BootstrapDeny);
        let raw_bytes = try!(serialisation::serialise(&message));
        try!(self.crust_service.send(&peer_id, raw_bytes));
        Ok(())
    }

    fn client_to_node(&mut self, peer_id: PeerId) -> Result<(), RoutingError> {
        let message = Message::Direct(DirectMessage::ClientToNode);
        let raw_bytes = try!(serialisation::serialise(&message));
        try!(self.crust_service.send(&peer_id, raw_bytes));
        Ok(())
    }

    fn client_identify(&mut self, peer_id: PeerId) -> Result<(), RoutingError> {
        if self.proxy_candidates.iter().any(|&(id, _)| id == peer_id) {
            warn!("Already sent ClientIdentify to this peer {:?}", peer_id);
            return Ok(());
        }

        trace!("{:?} - Sending ClientIdentify to {:?}.", self, peer_id);

        let token = self.timer.schedule(StdDuration::from_secs(BOOTSTRAP_TIMEOUT_SECS));
        self.proxy_candidates.push((peer_id, token));

        let serialised_public_id = try!(serialisation::serialise(self.full_id.public_id()));
        let signature = sign::sign_detached(&serialised_public_id,
                                            self.full_id.signing_private_key());

        let direct_message = DirectMessage::ClientIdentify {
            serialised_public_id: serialised_public_id,
            signature: signature,
            client_restriction: self.client_restriction,
        };

        let message = Message::Direct(direct_message);
        let raw_bytes = try!(serialisation::serialise(&message));

        try!(self.crust_service.send(&peer_id, raw_bytes));
        Ok(())
    }

    fn node_identify(&mut self, peer_id: PeerId) -> Result<(), RoutingError> {
        let serialised_public_id = try!(serialisation::serialise(self.full_id.public_id()));
        let signature = sign::sign_detached(&serialised_public_id,
                                            self.full_id
                                                .signing_private_key());

        let direct_message = DirectMessage::NodeIdentify {
            serialised_public_id: serialised_public_id,
            signature: signature,
        };

        let message = Message::Direct(direct_message);
        let raw_bytes = try!(serialisation::serialise(&message));

        try!(self.crust_service.send(&peer_id, raw_bytes));
        Ok(())
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
                             peer_id: PeerId)
                             -> Result<(), RoutingError> {
        match direct_message {
            DirectMessage::BootstrapIdentify { public_id, current_quorum_size } => {
                self.handle_bootstrap_identify(public_id, peer_id, current_quorum_size)
            }
            DirectMessage::BootstrapDeny => {
                if self.client_restriction {
                    warn!("Connection failed: Proxy node needs a larger routing table to accept \
                           clients.");
                } else {
                    warn!("Connection failed: Proxy node doesn't accept any more joining nodes.");
                }
                self.retry_bootstrap_with_blacklist(&peer_id);
                Ok(())
            }
            DirectMessage::ClientToNode => {
                if let Some((&pub_key, _)) = self.client_by_peer_id(&peer_id) {
                    let _ = self.client_map.remove(&pub_key);
                }
                // TODO(afck): Try adding them to the routing table?
                if self.routing_table.find(|node| node.peer_id == peer_id).is_none() {
                    warn!("Client requested ClientToNode, but is not in routing table: {:?}",
                          peer_id);
                    self.crust_service.disconnect(&peer_id);
                }
                Ok(())
            }
            DirectMessage::ClientIdentify {
                ref serialised_public_id,
                ref signature,
                client_restriction
            } => {
                if let Ok(public_id) = Core::verify_signed_public_id(serialised_public_id,
                                                                     signature) {
                    self.handle_client_identify(public_id, peer_id, client_restriction)
                } else {
                    warn!("Signature check failed in ClientIdentify - Dropping connection {:?}",
                          peer_id);
                    self.crust_service.disconnect(&peer_id);
                    Ok(())
                }
            }
            DirectMessage::NodeIdentify { ref serialised_public_id, ref signature } => {
                if let Ok(public_id) = Core::verify_signed_public_id(serialised_public_id,
                                                                     signature) {
                    self.handle_node_identify(public_id, peer_id)
                } else {
                    warn!("Signature check failed in NodeIdentify - Dropping peer {:?}",
                          peer_id);
                    self.crust_service.disconnect(&peer_id);
                    Ok(())
                }
            }
            DirectMessage::NewNode(public_id) => {
                trace!("Received NewNode({:?}).", public_id);
                if self.routing_table.need_to_add(public_id.name()) {
                    return self.send_connect_request(public_id.name());
                }
                Ok(())
            }
        }
    }

    /// Returns the public signing key and the `ClientInfo` associated with the given Crust
    /// `PeerId`, or `None` if not found in the `client_map`.
    fn client_by_peer_id(&self, peer_id: &PeerId) -> Option<(&sign::PublicKey, &ClientInfo)> {
        self.client_map.iter().find(|&(_, info)| info.peer_id == *peer_id)
    }

    fn handle_bootstrap_identify(&mut self,
                                 public_id: PublicId,
                                 peer_id: PeerId,
                                 current_quorum_size: usize)
                                 -> Result<(), RoutingError> {
        if *public_id.name() ==
           XorName::new(hash::sha512::hash(&public_id.signing_public_key().0).0) {
            warn!("Incoming Connection not validated as a proper node - dropping");
            self.retry_bootstrap_with_blacklist(&peer_id);

            return Ok(());
        }

        if self.proxy_map.is_empty() {
            let _ = self.proxy_map.insert(peer_id, public_id);
        } else {
            if let Some(previous_name) = self.proxy_map.insert(peer_id, public_id) {
                warn!("Adding bootstrap node to proxy map caused a prior ID to eject. Previous \
                       name: {:?}",
                      previous_name);
                warn!("Dropping this peer {:?}", peer_id);
                self.crust_service.disconnect(&peer_id);
                let _ = self.proxy_map.remove(&peer_id);
            } else {
                trace!("Disconnecting {:?} not accepting further bootstrap connections.",
                       peer_id);
                self.crust_service.disconnect(&peer_id);
            }

            return Ok(());
        }

        // Remove the peer from the list of proxy candidates.
        let _ = swap_remove_if(&mut self.proxy_candidates, |&(id, _)| id == peer_id);

        self.state = State::Client;
        trace!("{:?} - State changed to client, quorum size: {}.",
               self,
               current_quorum_size);
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
                              peer_id: PeerId,
                              client_restriction: bool)
                              -> Result<(), RoutingError> {
        if *public_id.name() !=
           XorName::new(hash::sha512::hash(&public_id.signing_public_key().0).0) {
            warn!("Incoming Connection not validated as a proper client - dropping");
            self.crust_service.disconnect(&peer_id);
            return Ok(());
        }

        self.remove_stale_joining_nodes();

        if client_restriction {
            if self.routing_table.len() < GROUP_SIZE - 1 {
                trace!("Client {:?} rejected: Routing table has {} entries. {} required.",
                       public_id.name(),
                       self.routing_table.len(),
                       GROUP_SIZE - 1);
                return self.bootstrap_deny(peer_id);
            }
        } else {
            let joining_nodes_num = self.joining_nodes_num();
            // Restrict the number of simultaneously joining nodes. If the network is still
            // small, we need to accept `GROUP_SIZE` nodes, so that they can fill their
            // routing tables and drop the proxy connection.
            if !(self.routing_table.len() < GROUP_SIZE && joining_nodes_num < GROUP_SIZE) &&
               joining_nodes_num >= MAX_JOINING_NODES {
                trace!("No additional joining nodes allowed. Denying {:?} to join.",
                       public_id.name());
                return self.bootstrap_deny(peer_id);
            }
        }
        if let Some(prev_info) = self.client_map
                                     .insert(*public_id.signing_public_key(),
                                             ClientInfo::new(peer_id, client_restriction)) {
            debug!("{:?} Found previous Crust ID associated with client key - Dropping {:?}",
                   self, prev_info.peer_id);
            self.crust_service.disconnect(&prev_info.peer_id);
        }

        trace!("{:?} Accepted client {:?}.", self, public_id.name());

        let _ = self.bootstrap_identify(peer_id);
        Ok(())
    }

    /// Returns whether the given node is in the cache with the given public ID.
    fn node_in_cache(&mut self, public_id: &PublicId, peer_id: &PeerId) -> bool {
        if let Some(their_public_id) = self.node_id_cache.get(public_id.name()) {
            if their_public_id == public_id {
                return true;
            }
            warn!("Given Public ID and Public ID in cache don't match - Given {:?} :: In cache \
                   {:?} Dropping peer {:?}",
                  public_id,
                  their_public_id,
                  peer_id);
            return false;
        }
        if self.client_by_peer_id(&peer_id).is_some() {
            // TODO(afck): At this point we probably haven't verified that the client's new name is
            // correct.
            trace!("Public ID not in cache, but peer {:?} is a client.",
                   peer_id);
            return true;
        }
        if self.proxy_map.get(&peer_id) == Some(&public_id) {
            // TODO(afck): Maybe we should verify the proxy's public ID.
            trace!("Public ID not in cache, but peer {:?} is a proxy.", peer_id);
            return true;
        }
        debug!("PublicId {:?} not found in node_id_cache - Dropping peer {:?}",
               public_id,
               peer_id);
        false
    }

    fn handle_node_identify(&mut self,
                            public_id: PublicId,
                            peer_id: PeerId)
                            -> Result<(), RoutingError> {
        if self.client_restriction {
            trace!("Received node identify as a client.");
            return Ok(());
        }

        trace!("{:?} Handling NodeIdentify from {:?}.", self, public_id.name());
        if !self.node_in_cache(&public_id, &peer_id) {
            self.crust_service.disconnect(&peer_id);
            return Ok(());
        }

        self.add_to_routing_table(public_id, peer_id)
    }

    fn add_to_routing_table(&mut self,
                            public_id: PublicId,
                            peer_id: PeerId)
                            -> Result<(), RoutingError> {
        let name = *public_id.name();
        if self.routing_table.contains(&name) {
            // We already sent an identify to this peer.
            return Ok(());
        }

        let info = NodeInfo::new(public_id, peer_id);

        match self.routing_table.add(info) {
            None => {
                error!("{:?} Peer was not added to the routing table: {:?}", self, peer_id);
                self.crust_service.disconnect(&peer_id);
                let _ = self.node_id_cache.remove(&name);
                return Ok(());
            }
            Some(AddedNodeDetails { must_notify, common_groups }) => {
                trace!("{:?} Added {:?} to routing table.", self, name);
                for notify_info in must_notify {
                    try!(self.notify_about_new_node(notify_info, public_id));
                }
                if common_groups {
                    let event = Event::NodeAdded(name);
                    if let Err(err) = self.event_sender.send(event) {
                        error!("{:?} Error sending event to routing user - {:?}", self, err);
                    }
                }
            }
        }

        self.state = State::Node;

        if self.routing_table.len() >= GROUP_SIZE && !self.proxy_map.is_empty() {
            trace!("{:?} Routing table reached group size. Dropping proxy.", self);
            try!(self.drop_proxies());
            // We have all close contacts now and know which bucket addresses to
            // request IDs from: All buckets up to the one containing the furthest
            // close node might still be not maximally filled.
            for i in 0..(self.routing_table.furthest_close_bucket() + 1) {
                if let Err(e) = self.request_bucket_ids(i) {
                    trace!("{:?} Failed to request public IDs from bucket {}: {:?}.", self, i, e);
                }
            }
        }

        Ok(())
    }

    /// Send `NewNode` messages to the given contacts.
    fn notify_about_new_node(&mut self,
                             notify_info: NodeInfo,
                             public_id: PublicId)
                             -> Result<(), RoutingError> {
        let notify_id = notify_info.peer_id;
        let direct_message = DirectMessage::NewNode(public_id);
        let message = Message::Direct(direct_message);
        let raw_bytes = try!(serialisation::serialise(&message));
        try!(self.crust_service.send(&notify_id, raw_bytes));
        Ok(())
    }

    /// Removes all proxy map entries and notifies or disconnects from them.
    fn drop_proxies(&mut self) -> Result<(), RoutingError> {
        let former_proxies = self.proxy_map.drain().collect_vec();
        for (peer_id, public_id) in former_proxies {
            if self.routing_table.contains(public_id.name()) {
                try!(self.client_to_node(peer_id));
            } else {
                self.crust_service.disconnect(&peer_id);
            }
        }
        Ok(())
    }

    /// Sends a `GetCloseGroup` request to the close group with our `bucket_index`-th bucket
    /// address.
    fn request_bucket_ids(&mut self, bucket_index: usize) -> Result<(), RoutingError> {
        if bucket_index >= xor_name::XOR_NAME_BITS {
            return Ok(());
        }
        trace!("Send GetCloseGroup to bucket {}.", bucket_index);
        let bucket_address = try!(self.routing_table.our_name().with_flipped_bit(bucket_index));
        let request_msg = RequestMessage {
            src: Authority::ManagedNode(*self.name()),
            dst: Authority::NaeManager(bucket_address),
            content: RequestContent::GetCloseGroup,
        };
        self.send_request(request_msg)
    }

    /// Returns the number of clients for which we act as a proxy and which intend to become a
    /// node.
    fn joining_nodes_num(&self) -> usize {
        self.client_map.values().filter(|&info| !info.client_restriction).count()
    }

    fn remove_stale_joining_nodes(&mut self) {
        let stale_keys = self.client_map
                             .iter()
                             .filter(|&(_, info)| info.is_stale())
                             .map(|(&public_key, _)| public_key)
                             .collect::<Vec<_>>();

        for key in stale_keys {
            if let Some(info) = self.client_map.remove(&key) {
                trace!("Removing stale joining node with Crust ID {:?}",
                       info.peer_id);
            }
        }
    }

    fn retry_bootstrap_with_blacklist(&mut self, peer_id: &PeerId) {
        trace!("Retry bootstrap without {:?}.", peer_id);
        self.crust_service.disconnect(peer_id);
        self.crust_service.stop_bootstrap();
        self.state = State::Disconnected;
        for &proxy_peer_id in self.proxy_map.keys() {
            self.crust_service.disconnect(&proxy_peer_id);
        }
        self.proxy_map.clear();
        thread::sleep(StdDuration::from_secs(5));
        restart_crust_service(&mut self.crust_service, self.crust_sender.clone());
        // TODO(andreas): Enable blacklisting once a solution for ci_test is found.
        //               Currently, ci_test's nodes all connect via the same beacon.
        // self.crust_service
        //    .bootstrap_with_blacklist(0u32, Some(CRUST_DEFAULT_BEACON_PORT), &[endpoint]);
    }

    // Constructed by A; From A -> X
    fn relocate(&mut self) -> Result<(), RoutingError> {
        let request_content = RequestContent::GetNetworkName {
            current_id: *self.full_id.public_id(),
        };

        let request_msg = RequestMessage {
            src: try!(self.get_client_authority()),
            dst: Authority::NaeManager(*self.name()),
            content: request_content,
        };

        self.send_request(request_msg)
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

        let close_group = match self.routing_table.close_nodes(&dst_name) {
            Some(close_group) => {
                close_group.iter()
                           .map(NodeInfo::name)
                           .cloned()
                           .collect()
            }
            None => return Err(RoutingError::InvalidDestination),
        };
        let relocated_name = try!(utils::calculate_relocated_name(close_group,
                                                                  &their_public_id.name()));
        their_public_id.set_name(relocated_name);

        // From X -> A (via B)
        {
            let response_content = ResponseContent::GetNetworkName {
                relocated_id: their_public_id,
            };

            let response_msg = ResponseMessage {
                src: Authority::NaeManager(dst_name),
                dst: Authority::Client {
                    client_key: client_key,
                    proxy_node_name: proxy_name,
                },
                content: response_content,
            };

            try!(self.send_response(response_msg));
        }

        // From X -> Y; Send to close group of the relocated name
        {
            let request_content = RequestContent::ExpectCloseNode { expect_id: their_public_id };

            let request_msg = RequestMessage {
                src: Authority::NaeManager(dst_name),
                dst: Authority::NaeManager(relocated_name),
                content: request_content,
            };

            self.send_request(request_msg)
        }
    }

    // Received by Y; From X -> Y
    fn handle_expect_close_node_request(&mut self,
                                        expect_id: PublicId)
                                        -> Result<(), RoutingError> {
        if let Some(prev_id) = self.node_id_cache.insert(*expect_id.name(), expect_id) {
            warn!("Previous ID {:?} with same name found during \
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

        self.send_request(request_msg)
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
        let close_group = match self.routing_table.close_nodes(&dst_name) {
            Some(close_group) => close_group,
            None => return Err(RoutingError::InvalidDestination),
        };
        let public_ids = close_group.into_iter()
                                    .map(|info| info.public_id)
                                    .collect_vec();

        trace!("Sending GetCloseGroup response with {:?} to client {:?}.",
               public_ids.iter().map(PublicId::name).collect_vec(),
               src);
        let response_content = ResponseContent::GetCloseGroup { close_group_ids: public_ids };

        let response_msg = ResponseMessage {
            src: Authority::NaeManager(dst_name),
            dst: src,
            content: response_content,
        };

        self.send_response(response_msg)
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
                Authority::ManagedNode(..) | Authority::Client { .. } => (),
                _ => return Err(RoutingError::BadAuthority),
            }
        }

        // From A -> Each in Y
        for close_node_id in close_group_ids {
            if self.node_id_cache.insert(*close_node_id.name(), close_node_id).is_none() {
                if self.routing_table.contains(close_node_id.name()) {
                    trace!("Routing table already contains {:?}.", close_node_id);
                } else if !self.routing_table.allow_connection(close_node_id.name()) {
                    trace!("Routing table does not allow {:?}.", close_node_id);
                } else {
                    trace!("Sending connection info to {:?} on GetCloseGroup response.",
                           close_node_id);
                    try!(self.send_connection_info(close_node_id,
                                                   dst.clone(),
                                                   Authority::ManagedNode(*close_node_id.name())));
                }
            }
        }

        Ok(())
    }

    fn handle_connection_info_from_client(&mut self,
                                          encrypted_connection_info: Vec<u8>,
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
                self.connect(encrypted_connection_info,
                             nonce_bytes,
                             *their_public_id,
                             Authority::ManagedNode(dst_name),
                             Authority::Client {
                                 client_key: client_key,
                                 proxy_node_name: proxy_name,
                             })
            }
            None => {
                warn!("Client with key {:?} not found in node_id_cache.", client_key);
                Err(RoutingError::RejectedPublicId)
            }
        }
    }

    fn handle_connection_info_from_node(&mut self,
                                        encrypted_connection_info: Vec<u8>,
                                        nonce_bytes: [u8; box_::NONCEBYTES],
                                        src_name: XorName,
                                        dst: Authority)
                                        -> Result<(), RoutingError> {
        if let Err(err) = self.check_address_for_routing_table(&src_name) {
            let _ = self.node_id_cache.remove(&src_name);
            return Err(err);
        }
        if let Some(their_public_id) = self.node_id_cache.get(&src_name).cloned() {
            self.connect(encrypted_connection_info,
                         nonce_bytes,
                         their_public_id,
                         dst,
                         Authority::ManagedNode(src_name))
        } else {
            let request_content = RequestContent::GetPublicIdWithConnectionInfo {
                encrypted_connection_info: encrypted_connection_info,
                nonce_bytes: nonce_bytes,
            };

            let request_msg = RequestMessage {
                src: dst,
                dst: Authority::NodeManager(src_name),
                content: request_content,
            };

            self.send_request(request_msg)
        }
    }

    // ---- Connect Requests and Responses --------------------------------------------------------

    fn send_connect_request(&mut self, dst_name: &XorName) -> Result<(), RoutingError> {
        let request_content = RequestContent::Connect;

        let request_msg = RequestMessage {
            src: Authority::ManagedNode(*self.name()),
            dst: Authority::ManagedNode(*dst_name),
            content: request_content,
        };

        self.send_request(request_msg)
    }

    fn handle_connect_request(&mut self,
                              src_name: XorName,
                              dst_name: XorName)
                              -> Result<(), RoutingError> {
        try!(self.check_address_for_routing_table(&src_name));

        let our_name = *self.name();
        if let Some(public_id) = self.node_id_cache.get(&src_name).cloned() {
            try!(self.send_connection_info(public_id,
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

        self.send_request(request_msg)
    }

    fn handle_get_public_id(&mut self,
                            src_name: XorName,
                            dst_name: XorName)
                            -> Result<(), RoutingError> {
        if !self.routing_table.is_close(&dst_name) {
            error!("Handling GetPublicId, but not close to the target!");
            Err(RoutingError::RejectedPublicId)
        } else {
            let msg = if let Some(info) = self.routing_table.get(&dst_name) {
                let response_content = ResponseContent::GetPublicId { public_id: info.public_id };

                ResponseMessage {
                    src: Authority::NodeManager(dst_name),
                    dst: Authority::ManagedNode(src_name),
                    content: response_content,
                }
            } else {
                error!("Cannot answer GetPublicId: {:?} not found in the routing table.", dst_name);
                return Err(RoutingError::RejectedPublicId);
            };

            self.send_response(msg)
        }
    }

    fn handle_get_public_id_response(&mut self,
                                     public_id: PublicId,
                                     dst_name: XorName)
                                     -> Result<(), RoutingError> {
        try!(self.check_address_for_routing_table(public_id.name()));

        try!(self.send_connection_info(public_id,
                                       Authority::ManagedNode(dst_name),
                                       Authority::ManagedNode(*public_id.name())));
        let _ = self.node_id_cache.insert(*public_id.name(), public_id);

        Ok(())
    }

    fn handle_get_public_id_with_connection_info(&mut self,
                                                 encrypted_connection_info: Vec<u8>,
                                                 nonce_bytes: [u8; box_::NONCEBYTES],
                                                 src_name: XorName,
                                                 dst_name: XorName)
                                                 -> Result<(), RoutingError> {
        if !self.routing_table.is_close(&dst_name) {
            error!("Handling GetPublicIdWithConnectionInfo, but not close to the target!");
            Err(RoutingError::RejectedPublicId)
        } else {
            let msg = if let Some(info) = self.routing_table.get(&dst_name) {
                let response_content = ResponseContent::GetPublicIdWithConnectionInfo {
                    public_id: info.public_id,
                    encrypted_connection_info: encrypted_connection_info,
                    nonce_bytes: nonce_bytes,
                };

                ResponseMessage {
                    src: Authority::NodeManager(dst_name),
                    dst: Authority::ManagedNode(src_name),
                    content: response_content,
                }
            } else {
                error!("Cannot answer GetPublicIdWithConnectionInfo: {:?} not found in the \
                       routing table.", dst_name);
                return Err(RoutingError::RejectedPublicId);
            };

            self.send_response(msg)
        }
    }

    fn handle_get_public_id_with_connection_info_response(&mut self,
                                                          public_id: PublicId,
                                                          encrypted_connection_info: Vec<u8>,
                                                          nonce_bytes: [u8; box_::NONCEBYTES],
                                                          dst_name: XorName)
                                                          -> Result<(), RoutingError> {
        try!(self.check_address_for_routing_table(public_id.name()));

        let _ = self.node_id_cache.insert(*public_id.name(), public_id);

        self.connect(encrypted_connection_info,
                     nonce_bytes,
                     public_id,
                     Authority::ManagedNode(dst_name),
                     Authority::ManagedNode(*public_id.name()))
    }

    fn send_connection_info(&mut self,
                            their_public_id: PublicId,
                            src: Authority,
                            dst: Authority)
                            -> Result<(), RoutingError> {
        if let Some(peer_id) = self.get_proxy_or_client_peer_id(&their_public_id) {
            try!(self.node_identify(peer_id));
            self.handle_node_identify(their_public_id, peer_id)
        } else if !self.routing_table.contains(their_public_id.name()) &&
           self.routing_table.allow_connection(their_public_id.name()) {
            if self.connection_token_map
                   .retrieve_all()
                   .into_iter()
                   .any(|(_, (public_id, _, _))| public_id == their_public_id) {
                debug!("Already sent connection info to {:?}!",
                       their_public_id.name());
            } else {
                let token = rand::random();
                self.crust_service.prepare_connection_info(token);
                let _ = self.connection_token_map.insert(token, (their_public_id, src, dst));
            }
            Ok(())
        } else {
            Ok(())
        }
    }

    fn handle_timeout(&mut self, token: u64) {
        // We haven't received response from a node we are trying to bootstrap against.
        if let Some((peer_id, _)) = swap_remove_if(&mut self.proxy_candidates,
                                                   |&(_, t)| t == token) {
            if self.state == State::Bootstrapping {
                trace!("Timeout when trying to bootstrap against {:?}", peer_id);
                self.retry_bootstrap_with_blacklist(&peer_id);
            }
        }
    }

    /// Returns the peer ID of the given node if it is our proxy or client.
    fn get_proxy_or_client_peer_id(&self, public_id: &PublicId) -> Option<PeerId> {
        if let Some(info) = self.client_map.get(public_id.signing_public_key()) {
            return Some(info.peer_id);
        };
        if let Some((&peer_id, _)) = self.proxy_map
                                         .iter()
                                         .find(|elt| elt.1 == public_id) {
            return Some(peer_id);
        }
        None
    }

    fn connect(&mut self,
               encrypted_connection_info: Vec<u8>,
               nonce_bytes: [u8; box_::NONCEBYTES],
               their_public_id: PublicId,
               src: Authority,
               dst: Authority)
               -> Result<(), RoutingError> {
        let decipher_result = box_::open(&encrypted_connection_info,
                                         &box_::Nonce(nonce_bytes),
                                         their_public_id.encrypting_public_key(),
                                         self.full_id.encrypting_private_key());

        let serialised_connection_info = try!(decipher_result.map_err(|()| {
            RoutingError::AsymmetricDecryptionFailure
        }));
        let their_connection_info = try!(serialisation::deserialise(&serialised_connection_info));

        if let Some(our_connection_info) = self.our_connection_info_map.remove(&their_public_id) {
            trace!("Received connection info. Trying to connect to {:?}.", their_public_id.name());
            self.crust_service.connect(our_connection_info, their_connection_info);
            Ok(())
        } else {
            let _ = self.their_connection_info_map
                        .insert(their_public_id, their_connection_info);
            self.send_connection_info(their_public_id, src, dst)
        }
    }

    // ----- Send Functions -----------------------------------------------------------------------

    fn send_request(&mut self, request_msg: RequestMessage) -> Result<(), RoutingError> {
        self.send_message(RoutingMessage::Request(request_msg))
    }

    fn send_response(&mut self, response_msg: ResponseMessage) -> Result<(), RoutingError> {
        self.send_message(RoutingMessage::Response(response_msg))
    }

    fn send_message(&mut self, routing_msg: RoutingMessage) -> Result<(), RoutingError> {
        // TODO crust should return the routing msg when it detects an interface error
        let signed_msg = try!(SignedMessage::new(routing_msg.clone(), &self.full_id));
        let hop = *self.name();
        self.send(signed_msg, &hop, true)
    }

    fn relay_to_client(&mut self,
                       signed_msg: SignedMessage,
                       client_key: &sign::PublicKey)
                       -> Result<(), RoutingError> {
        if let Some(&peer_id) = self.client_map.get(client_key).map(|i| &i.peer_id) {
            let hop_msg = try!(HopMessage::new(signed_msg,
                                               *self.name(),
                                               self.full_id.signing_private_key()));
            let message = Message::Hop(hop_msg);
            let raw_bytes = try!(serialisation::serialise(&message));

            try!(self.crust_service.send(&peer_id, raw_bytes));
            return Ok(());
        }

        error!("Client connection not found for message {:?}.", signed_msg);
        Err(RoutingError::ClientConnectionNotFound)
    }

    fn to_hop_bytes(&self, signed_msg: SignedMessage) -> Result<Vec<u8>, RoutingError> {
        let hop_msg = try!(HopMessage::new(signed_msg.clone(),
                                           *self.name(),
                                           self.full_id.signing_private_key()));
        let message = Message::Hop(hop_msg);
        Ok(try!(serialisation::serialise(&message)))
    }

    fn send(&mut self,
            signed_msg: SignedMessage,
            hop: &XorName,
            handle: bool)
            -> Result<(), RoutingError> {
        let raw_bytes = try!(self.to_hop_bytes(signed_msg.clone()));

        // If we're a client going to be a node, send via our bootstrap connection.
        if self.state == State::Client {
            if let Authority::Client { ref proxy_node_name, .. } = *signed_msg.content().src() {
                if let Some((peer_id, _)) = self.proxy_map
                                                .iter()
                                                .find(|elt| elt.1.name() == proxy_node_name) {
                    try!(self.crust_service.send(&peer_id, raw_bytes));
                    return Ok(());
                }

                error!("{:?} - Unable to find connection to proxy node in proxy map",
                       self);
                return Err(RoutingError::ProxyConnectionNotFound);
            }

            error!("{:?} - Source should be client if our state is a Client",
                   self);
            return Err(RoutingError::InvalidSource);
        }

        let count = self.signed_message_filter.count(&signed_msg).saturating_sub(1);
        let destination = signed_msg.content().dst().to_destination();
        let targets = self.routing_table.target_nodes(destination, hop, count);
        for target in targets {
            try!(self.crust_service.send(&target.peer_id, raw_bytes.clone()));
        }

        // If we need to handle this message, handle it.
        if handle && self.routing_table.is_recipient(signed_msg.content().dst().to_destination()) &&
           self.signed_message_filter.insert(&signed_msg) == 0 {
            let hop_name = *self.name();
            return self.handle_signed_message_for_node(&signed_msg, &hop_name, false);
        }

        Ok(())
    }

    fn get_client_authority(&self) -> Result<Authority, RoutingError> {
        match self.proxy_map.iter().next() {
            Some((ref _id, ref bootstrap_pub_id)) => {
                Ok(Authority::Client {
                    client_key: *self.full_id.public_id().signing_public_key(),
                    proxy_node_name: *bootstrap_pub_id.name(),
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

        self.full_id.public_id_mut().set_name(new_name);
        let our_info = NodeInfo::new(*self.full_id.public_id(), self.crust_service.id());
        self.routing_table = RoutingTable::new(our_info);
    }

    fn dropped_client_connection(&mut self, peer_id: &PeerId) {
        if let Some((&public_key, _)) = self.client_by_peer_id(peer_id) {
            if let Some(info) = self.client_map.remove(&public_key) {
                if !info.client_restriction {
                    trace!("Joining node dropped. {} remaining.",
                           self.joining_nodes_num());
                }
            }
        }
    }

    fn dropped_bootstrap_connection(&mut self, peer_id: &PeerId) {
        if let Some(public_id) = self.proxy_map.remove(peer_id) {
            trace!("Lost bootstrap connection to {:?}.", public_id.name());
        } else if self.state == State::Bootstrapping {
            trace!("Lost connection to candidate for proxy node {:?}", peer_id);
            self.retry_bootstrap_with_blacklist(peer_id);
        }
    }

    fn dropped_routing_node_connection(&mut self, peer_id: &PeerId) {
        if let Some(&node) = self.routing_table.find(|node| node.peer_id == *peer_id) {
            if let Some(DroppedNodeDetails { incomplete_bucket, common_groups }) =
                   self.routing_table.remove(node.public_id.name()) {
                trace!("Dropped {:?} from the routing table.", node.name());
                if common_groups {
                    // If the lost node shared some close group with us, send a NodeLost event.
                    let event = Event::NodeLost(*node.public_id.name());
                    if let Err(err) = self.event_sender.send(event) {
                        error!("Error sending event to routing user - {:?}", err);
                    }
                }
                if let Some(bucket_index) = incomplete_bucket {
                    if let Err(e) = self.request_bucket_ids(bucket_index) {
                        trace!("Failed to request replacement connection_info from bucket {}: \
                                {:?}.",
                               bucket_index,
                               e);
                    }
                }
            }
        };
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

    /// Returns the `XorName` of this node.
    fn name(&self) -> &XorName {
        self.full_id.public_id().name()
    }
}

impl Debug for Core {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{:?}({:?})", self.state, self.name())
    }
}

// Remove and return the first element for which the given predicate returns true.
fn swap_remove_if<T, F>(vec: &mut Vec<T>, pred: F) -> Option<T>
    where F: Fn(&T) -> bool
{
    if let Some(pos) = vec.iter().position(pred) {
        Some(vec.swap_remove(pos))
    } else {
        None
    }
}

#[cfg(not(feature = "use-mock-crust"))]
fn restart_crust_service(service: &mut Service, sender: crust::CrustEventSender) {
    use std::mem;

    let _ = mem::replace(service, match Service::new(sender, CRUST_DEFAULT_BEACON_PORT) {
        Ok(service) => service,
        Err(err) => panic!(format!("Unable to restart crust::Service {:?}", err)),
    });
}

#[cfg(feature = "use-mock-crust")]
fn restart_crust_service(service: &mut Service, sender: crust::CrustEventSender) {
    service.restart(sender, CRUST_DEFAULT_BEACON_PORT)
}
