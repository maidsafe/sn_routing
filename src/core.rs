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
use mock_crust::crust::{self, ConnectionInfoResult, OurConnectionInfo, PeerId, Service,
                        TheirConnectionInfo};

use itertools::Itertools;
use kademlia_routing_table::{AddedNodeDetails, ContactInfo, DroppedNodeDetails};
use lru_time_cache::LruCache;
use maidsafe_utilities::{self, serialisation};
use maidsafe_utilities::event_sender::MaidSafeEventCategory;
use message_filter::MessageFilter;
use peer_manager::{ConnectState, PeerManager};
use rand;
use sodiumoxide::crypto::{box_, hash, sign};
use std::{cmp, io, iter, fmt};
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::time::{Duration, Instant};
use std::sync::mpsc;
use tunnels::Tunnels;
use xor_name::{XorName, XOR_NAME_BITS};

use action::Action;
use authority::Authority;
use data::{Data, DataIdentifier};
use error::{RoutingError, InterfaceError};
use event::Event;
use id::{FullId, PublicId};
use stats::Stats;
use timer::Timer;
use types::{MessageId, RoutingActionSender};
use messages::{DirectMessage, HopMessage, Message, MessageContent, Request, RoutingMessage,
               SignedMessage, Response};
use utils;

/// The group size for the routing table. This is the maximum that can be used for consensus.
pub const GROUP_SIZE: usize = 8;
/// The quorum for group consensus.
pub const QUORUM_SIZE: usize = 5;
/// The number of entries beyond `GROUP_SIZE` that are not considered unnecessary in the routing
/// table.
const EXTRA_BUCKET_ENTRIES: usize = 2;
/// Time (in seconds) after which bootstrap is cancelled (and possibly retried).
const BOOTSTRAP_TIMEOUT_SECS: u64 = 20;
/// Time (in seconds) after which a `GetNodeName` request is resent.
const GET_NODE_NAME_TIMEOUT_SECS: u64 = 60;
/// Time (in seconds) after which a `Tick` event is sent.
const TICK_TIMEOUT_SECS: u64 = 60;
/// Time (in seconds) the new close group waits for a joining node it sent a network name to.
const SENT_NETWORK_NAME_TIMEOUT_SECS: u64 = 30;
/// Initial period for requesting bucket close groups of all non-full buckets. This is doubled each
/// time.
const REFRESH_BUCKET_GROUPS_SECS: u64 = 120;
/// Time (in seconds) after which a message is resent due to being unacknowledged by recipient.
const ACK_TIMEOUT_SECS: u64 = 20;

/// The state of the connection to the network.
#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
enum State {
    /// Not connected to any node.
    Disconnected,
    /// Transition state while validating a peer as a proxy node.
    Bootstrapping(PeerId, u64),
    /// We are bootstrapped and connected to a valid proxy node.
    Client,
    /// We have been Relocated and now a node.
    Node,
}

pub type RoutingTable = ::kademlia_routing_table::RoutingTable<NodeInfo>;

/// Info about nodes in the routing table.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NodeInfo {
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
    type Name = XorName;

    fn name(&self) -> &XorName {
        self.public_id.name()
    }
}

/// The role this `Core` instance intends to act as once it joined the network.
#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone, Copy)]
pub enum Role {
    /// Remain a client and not become a full routing node.
    Client,
    /// Join an existing network as a routing node.
    Node,
    /// Start a new network as its first node.
    FirstNode,
}

/// A copy of a message which has been sent and is pending the ack from the recipient.
#[derive(Clone, Debug)]
struct UnacknowledgedMessage {
    signed_msg: SignedMessage,
    route: u8,
    timer_token: u64,
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
/// Once in `Client` state, A sends a `GetNodeName` request to the `NaeManager` group authority X
/// of A's current name. X computes a new name and sends it in an `ExpectCloseNode` request to  the
/// `NaeManager` Y of A's new name. Each member of Y caches A's public ID, and Y sends a
/// `GetNodeName` response back to A, which includes the public IDs of the members of Y.
///
///
/// ### Connecting to the close group
///
/// To the `ManagedNode` for each public ID it receives from members of Y, A sends its
/// `ConnectionInfo`. It also caches the ID.
///
/// For each `ConnectionInfo` that a node Z receives from A, it decides whether it wants A in its
/// routing table. If yes, and if A's ID is in its ID cache, Z sends its own `ConnectionInfo` back
/// to A and also attempts to connect to A via Crust. A does the same, once it receives the
/// `ConnectionInfo`.
///
/// Once the connection between A and Z is established and a Crust `OnConnect` event is raised,
/// they exchange `NodeIdentify` messages and add each other to their routing tables. When A
/// receives its first `NodeIdentify`, it finally moves to the `Node` state.
pub struct Core {
    crust_service: Service,
    role: Role,
    is_listening: bool,
    category_rx: mpsc::Receiver<MaidSafeEventCategory>,
    crust_rx: mpsc::Receiver<crust::Event>,
    action_rx: mpsc::Receiver<Action>,
    event_sender: mpsc::Sender<Event>,
    timer: Timer,
    signed_message_filter: MessageFilter<SignedMessage>,
    pending_acks: HashMap<u64, UnacknowledgedMessage>,
    received_acks: MessageFilter<u64>,
    bucket_filter: MessageFilter<usize>,
    message_accumulator: Accumulator<RoutingMessage, sign::PublicKey>,
    // Group messages which have been accumulated and then actioned
    grp_msg_filter: MessageFilter<RoutingMessage>,
    full_id: FullId,
    state: State,
    routing_table: RoutingTable,
    get_node_name_timer_token: Option<u64>,
    bucket_refresh_token_and_delay: Option<(u64, u64)>,
    /// The last joining node we have sent a `GetNodeName` response to, and when.
    sent_network_name_to: Option<(XorName, Instant)>,
    tick_timer_token: Option<u64>,
    use_data_cache: bool,
    data_cache: LruCache<XorName, Data>,
    tunnels: Tunnels,
    stats: Stats,
    send_filter: LruCache<(u64, PeerId, u8), ()>,
    peer_mgr: PeerManager,
}

#[cfg_attr(feature="clippy", allow(new_ret_no_self))] // TODO: Maybe rename `new` to `start`?
impl Core {
    /// A Core instance for a client or node with the given id. Sends events to upper layer via the
    /// mpsc sender passed in.
    pub fn new(event_sender: mpsc::Sender<Event>,
               role: Role,
               keys: Option<FullId>,
               use_data_cache: bool)
               -> (RoutingActionSender, Self) {
        let (crust_tx, crust_rx) = mpsc::channel();
        let (action_tx, action_rx) = mpsc::channel();
        let (category_tx, category_rx) = mpsc::channel();

        let routing_event_category = MaidSafeEventCategory::Routing;
        let action_sender =
            RoutingActionSender::new(action_tx, routing_event_category, category_tx.clone());
        let action_sender2 = action_sender.clone();

        let crust_event_category = MaidSafeEventCategory::Crust;
        let crust_sender =
            crust::CrustEventSender::new(crust_tx, crust_event_category, category_tx);

        // TODO(afck): Add the listening port to the Service constructor.
        let crust_service = match Service::new(crust_sender) {
            Ok(service) => service,
            Err(what) => panic!(format!("Unable to start crust::Service {:?}", what)),
        };

        let full_id = match keys {
            Some(full_id) => full_id,
            None => FullId::new(),
        };

        let our_info = NodeInfo::new(*full_id.public_id(), crust_service.id());

        let mut core = Core {
            crust_service: crust_service,
            role: role,
            is_listening: false,
            category_rx: category_rx,
            crust_rx: crust_rx,
            action_rx: action_rx,
            event_sender: event_sender,
            timer: Timer::new(action_sender2),
            signed_message_filter: MessageFilter::with_expiry_duration(Duration::from_secs(60 *
                                                                                           20)),
            pending_acks: HashMap::new(),
            received_acks: MessageFilter::with_expiry_duration(Duration::from_secs(4 * 60)),
            // TODO Needs further discussion on interval
            bucket_filter: MessageFilter::with_expiry_duration(Duration::from_secs(60)),
            message_accumulator: Accumulator::with_duration(1, Duration::from_secs(60 * 20)),
            grp_msg_filter: MessageFilter::with_expiry_duration(Duration::from_secs(60 * 20)),
            full_id: full_id,
            state: State::Disconnected,
            routing_table: RoutingTable::new(our_info, GROUP_SIZE, EXTRA_BUCKET_ENTRIES),
            get_node_name_timer_token: None,
            bucket_refresh_token_and_delay: None,
            sent_network_name_to: None,
            tick_timer_token: None,
            use_data_cache: use_data_cache,
            data_cache: LruCache::with_capacity(100),
            tunnels: Default::default(),
            stats: Default::default(),
            send_filter: LruCache::with_expiry_duration(Duration::from_secs(60 * 10)),
            peer_mgr: Default::default(),
        };

        if role == Role::FirstNode {
            core.start_new_network();
        }

        (action_sender, core)
    }

    /// If there is an event in the queue, processes it and returns true.
    /// otherwise returns false. Never blocks.
    #[cfg(feature = "use-mock-crust")]
    pub fn poll(&mut self) -> bool {
        match self.category_rx.try_recv() {
            Ok(category) => {
                self.handle_event(category);
                true
            }
            _ => false,
        }
    }

    /// Run the event loop for sending and receiving messages. Blocks until
    /// the core is terminated, so it must be called in a separate thread.
    #[cfg(not(feature = "use-mock-crust"))]
    pub fn run(&mut self) {
        // Note: can't use self.category_rx.iter()... because of borrow checker.
        loop {
            let run = self.category_rx
                .recv()
                .map(|category| self.handle_event(category))
                .unwrap_or(false);

            if !run {
                break;
            }
        }
    }

    /// Returns the `XorName` of this node.
    pub fn name(&self) -> &XorName {
        self.full_id.public_id().name()
    }

    /// Returns the names of all nodes in the close group of this node.
    #[allow(unused)]
    pub fn close_group(&self) -> Vec<XorName> {
        self.routing_table
            .other_close_nodes(self.name(), GROUP_SIZE)
            .unwrap_or_else(Vec::new)
            .into_iter()
            .map(|info| *info.name())
            .collect()
    }

    /// Routing table of this node.
    #[allow(unused)]
    pub fn routing_table(&self) -> &RoutingTable {
        &self.routing_table
    }

    /// resends all unacknowledged messages.
    #[cfg(feature = "use-mock-crust")]
    pub fn resend_unacknowledged(&mut self) -> bool {
        self.timer.stop();
        let timer_tokens = self.pending_acks
            .iter()
            .map(|(_, unacked_msg)| unacked_msg.timer_token)
            .collect_vec();
        for timer_token in &timer_tokens {
            self.handle_timeout(*timer_token);
        }
        !timer_tokens.is_empty()
    }

    /// Clears all state containers.
    #[cfg(feature = "use-mock-crust")]
    pub fn clear_state(&mut self) {
        self.send_filter.clear();
        self.signed_message_filter.clear();
        self.received_acks.clear();
        self.bucket_filter.clear();
        // self.message_accumulator.clear();
        self.grp_msg_filter.clear();
        self.sent_network_name_to = None;
        self.peer_mgr.clear_caches();
    }

    fn update_stats(&mut self) {
        if self.state == State::Node {
            let old_client_num = self.stats.cur_client_num;
            self.stats.cur_client_num = self.peer_mgr.client_num();
            if self.stats.cur_client_num != old_client_num {
                if self.stats.cur_client_num > old_client_num {
                    self.stats.cumulative_client_num += self.stats.cur_client_num - old_client_num;
                }
                info!("{:?} - Connected clients: {}, cumulative: {}",
                      self,
                      self.stats.cur_client_num,
                      self.stats.cumulative_client_num);
            }
            if self.stats.tunnel_connections != self.tunnels.tunnel_count() ||
               self.stats.tunnel_client_pairs != self.tunnels.client_count() {
                self.stats.tunnel_connections = self.tunnels.tunnel_count();
                self.stats.tunnel_client_pairs = self.tunnels.client_count();
                info!("{:?} - Indirect connections: {}, tunneling for: {}",
                      self,
                      self.stats.tunnel_connections,
                      self.stats.tunnel_client_pairs);
            }
        }

        if self.state == State::Node &&
           self.stats.cur_routing_table_size != self.routing_table.len() {
            self.stats.cur_routing_table_size = self.routing_table.len();

            let status_str = format!("{:?} {:?} - Routing Table size: {:3}",
                                     self,
                                     self.crust_service.id(),
                                     self.routing_table.len());
            info!(" -{}- ",
                  iter::repeat('-').take(status_str.len()).collect::<String>());
            info!("| {} |", status_str); // Temporarily error for ci_test.
            info!(" -{}- ",
                  iter::repeat('-').take(status_str.len()).collect::<String>());
        }
    }

    fn handle_event(&mut self, category: MaidSafeEventCategory) -> bool {
        match category {
            MaidSafeEventCategory::Routing => {
                if let Ok(action) = self.action_rx.try_recv() {
                    if !self.handle_action(action) {
                        return false;
                    }
                }
            }
            MaidSafeEventCategory::Crust => {
                if let Ok(crust_event) = self.crust_rx.try_recv() {
                    self.handle_crust_event(crust_event);
                }
            }
        } // Category Match

        self.update_stats();

        true
    }

    fn handle_action(&mut self, action: Action) -> bool {
        match action {
            Action::NodeSendMessage { content, result_tx } => {
                if result_tx.send(match self.send_message(content) {
                        Err(RoutingError::Interface(err)) => Err(err),
                        Err(_err) => Ok(()),
                        Ok(()) => Ok(()),
                    })
                    .is_err() {
                    return false;
                }
            }
            Action::ClientSendRequest { content, dst, result_tx } => {
                if result_tx.send(if let Ok(src) = self.get_client_authority() {
                        let request_msg = RoutingMessage {
                            content: MessageContent::Request(content),
                            src: src,
                            dst: dst,
                        };

                        match self.send_message(request_msg) {
                            Err(RoutingError::Interface(err)) => Err(err),
                            Err(_err) => Ok(()),
                            Ok(()) => Ok(()),
                        }
                    } else {
                        Err(InterfaceError::NotConnected)
                    })
                    .is_err() {
                    return false;
                }
            }
            Action::CloseGroup { name, result_tx } => {
                let close_group = self.routing_table
                    .close_nodes(&name, GROUP_SIZE)
                    .map(|infos| {
                        infos.iter()
                            .map(NodeInfo::name)
                            .cloned()
                            .collect()
                    });

                if result_tx.send(close_group).is_err() {
                    return false;
                }
            }
            Action::Name { result_tx } => {
                if result_tx.send(*self.name()).is_err() {
                    return false;
                }
            }
            Action::QuorumSize { result_tx } => {
                if result_tx.send(self.dynamic_quorum_size()).is_err() {
                    return false;
                }
            }
            Action::Timeout(token) => self.handle_timeout(token),
            Action::Terminate => {
                return false;
            }
        }

        true
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
                    Err(RoutingError::FilterCheckFailed) |
                    Ok(_) => (),
                    Err(err) => debug!("{:?} - {:?}", self, err),
                }
            }
            crust::Event::ConnectionInfoPrepared(ConnectionInfoResult { result_token, result }) => {
                self.handle_connection_info_prepared(result_token, result);
            }
        }
    }

    fn handle_bootstrap_connect(&mut self, peer_id: PeerId) {
        if self.role == Role::FirstNode {
            error!("{:?} Received BootstrapConnect as the first node.", self);
            self.disconnect_peer(&peer_id);
            return;
        }
        self.peer_mgr.insert_peer(peer_id);
        self.crust_service.stop_bootstrap();
        match self.state {
            State::Disconnected => {
                if self.role == Role::Node {
                    let _ = self.start_listening();
                }
                debug!("{:?} Received BootstrapConnect from {:?}.", self, peer_id);
                // Established connection. Pending Validity checks
                let _ = self.client_identify(peer_id);
            }
            State::Bootstrapping(bootstrap_id, _) if bootstrap_id == peer_id => {
                warn!("{:?} Got more than one BootstrapConnect for peer {:?}.",
                      self,
                      peer_id);
            }
            _ => {
                self.disconnect_peer(&peer_id);
            }
        }
    }

    fn start_new_network(&mut self) {
        self.crust_service.stop_bootstrap();
        if !self.start_listening() {
            error!("{:?} Failed to start listening.", self);
            let _ = self.event_sender.send(Event::NetworkStartupFailed);
        }
        let new_name = XorName(hash::sha256::hash(&self.full_id.public_id().name().0).0);
        self.set_self_node_name(new_name);
        self.state = State::Node;
        let tick_period = Duration::from_secs(TICK_TIMEOUT_SECS);
        self.tick_timer_token = Some(self.timer.schedule(tick_period));
        info!("{:?} - Started a new network as a seed node.", self)
    }

    fn handle_bootstrap_accept(&mut self, peer_id: PeerId) {
        self.peer_mgr.insert_peer(peer_id);
        trace!("{:?} Received BootstrapAccept from {:?}.", self, peer_id);
        // TODO: Keep track of that peer to make sure we receive a message from them.
    }

    fn handle_new_peer(&mut self, result: io::Result<()>, peer_id: PeerId) {
        if peer_id == self.crust_service.id() {
            error!("{:?} Received NewPeer event with our Crust peer ID.", self);
            return;
        }
        if self.role == Role::Client {
            warn!("{:?} Received NewPeer event as a client.", self);
        } else {
            match result {
                Ok(()) => {
                    // TODO(afck): Keep track of this connection: Disconnect if we don't receive a
                    // NodeIdentify.
                    if let Some(node) = self.routing_table
                        .iter()
                        .find(|node| node.peer_id == peer_id) {
                        warn!("{:?} Received NewPeer from {:?}, but node {:?} is already in our \
                               routing table.",
                              self,
                              peer_id,
                              node.name());
                        return;
                    }
                    self.peer_mgr.connected_to(peer_id);
                    debug!("{:?} Received NewPeer with Ok from {:?}. Sending NodeIdentify.",
                           self,
                           peer_id);
                    let _ = self.node_identify(peer_id);
                }
                Err(err) => {
                    if self.routing_table.iter().all(|node| node.peer_id != peer_id) {
                        warn!("{:?} Failed to connect to peer {:?}: {:?}.",
                              self,
                              peer_id,
                              err);
                        if let Some(&(name, ConnectState::Crust)) = self.peer_mgr
                            .get_connecting_peer(&peer_id) {
                            self.find_tunnel_for_peer(peer_id, name);
                        }
                    }
                }
            }
        }
    }

    fn find_tunnel_for_peer(&mut self, peer_id: PeerId, name: XorName) {
        let _ = self.peer_mgr.insert_connecting_peer(peer_id, name, ConnectState::Tunnel);
        for node in self.routing_table.closest_nodes_to(&name, GROUP_SIZE, false) {
            trace!("{:?} Asking {:?} to serve as a tunnel.", self, node.name());
            let tunnel_request = DirectMessage::TunnelRequest(peer_id);
            if let Err(err) = self.send_direct_message(&node.peer_id, tunnel_request) {
                error!("{:?} Failed to send tunnel request: {:?}.", self, err);
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
                    error!("{:?} Failed to serialise connection info: {:?}", self, err);
                    return;
                }
                Ok(encoded_connection_info) => encoded_connection_info,
            };
        let (their_public_id, src, dst) = if let Some(entry) = self.peer_mgr
            .connection_token_map
            .remove(&result_token) {
            entry.clone()
        } else {
            error!("{:?} Prepared connection info, but no entry found in token map.",
                   self);
            return;
        };
        let nonce = box_::gen_nonce();
        let encrypted_connection_info = box_::seal(&encoded_connection_info,
                                                   &nonce,
                                                   their_public_id.encrypting_public_key(),
                                                   self.full_id.encrypting_private_key());

        let their_name = *their_public_id.name();
        if let Some(their_connection_info) = self.peer_mgr
            .their_connection_info_map
            .remove(&their_public_id) {
            let peer_id = their_connection_info.id();
            if let Some((name, _)) = self.peer_mgr
                .insert_connecting_peer(peer_id, their_name, ConnectState::Crust) {
                warn!("{:?} Prepared connection info for {:?} as {:?}, but already tried as {:?}.",
                      self,
                      peer_id,
                      their_name,
                      name);
            }
            debug!("{:?} Trying to connect to {:?} as {:?}.",
                   self,
                   peer_id,
                   their_name);
            self.crust_service.connect(our_connection_info, their_connection_info);
        } else {
            let _ =
                self.peer_mgr.our_connection_info_map.insert(their_public_id, our_connection_info);
            debug!("{:?} Prepared connection info for {:?}.", self, their_name);
        }

        let request_content = MessageContent::ConnectionInfo {
            encrypted_connection_info: encrypted_connection_info,
            nonce_bytes: nonce.0,
            public_id: *self.full_id.public_id(),
        };

        let request_msg = RoutingMessage {
            src: src,
            dst: dst,
            content: request_content,
        };

        if let Err(err) = self.send_message(request_msg) {
            error!("{:?} Failed to send connection info for {:?}: {:?}.",
                   self,
                   their_name,
                   err);
        }
    }

    fn handle_new_message(&mut self, peer_id: PeerId, bytes: Vec<u8>) -> Result<(), RoutingError> {
        if !self.peer_mgr.update_peer(&peer_id) {
            return Err(RoutingError::UnknownConnection(peer_id));
        }
        match serialisation::deserialise(&bytes) {
            Ok(Message::Hop(ref hop_msg)) => self.handle_hop_message(hop_msg, peer_id),
            Ok(Message::Direct(direct_msg)) => self.handle_direct_message(direct_msg, peer_id),
            Ok(Message::TunnelDirect { content, src, dst }) => {
                if dst == self.crust_service.id() &&
                   self.tunnels.tunnel_for(&src) == Some(&peer_id) {
                    self.handle_direct_message(content, src)
                } else if self.tunnels.has_clients(src, dst) {
                    self.send_or_drop(&dst, bytes, content.priority())
                } else if self.tunnels.accept_clients(src, dst) {
                    try!(self.send_direct_message(&dst, DirectMessage::TunnelSuccess(src)));
                    self.send_or_drop(&dst, bytes, content.priority())
                } else {
                    Err(RoutingError::InvalidDestination)
                }
            }
            Ok(Message::TunnelHop { content, src, dst }) => {
                if dst == self.crust_service.id() &&
                   self.tunnels.tunnel_for(&src) == Some(&peer_id) {
                    self.handle_hop_message(&content, src)
                } else if self.tunnels.has_clients(src, dst) {
                    self.send_or_drop(&dst, bytes, content.content().priority())
                } else {
                    Err(RoutingError::InvalidDestination)
                }
            }
            Err(error) => Err(RoutingError::SerialisationError(error)),
        }
    }

    fn handle_hop_message(&mut self,
                          hop_msg: &HopMessage,
                          peer_id: PeerId)
                          -> Result<(), RoutingError> {
        let hop_name;
        if self.state == State::Node {
            if let Some(info) = self.routing_table.iter().find(|node| node.peer_id == peer_id) {
                try!(hop_msg.verify(info.public_id.signing_public_key()));
                // try!(self.check_direction(hop_msg));
                hop_name = *info.name();
            } else if let Some(client_info) = self.peer_mgr.get_client(&peer_id) {
                try!(hop_msg.verify(&client_info.public_key));
                if client_info.client_restriction {
                    try!(self.check_not_get_node_name(hop_msg.content().routing_message()));
                }
                hop_name = *self.name();
            } else if let Some(pub_id) = self.peer_mgr.get_proxy(&peer_id) {
                try!(hop_msg.verify(pub_id.signing_public_key()));
                hop_name = *pub_id.name();
            } else {
                // TODO: Drop peer?
                // error!("Received hop message from unknown name {:?}. Dropping peer {:?}.",
                //        hop_msg.name(),
                //        peer_id);
                // self.disconnect_peer(&peer_id);
                return Err(RoutingError::UnknownConnection(peer_id));
            }
        } else if self.state == State::Client {
            if let Some(pub_id) = self.peer_mgr.get_proxy(&peer_id) {
                try!(hop_msg.verify(pub_id.signing_public_key()));
                hop_name = *pub_id.name();
            } else {
                return Err(RoutingError::UnknownConnection(peer_id));
            }
        } else {
            return Err(RoutingError::InvalidStateForOperation);
        }

        self.handle_signed_message(hop_msg.content(),
                                   hop_msg.route(),
                                   &hop_name,
                                   hop_msg.sent_to())
    }

    fn check_not_get_node_name(&self, msg: &RoutingMessage) -> Result<(), RoutingError> {
        if let MessageContent::GetNodeName { .. } = msg.content {
            debug!("{:?} Illegitimate GetNodeName request. Refusing to relay.",
                   self);
            return Err(RoutingError::RejectedGetNodeName);
        }
        Ok(())
    }

    fn handle_signed_message(&mut self,
                             signed_msg: &SignedMessage,
                             route: u8,
                             hop_name: &XorName,
                             sent_to: &[XorName])
                             -> Result<(), RoutingError> {
        try!(signed_msg.check_integrity());
        let routing_msg = signed_msg.routing_message();

        // FIXME: This is currently only in place so acks can get delivered if the
        // original ack was lost in transit
        if (self.grp_msg_filter.contains(routing_msg) || !routing_msg.src.is_group()) &&
           self.is_recipient(&routing_msg.dst) {
            self.send_ack(routing_msg, route);
        }

        // Prevents
        // 1) someone sending messages repeatedly to us
        // 2) swarm messages generated by us reaching us again
        if self.signed_message_filter.insert(signed_msg) > GROUP_SIZE {
            return Err(RoutingError::FilterCheckFailed);
        }

        // Since endpoint request / GetCloseGroup response messages while relocating are sent
        // to a client we still need to accept these msgs sent to us even if we have become a node.
        if let Authority::Client { ref client_key, .. } = routing_msg.dst {
            if client_key == self.full_id.public_id().signing_public_key() {
                if let MessageContent::ConnectionInfo { .. } = routing_msg.content {
                    return self.handle_signed_message_for_client(signed_msg);
                }
            }
        }

        match self.state {
            State::Node => {
                if let Err(error) = self.handle_signed_message_for_node(signed_msg) {
                    error!("{:?} Failed to handle {:?}: {:?}", self, signed_msg, error);
                }
                self.send(signed_msg, route, hop_name, sent_to)
            }
            State::Client => self.handle_signed_message_for_client(signed_msg),
            _ => Err(RoutingError::InvalidStateForOperation),
        }
    }

    fn handle_signed_message_for_node(&mut self,
                                      signed_msg: &SignedMessage)
                                      -> Result<(), RoutingError> {
        let routing_msg = signed_msg.routing_message();
        let dst = &routing_msg.dst;

        if let Authority::Client { ref peer_id, .. } = *dst {
            if self.name() == dst.name() {
                // This is a message for a client we are the proxy of. Relay it.
                return self.relay_to_client(signed_msg.clone(), peer_id);
            }
        }

        if self.routing_table.is_close(dst.name(), GROUP_SIZE) {
            try!(self.signed_msg_security_check(&signed_msg));
        }

        // Cache handling
        if self.use_data_cache {
            if let Some(response_msg) = self.get_from_cache(routing_msg) {
                return self.send_message(response_msg);
            }
        }
        self.add_to_cache(routing_msg);

        if self.signed_message_filter.count(signed_msg) <= 1 &&
           self.routing_table.is_recipient(dst.to_destination()) {
            self.handle_routing_message(routing_msg, *signed_msg.public_id())
        } else {
            Ok(())
        }
    }

    fn handle_signed_message_for_client(&mut self,
                                        signed_msg: &SignedMessage)
                                        -> Result<(), RoutingError> {
        if self.signed_message_filter.count(signed_msg) > 1 {
            return Err(RoutingError::FilterCheckFailed);
        }
        let routing_msg = signed_msg.routing_message();
        if let Authority::Client { ref client_key, .. } = routing_msg.dst {
            if self.full_id.public_id().signing_public_key() == client_key {
                return self.handle_routing_message(routing_msg, *signed_msg.public_id());
            }
        }
        Err(RoutingError::BadAuthority)
    }

    fn signed_msg_security_check(&self, signed_msg: &SignedMessage) -> Result<(), RoutingError> {
        // TODO: If group, verify the sender's membership.
        if let Authority::Client { ref client_key, .. } = signed_msg.routing_message().src {
            if client_key != signed_msg.public_id().signing_public_key() {
                return Err(RoutingError::FailedSignature);
            };
        }
        Ok(())
    }

    /// Returns a cached response, if one is available for the given message, otherwise `None`.
    fn get_from_cache(&mut self, routing_msg: &RoutingMessage) -> Option<RoutingMessage> {
        let content = match routing_msg.content {
            MessageContent::Request(Request::Get(DataIdentifier::Immutable(ref name), id)) => {
                match self.data_cache.get(name) {
                    Some(data) => MessageContent::Response(Response::GetSuccess(data.clone(), id)),
                    _ => return None,
                }
            }
            _ => return None,
        };

        let response_msg = RoutingMessage {
            src: Authority::ManagedNode(*self.name()),
            dst: routing_msg.src.clone(),
            content: content,
        };

        Some(response_msg)
    }

    fn add_to_cache(&mut self, routing_msg: &RoutingMessage) {
        if let MessageContent::Response(Response::GetSuccess(ref data @ Data::Immutable(_), _)) =
               routing_msg.content {
            let _ = self.data_cache.insert(data.name(), data.clone());
        }
    }

    fn handle_routing_message(&mut self,
                              routing_msg: &RoutingMessage,
                              public_id: PublicId)
                              -> Result<(), RoutingError> {
        if routing_msg.src.is_group() {
            if self.grp_msg_filter.contains(routing_msg) {
                return Err(RoutingError::FilterCheckFailed);
            }
            if self.accumulate(routing_msg, &public_id) {
                let _ = self.grp_msg_filter.insert(routing_msg);
                self.send_ack(routing_msg, 0);
            } else {
                return Ok(());
            }
        }
        self.dispatch_routing_message(routing_msg)
    }

    fn accumulate(&mut self, message: &RoutingMessage, public_id: &PublicId) -> bool {
        // For clients we already have set it on reception of BootstrapIdentify message
        if self.state == State::Node {
            let dynamic_quorum_size = self.dynamic_quorum_size();
            self.message_accumulator.set_quorum_size(dynamic_quorum_size);
        }
        let key = *public_id.signing_public_key();
        self.message_accumulator.add(message.clone(), key).is_some()
    }

    fn dynamic_quorum_size(&self) -> usize {
        // Routing table entries plus this node itself.
        let network_size = self.routing_table.len() + 1;
        if network_size >= GROUP_SIZE {
            QUORUM_SIZE
        } else {
            cmp::max(network_size * QUORUM_SIZE / GROUP_SIZE,
                     network_size / 2 + 1)
        }
    }

    fn dispatch_routing_message(&mut self,
                                routing_msg: &RoutingMessage)
                                -> Result<(), RoutingError> {
        let msg_content = routing_msg.content.clone();
        let msg_src = routing_msg.src.clone();
        let msg_dst = routing_msg.dst.clone();
        trace!("{:?} Got routing message {:?} from {:?} to {:?}.",
               self,
               msg_content,
               msg_src,
               msg_dst);
        match (msg_content, msg_src, msg_dst) {
            (MessageContent::GetNodeName { current_id, message_id },
             Authority::Client { client_key, proxy_node_name, peer_id },
             Authority::NaeManager(dst_name)) => {
                self.handle_get_node_name_request(current_id,
                                                  client_key,
                                                  proxy_node_name,
                                                  dst_name,
                                                  peer_id,
                                                  message_id)
            }
            (MessageContent::ExpectCloseNode { expect_id, client_auth, message_id },
             Authority::NaeManager(_),
             Authority::NaeManager(_)) => {
                self.handle_expect_close_node_request(expect_id, client_auth, message_id)
            }
            (MessageContent::GetCloseGroup(message_id), src, Authority::NaeManager(dst_name)) => {
                self.handle_get_close_group_request(src, dst_name, message_id)
            }
            (MessageContent::ConnectionInfo { encrypted_connection_info, nonce_bytes, public_id },
             src @ Authority::Client { .. },
             Authority::ManagedNode(dst_name)) => {
                self.handle_connection_info_from_client(encrypted_connection_info,
                                                        nonce_bytes,
                                                        src,
                                                        dst_name,
                                                        public_id)
            }
            (MessageContent::ConnectionInfo { encrypted_connection_info, nonce_bytes, public_id },
             Authority::ManagedNode(src_name),
             Authority::Client { .. }) |
            (MessageContent::ConnectionInfo { encrypted_connection_info, nonce_bytes, public_id },
             Authority::ManagedNode(src_name),
             Authority::ManagedNode(_)) => {
                self.handle_connection_info_from_node(encrypted_connection_info,
                                                      nonce_bytes,
                                                      src_name,
                                                      routing_msg.dst.clone(),
                                                      public_id)
            }
            (MessageContent::GetNodeNameResponse { relocated_id, close_group_ids, .. },
             Authority::NodeManager(_),
             dst) => self.handle_get_node_name_response(relocated_id, close_group_ids, dst),
            (MessageContent::GetCloseGroupResponse { close_group_ids, .. },
             Authority::ManagedNode(_),
             dst) => self.handle_get_close_group_response(close_group_ids, dst),
            (MessageContent::Ack(ack), _, _) => self.handle_ack_response(ack),
            (MessageContent::Request(request), src, dst) => {
                let event = Event::Request {
                    request: request,
                    src: src,
                    dst: dst,
                };
                let _ = self.event_sender.send(event);
                Ok(())
            }
            (MessageContent::Response(response), src, dst) => {
                let event = Event::Response {
                    response: response,
                    src: src,
                    dst: dst,
                };
                let _ = self.event_sender.send(event);
                Ok(())
            }
            _ => {
                warn!("{:?} Unhandled message {:?}", self, routing_msg);
                Err(RoutingError::BadAuthority)
            }
        }
    }

    fn handle_bootstrap_finished(&mut self) {
        debug!("{:?} Finished bootstrapping.", self);
        if self.state == State::Disconnected {
            let _ = self.event_sender.send(Event::Disconnected);
        }
    }

    fn start_listening(&mut self) -> bool {
        if self.is_listening {
            // TODO Implement a better call once fn
            return true;
        }
        self.is_listening = true;

        self.crust_service.start_service_discovery();
        match self.crust_service
            .start_listening_tcp() {
            Ok(()) => {
                info!("{:?} Running listener.", self);
                true
            }
            Err(err) => {
                error!("{:?} Failed to start listening: {:?}", self, err);
                false
            }
        }
    }

    fn handle_lost_peer(&mut self, peer_id: PeerId) {
        let _ = self.peer_mgr.remove_peer(&peer_id);
        if peer_id == self.crust_service.id() {
            error!("{:?} LostPeer fired with our crust peer id", self);
            return;
        }
        debug!("{:?} Received LostPeer - {:?}", self, peer_id);
        if self.role != Role::Client {
            self.dropped_tunnel_client(&peer_id);
            self.dropped_routing_node_connection(&peer_id);
            self.dropped_client_connection(&peer_id);
            self.dropped_tunnel_node(&peer_id);
        }
        self.dropped_bootstrap_connection(&peer_id);
    }

    fn bootstrap_identify(&mut self, peer_id: PeerId) -> Result<(), RoutingError> {
        let direct_message = DirectMessage::BootstrapIdentify {
            public_id: *self.full_id.public_id(),
            current_quorum_size: self.dynamic_quorum_size(),
        };
        self.send_direct_message(&peer_id, direct_message)
    }

    fn client_identify(&mut self, peer_id: PeerId) -> Result<(), RoutingError> {
        debug!("{:?} - Sending ClientIdentify to {:?}.", self, peer_id);

        let token = self.timer.schedule(Duration::from_secs(BOOTSTRAP_TIMEOUT_SECS));
        self.state = State::Bootstrapping(peer_id, token);

        let serialised_public_id = try!(serialisation::serialise(self.full_id.public_id()));
        let signature = sign::sign_detached(&serialised_public_id,
                                            self.full_id.signing_private_key());

        let direct_message = DirectMessage::ClientIdentify {
            serialised_public_id: serialised_public_id,
            signature: signature,
            client_restriction: self.role == Role::Client,
        };
        self.send_direct_message(&peer_id, direct_message)
    }

    fn node_identify(&mut self, peer_id: PeerId) -> Result<(), RoutingError> {
        let serialised_public_id = try!(serialisation::serialise(self.full_id.public_id()));
        let signature = sign::sign_detached(&serialised_public_id,
                                            self.full_id.signing_private_key());
        let direct_message = DirectMessage::NodeIdentify {
            serialised_public_id: serialised_public_id,
            signature: signature,
        };
        self.send_direct_message(&peer_id, direct_message)
    }

    fn send_direct_message(&mut self,
                           dst_id: &PeerId,
                           direct_message: DirectMessage)
                           -> Result<(), RoutingError> {
        self.stats.count_direct_message(&direct_message);
        let priority = direct_message.priority();
        let (message, peer_id) = if let Some(&tunnel_id) = self.tunnels.tunnel_for(dst_id) {
            let message = Message::TunnelDirect {
                content: direct_message,
                src: self.crust_service.id(),
                dst: *dst_id,
            };
            (message, tunnel_id)
        } else {
            (Message::Direct(direct_message), *dst_id)
        };
        let raw_bytes = try!(serialisation::serialise(&message));
        self.send_or_drop(&peer_id, raw_bytes, priority)
    }

    /// Sends the given `bytes` to the peer with the given Crust `PeerId`. If that results in an
    /// error, it disconnects from the peer.
    fn send_or_drop(&mut self,
                    peer_id: &PeerId,
                    bytes: Vec<u8>,
                    priority: u8)
                    -> Result<(), RoutingError> {
        if let Err(err) = self.crust_service.send(peer_id, bytes.clone(), priority) {
            info!("{:?} Connection to {:?} failed. Calling crust::Service::disconnect.",
                  self,
                  peer_id);
            self.crust_service.disconnect(peer_id);
            self.handle_lost_peer(*peer_id);
            return Err(err.into());
        }
        Ok(())
    }

    /// Adds the signed message to the statistics and returns `true` if it should be blocked due
    /// to deduplication.
    fn filter_signed_msg(&mut self, msg: &SignedMessage, peer_id: &PeerId, route: u8) -> bool {
        let hash = maidsafe_utilities::big_endian_sip_hash(msg);
        if self.send_filter.insert((hash, *peer_id, route), ()).is_some() {
            return true;
        }
        self.stats.count_routing_message(msg.routing_message());
        false
    }

    fn verify_signed_public_id(serialised_public_id: &[u8],
                               signature: &sign::Signature)
                               -> Result<PublicId, RoutingError> {
        let public_id: PublicId = try!(serialisation::deserialise(serialised_public_id));
        let public_key = public_id.signing_public_key();
        if sign::verify_detached(signature, serialised_public_id, public_key) {
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
                warn!("{:?} Connection failed: Proxy node needs a larger routing table to accept \
                       clients.",
                      self);
                let _ = self.event_sender.send(Event::Disconnected);
                Ok(())
            }
            DirectMessage::ClientToNode => {
                if self.peer_mgr.remove_client(&peer_id).is_none() {
                    warn!("{:?} Client requested ClientToNode, but is not in client map: {:?}",
                          self,
                          peer_id);
                }
                // TODO(afck): Try adding them to the routing table?
                if self.routing_table.iter().all(|node| node.peer_id != peer_id) {
                    warn!("{:?} Client requested ClientToNode, but is not in routing table: {:?}",
                          self,
                          peer_id);
                    self.disconnect_peer(&peer_id);
                }
                Ok(())
            }
            DirectMessage::ClientIdentify { ref serialised_public_id,
                                            ref signature,
                                            client_restriction } => {
                if let Ok(public_id) = Core::verify_signed_public_id(serialised_public_id,
                                                                     signature) {
                    self.handle_client_identify(public_id, peer_id, client_restriction)
                } else {
                    warn!("{:?} Signature check failed in ClientIdentify - \
                            Dropping connection {:?}",
                          self,
                          peer_id);
                    self.disconnect_peer(&peer_id);
                    Ok(())
                }
            }
            DirectMessage::NodeIdentify { ref serialised_public_id, ref signature } => {
                if let Ok(public_id) = Core::verify_signed_public_id(serialised_public_id,
                                                                     signature) {
                    self.handle_node_identify(public_id, peer_id);
                } else {
                    warn!("{:?} Signature check failed in NodeIdentify - Dropping peer {:?}",
                          self,
                          peer_id);
                    self.disconnect_peer(&peer_id);
                }
                Ok(())
            }
            DirectMessage::NewNode(public_id) => {
                trace!("{:?} Received NewNode({:?}).", self, public_id);
                if self.routing_table.need_to_add(public_id.name()) {
                    let our_name = *self.name();
                    return self.send_connection_info(public_id,
                                                     Authority::ManagedNode(our_name),
                                                     Authority::ManagedNode(*public_id.name()));
                }
                Ok(())
            }
            DirectMessage::ConnectionUnneeded(ref name) => {
                if let Some(node_info) = self.routing_table.get(name) {
                    if node_info.peer_id != peer_id {
                        error!("{:?} Received ConnectionUnneeded from {:?} with name {:?}, but \
                                that name actually belongs to {:?}.",
                               self,
                               peer_id,
                               name,
                               node_info.peer_id);
                        return Err(RoutingError::InvalidSource);
                    }
                }
                debug!("{:?} Received ConnectionUnneeded from {:?}.", self, peer_id);
                if self.routing_table.remove_if_unneeded(name) {
                    info!("{:?} Dropped {:?} from the routing table.", self, name);
                    self.crust_service.disconnect(&peer_id);
                    self.handle_lost_peer(peer_id);
                }
                Ok(())
            }
            DirectMessage::TunnelRequest(dst_id) => self.handle_tunnel_request(peer_id, dst_id),
            DirectMessage::TunnelSuccess(dst_id) => self.handle_tunnel_success(peer_id, dst_id),
            DirectMessage::TunnelClosed(dst_id) => self.handle_tunnel_closed(peer_id, dst_id),
            DirectMessage::TunnelDisconnect(dst_id) => {
                self.handle_tunnel_disconnect(peer_id, dst_id)
            }
        }
    }

    fn handle_bootstrap_identify(&mut self,
                                 public_id: PublicId,
                                 peer_id: PeerId,
                                 current_quorum_size: usize)
                                 -> Result<(), RoutingError> {
        if *public_id.name() == XorName(hash::sha256::hash(&public_id.signing_public_key().0).0) {
            warn!("{:?} Incoming Connection not validated as a proper node - dropping",
                  self);
            let _ = self.event_sender.send(Event::Disconnected);
            return Ok(());
        }

        if !self.peer_mgr.insert_proxy(peer_id, public_id) {
            self.disconnect_peer(&peer_id);
            return Ok(());
        }

        self.state = State::Client;
        debug!("{:?} - State changed to client, quorum size: {}.",
               self,
               current_quorum_size);
        self.message_accumulator.set_quorum_size(current_quorum_size);

        match self.role {
            Role::Client => {
                let _ = self.event_sender.send(Event::Connected);
            }
            Role::Node => try!(self.relocate()),
            Role::FirstNode => error!("{:?} Received BootstrapIdentify as the first node.", self),
        };
        Ok(())
    }

    fn handle_client_identify(&mut self,
                              public_id: PublicId,
                              peer_id: PeerId,
                              client_restriction: bool)
                              -> Result<(), RoutingError> {
        if *public_id.name() != XorName(hash::sha256::hash(&public_id.signing_public_key().0).0) {
            warn!("{:?} Incoming Connection not validated as a proper client - dropping",
                  self);
            self.disconnect_peer(&peer_id);
            return Ok(());
        }

        for peer_id in self.peer_mgr.remove_stale_joining_nodes() {
            debug!("{:?} Removing stale joining node with Crust ID {:?}",
                   self,
                   peer_id);
            self.disconnect_peer(&peer_id);
        }

        if (client_restriction || self.role != Role::FirstNode) &&
           self.routing_table.len() < GROUP_SIZE - 1 {
            debug!("{:?} Client {:?} rejected: Routing table has {} entries. {} required.",
                   self,
                   public_id.name(),
                   self.routing_table.len(),
                   GROUP_SIZE - 1);
            return self.send_direct_message(&peer_id, DirectMessage::BootstrapDeny);
        }
        if self.peer_mgr.get_client(&peer_id).is_some() {
            error!("{:?} Received two ClientInfo from the same peer ID {:?}.",
                   self,
                   peer_id);
        }
        self.peer_mgr.insert_client(peer_id, &public_id, client_restriction);

        debug!("{:?} Accepted client {:?}.", self, public_id.name());

        self.bootstrap_identify(peer_id)
    }

    fn handle_node_identify(&mut self, public_id: PublicId, peer_id: PeerId) {
        if self.role == Role::Client {
            debug!("{:?} Received node identify as a client.", self);
            return;
        }

        debug!("{:?} Handling NodeIdentify from {:?}.",
               self,
               public_id.name());

        if let Some((name, _)) = self.sent_network_name_to {
            if name == *public_id.name() {
                self.sent_network_name_to = None;
            }
        }

        self.add_to_routing_table(public_id, peer_id);
    }

    fn add_to_routing_table(&mut self, public_id: PublicId, peer_id: PeerId) {
        let name = *public_id.name();
        if self.routing_table.contains(&name) {
            return; // We already sent a `NodeIdentify` to this peer.
        }

        let info = NodeInfo::new(public_id, peer_id);

        let bucket_index = self.name().bucket_index(&name);
        let common_groups = self.routing_table.is_in_any_close_group_with(bucket_index, GROUP_SIZE);

        match self.routing_table.add(info) {
            None => {
                error!("{:?} Peer was not added to the routing table: {:?}",
                       self,
                       peer_id);
                self.disconnect_peer(&peer_id);
            }
            Some(AddedNodeDetails { must_notify, unneeded }) => {
                info!("{:?} Added {:?} to routing table.", self, name);
                if self.routing_table.len() == 1 {
                    let _ = self.event_sender.send(Event::Connected);
                }
                for notify_info in must_notify {
                    if let Err(error) = self.send_direct_message(&notify_info.peer_id,
                                             DirectMessage::NewNode(public_id)) {
                        error!("{:?} Failed to send NewNode: {:?}", self, error);
                    }
                }
                for node_info in unneeded {
                    let our_name = *self.name();
                    if let Err(error) = self.send_direct_message(&node_info.peer_id,
                                             DirectMessage::ConnectionUnneeded(our_name)) {
                        error!("{:?} Failed to send ConnectionUnneeded: {:?}", self, error);
                    }
                }

                self.reset_bucket_refresh_timer();

                if common_groups {
                    let event = Event::NodeAdded(name, self.routing_table.to_names());
                    if let Err(err) = self.event_sender.send(event) {
                        error!("{:?} Error sending event to routing user - {:?}", self, err);
                    }
                }
            }
        }

        if self.state != State::Node {
            self.state = State::Node;
            let tick_period = Duration::from_secs(TICK_TIMEOUT_SECS);
            self.tick_timer_token = Some(self.timer.schedule(tick_period));
        }

        if self.routing_table.len() == 1 {
            self.request_bucket_close_groups();
        }

        for (dst_id, name) in self.peer_mgr.peers_with_state(ConnectState::Tunnel) {
            let tunnel_request = DirectMessage::TunnelRequest(dst_id);
            if let Err(err) = self.send_direct_message(&peer_id, tunnel_request) {
                error!("{:?} Error requesting tunnel for {:?} from {:?} ({:?}): {:?}.",
                       self,
                       dst_id,
                       peer_id,
                       name,
                       err);
            }
        }
    }

    fn reset_bucket_refresh_timer(&mut self) {
        if let Some((_, REFRESH_BUCKET_GROUPS_SECS)) = self.bucket_refresh_token_and_delay {
            return; // Timer has already been reset.
        }
        let new_token = self.timer.schedule(Duration::from_secs(REFRESH_BUCKET_GROUPS_SECS));
        self.bucket_refresh_token_and_delay = Some((new_token, REFRESH_BUCKET_GROUPS_SECS));
    }

    /// Sends a `GetCloseGroup` request to the close group with our `bucket_index`-th bucket
    /// address.
    fn request_bucket_ids(&mut self, bucket_index: usize) -> Result<(), RoutingError> {
        if bucket_index >= XOR_NAME_BITS {
            return Ok(());
        }
        trace!("{:?} Send GetCloseGroup to bucket {}.", self, bucket_index);
        let bucket_address = self.name().with_flipped_bit(bucket_index);
        self.request_close_group(bucket_address)
    }

    fn request_close_group(&mut self, name: XorName) -> Result<(), RoutingError> {
        let request_msg = RoutingMessage {
            src: Authority::ManagedNode(*self.name()),
            dst: Authority::NaeManager(name),
            content: MessageContent::GetCloseGroup(MessageId::new()),
        };
        self.send_message(request_msg)
    }

    /// Handle a request by `peer_id` to act as a tunnel connecting it with `dst_id`.
    fn handle_tunnel_request(&mut self,
                             peer_id: PeerId,
                             dst_id: PeerId)
                             -> Result<(), RoutingError> {
        if self.routing_table.iter().any(|node| node.peer_id == peer_id) &&
           self.routing_table.iter().any(|node| node.peer_id == dst_id) {
            if let Some((id0, id1)) = self.tunnels.consider_clients(peer_id, dst_id) {
                debug!("{:?} Accepted tunnel request from {:?} for {:?}.",
                       self,
                       peer_id,
                       dst_id);
                return self.send_direct_message(&id0, DirectMessage::TunnelSuccess(id1));
            }
        } else {
            debug!("{:?} Rejected tunnel request from {:?} for {:?}.",
                   self,
                   peer_id,
                   dst_id);
        }
        Ok(())
    }

    /// Handle a `TunnelSuccess` response from `peer_id`: It will act as a tunnel to `dst_id`.
    fn handle_tunnel_success(&mut self,
                             peer_id: PeerId,
                             dst_id: PeerId)
                             -> Result<(), RoutingError> {
        if let Some((name, _)) = self.peer_mgr.remove_connecting_peer(&dst_id) {
            if self.tunnels.add(dst_id, peer_id) {
                debug!("{:?} Adding {:?} as a tunnel node for {:?}.",
                       self,
                       peer_id,
                       name);
                return self.node_identify(dst_id);
            }
        }
        Ok(())
    }

    /// Handle a `TunnelClosed` message from `peer_id`: `dst_id` disconnected.
    fn handle_tunnel_closed(&mut self,
                            peer_id: PeerId,
                            dst_id: PeerId)
                            -> Result<(), RoutingError> {
        if self.tunnels.remove(dst_id, peer_id) {
            warn!("{:?} Tunnel to {:?} via {:?} closed.",
                  self,
                  dst_id,
                  peer_id);
            self.dropped_routing_node_connection(&dst_id);
        }
        Ok(())
    }

    /// Handle a `TunnelDisconnect` message from `peer_id` who wants to disconnect `dst_id`.
    fn handle_tunnel_disconnect(&mut self,
                                peer_id: PeerId,
                                dst_id: PeerId)
                                -> Result<(), RoutingError> {
        warn!("{:?} Closing tunnel connecting {:?} and {:?}.",
              self,
              dst_id,
              peer_id);
        if self.tunnels.remove(dst_id, peer_id) {
            self.send_direct_message(&dst_id, DirectMessage::TunnelClosed(peer_id))
        } else {
            Ok(())
        }
    }

    /// Disconnects from the given peer, via Crust or by dropping the tunnel node, if the peer is
    /// not a proxy, client or routing table entry.
    fn disconnect_peer(&mut self, peer_id: &PeerId) {
        if let Some(&node) = self.routing_table.iter().find(|node| node.peer_id == *peer_id) {
            warn!("{:?} Not disconnecting routing table entry {:?} ({:?}).",
                  self,
                  node.name(),
                  peer_id);
        } else if let Some(&public_id) = self.peer_mgr.get_proxy(peer_id) {
            warn!("{:?} Not disconnecting proxy node {:?} ({:?}).",
                  self,
                  public_id.name(),
                  peer_id);
        } else if self.peer_mgr.get_client(peer_id).is_some() {
            warn!("{:?} Not disconnecting client {:?}.", self, peer_id);
        } else if let Some(tunnel_id) = self.tunnels.remove_tunnel_for(peer_id) {
            debug!("{:?} Disconnecting {:?} (indirect).", self, peer_id);
            let message = DirectMessage::TunnelDisconnect(*peer_id);
            if let Err(error) = self.send_direct_message(&tunnel_id, message) {
                error!("{:?} Failed to send TunnelDisconnect: {:?}", self, error);
            }
        } else {
            debug!("{:?} Disconnecting {:?}. Calling crust::Service::disconnect.",
                   self,
                   peer_id);
            let _ = self.crust_service.disconnect(peer_id);
            let _ = self.peer_mgr.remove_peer(peer_id);
        }
    }

    // Constructed by A; From A -> X
    fn relocate(&mut self) -> Result<(), RoutingError> {
        let duration = Duration::from_secs(GET_NODE_NAME_TIMEOUT_SECS);
        self.get_node_name_timer_token = Some(self.timer.schedule(duration));

        let request_content = MessageContent::GetNodeName {
            current_id: *self.full_id.public_id(),
            message_id: MessageId::new(),
        };

        let request_msg = RoutingMessage {
            src: try!(self.get_client_authority()),
            dst: Authority::NaeManager(*self.name()),
            content: request_content,
        };

        info!("{:?} Sending GetNodeName request with: {:?}. This can take a while.",
              self,
              self.full_id.public_id());
        self.send_message(request_msg)
    }

    // Received by X; From A -> X
    fn handle_get_node_name_request(&mut self,
                                    mut their_public_id: PublicId,
                                    client_key: sign::PublicKey,
                                    proxy_name: XorName,
                                    dst_name: XorName,
                                    peer_id: PeerId,
                                    message_id: MessageId)
                                    -> Result<(), RoutingError> {
        let hashed_key = hash::sha256::hash(&client_key.0);
        let close_group_to_client = XorName(hashed_key.0);

        // Validate Client (relocating node) has contacted the correct Group-X
        if close_group_to_client != dst_name {
            return Err(RoutingError::InvalidDestination);
        }

        let close_group = match self.routing_table.close_nodes(&dst_name, GROUP_SIZE) {
            Some(close_group) => close_group.iter().map(NodeInfo::name).cloned().collect(),
            None => return Err(RoutingError::InvalidDestination),
        };
        let relocated_name = try!(utils::calculate_relocated_name(close_group,
                                                                  &their_public_id.name()));
        their_public_id.set_name(relocated_name);

        // From X -> Y; Send to close group of the relocated name
        {
            let request_content = MessageContent::ExpectCloseNode {
                expect_id: their_public_id,
                client_auth: Authority::Client {
                    client_key: client_key,
                    proxy_node_name: proxy_name,
                    peer_id: peer_id,
                },
                message_id: message_id,
            };

            let request_msg = RoutingMessage {
                src: Authority::NaeManager(dst_name),
                dst: Authority::NaeManager(relocated_name),
                content: request_content,
            };

            self.send_message(request_msg)
        }
    }

    // Received by Y; From X -> Y
    fn handle_expect_close_node_request(&mut self,
                                        expect_id: PublicId,
                                        client_auth: Authority,
                                        message_id: MessageId)
                                        -> Result<(), RoutingError> {
        if expect_id == *self.full_id.public_id() {
            return Ok(());
        }

        let now = Instant::now();
        if let Some((_, timestamp)) = self.sent_network_name_to {
            if (now - timestamp).as_secs() <= SENT_NETWORK_NAME_TIMEOUT_SECS {
                return Err(RoutingError::RejectedGetNodeName);
            }
            self.sent_network_name_to = None;
        }


        let close_group = match self.routing_table.close_nodes(expect_id.name(), GROUP_SIZE) {
            Some(close_group) => close_group,
            None => return Err(RoutingError::InvalidDestination),
        };
        let public_ids = close_group.into_iter().map(|info| info.public_id).collect_vec();

        self.sent_network_name_to = Some((*expect_id.name(), now));
        // From Y -> A (via B)
        let response_content = MessageContent::GetNodeNameResponse {
            relocated_id: expect_id,
            close_group_ids: public_ids,
            message_id: message_id,
        };

        debug!("{:?} Responding to client {:?}: {:?}.",
               self,
               client_auth,
               response_content);

        let response_msg = RoutingMessage {
            src: Authority::NodeManager(*expect_id.name()),
            dst: client_auth,
            content: response_content,
        };

        try!(self.send_message(response_msg));

        Ok(())
    }

    // Received by A; From X -> A
    fn handle_get_node_name_response(&mut self,
                                     relocated_id: PublicId,
                                     mut close_group_ids: Vec<PublicId>,
                                     dst: Authority)
                                     -> Result<(), RoutingError> {
        self.get_node_name_timer_token = None;
        self.set_self_node_name(*relocated_id.name());
        close_group_ids.truncate(GROUP_SIZE / 2);
        // From A -> Closest in Y
        for close_node_id in close_group_ids {
            debug!("{:?} Sending connection info to {:?} on GetNodeName response.",
                   self,
                   close_node_id);
            try!(self.send_connection_info(close_node_id,
                                           dst.clone(),
                                           Authority::ManagedNode(*close_node_id.name())));
        }
        Ok(())
    }

    // Received by Y; From A -> Y, or from any node to one of its bucket addresses.
    fn handle_get_close_group_request(&mut self,
                                      src: Authority,
                                      dst_name: XorName,
                                      message_id: MessageId)
                                      -> Result<(), RoutingError> {
        // If msg is from ourselves, ignore it.
        if src.name() == self.name() {
            return Ok(());
        }

        let close_group = match self.routing_table.close_nodes(&dst_name, GROUP_SIZE) {
            Some(close_group) => close_group,
            None => return Err(RoutingError::InvalidDestination),
        };
        let public_ids = close_group.into_iter().map(|info| info.public_id).collect_vec();

        trace!("{:?} Sending GetCloseGroup response with {:?} to client {:?}.",
               self,
               public_ids.iter().map(PublicId::name).collect_vec(),
               src);
        let response_content = MessageContent::GetCloseGroupResponse {
            close_group_ids: public_ids,
            message_id: message_id,
        };

        let response_msg = RoutingMessage {
            src: Authority::ManagedNode(*self.name()),
            dst: src,
            content: response_content,
        };

        self.send_message(response_msg)
    }

    fn handle_get_close_group_response(&mut self,
                                       close_group_ids: Vec<PublicId>,
                                       dst: Authority)
                                       -> Result<(), RoutingError> {
        for close_node_id in close_group_ids {
            if self.routing_table.need_to_add(close_node_id.name()) {
                debug!("{:?} Sending connection info to {:?} on GetCloseGroup response.",
                       self,
                       close_node_id);
                try!(self.send_connection_info(close_node_id,
                                               dst.clone(),
                                               Authority::ManagedNode(*close_node_id.name())));
            } else {
                trace!("{:?} Routing table does not need {:?}.",
                       self,
                       close_node_id);
            }
        }

        Ok(())
    }

    fn handle_ack_response(&mut self, ack: u64) -> Result<(), RoutingError> {
        if self.pending_acks.remove(&ack).is_none() {
            let _ = self.received_acks.insert(&ack);
        }
        Ok(())
    }

    fn handle_connection_info_from_client(&mut self,
                                          encrypted_connection_info: Vec<u8>,
                                          nonce_bytes: [u8; box_::NONCEBYTES],
                                          src: Authority,
                                          dst_name: XorName,
                                          their_public_id: PublicId)
                                          -> Result<(), RoutingError> {
        try!(self.check_address_for_routing_table(their_public_id.name()));
        self.connect(encrypted_connection_info,
                     nonce_bytes,
                     their_public_id,
                     Authority::ManagedNode(dst_name),
                     src)
    }

    fn handle_connection_info_from_node(&mut self,
                                        encrypted_connection_info: Vec<u8>,
                                        nonce_bytes: [u8; box_::NONCEBYTES],
                                        src_name: XorName,
                                        dst: Authority,
                                        their_public_id: PublicId)
                                        -> Result<(), RoutingError> {
        try!(self.check_address_for_routing_table(&src_name));
        self.connect(encrypted_connection_info,
                     nonce_bytes,
                     their_public_id,
                     dst,
                     Authority::ManagedNode(src_name))
    }

    // ---- Connect Requests and Responses --------------------------------------------------------

    fn send_connection_info(&mut self,
                            their_public_id: PublicId,
                            src: Authority,
                            dst: Authority)
                            -> Result<(), RoutingError> {
        if let Some(peer_id) = self.peer_mgr.get_proxy_or_client_peer_id(&their_public_id) {
            try!(self.node_identify(peer_id));
            self.handle_node_identify(their_public_id, peer_id);
        } else if !self.routing_table.contains(their_public_id.name()) &&
           self.routing_table.allow_connection(their_public_id.name()) {
            if self.peer_mgr
                .connection_token_map
                .peek_iter()
                .any(|(_, &(ref public_id, _, _))| *public_id == their_public_id) ||
               self.peer_mgr.our_connection_info_map.contains_key(&their_public_id) ||
               self.peer_mgr.connecting_peer_state(their_public_id.name()) ==
               Some(ConnectState::Crust) {
                debug!("{:?} Already sent connection info to {:?}!",
                       self,
                       their_public_id.name());
            } else {
                let token = rand::random();
                self.crust_service.prepare_connection_info(token);
                let _ =
                    self.peer_mgr.connection_token_map.insert(token, (their_public_id, src, dst));
            }
        }
        Ok(())
    }

    fn handle_timeout(&mut self, token: u64) {
        // We haven't received response from a node we are trying to bootstrap against.
        if let State::Bootstrapping(peer_id, bootstrap_token) = self.state {
            if bootstrap_token == token {
                debug!("{:?} Timeout when trying to bootstrap against {:?}.",
                       self,
                       peer_id);
                let _ = self.event_sender.send(Event::Disconnected);
            }
            return;
        }
        if self.get_node_name_timer_token == Some(token) {
            error!("{:?} Failed to get GetNodeName response.", self);
            let _ = self.event_sender.send(Event::GetNodeNameFailed);
            return;
        }
        if self.tick_timer_token == Some(token) {
            let _ = self.event_sender.send(Event::Tick);
            let tick_period = Duration::from_secs(TICK_TIMEOUT_SECS);
            self.tick_timer_token = Some(self.timer.schedule(tick_period));
            return;
        }
        if let Some((bucket_token, delay)) = self.bucket_refresh_token_and_delay {
            if bucket_token == token {
                self.request_bucket_close_groups();
                let new_delay = delay.saturating_mul(2);
                let new_token = self.timer.schedule(Duration::from_secs(new_delay));
                self.bucket_refresh_token_and_delay = Some((new_token, new_delay));
                return;
            }
        }
        let timed_out_ack = if let Some((sip_hash, _)) = self.pending_acks
            .iter()
            .find(|&(_, ref unacked_msg)| unacked_msg.timer_token == token) {
            Some(*sip_hash)
        } else {
            None
        };
        if let Some(timed_out) = timed_out_ack {
            // Safe to use `expect` here as we just got a valid key in the `find` call above.
            let mut unacked_msg = self.pending_acks.remove(&timed_out).expect("Bug in HashMap.");
            trace!("{:?} - Timed out waiting for ack({}) {:?}",
                   self,
                   timed_out,
                   unacked_msg);
            unacked_msg.route += 1;
            // If we've tried all `GROUP_SIZE` routes, give up.  Otherwise resend on next route.
            if unacked_msg.route as usize == GROUP_SIZE {
                info!("{:?} - Message unable to be acknowledged - giving up. {:?}",
                      self,
                      unacked_msg);
            } else {
                let hop = *self.name();
                let _ = self.send(&unacked_msg.signed_msg, unacked_msg.route, &hop, &[hop]);
            }
        }
    }

    /// Sends `GetCloseGroup` requests to all incompletely filled buckets and our own address.
    fn request_bucket_close_groups(&mut self) {
        if !self.bucket_filter.contains(&XOR_NAME_BITS) {
            let _ = self.bucket_filter.insert(&XOR_NAME_BITS);
            let our_name = *self.name();
            if let Err(err) = self.request_close_group(our_name) {
                error!("{:?} Failed to request our own close group: {:?}",
                       self,
                       err);
            }
        }
        for index in 0..self.routing_table.bucket_count() {
            if self.routing_table.bucket_len(index) < GROUP_SIZE &&
               !self.bucket_filter.contains(&index) {
                let _ = self.bucket_filter.insert(&index);
                if let Err(err) = self.request_bucket_ids(index) {
                    error!("{:?} Failed to request public IDs from bucket {}: {:?}.",
                           self,
                           index,
                           err);
                }
            }
        }
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

        let serialised_connection_info =
            try!(decipher_result.map_err(|()| RoutingError::AsymmetricDecryptionFailure));
        let their_connection_info: TheirConnectionInfo =
            try!(serialisation::deserialise(&serialised_connection_info));

        if let Some(our_connection_info) = self.peer_mgr
            .our_connection_info_map
            .remove(&their_public_id) {
            let peer_id = their_connection_info.id();
            let their_name = *their_public_id.name();
            if let Some((name, _)) = self.peer_mgr
                .insert_connecting_peer(peer_id, their_name, ConnectState::Crust) {
                warn!("{:?} Prepared connection info for {:?} as {:?}, but already tried as {:?}.",
                      self,
                      peer_id,
                      their_name,
                      name);
            }
            debug!("{:?} Received connection info. Trying to connect to {:?} as {:?}.",
                   self,
                   peer_id,
                   their_public_id.name());
            self.crust_service.connect(our_connection_info, their_connection_info);
            Ok(())
        } else {
            let _ = self.peer_mgr
                .their_connection_info_map
                .insert(their_public_id, their_connection_info);
            self.send_connection_info(their_public_id, src, dst)
        }
    }

    // ----- Send Functions -----------------------------------------------------------------------

    fn send_message(&mut self, routing_msg: RoutingMessage) -> Result<(), RoutingError> {
        // TODO crust should return the routing msg when it detects an interface error
        let signed_msg = try!(SignedMessage::new(routing_msg.clone(), &self.full_id));
        let hop = *self.name();
        try!(self.send(&signed_msg, 0, &hop, &[hop]));
        self.handle_sent_message(&signed_msg)
    }

    fn relay_to_client(&mut self,
                       signed_msg: SignedMessage,
                       peer_id: &PeerId)
                       -> Result<(), RoutingError> {
        let priority = signed_msg.priority();
        if self.peer_mgr.get_client(peer_id).is_some() {
            if self.filter_signed_msg(&signed_msg, peer_id, 0) {
                return Ok(());
            }
            let hop_msg =
                try!(HopMessage::new(signed_msg, 0, vec![], self.full_id.signing_private_key()));
            let message = Message::Hop(hop_msg);
            let raw_bytes = try!(serialisation::serialise(&message));
            self.send_or_drop(peer_id, raw_bytes, priority)
        } else {
            // Acknowledge the message so that the sender doesn't retry.
            let hop = *self.name();
            self.send_ack_from(signed_msg.routing_message(), 0, Authority::ManagedNode(hop));
            debug!("{:?} Client connection not found for message {:?}.",
                   self,
                   signed_msg);
            Err(RoutingError::ClientConnectionNotFound)
        }
    }

    fn to_hop_bytes(&self,
                    signed_msg: SignedMessage,
                    route: u8,
                    sent_to: Vec<XorName>)
                    -> Result<Vec<u8>, RoutingError> {
        let hop_msg = try!(HopMessage::new(signed_msg,
                                           route,
                                           sent_to,
                                           self.full_id.signing_private_key()));
        let message = Message::Hop(hop_msg);
        Ok(try!(serialisation::serialise(&message)))
    }

    fn to_tunnel_hop_bytes(&self,
                           signed_msg: SignedMessage,
                           route: u8,
                           sent_to: Vec<XorName>,
                           src: PeerId,
                           dst: PeerId)
                           -> Result<Vec<u8>, RoutingError> {
        let hop_msg = try!(HopMessage::new(signed_msg.clone(),
                                           route,
                                           sent_to,
                                           self.full_id.signing_private_key()));
        let message = Message::TunnelHop {
            content: hop_msg,
            src: src,
            dst: dst,
        };
        Ok(try!(serialisation::serialise(&message)))
    }

    fn send(&mut self,
            signed_msg: &SignedMessage,
            route: u8,
            hop: &XorName,
            sent_to: &[XorName])
            -> Result<(), RoutingError> {
        let (new_sent_to, target_peer_ids) =
            try!(self.get_targets(signed_msg.routing_message(), route, hop, sent_to));

        if !self.add_to_pending_acks(signed_msg, route) {
            return Ok(());
        }
        let raw_bytes = try!(self.to_hop_bytes(signed_msg.clone(), route, new_sent_to.clone()));
        for target_peer_id in target_peer_ids {
            let (peer_id, bytes) = match self.tunnels.tunnel_for(&target_peer_id) {
                None => (target_peer_id, raw_bytes.clone()),
                Some(&tunnel_id) => {
                    let bytes = try!(self.to_tunnel_hop_bytes(signed_msg.clone(),
                                                              route,
                                                              new_sent_to.clone(),
                                                              self.crust_service.id(),
                                                              target_peer_id));
                    (tunnel_id, bytes)
                }
            };
            if !self.filter_signed_msg(signed_msg, &target_peer_id, route) {
                if let Err(err) = self.send_or_drop(&peer_id, bytes, signed_msg.priority()) {
                    info!("{:?} Error sending message to {:?}: {:?}.",
                          self,
                          target_peer_id,
                          err);
                }
            }
        }
        Ok(())
    }

    /// If we are a node and the recipient, handle the given message.
    fn handle_sent_message(&mut self, signed_msg: &SignedMessage) -> Result<(), RoutingError> {
        // If we need to handle this message, handle it.
        if self.is_recipient(&signed_msg.routing_message().dst) &&
           self.signed_message_filter.insert(signed_msg) == 1 {
            self.handle_signed_message_for_node(signed_msg)
        } else {
            Ok(())
        }
    }

    /// Returns whether we are the recipient of a message for the given authority.
    fn is_recipient(&self, dst: &Authority) -> bool {
        match self.state {
            State::Node => self.routing_table.is_recipient(dst.to_destination()),
            State::Client => {
                if let Authority::Client { ref client_key, .. } = *dst {
                    client_key == self.full_id.public_id().signing_public_key()
                } else {
                    false
                }
            }
            State::Disconnected |
            State::Bootstrapping(..) => false,
        }
    }

    /// Returns a `sent_to` entry for the next hop message, and a list of target peer IDs.
    fn get_targets(&self,
                   routing_msg: &RoutingMessage,
                   route: u8,
                   hop: &XorName,
                   sent_to: &[XorName])
                   -> Result<(Vec<XorName>, Vec<PeerId>), RoutingError> {
        match self.state {
            State::Disconnected |
            State::Bootstrapping(_, _) => {
                error!("{:?} - Tried to send message in state {:?}",
                       self,
                       self.state);
                Err(RoutingError::NotBootstrapped)
            }
            State::Client => {
                // If we're a client going to be a node, send via our bootstrap connection.
                if let Authority::Client { ref proxy_node_name, .. } = routing_msg.src {
                    if let Some(&peer_id) = self.peer_mgr.get_proxy_peer_id(proxy_node_name) {
                        Ok((vec![], vec![peer_id]))
                    } else {
                        error!("{:?} - Unable to find connection to proxy node in proxy map",
                               self);
                        Err(RoutingError::ProxyConnectionNotFound)
                    }
                } else {
                    error!("{:?} - Source should be client if our state is a Client",
                           self);
                    Err(RoutingError::InvalidSource)
                }
            }
            State::Node => {
                let destination = routing_msg.dst.to_destination();
                let targets = self.routing_table
                    .target_nodes(destination, hop, route as usize)
                    .into_iter()
                    .filter(|target| !sent_to.contains(target.name()))
                    .collect_vec();
                let new_sent_to = sent_to.iter()
                    .chain(targets.iter().map(NodeInfo::name))
                    .cloned()
                    .collect_vec();
                Ok((new_sent_to, targets.into_iter().map(|target| target.peer_id).collect()))
            }
        }
    }

    fn send_ack(&mut self, routing_msg: &RoutingMessage, route: u8) {
        self.send_ack_from(routing_msg, route, routing_msg.dst.clone());
    }

    fn send_ack_from(&mut self, routing_msg: &RoutingMessage, route: u8, src: Authority) {
        if let MessageContent::Ack(_) = routing_msg.content {
            return;
        }
        let response = RoutingMessage {
            src: src,
            dst: routing_msg.src.clone(),
            content: MessageContent::Ack(maidsafe_utilities::big_endian_sip_hash(&routing_msg)),
        };

        let signed_msg = match SignedMessage::new(response, &self.full_id) {
            Ok(signed_msg) => signed_msg,
            Err(error) => {
                error!("{:?} Failed to create ack message: {:?}", self, error);
                return;
            }
        };
        let hop = *self.name();
        if let Err(error) = self.send(&signed_msg, route, &hop, &[hop]) {
            error!("{:?} Failed to ack: {:?}", self, error);
        }
        if let Err(error) = self.handle_sent_message(&signed_msg) {
            error!("{:?} Failed to handle ack: {:?}", self, error);
        }
    }

    /// Adds the given message to the pending acks, if it has not already been received.
    ///
    /// Returns whether the message should actually be sent. This is always `true` except if the
    /// ack for this message has already been received.
    fn add_to_pending_acks(&mut self, signed_msg: &SignedMessage, route: u8) -> bool {
        // If this is not an ack and we're the source, expect to receive an ack for this.
        if let MessageContent::Ack(_) = signed_msg.routing_message().content {
            return true;
        }

        if *signed_msg.public_id() != *self.full_id.public_id() {
            return true;
        }

        let ack = maidsafe_utilities::big_endian_sip_hash(signed_msg.routing_message());
        if self.received_acks.contains(&ack) {
            return false;
        }

        let token = self.timer.schedule(Duration::from_secs(ACK_TIMEOUT_SECS));
        let unacked_msg = UnacknowledgedMessage {
            signed_msg: signed_msg.clone(),
            route: route,
            timer_token: token,
        };

        if let Some(ejected) = self.pending_acks.insert(ack, unacked_msg) {
            // FIXME: This currently occurs for Connect request and
            // GetNodeName response. Connect requests arent filtered which
            // should get resolved with peer_mgr completion.
            // GetNodeName response resends from a node needs to get looked into.
            trace!("{:?} Ejected pending ack: {:?} - {:?}", self, ack, ejected);
        }
        true
    }

    fn get_client_authority(&self) -> Result<Authority, RoutingError> {
        match self.peer_mgr.default_proxy() {
            Some(bootstrap_pub_id) => {
                Ok(Authority::Client {
                    client_key: *self.full_id.public_id().signing_public_key(),
                    proxy_node_name: *bootstrap_pub_id.name(),
                    peer_id: self.crust_service.id(),
                })
            }
            None => Err(RoutingError::NotBootstrapped),
        }
    }

    // set our network name while transitioning to a node
    // If called more than once with a unique name, this function will assert
    fn set_self_node_name(&mut self, new_name: XorName) {
        // Validating this function doesn't run more that once
        assert!(XorName(hash::sha256::hash(&self.full_id.public_id().signing_public_key().0).0) !=
                new_name);

        self.full_id.public_id_mut().set_name(new_name);
        let our_info = NodeInfo::new(*self.full_id.public_id(), self.crust_service.id());
        self.routing_table = RoutingTable::new(our_info, GROUP_SIZE, EXTRA_BUCKET_ENTRIES);
    }

    fn dropped_client_connection(&mut self, peer_id: &PeerId) {
        if let Some(info) = self.peer_mgr.remove_client(peer_id) {
            if info.client_restriction {
                debug!("{:?} Client disconnected: {:?}", self, peer_id);
            } else {
                debug!("{:?} Joining node {:?} dropped. {} remaining.",
                       self,
                       peer_id,
                       self.peer_mgr.joining_nodes_num());
            }
        }
    }

    fn dropped_bootstrap_connection(&mut self, peer_id: &PeerId) {
        if let Some(public_id) = self.peer_mgr.remove_proxy(peer_id) {
            debug!("{:?} Lost bootstrap connection to {:?} ({:?}).",
                   self,
                   public_id.name(),
                   peer_id);
            if self.peer_mgr.default_proxy().is_none() {
                debug!("{:?} Lost connection to last proxy node {:?}",
                       self,
                       peer_id);
                if self.role == Role::Client {
                    let _ = self.event_sender.send(Event::Disconnected);
                }
            }
        }
    }

    fn dropped_tunnel_client(&mut self, peer_id: &PeerId) {
        for other_id in self.tunnels.drop_client(peer_id) {
            let message = DirectMessage::TunnelClosed(*peer_id);
            if let Err(err) = self.send_direct_message(&other_id, message) {
                error!("{:?} Error sending TunnelClosed info to {:?}: {:?}.",
                       self,
                       other_id,
                       err);
            }
        }
    }

    fn dropped_tunnel_node(&mut self, peer_id: &PeerId) {
        let peers = self.tunnels
            .remove_tunnel(peer_id)
            .into_iter()
            .filter_map(|dst_id| {
                self.routing_table
                    .iter()
                    .find(|node| node.peer_id == dst_id)
                    .map(|&node| (dst_id, node))
            })
            .collect_vec();
        for (dst_id, node) in peers {
            self.dropped_routing_node_connection(&dst_id);
            warn!("{:?} Lost tunnel for peer {:?} ({:?}). Requesting new tunnel.",
                  self,
                  dst_id,
                  node.name());
            self.find_tunnel_for_peer(dst_id, *node.name());
        }
    }

    fn dropped_routing_node_connection(&mut self, peer_id: &PeerId) {
        if let Some(&node) = self.routing_table.iter().find(|node| node.peer_id == *peer_id) {
            if let Some(DroppedNodeDetails { incomplete_bucket }) = self.routing_table
                .remove(node.name()) {
                info!("{:?} Dropped {:?} from the routing table.",
                      self,
                      node.name());

                let common_groups = self.routing_table
                    .is_in_any_close_group_with(self.name().bucket_index(node.name()), GROUP_SIZE);
                if common_groups {
                    // If the lost node shared some close group with us, send a NodeLost event.
                    let event = Event::NodeLost(*node.name(), self.routing_table.to_names());
                    if let Err(err) = self.event_sender.send(event) {
                        error!("{:?} Error sending event to routing user - {:?}", self, err);
                    }
                }
                if let Some(bucket_index) = incomplete_bucket {
                    if let Err(e) = self.request_bucket_ids(bucket_index) {
                        debug!("{:?} Failed to request replacement connection_info from bucket \
                                {}: {:?}.",
                               self,
                               bucket_index,
                               e);
                    }
                }
                if self.routing_table.len() < GROUP_SIZE - 1 {
                    debug!("{:?} Lost connection, less than {} remaining.",
                           self,
                           GROUP_SIZE - 1);
                    let _ = self.event_sender.send(Event::Disconnected);
                }
                self.reset_bucket_refresh_timer();
            }
        };
    }

    /// Checks whether the given `name` is allowed to be added to our routing table or is already
    /// there. If not, returns an error.
    fn check_address_for_routing_table(&self, name: &XorName) -> Result<(), RoutingError> {
        if !self.routing_table.contains(name) && self.routing_table.allow_connection(name) {
            Ok(())
        } else {
            Err(RoutingError::RefusedFromRoutingTable)
        }
    }
}

impl Debug for Core {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{:?}({})", self.state, self.name())
    }
}
