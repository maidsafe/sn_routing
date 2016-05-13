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
use kademlia_routing_table::{AddedNodeDetails, ContactInfo, DroppedNodeDetails, GROUP_SIZE,
                             PARALLELISM};
use lru_time_cache::LruCache;
use maidsafe_utilities::event_sender::MaidSafeEventCategory;
use maidsafe_utilities::serialisation;
use message_filter::MessageFilter;
use rand;
use sodiumoxide::crypto::{box_, hash, sign};
use std::io;
use std::iter;
use std::collections::HashMap;
use std::fmt;
use std::fmt::{Debug, Formatter};
use std::hash::{Hash, Hasher, SipHasher};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};
use tunnels::Tunnels;
use xor_name;
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
use messages::{DirectMessage, HopMessage, Message, RequestContent, RequestMessage,
               ResponseContent, ResponseMessage, RoutingMessage, SignedMessage};
use utils;

/// Time (in seconds) after which a joining node will get dropped from the map
/// of joining nodes.
const JOINING_NODE_TIMEOUT_SECS: u64 = 300;

/// Time (in seconds) after which bootstrap is cancelled (and possibly retried).
const BOOTSTRAP_TIMEOUT_SECS: u64 = 20;
/// Time (in seconds) after which a `GetNetworkName` request is resent.
const GET_NETWORK_NAME_TIMEOUT_SECS: u64 = 60;
/// Time (in seconds) after which a `Tick` event is sent.
const TICK_TIMEOUT_SECS: u64 = 60;
/// Time (in seconds) the new close group waits for a joining node it sent a network name to.
const SENT_NETWORK_NAME_TIMEOUT_SECS: u64 = 30;
/// Initial period for requesting bucket close groups of all non-full buckets. This is doubled each
/// time.
const REFRESH_BUCKET_GROUPS_SECS: u64 = 120;

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

/// The state of a peer we are trying to connect to.
#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
enum ConnectState {
    /// We called `crust::Service::connect` and are waiting for a `NewPeer` event.
    Crust,
    /// Crust connection has failed; try to find a tunnel node.
    Tunnel,
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
    fn name(&self) -> &XorName {
        self.public_id.name()
    }
}

/// Info about client a proxy kept in a proxy node.
struct ClientInfo {
    public_key: sign::PublicKey,
    client_restriction: bool,
    timestamp: Instant,
}

impl ClientInfo {
    fn new(public_key: sign::PublicKey, client_restriction: bool) -> Self {
        ClientInfo {
            public_key: public_key,
            client_restriction: client_restriction,
            timestamp: Instant::now(),
        }
    }

    fn is_stale(&self) -> bool {
        !self.client_restriction &&
        self.timestamp.elapsed() > Duration::from_secs(JOINING_NODE_TIMEOUT_SECS)
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
/// of A's current name. X computes a new name and sends it in an `ExpectCloseNode` request to  the
/// `NaeManager` Y of A's new name. Each member of Y caches A's public ID, and Y sends a
/// `GetNetworkName` response back to A, which includes the public IDs of the members of Y.
///
///
/// ### Connecting to the close group
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
    crust_service: Service,
    role: Role,
    is_listening: bool,
    category_rx: mpsc::Receiver<MaidSafeEventCategory>,
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
    routing_table: RoutingTable,
    get_network_name_timer_token: Option<u64>,
    bucket_refresh_token_and_delay: Option<(u64, u64)>,
    /// The last joining node we have sent a `GetNetworkName` response to, and when.
    sent_network_name_to: Option<(XorName, Instant)>,
    tick_timer_token: Option<u64>,

    // our bootstrap connections
    proxy_map: HashMap<PeerId, PublicId>,
    // any clients we have proxying through us, and whether they have `client_restriction`
    client_map: HashMap<PeerId, ClientInfo>,
    /// All directly connected peers (proxies, clients and routing nodes), and the timestamps of
    /// their most recent message.
    peer_map: HashMap<PeerId, Instant>,
    use_data_cache: bool,
    data_cache: LruCache<XorName, Data>,
    // TODO(afck): Move these three fields into their own struct.
    connection_token_map: LruCache<u32, (PublicId, Authority, Authority)>,
    our_connection_info_map: LruCache<PublicId, OurConnectionInfo>,
    their_connection_info_map: LruCache<PublicId, TheirConnectionInfo>,

    /// Maps the ID of a peer we are currently trying to connect to to their name.
    connecting_peers: LruCache<PeerId, (XorName, ConnectState)>,
    tunnels: Tunnels,
    stats: Stats,
    send_filter: LruCache<(u64, PeerId), ()>,
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
        let action_sender = RoutingActionSender::new(action_tx,
                                                     routing_event_category,
                                                     category_tx.clone());
        let action_sender2 = action_sender.clone();

        let crust_event_category = MaidSafeEventCategory::Crust;
        let crust_sender = crust::CrustEventSender::new(crust_tx,
                                                        crust_event_category,
                                                        category_tx);

        // TODO(afck): Add the listening port to the Service constructor.
        let crust_service = match Service::new(crust_sender.clone()) {
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
            crust_sender: crust_sender,
            timer: Timer::new(action_sender2),
            signed_message_filter: MessageFilter::with_expiry_duration(Duration::from_secs(60 *
                                                                                           20)),
            // TODO Needs further discussion on interval
            bucket_filter: MessageFilter::with_expiry_duration(Duration::from_secs(60)),
            node_id_cache: LruCache::with_expiry_duration(Duration::from_secs(60 * 10)),
            message_accumulator: Accumulator::with_duration(1, Duration::from_secs(60 * 20)),
            grp_msg_filter: MessageFilter::with_expiry_duration(Duration::from_secs(60 * 20)),
            full_id: full_id,
            state: State::Disconnected,
            routing_table: RoutingTable::new(our_info),
            get_network_name_timer_token: None,
            bucket_refresh_token_and_delay: None,
            sent_network_name_to: None,
            tick_timer_token: None,
            proxy_map: HashMap::new(),
            client_map: HashMap::new(),
            peer_map: HashMap::new(),
            use_data_cache: use_data_cache,
            data_cache: LruCache::with_capacity(100),
            connection_token_map: LruCache::with_expiry_duration(Duration::from_secs(90)),
            our_connection_info_map: LruCache::with_expiry_duration(Duration::from_secs(90)),
            their_connection_info_map: LruCache::with_expiry_duration(Duration::from_secs(90)),
            connecting_peers: LruCache::with_expiry_duration(Duration::from_secs(90)),
            tunnels: Default::default(),
            stats: Default::default(),
            send_filter: LruCache::with_expiry_duration(Duration::from_secs(60 * 10)),
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
            .other_close_nodes(self.name())
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

    fn update_stats(&mut self) {
        if self.state == State::Node {
            let old_client_num = self.stats.cur_client_num;
            self.stats.cur_client_num = self.client_map.len() - self.joining_nodes_num();
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
                    return false;
                }
            }
            Action::CloseGroup { name, result_tx } => {
                let close_group = self.routing_table
                                      .close_nodes(&name)
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
                if result_tx.send(self.routing_table.dynamic_quorum_size()).is_err() {
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
            error!("Received BootstrapConnect as the first node.");
            let _ = self.disconnect_peer(&peer_id);
            return;
        }
        let _ = self.peer_map.insert(peer_id, Instant::now());
        self.crust_service.stop_bootstrap();
        match self.state {
            State::Disconnected => {
                if self.role == Role::Node {
                    let _ = self.start_listening();
                }
                debug!("Received BootstrapConnect from {:?}.", peer_id);
                // Established connection. Pending Validity checks
                let _ = self.client_identify(peer_id);
            }
            State::Bootstrapping(bootstrap_id, _) if bootstrap_id == peer_id => {
                warn!("Got more than one BootstrapConnect for peer {:?}.", peer_id);
            }
            _ => {
                if let Err(err) = self.disconnect_peer(&peer_id) {
                    warn!("Failed to disconnect peer {:?}: {:?}.", peer_id, err);
                }
            }
        }
    }

    fn start_new_network(&mut self) {
        self.crust_service.stop_bootstrap();
        let _ = self.start_listening();
        let new_name = XorName::new(hash::sha512::hash(&self.full_id.public_id().name().0).0);
        self.set_self_node_name(new_name);
        self.state = State::Node;
        let tick_period = Duration::from_secs(TICK_TIMEOUT_SECS);
        self.tick_timer_token = Some(self.timer.schedule(tick_period));
        info!("{:?} - Started a new network as a seed node.", self)
    }

    fn handle_bootstrap_accept(&mut self, peer_id: PeerId) {
        let _ = self.peer_map.insert(peer_id, Instant::now());
        trace!("{:?} Received BootstrapAccept from {:?}.", self, peer_id);
        // TODO: Keep track of that peer to make sure we receive a message from them.
    }

    fn handle_new_peer(&mut self, result: io::Result<()>, peer_id: PeerId) {
        if peer_id == self.crust_service.id() {
            error!("NewPeer fired with our crust peer id");
            return;
        }
        if self.role == Role::Client {
            warn!("{:?} Received NewPeer event as a client.", self);
        } else {
            match result {
                Ok(()) => {
                    if self.connecting_peers.remove(&peer_id).is_none() {
                        warn!("Received NewPeer from {:?}, but was not expecting connection.",
                              peer_id);
                        // TODO: Crust should not connect before both sides have called connect.
                        // return;
                    }
                    // TODO(afck): Keep track of this connection: Disconnect if we don't receive a
                    // NodeIdentify.
                    if let Some(node) = self.routing_table.find(|node| node.peer_id == peer_id) {
                        warn!("Received NewPeer from {:?}, but node {:?} is already in our \
                               routing table.",
                              peer_id,
                              node.name());
                        return;
                    }
                    debug!("Received NewPeer with Ok from {:?}. Sending NodeIdentify.",
                           peer_id);
                    let _ = self.peer_map.insert(peer_id, Instant::now());
                    let _ = self.node_identify(peer_id);
                }
                Err(err) => {
                    if self.routing_table.find(|node| node.peer_id == peer_id).is_none() {
                        warn!("{:?} Failed to connect to peer {:?}: {:?}.",
                              self,
                              peer_id,
                              err);
                        if let Some(&(name, ConnectState::Crust)) = self.connecting_peers
                                                                        .get(&peer_id) {
                            self.find_tunnel_for_peer(peer_id, name);
                        }
                    }
                }
            }
        }
    }

    fn find_tunnel_for_peer(&mut self, peer_id: PeerId, name: XorName) {
        let _ = self.connecting_peers.insert(peer_id, (name, ConnectState::Tunnel));
        for node in self.routing_table.closest_nodes_to(&name, GROUP_SIZE, false) {
            trace!("Asking {:?} to serve as a tunnel.", node.name());
            let tunnel_request = DirectMessage::TunnelRequest(peer_id);
            if let Err(err) = self.send_direct_message(&node.peer_id, tunnel_request) {
                error!("Failed to send tunnel request: {:?}.", err);
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
                                                                   .remove(&result_token) {
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

        let their_name = *their_public_id.name();
        if let Some(their_connection_info) = self.their_connection_info_map
                                                 .remove(&their_public_id) {
            let peer_id = their_connection_info.id();
            if let Some((name, _)) = self.connecting_peers
                                         .insert(peer_id, (their_name, ConnectState::Crust)) {
                warn!("Prepared connection info for {:?} as {:?}, but already tried as {:?}.",
                      peer_id,
                      their_name,
                      name);
            }
            debug!("Trying to connect to {:?} as {:?}.", peer_id, their_name);
            self.crust_service.connect(our_connection_info, their_connection_info);
        } else {
            let _ = self.our_connection_info_map.insert(their_public_id, our_connection_info);
            debug!("Prepared connection info for {:?}.", their_name);
        }

        let request_content = RequestContent::ConnectionInfo {
            encrypted_connection_info: encrypted_connection_info,
            nonce_bytes: nonce.0,
            public_id: *self.full_id.public_id(),
        };

        let request_msg = RequestMessage {
            src: src,
            dst: dst,
            content: request_content,
        };

        if let Err(err) = self.send_request(request_msg) {
            error!("Failed to send connection info for {:?}: {:?}.",
                   their_name,
                   err);
        }
    }

    fn handle_new_message(&mut self, peer_id: PeerId, bytes: Vec<u8>) -> Result<(), RoutingError> {
        match self.peer_map.get_mut(&peer_id) {
            None => return Err(RoutingError::UnknownConnection(peer_id)),
            Some(timestamp) => *timestamp = Instant::now(),
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
            if let Some(info) = self.routing_table.find(|node| node.peer_id == peer_id) {
                try!(hop_msg.verify(info.public_id.signing_public_key()));
                // try!(self.check_direction(hop_msg));
                hop_name = *info.name();
            } else if let Some(client_info) = self.client_map.get(&peer_id) {
                try!(hop_msg.verify(&client_info.public_key));
                if client_info.client_restriction {
                    try!(self.check_not_get_network_name(hop_msg.content().content()));
                }
                hop_name = *self.name();
            } else if let Some(pub_id) = self.proxy_map.get(&peer_id) {
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
            if let Some(pub_id) = self.proxy_map.get(&peer_id) {
                try!(hop_msg.verify(pub_id.signing_public_key()));
                hop_name = *pub_id.name();
            } else {
                return Err(RoutingError::UnknownConnection(peer_id));
            }
        } else {
            return Err(RoutingError::InvalidStateForOperation);
        }

        self.handle_signed_message(hop_msg.content(), &hop_name, hop_msg.sent_to())
    }

    fn check_not_get_network_name(&self, msg: &RoutingMessage) -> Result<(), RoutingError> {
        match *msg {
            RoutingMessage::Request(RequestMessage {
                content: RequestContent::GetNetworkName { .. },
                ..
            }) => {
                debug!("Illegitimate GetNetworkName request. Refusing to relay.");
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
    fn _check_direction(&self,
                        hop_name: &XorName,
                        hop_msg: &HopMessage)
                        -> Result<(), RoutingError> {
        let dst = hop_msg.content().content().dst();
        if self._is_swarm(dst, hop_name) ||
           !xor_name::closer_to_target(hop_name, self.name(), dst.name()) {
            Ok(())
        } else {
            debug!("Direction check failed in hop message from node {:?}: {:?}",
                   hop_name,
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
                             hop_name: &XorName,
                             sent_to: &[XorName])
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
                if let RoutingMessage::Request(RequestMessage {
                        content: RequestContent::ConnectionInfo { .. },
                        ..
                    }) = *signed_msg.content() {
                     return self.handle_signed_message_for_client(signed_msg);
                }
            }
        }

        match self.state {
            State::Node => self.handle_signed_message_for_node(signed_msg, hop_name, sent_to, true),
            State::Client => self.handle_signed_message_for_client(signed_msg),
            _ => Err(RoutingError::InvalidStateForOperation),
        }
    }

    fn handle_signed_message_for_node(&mut self,
                                      signed_msg: &SignedMessage,
                                      hop_name: &XorName,
                                      sent_to: &[XorName],
                                      relay: bool)
                                      -> Result<(), RoutingError> {
        let dst = signed_msg.content().dst();

        if let Authority::Client { ref peer_id, .. } = *dst {
            if self.name() == dst.name() {
                // This is a message for a client we are the proxy of. Relay it.
                return self.relay_to_client(signed_msg.clone(), peer_id);
            }
        }

        if self.routing_table.is_close(dst.name()) {
            try!(self.signed_msg_security_check(&signed_msg));
        }

        // Cache handling
        if self.use_data_cache {
            if let Some(routing_msg) = self.get_from_cache(signed_msg.content()) {
                return self.send_message(routing_msg);
            }
        }
        self.add_to_cache(signed_msg.content());

        if relay {
            if let Err(err) = self.send(signed_msg.clone(), hop_name, sent_to, false) {
                trace!("Failed relaying message: {:?}", err);
            }
        }
        if self.signed_message_filter.count(signed_msg) == 0 &&
           self.routing_table.is_recipient(dst.to_destination()) {
            self.handle_routing_message(signed_msg.content().clone(), *signed_msg.public_id())
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
                (&Authority::ManagedNode(_node_name), &Authority::NodeManager(_manager_name)) => {
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
                    content: RequestContent::Get(DataIdentifier::Immutable(ref name), id),
                    ..
                }) => {
                match self.data_cache.get(name) {
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
            // TODO(afck): Currently we don't accumulate GetCloseGroup, GetPublicId and
            // GetPublicIdWithConnectionInfo responses, because while a node is joining,
            // the responses can disagree. Some of the group members might already have
            // the new node in their routing table and others might not. To resolve this,
            // we will need a cleaner algorithm for joining nodes: They should connect to
            // all their future routing table entries, and once these connections are
            // established, send a direct message to these contacts. Only when they receive
            // that message, the contacts should add the new node to their routing tables in
            // turn, because only then it can act as a fully functioning routing node.
            let skip_accumulate =
                if let RoutingMessage::Response(ResponseMessage { ref content, .. }) =
                       routing_msg {
                    match *content {
                        ResponseContent::GetCloseGroup { .. } |
                        ResponseContent::GetPublicId { .. } |
                        ResponseContent::GetPublicIdWithConnectionInfo { .. } => true,
                        _ => false,
                    }
                } else {
                    false
                };

            if skip_accumulate {
                let _ = self.grp_msg_filter.insert(&routing_msg);
            } else if let Some(output_msg) = self.accumulate(routing_msg.clone(), &public_id) {
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
            (RequestContent::GetNetworkName { current_id, message_id },
             Authority::Client { client_key, proxy_node_name, peer_id },
             Authority::NaeManager(dst_name)) => {
                self.handle_get_network_name_request(current_id,
                                                     client_key,
                                                     proxy_node_name,
                                                     dst_name,
                                                     peer_id,
                                                     message_id)
            }
            (RequestContent::ExpectCloseNode { expect_id, client_auth, message_id },
             Authority::NaeManager(_),
             Authority::NaeManager(_)) => {
                self.handle_expect_close_node_request(expect_id, client_auth, message_id)
            }
            (RequestContent::GetCloseGroup(message_id), src, Authority::NaeManager(dst_name)) => {
                self.handle_get_close_group_request(src, dst_name, message_id)
            }
            (RequestContent::ConnectionInfo { encrypted_connection_info, nonce_bytes, public_id },
             Authority::Client { client_key, proxy_node_name, peer_id },
             Authority::ManagedNode(dst_name)) => {
                self.handle_connection_info_from_client(encrypted_connection_info,
                                                        nonce_bytes,
                                                        client_key,
                                                        proxy_node_name,
                                                        dst_name,
                                                        peer_id,
                                                        public_id)
            }
            (RequestContent::ConnectionInfo { encrypted_connection_info, nonce_bytes, public_id },
             Authority::ManagedNode(src_name),
             Authority::Client { .. }) |
            (RequestContent::ConnectionInfo { encrypted_connection_info, nonce_bytes, public_id },
             Authority::ManagedNode(src_name),
             Authority::ManagedNode(_)) => {
                self.handle_connection_info_from_node(encrypted_connection_info,
                                                      nonce_bytes,
                                                      src_name,
                                                      request_msg.dst,
                                                      public_id)
            }
            (RequestContent::Connect,
             Authority::ManagedNode(src_name),
             Authority::ManagedNode(dst_name)) => self.handle_connect_request(src_name, dst_name),
            (RequestContent::GetPublicId,
             Authority::ManagedNode(src_name),
             Authority::NodeManager(dst_name)) => self.handle_get_public_id(src_name, dst_name),
            (RequestContent::GetPublicIdWithConnectionInfo { encrypted_connection_info,
                                                             nonce_bytes },
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
            (RequestContent::Refresh(..), _, _) => {
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
            (ResponseContent::GetNetworkName { relocated_id, close_group_ids, .. },
             Authority::NodeManager(_),
             dst) => self.handle_get_network_name_response(relocated_id, close_group_ids, dst),
            (ResponseContent::GetPublicId { public_id },
             Authority::NodeManager(_),
             Authority::ManagedNode(dst_name)) => {
                self.handle_get_public_id_response(public_id, dst_name)
            }
            (ResponseContent::GetPublicIdWithConnectionInfo { public_id,
                                                              encrypted_connection_info,
                                                              nonce_bytes },
             Authority::NodeManager(_),
             Authority::ManagedNode(dst_name)) => {
                self.handle_get_public_id_with_connection_info_response(public_id,
                                                                        encrypted_connection_info,
                                                                        nonce_bytes,
                                                                        dst_name)
            }
            (ResponseContent::GetCloseGroup { close_group_ids, .. },
             Authority::NaeManager(_),
             dst) => self.handle_get_close_group_response(close_group_ids, dst),
            (ResponseContent::GetSuccess(..), _, _) |
            (ResponseContent::PutSuccess(..), _, _) |
            (ResponseContent::PostSuccess(..), _, _) |
            (ResponseContent::DeleteSuccess(..), _, _) |
            (ResponseContent::GetFailure { .. }, _, _) |
            (ResponseContent::PutFailure { .. }, _, _) |
            (ResponseContent::PostFailure { .. }, _, _) |
            (ResponseContent::DeleteFailure { .. }, _, _) => {
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
            if self.role == Role::Client {
                let _ = self.event_sender.send(Event::Disconnected);
            } else {
                debug!("{:?} Bootstrap finished with no connections. Start Listening to allow \
                        incoming connections.",
                       self);
                if !self.start_listening() {
                    let _ = self.event_sender.send(Event::NetworkStartupFailed);
                }
            }
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
                info!("Running listener.");
                true
            }
            Err(err) => {
                error!("Failed to start listening: {:?}", err);
                false
            }
        }
    }

    fn handle_lost_peer(&mut self, peer_id: PeerId) {
        let _ = self.peer_map.remove(&peer_id);
        if peer_id == self.crust_service.id() {
            error!("LostPeer fired with our crust peer id");
            return;
        }
        debug!("Received LostPeer - {:?}", peer_id);
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
            current_quorum_size: self.routing_table.dynamic_quorum_size(),
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
            info!("Connection to {:?} failed. Calling crust::Service::disconnect.",
                  peer_id);
            self.crust_service.disconnect(peer_id);
            self.handle_lost_peer(*peer_id);
            return Err(err.into());
        }
        Ok(())
    }

    /// Adds the signed message to the statistics and returns `true` if it should be blocked due
    /// to deduplication.
    fn filter_signed_msg(&mut self, msg: &SignedMessage, peer_id: &PeerId) -> bool {
        let mut hasher = SipHasher::new();
        msg.hash(&mut hasher);
        if self.send_filter.insert((hasher.finish(), *peer_id), ()).is_some() {
            return true;
        }
        self.stats.count_routing_message(msg.content());
        false
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
                warn!("Connection failed: Proxy node needs a larger routing table to accept \
                       clients.");
                self.retry_bootstrap_with_blacklist(&peer_id);
                Ok(())
            }
            DirectMessage::ClientToNode => {
                if self.client_map.remove(&peer_id).is_none() {
                    warn!("Client requested ClientToNode, but is not in client_map: {:?}",
                          peer_id);
                }
                // TODO(afck): Try adding them to the routing table?
                if self.routing_table.find(|node| node.peer_id == peer_id).is_none() {
                    warn!("Client requested ClientToNode, but is not in routing table: {:?}",
                          peer_id);
                    try!(self.disconnect_peer(&peer_id));
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
                    warn!("Signature check failed in ClientIdentify - Dropping connection {:?}",
                          peer_id);
                    self.disconnect_peer(&peer_id)
                }
            }
            DirectMessage::NodeIdentify { ref serialised_public_id, ref signature } => {
                if let Ok(public_id) = Core::verify_signed_public_id(serialised_public_id,
                                                                     signature) {
                    self.handle_node_identify(public_id, peer_id)
                } else {
                    warn!("Signature check failed in NodeIdentify - Dropping peer {:?}",
                          peer_id);
                    self.disconnect_peer(&peer_id)
                }
            }
            DirectMessage::NewNode(public_id) => {
                trace!("Received NewNode({:?}).", public_id);
                if self.routing_table.need_to_add(public_id.name()) {
                    return self.send_connect_request(public_id.name());
                }
                Ok(())
            }
            DirectMessage::ConnectionUnneeded(ref name) => {
                if let Some(node_info) = self.routing_table.get(name) {
                    if node_info.peer_id != peer_id {
                        error!("Received ConnectionUnneeded from {:?} with name {:?}, but that \
                                name actually belongs to {:?}.",
                               peer_id,
                               name,
                               node_info.peer_id);
                        return Err(RoutingError::InvalidSource);
                    }
                }
                debug!("Received ConnectionUnneeded from {:?}.", peer_id);
                if self.routing_table.remove_if_unneeded(name) {
                    info!("Dropped {:?} from the routing table.", name);
                    self.crust_service.disconnect(&peer_id);
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
        if *public_id.name() ==
           XorName::new(hash::sha512::hash(&public_id.signing_public_key().0).0) {
            warn!("Incoming Connection not validated as a proper node - dropping");
            self.retry_bootstrap_with_blacklist(&peer_id);

            return Ok(());
        }

        if self.proxy_map.is_empty() {
            let _ = self.proxy_map.insert(peer_id, public_id);
        } else if let Some(previous_name) = self.proxy_map.insert(peer_id, public_id) {
            warn!("Adding bootstrap node to proxy map caused a prior ID to eject. Previous name: \
                   {:?}",
                  previous_name);
            warn!("Dropping this peer {:?}", peer_id);
            let _ = self.proxy_map.remove(&peer_id);
            return self.disconnect_peer(&peer_id);
        } else {
            debug!("Disconnecting {:?} not accepting further bootstrap connections.",
                   peer_id);
            return self.disconnect_peer(&peer_id);
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
            Role::FirstNode => error!("Received BootstrapIdentify as the first node."),
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
            return self.disconnect_peer(&peer_id);
        }

        self.remove_stale_joining_nodes();

        if (client_restriction || self.role != Role::FirstNode) &&
           self.routing_table.len() < GROUP_SIZE - 1 {
            debug!("Client {:?} rejected: Routing table has {} entries. {} required.",
                   public_id.name(),
                   self.routing_table.len(),
                   GROUP_SIZE - 1);
            return self.send_direct_message(&peer_id, DirectMessage::BootstrapDeny);
        }
        let client_info = ClientInfo::new(*public_id.signing_public_key(), client_restriction);
        if self.client_map.insert(peer_id, client_info).is_some() {
            error!("Received two ClientInfo from the same peer ID {:?}.",
                   peer_id);
        }

        debug!("{:?} Accepted client {:?}.", self, public_id.name());

        self.bootstrap_identify(peer_id)
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
        if self.client_map.contains_key(peer_id) {
            // TODO(afck): At this point we probably haven't verified that the client's new name is
            // correct.
            debug!("Public ID not in cache, but peer {:?} is a client.",
                   peer_id);
            return true;
        }
        if self.proxy_map.get(peer_id) == Some(public_id) {
            // TODO(afck): Maybe we should verify the proxy's public ID.
            debug!("Public ID not in cache, but peer {:?} is a proxy.", peer_id);
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
        if self.role == Role::Client {
            debug!("Received node identify as a client.");
            return Ok(());
        }

        debug!("{:?} Handling NodeIdentify from {:?}.",
               self,
               public_id.name());
        if !self.node_in_cache(&public_id, &peer_id) {
            warn!("Accepting connection anyway, since node_id_cache is disabled.");
            // TODO: Re-enable this once Routing stability issues have been resolved.
            // return self.disconnect_peer(&peer_id);
        }

        if let Some((name, _)) = self.sent_network_name_to {
            if name == *public_id.name() {
                self.sent_network_name_to = None;
            }
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

        let _ = self.node_id_cache.remove(&name);
        let info = NodeInfo::new(public_id, peer_id);

        match self.routing_table.add(info) {
            None => {
                error!("{:?} Peer was not added to the routing table: {:?}",
                       self,
                       peer_id);
                return self.disconnect_peer(&peer_id);
            }
            Some(AddedNodeDetails { must_notify, unneeded, .. }) => {
                info!("{:?} Added {:?} to routing table.", self, name);
                if self.routing_table.len() == 1 {
                    let _ = self.event_sender.send(Event::Connected);
                }
                for notify_info in must_notify {
                    try!(self.send_direct_message(&notify_info.peer_id,
                                                  DirectMessage::NewNode(public_id)));
                }
                for node_info in unneeded {
                    let our_name = *self.name();
                    try!(self.send_direct_message(&node_info.peer_id,
                                                  DirectMessage::ConnectionUnneeded(our_name)));
                }

                self.reset_bucket_refresh_timer();

                // TODO: Figure out whether common_groups makes sense: Do we need to send a
                // NodeAdded event for _every_ new peer?
                let event = Event::NodeAdded(name, self.routing_table.clone());
                if let Err(err) = self.event_sender.send(event) {
                    error!("{:?} Error sending event to routing user - {:?}", self, err);
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

        for (dst_id, (name, state)) in self.connecting_peers.retrieve_all() {
            if state == ConnectState::Tunnel {
                let tunnel_request = DirectMessage::TunnelRequest(dst_id);
                if let Err(err) = self.send_direct_message(&peer_id, tunnel_request) {
                    error!("Error requesting tunnel for {:?} from {:?} ({:?}): {:?}.",
                           dst_id,
                           peer_id,
                           name,
                           err);
                }
            }
        }

        Ok(())
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
        trace!("Send GetCloseGroup to bucket {}.", bucket_index);
        let bucket_address = try!(self.name().with_flipped_bit(bucket_index));
        self.request_close_group(bucket_address)
    }

    fn request_close_group(&mut self, name: XorName) -> Result<(), RoutingError> {
        let request_msg = RequestMessage {
            src: Authority::ManagedNode(*self.name()),
            dst: Authority::NaeManager(name),
            content: RequestContent::GetCloseGroup(MessageId::new()),
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
                             .map(|(&peer_id, _)| peer_id)
                             .collect::<Vec<_>>();

        for peer_id in stale_keys {
            if self.client_map.remove(&peer_id).is_some() {
                debug!("Removing stale joining node with Crust ID {:?}", peer_id);
                if let Err(err) = self.disconnect_peer(&peer_id) {
                    warn!("Failed to remove node: {:?}", err);
                }
            }
        }
    }

    fn retry_bootstrap_with_blacklist(&mut self, peer_id: &PeerId) {
        debug!("Retry bootstrap without {:?}.", peer_id);
        self.crust_service.stop_bootstrap();
        self.state = State::Disconnected;
        self.proxy_map.clear();
        thread::sleep(Duration::from_secs(5));
        self.restart_crust_service();
        // TODO(andreas): Enable blacklisting once a solution for ci_test is found.
        //               Currently, ci_test's nodes all connect via the same beacon.
        // self.crust_service
        //    .bootstrap_with_blacklist(0u32, Some(CRUST_DEFAULT_BEACON_PORT), &[endpoint]);
    }

    /// Handle a request by `peer_id` to act as a tunnel connecting it with `dst_id`.
    fn handle_tunnel_request(&mut self,
                             peer_id: PeerId,
                             dst_id: PeerId)
                             -> Result<(), RoutingError> {
        if self.routing_table.find(|node| node.peer_id == peer_id).is_some() &&
           self.routing_table.find(|node| node.peer_id == dst_id).is_some() {
            if let Some((id0, id1)) = self.tunnels.consider_clients(peer_id, dst_id) {
                debug!("Accepted tunnel request from {:?} for {:?}.",
                       peer_id,
                       dst_id);
                return self.send_direct_message(&id0, DirectMessage::TunnelSuccess(id1));
            }
        } else {
            debug!("Rejected tunnel request from {:?} for {:?}.",
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
        if let Some((name, _)) = self.connecting_peers.remove(&dst_id) {
            if self.tunnels.add(dst_id, peer_id) {
                debug!("Adding {:?} as a tunnel node for {:?}.", peer_id, name);
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
            warn!("Tunnel to {:?} via {:?} closed.", dst_id, peer_id);
            self.dropped_routing_node_connection(&dst_id);
        }
        Ok(())
    }

    /// Handle a `TunnelDisconnect` message from `peer_id` who wants to disconnect `dst_id`.
    fn handle_tunnel_disconnect(&mut self,
                                peer_id: PeerId,
                                dst_id: PeerId)
                                -> Result<(), RoutingError> {
        warn!("Closing tunnel connecting {:?} and {:?}.", dst_id, peer_id);
        if self.tunnels.remove(dst_id, peer_id) {
            self.send_direct_message(&dst_id, DirectMessage::TunnelClosed(peer_id))
        } else {
            Ok(())
        }
    }

    /// Disconnects from the given peer, via Crust or by dropping the tunnel node, if the peer is
    /// not a proxy, client or routing table entry.
    fn disconnect_peer(&mut self, peer_id: &PeerId) -> Result<(), RoutingError> {
        if let Some(&node) = self.routing_table.find(|node| node.peer_id == *peer_id) {
            warn!("Not disconnecting routing table entry {:?} ({:?}).",
                  node.name(),
                  peer_id);
        } else if let Some(&public_id) = self.proxy_map.get(peer_id) {
            warn!("Not disconnecting proxy node {:?} ({:?}).",
                  public_id.name(),
                  peer_id);
        } else if self.client_map.contains_key(peer_id) {
            warn!("Not disconnecting client {:?}.", peer_id);
        } else if let Some(tunnel_id) = self.tunnels.remove_tunnel_for(peer_id) {
            debug!("Disconnecting {:?} (indirect).", peer_id);
            try!(self.send_direct_message(&tunnel_id, DirectMessage::TunnelDisconnect(*peer_id)));
        } else {
            debug!("Disconnecting {:?}. Calling crust::Service::disconnect.",
                   peer_id);
            let _ = self.crust_service.disconnect(peer_id);
            let _ = self.peer_map.remove(peer_id);
        }
        Ok(())
    }

    // Constructed by A; From A -> X
    fn relocate(&mut self) -> Result<(), RoutingError> {
        let duration = Duration::from_secs(GET_NETWORK_NAME_TIMEOUT_SECS);
        self.get_network_name_timer_token = Some(self.timer.schedule(duration));

        let request_content = RequestContent::GetNetworkName {
            current_id: *self.full_id.public_id(),
            message_id: MessageId::new(),
        };

        let request_msg = RequestMessage {
            src: try!(self.get_client_authority()),
            dst: Authority::NaeManager(*self.name()),
            content: request_content,
        };

        info!("Sending GetNetworkName request with: {:?}. This can take a while.",
              self.full_id.public_id());
        self.send_request(request_msg)
    }

    // Received by X; From A -> X
    fn handle_get_network_name_request(&mut self,
                                       mut their_public_id: PublicId,
                                       client_key: sign::PublicKey,
                                       proxy_name: XorName,
                                       dst_name: XorName,
                                       peer_id: PeerId,
                                       message_id: MessageId)
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

        // From X -> Y; Send to close group of the relocated name
        {
            let request_content = RequestContent::ExpectCloseNode {
                expect_id: their_public_id,
                client_auth: Authority::Client {
                    client_key: client_key,
                    proxy_node_name: proxy_name,
                    peer_id: peer_id,
                },
                message_id: message_id,
            };

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
                                        expect_id: PublicId,
                                        client_auth: Authority,
                                        message_id: MessageId)
                                        -> Result<(), RoutingError> {
        // Add expect_id to node_id_cache regardless of whether we can
        // accommodate entry in sent_network_name_to. This prevents us from rejecting
        // connect request from nodes that have been accepted by majority in group
        if let Some(prev_id) = self.node_id_cache.insert(*expect_id.name(), expect_id) {
            warn!("Previous ID {:?} with same name found during \
                   handle_expect_close_node_request. Ignoring that",
                  prev_id);
            return Err(RoutingError::RejectedPublicId);
        }

        let now = Instant::now();
        if let Some((_, timestamp)) = self.sent_network_name_to {
            if (now - timestamp).as_secs() <= SENT_NETWORK_NAME_TIMEOUT_SECS {
                return Err(RoutingError::RejectedGetNetworkName);
            }
            self.sent_network_name_to = None;
        }


        let close_group = match self.routing_table.close_nodes(expect_id.name()) {
            Some(close_group) => close_group,
            None => return Err(RoutingError::InvalidDestination),
        };
        let public_ids = close_group.into_iter()
                                    .map(|info| info.public_id)
                                    .collect_vec();

        self.sent_network_name_to = Some((*expect_id.name(), now));
        // From Y -> A (via B)
        let response_content = ResponseContent::GetNetworkName {
            relocated_id: expect_id,
            close_group_ids: public_ids,
            message_id: message_id,
        };

        debug!("Responding to client {:?}: {:?}.",
               client_auth,
               response_content);

        let response_msg = ResponseMessage {
            src: Authority::NodeManager(*expect_id.name()),
            dst: client_auth,
            content: response_content,
        };

        try!(self.send_response(response_msg));

        Ok(())
    }

    // Received by A; From X -> A
    fn handle_get_network_name_response(&mut self,
                                        relocated_id: PublicId,
                                        mut close_group_ids: Vec<PublicId>,
                                        dst: Authority)
                                        -> Result<(), RoutingError> {
        self.get_network_name_timer_token = None;
        self.set_self_node_name(*relocated_id.name());
        close_group_ids.truncate(PARALLELISM);
        // From A -> Closest in Y
        for close_node_id in close_group_ids {
            if self.node_id_cache.insert(*close_node_id.name(), close_node_id).is_none() {
                debug!("Sending connection info to {:?} on GetNetworkName response.",
                       close_node_id);
                try!(self.send_connection_info(close_node_id,
                                               dst.clone(),
                                               Authority::ManagedNode(*close_node_id.name())));
            }
        }
        Ok(())
    }

    // Received by Y; From A -> Y, or from any node to one of its bucket addresses.
    fn handle_get_close_group_request(&mut self,
                                      src: Authority,
                                      dst_name: XorName,
                                      message_id: MessageId)
                                      -> Result<(), RoutingError> {
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
        let response_content = ResponseContent::GetCloseGroup {
            close_group_ids: public_ids,
            message_id: message_id,
        };

        let response_msg = ResponseMessage {
            src: Authority::NaeManager(dst_name),
            dst: src,
            content: response_content,
        };

        self.send_response(response_msg)
    }

    fn handle_get_close_group_response(&mut self,
                                       close_group_ids: Vec<PublicId>,
                                       dst: Authority)
                                       -> Result<(), RoutingError> {
        for close_node_id in close_group_ids {
            if self.routing_table.need_to_add(close_node_id.name()) {
                let _ = self.node_id_cache.insert(*close_node_id.name(), close_node_id);
                debug!("Sending connection info to {:?} on GetCloseGroup response.",
                       close_node_id);
                try!(self.send_connection_info(close_node_id,
                                               dst.clone(),
                                               Authority::ManagedNode(*close_node_id.name())));
            } else {
                trace!("Routing table does not need {:?}.", close_node_id);
            }
        }

        Ok(())
    }

    // It is preferable to destructure the message and the request in `handle_request_message`,
    // even if that requires a long list of arguments.
    #[cfg_attr(feature="clippy", allow(too_many_arguments))]
    fn handle_connection_info_from_client(&mut self,
                                          encrypted_connection_info: Vec<u8>,
                                          nonce_bytes: [u8; box_::NONCEBYTES],
                                          client_key: sign::PublicKey,
                                          proxy_name: XorName,
                                          dst_name: XorName,
                                          peer_id: PeerId,
                                          their_public_id: PublicId)
                                          -> Result<(), RoutingError> {
        try!(self.check_address_for_routing_table(their_public_id.name()));
        try!(self.connect(encrypted_connection_info,
                          nonce_bytes,
                          their_public_id,
                          Authority::ManagedNode(dst_name),
                          Authority::Client {
                              client_key: client_key,
                              proxy_node_name: proxy_name,
                              peer_id: peer_id,
                          }));
        if let Some(&(ref _name, ref _their_public_id)) = self.node_id_cache
                                                              .retrieve_all()
                                                              .iter()
                                                              .find(|elt| {
                                                                  *elt.1.signing_public_key() ==
                                                                  client_key
                                                              }) {
            // try!(self.check_address_for_routing_table(&name));
            // self.connect(encrypted_connection_info,
            //              nonce_bytes,
            //              *their_public_id,
            //              Authority::ManagedNode(dst_name),
            //              Authority::Client {
            //                  client_key: client_key,
            //                  proxy_node_name: proxy_name,
            //                  peer_id: peer_id,
            //              })
            Ok(())
        } else {
            warn!("Client with key {:?} not found in node_id_cache.",
                  client_key);
            Err(RoutingError::RejectedPublicId)
        }
    }

    fn handle_connection_info_from_node(&mut self,
                                        encrypted_connection_info: Vec<u8>,
                                        nonce_bytes: [u8; box_::NONCEBYTES],
                                        src_name: XorName,
                                        dst: Authority,
                                        their_public_id: PublicId)
                                        -> Result<(), RoutingError> {
        try!(self.check_address_for_routing_table(&src_name));
        try!(self.connect(encrypted_connection_info,
                          nonce_bytes,
                          their_public_id,
                          dst,
                          Authority::ManagedNode(src_name)));
        if let Some(_their_public_id) = self.node_id_cache.get(&src_name).cloned() {
            // self.connect(encrypted_connection_info,
            //              nonce_bytes,
            //              their_public_id,
            //              dst,
            //              Authority::ManagedNode(src_name))
            Ok(())
        } else {
            // let request_content = RequestContent::GetPublicIdWithConnectionInfo {
            //     encrypted_connection_info: encrypted_connection_info,
            //     nonce_bytes: nonce_bytes,
            // };

            // let request_msg = RequestMessage {
            //     src: dst,
            //     dst: Authority::NodeManager(src_name),
            //     content: request_content,
            // };

            // self.send_request(request_msg)
            Ok(())
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
        if self.routing_table.is_close(&dst_name) {
            let public_id = if let Some(info) = self.routing_table.get(&dst_name) {
                info.public_id
            } else if let Some(&public_id) = self.node_id_cache.get(&dst_name) {
                public_id
            } else {
                debug!("Cannot answer GetPublicId: {:?} not found in the routing table.",
                       dst_name);
                return Err(RoutingError::RejectedPublicId);
            };

            let msg = ResponseMessage {
                src: Authority::NodeManager(dst_name),
                dst: Authority::ManagedNode(src_name),
                content: ResponseContent::GetPublicId { public_id: public_id },
            };

            self.send_response(msg)
        } else {
            error!("Handling GetPublicId, but not close to the target!");
            Err(RoutingError::RejectedPublicId)
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
        if self.routing_table.is_close(&dst_name) {
            let public_id = if let Some(info) = self.routing_table.get(&dst_name) {
                info.public_id
            } else if let Some(public_id) = self.node_id_cache.get(&dst_name) {
                *public_id
            } else {
                error!("Cannot answer GetPublicIdWithConnectionInfo: {:?} not found in the \
                        routing table.",
                       dst_name);
                return Err(RoutingError::RejectedPublicId);
            };

            let response_content = ResponseContent::GetPublicIdWithConnectionInfo {
                public_id: public_id,
                encrypted_connection_info: encrypted_connection_info,
                nonce_bytes: nonce_bytes,
            };

            let msg = ResponseMessage {
                src: Authority::NodeManager(dst_name),
                dst: Authority::ManagedNode(src_name),
                content: response_content,
            };
            self.send_response(msg)
        } else {
            error!("Handling GetPublicIdWithConnectionInfo, but not close to the target!");
            Err(RoutingError::RejectedPublicId)
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
        if let State::Bootstrapping(peer_id, bootstrap_token) = self.state {
            if bootstrap_token == token {
                debug!("Timeout when trying to bootstrap against {:?}.", peer_id);
                self.retry_bootstrap_with_blacklist(&peer_id);
            }
            return;
        }
        if self.get_network_name_timer_token == Some(token) {
            error!("Failed to get GetNetworkName response.");
            let _ = self.event_sender.send(Event::GetNetworkNameFailed);
        } else if self.tick_timer_token == Some(token) {
            let _ = self.event_sender.send(Event::Tick);
            let tick_period = Duration::from_secs(TICK_TIMEOUT_SECS);
            self.tick_timer_token = Some(self.timer.schedule(tick_period));
        } else if let Some((bucket_token, delay)) = self.bucket_refresh_token_and_delay {
            if bucket_token == token {
                self.request_bucket_close_groups();
                let new_delay = delay.saturating_mul(2);
                let new_token = self.timer.schedule(Duration::from_secs(new_delay));
                self.bucket_refresh_token_and_delay = Some((new_token, new_delay));
            }
        }
    }

    /// Sends `GetCloseGroup` requests to all incompletely filled buckets and our own address.
    fn request_bucket_close_groups(&mut self) {
        if !self.bucket_filter.contains(&XOR_NAME_BITS) {
            let _ = self.bucket_filter.insert(&XOR_NAME_BITS);
            let our_name = *self.name();
            if let Err(err) = self.request_close_group(our_name) {
                error!("Failed to request our own close group: {:?}", err);
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

    /// Returns the peer ID of the given node if it is our proxy or client.
    fn get_proxy_or_client_peer_id(&self, public_id: &PublicId) -> Option<PeerId> {
        if let Some((&peer_id, _)) = self.client_map
                                         .iter()
                                         .find(|elt| {
                                             &elt.1.public_key == public_id.signing_public_key()
                                         }) {
            return Some(peer_id);
        }
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
        let their_connection_info: TheirConnectionInfo =
            try!(serialisation::deserialise(&serialised_connection_info));

        if let Some(our_connection_info) = self.our_connection_info_map.remove(&their_public_id) {
            let peer_id = their_connection_info.id();
            let their_name = *their_public_id.name();
            if let Some((name, _)) = self.connecting_peers
                                         .insert(peer_id, (their_name, ConnectState::Crust)) {
                warn!("Prepared connection info for {:?} as {:?}, but already tried as {:?}.",
                      peer_id,
                      their_name,
                      name);
            }
            debug!("Received connection info. Trying to connect to {:?} as {:?}.",
                   peer_id,
                   their_public_id.name());
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
        self.send(signed_msg, &hop, &[hop], true)
    }

    fn relay_to_client(&mut self,
                       signed_msg: SignedMessage,
                       peer_id: &PeerId)
                       -> Result<(), RoutingError> {
        let priority = signed_msg.priority();
        if self.client_map.contains_key(peer_id) {
            if self.filter_signed_msg(&signed_msg, peer_id) {
                return Ok(());
            }
            let hop_msg = try!(HopMessage::new(signed_msg,
                                               vec![],
                                               self.full_id.signing_private_key()));
            let message = Message::Hop(hop_msg);
            let raw_bytes = try!(serialisation::serialise(&message));
            self.send_or_drop(peer_id, raw_bytes, priority)
        } else {
            debug!("Client connection not found for message {:?}.", signed_msg);
            Err(RoutingError::ClientConnectionNotFound)
        }
    }

    fn to_hop_bytes(&self,
                    signed_msg: SignedMessage,
                    sent_to: Vec<XorName>)
                    -> Result<Vec<u8>, RoutingError> {
        let hop_msg = try!(HopMessage::new(signed_msg,
                                           sent_to,
                                           self.full_id.signing_private_key()));
        let message = Message::Hop(hop_msg);
        Ok(try!(serialisation::serialise(&message)))
    }

    fn to_tunnel_hop_bytes(&self,
                           signed_msg: SignedMessage,
                           sent_to: Vec<XorName>,
                           src: PeerId,
                           dst: PeerId)
                           -> Result<Vec<u8>, RoutingError> {
        let hop_msg = try!(HopMessage::new(signed_msg.clone(),
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
            signed_msg: SignedMessage,
            hop: &XorName,
            sent_to: &[XorName],
            handle: bool)
            -> Result<(), RoutingError> {
        let priority = signed_msg.priority();
        // If we're a client going to be a node, send via our bootstrap connection.
        if self.state == State::Client {
            if let Authority::Client { ref proxy_node_name, .. } = *signed_msg.content().src() {
                if let Some((&peer_id, _)) = self.proxy_map
                                                 .iter()
                                                 .find(|elt| elt.1.name() == proxy_node_name) {
                    let raw_bytes = try!(self.to_hop_bytes(signed_msg.clone(), vec![]));
                    return self.send_or_drop(&peer_id, raw_bytes, priority);
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
        let targets = self.routing_table
                          .target_nodes(destination, hop, count)
                          .into_iter()
                          .filter(|target| !sent_to.contains(target.name()))
                          .collect_vec();
        let new_sent_to = sent_to.iter()
                                 .chain(targets.iter().map(NodeInfo::name))
                                 .cloned()
                                 .collect_vec();
        let raw_bytes = try!(self.to_hop_bytes(signed_msg.clone(), new_sent_to.clone()));
        let mut result = Ok(());
        for target in targets {
            if let Some(&tunnel_id) = self.tunnels.tunnel_for(&target.peer_id) {
                let bytes = try!(self.to_tunnel_hop_bytes(signed_msg.clone(),
                                                          new_sent_to.clone(),
                                                          self.crust_service.id(),
                                                          target.peer_id));
                if !self.filter_signed_msg(&signed_msg, &target.peer_id) {
                    if let Err(err) = self.send_or_drop(&tunnel_id, bytes, priority) {
                        info!("Error sending message to {:?}: {:?}.", target.peer_id, err);
                        result = Err(err);
                    }
                }
            } else {
                if !self.filter_signed_msg(&signed_msg, &target.peer_id) {
                    if let Err(err) = self.send_or_drop(&target.peer_id,
                                                        raw_bytes.clone(),
                                                        priority) {
                        info!("Error sending message to {:?}: {:?}.", target.peer_id, err);
                        result = Err(err);
                    }
                }
            }
        }

        // If we need to handle this message, handle it.
        if handle && self.routing_table.is_recipient(signed_msg.content().dst().to_destination()) &&
           self.signed_message_filter.insert(&signed_msg) == 0 {
            let hop_name = *self.name();
            try!(self.handle_signed_message_for_node(&signed_msg, &hop_name, &new_sent_to, false));
        }

        result
    }

    fn get_client_authority(&self) -> Result<Authority, RoutingError> {
        match self.proxy_map.iter().next() {
            Some((ref _id, ref bootstrap_pub_id)) => {
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
        assert!(XorName(hash::sha512::hash(&self.full_id.public_id().signing_public_key().0).0) !=
                new_name);

        self.full_id.public_id_mut().set_name(new_name);
        let our_info = NodeInfo::new(*self.full_id.public_id(), self.crust_service.id());
        self.routing_table = RoutingTable::new(our_info);
    }

    fn dropped_client_connection(&mut self, peer_id: &PeerId) {
        if let Some(info) = self.client_map.remove(peer_id) {
            if info.client_restriction {
                debug!("Client disconnected: {:?}", peer_id);
            } else {
                debug!("Joining node {:?} dropped. {} remaining.",
                       peer_id,
                       self.joining_nodes_num());
            }
        }
    }

    fn dropped_bootstrap_connection(&mut self, peer_id: &PeerId) {
        if let Some(public_id) = self.proxy_map.remove(peer_id) {
            debug!("Lost bootstrap connection to {:?} ({:?}).",
                   public_id.name(),
                   peer_id);
            if self.proxy_map.is_empty() {
                debug!("Lost connection to last proxy node {:?}", peer_id);
                if self.role == Role::Client ||
                   (self.role == Role::Node && self.routing_table.is_empty()) {
                    let _ = self.event_sender.send(Event::Disconnected);
                    self.retry_bootstrap_with_blacklist(peer_id);
                }
            }
        }
    }

    fn dropped_tunnel_client(&mut self, peer_id: &PeerId) {
        for other_id in self.tunnels.drop_client(peer_id) {
            let message = DirectMessage::TunnelClosed(*peer_id);
            if let Err(err) = self.send_direct_message(&other_id, message) {
                error!("Error sending TunnelClosed info to {:?}: {:?}.",
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
                                .find(|node| node.peer_id == dst_id)
                                .map(|&node| (dst_id, node))
                        })
                        .collect_vec();
        for (dst_id, node) in peers {
            self.dropped_routing_node_connection(&dst_id);
            warn!("Lost tunnel for peer {:?} ({:?}). Requesting new tunnel.",
                  dst_id,
                  node.name());
            let _ = self.node_id_cache.insert(*node.name(), node.public_id);
            self.find_tunnel_for_peer(dst_id, *node.name());
        }
    }

    fn dropped_routing_node_connection(&mut self, peer_id: &PeerId) {
        if let Some(&node) = self.routing_table.find(|node| node.peer_id == *peer_id) {
            if let Some(DroppedNodeDetails { incomplete_bucket, common_groups }) =
                   self.routing_table.remove(node.public_id.name()) {
                info!("Dropped {:?} from the routing table.", node.name());
                if common_groups {
                    // If the lost node shared some close group with us, send a NodeLost event.
                    let event = Event::NodeLost(*node.public_id.name(), self.routing_table.clone());
                    if let Err(err) = self.event_sender.send(event) {
                        error!("Error sending event to routing user - {:?}", err);
                    }
                }
                if let Some(bucket_index) = incomplete_bucket {
                    if let Err(e) = self.request_bucket_ids(bucket_index) {
                        debug!("Failed to request replacement connection_info from bucket {}: \
                                {:?}.",
                               bucket_index,
                               e);
                    }
                }
                if self.routing_table.len() < GROUP_SIZE - 1 {
                    debug!("Lost connection, less than {} remaining.", GROUP_SIZE - 1);
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

    #[cfg(not(feature = "use-mock-crust"))]
    fn restart_crust_service(&mut self) {
        self.crust_service = match Service::new(self.crust_sender.clone()) {
            Ok(service) => service,
            Err(err) => panic!(format!("Unable to restart crust::Service {:?}", err)),
        };
    }

    #[cfg(feature = "use-mock-crust")]
    fn restart_crust_service(&mut self) {
        self.crust_service.restart(self.crust_sender.clone())
    }
}

impl Debug for Core {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{:?}({})", self.state, self.name())
    }
}
