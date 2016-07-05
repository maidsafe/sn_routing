// Copyright 2016 MaidSafe.net limited.
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

#[cfg(not(feature = "use-mock-crust"))]
use crust::{PeerId, PrivConnectionInfo, PubConnectionInfo};
#[cfg(feature = "use-mock-crust")]
use mock_crust::crust::{PeerId, PrivConnectionInfo, PubConnectionInfo};
use authority::Authority;
use sodiumoxide::crypto::sign;
use id::PublicId;
use itertools::Itertools;
use rand;
use std::collections::HashMap;
use std::{error, fmt};
use std::time::{Duration, Instant};
use xor_name::XorName;
use kademlia_routing_table::{AddedNodeDetails, ContactInfo, DroppedNodeDetails, RoutingTable};

/// Time (in seconds) after which a joining node will get dropped from the map
/// of joining nodes.
const JOINING_NODE_TIMEOUT_SECS: u64 = 300;
/// Time (in seconds) after which the connection to a peer is considered failed.
#[cfg(not(feature = "use-mock-crust"))]
const CONNECTION_TIMEOUT_SECS: u64 = 90;
/// With mock Crust, all pending connections are removed explicitly.
#[cfg(feature = "use-mock-crust")]
const CONNECTION_TIMEOUT_SECS: u64 = 0;
/// The group size for the routing table. This is the maximum that can be used for consensus.
pub const GROUP_SIZE: usize = 8;
/// The number of entries beyond `GROUP_SIZE` that are not considered unnecessary in the routing
/// table.
const EXTRA_BUCKET_ENTRIES: usize = 2;

/// Info about nodes in the routing table.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NodeInfo {
    pub public_id: PublicId,
    pub peer_id: PeerId,
}

impl NodeInfo {
    pub fn new(public_id: PublicId, peer_id: PeerId) -> Self {
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

/// Info about client a proxy kept in a proxy node.
pub struct ClientInfo {
    pub public_key: sign::PublicKey,
    pub client_restriction: bool,
    pub timestamp: Instant,
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

#[derive(Debug)]
/// Errors that occur in peer status management.
pub enum Error {
    /// The specified peer was not found.
    PeerNotFound,
    /// The peer is in a state that doesn't allow the requested operation.
    UnexpectedState,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::PeerNotFound => write!(formatter, "Peer not found"),
            Error::UnexpectedState => write!(formatter, "Peer state does not allow operation"),
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::PeerNotFound => "Peer not found",
            Error::UnexpectedState => "Peer state does not allow operation",
        }
    }
}

/// Our relationship status with a known peer.
#[derive(Debug)]
pub enum PeerState {
    /// Waiting for Crust to prepare our `PrivConnectionInfo`. Contains source and destination for
    /// sending it to the peer, and their connection info, if we already received it.
    ConnectionInfoPreparing(Authority, Authority, Option<PubConnectionInfo>),
    /// The prepared connection info that has been sent to the peer.
    ConnectionInfoReady(PrivConnectionInfo),
    /// We called `connect` and are waiting for a `NewPeer` event.
    CrustConnecting,
    /// We failed to connect and are trying to find a tunnel node.
    SearchingForTunnel,
    /// We are connected to that peer.
    Connected,
    /// We have a tunnel to that peer.
    Tunnel,
}

/// The result of adding a peer's `PubConnectionInfo`.
#[derive(Debug)]
pub enum ConnectionInfoReceivedResult {
    /// Our own connection info has already been prepared: The peer was switched to
    /// `CrustConnecting` status; Crust's `connect` method should be called with these infos now.
    Ready(PrivConnectionInfo, PubConnectionInfo),
    /// We don't have a connection info for that peer yet. The peer was switched to
    /// `ConnectionInfoPreparing` status; Crust's `prepare_connection_info` should be called with
    /// this token now.
    Prepare(u32),
    /// We are currently preparing our own connection info and need to wait for it. The peer
    /// remains in `ConnectionInfoPreparing` status.
    Waiting,
}

/// The result of adding our prepared `PrivConnectionInfo`. It needs to be sent to a peer as a
/// `PubConnectionInfo`.
#[derive(Debug)]
pub struct ConnectionInfoPreparedResult {
    /// The peer's public ID.
    pub pub_id: PublicId,
    /// The source authority for sending the connection info.
    pub src: Authority,
    /// The destination authority for sending the connection info.
    pub dst: Authority,
    /// If the peer's connection info was already present, the peer has been moved to
    /// `CrustConnecting` status. Crust's `connect` method should be called with these infos now.
    pub infos: Option<(PrivConnectionInfo, PubConnectionInfo)>,
}

// TODO: Move `node_id_cache`, the `connection_info_map`s and possibly `tunnels` and `routing_table`
// from `Core` into this structure, too. Then, try to remove redundancies and ideally merge
// (almost?) all these fields into a single map with one entry per peer, containing all relevant
// information, e. g.:
// * Do we want this peer in our routing table? Do they want us?
// * Are we connected? Have we tried connecting? Did it fail?
// * Are we looking for a tunnel? Do we have one?
// * Are they a proxy, a client, a routing table entry? Are they in the process of becoming one?
// * Have we verified their public ID?
// * Have we disconnected? Did they go offline or have we tried reconnecting?

/// A container for information about other nodes in the network.
///
/// This keeps track of which nodes we know of, which ones we have tried to connect to, which IDs
/// we have verified, whom we are directly connected to or via a tunnel.
pub struct PeerManager {
    // Any clients we have proxying through us, and whether they have `client_restriction`.
    client_map: HashMap<PeerId, ClientInfo>,
    connection_token_map: HashMap<u32, PublicId>,
    node_map: HashMap<PublicId, (Instant, PeerState)>,
    /// Our bootstrap connection.
    proxy: Option<(PeerId, PublicId)>,
    pub_id_map: HashMap<PeerId, PublicId>,
    routing_table: RoutingTable<NodeInfo>,
}

impl PeerManager {
    pub fn new(our_info: NodeInfo) -> PeerManager {
        PeerManager {
            client_map: HashMap::new(),
            connection_token_map: HashMap::new(),
            node_map: HashMap::new(),
            proxy: None,
            pub_id_map: HashMap::new(),
            routing_table: RoutingTable::<NodeInfo>::new(our_info, GROUP_SIZE, EXTRA_BUCKET_ENTRIES),
        }
    }

    pub fn reset_routing_table(&mut self, our_info: NodeInfo) {
        self.routing_table = RoutingTable::<NodeInfo>::new(our_info, GROUP_SIZE, EXTRA_BUCKET_ENTRIES);
    }

    pub fn routing_table(&self) -> &RoutingTable<NodeInfo> {
        &self.routing_table
    }

    pub fn close_group(&self, name: &XorName) -> Option<Vec<XorName>> {
        self.routing_table.close_nodes(name, GROUP_SIZE)
                          .map(|infos| {
                                infos.iter().map(NodeInfo::name).cloned().collect()
                          })
    }

    pub fn add_to_routing_table(&mut self, info: NodeInfo) -> Option<AddedNodeDetails<NodeInfo>> {
        self.routing_table.add(info)
    }

    pub fn remove_if_unneeded(&mut self, name: &XorName) -> bool {
        self.routing_table.remove_if_unneeded(name)
    }

    pub fn remove_node(&mut self, name: &XorName) -> Option<DroppedNodeDetails> {
        self.routing_table.remove(name)
    }

    pub fn is_tunnel(&self, peer_id: &PeerId, dst_id: &PeerId) -> bool {
        self.routing_table.iter().any(|node| node.peer_id == *peer_id) &&
                self.routing_table.iter().any(|node| node.peer_id == *dst_id)
    }

    pub fn proxy(&self) -> &Option<(PeerId, PublicId)> {
        &self.proxy
    }

    /// Returns the proxy node's public ID, if it has the given peer ID.
    pub fn get_proxy_public_id(&self, peer_id: &PeerId) -> Option<&PublicId> {
        match self.proxy {
            Some((ref proxy_id, ref pub_id)) if proxy_id == peer_id => Some(pub_id),
            _ => None,
        }
    }

    /// Returns the proxy node's peer ID, if it has the given name.
    pub fn get_proxy_peer_id(&self, name: &XorName) -> Option<&PeerId> {
        match self.proxy {
            Some((ref peer_id, ref pub_id)) if pub_id.name() == name => Some(peer_id),
            _ => None,
        }
    }

    /// Inserts the given peer as a proxy node if applicable, returns `false` if it is not accepted
    /// and should be disconnected.
    pub fn set_proxy(&mut self, peer_id: PeerId, public_id: PublicId) -> bool {
        if let Some((ref proxy_id, _)) = self.proxy {
            debug!("Not accepting further bootstrap connections.");
            *proxy_id == peer_id
        } else {
            self.proxy = Some((peer_id, public_id));
            true
        }
    }

    /// Removes the from and returns it, if present.
    pub fn remove_proxy(&mut self) -> Option<(PeerId, PublicId)> {
        self.proxy.take()
    }

    /// Inserts the given client into the map.
    pub fn insert_client(&mut self,
                         peer_id: PeerId,
                         public_id: &PublicId,
                         client_restriction: bool) {
        let client_info = ClientInfo::new(*public_id.signing_public_key(), client_restriction);
        let _ = self.client_map.insert(peer_id, client_info);
    }

    /// Returns the given client's `ClientInfo`, if present.
    pub fn get_client(&self, peer_id: &PeerId) -> Option<&ClientInfo> {
        self.client_map.get(peer_id)
    }

    /// Removes the given peer ID from the client nodes and returns their `ClientInfo`, if present.
    pub fn remove_client(&mut self, peer_id: &PeerId) -> Option<ClientInfo> {
        self.client_map.remove(peer_id)
    }

    /// Removes all clients that intend to become a node but have timed out, and returns their peer
    /// IDs.
    pub fn remove_stale_joining_nodes(&mut self) -> Vec<PeerId> {
        let stale_keys = self.client_map
            .iter()
            .filter(|&(_, info)| info.is_stale())
            .map(|(&peer_id, _)| peer_id)
            .collect_vec();
        for peer_id in &stale_keys {
            let _ = self.client_map.remove(peer_id);
        }
        stale_keys
    }

    /// Returns the peer ID of the given node if it is our proxy or client.
    pub fn get_proxy_or_client_peer_id(&self, public_id: &PublicId) -> Option<PeerId> {
        if let Some((&peer_id, _)) = self.client_map
            .iter()
            .find(|elt| &elt.1.public_key == public_id.signing_public_key()) {
            return Some(peer_id);
        }
        match self.proxy {
            Some((ref peer_id, ref proxy_pub_id)) if proxy_pub_id == public_id => Some(*peer_id),
            _ => None,
        }
    }

    /// Returns the number of clients for which we act as a proxy and which intend to become a
    /// node.
    pub fn joining_nodes_num(&self) -> usize {
        self.client_map.len() - self.client_num()
    }

    /// Returns the number of clients for which we act as a proxy and which do not intend to become
    /// a node.
    pub fn client_num(&self) -> usize {
        self.client_map.values().filter(|&info| info.client_restriction).count()
    }

    /// Marks the given peer as "connected".
    pub fn connected_to(&mut self, peer_id: PeerId) -> bool {
        self.set_peer_state(peer_id, PeerState::Connected)
    }

    /// Marks the given peer as "Tunnelling to".
    pub fn tunnelling_to(&mut self, peer_id: PeerId) -> bool {
        self.set_peer_state(peer_id, PeerState::Tunnel)
    }

    /// Returns the public ID of the given peer, if it is in `CrustConnecting` state.
    pub fn get_connecting_peer(&mut self, peer_id: &PeerId) -> Option<&PublicId> {
        self.pub_id_map.get(peer_id).and_then(|pub_id| {
            match self.get_state(pub_id) {
                // Some(&PeerState::ConnectionInfoPreparing(..)) |
                // Some(&PeerState::ConnectionInfoReady(_)) |
                // Some(&PeerState::SearchingForTunnel) |
                Some(&PeerState::CrustConnecting) => Some(pub_id),
                _ => None,
            }
        })
    }

    /// Sets the given peer to state `SearchingForTunnel` or returns `false` if it doesn't exist.
    pub fn set_searching_for_tunnel(&mut self, peer_id: PeerId, pub_id: &PublicId) -> bool {
        match self.get_state(pub_id) {
            Some(&PeerState::Connected) |
            Some(&PeerState::Tunnel) => {
                return false;
            }
            _ => (),
        }
        let _ = self.pub_id_map.insert(peer_id, *pub_id);
        self.insert_state(*pub_id, PeerState::SearchingForTunnel);
        true
    }

    /// Inserts the given connection info in the map to wait for the peer's info, or returns both
    /// if that's already present and sets the status to `CrustConnecting`. It also returns the
    /// source and destination authorities for sending the serialised connection info to the peer.
    pub fn connection_info_prepared(&mut self,
                                    token: u32,
                                    our_info: PrivConnectionInfo)
                                    -> Result<ConnectionInfoPreparedResult, Error> {
        let pub_id = try!(self.connection_token_map.remove(&token).ok_or(Error::PeerNotFound));
        let (src, dst, opt_their_info) = match self.node_map.remove(&pub_id) {
            Some((_, PeerState::ConnectionInfoPreparing(src, dst, info))) => (src, dst, info),
            Some((timestamp, state)) => {
                let _ = self.node_map.insert(pub_id, (timestamp, state));
                return Err(Error::UnexpectedState);
            }
            None => return Err(Error::PeerNotFound),
        };
        Ok(ConnectionInfoPreparedResult {
            pub_id: pub_id,
            src: src,
            dst: dst,
            infos: match opt_their_info {
                Some(their_info) => {
                    self.insert_state(pub_id, PeerState::CrustConnecting);
                    Some((our_info, their_info))
                }
                None => {
                    self.insert_state(pub_id, PeerState::ConnectionInfoReady(our_info));
                    None
                }
            },
        })
    }

    /// Inserts the given connection info in the map to wait for the preparation of our own info, or
    /// returns both if that's already present and sets the status to `CrustConnecting`.
    pub fn connection_info_received(&mut self,
                                    src: Authority,
                                    dst: Authority,
                                    pub_id: PublicId,
                                    their_info: PubConnectionInfo)
                                    -> Result<ConnectionInfoReceivedResult, Error> {
        let peer_id = their_info.id();
        match self.node_map.remove(&pub_id) {
            Some((_, PeerState::ConnectionInfoReady(our_info))) => {
                self.insert_state(pub_id, PeerState::CrustConnecting);
                let _ = self.pub_id_map.insert(peer_id, pub_id);
                Ok(ConnectionInfoReceivedResult::Ready(our_info, their_info))
            }
            Some((_, PeerState::ConnectionInfoPreparing(src, dst, None))) => {
                let state = PeerState::ConnectionInfoPreparing(src, dst, Some(their_info));
                self.insert_state(pub_id, state);
                Ok(ConnectionInfoReceivedResult::Waiting)
            }
            Some((timestamp, state)) => {
                let _ = self.node_map.insert(pub_id, (timestamp, state));
                Err(Error::UnexpectedState)
            }
            None => {
                let state = PeerState::ConnectionInfoPreparing(src, dst, Some(their_info));
                self.insert_state(pub_id, state);
                let _ = self.pub_id_map.insert(peer_id, pub_id);
                let token = rand::random();
                let _ = self.connection_token_map.insert(token, pub_id);
                Ok(ConnectionInfoReceivedResult::Prepare(token))
            }
        }
    }

    /// Returns a new token for Crust's `prepare_connection_info` and puts the given peer into
    /// `ConnectionInfoPreparing` status.
    pub fn get_connection_info_token(&mut self,
                                     src: Authority,
                                     dst: Authority,
                                     pub_id: PublicId)
                                     -> u32 {
        let token = rand::random();
        let _ = self.connection_token_map.insert(token, pub_id);
        self.insert_state(pub_id, PeerState::ConnectionInfoPreparing(src, dst, None));
        token
    }

    /// Returns all peers we are looking for a tunnel to.
    pub fn peers_needing_tunnel(&self) -> Vec<PeerId> {
        self.pub_id_map
            .iter()
            .filter_map(|(peer_id, pub_id)| match self.get_state(pub_id) {
                Some(&PeerState::SearchingForTunnel) => Some(*peer_id),
                _ => None,
            })
            .collect()
    }
    pub fn allow_connect(&self, name: &XorName) -> bool {
        !self.routing_table.contains(name) && self.routing_table.allow_connection(name)
    }

    /// Returns `true` if we are in the process of connecting to the given peer.
    pub fn is_connecting(&self, pub_id: &PublicId) -> bool {
        match self.get_state(pub_id) {
            Some(&PeerState::ConnectionInfoPreparing(..)) |
            Some(&PeerState::ConnectionInfoReady(..)) |
            Some(&PeerState::CrustConnecting) => true,
            _ => false,
        }
    }

    /// Removes the given entry.
    pub fn remove_peer(&mut self, peer_id: &PeerId) {
        if let Some(pub_id) = self.pub_id_map.remove(peer_id) {
            let _ = self.node_map.remove(&pub_id);
        };
    }

    #[cfg(feature = "use-mock-crust")]
    /// Removes all entries that are not in `Connected` or `Tunnel` state.
    pub fn clear_caches(&mut self) {
        self.remove_expired();
    }

    fn set_peer_state(&mut self, peer_id: PeerId, state: PeerState) -> bool {
        if let Some(&pub_id) = self.pub_id_map.get(&peer_id) {
            self.insert_state(pub_id, state);
            true
        } else {
            trace!("{:?} not found. Cannot set state {:?}.", peer_id, state);
            false
        }
    }

    #[cfg(feature = "use-mock-crust")]
    fn insert_state(&mut self, pub_id: PublicId, state: PeerState) {
        // In mock Crust tests, "expired" entries are removed with `clear_caches`.
        let _ = self.node_map.insert(pub_id, (Instant::now(), state));
    }

    #[cfg(not(feature = "use-mock-crust"))]
    fn insert_state(&mut self, pub_id: PublicId, state: PeerState) {
        let _ = self.node_map.insert(pub_id, (Instant::now(), state));
        self.remove_expired();
    }

    fn get_state(&self, pub_id: &PublicId) -> Option<&PeerState> {
        self.node_map.get(pub_id).map(|&(_, ref state)| state)
    }

    // CONNECTION_TIMEOUT_SECS == 0 if use-mock-crust.
    #[cfg_attr(feature="clippy", allow(absurd_extreme_comparisons))]
    fn remove_expired(&mut self) {
        let remove_ids = self.node_map
            .iter()
            .filter(|&(_, &(ref timestamp, ref state))| match *state {
                PeerState::ConnectionInfoPreparing(..) |
                PeerState::ConnectionInfoReady(_) |
                PeerState::CrustConnecting |
                PeerState::SearchingForTunnel => {
                    timestamp.elapsed().as_secs() >= CONNECTION_TIMEOUT_SECS
                }
                PeerState::Connected | PeerState::Tunnel => false,
            })
            .map(|(pub_id, _)| *pub_id)
            .collect_vec();
        for pub_id in remove_ids {
            let _ = self.node_map.remove(&pub_id);
        }
        let remove_tokens = self.connection_token_map
            .iter()
            .filter(|&(_, pub_id)| !self.node_map.contains_key(pub_id))
            .map(|(token, _)| *token)
            .collect_vec();
        for token in remove_tokens {
            let _ = self.connection_token_map.remove(&token);
        }
        let remove_peer_ids = self.pub_id_map
            .iter()
            .filter(|&(_, pub_id)| !self.node_map.contains_key(pub_id))
            .map(|(peer_id, _)| *peer_id)
            .collect_vec();
        for peer_id in remove_peer_ids {
            let _ = self.pub_id_map.remove(&peer_id);
        }
    }
}

#[cfg(all(test, feature = "use-mock-crust"))]
mod tests {
    use super::*;
    use authority::Authority;
    use id::FullId;
    use mock_crust::crust::{PeerId, PrivConnectionInfo, PubConnectionInfo};
    use mock_crust::Endpoint;
    use xor_name::{XOR_NAME_LEN, XorName};

    fn node_auth(byte: u8) -> Authority {
        Authority::ManagedNode(XorName([byte; XOR_NAME_LEN]))
    }

    #[test]
    pub fn connection_info_prepare_receive() {
        let orig_pub_id = *FullId::new().public_id();
        let mut peer_mgr = PeerManager::new(NodeInfo::new(orig_pub_id, PeerId(0)));

        let our_connection_info = PrivConnectionInfo(PeerId(0), Endpoint(0));
        let their_connection_info = PubConnectionInfo(PeerId(1), Endpoint(1));
        // We decide to connect to the peer with `pub_id`:
        let token = peer_mgr.get_connection_info_token(node_auth(0), node_auth(1), orig_pub_id);
        // Crust has finished preparing the connection info.
        match peer_mgr.connection_info_prepared(token, our_connection_info.clone()) {
            Ok(ConnectionInfoPreparedResult { pub_id, src, dst, infos: None }) => {
                assert_eq!(orig_pub_id, pub_id);
                assert_eq!(node_auth(0), src);
                assert_eq!(node_auth(1), dst);
            }
            result => panic!("Unexpected result: {:?}", result),
        }
        // Finally, we received the peer's connection info.
        match peer_mgr.connection_info_received(node_auth(0),
                                                node_auth(1),
                                                orig_pub_id,
                                                their_connection_info.clone()) {
            Ok(ConnectionInfoReceivedResult::Ready(our_info, their_info)) => {
                assert_eq!(our_connection_info, our_info);
                assert_eq!(their_connection_info, their_info);
            }
            result => panic!("Unexpected result: {:?}", result),
        }
        // Since both connection infos are present, the state should now be `CrustConnecting`.
        match peer_mgr.get_state(&orig_pub_id) {
            Some(&PeerState::CrustConnecting) => (),
            state => panic!("Unexpected state: {:?}", state),
        }
    }

    #[test]
    pub fn connection_info_receive_prepare() {
        let orig_pub_id = *FullId::new().public_id();
        let mut peer_mgr = PeerManager::new(NodeInfo::new(orig_pub_id, PeerId(0)));
        let our_connection_info = PrivConnectionInfo(PeerId(0), Endpoint(0));
        let their_connection_info = PubConnectionInfo(PeerId(1), Endpoint(1));
        // We received a connection info from the peer and get a token to prepare ours.
        let token = match peer_mgr.connection_info_received(node_auth(0),
                                                            node_auth(1),
                                                            orig_pub_id,
                                                            their_connection_info.clone()) {
            Ok(ConnectionInfoReceivedResult::Prepare(token)) => token,
            result => panic!("Unexpected result: {:?}", result),
        };
        // Crust has finished preparing the connection info.
        match peer_mgr.connection_info_prepared(token, our_connection_info.clone()) {
            Ok(ConnectionInfoPreparedResult { pub_id,
                                              src,
                                              dst,
                                              infos: Some((our_info, their_info)) }) => {
                assert_eq!(orig_pub_id, pub_id);
                assert_eq!(node_auth(0), src);
                assert_eq!(node_auth(1), dst);
                assert_eq!(our_connection_info, our_info);
                assert_eq!(their_connection_info, their_info);
            }
            result => panic!("Unexpected result: {:?}", result),
        }
        // Since both connection infos are present, the state should now be `CrustConnecting`.
        match peer_mgr.get_state(&orig_pub_id) {
            Some(&PeerState::CrustConnecting) => (),
            state => panic!("Unexpected state: {:?}", state),
        }
    }
}
