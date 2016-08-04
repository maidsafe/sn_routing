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

use crust::{PeerId, PrivConnectionInfo, PubConnectionInfo};
use authority::Authority;
use sodiumoxide::crypto::sign;
use id::PublicId;
use itertools::Itertools;
use rand;
use std::collections::HashMap;
use std::collections::hash_map::Values;
use std::{error, fmt, mem};
use std::time::{Duration, Instant};
use xor_name::XorName;
use kademlia_routing_table::{AddedNodeDetails, DroppedNodeDetails, RoutingTable};

/// The group size for the routing table. This is the maximum that can be used for consensus.
pub const GROUP_SIZE: usize = 8;
/// The quorum for group consensus.
pub const QUORUM_SIZE: usize = 5;
/// Time (in seconds) after which a joining node will get dropped from the map
/// of joining nodes.
const JOINING_NODE_TIMEOUT_SECS: u64 = 300;
/// Time (in seconds) after which the connection to a peer is considered failed.
const CONNECTION_TIMEOUT_SECS: u64 = 90;
/// The number of entries beyond `GROUP_SIZE` that are not considered unnecessary in the routing
/// table.
const EXTRA_BUCKET_ENTRIES: usize = 2;

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
    /// We are connected - via a tunnel if the field is `true` - and waiting for a `NodeIdentify`.
    AwaitingNodeIdentify(bool),
    /// We are the proxy for the client
    Client,
    /// We are the proxy for the joining node
    JoiningNode,
    /// We are connected and routing to that peer - via a tunnel if the field is `true`.
    Routing(bool),
    /// We are connected to the peer who is our proxy node.
    Proxy,
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
    /// We are already connected: They are our proxy.
    IsProxy,
    /// We are already connected: They are our client.
    IsClient,
    /// We are already connected: They are becoming a routing node.
    IsJoiningNode,
    /// We are already connected: They are a routing peer.
    IsConnected,
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

/// Represents peer we are connected or attempting connection to.
pub struct Peer {
    pub_id: PublicId,
    peer_id: Option<PeerId>,
    state: PeerState,
    timestamp: Instant,
}

impl Peer {
    fn new(pub_id: PublicId, peer_id: Option<PeerId>, state: PeerState) -> Self {
        Peer {
            pub_id: pub_id,
            peer_id: peer_id,
            state: state,
            timestamp: Instant::now(),
        }
    }

    pub fn peer_id(&self) -> Option<&PeerId> {
        self.peer_id.as_ref()
    }

    pub fn pub_id(&self) -> &PublicId {
        &self.pub_id
    }

    pub fn name(&self) -> &XorName {
        self.pub_id.name()
    }

    pub fn state(&self) -> &PeerState {
        &self.state
    }

    fn is_expired(&self) -> bool {
        match self.state {
            PeerState::ConnectionInfoPreparing(..) |
            PeerState::ConnectionInfoReady(_) |
            PeerState::CrustConnecting |
            PeerState::SearchingForTunnel => {
                self.timestamp.elapsed() >= Duration::from_secs(CONNECTION_TIMEOUT_SECS)
            }
            PeerState::JoiningNode |
            PeerState::Proxy => {
                self.timestamp.elapsed() >= Duration::from_secs(JOINING_NODE_TIMEOUT_SECS)
            }
            PeerState::Client |
            PeerState::Routing(_) |
            PeerState::AwaitingNodeIdentify(_) => false,
        }
    }
}

/// Holds peers and provides efficient insertion and lookup and removal by peer id
/// and name.
struct PeerMap {
    peers: HashMap<XorName, Peer>,
    names: HashMap<PeerId, XorName>,
}

impl PeerMap {
    fn new() -> Self {
        PeerMap {
            peers: HashMap::new(),
            names: HashMap::new(),
        }
    }

    fn get(&self, peer_id: &PeerId) -> Option<&Peer> {
        if let Some(name) = self.names.get(peer_id) {
            self.peers.get(name)
        } else {
            None
        }
    }

    fn get_mut(&mut self, peer_id: &PeerId) -> Option<&mut Peer> {
        if let Some(name) = self.names.get(peer_id) {
            self.peers.get_mut(name)
        } else {
            None
        }
    }

    fn get_by_name(&self, name: &XorName) -> Option<&Peer> {
        self.peers.get(name)
    }

    // Iterator over all peers in the map.
    fn peers(&self) -> Values<XorName, Peer> {
        self.peers.values()
    }

    fn insert(&mut self, peer: Peer) -> Option<Peer> {
        if let Some(peer_id) = peer.peer_id {
            let _ = self.names.insert(peer_id, *peer.name());
        }

        self.peers.insert(*peer.name(), peer)
    }

    fn remove(&mut self, peer_id: &PeerId) -> Option<Peer> {
        if let Some(name) = self.names.remove(peer_id) {
            self.peers.remove(&name)
        } else {
            None
        }
    }

    fn remove_by_name(&mut self, name: &XorName) -> Option<Peer> {
        if let Some(peer) = self.peers.remove(name) {
            if let Some(peer_id) = peer.peer_id {
                let _ = self.names.remove(&peer_id);
            }

            Some(peer)
        } else {
            None
        }
    }
}

/// A container for information about other nodes in the network.
///
/// This keeps track of which nodes we know of, which ones we have tried to connect to, which IDs
/// we have verified, whom we are directly connected to or via a tunnel.
pub struct PeerManager {
    connection_token_map: HashMap<u32, PublicId>,
    peer_map: PeerMap,
    proxy_peer_id: Option<PeerId>,
    routing_table: RoutingTable<XorName>,
    our_public_id: PublicId,
}

impl PeerManager {
    /// Returns a new peer manager with no entries.
    pub fn new(our_public_id: PublicId) -> PeerManager {
        PeerManager {
            connection_token_map: HashMap::new(),
            peer_map: PeerMap::new(),
            proxy_peer_id: None,
            routing_table: RoutingTable::<XorName>::new(*our_public_id.name(),
                                                        GROUP_SIZE,
                                                        EXTRA_BUCKET_ENTRIES),
            our_public_id: our_public_id,
        }
    }

    /// Clears the routing table and resets this node's public ID.
    pub fn reset_routing_table(&mut self, our_public_id: PublicId) {
        self.our_public_id = our_public_id;
        let new_rt = RoutingTable::new(*our_public_id.name(), GROUP_SIZE, EXTRA_BUCKET_ENTRIES);
        let old_rt = mem::replace(&mut self.routing_table, new_rt);
        for name in old_rt.iter() {
            let _ = self.peer_map.remove_by_name(name);
        }

        self.cleanup_proxy_peer_id();
    }

    /// Returns the routing table.
    pub fn routing_table(&self) -> &RoutingTable<XorName> {
        &self.routing_table
    }

    /// Tries to add the given peer to the routing table, and returns the result, if successful.
    pub fn add_to_routing_table(&mut self,
                                pub_id: PublicId,
                                peer_id: PeerId)
                                -> Option<AddedNodeDetails<XorName>> {
        let result = self.routing_table.add(*pub_id.name());
        if result.is_some() {
            let tunnel = match self.peer_map.remove(&peer_id).map(|peer| peer.state) {
                Some(PeerState::SearchingForTunnel) |
                Some(PeerState::AwaitingNodeIdentify(true)) => true,
                Some(PeerState::Routing(tunnel)) => {
                    error!("Peer {:?} added to routing table, but already in state Routing.",
                           peer_id);
                    tunnel
                }
                _ => false,
            };

            let state = PeerState::Routing(tunnel);
            let _ = self.peer_map.insert(Peer::new(pub_id, Some(peer_id), state));
        }
        result
    }

    /// If unneeded, removes the given peer from the routing table and returns `true`.
    pub fn remove_if_unneeded(&mut self, name: &XorName, peer_id: &PeerId) -> bool {
        if self.get_proxy_public_id(peer_id).is_some() || self.get_client(peer_id).is_some() ||
           self.get_joining_node(peer_id).is_some() ||
           Some(name) != self.peer_map.get(peer_id).map(Peer::name) ||
           !self.routing_table.remove_if_unneeded(name) {
            return false;
        }
        let _ = self.peer_map.remove(peer_id);
        true
    }

    /// Returns `true` if we are directly connected to both peers.
    pub fn can_tunnel_for(&self, peer_id: &PeerId, dst_id: &PeerId) -> bool {
        let peer_state = self.get_state(peer_id);
        let dst_state = self.get_state(dst_id);
        match (peer_state, dst_state) {
            (Some(&PeerState::Routing(false)), Some(&PeerState::Routing(false))) => true,
            _ => false,
        }
    }

    /// Returns the public ID of the given peer, if it is in `Routing` state.
    pub fn get_routing_peer(&self, peer_id: &PeerId) -> Option<&PublicId> {
        self.peer_map.get(peer_id).and_then(|peer| {
            if let PeerState::Routing(_) = peer.state {
                Some(&peer.pub_id)
            } else {
                None
            }
        })
    }

    /// Returns the proxy node, if connected.
    pub fn proxy(&self) -> Option<(&PeerId, &PublicId)> {
        if let Some(peer_id) = self.proxy_peer_id.as_ref() {
            if let Some(peer) = self.peer_map.get(peer_id) {
                return Some((peer_id, &peer.pub_id));
            }
        }

        None
    }

    /// Returns the proxy node's public ID, if it has the given peer ID.
    pub fn get_proxy_public_id(&self, peer_id: &PeerId) -> Option<&PublicId> {
        if Some(*peer_id) == self.proxy_peer_id {
            self.peer_map.get(peer_id).map(Peer::pub_id)
        } else {
            None
        }
    }

    /// Returns the proxy node's peer ID, if it has the given name.
    pub fn get_proxy_peer_id(&self, name: &XorName) -> Option<&PeerId> {
        if let Some(ref peer_id) = self.proxy_peer_id {
            if self.peer_map.get(peer_id).map(Peer::name) == Some(name) {
                return Some(peer_id);
            }
        }

        None
    }

    /// Inserts the given peer as a proxy node if applicable, returns `false` if it is not accepted
    /// and should be disconnected.
    pub fn set_proxy(&mut self, peer_id: PeerId, pub_id: PublicId) -> bool {
        if let Some(proxy_peer_id) = self.proxy_peer_id {
            debug!("Not accepting further bootstrap connections.");
            proxy_peer_id == peer_id
        } else {
            let _ = self.insert_peer(pub_id, Some(peer_id), PeerState::Proxy);
            self.proxy_peer_id = Some(peer_id);
            true
        }
    }

    /// Inserts the given client into the map. Returns true if we already had
    /// a peer with the given peer id.
    pub fn insert_client(&mut self, peer_id: PeerId, pub_id: PublicId) -> bool {
        self.insert_peer(pub_id, Some(peer_id), PeerState::Client)
    }

    /// Returns the given client's public key, if present.
    pub fn get_client(&self, peer_id: &PeerId) -> Option<&sign::PublicKey> {
        self.peer_map.get(peer_id).and_then(|peer| match peer.state {
            PeerState::Client => Some(peer.pub_id.signing_public_key()),
            _ => None,
        })
    }

    /// Inserts the given joining node into the map. Returns true if we already
    /// had a peer with the given peer id.
    pub fn insert_joining_node(&mut self, peer_id: PeerId, pub_id: PublicId) -> bool {
        self.insert_peer(pub_id, Some(peer_id), PeerState::JoiningNode)
    }

    /// Returns the given joining node's public key, if present.
    pub fn get_joining_node(&self, peer_id: &PeerId) -> Option<&sign::PublicKey> {
        self.peer_map.get(peer_id).and_then(|peer| match peer.state {
            PeerState::JoiningNode => Some(peer.pub_id.signing_public_key()),
            _ => None,
        })
    }

    /// Removes all joining nodes that have timed out, and returns their peer
    /// IDs. Also, removes our proxy if we have timed out.
    pub fn remove_expired_joining_nodes(&mut self) -> Vec<PeerId> {
        let expired_ids = self.peer_map
            .peers()
            .filter(|peer| match peer.state {
                PeerState::JoiningNode |
                PeerState::Proxy => peer.is_expired(),
                _ => false,
            })
            .filter_map(|peer| peer.peer_id)
            .collect_vec();

        for peer_id in &expired_ids {
            let _ = self.remove_peer(peer_id);
        }

        self.cleanup_proxy_peer_id();

        expired_ids
    }

    /// Returns the peer ID of the given node if it is our proxy or client or
    /// joining node.
    pub fn get_proxy_or_client_or_joining_node_peer_id(&self, pub_id: &PublicId) -> Option<PeerId> {
        if let Some(peer) = self.peer_map.get_by_name(pub_id.name()) {
            match peer.state {
                PeerState::Client |
                PeerState::JoiningNode |
                PeerState::Proxy => peer.peer_id,
                _ => None,
            }
        } else {
            None
        }
    }

    /// Returns the number of clients for which we act as a proxy and which intend to become a
    /// node.
    pub fn joining_nodes_num(&self) -> usize {
        self.peer_map
            .peers()
            .filter(|&peer| match peer.state {
                PeerState::JoiningNode => true,
                _ => false,
            })
            .count()
    }

    /// Returns the number of clients for which we act as a proxy and which do not intend to become
    /// a node.
    pub fn client_num(&self) -> usize {
        self.peer_map
            .peers()
            .filter(|&peer| match peer.state {
                PeerState::Client => true,
                _ => false,
            })
            .count()
    }

    /// Marks the given peer as "connected and waiting for `NodeIdentify`".
    pub fn connected_to(&mut self, peer_id: &PeerId) -> bool {
        self.set_state(peer_id, PeerState::AwaitingNodeIdentify(false))
    }

    /// Marks the given peer as "connected via tunnel and waiting for `NodeIdentify`".
    pub fn tunnelling_to(&mut self, peer_id: &PeerId) -> bool {
        self.set_state(peer_id, PeerState::AwaitingNodeIdentify(true))
    }

    /// Returns the public ID of the given peer, if it is in `CrustConnecting` state.
    pub fn get_connecting_peer(&self, peer_id: &PeerId) -> Option<&PublicId> {
        self.peer_map.get(peer_id).and_then(|peer| {
            if let PeerState::CrustConnecting = peer.state {
                return Some(&peer.pub_id);
            } else {
                None
            }
        })
    }

    /// Returns the peer with the given peer_id if it is already in one of the
    /// connected states.
    pub fn get_connected_peer(&self, peer_id: &PeerId) -> Option<&Peer> {
        self.peer_map.get(peer_id).and_then(|peer| {
            match peer.state {
                PeerState::Client |
                PeerState::JoiningNode |
                PeerState::Proxy |
                PeerState::Routing(_) => Some(peer),
                _ => None,
            }
        })
    }

    /// Return the PeerIds of nodes bearing the names.
    pub fn get_peer_ids(&self, names: &[XorName]) -> Vec<PeerId> {
        names.iter()
            .filter_map(|name| self.peer_map.get_by_name(name).and_then(Peer::peer_id))
            .cloned()
            .collect()
    }

    /// Return the PublicIds of nodes bearing the names.
    pub fn get_pub_ids(&self, names: &[XorName]) -> Vec<PublicId> {
        let mut result_map = names.iter()
            .filter_map(|name| {
                if let Some(peer) = self.peer_map.get_by_name(name) {
                    Some((*name, peer.pub_id))
                } else {
                    None
                }
            })
            .collect::<HashMap<_, _>>();

        if names.contains(self.our_public_id.name()) {
            let _ = result_map.insert(*self.our_public_id.name(), self.our_public_id);
        }

        names.iter()
            .filter_map(|name| result_map.get(name))
            .cloned()
            .collect()
    }

    /// Sets the given peer to state `SearchingForTunnel` and returns querying candidates.
    /// Returns empty vector of candidates if it is already in Routing state.
    pub fn set_searching_for_tunnel(&mut self,
                                    peer_id: PeerId,
                                    pub_id: PublicId)
                                    -> Vec<(XorName, PeerId)> {
        match self.get_state_by_name(pub_id.name()) {
            Some(&PeerState::Client) |
            Some(&PeerState::JoiningNode) |
            Some(&PeerState::Proxy) |
            Some(&PeerState::Routing(_)) |
            Some(&PeerState::AwaitingNodeIdentify(_)) => return vec![],
            _ => (),
        }

        let _ = self.insert_peer(pub_id, Some(peer_id), PeerState::SearchingForTunnel);

        let close_group = self.routing_table.closest_nodes_to(pub_id.name(), GROUP_SIZE, false);
        self.peer_map
            .peers()
            .filter_map(|peer| peer.peer_id.map(|peer_id| (*peer.name(), peer_id)))
            .filter(|&(name, _)| close_group.contains(&name))
            .collect()
    }

    /// Inserts the given connection info in the map to wait for the peer's info, or returns both
    /// if that's already present and sets the status to `CrustConnecting`. It also returns the
    /// source and destination authorities for sending the serialised connection info to the peer.
    pub fn connection_info_prepared(&mut self,
                                    token: u32,
                                    our_info: PrivConnectionInfo)
                                    -> Result<ConnectionInfoPreparedResult, Error> {
        let pub_id = try!(self.connection_token_map.remove(&token).ok_or(Error::PeerNotFound));
        let (src, dst, opt_their_info) = match self.peer_map.remove_by_name(pub_id.name()) {
            Some(Peer { state: PeerState::ConnectionInfoPreparing(src, dst, info), .. }) => {
                (src, dst, info)
            }
            Some(peer) => {
                let _ = self.peer_map.insert(peer);
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
                    let state = PeerState::CrustConnecting;
                    self.insert_peer(pub_id, Some(their_info.id()), state);
                    Some((our_info, their_info))
                }
                None => {
                    let state = PeerState::ConnectionInfoReady(our_info);
                    self.insert_peer(pub_id, None, state);
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

        match self.peer_map.remove_by_name(pub_id.name()) {
            Some(Peer { state: PeerState::ConnectionInfoReady(our_info), .. }) => {
                let state = PeerState::CrustConnecting;
                self.insert_peer(pub_id, Some(peer_id), state);
                Ok(ConnectionInfoReceivedResult::Ready(our_info, their_info))
            }
            Some(Peer { state: PeerState::ConnectionInfoPreparing(src, dst, None), .. }) => {
                let state = PeerState::ConnectionInfoPreparing(src, dst, Some(their_info));
                self.insert_peer(pub_id, Some(peer_id), state);
                Ok(ConnectionInfoReceivedResult::Waiting)
            }
            Some(peer @ Peer { state: PeerState::CrustConnecting, .. }) => {
                let _ = self.peer_map.insert(peer);
                Ok(ConnectionInfoReceivedResult::Waiting)
            }
            Some(peer @ Peer { state: PeerState::Client, .. }) => {
                let _ = self.peer_map.insert(peer);
                Ok(ConnectionInfoReceivedResult::IsClient)
            }
            Some(peer @ Peer { state: PeerState::JoiningNode, .. }) => {
                let _ = self.peer_map.insert(peer);
                Ok(ConnectionInfoReceivedResult::IsJoiningNode)
            }
            Some(peer @ Peer { state: PeerState::Proxy, .. }) => {
                let _ = self.peer_map.insert(peer);
                Ok(ConnectionInfoReceivedResult::IsProxy)
            }
            Some(peer @ Peer { state: PeerState::Routing(_), .. }) => {
                // TODO: We _should_ retry connecting if the peer is connected via tunnel.
                let _ = self.peer_map.insert(peer);
                Ok(ConnectionInfoReceivedResult::IsConnected)
            }
            Some(peer) => {
                let _ = self.peer_map.insert(peer);
                Err(Error::UnexpectedState)
            }
            None => {
                let state = PeerState::ConnectionInfoPreparing(src, dst, Some(their_info));
                self.insert_peer(pub_id, Some(peer_id), state);
                let token = rand::random();
                let _ = self.connection_token_map.insert(token, pub_id);
                Ok(ConnectionInfoReceivedResult::Prepare(token))
            }
        }
    }

    /// Returns a new token for Crust's `prepare_connection_info` and puts the given peer into
    /// `ConnectionInfoPreparing` status.
    pub fn get_connection_token(&mut self,
                                src: Authority,
                                dst: Authority,
                                pub_id: PublicId)
                                -> Option<u32> {
        match self.get_state_by_name(pub_id.name()) {
            Some(&PeerState::AwaitingNodeIdentify(_)) |
            Some(&PeerState::Client) |
            Some(&PeerState::ConnectionInfoPreparing(..)) |
            Some(&PeerState::ConnectionInfoReady(..)) |
            Some(&PeerState::CrustConnecting) |
            Some(&PeerState::JoiningNode) |
            Some(&PeerState::Proxy) |
            Some(&PeerState::Routing(_)) => return None,
            Some(&PeerState::SearchingForTunnel) |
            None => (),
        }
        let token = rand::random();
        let _ = self.connection_token_map.insert(token, pub_id);
        self.insert_peer(pub_id,
                         None,
                         PeerState::ConnectionInfoPreparing(src, dst, None));
        Some(token)
    }

    /// Returns all peers we are looking for a tunnel to.
    pub fn peers_needing_tunnel(&self) -> Vec<PeerId> {
        self.peer_map
            .peers()
            .filter_map(|peer| match peer.state {
                PeerState::SearchingForTunnel => peer.peer_id,
                _ => None,
            })
            .collect()
    }

    /// Returns `true` if the given peer is not yet in the routing table but is allowed to connect.
    pub fn allow_connect(&self, name: &XorName) -> bool {
        !self.routing_table.contains(name) && self.routing_table.allow_connection(name)
    }

    /// Removes the given entry, returns the removed peer and if it was a routing node,
    /// the removal details
    pub fn remove_peer(&mut self, peer_id: &PeerId) -> Option<(Peer, Option<DroppedNodeDetails>)> {
        if let Some(peer) = self.peer_map.remove(peer_id) {
            self.cleanup_proxy_peer_id();
            let name = *peer.name();
            Some((peer, self.routing_table.remove(&name)))
        } else {
            None
        }
    }

    fn get_state(&self, peer_id: &PeerId) -> Option<&PeerState> {
        self.peer_map.get(peer_id).map(Peer::state)
    }

    pub fn get_state_by_name(&self, name: &XorName) -> Option<&PeerState> {
        self.peer_map.get_by_name(name).map(Peer::state)
    }

    fn set_state(&mut self, peer_id: &PeerId, state: PeerState) -> bool {
        if let Some(peer) = self.peer_map.get_mut(peer_id) {
            peer.state = state;
            true
        } else {
            trace!("{:?} not found. Cannot set state {:?}.", peer_id, state);
            false
        }
    }

    fn insert_peer(&mut self, pub_id: PublicId, peer_id: Option<PeerId>, state: PeerState) -> bool {
        let result = self.peer_map.insert(Peer::new(pub_id, peer_id, state)).is_some();
        self.remove_expired();
        result
    }

    fn remove_expired(&mut self) {
        self.remove_expired_peers();
        self.remove_expired_tokens();
        self.cleanup_proxy_peer_id();
    }

    fn remove_expired_peers(&mut self) {
        let expired_names = self.peer_map
            .peers()
            .filter(|peer| peer.is_expired())
            .map(|peer| *peer.name())
            .collect_vec();

        for name in expired_names {
            let _ = self.peer_map.remove_by_name(&name);
        }

        self.cleanup_proxy_peer_id();
    }

    fn remove_expired_tokens(&mut self) {
        let remove_tokens = self.connection_token_map
            .iter()
            .filter(|&(_, pub_id)| match self.get_state_by_name(pub_id.name()) {
                Some(&PeerState::ConnectionInfoPreparing(..)) => false,
                _ => true,
            })
            .map(|(token, _)| *token)
            .collect_vec();

        for token in remove_tokens {
            let _ = self.connection_token_map.remove(&token);
        }
    }

    fn cleanup_proxy_peer_id(&mut self) {
        if let Some(peer_id) = self.proxy_peer_id {
            if self.peer_map.get(&peer_id).is_none() {
                self.proxy_peer_id = None;
            }
        }
    }
}

#[cfg(feature = "use-mock-crust")]
impl PeerManager {
    pub fn remove_connecting_peers(&mut self) {
        // Remove all peers that are not yet connected.
        let remove_names = self.peer_map
            .peers()
            .filter(|peer| match peer.state {
                PeerState::ConnectionInfoPreparing(..) |
                PeerState::ConnectionInfoReady(_) |
                PeerState::CrustConnecting |
                PeerState::SearchingForTunnel => true,
                _ => false,
            })
            .map(|peer| *peer.name())
            .collect_vec();

        for name in remove_names {
            let _ = self.peer_map.remove_by_name(&name);
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
        let mut peer_mgr = PeerManager::new(orig_pub_id);

        let our_connection_info = PrivConnectionInfo(PeerId(0), Endpoint(0));
        let their_connection_info = PubConnectionInfo(PeerId(1), Endpoint(1));
        // We decide to connect to the peer with `pub_id`:
        let token = unwrap!(peer_mgr.get_connection_token(node_auth(0), node_auth(1), orig_pub_id));
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
        match peer_mgr.get_state_by_name(orig_pub_id.name()) {
            Some(&PeerState::CrustConnecting) => (),
            state => panic!("Unexpected state: {:?}", state),
        }
    }

    #[test]
    pub fn connection_info_receive_prepare() {
        let orig_pub_id = *FullId::new().public_id();
        let mut peer_mgr = PeerManager::new(orig_pub_id);
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
        match peer_mgr.get_state_by_name(orig_pub_id.name()) {
            Some(&PeerState::CrustConnecting) => (),
            state => panic!("Unexpected state: {:?}", state),
        }
    }
}
