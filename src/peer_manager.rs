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
#[cfg(not(feature = "use-mock-crust"))]
const JOINING_NODE_TIMEOUT_SECS: u64 = 300;

/// Time (in seconds) after which the connection to a peer is considered failed.
#[cfg(not(feature = "use-mock-crust"))]
const CONNECTION_TIMEOUT_SECS: u64 = 90;

/// With mock Crust, all pending connections are removed explicitly.
#[cfg(feature = "use-mock-crust")]
const CONNECTION_TIMEOUT_SECS: u64 = 0;
#[cfg(feature = "use-mock-crust")]
const JOINING_NODE_TIMEOUT_SECS: u64 = 0;

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
    Client(sign::PublicKey),
    /// We are the proxy for the joining node
    JoiningNode(sign::PublicKey),
    /// We are connected and routing to that peer - via a tunnel if the field is `true`.
    Routing(bool),
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

pub struct Peer(Instant, PeerState);

impl Peer {
    fn new(state: PeerState) -> Self {
        Peer(Instant::now(), state)
    }

    pub fn state(&self) -> &PeerState {
        &self.1
    }

    fn is_stale(&self) -> bool {
        match self.1 {
            PeerState::JoiningNode(_) => {
                self.0.elapsed() > Duration::from_secs(JOINING_NODE_TIMEOUT_SECS)
            }
            _ => false,
        }
    }
}

/// A container for information about other nodes in the network.
///
/// This keeps track of which nodes we know of, which ones we have tried to connect to, which IDs
/// we have verified, whom we are directly connected to or via a tunnel.
pub struct PeerManager {
    connection_token_map: HashMap<u32, PublicId>,
    // node_map indexed by public_id.name()
    peer_map: HashMap<XorName, Peer>,
    /// Our bootstrap connection.
    proxy: Option<(Instant, PeerId, PublicId)>,
    pub_id_map: HashMap<PeerId, PublicId>,
    routing_table: RoutingTable<XorName>,
    our_public_id: PublicId,
}

impl PeerManager {
    /// Returns a new peer manager with no entries.
    pub fn new(our_public_id: PublicId) -> PeerManager {
        PeerManager {
            connection_token_map: HashMap::new(),
            peer_map: HashMap::new(),
            proxy: None,
            pub_id_map: HashMap::new(),
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
            let _ = self.peer_map.remove(name);
        }
        self.cleanup_pub_id_map();
    }

    /// Returns the routing table.
    pub fn routing_table(&self) -> &RoutingTable<XorName> {
        &self.routing_table
    }

    /// Tries to add the given peer to the routing table, and returns the result, if successful.
    pub fn add_to_routing_table(&mut self,
                                public_id: PublicId,
                                peer_id: PeerId)
                                -> Option<AddedNodeDetails<XorName>> {
        let result = self.routing_table.add(*public_id.name());
        if result.is_some() {
            let state = PeerState::Routing(match self.peer_map.remove(public_id.name()) {
                Some(Peer(_, PeerState::SearchingForTunnel)) |
                Some(Peer(_, PeerState::AwaitingNodeIdentify(true))) => true,
                Some(Peer(_, PeerState::Routing(tunnel))) => {
                    error!("Peer {:?} added to routing table, but already in state Routing.",
                           peer_id);
                    tunnel
                }
                _ => false,
            });
            let _ = self.peer_map.insert(*public_id.name(), Peer::new(state));
            let _ = self.pub_id_map.insert(peer_id, public_id);
        }
        result
    }

    /// If unneeded, removes the given peer from the routing table and returns `true`.
    pub fn remove_if_unneeded(&mut self, name: &XorName, peer_id: &PeerId) -> bool {
        if self.get_proxy_public_id(peer_id).is_some() ||
           self.get_client(peer_id).is_some() ||
           self.get_joining_node(peer_id).is_some() ||
           Some(name) != self.pub_id_map.get(peer_id).map(PublicId::name) ||
           !self.routing_table.remove_if_unneeded(name) {
            return false;
        }
        let _ = self.pub_id_map.remove(peer_id);
        let _ = self.peer_map.remove(name);
        true
    }

    /// Returns `true` if we are directly connected to both peers.
    pub fn can_tunnel_for(&self, peer_id: &PeerId, dst_id: &PeerId) -> bool {
        let peer_state = self.pub_id_map.get(peer_id).and_then(|pub_id| self.get_state(pub_id));
        let dst_state = self.pub_id_map.get(dst_id).and_then(|pub_id| self.get_state(pub_id));
        match (peer_state, dst_state) {
            (Some(&PeerState::Routing(false)), Some(&PeerState::Routing(false))) => true,
            _ => false,
        }
    }

    /// Returns the proxy node, if connected.
    pub fn proxy(&self) -> &Option<(Instant, PeerId, PublicId)> {
        &self.proxy
    }

    /// Returns the proxy node's public ID, if it has the given peer ID.
    pub fn get_proxy_public_id(&self, peer_id: &PeerId) -> Option<&PublicId> {
        match self.proxy {
            Some((_, ref proxy_id, ref pub_id)) if proxy_id == peer_id => Some(pub_id),
            _ => None,
        }
    }

    /// Returns the proxy node's peer ID, if it has the given name.
    pub fn get_proxy_peer_id(&self, name: &XorName) -> Option<&PeerId> {
        match self.proxy {
            Some((_, ref peer_id, ref pub_id)) if pub_id.name() == name => Some(peer_id),
            _ => None,
        }
    }

    /// Inserts the given peer as a proxy node if applicable, returns `false` if it is not accepted
    /// and should be disconnected.
    pub fn set_proxy(&mut self, peer_id: PeerId, public_id: PublicId) -> bool {
        if let Some((_, ref proxy_id, _)) = self.proxy {
            debug!("Not accepting further bootstrap connections.");
            *proxy_id == peer_id
        } else {
            self.proxy = Some((Instant::now(), peer_id, public_id));
            true
        }
    }

    /// Inserts the given client into the map. Returns true if we already had
    /// a peer with the given peer id.
    pub fn insert_client(&mut self, peer_id: PeerId, pub_id: &PublicId) -> bool {
        let state = PeerState::Client(*pub_id.signing_public_key());
        self.insert_state(*pub_id, state);
        self.pub_id_map.insert(peer_id, *pub_id).is_some()
    }

    /// Returns the given client's public key, if present.
    pub fn get_client(&self, peer_id: &PeerId) -> Option<&sign::PublicKey> {
        self.get_state_by_peer_id(peer_id).and_then(|state| match state {
            &PeerState::Client(ref pub_key) => Some(pub_key),
            _ => None,
        })
    }

    /// Removes the given peer ID from the client nodes and returns whether it was present.
    pub fn remove_client(&mut self, peer_id: &PeerId) -> bool {
        if let Some(&PeerState::Client(_)) = self.get_state_by_peer_id(peer_id) {
            self.remove_peer(peer_id).is_some()
        } else {
            false
        }
    }

    /// Inserts the given joining node into the map. Returns true if we already
    /// had a peer with the given peer id.
    pub fn insert_joining_node(&mut self, peer_id: PeerId, pub_id: &PublicId) -> bool {
        let state = PeerState::JoiningNode(*pub_id.signing_public_key());
        self.insert_state(*pub_id, state);
        self.pub_id_map.insert(peer_id, *pub_id).is_some()
    }

    /// Returns the given joining node's public key, if present.
    pub fn get_joining_node(&self, peer_id: &PeerId) -> Option<&sign::PublicKey> {
        self.get_state_by_peer_id(peer_id).and_then(|state| match state {
            &PeerState::JoiningNode(ref pub_key) => Some(pub_key),
            _ => None,
        })
    }

    /// Removes the given joining nodes and returns whether it was present.
    pub fn remove_joining_node(&mut self, peer_id: &PeerId) -> bool {
        if let Some(&PeerState::JoiningNode(_)) = self.get_state_by_peer_id(peer_id) {
            self.remove_peer(peer_id).is_some()
        } else {
            false
        }
    }

    /// Removes all joining nodes that have timed out, and returns their peer
    /// IDs. Also, removes our proxy if we have timed out.
    pub fn remove_stale_joining_nodes(&mut self) -> Vec<PeerId> {
        let mut stale_ids = self.pub_id_map
            .iter()
            .filter(|&(_, pub_id)| self.peer_map.get(pub_id.name())
                                                .map(Peer::is_stale)
                                                .unwrap_or(false))
            .map(|(peer_id, _)| *peer_id)
            .collect_vec();

        for peer_id in &stale_ids {
            let _ = self.remove_peer(peer_id);
        }

        if let Some((timestamp, peer_id, pub_id)) = self.proxy.take() {
            if timestamp.elapsed() > Duration::from_secs(JOINING_NODE_TIMEOUT_SECS) {
                stale_ids.push(peer_id);
            } else {
                self.proxy = Some((timestamp, peer_id, pub_id));
            }
        }

        stale_ids
    }

    /// Returns the peer ID of the given node if it is our proxy or client.
    pub fn get_proxy_or_client_peer_id(&self, pub_id: &PublicId) -> Option<PeerId> {
        let peer_id = match self.peer_map.get(pub_id.name()) {
            Some(&Peer(_, PeerState::Client(_))) |
            Some(&Peer(_, PeerState::JoiningNode(_))) => self.get_peer_id(pub_id),
            _ => None,
        };

        if let Some(peer_id) = peer_id {
            return Some(*peer_id);
        }

        match self.proxy {
            Some((_, peer_id, ref proxy_pub_id)) if proxy_pub_id == pub_id => Some(peer_id),
            _ => None,
        }
    }

    /// Returns the number of clients for which we act as a proxy and which intend to become a
    /// node.
    pub fn joining_nodes_num(&self) -> usize {
        self.peer_map.values().filter(|&peer| match peer {
            &Peer(_, PeerState::JoiningNode(_)) => true,
            _ => false,
        }).count()
    }

    /// Returns the number of clients for which we act as a proxy and which do not intend to become
    /// a node.
    pub fn client_num(&self) -> usize {
        self.peer_map.values().filter(|&peer| match peer {
            &Peer(_, PeerState::Client(_)) => true,
            _ => false,
        }).count()
    }

    /// Marks the given peer as "connected and waiting for `NodeIdentify`".
    pub fn connected_to(&mut self, peer_id: PeerId) -> bool {
        self.set_peer_state(peer_id, PeerState::AwaitingNodeIdentify(false))
    }

    /// Marks the given peer as "connected via tunnel and waiting for `NodeIdentify`".
    pub fn tunnelling_to(&mut self, peer_id: PeerId) -> bool {
        self.set_peer_state(peer_id, PeerState::AwaitingNodeIdentify(true))
    }

    /// Returns the public ID of the given peer, if it is in `CrustConnecting` state.
    pub fn get_connecting_peer(&mut self, peer_id: &PeerId) -> Option<&PublicId> {
        self.pub_id_map.get(peer_id).and_then(|pub_id| {
            match self.get_state(pub_id) {
                Some(&PeerState::CrustConnecting) => Some(pub_id),
                _ => None,
            }
        })
    }

    /// Return the PeerIds of nodes bearing the names.
    pub fn get_peer_ids(&self, names: &[XorName]) -> Vec<PeerId> {
        self.pub_id_map
            .iter()
            .filter_map(|(peer_id, pub_id)| if names.contains(pub_id.name()) {
                Some(*peer_id)
            } else {
                None
            })
            .collect()
    }

    /// Return the PublicIds of nodes bearing the names.
    pub fn get_pub_ids(&self, names: &[XorName]) -> Vec<PublicId> {
        let mut result_map: HashMap<XorName, PublicId> = HashMap::new();
        for pub_id in self.pub_id_map.values() {
            if names.contains(pub_id.name()) {
                let _ = result_map.insert(*pub_id.name(), *pub_id);
            }
        }
        if names.contains(self.our_public_id.name()) {
            let _ = result_map.insert(*self.our_public_id.name(), self.our_public_id);
        }
        names.iter()
            .filter_map(|name| result_map.get(name))
            .cloned()
            .collect()
    }

    /// Returns the public ID of the given peer, if it is in `Routing` state.
    pub fn get_routing_peer(&self, peer_id: &PeerId) -> Option<&PublicId> {
        self.pub_id_map.get(peer_id).and_then(|pub_id| {
            if let Some(&PeerState::Routing(_)) = self.get_state(pub_id) {
                Some(pub_id)
            } else {
                None
            }
        })
    }

    /// Sets the given peer to state `SearchingForTunnel` and returns querying candidates.
    /// Returns empty vector of candidates if it is already in Routing state.
    pub fn set_searching_for_tunnel(&mut self,
                                    peer_id: PeerId,
                                    pub_id: &PublicId)
                                    -> Vec<(XorName, PeerId)> {
        match self.get_state(pub_id) {
            Some(&PeerState::Routing(_)) |
            Some(&PeerState::AwaitingNodeIdentify(_)) => return vec![],
            _ => (),
        }
        let _ = self.pub_id_map.insert(peer_id, *pub_id);
        self.insert_state(*pub_id, PeerState::SearchingForTunnel);
        let close_group = self.routing_table.closest_nodes_to(pub_id.name(), GROUP_SIZE, false);
        self.pub_id_map
            .iter()
            .filter_map(|(peer_id, pub_id)| if close_group.contains(pub_id.name()) {
                Some((*pub_id.name(), *peer_id))
            } else {
                None
            })
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
        let (src, dst, opt_their_info) = match self.peer_map.remove(pub_id.name()) {
            Some(Peer(_, PeerState::ConnectionInfoPreparing(src, dst, info))) => (src, dst, info),
            Some(Peer(timestamp, state)) => {
                let _ = self.peer_map.insert(*pub_id.name(), Peer(timestamp, state));
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
                    let _ = self.pub_id_map.insert(their_info.id(), pub_id);
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

        if self.get_proxy_public_id(&peer_id).is_some() {
            return Ok(ConnectionInfoReceivedResult::IsProxy);
        }

        match self.peer_map.remove(pub_id.name()) {
            Some(Peer(_, PeerState::ConnectionInfoReady(our_info))) => {
                self.insert_state(pub_id, PeerState::CrustConnecting);
                let _ = self.pub_id_map.insert(peer_id, pub_id);
                Ok(ConnectionInfoReceivedResult::Ready(our_info, their_info))
            }
            Some(Peer(_, PeerState::ConnectionInfoPreparing(src, dst, None))) => {
                let state = PeerState::ConnectionInfoPreparing(src, dst, Some(their_info));
                self.insert_state(pub_id, state);
                Ok(ConnectionInfoReceivedResult::Waiting)
            }
            Some(Peer(_, PeerState::CrustConnecting)) => {
                self.insert_state(pub_id, PeerState::CrustConnecting);
                Ok(ConnectionInfoReceivedResult::Waiting)
            }
            Some(Peer(_, PeerState::Client(pub_key))) => {
                self.insert_state(pub_id, PeerState::Client(pub_key));
                Ok(ConnectionInfoReceivedResult::IsClient)
            }
            Some(Peer(_, PeerState::JoiningNode(pub_key))) => {
                self.insert_state(pub_id, PeerState::JoiningNode(pub_key));
                Ok(ConnectionInfoReceivedResult::IsJoiningNode)
            }
            Some(Peer(timestamp, PeerState::Routing(tunnel))) => {
                // TODO: We _should_ retry connecting if the peer is connected via tunnel.
                let _ = self.peer_map
                    .insert(*pub_id.name(), Peer(timestamp, PeerState::Routing(tunnel)));
                Ok(ConnectionInfoReceivedResult::IsConnected)
            }
            Some(Peer(timestamp, state)) => {
                let _ = self.peer_map.insert(*pub_id.name(), Peer(timestamp, state));
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
    pub fn get_connection_token(&mut self,
                                src: Authority,
                                dst: Authority,
                                pub_id: PublicId)
                                -> Option<u32> {
        match self.get_state(&pub_id) {
            Some(&PeerState::AwaitingNodeIdentify(_)) |
            Some(&PeerState::Client(_)) |
            Some(&PeerState::ConnectionInfoPreparing(..)) |
            Some(&PeerState::ConnectionInfoReady(..)) |
            Some(&PeerState::CrustConnecting) |
            Some(&PeerState::JoiningNode(_)) |
            Some(&PeerState::Routing(_)) => return None,
            Some(&PeerState::SearchingForTunnel) |
            None => (),
        }
        let token = rand::random();
        let _ = self.connection_token_map.insert(token, pub_id);
        self.insert_state(pub_id, PeerState::ConnectionInfoPreparing(src, dst, None));
        Some(token)
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

    /// Returns `true` if the given peer is not yet in the routing table but is allowed to connect.
    pub fn allow_connect(&self, name: &XorName) -> bool {
        !self.routing_table.contains(name) && self.routing_table.allow_connection(name)
    }

    /// Removes the given entry, returns the pair of (peer's public name, the removal result)
    pub fn remove_peer(&mut self, peer_id: &PeerId) -> Option<(XorName, DroppedNodeDetails)> {
        if let Some(pub_id) = self.pub_id_map.remove(peer_id) {
            let name = *pub_id.name();
            let _ = self.peer_map.remove(&name);
            self.cleanup_pub_id_map();
            self.routing_table.remove(&name).map(|result| (name, result))
        } else {
            None
        }
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

    fn get_state(&self, pub_id: &PublicId) -> Option<&PeerState> {
        self.peer_map.get(pub_id.name()).map(Peer::state)
    }

    fn get_state_by_peer_id(&self, peer_id: &PeerId) -> Option<&PeerState> {
        self.pub_id_map.get(peer_id).and_then(|pub_id| self.get_state(pub_id))
    }

    #[cfg(not(feature = "use-mock-crust"))]
    fn insert_state(&mut self, pub_id: PublicId, state: PeerState) {
        let _ = self.peer_map.insert(*pub_id.name(), Peer::new(state));
        self.remove_expired();
    }

    fn get_peer_id(&self, pub_id: &PublicId) -> Option<&PeerId> {
        self.pub_id_map
            .iter()
            .find(|&(_, other_pub_id)| other_pub_id == pub_id)
            .map(|(peer_id, _)| peer_id)
    }

    // CONNECTION_TIMEOUT_SECS == 0 if use-mock-crust.
    #[cfg_attr(feature="clippy", allow(absurd_extreme_comparisons))]
    fn remove_expired(&mut self) {
        let remove_ids = self.peer_map
            .iter()
            .filter(|&(_, &Peer(ref timestamp, ref state))| match *state {
                PeerState::ConnectionInfoPreparing(..) |
                PeerState::ConnectionInfoReady(_) |
                PeerState::CrustConnecting |
                PeerState::SearchingForTunnel => {
                    timestamp.elapsed().as_secs() >= CONNECTION_TIMEOUT_SECS
                }
                PeerState::JoiningNode(_) => {
                    timestamp.elapsed().as_secs() >= JOINING_NODE_TIMEOUT_SECS
                }
                PeerState::Client(_) |
                PeerState::Routing(_) |
                PeerState::AwaitingNodeIdentify(_) => false,
            })
            .map(|(pub_id, _)| *pub_id)
            .collect_vec();
        for pub_id in remove_ids {
            let _ = self.peer_map.remove(&pub_id);
        }
        let remove_tokens = self.connection_token_map
            .iter()
            .filter(|&(_, pub_id)| match self.get_state(pub_id) {
                Some(&PeerState::ConnectionInfoPreparing(..)) => false,
                _ => true,
            })
            .map(|(token, _)| *token)
            .collect_vec();
        for token in remove_tokens {
            let _ = self.connection_token_map.remove(&token);
        }
        self.cleanup_pub_id_map();
    }

    fn cleanup_pub_id_map(&mut self) {
        let remove_peer_ids = self.pub_id_map
            .iter()
            .filter(|&(_, pub_id)| !self.peer_map.contains_key(pub_id.name()))
            .map(|(peer_id, _)| *peer_id)
            .collect_vec();
        for peer_id in remove_peer_ids {
            let _ = self.pub_id_map.remove(&peer_id);
        }
    }
}

#[cfg(feature = "use-mock-crust")]
impl PeerManager {
    /// Removes all entries that are not in `Routing` or `Tunnel` state.
    pub fn clear_caches(&mut self) {
        self.remove_expired();
    }

    fn insert_state(&mut self, pub_id: PublicId, state: PeerState) {
        // In mock Crust tests, "expired" entries are removed with `clear_caches`.
        let _ = self.peer_map.insert(*pub_id.name(), Peer::new(state));
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
        match peer_mgr.get_state(&orig_pub_id) {
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
        match peer_mgr.get_state(&orig_pub_id) {
            Some(&PeerState::CrustConnecting) => (),
            state => panic!("Unexpected state: {:?}", state),
        }
    }
}
