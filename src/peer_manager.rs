// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    error::RoutingError,
    id::PublicId,
    time::{Duration, Instant},
    utils::LogIdent,
    xor_name::XorName,
};
use itertools::Itertools;
use log::LogLevel;
use std::collections::btree_map::{BTreeMap, Entry};

/// Time (in seconds) after which a joining node will get dropped from the map of joining nodes.
const JOINING_NODE_TIMEOUT_SECS: u64 = 900;
/// Time (in seconds) after which the connection to a peer is considered failed.
const CONNECTING_PEER_TIMEOUT_SECS: u64 = 150;
/// Time (in seconds) the node waits for a peer to either become valid once connected to it or to
/// transition once bootstrapped to it.
const CONNECTED_PEER_TIMEOUT_SECS: u64 = 120;

#[cfg(feature = "mock_base")]
#[doc(hidden)]
pub mod test_consts {
    pub const CONNECTING_PEER_TIMEOUT_SECS: u64 = super::CONNECTING_PEER_TIMEOUT_SECS;
    pub const CONNECTED_PEER_TIMEOUT_SECS: u64 = super::CONNECTED_PEER_TIMEOUT_SECS;
    pub const JOINING_NODE_TIMEOUT_SECS: u64 = super::JOINING_NODE_TIMEOUT_SECS;
}

/// Our relationship status with a known peer.
#[derive(Debug, Eq, PartialEq)]
pub enum PeerState {
    /// We sent our connection info to them and are waiting for the connection.
    Connecting,
    /// We are connected.
    Connected,
    /// We are the proxy for the joining node
    JoiningNode,
    /// We are connected to the peer who is a full node.
    Node { was_joining: bool },
}

/// Represents peer we are connected or attempting connection to.
#[derive(Debug)]
pub struct Peer {
    state: PeerState,
    timestamp: Instant,
}

impl Peer {
    pub fn new(state: PeerState) -> Self {
        Self {
            state,
            timestamp: Instant::now(),
        }
    }

    pub fn state(&self) -> &PeerState {
        &self.state
    }

    /// Returns whether we are connected to the peer.
    pub fn is_connected(&self) -> bool {
        match self.state {
            PeerState::Connecting => false,
            PeerState::Connected | PeerState::JoiningNode | PeerState::Node { .. } => true,
        }
    }

    /// Returns `true` if the peer is not connected and has timed out. In this case, it can be
    /// safely removed from the peer map.
    fn is_expired(&self) -> bool {
        let timeout = match self.state {
            PeerState::Connecting => CONNECTING_PEER_TIMEOUT_SECS,
            PeerState::JoiningNode => JOINING_NODE_TIMEOUT_SECS,
            PeerState::Connected => CONNECTED_PEER_TIMEOUT_SECS,
            PeerState::Node { .. } => {
                return false;
            }
        };

        self.timestamp.elapsed() >= Duration::from_secs(timeout)
    }

    /// Returns whether the peer is a full node.
    pub fn is_node(&self) -> bool {
        match self.state {
            PeerState::Node { .. } => true,
            _ => false,
        }
    }

    /// Returns whether the peer is or was a joining node and we are their proxy.
    fn is_or_was_joining_node(&self) -> bool {
        match self.state {
            PeerState::JoiningNode => true,
            PeerState::Node { was_joining } => was_joining,
            _ => false,
        }
    }
}

/// A container for information about other nodes in the network.
///
/// This keeps track of which nodes we know of, which ones we have tried to connect to, which IDs
/// we have verified, and whom we are connected to.
#[derive(Default)]
pub struct PeerManager {
    peers: BTreeMap<PublicId, Peer>,
}

impl PeerManager {
    /// Returns a new peer manager with no entries.
    pub fn new() -> PeerManager {
        PeerManager {
            peers: BTreeMap::new(),
        }
    }

    /// Handle a `BootstrapRequest` message.
    pub fn handle_bootstrap_request(&mut self, pub_id: PublicId) {
        self.insert_peer(pub_id, PeerState::JoiningNode);
    }

    /// Mark the given peer as node.
    /// Returns `true` if the peer state changed, `false` if it was already node.
    pub fn set_node(
        &mut self,
        pub_id: &PublicId,
        log_ident: &LogIdent,
    ) -> Result<bool, RoutingError> {
        let peer = if let Some(peer) = self.peers.get_mut(pub_id) {
            peer
        } else {
            log_or_panic!(LogLevel::Error, "{} Peer {} not found.", log_ident, pub_id);
            return Err(RoutingError::UnknownConnection(*pub_id));
        };
        if peer.is_node() {
            Ok(false)
        } else {
            peer.state = PeerState::Node {
                was_joining: peer.is_or_was_joining_node(),
            };
            Ok(true)
        }
    }

    /// Returns an iterator over all connected peers.
    pub fn connected_peers(&self) -> impl Iterator<Item = (&PublicId, &Peer)> {
        self.peers.iter().filter(|(_, peer)| peer.is_connected())
    }

    /// Returns if the given peer is or was a joining node.
    pub fn is_or_was_joining_node(&self, pub_id: &PublicId) -> bool {
        self.peers
            .get(pub_id)
            .map_or(false, Peer::is_or_was_joining_node)
    }

    /// Remove and return `PublicId`s of expired peers.
    pub fn remove_expired_peers(&mut self) -> Vec<PublicId> {
        let expired_peers = self
            .peers
            .iter()
            .filter(|(_, peer)| peer.is_expired())
            .map(|(pub_id, _)| *pub_id)
            .collect_vec();

        for id in &expired_peers {
            let _ = self.remove_peer(id);
        }

        expired_peers
    }

    /// Inserts the peer in the `Connecting` state, unless already exists.
    pub fn set_connecting(&mut self, pub_id: PublicId) {
        let _ = self
            .peers
            .entry(pub_id)
            .or_insert_with(|| Peer::new(PeerState::Connecting));
    }

    /// Marks the given peer as direct-connected.
    pub fn set_connected(&mut self, pub_id: PublicId) {
        self.insert_peer(pub_id, PeerState::Connected);
    }

    /// Returns the given peer.
    pub fn get_peer(&self, pub_id: &PublicId) -> Option<&Peer> {
        self.peers.get(pub_id)
    }

    /// Returns `true` if the peer is connected to us.
    pub fn is_connected(&self, pub_id: &PublicId) -> bool {
        self.get_peer(pub_id).map_or(false, Peer::is_connected)
    }

    /// Returns the `PublicId` of the node with a given name.
    pub fn get_pub_id(&self, name: &XorName) -> Option<&PublicId> {
        self.peers.keys().find(|pub_id| pub_id.name() == name)
    }

    /// Insert a peer with the given state.
    /// If a peer with the same public id already exists, it is overwritten.
    pub fn insert_peer(&mut self, pub_id: PublicId, state: PeerState) {
        let _ = self.peers.insert(pub_id, Peer::new(state));
    }

    /// Removes the given peer. Returns whether the peer was actually present.
    /// If the peer was joining before, it is demoted back to JoiningNode and false is returned.
    pub fn remove_peer(&mut self, pub_id: &PublicId) -> bool {
        match self.peers.entry(*pub_id) {
            Entry::Occupied(mut entry) => {
                if entry.get().is_or_was_joining_node() && entry.get().is_node() {
                    entry.get_mut().state = PeerState::JoiningNode;
                    false
                } else {
                    let _ = entry.remove();
                    true
                }
            }
            Entry::Vacant(_) => false,
        }
    }

    /// Removes the given peer. Returns whether the peer was actually present.
    pub fn remove_peer_no_joining_checks(&mut self, pub_id: &PublicId) -> bool {
        self.peers.remove(pub_id).is_some()
    }
}
