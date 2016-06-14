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
use crust::{PrivConnectionInfo, PeerId, PubConnectionInfo};
#[cfg(feature = "use-mock-crust")]
use mock_crust::crust::{PrivConnectionInfo, PeerId, PubConnectionInfo};
use authority::Authority;
use sodiumoxide::crypto::sign;
use id::PublicId;
use lru_time_cache::LruCache;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use xor_name::XorName;

/// Time (in seconds) after which a joining node will get dropped from the map
/// of joining nodes.
const JOINING_NODE_TIMEOUT_SECS: u64 = 300;

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

/// The state of a peer we are trying to connect to.
#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone, Copy)]
pub enum ConnectState {
    /// We called `crust::Service::connect` and are waiting for a `NewPeer` event.
    Crust,
    /// Crust connection has failed; try to find a tunnel node.
    Tunnel,
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
    /// Our bootstrap connections.
    proxy: Option<(PeerId, PublicId)>,
    /// Any clients we have proxying through us, and whether they have `client_restriction`.
    client_map: HashMap<PeerId, ClientInfo>,
    /// Maps the ID of a peer we are currently trying to connect to to their name.
    connecting_peers: LruCache<PeerId, (XorName, ConnectState)>,
    pub connection_token_map: LruCache<u32, (PublicId, Authority, Authority)>,
    pub our_connection_info_map: LruCache<PublicId, PrivConnectionInfo>,
    pub their_connection_info_map: LruCache<PublicId, PubConnectionInfo>,
}

impl Default for PeerManager {
    fn default() -> PeerManager {
        PeerManager {
            proxy: None,
            client_map: Default::default(),
            connecting_peers: LruCache::with_expiry_duration(Duration::from_secs(90)),
            connection_token_map: LruCache::with_expiry_duration(Duration::from_secs(90)),
            our_connection_info_map: LruCache::with_expiry_duration(Duration::from_secs(90)),
            their_connection_info_map: LruCache::with_expiry_duration(Duration::from_secs(90)),
        }
    }
}

impl PeerManager {
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
            .collect::<Vec<_>>();
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
    pub fn connected_to(&mut self, peer_id: PeerId) {
        if self.connecting_peers.remove(&peer_id).is_none() {
            trace!("Received NewPeer from {:?}, but was not expecting connection.",
                   peer_id);
            // TODO: Having sent connection info should suffice. Otherwise reject the connection.
        }
    }

    /// Returns the name and state of the given peer, if present.
    pub fn get_connecting_peer(&mut self, peer_id: &PeerId) -> Option<&(XorName, ConnectState)> {
        self.connecting_peers.peek(peer_id)
    }

    /// Returns the state of the given peer, if present.
    pub fn connecting_peer_state(&self, name: &XorName) -> Option<ConnectState> {
        self.connecting_peers
            .peek_iter()
            .find(|&(_, &(ref n, _))| n == name)
            .map(|(_, &(_, state))| state)
    }

    /// Adds the given peer and sets the given connection status.
    pub fn insert_connecting_peer(&mut self,
                                  peer_id: PeerId,
                                  name: XorName,
                                  state: ConnectState)
                                  -> Option<(XorName, ConnectState)> {
        self.connecting_peers.insert(peer_id, (name, state))
    }

    /// Removes the given connecting peer.
    pub fn remove_connecting_peer(&mut self, peer_id: &PeerId) -> Option<(XorName, ConnectState)> {
        self.connecting_peers.remove(peer_id)
    }

    /// Returns all peers with the given state.
    pub fn peers_with_state(&mut self, state: ConnectState) -> Vec<(PeerId, XorName)> {
        // TODO: Add a peek_all method to LruCache that doesn't update the timestamps.
        self.connecting_peers
            .peek_iter()
            .filter(|&(_, &(_, s))| s == state)
            .map(|(dst_id, &(name, _))| (*dst_id, name))
            .collect()
    }

    #[cfg(feature = "use-mock-crust")]
    pub fn clear_caches(&mut self) {
        self.connecting_peers.clear();
        self.connection_token_map.clear();
        self.our_connection_info_map.clear();
        self.their_connection_info_map.clear();
    }
}
