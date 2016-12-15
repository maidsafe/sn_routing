// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.1.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use crust::{PeerId, PrivConnectionInfo, PubConnectionInfo};
use id::PublicId;
use itertools::Itertools;
use maidsafe_utilities::SeededRng;
use rand::{self, Rng};
use routing_table::{Authority, OtherMergeDetails, OwnMergeDetails, OwnMergeState, Prefix,
                    RemovalDetails, RoutingTable};
use routing_table::Error as RoutingTableError;
use rust_sodium::crypto::hash::sha256;
use rust_sodium::crypto::sign;
use std::{error, fmt, mem};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::collections::hash_map::Values;
use std::time::{Duration, Instant};
use xor_name::XorName;

/// Time (in seconds) after which a joining node will get dropped from the map of joining nodes.
const JOINING_NODE_TIMEOUT_SECS: u64 = 300;
/// Time (in seconds) after which the connection to a peer is considered failed.
const CONNECTION_TIMEOUT_SECS: u64 = 90;
/// Time (in seconds) the node waits for a `NodeIdentify` message.
const NODE_IDENTIFY_TIMEOUT_SECS: u64 = 60;
/// Time (in seconds) the node candidate supposed to complete upload the proof.
const RESOURCE_PROOF_EVALUATE_TIMEOUT_SECS: u64 = 40;
/// Time (in seconds) the node candidate supposed to be arrpoved.
const RESOURCE_PROOF_APPROVE_TIMEOUT_SECS: u64 = 60;
/// Time (in seconds) the node waits for connection from an expected node.
const NODE_CONNECT_TIMEOUT_SECS: u64 = 60;

type Group = (Prefix<XorName>, Vec<PublicId>);

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
    ConnectionInfoPreparing(Authority<XorName>, Authority<XorName>, Option<PubConnectionInfo>),
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
    /// We are approved and routing to that peer - via a tunnel if the field is `true`.
    Routing(bool),
    /// Connected and waiting for approval to that peer - via a tunnel if the field is `true`.
    Candidate(bool),
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
    pub src: Authority<XorName>,
    /// The destination authority for sending the connection info.
    pub dst: Authority<XorName>,
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
            PeerState::JoiningNode | PeerState::Proxy => {
                self.timestamp.elapsed() >= Duration::from_secs(JOINING_NODE_TIMEOUT_SECS)
            }
            PeerState::Client |
            PeerState::Routing(_) |
            PeerState::AwaitingNodeIdentify(_) => false,
            PeerState::Candidate(_) => {
                self.timestamp.elapsed() >=
                Duration::from_secs(RESOURCE_PROOF_EVALUATE_TIMEOUT_SECS)
            }
        }
    }
}

/// Holds peers and provides efficient insertion and lookup and removal by peer id and name.
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
    /// Token map for the connections
    connection_token_map: HashMap<u32, PublicId>,
    /// Peer map for the connections
    peer_map: PeerMap,
    // Peers we connected to but don't know about yet
    unknown_peers: HashMap<PeerId, Instant>,
    // Peers we expect to connect to
    expected_peers: HashMap<XorName, Instant>,
    proxy_peer_id: Option<PeerId>,
    /// Routing table
    routing_table: RoutingTable<XorName>,
    /// Our public id
    our_public_id: PublicId,
    /// A joining node wants to join our group
    /// (name, time_inserted, seed_for_resource_proof)
    node_candidate: Option<(XorName, Instant, Vec<u8>)>,
    /// Candidate has been approved
    approved_candidate: Option<XorName>,
    /// A joining node's cache for the group it first joining to
    peer_candidates: Vec<XorName>,
}

impl PeerManager {
    /// Returns a new peer manager with no entries.
    pub fn new(min_group_size: usize, our_public_id: PublicId) -> PeerManager {
        PeerManager {
            connection_token_map: HashMap::new(),
            peer_map: PeerMap::new(),
            unknown_peers: HashMap::new(),
            expected_peers: HashMap::new(),
            proxy_peer_id: None,
            routing_table: RoutingTable::<XorName>::new(*our_public_id.name(), min_group_size),
            our_public_id: our_public_id,
            node_candidate: None,
            approved_candidate: None,
            peer_candidates: vec![],
        }
    }

    /// Clears the routing table and resets this node's public ID.
    pub fn reset_routing_table(&mut self, our_public_id: PublicId, groups: &[Group]) {
        self.unknown_peers.clear();
        self.expected_peers.clear();
        let min_group_size = self.routing_table.min_group_size();
        self.our_public_id = our_public_id;
        self.expected_peers.extend(groups.iter()
            .flat_map(|&(_, ref members)| members)
            .map(|id| (*id.name(), Instant::now())));
        let prefixes = groups.iter().map(|&(ref prefix, _)| *prefix).collect_vec();
        // TODO - nothing can be done to recover from an error here - use `unwrap!` for now, but
        // consider refactoring to return an error which can be used to transition the state
        // machine to `Terminate`.
        let new_rt =
            unwrap!(RoutingTable::new_with_groups(*our_public_id.name(), min_group_size, prefixes));
        let old_rt = mem::replace(&mut self.routing_table, new_rt);
        for name in old_rt.iter() {
            let _ = self.peer_map.remove_by_name(name);
        }

        self.cleanup_proxy_peer_id();
    }

    /// Clears the routing table and resets this node's public ID.
    pub fn restart_routing_table(&mut self, our_public_id: PublicId) {
        let min_group_size = self.routing_table.min_group_size();
        self.our_public_id = our_public_id;

        let new_rt = RoutingTable::new(*our_public_id.name(), min_group_size);
        self.routing_table = new_rt;
    }

    /// Populates the routing table.
    pub fn populate_routing_table(&mut self, groups: &[Group]) {
        let min_group_size = self.routing_table.min_group_size();
        let groups_prefixes = groups.into_iter()
            .map(|&(ref prefix, _)| {
                *prefix
            })
            .collect_vec();
        // TODO - nothing can be done to recover from an error here - use `unwrap!` for now, but
        // consider refactoring to return an error which can be used to transition the state
        // machine to `Terminate`.
        let new_rt = unwrap!(RoutingTable::new_with_groups(*self.our_public_id.name(),
                                                           min_group_size,
                                                           groups_prefixes));
        self.routing_table = new_rt;
    }

    /// Returns the routing table.
    pub fn routing_table(&self) -> &RoutingTable<XorName> {
        &self.routing_table
    }

    /// Notes that a new peer should be expected. This should only be called for peers not already
    /// in our routing table.
    pub fn expect_peer(&mut self, id: &PublicId) {
        let _ = self.expected_peers.insert(*id.name(), Instant::now());
    }

    /// Wraps the routing table function of the same name and maps `XorName`s to `PublicId`s.
    ///
    /// Returns: (true, our_group_list)     if needs to carry out resource proof evaluate
    ///          (false, empty_list)        if doesn't need to carry out resource proof evaluate
    pub fn expect_join_our_group
        (&mut self,
         expected_name: &XorName,
         our_public_id: &PublicId)
         -> Result<(bool, (Prefix<XorName>, Vec<PublicId>)), RoutingTableError> {
        if let Some((name, now, _)) = self.node_candidate {
            if name == *expected_name ||
               now.elapsed() < Duration::from_secs(RESOURCE_PROOF_APPROVE_TIMEOUT_SECS) {
                return Err(RoutingTableError::AlreadyExists);
            }
        }

        let (prefix, names) = self.routing_table.expect_join_our_group(expected_name)?;

        if names.len() > self.routing_table.min_group_size() {
            let mut rng = SeededRng::new();
            let seed = rng.gen_iter().take(10).collect();
            self.node_candidate = Some((*expected_name, Instant::now(), seed));
            self.approved_candidate = None;
        } else {
            return Ok((false, (prefix, vec![])));
        }

        let mut public_ids = vec![];
        for name in names {
            if name == *our_public_id.name() {
                public_ids.push(*our_public_id);
            } else if let Some(peer) = self.peer_map.get_by_name(&name) {
                public_ids.push(*peer.pub_id())
            }
        }
        public_ids.sort();

        Ok((true, (prefix, public_ids)))
    }

    pub fn add_as_peer_candidate(&mut self, name: XorName) {
        self.peer_candidates.push(name)
    }

    pub fn verify_candidate(&mut self,
                            node_name: XorName,
                            proof: Vec<u8>,
                            _leading_zero_bytes: u32,
                            _difficulty: u32)
                            -> Option<bool> {
        if let Some((ref name, ref now, ref seed)) = self.node_candidate {
            if *name == node_name &&
               now.elapsed() < Duration::from_secs(RESOURCE_PROOF_EVALUATE_TIMEOUT_SECS) {
                return Some(*seed == proof);
            }
        }
        None
    }

    /// Handles node_approval vote. `validity` indicates whether rejected or approved
    ///
    /// Returns:
    /// (true, Some(peer_info)) if approved peer is a node candidate
    /// (false, None)           if approved peer is not a node candidate, or cannot find peer_info,
    ///                         or not connected yet
    pub fn handle_node_approval_vote(&mut self,
                                     candidate_name: XorName,
                                     validity: bool)
                                     -> (bool, Option<(PublicId, PeerId)>) {
        if let Some((name, _, _)) = self.node_candidate {
            if name == candidate_name {
                self.node_candidate = None;
                let result = if validity {
                    self.approved_candidate = Some(candidate_name);
                    let (pub_id, peer_id) = if let Some(peer) = self.peer_map
                        .get_by_name(&candidate_name) {
                        if let PeerState::ConnectionInfoPreparing(..) = peer.state {
                            return (false, None);
                        }
                        if let Some(peer_id) = peer.peer_id().clone() {
                            (*peer.pub_id(), *peer_id)
                        } else {
                            return (false, None);
                        }
                    } else {
                        return (false, None);
                    };
                    Some((pub_id, peer_id))
                } else {
                    None
                };
                return (true, result);
            }
        }
        (false, None)
    }

    /// Returns peer_candidates and empty it
    pub fn peer_candidates(&mut self) -> Vec<(PublicId, PeerId)> {
        let mut result = vec![];
        for peer_name in &self.peer_candidates.clone() {
            if let Some(peer) = self.peer_map.get_by_name(peer_name) {
                if let Some(peer_id) = peer.peer_id().clone() {
                    result.push((*peer.pub_id(), *peer_id));
                }
            }
        }
        self.peer_candidates.clear();
        result
    }

    /// Update peer's state to `Candidate` if it is a node candidate
    ///
    /// Returns:
    ///     Ok(None)                   if the peer is not a node candidate or has been approved
    ///     Ok(Some(is_tunnel, seed))  if the peer is a node candidate
    ///     Err(AlreadyExists)         If peer already a routing node
    pub fn is_node_candidate(&mut self,
                             pub_id: &PublicId,
                             peer_id: &PeerId)
                             -> Result<Option<(bool, Vec<u8>)>, RoutingTableError> {
        if self.approved_candidate == Some(*pub_id.name()) {
            self.approved_candidate = None;
            return Ok(None);
        }
        if let Some((ref name, _, ref seed)) = self.node_candidate {
            if name == pub_id.name() {
                let tunnel = match self.peer_map.remove(peer_id).map(|peer| peer.state) {
                    Some(PeerState::SearchingForTunnel) |
                    Some(PeerState::AwaitingNodeIdentify(true)) => true,
                    Some(PeerState::Routing(tunnel)) => {
                        let _ = self.peer_map
                            .insert(Peer::new(*pub_id, Some(*peer_id), PeerState::Routing(tunnel)));
                        return Err(RoutingTableError::AlreadyExists);
                    }
                    _ => false,
                };
                let state = PeerState::Candidate(tunnel);
                let _ = self.peer_map.insert(Peer::new(*pub_id, Some(*peer_id), state));
                return Ok(Some((tunnel, seed.clone())));
            }
        }
        Ok(None)
    }

    /// Update peer's state to `Candidate` if it is a peer candidate
    ///
    /// Returns: true       if the peer is a peer candidate
    ///          false      if the peer is not a peer candidate
    pub fn is_peer_candidate(&mut self, pub_id: &PublicId, peer_id: &PeerId) -> bool {
        if !self.peer_candidates.contains(pub_id.name()) {
            return false;
        }
        let tunnel = match self.peer_map.remove(peer_id).map(|peer| peer.state) {
            Some(PeerState::SearchingForTunnel) |
            Some(PeerState::AwaitingNodeIdentify(true)) => true,
            Some(PeerState::Routing(tunnel)) => {
                error!("PeerCandidate {:?} already in state Routing.", peer_id);
                tunnel
            }
            _ => false,
        };
        let state = PeerState::Candidate(tunnel);
        let _ = self.peer_map.insert(Peer::new(*pub_id, Some(*peer_id), state));
        true
    }

    /// Wraps the routing table function of the same name and maps `XorName`s to `PublicId`s.
    pub fn get_sections_to_join(&self,
                                name: &XorName,
                                our_public_id: &PublicId)
                                -> Result<Vec<Group>, RoutingTableError> {
        self.routing_table.validate_joining_node(name)?;
        let groups = self.routing_table.groups();
        let mut result = vec![];
        for (prefix, names) in groups {
            let mut public_ids = vec![];
            for name in names {
                if name == *our_public_id.name() {
                    public_ids.push(*our_public_id);
                } else if let Some(peer) = self.peer_map.get_by_name(&name) {
                    public_ids.push(*peer.pub_id())
                }
            }
            public_ids.sort();
            result.push((prefix, public_ids));
        }
        result.sort();
        Ok(result)
    }

    /// Tries to add the given peer to the routing table. If successful, this returns `Ok(true)` if
    /// the addition should cause our group to split or `Ok(false)` if the addition shouldn't cause
    /// a split.
    pub fn add_to_routing_table(&mut self,
                                pub_id: &PublicId,
                                peer_id: &PeerId)
                                -> Result<bool, RoutingTableError> {
        let _ = self.unknown_peers.remove(&peer_id);
        let _ = self.expected_peers.remove(pub_id.name());
        let should_split = self.routing_table.add(*pub_id.name())?;
        let tunnel = match self.peer_map.remove(peer_id).map(|peer| peer.state) {
            Some(PeerState::SearchingForTunnel) |
            Some(PeerState::AwaitingNodeIdentify(true)) => true,
            Some(PeerState::Candidate(tunnel)) => tunnel,
            Some(PeerState::Routing(tunnel)) => {
                error!("Peer {:?} added to routing table, but already in state Routing.",
                       peer_id);
                tunnel
            }
            _ => false,
        };
        let state = PeerState::Routing(tunnel);
        let _ = self.peer_map.insert(Peer::new(*pub_id, Some(*peer_id), state));
        Ok(should_split)
    }

    /// Splits the indicated group and returns the `PeerId`s of any peers to which we should not
    /// remain connected.
    pub fn split_group(&mut self,
                       prefix: Prefix<XorName>)
                       -> (Vec<(XorName, PeerId)>, Option<Prefix<XorName>>) {
        let (names_to_drop, our_new_prefix) = self.routing_table.split(prefix);

        let mut ids_to_drop = vec![];
        for name in &names_to_drop {
            if let Some(peer) = self.peer_map.remove_by_name(name) {
                self.cleanup_proxy_peer_id();
                if let Some(peer_id) = peer.peer_id {
                    ids_to_drop.push((*name, peer_id));
                }
            }
        }

        let old_expected_peers = mem::replace(&mut self.expected_peers, HashMap::new());
        self.expected_peers = old_expected_peers.into_iter()
            .filter(|&(ref name, _)| self.routing_table.need_to_add(name) == Ok(()))
            .collect();

        (ids_to_drop, our_new_prefix)
    }

    /// Wraps `RoutingTable::should_merge` with an extra check.
    pub fn should_merge(&self) -> Option<OwnMergeDetails<XorName>> {
        if !self.expected_peers.is_empty() {
            return None;
        }
        self.routing_table.should_merge()
    }

    // Returns the `OwnMergeState` from `RoutingTable` which defines what further action needs to be
    // taken by the node, and the list of peers to which we should now connect (only those within
    // the merging groups for now).
    pub fn merge_own_group(&mut self,
                           sender_prefix: Prefix<XorName>,
                           merge_prefix: Prefix<XorName>,
                           groups: Vec<Group>)
                           -> (OwnMergeState<XorName>, Vec<PublicId>) {
        self.remove_expired();
        let needed = groups.iter()
            .flat_map(|&(_, ref pub_ids)| pub_ids)
            .filter(|pub_id| !self.routing_table.has(pub_id.name()))
            .cloned()
            .collect();

        let groups_as_names = groups.into_iter()
            .map(|(prefix, members)| {
                (prefix, members.into_iter().map(|pub_id| *pub_id.name()).collect::<HashSet<_>>())
            })
            .collect();

        let own_merge_details = OwnMergeDetails {
            sender_prefix: sender_prefix,
            merge_prefix: merge_prefix,
            groups: groups_as_names,
        };
        let mut expected_peers = mem::replace(&mut self.expected_peers, HashMap::new());
        expected_peers.extend(own_merge_details.groups
            .values()
            .flat_map(|group| group.iter())
            .filter_map(|name| if self.routing_table.has(name) {
                None
            } else {
                Some((*name, Instant::now()))
            }));
        self.expected_peers = expected_peers;
        (self.routing_table.merge_own_group(own_merge_details), needed)
    }

    pub fn merge_other_group(&mut self,
                             prefix: Prefix<XorName>,
                             group: BTreeSet<PublicId>)
                             -> HashSet<PublicId> {
        self.remove_expired();

        let merge_details = OtherMergeDetails {
            prefix: prefix,
            group: group.iter().map(|public_id| *public_id.name()).collect(),
        };
        let needed_names = self.routing_table.merge_other_group(merge_details);
        self.expected_peers.extend(needed_names.iter().map(|name| (*name, Instant::now())));
        group.into_iter().filter(|pub_id| needed_names.contains(pub_id.name())).collect()
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
                PeerState::JoiningNode | PeerState::Proxy => peer.is_expired(),
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

    /// Removes all timed out connections to unknown peers (i.e. whose public id we don't have yet)
    /// and also known peers from whom we're awaiting a `NodeIdentify`, and returns their peer IDs.
    ///
    /// Also removes timed out expected peers (those we tried to connect to), but doesn't return
    /// those.
    pub fn remove_expired_connections(&mut self) -> Vec<PeerId> {
        let mut expired_connections = Vec::new();

        for (peer_id, xor_name) in &self.peer_map.names {
            if let Some(peer) = self.peer_map.peers.get(xor_name) {
                if let PeerState::AwaitingNodeIdentify(_) = peer.state {
                    if peer.timestamp.elapsed() >= Duration::from_secs(NODE_IDENTIFY_TIMEOUT_SECS) {
                        expired_connections.push(*peer_id);
                    }
                }
            }
        }

        for peer_id in &expired_connections {
            let _ = self.peer_map.remove(peer_id);
        }

        let mut expired_unknown_peers = Vec::new();

        for (peer_id, timestamp) in &self.unknown_peers {
            if timestamp.elapsed() >= Duration::from_secs(NODE_IDENTIFY_TIMEOUT_SECS) {
                expired_unknown_peers.push(*peer_id);
            }
        }

        for peer_id in expired_unknown_peers {
            expired_connections.push(peer_id);
            let _ = self.unknown_peers.remove(&peer_id);
        }

        let mut expired_expected = Vec::new();
        for (name, timestamp) in &self.expected_peers {
            if timestamp.elapsed() >= Duration::from_secs(NODE_CONNECT_TIMEOUT_SECS) {
                expired_expected.push(*name);
            }
        }
        for name in expired_expected {
            let _ = self.expected_peers.remove(&name);
        }

        expired_connections
    }

    /// Returns the peer ID of the given node if it is our proxy or client or
    /// joining node.
    pub fn get_proxy_or_client_or_joining_node_peer_id(&self, pub_id: &PublicId) -> Option<PeerId> {
        if let Some(peer) = self.peer_map.get_by_name(pub_id.name()) {
            match peer.state {
                PeerState::Client | PeerState::JoiningNode | PeerState::Proxy => peer.peer_id,
                _ => None,
            }
        } else if let Some(join_peer) = self.peer_map
            .get_by_name(&XorName(sha256::hash(&pub_id.signing_public_key().0).0)) {
            // Joining node might have relocated by now but we might have it via its client name
            match join_peer.state {
                PeerState::JoiningNode => join_peer.peer_id,
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
    pub fn connected_to(&mut self, peer_id: &PeerId) {
        if !self.set_state(peer_id, PeerState::AwaitingNodeIdentify(false)) {
            let _ = self.unknown_peers.insert(*peer_id, Instant::now());
        }
    }

    /// Marks the given peer as "connected via tunnel and waiting for `NodeIdentify`".
    /// Returns `false` if a tunnel is not needed.
    pub fn tunnelling_to(&mut self, peer_id: &PeerId) -> bool {
        match self.get_state(peer_id) {
            Some(&PeerState::AwaitingNodeIdentify(false)) |
            Some(&PeerState::Routing(_)) => {
                return false;
            }
            _ => (),
        }
        if !self.set_state(peer_id, PeerState::AwaitingNodeIdentify(true)) {
            let _ = self.unknown_peers.insert(*peer_id, Instant::now());
        }
        true
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

    /// Returns the name of the given peer.
    pub fn get_peer_name(&self, peer_id: &PeerId) -> Option<&XorName> {
        self.peer_map.get(peer_id).map(Peer::name)
    }

    /// Returns the peer with the given peer_id if it is already in one of the
    /// connected states.
    pub fn get_connected_peer(&self, peer_id: &PeerId) -> Option<&Peer> {
        self.peer_map.get(peer_id).and_then(|peer| {
            match peer.state {
                PeerState::Client |
                PeerState::JoiningNode |
                PeerState::Proxy |
                PeerState::Candidate(_) |
                PeerState::Routing(_) => Some(peer),
                _ => None,
            }
        })
    }

    /// Are we expecting a connection from this name?
    pub fn is_expected(&self, name: &XorName) -> bool {
        self.expected_peers.contains_key(name)
    }

    /// Return the PeerId of the node with a given name
    pub fn get_peer_id(&self, name: &XorName) -> Option<&PeerId> {
        self.peer_map.get_by_name(name).and_then(Peer::peer_id)
    }

    /// Return the PeerIds of nodes bearing the names.
    pub fn get_peer_ids(&self, names: &HashSet<XorName>) -> Vec<PeerId> {
        names.iter()
            .filter_map(|name| self.get_peer_id(name))
            .cloned()
            .collect()
    }

    /// Returns the PublicIds of nodes given their names; the result is filtered to the names we
    /// know about (i.e. unknown names are ignored).
    pub fn get_pub_ids(&self, names: &HashSet<XorName>) -> HashSet<PublicId> {
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

        let close_group = self.routing_table.other_close_names(pub_id.name()).unwrap_or_default();
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
        let pub_id = self.connection_token_map.remove(&token).ok_or(Error::PeerNotFound)?;
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
                                    src: Authority<XorName>,
                                    dst: Authority<XorName>,
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
            Some(peer @ Peer { state: PeerState::Candidate(_), .. }) => {
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
                                src: Authority<XorName>,
                                dst: Authority<XorName>,
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
            Some(&PeerState::Candidate(_)) |
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

    /// Returns `Ok(())` if the given peer is not yet in the routing table but is allowed to
    /// connect.
    pub fn allow_connect(&self, name: &XorName) -> Result<(), RoutingTableError> {
        self.routing_table.need_to_add(name)
    }

    /// Removes the given entry, returns the removed peer and if it was a routing node,
    /// the removal details
    pub fn remove_peer(&mut self,
                       peer_id: &PeerId)
                       -> Option<(Peer, Result<RemovalDetails<XorName>, RoutingTableError>)> {
        if let Some(peer) = self.peer_map.remove(peer_id) {
            self.cleanup_proxy_peer_id();
            let removal_details = self.routing_table.remove(peer.name());
            Some((peer, removal_details))
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
            trace!("{:?}: {:?} not found. Cannot set state {:?}.",
                   self.our_public_id.name(),
                   peer_id,
                   state);
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
    use id::FullId;
    use mock_crust::Endpoint;
    use mock_crust::crust::{PeerId, PrivConnectionInfo, PubConnectionInfo};
    use routing_table::Authority;
    use super::*;
    use xor_name::{XOR_NAME_LEN, XorName};

    fn node_auth(byte: u8) -> Authority<XorName> {
        Authority::ManagedNode(XorName([byte; XOR_NAME_LEN]))
    }

    #[test]
    pub fn connection_info_prepare_receive() {
        let min_group_size = 8;
        let orig_pub_id = *FullId::new().public_id();
        let mut peer_mgr = PeerManager::new(min_group_size, orig_pub_id);

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
        let min_group_size = 8;
        let orig_pub_id = *FullId::new().public_id();
        let mut peer_mgr = PeerManager::new(min_group_size, orig_pub_id);
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
