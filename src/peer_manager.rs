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
use error::RoutingError;
use id::PublicId;
use itertools::Itertools;
use rand;
use resource_proof::ResourceProof;
use routing_table::{Authority, Prefix};
use rust_sodium::crypto::hash::sha256;
use rust_sodium::crypto::sign;
use signature_accumulator::ACCUMULATION_TIMEOUT_SECS;
use std::{error, fmt, mem};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::collections::hash_map::Values;
use std::time::{Duration, Instant};
use types::MessageId;
use xor_name::XorName;

/// Time (in seconds) after which a joining node will get dropped from the map of joining nodes.
const JOINING_NODE_TIMEOUT_SECS: u64 = 900;
/// Time (in seconds) after which the connection to a peer is considered failed.
const CONNECTION_TIMEOUT_SECS: u64 = 90;
/// Time (in seconds) the node waits for a `NodeIdentify` message.
const NODE_IDENTIFY_TIMEOUT_SECS: u64 = 60;
/// Time (in seconds) between accepting a new candidate (i.e. receiving an `AcceptAsCandidate` from
/// our section) and sending a `CandidateApproval` for this candidate.  If the candidate cannot
/// satisfy the proof of resource challenge within this time, no `CandidateApproval` is sent.
pub const RESOURCE_PROOF_DURATION_SECS: u64 = 300;
/// Time (in seconds) after which a `VotedFor` candidate will be removed.
const CANDIDATE_ACCEPT_TIMEOUT_SECS: u64 = 60;
/// Number of close nodes we try to use to establish a tunnel
const NUM_TUNNEL_VIA_NODES: usize = 10;

pub type SectionMap = BTreeMap<Prefix<XorName>, BTreeSet<PublicId>>;

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

/// The type of a connection with a peer in our routing table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoutingConnection {
    /// We are/were the peer's proxy node.
    JoiningNode(Instant),
    /// The peer is/was our proxy node.
    Proxy(Instant),
    /// The peer is directly connected to us.
    Direct,
    /// The peer is connected via a tunnel.
    Tunnel,
}

/// Our relationship status with a known peer.
#[derive(Debug)]
pub enum PeerState {
    /// Waiting for Crust to prepare our `PrivConnectionInfo`. Contains source and destination for
    /// sending it to the peer, and their connection info with the associated request's message ID,
    /// if we already received it.
    ConnectionInfoPreparing {
        /// Our authority
        us_as_src: Authority<XorName>,
        /// Peer's authority
        them_as_dst: Authority<XorName>,
        /// Peer's connection info if received
        their_info: Option<(PubConnectionInfo, MessageId)>,
    },
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
    /// We are approved and routing to that peer.
    Routing(RoutingConnection),
    /// Connected peer is a joining node and waiting for approval of routing.
    Candidate(RoutingConnection),
    /// We are connected to the peer who is our proxy node.
    Proxy,
}

impl PeerState {
    fn can_tunnel_for(&self) -> bool {
        match *self {
            PeerState::Routing(RoutingConnection::Direct) |
            PeerState::Candidate(RoutingConnection::Direct) => true,
            _ => false,
        }
    }
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
    pub infos: Option<(PrivConnectionInfo, PubConnectionInfo, MessageId)>,
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

    /// Returns `true` if the peer is not connected and has timed out. In this case, it can be
    /// safely removed from the peer map.
    fn is_expired(&self) -> bool {
        match self.state {
            PeerState::ConnectionInfoPreparing { .. } |
            PeerState::ConnectionInfoReady(_) |
            PeerState::CrustConnecting |
            PeerState::SearchingForTunnel => {
                self.timestamp.elapsed() >= Duration::from_secs(CONNECTION_TIMEOUT_SECS)
            }
            PeerState::JoiningNode |
            PeerState::Proxy |
            PeerState::Candidate(_) |
            PeerState::Client |
            PeerState::Routing(_) |
            PeerState::AwaitingNodeIdentify(_) => false,
        }
    }

    /// Returns the `RoutingConnection` type for this peer when it is put in the routing table.
    fn to_routing_connection(&self) -> RoutingConnection {
        match self.state {
            PeerState::SearchingForTunnel |
            PeerState::AwaitingNodeIdentify(true) => RoutingConnection::Tunnel,
            PeerState::Candidate(conn) |
            PeerState::Routing(conn) => conn,
            PeerState::Proxy => RoutingConnection::Proxy(self.timestamp),
            PeerState::JoiningNode => RoutingConnection::JoiningNode(self.timestamp),
            PeerState::AwaitingNodeIdentify(false) |
            PeerState::ConnectionInfoPreparing { .. } |
            PeerState::ConnectionInfoReady(_) |
            PeerState::Client |
            PeerState::CrustConnecting => RoutingConnection::Direct,
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
        let old_peer = peer.peer_id
            .and_then(|peer_id| self.names.insert(peer_id, *peer.name()))
            .and_then(|old_name| self.peers.remove(&old_name));
        self.peers.insert(*peer.name(), peer).or(old_peer)
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

#[derive(Debug)]
enum CandidateState {
    VotedFor,
    AcceptedAsCandidate,
    Approved,
}

#[derive(Debug)]
struct ChallengeResponse {
    target_size: usize,
    difficulty: u8,
    seed: Vec<u8>,
    proof: VecDeque<u8>,
}

/// Holds the information of the joining node.
#[derive(Debug)]
struct Candidate {
    insertion_time: Instant,
    challenge_response: Option<ChallengeResponse>,
    client_auth: Authority<XorName>,
    state: CandidateState,
    passed_our_challenge: bool,
}

impl Candidate {
    fn new(client_auth: Authority<XorName>) -> Candidate {
        Candidate {
            insertion_time: Instant::now(),
            challenge_response: None,
            client_auth: client_auth,
            state: CandidateState::VotedFor,
            passed_our_challenge: false,
        }
    }

    fn is_expired(&self) -> bool {
        let timeout_duration = match self.state {
            CandidateState::VotedFor => Duration::from_secs(CANDIDATE_ACCEPT_TIMEOUT_SECS),
            CandidateState::AcceptedAsCandidate |
            CandidateState::Approved => {
                Duration::from_secs(RESOURCE_PROOF_DURATION_SECS + ACCUMULATION_TIMEOUT_SECS)
            }
        };
        self.insertion_time.elapsed() > timeout_duration
    }

    fn is_approved(&self) -> bool {
        match self.state {
            CandidateState::VotedFor |
            CandidateState::AcceptedAsCandidate => false,
            CandidateState::Approved => true,
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
    /// Peers we connected to but don't know about yet
    unknown_peers: HashMap<PeerId, Instant>,
    proxy_peer_id: Option<PeerId>,
    our_public_id: PublicId,
    /// Joining nodes which want to join our section
    candidates: HashMap<XorName, Candidate>,
}

impl PeerManager {
    /// Returns a new peer manager with no entries.
    pub fn new(our_public_id: PublicId) -> PeerManager {
        PeerManager {
            connection_token_map: HashMap::new(),
            peer_map: PeerMap::new(),
            unknown_peers: HashMap::new(),
            proxy_peer_id: None,
            our_public_id: our_public_id,
            candidates: HashMap::new(),
        }
    }

    /// Adds a potential candidate to the candidate list setting its state to `VotedFor`.  If
    /// another ongoing (i.e. unapproved) candidate exists, or if the candidate is unsuitable for
    /// adding to our section, returns an error.
    pub fn expect_candidate(&mut self,
                            candidate_name: XorName,
                            client_auth: Authority<XorName>)
                            -> Result<(), RoutingError> {
        if let Some((ongoing_name, _)) =
            self.candidates.iter().find(|&(_, candidate)| !candidate.is_approved()) {
            trace!("{:?} Rejected {} as a new candidate: still handling attempt by {}.",
                   self,
                   candidate_name,
                   ongoing_name);
            return Err(RoutingError::AlreadyHandlingJoinRequest);
        }
        let _ = self.candidates.insert(candidate_name, Candidate::new(client_auth));
        Ok(())
    }

    /// Our section has agreed that the candidate should be accepted pending proof of resource.
    /// Replaces any other potential candidate we have previously voted for.  Sets the candidate
    /// state to `AcceptedAsCandidate`.
    pub fn accept_as_candidate(&mut self,
                               candidate_name: XorName,
                               client_auth: Authority<XorName>,
                               our_section: &BTreeSet<XorName>)
                               -> BTreeSet<PublicId> {
        self.remove_unapproved_candidates(&candidate_name);
        self.candidates
            .entry(candidate_name)
            .or_insert_with(|| Candidate::new(client_auth))
            .state = CandidateState::AcceptedAsCandidate;
        self.get_pub_ids(our_section)
    }

    /// Verifies proof of resource.  If the response is not the current candidate, or if it fails
    /// validation, returns `Err`.  Otherwise returns the target size, difficulty and the time
    /// elapsed since the candidate was inserted.
    pub fn verify_candidate(&mut self,
                            candidate_name: &XorName,
                            part_index: usize,
                            part_count: usize,
                            proof_part: Vec<u8>,
                            leading_zero_bytes: u64)
                            -> Result<Option<(usize, u8, Duration)>, RoutingError> {
        let candidate = if let Some(candidate) = self.candidates.get_mut(candidate_name) {
            candidate
        } else {
            return Err(RoutingError::UnknownCandidate);
        };
        let challenge_response = &mut (if let Some(ref mut rp) = candidate.challenge_response {
            rp
        } else {
            return Err(RoutingError::FailedResourceProofValidation);
        });
        challenge_response.proof.extend(proof_part);
        if part_index + 1 != part_count {
            return Ok(None);
        }
        let rp_object = ResourceProof::new(challenge_response.target_size,
                                           challenge_response.difficulty);
        if rp_object.validate_all(&challenge_response.seed,
                                  &challenge_response.proof,
                                  leading_zero_bytes) {
            candidate.passed_our_challenge = true;
            Ok(Some((challenge_response.target_size,
                     challenge_response.difficulty,
                     candidate.insertion_time.elapsed())))
        } else {
            Err(RoutingError::FailedResourceProofValidation)
        }
    }

    /// Returns a tuple containing the verified candidate's `PublicId`, its client `Authority` and
    /// the `PublicId`s of all routing table entries.
    pub fn verified_candidate_info(&self) -> Result<(PublicId, Authority<XorName>), RoutingError> {
        if let Some((name, candidate)) =
            self.candidates
                .iter()
                .find(|&(_, cand)| cand.passed_our_challenge && !cand.is_approved()) {
            return if let Some(peer) = self.peer_map.get_by_name(name) {
                Ok((*peer.pub_id(), candidate.client_auth))
            } else {
                Err(RoutingError::UnknownCandidate)
            };
        }
        if let Some((name, _)) = self.candidates.iter().find(|&(_, cand)| !cand.is_approved()) {
            info!("{:?} Candidate {} has not passed our resource proof challenge in time. Not \
                   sending approval vote to our section.",
                  self,
                  name);
        }
        Err(RoutingError::UnknownCandidate)
    }

    /// Handles accumulated candidate approval.  Marks the candidate as `Approved` and returns the
    /// candidate's `PeerId`; or `Err` if the peer is not the candidate or we are missing its info.
    pub fn handle_candidate_approval(&mut self,
                                     candidate_name: XorName,
                                     client_auth: Authority<XorName>)
                                     -> Result<Option<PeerId>, RoutingError> {
        if let Some(candidate) = self.candidates.get_mut(&candidate_name) {
            candidate.state = CandidateState::Approved;
            if let Some(peer) = self.peer_map.get_by_name(&candidate_name) {
                if let Some(peer_id) = peer.peer_id() {
                    if let PeerState::Candidate(_) = *peer.state() {
                        return Ok(Some(*peer_id));
                    } else {
                        trace!("Node({:?}) Candidate {:?} not yet connected to us.",
                               self.our_public_id.name(),
                               candidate_name);
                        return Ok(None);
                    };
                } else {
                    trace!("Node({:?}) No peer ID with name {:?}",
                           self.our_public_id.name(),
                           candidate_name);
                }
            } else {
                trace!("Node({:?}) No peer with name {:?}",
                       self.our_public_id.name(),
                       candidate_name);
            }
            return Err(RoutingError::InvalidStateForOperation);
        }

        self.remove_unapproved_candidates(&candidate_name);
        let mut candidate = Candidate::new(client_auth);
        candidate.state = CandidateState::Approved;
        let _ = self.candidates.insert(candidate_name, candidate);
        trace!("{:?} No candidate with name {:?}", self, candidate_name);
        // TODO: more specific return error
        Err(RoutingError::InvalidStateForOperation)
    }

    /// Updates peer's state to `Candidate` in the peer map if it is an unapproved candidate and
    /// returns the whether the candidate needs to perform the resource proof.
    ///
    /// Returns:
    ///
    /// * Ok(true)                      if the peer is an unapproved candidate
    /// * Ok(false)                     if the peer has already been approved
    /// * Err(CandidateIsTunnelling)    if the peer is tunnelling
    /// * Err(UnknownCandidate)         if the peer is not in the candidate list
    pub fn handle_candidate_identify(&mut self,
                                     pub_id: &PublicId,
                                     peer_id: &PeerId,
                                     target_size: usize,
                                     difficulty: u8,
                                     seed: Vec<u8>)
                                     -> Result<bool, RoutingError> {
        if let Some(candidate) = self.candidates.get_mut(pub_id.name()) {
            if candidate.is_approved() {
                Ok(false)
            } else {
                let conn = self.peer_map
                    .get(peer_id)
                    .map_or(RoutingConnection::Direct, Peer::to_routing_connection);
                let state = PeerState::Candidate(conn);
                let _ = self.peer_map.insert(Peer::new(*pub_id, Some(*peer_id), state));
                if conn == RoutingConnection::Tunnel {
                    Err(RoutingError::CandidateIsTunnelling)
                } else {
                    candidate.challenge_response = Some(ChallengeResponse {
                        target_size: target_size,
                        difficulty: difficulty,
                        seed: seed,
                        proof: VecDeque::new(),
                    });
                    Ok(true)
                }
            }
        } else {
            Err(RoutingError::UnknownCandidate)
        }
    }

    /// Logs info about ongoing candidate state, if any.
    pub fn show_candidate_status(&self) {
        let mut have_candidate = false;
        let log_prefix = format!("{:?} Candidate Status - ", self);
        for (name, candidate) in self.candidates.iter().filter(|&(_, cand)| !cand.is_expired()) {
            have_candidate = true;
            let mut log_msg = format!("{}{} ", log_prefix, name);
            match candidate.challenge_response {
                Some(ChallengeResponse { ref target_size, ref proof, .. }) => {
                    if candidate.passed_our_challenge {
                        log_msg = format!("{}has passed our challenge ", log_msg);
                    } else if proof.is_empty() {
                        log_msg = format!("{}hasn't responded to our challenge yet ", log_msg);
                    } else {
                        log_msg = format!("{}has sent {}% of resource proof ",
                                          log_msg,
                                          (proof.len() * 100) / target_size);
                    }
                    if candidate.is_approved() {
                        log_msg = format!("{}and is approved by our section.", log_msg);
                    } else {
                        log_msg = format!("{}and is not yet approved by our section.", log_msg);
                    }
                }
                None => {
                    log_msg = format!("{}has not sent CandidateIdentify yet.", log_msg);
                }
            }
            trace!("{}", log_msg);
        }

        if have_candidate {
            return;
        }

        trace!("{}No candidate is currently being handled.", log_prefix);
    }

    /// Set as a full routing node (called at the same time as
    /// `RouteManager::add_to_routing_table()`).
    pub fn set_to_full_node(&mut self, pub_id: &PublicId, peer_id: &PeerId) {
        if let Some(peer) = self.peer_map.get(peer_id) {
            match peer.state {
                PeerState::ConnectionInfoPreparing { .. } |
                PeerState::ConnectionInfoReady(_) |
                PeerState::SearchingForTunnel |
                PeerState::Routing(RoutingConnection::Proxy(_)) |
                PeerState::Routing(RoutingConnection::Direct) |
                PeerState::Routing(RoutingConnection::Tunnel) => {
                    trace!("{:?} Unexpected peer state {:?} while adding {:?} into routing table.",
                           self,
                           peer.state,
                           peer_id)
                }
                PeerState::CrustConnecting if !self.unknown_peers.contains_key(peer_id) => {
                    trace!("{:?} Unexpected peer state {:?} while adding {:?} into routing table.",
                           self,
                           peer.state,
                           peer_id)
                }
                PeerState::CrustConnecting |
                PeerState::AwaitingNodeIdentify(_) |
                PeerState::Client |
                PeerState::JoiningNode |
                // This state is not unexpected; the peer may have been previously added via a
                // section update, and we handle it in `self.routing_table.add()` below by returning
                // an `AlreadyExists` error.
                PeerState::Routing(RoutingConnection::JoiningNode(_)) |
                PeerState::Candidate(_) |
                PeerState::Proxy => (),
            }
        } else {
            trace!("{:?} Add to routing table called for {:?} not found in peer_map",
                   self,
                   peer_id);
        }

        let _ = self.unknown_peers.remove(peer_id);

        let conn = self.peer_map
            .remove(peer_id)
            .map_or(RoutingConnection::Direct,
                    |peer| peer.to_routing_connection());
        let _ = self.peer_map.insert(Peer::new(*pub_id, Some(*peer_id), PeerState::Routing(conn)));
    }

    /// Splits the indicated section and returns the `PeerId`s of any peers to which we should not
    /// remain connected.
    pub fn split_section(&mut self,
                         our_prefix: &Prefix<XorName>,
                         names_to_drop: Vec<XorName>)
                         -> Vec<(XorName, PeerId)> {
        let removal_keys = self.candidates
            .iter()
            .find(|&(name, candidate)| !candidate.is_approved() && !our_prefix.matches(name))
            .map(|(name, _)| *name);

        let ids_to_drop = names_to_drop.iter()
            .chain(removal_keys.iter())
            .filter_map(|name| {
                self.peer_map.remove_by_name(name).and_then(|peer| match peer {
                    Peer {
                        state: PeerState::Routing(RoutingConnection::JoiningNode(timestamp)),
                        ..
                    } |
                    Peer {
                        state: PeerState::Candidate(RoutingConnection::JoiningNode(timestamp)),
                        ..
                    } => {
                        debug!("{:?} still acts as proxy of {:?}, re-insert peer as JoiningNode",
                               self,
                               name);
                        let _ = self.peer_map.insert(Peer {
                            timestamp: timestamp,
                            state: PeerState::JoiningNode,
                            ..peer
                        });
                        None
                    }
                    Peer { state: PeerState::Routing(RoutingConnection::Proxy(timestamp)), .. } => {
                        let _ = self.peer_map.insert(Peer {
                            timestamp: timestamp,
                            state: PeerState::Proxy,
                            ..peer
                        });
                        None
                    }
                    Peer { peer_id: Some(id), .. } => Some((*name, id)),
                    Peer { peer_id: None, .. } => None,
                })
            })
            .collect_vec();

        self.cleanup_proxy_peer_id();

        for name in removal_keys.iter() {
            let _ = self.candidates.remove(name);
            trace!("{:?} Removed unapproved candidate {:?} after split.",
                   self,
                   name);
        }

        ids_to_drop
    }

    /// Returns the list of peers that have been dropped and need to be disconnected.
    pub fn add_prefix(&mut self, names_to_drop: Vec<XorName>) -> Vec<(XorName, PeerId)> {
        names_to_drop.into_iter()
            .filter_map(|name| if let Some(peer) = self.peer_map.remove_by_name(&name) {
                self.cleanup_proxy_peer_id();
                peer.peer_id.map(|peer_id| (name, peer_id))
            } else {
                None
            })
            .collect()
    }

    /// Returns `true` if we are directly connected to both peers.
    pub fn can_tunnel_for(&self, peer_id: &PeerId, dst_id: &PeerId) -> bool {
        let peer_state = self.get_state(peer_id);
        let dst_state = self.get_state(dst_id);
        match (peer_state, dst_state) {
            (Some(peer1), Some(peer2)) => peer1.can_tunnel_for() && peer2.can_tunnel_for(),
            _ => false,
        }
    }

    /// Returns the public ID of the given peer, if it is in `Routing` state.
    pub fn get_routing_peer(&self, peer_id: &PeerId) -> Option<&PublicId> {
        self.peer_map.get(peer_id).and_then(|peer| if let PeerState::Routing(_) = peer.state {
            Some(&peer.pub_id)
        } else {
            None
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
            debug!("{:?} Not accepting further bootstrap connections.", self);
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

    /// Finds all joining nodes that have timed out and returns their peer IDs.
    pub fn remove_expired_joining_nodes(&mut self) -> Vec<PeerId> {
        let expired_ids = self.peer_map
            .peers()
            .filter(|peer| match peer.state {
                PeerState::JoiningNode | PeerState::Proxy => {
                    peer.timestamp.elapsed() >= Duration::from_secs(JOINING_NODE_TIMEOUT_SECS)
                }
                _ => false,
            })
            .filter_map(|peer| peer.peer_id)
            .collect_vec();

        expired_ids
    }

    /// Removes all timed out connections to unknown peers (i.e. whose public id we don't have yet)
    /// and also known peers from whom we're awaiting a `NodeIdentify`, and returns their peer IDs.
    ///
    /// Also removes timed out expected peers (those we tried to connect to), but doesn't return
    /// those.
    pub fn remove_expired_connections(&mut self) -> Vec<PeerId> {
        self.remove_expired();
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
        self.peer_map.get(peer_id).and_then(|peer| if let PeerState::CrustConnecting = peer.state {
            return Some(&peer.pub_id);
        } else {
            None
        })
    }

    /// Returns the name of the given peer.
    pub fn get_peer_name(&self, peer_id: &PeerId) -> Option<&XorName> {
        self.peer_map.get(peer_id).map(Peer::name)
    }

    /// Returns the peer with the given peer_id if it is already in one of the
    /// connected states.
    pub fn get_connected_peer(&self, peer_id: &PeerId) -> Option<&Peer> {
        self.peer_map.get(peer_id).and_then(|peer| match peer.state {
            PeerState::Client |
            PeerState::JoiningNode |
            PeerState::Proxy |
            PeerState::Candidate(_) |
            PeerState::Routing(_) => Some(peer),
            _ => None,
        })
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
    pub fn get_pub_ids(&self, names: &BTreeSet<XorName>) -> BTreeSet<PublicId> {
        names.into_iter()
            .filter_map(|name| if name == self.our_public_id.name() {
                Some(self.our_public_id)
            } else if let Some(peer) = self.peer_map.get_by_name(name) {
                Some(*peer.pub_id())
            } else {
                error!("{:?} Missing public ID for peer {:?}.", self, name);
                None
            })
            .collect()
    }

    /// Returns the `PeerId` of `name`, and whether it is connected via a tunnel or not.
    /// Returns `None` if peer is not found, has no `PeerId`, or non-routing state.
    pub fn get_id_and_tunnel_status(&self, name: &XorName) -> Option<(PeerId, bool)> {
        let peer = match self.peer_map.get_by_name(name) {
            Some(peer) => peer,
            None => {
                error!("{:?} has {} in RT, but has no entry in peer_map for it.",
                       self,
                       name);
                return None;
            }
        };
        let peer_id = match peer.peer_id {
            Some(peer_id) => peer_id,
            None => {
                error!("{:?} has {} in RT, but has no peer ID for it.", self, name);
                return None;
            }
        };
        let is_tunnel = match peer.state {
            PeerState::Routing(RoutingConnection::Tunnel) => true,
            PeerState::Routing(_) => false,
            _ => {
                error!("{:?} has {} in RT, but has state {:?} for it.",
                       self,
                       name,
                       peer.state);
                return None;
            }
        };
        Some((peer_id, is_tunnel))
    }

    pub fn correct_routing_state_to_direct(&mut self, peer_id: &PeerId) {
        let _ = self.set_state(peer_id, PeerState::Routing(RoutingConnection::Direct));
    }

    /// Returns the `NUM_TUNNEL_VIA_NODES` closest peers from our section which can be potential
    /// tunnel node.
    pub fn potential_tunnel_nodes(&self,
                                  our_section: &BTreeSet<XorName>)
                                  -> Vec<(XorName, PeerId)> {
        self.peer_map
            .peers()
            .filter_map(|peer| if our_section.contains(peer.name()) &&
                                  peer.state.can_tunnel_for() {
                peer.peer_id.map_or(None, |peer_id| Some((*peer.name(), peer_id)))
            } else {
                None
            })
            .take(NUM_TUNNEL_VIA_NODES)
            .collect()
    }

    /// Sets the given peer to state `SearchingForTunnel` and returns querying candidates.
    /// Returns empty vector of candidates if it is already in Routing state.
    pub fn set_searching_for_tunnel(&mut self,
                                    our_section: &BTreeSet<XorName>,
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
        self.potential_tunnel_nodes(our_section)
    }

    /// Inserts the given connection info in the map to wait for the peer's info, or returns both
    /// if that's already present and sets the status to `CrustConnecting`. It also returns the
    /// source and destination authorities for sending the serialised connection info to the peer.
    pub fn connection_info_prepared(&mut self,
                                    token: u32,
                                    our_info: PrivConnectionInfo)
                                    -> Result<ConnectionInfoPreparedResult, Error> {
        let pub_id = self.connection_token_map.remove(&token).ok_or(Error::PeerNotFound)?;
        let (us_as_src, them_as_dst, opt_their_info) = match self.peer_map
            .remove_by_name(pub_id.name()) {
            Some(Peer { state: PeerState::ConnectionInfoPreparing { us_as_src,
                                                             them_as_dst,
                                                             their_info },
                        .. }) => (us_as_src, them_as_dst, their_info),
            Some(peer) => {
                let _ = self.peer_map.insert(peer);
                return Err(Error::UnexpectedState);
            }
            None => return Err(Error::PeerNotFound),
        };
        Ok(ConnectionInfoPreparedResult {
            pub_id: pub_id,
            src: us_as_src,
            dst: them_as_dst,
            infos: match opt_their_info {
                Some((their_info, msg_id)) => {
                    let state = PeerState::CrustConnecting;
                    self.insert_peer(pub_id, Some(their_info.id()), state);
                    Some((our_info, their_info, msg_id))
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
                                    peer_info: PubConnectionInfo,
                                    msg_id: MessageId)
                                    -> Result<ConnectionInfoReceivedResult, Error> {
        let peer_id = peer_info.id();

        match self.peer_map.remove_by_name(pub_id.name()) {
            Some(Peer { state: PeerState::ConnectionInfoReady(our_info), .. }) => {
                let state = PeerState::CrustConnecting;
                self.insert_peer(pub_id, Some(peer_id), state);
                Ok(ConnectionInfoReceivedResult::Ready(our_info, peer_info))
            }
            Some(Peer { state: PeerState::ConnectionInfoPreparing { us_as_src,
                                                             them_as_dst,
                                                             their_info: None },
                        .. }) => {
                let state = PeerState::ConnectionInfoPreparing {
                    us_as_src: us_as_src,
                    them_as_dst: them_as_dst,
                    their_info: Some((peer_info, msg_id)),
                };
                self.insert_peer(pub_id, Some(peer_id), state);
                Ok(ConnectionInfoReceivedResult::Waiting)
            }
            Some(peer @ Peer { state: PeerState::ConnectionInfoPreparing { .. }, .. }) |
            Some(peer @ Peer { state: PeerState::CrustConnecting, .. }) |
            Some(peer @ Peer { state: PeerState::AwaitingNodeIdentify(_), .. }) => {
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
            Some(peer @ Peer { state: PeerState::Routing(_), .. }) |
            Some(peer @ Peer { state: PeerState::Candidate(_), .. }) => {
                // TODO: We _should_ retry connecting if the peer is connected via tunnel.
                let _ = self.peer_map.insert(peer);
                Ok(ConnectionInfoReceivedResult::IsConnected)
            }
            Some(peer) => {
                warn!("{:?} Failed to insert connection info from {:?} ({:?}) as peer's current \
                       state is {:?}",
                      self,
                      pub_id.name(),
                      peer_id,
                      peer.state);
                let _ = self.peer_map.insert(peer);
                Err(Error::UnexpectedState)
            }
            None => {
                let state = PeerState::ConnectionInfoPreparing {
                    us_as_src: dst,
                    them_as_dst: src,
                    their_info: Some((peer_info, msg_id)),
                };
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
            Some(&PeerState::ConnectionInfoPreparing { .. }) |
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
                         PeerState::ConnectionInfoPreparing {
                             us_as_src: src,
                             them_as_dst: dst,
                             their_info: None,
                         });
        Some(token)
    }

    /// If preparing connection info failed with the given token, prepares and returns a new token.
    pub fn get_new_connection_info_token(&mut self, token: u32) -> Result<u32, Error> {
        let pub_id = self.connection_token_map.remove(&token).ok_or(Error::PeerNotFound)?;
        let new_token = rand::random();
        let _ = self.connection_token_map.insert(new_token, pub_id);
        Ok(new_token)
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

    /// Removes the given peer and returns it
    pub fn remove_peer_from_map(&mut self, peer_id: &PeerId) -> Option<Peer> {
        if let Some(peer) = self.peer_map.remove(peer_id) {
            self.cleanup_proxy_peer_id();
            Some(peer)
        } else {
            None
        }
    }

    /// Returns the state of the peer with the given name, if present.
    pub fn get_state_by_name(&self, name: &XorName) -> Option<&PeerState> {
        self.peer_map.get_by_name(name).map(Peer::state)
    }

    /// Returns the given peer's state, if present.
    pub fn get_state(&self, peer_id: &PeerId) -> Option<&PeerState> {
        self.peer_map.get(peer_id).map(Peer::state)
    }

    fn set_state(&mut self, peer_id: &PeerId, state: PeerState) -> bool {
        if let Some(peer) = self.peer_map.get_mut(peer_id) {
            peer.state = state;
            return true;
        }
        trace!("{:?}: {:?} not found. Cannot set state {:?}.",
               self,
               peer_id,
               state);
        false
    }

    fn insert_peer(&mut self, pub_id: PublicId, peer_id: Option<PeerId>, state: PeerState) -> bool {
        let result = self.peer_map.insert(Peer::new(pub_id, peer_id, state)).is_some();
        self.remove_expired();
        result
    }

    /// Remove expired connecting peers
    pub fn remove_expired(&mut self) {
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

    /// Removes our proxy if the node is no longer connected.
    pub fn cleanup_proxy_peer_id(&mut self) {
        if let Some(peer_id) = self.proxy_peer_id {
            if self.peer_map.get(&peer_id).is_none() {
                self.proxy_peer_id = None;
            }
        }
    }

    fn remove_unapproved_candidates(&mut self, candidate_name: &XorName) {
        let old_candidates = mem::replace(&mut self.candidates, HashMap::new());
        self.candidates = old_candidates.into_iter()
            .filter(|&(name, ref candidate)| name == *candidate_name || candidate.is_approved())
            .collect();
    }

    /// Removes expired candidates and returns the list of peers from which we should disconnect.
    pub fn remove_expired_candidates(&mut self) -> Vec<PeerId> {
        let candidates = mem::replace(&mut self.candidates, HashMap::new());
        let (to_prune, to_keep) = candidates.into_iter()
            .partition(|&(_, ref candidate)| candidate.is_expired());
        self.candidates = to_keep;
        to_prune.into_iter().filter_map(|(name, _)| self.get_peer_id(&name).cloned()).collect()
    }
}

impl fmt::Debug for PeerManager {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "Node({})", self.our_public_id.name())
    }
}

#[cfg(feature = "use-mock-crust")]
impl PeerManager {
    /// Removes all peers that are not connected, as well as all expected peers and candidates.
    /// Returns `true` if any entry was removed, and `false` if there were no such peers.
    pub fn remove_connecting_peers(&mut self) -> bool {
        // Remove all peers that are not yet connected.
        let remove_names = self.peer_map
            .peers()
            .filter(|peer| match peer.state {
                PeerState::ConnectionInfoPreparing { .. } |
                PeerState::ConnectionInfoReady(_) |
                PeerState::CrustConnecting |
                PeerState::SearchingForTunnel => true,
                _ => false,
            })
            .map(|peer| *peer.name())
            .collect_vec();

        if remove_names.is_empty() && self.candidates.is_empty() {
            return false;
        }

        for name in remove_names {
            let _ = self.peer_map.remove_by_name(&name);
        }

        self.candidates.clear();
        true
    }
}

#[cfg(all(test, feature = "use-mock-crust"))]
mod tests {
    use id::FullId;
    use mock_crust::Endpoint;
    use mock_crust::crust::{PeerId, PrivConnectionInfo, PubConnectionInfo};
    use routing_table::Authority;
    use super::*;
    use types::MessageId;
    use xor_name::{XOR_NAME_LEN, XorName};

    fn node_auth(byte: u8) -> Authority<XorName> {
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
                                                their_connection_info.clone(),
                                                MessageId::new()) {
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
        let original_msg_id = MessageId::new();
        // We received a connection info from the peer and get a token to prepare ours.
        let token = match peer_mgr.connection_info_received(node_auth(0),
                                                            node_auth(1),
                                                            orig_pub_id,
                                                            their_connection_info.clone(),
                                                            original_msg_id) {
            Ok(ConnectionInfoReceivedResult::Prepare(token)) => token,
            result => panic!("Unexpected result: {:?}", result),
        };
        // Crust has finished preparing the connection info.
        match peer_mgr.connection_info_prepared(token, our_connection_info.clone()) {
            Ok(ConnectionInfoPreparedResult { pub_id,
                                              src,
                                              dst,
                                              infos: Some((our_info, their_info, msg_id)) }) => {
                assert_eq!(orig_pub_id, pub_id);
                assert_eq!(node_auth(1), src);
                assert_eq!(node_auth(0), dst);
                assert_eq!(our_connection_info, our_info);
                assert_eq!(their_connection_info, their_info);
                assert_eq!(original_msg_id, msg_id);
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
