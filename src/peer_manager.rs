// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use crust::{PeerId, PrivConnectionInfo, PubConnectionInfo};
use error::RoutingError;
#[cfg(feature="use-mock-crust")]
use fake_clock::FakeClock as Instant;
use id::PublicId;
use itertools::Itertools;
use log::LogLevel;
use messages::MessageContent;
use rand;
use resource_proof::ResourceProof;
use resource_prover::RESOURCE_PROOF_DURATION_SECS;
use routing_table::{Authority, OwnMergeState, Prefix, RemovalDetails, RoutingTable,
                    VersionedPrefix};
use routing_table::Error as RoutingTableError;
use rust_sodium::crypto::hash::sha256;
use rust_sodium::crypto::sign;
use signature_accumulator::ACCUMULATION_TIMEOUT_SECS;
use std::{error, fmt, mem};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::collections::hash_map::Values;
use std::time::Duration;
#[cfg(not(feature="use-mock-crust"))]
use std::time::Instant;
use types::MessageId;
use xor_name::XorName;

/// Time (in seconds) after which a joining node will get dropped from the map of joining nodes.
const JOINING_NODE_TIMEOUT_SECS: u64 = 900;
/// Time (in seconds) after which the connection to a peer is considered failed.
const CONNECTION_TIMEOUT_SECS: u64 = 90;
/// Time (in seconds) the node waits for a `NodeIdentify` message.
const NODE_IDENTIFY_TIMEOUT_SECS: u64 = 60;
/// Time (in seconds) after which a `VotedFor` candidate will be removed.
const CANDIDATE_ACCEPT_TIMEOUT_SECS: u64 = 60;
/// Time (in seconds) the node waits for connection from an expected node.
const NODE_CONNECT_TIMEOUT_SECS: u64 = 60;

pub type SectionMap = BTreeMap<VersionedPrefix<XorName>, BTreeSet<PublicId>>;

#[derive(Default)]
pub struct PeerDetails {
    pub routing_peer_details: Vec<(PeerId, XorName, bool)>,
    pub out_of_sync_peers: Vec<PeerId>,
    pub removal_details: Vec<RemovalDetails<XorName>>,
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
// FIXME - See https://maidsafe.atlassian.net/browse/MAID-2026 for info on removing this exclusion.
#[cfg_attr(feature="cargo-clippy", allow(large_enum_variant))]
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
    pub fn can_tunnel_for(&self) -> bool {
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
#[derive(Debug)]
pub struct Peer {
    pub_id: PublicId,
    peer_id: Option<PeerId>,
    state: PeerState,
    timestamp: Instant,
    valid: bool,
}

impl Peer {
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

    pub fn valid(&self) -> bool {
        self.valid
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
    fn to_routing_connection(&self, is_tunnel: bool) -> RoutingConnection {
        match self.state {
            PeerState::Candidate(conn) |
            PeerState::Routing(conn) => {
                if conn == RoutingConnection::Tunnel && !is_tunnel {
                    RoutingConnection::Direct
                } else {
                    conn
                }
            }
            PeerState::Proxy => RoutingConnection::Proxy(self.timestamp),
            PeerState::JoiningNode => RoutingConnection::JoiningNode(self.timestamp),
            PeerState::ConnectionInfoPreparing { .. } |
            PeerState::ConnectionInfoReady(_) |
            PeerState::CrustConnecting |
            PeerState::SearchingForTunnel |
            PeerState::Client |
            PeerState::AwaitingNodeIdentify(_) => {
                // Since some of these states arent exclusive to connection types,
                // use the is_tunnel argument to know the promoted connection type
                if is_tunnel {
                    RoutingConnection::Tunnel
                } else {
                    RoutingConnection::Direct
                }
            }
        }
    }
}

/// Holds peers and provides efficient insertion and lookup and removal by peer id and name.
#[derive(Debug)]
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

    fn get_by_name_mut(&mut self, name: &XorName) -> Option<&mut Peer> {
        self.peers.get_mut(name)
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
    target_interval: Option<(XorName, XorName)>,
    new_pub_id: Option<PublicId>,
    new_client_auth: Option<Authority<XorName>>,
    state: CandidateState,
    passed_our_challenge: bool,
}

impl Candidate {
    fn new() -> Candidate {
        Candidate {
            insertion_time: Instant::now(),
            challenge_response: None,
            target_interval: None,
            new_pub_id: None,
            new_client_auth: None,
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

    fn has_valid_new_pub_id(&self, debug_prefix: &str) -> bool {
        // FIXME(Fraser) - Create and use new helper in `PublicId::has_valid_name()` too?
        self.new_pub_id
            .map_or(false, |new_pub_id| {
                self.target_interval
                    .map_or_else(|| {
                        debug!("{} has sent CandidateIdentify before we have received an \
                               AcceptAsCandidate, so relocation target interval is still unknown.",
                               debug_prefix);
                        false
                    }, |target_interval| {
                        if new_pub_id
                            .name()
                            .between(&target_interval.0, &target_interval.1) { true } else {
                warn!("{} has used a new ID which is not within the required target range.",
                      debug_prefix);
                false
                            }
                    })
            })
    }

    fn fmt_new_name(&self) -> String {
        self.new_pub_id
            .as_ref()
            .map_or("?".to_string(),
                    |new_pub_id| format!("{}", new_pub_id.name()))
    }
}

/// A container for information about other nodes in the network.
///
/// This keeps track of which nodes we know of, which ones we have tried to connect to, which IDs
/// we have verified, whom we are directly connected to or via a tunnel.
pub struct PeerManager {
    connection_token_map: HashMap<u32, PublicId>,
    peer_map: PeerMap,
    /// Peers we connected to but don't know about yet.
    unknown_peers: HashMap<PeerId, Instant>,
    /// Peers we expect to connect to
    expected_peers: HashMap<XorName, Instant>,
    proxy_peer_id: Option<PeerId>,
    routing_table: RoutingTable<XorName>,
    our_public_id: PublicId,
    /// Relocating nodes which want to join our section, indexed by "old" public ID (i.e. their
    /// pre-relocation IDs). Note that they will be indexed by their "new" IDs in the `peer_map`.
    candidates: HashMap<PublicId, Candidate>,
}

impl PeerManager {
    /// Returns a new peer manager with no entries.
    pub fn new(min_section_size: usize, our_public_id: PublicId) -> PeerManager {
        PeerManager {
            connection_token_map: HashMap::new(),
            peer_map: PeerMap::new(),
            unknown_peers: HashMap::new(),
            expected_peers: HashMap::new(),
            proxy_peer_id: None,
            routing_table: RoutingTable::new(*our_public_id.name(), min_section_size),
            our_public_id: our_public_id,
            candidates: HashMap::new(),
        }
    }

    /// Add prefixes into routing table.
    pub fn add_prefixes(&mut self,
                        prefixes: Vec<VersionedPrefix<XorName>>)
                        -> Result<(), RoutingError> {
        Ok(self.routing_table.add_prefixes(prefixes)?)
    }

    /// Returns the routing table.
    pub fn routing_table(&self) -> &RoutingTable<XorName> {
        &self.routing_table
    }

    /// Returns the unknown peers container.
    pub fn unknown_peers(&self) -> &HashMap<PeerId, Instant> {
        &self.unknown_peers
    }

    /// Notes that a new peer should be expected. This should only be called for peers not already
    /// in our routing table.
    pub fn expect_peer(&mut self, id: &PublicId) {
        let _ = self.expected_peers.insert(*id.name(), Instant::now());
    }

    /// Adds a potential candidate to the candidate list setting its state to `VotedFor`.  If
    /// another ongoing (i.e. unapproved) candidate exists, or if the candidate is unsuitable for
    /// adding to our section, returns an error.
    pub fn expect_candidate(&mut self, old_pub_id: PublicId) -> Result<(), RoutingError> {
        if let Some((ongoing_pub_id, candidate)) =
            self.candidates
                .iter()
                .find(|&(_, cand)| !cand.is_approved()) {
            trace!("{:?} Rejected {} as a new candidate: still handling attempt by {}->{}.",
                   self,
                   old_pub_id.name(),
                   ongoing_pub_id.name(),
                   candidate.fmt_new_name());
            return Err(RoutingError::AlreadyHandlingJoinRequest);
        }
        let _ = self.candidates.insert(old_pub_id, Candidate::new());
        Ok(())
    }

    /// Our section has agreed that the candidate should be accepted pending proof of resource.
    /// Replaces any other potential candidate we have previously voted for.  Sets the candidate
    /// state to `AcceptedAsCandidate`.
    pub fn accept_as_candidate(&mut self,
                               old_pub_id: PublicId,
                               target_interval: (XorName, XorName))
                               -> BTreeSet<PublicId> {
        self.remove_unapproved_candidates(&old_pub_id);
        {
            let candidate = self.candidates
                .entry(old_pub_id)
                .or_insert_with(Candidate::new);
            candidate.target_interval = Some(target_interval);
            candidate.state = CandidateState::AcceptedAsCandidate;
        }
        let our_section = self.routing_table.our_section();
        self.get_pub_ids(our_section)
    }

    /// Returns a tuple of the old `PublicId` and new `PublicId` (in that order) if it exists.
    pub fn get_candidate_from_peer_id(&self, peer_id: &PeerId) -> Option<(PublicId, PublicId)> {
        let new_pub_id = if let Some(peer) = self.get_peer(peer_id) {
            *peer.pub_id()
        } else {
            return None;
        };
        let old_pub_id = if let Some(elt) = self.candidates
               .iter()
               .find(|&(_, cand)| match cand.new_pub_id {
                         Some(pub_id) => pub_id == new_pub_id,
                         None => false,
                     }) {
            *elt.0
        } else {
            return None;
        };
        Some((old_pub_id, new_pub_id))
    }

    /// Verifies proof of resource.  If the response is not the current candidate, or if it fails
    /// validation, returns `Err`.  Otherwise returns the target size, difficulty and the time
    /// elapsed since the candidate was inserted.
    pub fn verify_candidate(&mut self,
                            old_pub_id: &PublicId,
                            part_index: usize,
                            part_count: usize,
                            proof_part: Vec<u8>,
                            leading_zero_bytes: u64)
                            -> Result<Option<(usize, u8, Duration)>, RoutingError> {
        let candidate = if let Some(candidate) = self.candidates.get_mut(old_pub_id) {
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

    /// Returns a (`MessageContent::CandidateApproval`, new name) tuple completed using the verified
    /// candidate's details.
    pub fn verified_candidate_info(&self) -> Result<(MessageContent, XorName), RoutingError> {
        if let Some((old_pub_id, candidate)) =
            self.candidates
                .iter()
                .find(|&(_, cand)| cand.passed_our_challenge && !cand.is_approved()) {
            return if let (Some(new_pub_id), Some(new_client_auth)) =
                (candidate.new_pub_id.as_ref(), candidate.new_client_auth.as_ref()) {
                       self.peer_map
                           .get_by_name(new_pub_id.name())
                           .map_or(Err(RoutingError::UnknownCandidate), |_peer| {
                    Ok((MessageContent::CandidateApproval {
                            old_public_id: *old_pub_id,
                            new_public_id: *new_pub_id,
                            new_client_auth: *new_client_auth,
                            sections: self.ideal_rt(),
                        },
                        *new_pub_id.name()))
                })
                   } else {
                       Err(RoutingError::UnknownCandidate)
                   };
        }
        if let Some((old_pub_id, candidate)) =
            self.candidates
                .iter()
                .find(|&(_, cand)| !cand.is_approved()) {
            info!("{:?} Candidate {}->{} has not passed our resource proof challenge in time. Not \
                   sending approval vote to our section with {:?}",
                  self,
                  old_pub_id.name(),
                  candidate.fmt_new_name(),
                  self.routing_table.our_prefix());
        }
        Err(RoutingError::UnknownCandidate)
    }

    /// Handles accumulated candidate approval.  Marks the candidate as `Approved` and returns the
    /// candidate's `PeerId`; or `Err` if the peer is not the candidate or we are missing its info.
    pub fn handle_candidate_approval(&mut self,
                                     old_pub_id: &PublicId,
                                     new_pub_id: &PublicId,
                                     new_client_auth: &Authority<XorName>)
                                     -> Result<Option<PeerId>, RoutingError> {
        let debug_id = format!("{:?}", self);
        if let Some(candidate) = self.candidates.get_mut(old_pub_id) {
            candidate.new_pub_id = Some(*new_pub_id);
            candidate.new_client_auth = Some(*new_client_auth);
            candidate.state = CandidateState::Approved;
            if let Some(peer) = self.peer_map.get_by_name_mut(new_pub_id.name()) {
                peer.valid = true;
                if let Some(peer_id) = peer.peer_id() {
                    if let PeerState::Candidate(_) = *peer.state() {
                        return Ok(Some(*peer_id));
                    } else {
                        trace!("{} Candidate {}->{} not yet connected to us.",
                               debug_id,
                               old_pub_id.name(),
                               new_pub_id.name());
                        return Ok(None);
                    };
                } else {
                    trace!("{} No peer ID with name {}", debug_id, new_pub_id.name());
                }
            } else {
                trace!("{} No peer with name {}", debug_id, new_pub_id.name());
            }
            return Err(RoutingError::InvalidStateForOperation);
        }

        self.remove_unapproved_candidates(old_pub_id);
        let mut candidate = Candidate::new();
        candidate.state = CandidateState::Approved;
        candidate.new_pub_id = Some(*new_pub_id);
        candidate.new_client_auth = Some(*new_client_auth);
        let _ = self.candidates.insert(*old_pub_id, candidate);
        trace!("{:?} No candidate with name {}", self, old_pub_id.name());
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
    #[cfg_attr(feature = "cargo-clippy", allow(too_many_arguments))]
    pub fn handle_candidate_identify(&mut self,
                                     old_pub_id: &PublicId,
                                     new_pub_id: &PublicId,
                                     new_client_auth: &Authority<XorName>,
                                     peer_id: &PeerId,
                                     target_size: usize,
                                     difficulty: u8,
                                     seed: Vec<u8>,
                                     is_tunnel: bool)
                                     -> Result<bool, RoutingError> {
        let debug_prefix = format!("{:?} Candidate {}->{}",
                                   self,
                                   old_pub_id.name(),
                                   new_pub_id.name());
        let (res, should_insert) = if let Some(candidate) = self.candidates.get_mut(old_pub_id) {
            candidate.new_pub_id = Some(*new_pub_id);
            candidate.new_client_auth = Some(*new_client_auth);
            if candidate.is_approved() {
                (Ok(false), None)
            } else if !candidate.has_valid_new_pub_id(&debug_prefix) {
                (Err(RoutingError::InvalidRelocation), None)
            } else {
                let conn = self.peer_map
                    .get(peer_id)
                    .map_or(RoutingConnection::Direct,
                            |peer| peer.to_routing_connection(is_tunnel));
                let state = PeerState::Candidate(conn);
                if conn == RoutingConnection::Tunnel {
                    (Err(RoutingError::CandidateIsTunnelling), Some(state))
                } else {
                    candidate.challenge_response = Some(ChallengeResponse {
                                                            target_size: target_size,
                                                            difficulty: difficulty,
                                                            seed: seed,
                                                            proof: VecDeque::new(),
                                                        });
                    (Ok(true), Some(state))
                }
            }
        } else {
            (Err(RoutingError::UnknownCandidate), None)
        };

        if let Some(state) = should_insert {
            let _ = self.insert_peer(*new_pub_id, Some(*peer_id), state, false);
        }
        res
    }

    /// Logs info about ongoing candidate state, if any.
    pub fn show_candidate_status(&self) {
        let mut have_candidate = false;
        let log_prefix = format!("{:?} Candidate Status - ", self);
        for (old_pub_id, candidate) in
            self.candidates
                .iter()
                .filter(|&(_, cand)| !cand.is_expired()) {
            have_candidate = true;
            let mut log_msg = format!("{}{}->{} ",
                                      log_prefix,
                                      old_pub_id.name(),
                                      candidate.fmt_new_name());
            match candidate.challenge_response {
                Some(ChallengeResponse {
                         ref target_size,
                         ref proof,
                         ..
                     }) => {
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

    /// Tries to add the given peer to the routing table.
    pub fn add_to_routing_table(&mut self,
                                pub_id: &PublicId,
                                peer_id: &PeerId,
                                is_tunnel: bool)
                                -> Result<(), RoutingTableError> {
        // Check we can find the peer in the map both by name and peer_id, and if so ensure it has
        // its `valid` flag set to true.
        let peer_by_name_is_valid = self.peer_map
            .get_by_name(pub_id.name())
            .map_or(false, |peer_by_name| peer_by_name.valid);
        if self.peer_map
               .get(peer_id)
               .map_or(false,
                       |peer_by_id| peer_by_id.valid && peer_by_name_is_valid) {
        } else {
            log_or_panic!(LogLevel::Error,
                          "{:?} Invalid peer {} added to the RT.",
                          self,
                          pub_id.name());
        }

        let _ = self.unknown_peers.remove(peer_id);
        let _ = self.expected_peers.remove(pub_id.name());
        let res = match self.routing_table.add(*pub_id.name()) {
            res @ Ok(_) |
            res @ Err(RoutingTableError::AlreadyExists) => res,
            Err(e) => return Err(e),
        };

        let conn_type = if is_tunnel {
            RoutingConnection::Tunnel
        } else {
            RoutingConnection::Direct
        };

        let conn = self.peer_map
            .get(peer_id)
            .map_or(conn_type, |peer| peer.to_routing_connection(is_tunnel));
        let _ = self.insert_peer(*pub_id, Some(*peer_id), PeerState::Routing(conn), true);
        trace!("{:?} Set {:?} to {:?}",
               self,
               pub_id.name(),
               PeerState::Routing(conn));
        res
    }

    /// Removes the peer with the given name if present, and returns the name and peer ID that was
    /// stored in the entry. If the peer is also our proxy, or we are theirs, it is reinserted as a
    /// proxy or joining node.
    fn remove_by_name(&mut self, name: XorName) -> Option<(XorName, PeerId)> {
        let peer = match self.peer_map.remove_by_name(&name) {
            Some(peer) => peer,
            None => return None,
        };
        match peer {
            Peer {
                state: PeerState::Routing(RoutingConnection::JoiningNode(timestamp)), ..
            } |
            Peer {
                state: PeerState::Candidate(RoutingConnection::JoiningNode(timestamp)), ..
            } => {
                debug!("{:?} Still acts as proxy of {:?}, re-insert peer as JoiningNode",
                       self,
                       name);
                let _ = self.peer_map
                    .insert(Peer {
                                timestamp: timestamp,
                                state: PeerState::JoiningNode,
                                ..peer
                            });
                None
            }
            Peer { state: PeerState::Routing(RoutingConnection::Proxy(timestamp)), .. } => {
                let _ = self.peer_map
                    .insert(Peer {
                                timestamp: timestamp,
                                state: PeerState::Proxy,
                                ..peer
                            });
                None
            }
            Peer { peer_id: Some(id), .. } => Some((name, id)),
            Peer { peer_id: None, .. } => None,
        }
    }

    /// Splits the indicated section and returns the `PeerId`s of any peers to which we should not
    /// remain connected.
    pub fn split_section(&mut self,
                         ver_pfx: VersionedPrefix<XorName>)
                         -> (Vec<(XorName, PeerId)>, Option<Prefix<XorName>>) {
        let (names_to_drop, our_new_prefix) = self.routing_table.split(ver_pfx);
        for name in &names_to_drop {
            info!("{:?} Dropped {:?} from the routing table.", self, name);
        }

        let removal_keys = self.candidates
            .iter()
            .filter_map(|(old_pub_id, candidate)| if let Some(new_name) =
                candidate.new_pub_id.map(|pub_id| *pub_id.name()) {
                            if !candidate.is_approved() &&
                               !self.routing_table.our_prefix().matches(&new_name) {
                                Some((*old_pub_id, new_name))
                            } else {
                                None
                            }
                        } else {
                            None
                        })
            .collect_vec();

        let ids_to_drop = names_to_drop
            .into_iter()
            .chain(removal_keys
                       .iter()
                       .map(|&(_old_pub_id, new_name)| new_name))
            .filter_map(|name| self.remove_by_name(name))
            .collect_vec();

        self.cleanup_proxy_peer_id();

        for &(old_pub_id, new_name) in &removal_keys {
            let _ = self.candidates.remove(&old_pub_id);
            trace!("{:?} Removed unapproved candidate {}->{} after split.",
                   self,
                   old_pub_id.name(),
                   new_name);
        }

        let old_expected_peers = mem::replace(&mut self.expected_peers, HashMap::new());
        self.expected_peers = old_expected_peers
            .into_iter()
            .filter(|&(ref name, _)| self.routing_table.need_to_add(name) == Ok(()))
            .collect();

        (ids_to_drop, our_new_prefix)
    }

    /// Adds the given prefix to the routing table, splitting or merging as necessary. Returns the
    /// list of peers that have been dropped and need to be disconnected.
    pub fn add_prefix(&mut self, ver_pfx: VersionedPrefix<XorName>) -> Vec<(XorName, PeerId)> {
        let names_to_drop = self.routing_table.add_prefix(ver_pfx);
        let old_expected_peers = mem::replace(&mut self.expected_peers, HashMap::new());
        self.expected_peers = old_expected_peers
            .into_iter()
            .filter(|&(ref name, _)| self.routing_table.need_to_add(name) == Ok(()))
            .collect();
        names_to_drop
            .into_iter()
            .filter_map(|name| if let Some(peer) = self.peer_map.remove_by_name(&name) {
                            self.cleanup_proxy_peer_id();
                            peer.peer_id.map(|peer_id| (name, peer_id))
                        } else {
                            None
                        })
            .collect()
    }

    /// Returns whether we should initiate a merge.
    pub fn should_merge(&self) -> bool {
        self.expected_peers.is_empty() && self.routing_table.should_merge()
    }

    /// Returns the sender prefix and sections to prepare a merge.
    pub fn merge_details(&self) -> (Prefix<XorName>, SectionMap) {
        let sections = self.routing_table
            .all_sections_iter()
            .map(|(prefix, (v, members))| (prefix.with_version(v), self.get_pub_ids(members)))
            .collect();
        (*self.routing_table.our_prefix(), sections)
    }

    /// Returns the `OwnMergeState` from `RoutingTable` which defines what further action needs to
    /// be taken by the node, and the list of peers we should disconnect from as well as those we
    /// should now connect to.
    pub fn merge_own_section(&mut self,
                             sender_prefix: Prefix<XorName>,
                             merge_version: u64,
                             sections: SectionMap)
                             -> (OwnMergeState<XorName>, Vec<(XorName, PeerId)>, Vec<PublicId>) {
        self.remove_expired();
        let needed = sections
            .iter()
            .flat_map(|(_, pub_ids)| pub_ids)
            .filter(|pub_id| !self.routing_table.has(pub_id.name()))
            .cloned()
            .collect();

        let ver_pfxs = sections.keys().cloned();
        let mut expected_peers = mem::replace(&mut self.expected_peers, HashMap::new());
        expected_peers.extend(sections
                                  .iter()
                                  .flat_map(|(_, members)| members)
                                  .filter_map(|pub_id| if self.routing_table
                                                     .has(pub_id.name()) {
                                                  None
                                              } else {
                                                  Some((*pub_id.name(), Instant::now()))
                                              }));
        self.expected_peers = expected_peers;
        let (merge_state, dropped) =
            self.routing_table
                .merge_own_section(sender_prefix.popped().with_version(merge_version), ver_pfxs);
        let ids_to_drop = dropped
            .into_iter()
            .filter_map(|name| self.remove_by_name(name))
            .collect_vec();
        (merge_state, ids_to_drop, needed)
    }

    pub fn merge_other_section(&mut self,
                               ver_pfx: VersionedPrefix<XorName>,
                               section: BTreeSet<PublicId>)
                               -> BTreeSet<PublicId> {
        self.remove_expired();

        let needed_names =
            self.routing_table
                .merge_other_section(ver_pfx, section.iter().map(PublicId::name).cloned());
        self.expected_peers
            .extend(needed_names.iter().map(|name| (*name, Instant::now())));
        section
            .into_iter()
            .filter(|pub_id| needed_names.contains(pub_id.name()))
            .collect()
    }

    /// Returns `true` if we are directly connected to both peers.
    pub fn can_tunnel_for(&self, peer_id: &PeerId, dst_id: &PeerId) -> bool {
        let peer_state = self.get_state(peer_id);
        let dst_state = self.get_state(dst_id);
        let result = match (peer_state, dst_state) {
            (Some(peer1), Some(peer2)) => peer1.can_tunnel_for() && peer2.can_tunnel_for(),
            _ => false,
        };
        if !result {
            trace!("{:?} Can't tunnel from {:?} with state {:?} to {:?} with state {:?}.",
                   self,
                   peer_id,
                   peer_state,
                   dst_id,
                   dst_state);
        }
        result
    }

    /// Returns the public ID of the given peer, if it is in `Routing` state.
    pub fn get_routing_peer(&self, peer_id: &PeerId) -> Option<&PublicId> {
        self.peer_map
            .get(peer_id)
            .and_then(|peer| if let PeerState::Routing(_) = peer.state {
                          Some(&peer.pub_id)
                      } else {
                          None
                      })
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

    /// Returns the proxy node's name if we have a proxy.
    pub fn get_proxy_name(&self) -> Option<&XorName> {
        self.proxy_peer_id
            .and_then(|proxy_peer_id| self.peer_map.get(&proxy_peer_id).map(Peer::name))
    }

    /// Inserts the given peer as a proxy node if applicable, returns `false` if it is not accepted
    /// and should be disconnected.
    pub fn set_proxy(&mut self, peer_id: PeerId, pub_id: PublicId) -> bool {
        if let Some(proxy_peer_id) = self.proxy_peer_id {
            debug!("{:?} Not accepting further bootstrap connections.", self);
            proxy_peer_id == peer_id
        } else {
            let _ = self.insert_peer(pub_id, Some(peer_id), PeerState::Proxy, false);
            self.proxy_peer_id = Some(peer_id);
            true
        }
    }

    /// Inserts the given client into the map. Returns true if we already had
    /// a peer with the given peer id.
    pub fn insert_client(&mut self, peer_id: PeerId, pub_id: PublicId) -> bool {
        self.insert_peer(pub_id, Some(peer_id), PeerState::Client, false)
    }

    /// Returns the given client's public key, if present.
    pub fn get_client(&self, peer_id: &PeerId) -> Option<&sign::PublicKey> {
        self.peer_map
            .get(peer_id)
            .and_then(|peer| match peer.state {
                          PeerState::Client => Some(peer.pub_id.signing_public_key()),
                          _ => None,
                      })
    }

    /// Inserts the given peer with `valid` set to false.
    ///
    /// This is to be used when we receive a `NodeIdentify` from a peer we do not have in the
    /// `peer_map`. We flag the `valid` attribute to false and accept the node as a temporary
    /// connection with the state `AwaitingNodeIdentify`.
    // TODO - Using `AwaitingNodeIdentify` for this extra purpose should be fixed in a future
    //        cleanup. What we need is a state indicating we've received a `NodeIdentify` but
    //        haven't been told by a section that we _should_ be connected to this peer. That
    //        state could be applicable in tandem with some of the other current states though, so
    //        it's not a trivial issue.
    pub fn insert_pending_approval_node(&mut self,
                                        peer_id: PeerId,
                                        pub_id: PublicId,
                                        is_tunnel: bool)
                                        -> bool {
        self.insert_peer(pub_id,
                         Some(peer_id),
                         PeerState::AwaitingNodeIdentify(is_tunnel),
                         false)
    }

    /// Inserts the given joining node into the map. Returns true if we already
    /// had a peer with the given peer id.
    pub fn insert_joining_node(&mut self, peer_id: PeerId, pub_id: PublicId) -> bool {
        self.insert_peer(pub_id, Some(peer_id), PeerState::JoiningNode, false)
    }

    /// Returns the given joining node's public key, if present.
    pub fn get_joining_node(&self, peer_id: &PeerId) -> Option<&sign::PublicKey> {
        self.peer_map
            .get(peer_id)
            .and_then(|peer| match peer.state {
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
                        PeerState::JoiningNode | PeerState::Proxy => {
                            peer.timestamp.elapsed() >=
                            Duration::from_secs(JOINING_NODE_TIMEOUT_SECS)
                        }
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

        for (peer_id, &timestamp) in &self.unknown_peers {
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
    pub fn get_proxy_or_client_or_joining_node(&self,
                                               pub_id: &PublicId)
                                               -> Option<(XorName, PeerId)> {
        match self.peer_map.get_by_name(pub_id.name()) {
            Some(&Peer {
                      state: PeerState::Client,
                      pub_id,
                      peer_id: Some(peer_id),
                      ..
                  }) |
            Some(&Peer {
                      state: PeerState::JoiningNode,
                      pub_id,
                      peer_id: Some(peer_id),
                      ..
                  }) |
            Some(&Peer {
                      state: PeerState::Proxy,
                      pub_id,
                      peer_id: Some(peer_id),
                      ..
                  }) => return Some((*pub_id.name(), peer_id)),
            _ => (),
        }
        match self.peer_map.get_by_name(&XorName(sha256::hash(&pub_id.signing_public_key().0).0)) {
            Some(&Peer { state: PeerState::JoiningNode, pub_id, peer_id: Some(peer_id), ..}) =>
            // Joining node might have relocated by now but we might have it via its client name
            Some((*pub_id.name(), peer_id)),
            _ => None,
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
        // ConnectSuccess may be received after establishing a tunnel to peer (and adding to RT).
        if let Some(peer @ &mut Peer {
                             state: PeerState::Routing(RoutingConnection::Tunnel), ..
                         }) = self.peer_map.get_mut(peer_id) {
            peer.state = PeerState::Routing(RoutingConnection::Direct);
            return;
        }
        if !self.set_state(peer_id, PeerState::AwaitingNodeIdentify(false)) {
            let _ = self.unknown_peers.insert(*peer_id, Instant::now());
        }
    }

    /// Marks the given peer as "connected via tunnel and waiting for `NodeIdentify`".
    /// Returns `false` if a tunnel is not needed.
    pub fn tunnelling_to(&mut self, peer_id: &PeerId) -> bool {
        match self.get_state(peer_id) {
            Some(&PeerState::AwaitingNodeIdentify(_)) |
            Some(&PeerState::Candidate(_)) |
            Some(&PeerState::Routing(_)) => return false,
            _ => (),
        }

        if !self.set_state(peer_id, PeerState::AwaitingNodeIdentify(true)) {
            let _ = self.unknown_peers.insert(*peer_id, Instant::now());
        }
        true
    }

    /// Returns the public ID of the given peer, if it is in `CrustConnecting` state.
    pub fn get_connecting_peer(&self, peer_id: &PeerId) -> Option<&PublicId> {
        self.peer_map
            .get(peer_id)
            .and_then(|peer| if let PeerState::CrustConnecting = peer.state {
                          return Some(&peer.pub_id);
                      } else {
                          None
                      })
    }

    /// Returns the given peer.
    pub fn get_peer(&self, peer_id: &PeerId) -> Option<&Peer> {
        self.peer_map.get(peer_id)
    }

    /// Returns the given peer.
    pub fn get_peer_by_name(&self, name: &XorName) -> Option<&Peer> {
        self.peer_map.get_by_name(name)
    }

    /// Returns the peer with the given peer_id if it is already in one of the
    /// connected states.
    pub fn get_connected_peer(&self, peer_id: &PeerId) -> Option<&Peer> {
        self.peer_map
            .get(peer_id)
            .and_then(|peer| match peer.state {
                          PeerState::Client |
                          PeerState::JoiningNode |
                          PeerState::Proxy |
                          PeerState::Candidate(_) |
                          PeerState::Routing(_) => Some(peer),
                          _ => None,
                      })
    }

    /// Are we expecting a connection from this name?
    pub fn is_expected(&self, name: &XorName) -> bool {
        self.expected_peers.contains_key(name)
    }

    /// Set the `PeerId` of the given node. Returns true if the peer is updated.
    pub fn set_peer_id(&mut self, name: &XorName, peer_id: PeerId) -> bool {
        if let Some(peer) = self.peer_map.remove_by_name(name) {
            self.insert_peer(peer.pub_id, Some(peer_id), peer.state, peer.valid);
            true
        } else {
            false
        }
    }

    /// Set the given peer as valid. Returns true if the peer is updated.
    pub fn set_peer_valid(&mut self, name: &XorName, valid: bool) -> bool {
        if let Some(peer) = self.peer_map.remove_by_name(name) {
            self.insert_peer(peer.pub_id, peer.peer_id, peer.state, valid);
            true
        } else {
            false
        }
    }

    /// Return the PeerId of the node with a given name
    pub fn get_peer_id(&self, name: &XorName) -> Option<&PeerId> {
        self.peer_map.get_by_name(name).and_then(Peer::peer_id)
    }

    /// Return the PeerIds of nodes bearing the names.
    pub fn get_peer_ids(&self, names: &BTreeSet<XorName>) -> Vec<PeerId> {
        names
            .iter()
            .filter_map(|name| self.get_peer_id(name))
            .cloned()
            .collect()
    }

    /// Returns the PublicIds of nodes given their names; the result is filtered to the names we
    /// know about (i.e. unknown names are ignored).
    pub fn get_pub_ids(&self, names: &BTreeSet<XorName>) -> BTreeSet<PublicId> {
        names
            .into_iter()
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

    /// Returns all syncing peer's `PeerId`s, names and whether connected via a tunnel or not;
    /// together with all out-of-sync peer's `PeerId`s.
    /// And purges all dropped routing_nodes (nodes in routing_table but not in the peer_map)
    pub fn get_routing_peer_details(&mut self) -> PeerDetails {
        let mut result = PeerDetails::default();
        let mut dropped_routing_nodes = Vec::new();
        for name in self.routing_table().iter() {
            match self.peer_map.get_by_name(name) {
                None => {
                    log_or_panic!(LogLevel::Error,
                                  "{:?} Have {} in RT, but have no entry in peer_map for it.",
                                  self,
                                  name);
                    dropped_routing_nodes.push(*name);
                }
                Some(&Peer { peer_id: None, .. }) => {
                    log_or_panic!(LogLevel::Error,
                                  "{:?} Have {} in RT, but have no peer ID for it.",
                                  self,
                                  name);
                    dropped_routing_nodes.push(*name);
                }
                Some(&Peer {
                          peer_id: Some(peer_id),
                          ref state,
                          ..
                      }) => {
                    match *state {
                        PeerState::Routing(_) => (),
                        _ => {
                            log_or_panic!(LogLevel::Error,
                                          "{:?} Have {} in RT, but have state {:?} for it.",
                                          self,
                                          name,
                                          state);
                            dropped_routing_nodes.push(*name);
                            result.out_of_sync_peers.push(peer_id);
                        }
                    }
                }
            };
        }
        for name in dropped_routing_nodes {
            let _ = self.peer_map.remove_by_name(&name);
            if let Ok(removal_detail) = self.routing_table.remove(&name) {
                result.removal_details.push(removal_detail);
            }
        }
        let mut nodes_missing_from_rt = Vec::new();
        for peer in self.peer_map.peers() {
            let is_tunnel = match peer.state {
                PeerState::Routing(conn) => {
                    if !self.routing_table.has(peer.name()) {
                        nodes_missing_from_rt.push(*peer.name());
                        continue;
                    } else {
                        conn == RoutingConnection::Tunnel
                    }
                }
                PeerState::Candidate(conn) => conn == RoutingConnection::Tunnel,
                PeerState::AwaitingNodeIdentify(is_tunnel) => is_tunnel,
                _ => continue,
            };
            if let Some(peer_id) = peer.peer_id {
                result
                    .routing_peer_details
                    .push((peer_id, *peer.name(), is_tunnel));
            }
        }
        for name in nodes_missing_from_rt {
            if let Some(peer) = self.peer_map.remove_by_name(&name) {
                log_or_panic!(LogLevel::Error,
                              "{:?} Peer {:?} with state {:?} is missing from RT.",
                              self,
                              peer.name(),
                              peer.state);
                result.out_of_sync_peers.extend(peer.peer_id);
            }
        }
        result
    }

    pub fn correct_state_to_direct(&mut self, peer_id: &PeerId) {
        let state = match self.peer_map.get(peer_id).map(|peer| &peer.state) {
            Some(&PeerState::Routing(_)) => PeerState::Routing(RoutingConnection::Direct),
            Some(&PeerState::Candidate(_)) => PeerState::Candidate(RoutingConnection::Direct),
            Some(&PeerState::AwaitingNodeIdentify(_)) => PeerState::AwaitingNodeIdentify(false),
            state => {
                log_or_panic!(LogLevel::Error,
                              "{:?} Cannot set state {:?} to direct.",
                              self,
                              state);
                return;
            }
        };
        let _ = self.set_state(peer_id, state);
    }

    pub fn correct_state_to_tunnel(&mut self, peer_id: &PeerId) {
        let state = match self.peer_map.get(peer_id).map(|peer| &peer.state) {
            Some(&PeerState::Routing(_)) => PeerState::Routing(RoutingConnection::Tunnel),
            Some(&PeerState::Candidate(_)) => PeerState::Candidate(RoutingConnection::Tunnel),
            Some(&PeerState::AwaitingNodeIdentify(_)) => PeerState::AwaitingNodeIdentify(true),
            state => {
                log_or_panic!(LogLevel::Error,
                              "{:?} Cannot set state {:?} to tunnel.",
                              self,
                              state);
                return;
            }
        };
        let _ = self.set_state(peer_id, state);
    }

    /// Returns direct-connected peers suitable as a tunnel node for `client_name`.
    pub fn potential_tunnel_nodes(&self, client_name: &XorName) -> Vec<(XorName, PeerId)> {
        self.routing_table
            .iter()
            .filter(|tunnel_name| self.is_potential_tunnel_node(tunnel_name, client_name))
            .filter_map(|name| {
                            self.peer_map
                                .get_by_name(name)
                                .and_then(|peer| {
                                              peer.peer_id()
                                                  .and_then(|peer_id| Some((*name, *peer_id)))
                                          })
                        })
            .collect()
    }

    /// Returns `true` if `tunnel_name` is directly connected and in our section or in
    /// `client_name`'s section. If those sections are the same, `tunnel_name` is also allowed to
    /// match our sibling prefix instead.
    pub fn is_potential_tunnel_node(&self, tunnel_name: &XorName, client_name: &XorName) -> bool {
        if self.our_public_id.name() == tunnel_name || self.our_public_id.name() == client_name ||
           !self.get_state_by_name(tunnel_name)
                .map_or(false, PeerState::can_tunnel_for) {
            return false;
        }
        let our_prefix = self.routing_table.our_prefix();
        if our_prefix.matches(client_name) {
            our_prefix.popped().matches(tunnel_name)
        } else {
            self.routing_table
                .find_section_prefix(tunnel_name)
                .map_or(false, |pfx| pfx.matches(client_name) || pfx == *our_prefix)
        }
    }

    /// Sets the given peer to state `SearchingForTunnel` and returns querying candidates.
    /// Returns empty vector of candidates if it is already in Routing state.
    pub fn set_searching_for_tunnel(&mut self,
                                    peer_id: PeerId,
                                    pub_id: PublicId,
                                    valid: bool)
                                    -> Vec<(XorName, PeerId)> {
        match self.get_state_by_name(pub_id.name()) {
            Some(&PeerState::Client) |
            Some(&PeerState::JoiningNode) |
            Some(&PeerState::Proxy) |
            Some(&PeerState::Routing(_)) |
            Some(&PeerState::AwaitingNodeIdentify(_)) => return vec![],
            _ => (),
        }
        let _ = self.insert_peer(pub_id, Some(peer_id), PeerState::SearchingForTunnel, valid);
        self.potential_tunnel_nodes(pub_id.name())
    }

    /// Inserts the given connection info in the map to wait for the peer's info, or returns both
    /// if that's already present and sets the status to `CrustConnecting`. It also returns the
    /// source and destination authorities for sending the serialised connection info to the peer.
    pub fn connection_info_prepared(&mut self,
                                    token: u32,
                                    our_info: PrivConnectionInfo)
                                    -> Result<ConnectionInfoPreparedResult, Error> {
        let pub_id = self.connection_token_map
            .remove(&token)
            .ok_or(Error::PeerNotFound)?;
        let (us_as_src, them_as_dst, opt_their_info, valid) =
            match self.peer_map.remove_by_name(pub_id.name()) {
                Some(Peer {
                         state: PeerState::ConnectionInfoPreparing {
                             us_as_src,
                             them_as_dst,
                             their_info,
                         },
                         valid,
                         ..
                     }) => (us_as_src, them_as_dst, their_info, valid),
                Some(peer) => {
                    let _ = self.peer_map.insert(peer);
                    return Err(Error::UnexpectedState);
                }
                None => return Err(Error::PeerNotFound),
            };

        let infos = match opt_their_info {
            Some((their_info, msg_id)) => {
                let state = PeerState::CrustConnecting;
                self.insert_peer(pub_id, Some(their_info.id()), state, valid);
                Some((our_info, their_info, msg_id))
            }
            None => {
                let state = PeerState::ConnectionInfoReady(our_info);
                self.insert_peer(pub_id, None, state, valid);
                None
            }
        };
        Ok(ConnectionInfoPreparedResult {
               pub_id: pub_id,
               src: us_as_src,
               dst: them_as_dst,
               infos: infos,
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
            Some(Peer {
                     state: PeerState::ConnectionInfoReady(our_info),
                     valid,
                     ..
                 }) => {
                let state = PeerState::CrustConnecting;
                self.insert_peer(pub_id, Some(peer_id), state, valid);
                Ok(ConnectionInfoReceivedResult::Ready(our_info, peer_info))
            }
            Some(Peer {
                     state: PeerState::ConnectionInfoPreparing {
                         us_as_src,
                         them_as_dst,
                         their_info: None,
                     },
                     valid,
                     ..
                 }) => {
                let state = PeerState::ConnectionInfoPreparing {
                    us_as_src: us_as_src,
                    them_as_dst: them_as_dst,
                    their_info: Some((peer_info, msg_id)),
                };
                self.insert_peer(pub_id, Some(peer_id), state, valid);
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
            x => {
                let valid = x.map_or(false,
                                     |peer| if let PeerState::SearchingForTunnel = peer.state {
                                         peer.valid
                                     } else {
                                         false
                                     });
                let state = PeerState::ConnectionInfoPreparing {
                    us_as_src: dst,
                    them_as_dst: src,
                    their_info: Some((peer_info, msg_id)),
                };
                self.insert_peer(pub_id, Some(peer_id), state, valid);
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
                         },
                         true);
        Some(token)
    }

    /// If preparing connection info failed with the given token, prepares and returns a new token.
    pub fn get_new_connection_info_token(&mut self, token: u32) -> Result<u32, Error> {
        let pub_id = self.connection_token_map
            .remove(&token)
            .ok_or(Error::PeerNotFound)?;
        let new_token = rand::random();
        let _ = self.connection_token_map.insert(new_token, pub_id);
        Ok(new_token)
    }

    /// Returns all peers we are looking for a tunnel to.
    pub fn peers_needing_tunnel(&self) -> Vec<(PeerId, XorName)> {
        self.peer_map
            .peers()
            .filter_map(|peer| match peer.state {
                            PeerState::SearchingForTunnel => {
                                peer.peer_id
                                    .and_then(|peer_id| Some((peer_id, *peer.name())))
                            }
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
        // Remove peer if it exists in `unknown_peers` and `candidates` too.
        let _ = self.unknown_peers.remove(peer_id);
        let _ = self.get_candidate_from_peer_id(peer_id)
            .map(|(old_pub_id, _)| self.candidates.remove(&old_pub_id));

        if let Some(peer) = self.peer_map.remove(peer_id) {
            self.cleanup_proxy_peer_id();
            let removal_details = self.routing_table.remove(peer.name());
            Some((peer, removal_details))
        } else {
            None
        }
    }

    /// Returns the state of the peer with the given name, if present.
    pub fn get_state_by_name(&self, name: &XorName) -> Option<&PeerState> {
        self.peer_map.get_by_name(name).map(Peer::state)
    }

    /// Returns the given peer's state, if present.
    fn get_state(&self, peer_id: &PeerId) -> Option<&PeerState> {
        self.peer_map.get(peer_id).map(Peer::state)
    }

    fn set_state(&mut self, peer_id: &PeerId, state: PeerState) -> bool {
        if let Some(peer) = self.peer_map.get_mut(peer_id) {
            peer.state = state;
            return true;
        }
        trace!("{:?} {:?} not found. Cannot set state {:?}.",
               self,
               peer_id,
               state);
        false
    }

    fn insert_peer(&mut self,
                   pub_id: PublicId,
                   peer_id: Option<PeerId>,
                   state: PeerState,
                   valid: bool)
                   -> bool {
        let result = self.peer_map
            .insert(Peer {
                        pub_id: pub_id,
                        peer_id: peer_id,
                        state: state,
                        timestamp: Instant::now(),
                        valid: valid,
                    })
            .is_some();
        self.remove_expired();
        result
    }

    fn remove_expired(&mut self) {
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

    fn cleanup_proxy_peer_id(&mut self) {
        if let Some(peer_id) = self.proxy_peer_id {
            if self.peer_map.get(&peer_id).is_none() {
                self.proxy_peer_id = None;
            }
        }
    }

    fn remove_unapproved_candidates(&mut self, old_pub_id: &PublicId) {
        let old_candidates = mem::replace(&mut self.candidates, HashMap::new());
        self.candidates = old_candidates
            .into_iter()
            .filter(|&(pub_id, ref cand)| pub_id == *old_pub_id || cand.is_approved())
            .collect();
    }

    /// Removes expired candidates and returns the list of peers from which we should disconnect.
    pub fn remove_expired_candidates(&mut self) -> Vec<PeerId> {
        let candidates = mem::replace(&mut self.candidates, HashMap::new());
        let (to_prune, to_keep) = candidates
            .into_iter()
            .partition(|&(_, ref candidate)| candidate.is_expired());
        self.candidates = to_keep;
        to_prune
            .into_iter()
            .filter_map(|(_, cand)| {
                            cand.new_pub_id
                                .and_then(|new_pub_id| {
                                              self.get_peer_id(new_pub_id.name()).cloned()
                                          })
                        })
            .collect()
    }

    /// Returns the public IDs of all routing table entries connected or not that we see as valid
    /// peers, sorted by section.
    pub fn ideal_rt(&self) -> SectionMap {
        let versioned_prefixes = self.routing_table
            .all_sections()
            .into_iter()
            .map(|(prefix, (v, _))| prefix.with_version(v))
            .collect_vec();
        let mut result = SectionMap::new();
        for pub_id in self.peer_map
                .peers()
                .filter(|peer| peer.valid)
                .map(|peer| peer.pub_id())
                .chain(::std::iter::once(&self.our_public_id)) {
            if let Some(versioned_prefix) =
                versioned_prefixes
                    .iter()
                    .find(|versioned_prefix| versioned_prefix.prefix().matches(pub_id.name())) {
                result
                    .entry(*versioned_prefix)
                    .or_insert_with(BTreeSet::new)
                    .insert(*pub_id);
            }
        }
        result
    }
}

impl fmt::Debug for PeerManager {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter,
               "Node({}({:b}))",
               self.routing_table.our_name(),
               self.routing_table.our_prefix())
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

        if remove_names.is_empty() && self.expected_peers.is_empty() && self.candidates.is_empty() {
            return false;
        }

        for name in remove_names {
            let _ = self.peer_map.remove_by_name(&name);
        }

        self.expected_peers.clear();
        self.candidates.clear();
        true
    }
}

#[cfg(all(test, feature = "use-mock-crust"))]
mod tests {
    use super::*;
    use id::FullId;
    use mock_crust::Endpoint;
    use mock_crust::crust::{PeerId, PrivConnectionInfo, PubConnectionInfo};
    use routing_table::Authority;
    use types::MessageId;
    use xor_name::{XOR_NAME_LEN, XorName};

    fn node_auth(byte: u8) -> Authority<XorName> {
        Authority::ManagedNode(XorName([byte; XOR_NAME_LEN]))
    }

    #[test]
    pub fn connection_info_prepare_receive() {
        let min_section_size = 8;
        let orig_pub_id = *FullId::new().public_id();
        let mut peer_mgr = PeerManager::new(min_section_size, orig_pub_id);

        let our_connection_info = PrivConnectionInfo(PeerId(0), Endpoint(0));
        let their_connection_info = PubConnectionInfo(PeerId(1), Endpoint(1));
        // We decide to connect to the peer with `pub_id`:
        let token = unwrap!(peer_mgr.get_connection_token(node_auth(0), node_auth(1), orig_pub_id));
        // Crust has finished preparing the connection info.
        match peer_mgr.connection_info_prepared(token, our_connection_info.clone()) {
            Ok(ConnectionInfoPreparedResult {
                   pub_id,
                   src,
                   dst,
                   infos: None,
               }) => {
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
        let min_section_size = 8;
        let orig_pub_id = *FullId::new().public_id();
        let mut peer_mgr = PeerManager::new(min_section_size, orig_pub_id);
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
            Ok(ConnectionInfoPreparedResult {
                   pub_id,
                   src,
                   dst,
                   infos: Some((our_info, their_info, msg_id)),
               }) => {
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
