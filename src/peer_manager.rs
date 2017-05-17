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

use {PrivConnectionInfo, PubConnectionInfo};
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
use signature_accumulator::ACCUMULATION_TIMEOUT_SECS;
use std::{error, fmt, mem};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::time::Duration;
#[cfg(not(feature="use-mock-crust"))]
use std::time::Instant;
use types::MessageId;
use xor_name::XorName;

/// Time (in seconds) after which a joining node will get dropped from the map of joining nodes.
const JOINING_NODE_TIMEOUT_SECS: u64 = 900;
/// Time (in seconds) after which the connection to a peer is considered failed.
const CONNECTING_PEER_TIMEOUT_SECS: u64 = 90;
/// Time (in seconds) the node waits for a peer to become valid once connected.
const CONNECTED_PEER_TIMEOUT_SECS: u64 = 60;
/// Time (in seconds) after which a `VotedFor` candidate will be removed.
const CANDIDATE_ACCEPT_TIMEOUT_SECS: u64 = 60;

#[cfg(feature = "use-mock-crust")]
#[doc(hidden)]
pub mod test_consts {
    pub const ACCUMULATION_TIMEOUT_SECS: u64 = super::ACCUMULATION_TIMEOUT_SECS;
    pub const ACK_TIMEOUT_SECS: u64 = ::ack_manager::ACK_TIMEOUT_SECS;
    pub const CANDIDATE_ACCEPT_TIMEOUT_SECS: u64 = super::CANDIDATE_ACCEPT_TIMEOUT_SECS;
    pub const RESOURCE_PROOF_DURATION_SECS: u64 = super::RESOURCE_PROOF_DURATION_SECS;
    pub const CONNECTING_PEER_TIMEOUT_SECS: u64 = super::CONNECTING_PEER_TIMEOUT_SECS;
    pub const CONNECTED_PEER_TIMEOUT_SECS: u64 = super::CONNECTED_PEER_TIMEOUT_SECS;
}

pub type SectionMap = BTreeMap<VersionedPrefix<XorName>, BTreeSet<PublicId>>;

#[derive(Default)]
pub struct PeerDetails {
    pub routing_peer_details: Vec<(PublicId, bool)>,
    pub out_of_sync_peers: Vec<PublicId>,
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

impl RoutingConnection {
    /// Returns `true` if this is a tunnel connection.
    fn is_tunnel(&self) -> bool {
        match *self {
            RoutingConnection::Tunnel => true,
            RoutingConnection::Direct |
            RoutingConnection::JoiningNode(_) |
            RoutingConnection::Proxy(_) => false,
        }
    }
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
    /// We are connected - via a tunnel if the field is `true`.
    Connected(bool),
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
// FIXME - See https://maidsafe.atlassian.net/browse/MAID-2026 for info on removing this exclusion.
#[cfg_attr(feature="cargo-clippy", allow(large_enum_variant))]
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
    state: PeerState,
    timestamp: Instant,
    valid: bool,
}

impl Peer {
    pub fn new(pub_id: PublicId, state: PeerState, valid: bool) -> Self {
        Self {
            pub_id: pub_id,
            state: state,
            timestamp: Instant::now(),
            valid: valid,
        }
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

    /// Returns connected status of `Peer`
    /// `None` for not connected. `Some(true)` for tunnels and `Some(false)` for direct connections
    fn is_connected(&self) -> Option<bool> {
        match self.state {
            PeerState::ConnectionInfoPreparing { .. } |
            PeerState::ConnectionInfoReady(_) |
            PeerState::CrustConnecting |
            PeerState::SearchingForTunnel => None,
            PeerState::JoiningNode | PeerState::Proxy | PeerState::Client => Some(false),
            PeerState::Connected(is_tunnel) => Some(is_tunnel),
            PeerState::Candidate(conn) |
            PeerState::Routing(conn) => Some(conn.is_tunnel()),
        }
    }

    /// Returns `true` if the peer is not connected and has timed out. In this case, it can be
    /// safely removed from the peer map.
    fn is_expired(&self) -> bool {
        let timeout = match self.state {
            PeerState::ConnectionInfoPreparing { .. } |
            PeerState::ConnectionInfoReady(_) |
            PeerState::CrustConnecting |
            PeerState::SearchingForTunnel => CONNECTING_PEER_TIMEOUT_SECS,
            PeerState::JoiningNode | PeerState::Proxy => JOINING_NODE_TIMEOUT_SECS,
            PeerState::Connected(_) => CONNECTED_PEER_TIMEOUT_SECS,
            PeerState::Candidate(_) |
            PeerState::Client |
            PeerState::Routing(_) => return false,
        };

        self.timestamp.elapsed() >= Duration::from_secs(timeout)
    }

    /// Returns the `RoutingConnection` type for this peer when it is put in the routing table.
    fn to_routing_connection(&self, is_tunnel: bool) -> Result<RoutingConnection, RoutingError> {
        match self.state {
            PeerState::ConnectionInfoPreparing { .. } |
            PeerState::ConnectionInfoReady(_) |
            PeerState::CrustConnecting |
            PeerState::SearchingForTunnel |
            PeerState::Client => Err(RoutingError::UnknownConnection(*self.pub_id())),
            PeerState::Candidate(conn) |
            PeerState::Routing(conn) => {
                if conn == RoutingConnection::Tunnel && !is_tunnel {
                    Ok(RoutingConnection::Direct)
                } else {
                    Ok(conn)
                }
            }
            PeerState::Proxy => Ok(RoutingConnection::Proxy(self.timestamp)),
            PeerState::JoiningNode => Ok(RoutingConnection::JoiningNode(self.timestamp)),
            PeerState::Connected(_) => {
                // Since some of these states arent exclusive to connection types,
                // use the is_tunnel argument to know the promoted connection type
                if is_tunnel {
                    Ok(RoutingConnection::Tunnel)
                } else {
                    Ok(RoutingConnection::Direct)
                }
            }
        }
    }
}

// FIXME - See https://maidsafe.atlassian.net/browse/MAID-2026 for info on removing this exclusion.
#[cfg_attr(feature="cargo-clippy", allow(large_enum_variant))]
#[derive(Debug, Eq, PartialEq)]
enum Candidate {
    None,
    Expecting {
        timestamp: Instant,
        old_pub_id: PublicId,
    },
    AcceptedForResourceProof {
        res_proof_start: Instant,
        target_interval: (XorName, XorName),
        old_pub_id: PublicId,
    },
    ResourceProof {
        res_proof_start: Instant,
        new_pub_id: PublicId,
        new_client_auth: Authority<XorName>,
        challenge: Option<ResourceProofChallenge>,
        passed_our_challenge: bool,
    },
}

impl Candidate {
    fn is_expired(&self) -> bool {
        match *self {
            Candidate::None => false,
            Candidate::Expecting { ref timestamp, .. } => {
                timestamp.elapsed() > Duration::from_secs(CANDIDATE_ACCEPT_TIMEOUT_SECS)
            }
            Candidate::AcceptedForResourceProof { res_proof_start, .. } |
            Candidate::ResourceProof { res_proof_start, .. } => {
                res_proof_start.elapsed() >
                Duration::from_secs(RESOURCE_PROOF_DURATION_SECS + ACCUMULATION_TIMEOUT_SECS)
            }
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
struct ResourceProofChallenge {
    target_size: usize,
    difficulty: u8,
    seed: Vec<u8>,
    proof: VecDeque<u8>,
}

/// A container for information about other nodes in the network.
///
/// This keeps track of which nodes we know of, which ones we have tried to connect to, which IDs
/// we have verified, whom we are directly connected to or via a tunnel.
pub struct PeerManager {
    connection_token_map: HashMap<u32, PublicId>,
    peers: HashMap<PublicId, Peer>,
    routing_table: RoutingTable<XorName>,
    our_public_id: PublicId,
    /// Joining nodes which want to join our section, indexed by "old" public ID (i.e. their
    /// pre-relocation IDs). Note that they will be indexed by their "new" IDs in the `peers`.
    candidate: Candidate,
}

impl PeerManager {
    /// Returns a new peer manager with no entries.
    pub fn new(min_section_size: usize, our_public_id: PublicId) -> PeerManager {
        PeerManager {
            connection_token_map: HashMap::new(),
            peers: HashMap::new(),
            routing_table: RoutingTable::new(*our_public_id.name(), min_section_size),
            our_public_id: our_public_id,
            candidate: Candidate::None,
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

    /// Adds a potential candidate to the candidate list setting its state to `VotedFor`.  If
    /// another ongoing (i.e. unapproved) candidate exists, or if the candidate is unsuitable for
    /// adding to our section, returns an error.
    pub fn expect_candidate(&mut self, old_pub_id: PublicId) -> Result<(), RoutingError> {
        if self.candidate != Candidate::None {
            return Err(RoutingError::AlreadyHandlingJoinRequest);
        }
        self.candidate = Candidate::Expecting {
            timestamp: Instant::now(),
            old_pub_id: old_pub_id,
        };
        Ok(())
    }

    /// Our section has agreed that the candidate should be accepted pending proof of resource.
    /// Replaces any other potential candidate we have previously voted for.  Sets the candidate
    /// state to `AcceptedForResourceProof`.
    pub fn accept_as_candidate(&mut self,
                               old_pub_id: PublicId,
                               target_interval: (XorName, XorName))
                               -> BTreeSet<PublicId> {
        self.candidate = Candidate::AcceptedForResourceProof {
            res_proof_start: Instant::now(),
            old_pub_id: old_pub_id,
            target_interval: target_interval,
        };

        let our_section = self.routing_table
            .our_section()
            .iter()
            .cloned()
            .collect();
        self.get_peer_ids(&our_section)
    }

    /// Verifies proof of resource.  If the response is not the current candidate, or if it fails
    /// validation, returns `Err`.  Otherwise returns the target size, difficulty and the time
    /// elapsed since the candidate was inserted.
    pub fn verify_candidate(&mut self,
                            new_pub_id: &PublicId,
                            part_index: usize,
                            part_count: usize,
                            proof_part: Vec<u8>,
                            leading_zero_bytes: u64)
                            -> Result<Option<(usize, u8, Duration)>, RoutingError> {
        let (challenge, passed_our_challenge, res_proof_start) = match self.candidate {
            Candidate::ResourceProof {
                new_pub_id: ref pub_id,
                challenge: Some(ref mut challenge),
                ref mut passed_our_challenge,
                ref res_proof_start,
                ..
            } if new_pub_id == pub_id => (challenge, passed_our_challenge, res_proof_start),
            _ => return Err(RoutingError::UnknownCandidate),
        };

        challenge.proof.extend(proof_part);
        if part_index + 1 != part_count {
            return Ok(None);
        }
        let rp_object = ResourceProof::new(challenge.target_size, challenge.difficulty);
        if rp_object.validate_all(&challenge.seed, &challenge.proof, leading_zero_bytes) {
            *passed_our_challenge = true;
            Ok(Some((challenge.target_size, challenge.difficulty, res_proof_start.elapsed())))
        } else {
            Err(RoutingError::FailedResourceProofValidation)
        }
    }

    /// Returns a (`MessageContent::CandidateApproval`, new name) tuple completed using the verified
    /// candidate's details.
    pub fn verified_candidate_info(&self) -> Result<(MessageContent, XorName), RoutingError> {
        let (new_pub_id, new_client_auth) = match self.candidate {
            Candidate::ResourceProof {
                ref new_pub_id,
                ref new_client_auth,
                passed_our_challenge: true,
                ..
            } => (new_pub_id, new_client_auth),
            Candidate::ResourceProof {
                ref new_pub_id,
                passed_our_challenge: false,
                ..
            } => {
                info!("{:?} Candidate {} has not passed our resource proof challenge in time. Not \
                   sending approval vote to our section with {:?}",
                      self,
                      new_pub_id.name(),
                      self.routing_table.our_prefix());
                return Err(RoutingError::UnknownCandidate);
            }
            _ => return Err(RoutingError::UnknownCandidate),
        };

        if self.peers
               .get(new_pub_id)
               .and_then(Peer::is_connected)
               .is_none() {
            log_or_panic!(LogLevel::Error,
                          "{:?} Not connected to {}.",
                          self,
                          new_pub_id.name());
            return Err(RoutingError::UnknownCandidate);
        }

        Ok((MessageContent::CandidateApproval {
                new_public_id: *new_pub_id,
                new_client_auth: *new_client_auth,
                sections: self.ideal_rt(),
            },
            *new_pub_id.name()))
    }

    /// Handles accumulated candidate approval. Marks the candidate as `Approved` and returns if the
    /// candidate is connected or `Err` if the peer is not the candidate or we're missing its info.
    pub fn handle_candidate_approval(&mut self,
                                     new_pub_id: &PublicId)
                                     -> Result<Option<bool>, RoutingError> {
        match mem::replace(&mut self.candidate, Candidate::None) {
            Candidate::ResourceProof { new_pub_id: pub_id, .. } if pub_id == *new_pub_id => (),
            _ => return Err(RoutingError::UnknownCandidate),
        }

        let debug_id = format!("{:?}", self);
        if let Some(peer) = self.peers.get_mut(new_pub_id) {
            peer.valid = true;
            let is_connected = peer.is_connected();
            if is_connected.is_none() {
                trace!("{} Candidate {} not yet connected to us.",
                       debug_id,
                       new_pub_id.name());
            }
            Ok(is_connected)
        } else {
            trace!("{} No peer with name {}", debug_id, new_pub_id.name());
            Err(RoutingError::InvalidStateForOperation)
        }
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
                                     target_size: usize,
                                     difficulty: u8,
                                     seed: Vec<u8>,
                                     is_tunnel: bool)
                                     -> Result<bool, RoutingError> {
        let debug_prefix = format!("{:?} Candidate {}->{}",
                                   self,
                                   old_pub_id.name(),
                                   new_pub_id.name());
        match mem::replace(&mut self.candidate, Candidate::None) {
            Candidate::AcceptedForResourceProof {
                old_pub_id: old_id,
                res_proof_start,
                target_interval,
            } if old_id == *old_pub_id => {
                if *new_pub_id.name() < target_interval.0 ||
                   *new_pub_id.name() > target_interval.1 {
                    warn!("{} has used a new ID which is not within the required target range.",
                          debug_prefix);
                    return Err(RoutingError::InvalidRelocationTargetRange);
                }

                let peer = match self.peers.get_mut(new_pub_id) {
                    Some(peer) => peer,
                    None => {
                        log_or_panic!(LogLevel::Error, "{} is not connected to us.", debug_prefix);
                        return Err(RoutingError::UnknownConnection(*new_pub_id));
                    }
                };

                let conn = peer.to_routing_connection(is_tunnel)?;
                peer.state = PeerState::Candidate(conn);

                let (res, challenge) = if conn == RoutingConnection::Tunnel {
                    (Err(RoutingError::CandidateIsTunnelling), None)
                } else {
                    (Ok(true),
                     Some(ResourceProofChallenge {
                              target_size: target_size,
                              difficulty: difficulty,
                              seed: seed,
                              proof: VecDeque::new(),
                          }))
                };

                self.candidate = Candidate::ResourceProof {
                    res_proof_start: res_proof_start,
                    new_pub_id: *new_pub_id,
                    new_client_auth: *new_client_auth,
                    challenge: challenge,
                    passed_our_challenge: false,
                };

                res
            }
            x => {
                self.candidate = x;
                if self.peers.get(new_pub_id).map_or(false, Peer::valid) {
                    Ok(false)
                } else {
                    Err(RoutingError::UnknownCandidate)
                }
            }
        }
    }

    /// Logs info about ongoing candidate state, if any.
    pub fn show_candidate_status(&self) {
        let mut log_msg = format!("{:?} Candidate Status - ", self);
        match self.candidate {
            Candidate::None => trace!("{}No candidate is currently being handled.", log_msg),
            Candidate::Expecting { .. } => (),
            Candidate::AcceptedForResourceProof { ref old_pub_id, .. } => {
                trace!("{}{} has not sent CandidateIdentify yet.",
                       log_msg,
                       old_pub_id.name())
            }
            Candidate::ResourceProof {
                ref new_pub_id,
                challenge: None,
                ..
            } => trace!("{}{} is tunneling to us.", log_msg, new_pub_id.name()),
            Candidate::ResourceProof {
                ref new_pub_id,
                challenge: Some(ref challenge),
                passed_our_challenge,
                ..
            } => {
                log_msg = format!("{}{}", log_msg, new_pub_id.name());
                if passed_our_challenge {
                    log_msg = format!("{}has passed our challenge ", log_msg);
                } else if challenge.proof.is_empty() {
                    log_msg = format!("{}hasn't responded to our challenge yet ", log_msg);
                } else {
                    log_msg = format!("{}has sent {}% of resource proof ",
                                      log_msg,
                                      (challenge.proof.len() * 100) / challenge.target_size);
                }
                trace!("{}and is not yet approved by our section.", log_msg);
            }
        }
    }

    /// Tries to add the given peer to the routing table.
    pub fn add_to_routing_table(&mut self,
                                pub_id: &PublicId,
                                is_tunnel: bool)
                                -> Result<(), RoutingTableError> {
        if self.peers.get(pub_id).map_or(false, |peer| peer.valid) {
        } else {
            log_or_panic!(LogLevel::Error,
                          "{:?} Invalid peer {} added to the RT.",
                          self,
                          pub_id.name());
        }

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

        let conn = self.peers
            .get(pub_id)
            .map_or(conn_type, |peer| {
                peer.to_routing_connection(is_tunnel)
                    .unwrap_or_else(|_| {
                                        log_or_panic!(LogLevel::Error,
                                                 "{:?} Not connected peer {} being added to RT.",
                                                 self,
                                                 pub_id.name());
                                        conn_type
                                    })
            });
        self.insert_peer(Peer::new(*pub_id, PeerState::Routing(conn), true));
        trace!("{:?} Set {:?} to {:?}",
               self,
               pub_id.name(),
               PeerState::Routing(conn));
        res
    }

    /// Splits the indicated section and returns the `PublicId`s of any peers to which we should not
    /// remain connected.
    pub fn split_section(&mut self,
                         ver_pfx: VersionedPrefix<XorName>)
                         -> (Vec<PublicId>, Option<Prefix<XorName>>) {
        let (names_to_drop, our_new_prefix) = self.routing_table.split(ver_pfx);
        for name in &names_to_drop {
            info!("{:?} Dropped {:?} from the routing table.", self, name);
        }

        let mut ids_to_drop = names_to_drop
            .iter()
            .filter_map(|name| self.get_peer_by_name(name))
            .map(Peer::pub_id)
            .cloned()
            .collect_vec();

        let remove_candidate = match self.candidate {
            Candidate::None |
            Candidate::Expecting { .. } |
            Candidate::AcceptedForResourceProof { .. } => None,
            Candidate::ResourceProof { ref new_pub_id, .. } => {
                if !self.routing_table
                        .our_prefix()
                        .matches(new_pub_id.name()) {
                    Some(*new_pub_id)
                } else {
                    None
                }
            }
        };

        ids_to_drop = ids_to_drop
            .into_iter()
            .chain(remove_candidate.iter().cloned())
            .collect_vec();

        let ids_to_drop = self.remove_split_peers(ids_to_drop);

        (ids_to_drop, our_new_prefix)
    }

    /// Adds the given prefix to the routing table, splitting or merging them as necessary. Returns
    /// the list of peers that have been dropped and need to be disconnected.
    pub fn add_prefix(&mut self, ver_pfx: VersionedPrefix<XorName>) -> Vec<PublicId> {
        let names_to_drop = self.routing_table.add_prefix(ver_pfx);
        let ids_to_drop = names_to_drop
            .iter()
            .filter_map(|name| self.get_peer_by_name(name))
            .map(Peer::pub_id)
            .cloned()
            .collect_vec();

        self.remove_split_peers(ids_to_drop)
    }

    /// Returns whether we should initiate a merge.
    pub fn should_merge(&mut self) -> bool {
        let expected_peers_count = self.peers
            .values()
            .filter(|peer| {
                        peer.valid() &&
                        match peer.state {
                            PeerState::Routing(_) => false,
                            _ => true,
                        }
                    })
            .count();
        expected_peers_count == 0 && self.routing_table.should_merge()
    }

    /// Returns the sender prefix and sections to prepare a merge.
    pub fn merge_details(&self) -> (Prefix<XorName>, SectionMap) {
        let sections = self.routing_table
            .all_sections_iter()
            .map(|(prefix, (v, members))| (prefix.with_version(v), self.get_peer_ids(members)))
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
                             -> (OwnMergeState<XorName>, Vec<PublicId>) {
        let needed = sections
            .iter()
            .flat_map(|(_, pub_ids)| pub_ids)
            .filter(|pub_id| !self.routing_table.has(pub_id.name()))
            .cloned()
            .collect();

        let ver_pfxs = sections.keys().cloned();
        let merge_state =
            self.routing_table
                .merge_own_section(sender_prefix.popped().with_version(merge_version), ver_pfxs);
        (merge_state, needed)
    }

    pub fn merge_other_section(&mut self,
                               ver_pfx: VersionedPrefix<XorName>,
                               section: BTreeSet<PublicId>)
                               -> BTreeSet<PublicId> {
        let needed_names =
            self.routing_table
                .merge_other_section(ver_pfx, section.iter().map(PublicId::name).cloned());
        section
            .iter()
            .filter(|id| needed_names.contains(id.name()))
            .cloned()
            .collect()
    }

    /// Returns `true` if we are directly connected to both peers.
    pub fn can_tunnel_for(&self, peer_id: &PublicId, dst_id: &PublicId) -> bool {
        let peer_state = self.get_peer(peer_id).map(Peer::state);
        let dst_state = self.get_peer(dst_id).map(Peer::state);
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

    /// Returns if the given peer is a routing node.
    pub fn is_routing_peer(&self, peer_id: &PublicId) -> bool {
        self.peers
            .get(peer_id)
            .map_or(false, |peer| if let PeerState::Routing(_) = peer.state {
                true
            } else {
                false
            })
    }

    /// Returns if the given peer is our proxy node.
    pub fn is_proxy(&self, peer_id: &PublicId) -> bool {
        self.peers
            .get(peer_id)
            .map_or(false, |peer| match peer.state {
                PeerState::Proxy |
                PeerState::Candidate(RoutingConnection::Proxy(_)) |
                PeerState::Routing(RoutingConnection::Proxy(_)) => true,
                _ => false,
            })
    }

    /// Returns if the given peer is our client.
    pub fn is_client(&self, peer_id: &PublicId) -> bool {
        self.peers
            .get(peer_id)
            .map_or(false, |peer| if let PeerState::Client = peer.state {
                true
            } else {
                false
            })
    }

    /// Returns if the given peer is our joining node.
    pub fn is_joining_node(&self, peer_id: &PublicId) -> bool {
        self.peers
            .get(peer_id)
            .map_or(false, |peer| match peer.state {
                PeerState::JoiningNode |
                PeerState::Candidate(RoutingConnection::JoiningNode(_)) |
                PeerState::Routing(RoutingConnection::JoiningNode(_)) => true,
                _ => false,
            })
    }

    /// Returns the proxy node's name if we have a proxy.
    pub fn get_proxy_name(&self) -> Option<&XorName> {
        self.peers
            .values()
            .find(|peer| match peer.state {
                      PeerState::Proxy |
                      PeerState::Routing(RoutingConnection::Proxy(_)) => true,
                      _ => false,
                  })
            .map(Peer::name)
    }

    pub fn remove_expired_peers(&mut self) -> Vec<PublicId> {
        let mut expired_peers = self.peers
            .values()
            .filter(|peer| peer.is_expired())
            .map(Peer::pub_id)
            .cloned()
            .collect_vec();

        let remove_candidate = if self.candidate.is_expired() {
            match self.candidate {
                Candidate::None => None,
                Candidate::Expecting { ref old_pub_id, .. } |
                Candidate::AcceptedForResourceProof { ref old_pub_id, .. } => Some(*old_pub_id),
                Candidate::ResourceProof { ref new_pub_id, .. } => Some(*new_pub_id),
            }
        } else {
            None
        };

        expired_peers = expired_peers
            .into_iter()
            .chain(remove_candidate.iter().cloned())
            .collect_vec();

        for id in &expired_peers {
            let _ = self.remove_peer(id);
        }

        expired_peers
    }

    /// Returns the number of clients for which we act as a proxy and which do not intend to become
    /// a node.
    pub fn client_num(&self) -> usize {
        self.peers
            .values()
            .filter(|&peer| match peer.state {
                        PeerState::Client => true,
                        _ => false,
                    })
            .count()
    }

    /// Marks the given peer as direct-connected.
    pub fn connected_to(&mut self, peer_id: &PublicId) {
        let found = if let Some(peer) = self.peers.get_mut(peer_id) {
            match peer.state {
                // ConnectSuccess may be received after establishing a tunnel
                // to peer (and adding to RT).
                PeerState::Routing(RoutingConnection::Tunnel) => {
                    peer.state = PeerState::Routing(RoutingConnection::Direct)
                }
                _ => peer.state = PeerState::Connected(false),
            }
            true
        } else {
            false
        };
        if !found {
            self.insert_peer(Peer::new(*peer_id, PeerState::Connected(false), false));
        }
    }

    /// Marks the given peer as tunnel-connected. Returns `false` if a tunnel is not needed.
    pub fn tunnelling_to(&mut self, peer_id: &PublicId) -> bool {
        match self.get_peer(peer_id).map(Peer::state) {
            Some(&PeerState::Connected(_)) |
            Some(&PeerState::Candidate(_)) |
            Some(&PeerState::Routing(_)) => return false,
            _ => (),
        }

        let found = if let Some(peer) = self.peers.get_mut(peer_id) {
            peer.state = PeerState::Connected(true);
            true
        } else {
            false
        };

        if !found {
            self.insert_peer(Peer::new(*peer_id, PeerState::Connected(true), false));
        }

        true
    }

    /// Returns the given peer.
    pub fn get_peer(&self, peer_id: &PublicId) -> Option<&Peer> {
        self.peers.get(peer_id)
    }

    /// Returns the given peer.
    pub fn get_peer_by_name(&self, name: &XorName) -> Option<&Peer> {
        let id = if let Some(id) = self.peers.keys().find(|id| id.name() == name) {
            id
        } else {
            return None;
        };
        self.get_peer(id)
    }

    /// Set the given peer as valid. Returns true if the peer is updated.
    pub fn set_peer_valid(&mut self, id: &PublicId, valid: bool) {
        let _ = self.peers.get_mut(id).map(|peer| peer.valid = valid);
    }

    /// Return the PublicId of the node with a given name
    pub fn get_peer_id(&self, name: &XorName) -> Option<&PublicId> {
        self.get_peer_by_name(name).map(Peer::pub_id)
    }

    /// Return the PublicIds of nodes bearing the names.
    pub fn get_peer_ids(&self, names: &BTreeSet<XorName>) -> BTreeSet<PublicId> {
        names
            .iter()
            .filter_map(|name| if name == self.our_public_id.name() {
                            Some(&self.our_public_id)
                        } else {
                            self.get_peer_id(name)
                        })
            .cloned()
            .collect()
    }

    /// Returns all syncing peer's `PublicId`s, names and whether connected via a tunnel or not;
    /// together with all out-of-sync peer's `PublicId`s.
    /// And purges all dropped routing_nodes (nodes in routing_table but not in the peer_map)
    pub fn get_routing_peer_details(&mut self) -> PeerDetails {
        let mut result = PeerDetails::default();
        let mut dropped_routing_nodes = Vec::new();
        for name in self.routing_table().iter() {
            match self.get_peer_by_name(name) {
                None => {
                    log_or_panic!(LogLevel::Error,
                                  "{:?} Have {} in RT, but have no entry in peer_map for it.",
                                  self,
                                  name);
                    dropped_routing_nodes.push(*name);
                }
                Some(&Peer { pub_id, ref state, .. }) => {
                    match *state {
                        PeerState::Routing(_) => (),
                        _ => {
                            log_or_panic!(LogLevel::Error,
                                          "{:?} Have {} in RT, but have state {:?} for it.",
                                          self,
                                          name,
                                          state);
                            result.out_of_sync_peers.push(pub_id);
                        }
                    }
                }
            };
        }
        for name in dropped_routing_nodes {
            if let Ok(removal_detail) = self.routing_table.remove(&name) {
                result.removal_details.push(removal_detail);
            }
        }

        let mut nodes_missing_from_rt = Vec::new();
        for peer in self.peers.values() {
            let is_tunnel = match peer.state {
                PeerState::Routing(conn) => {
                    if !self.routing_table.has(peer.name()) {
                        nodes_missing_from_rt.push(peer.pub_id);
                        continue;
                    } else {
                        conn == RoutingConnection::Tunnel
                    }
                }
                PeerState::Candidate(conn) => conn == RoutingConnection::Tunnel,
                PeerState::Connected(is_tunnel) => is_tunnel,
                _ => continue,
            };
            result
                .routing_peer_details
                .push((peer.pub_id, is_tunnel));

        }
        for id in nodes_missing_from_rt {
            if let Some(peer) = self.peers.remove(&id) {
                log_or_panic!(LogLevel::Error,
                              "{:?} Peer {:?} with state {:?} is missing from RT.",
                              self,
                              peer.name(),
                              peer.state);
                result
                    .out_of_sync_peers
                    .extend(::std::iter::once(peer.pub_id()));
            }
        }
        result
    }

    pub fn correct_state_to_direct(&mut self, peer_id: &PublicId) {
        let state = match self.peers.get_mut(peer_id).map(|peer| &peer.state) {
            Some(&PeerState::Routing(_)) => PeerState::Routing(RoutingConnection::Direct),
            Some(&PeerState::Candidate(_)) => PeerState::Candidate(RoutingConnection::Direct),
            Some(&PeerState::Connected(_)) => PeerState::Connected(false),
            state => {
                log_or_panic!(LogLevel::Error,
                              "{:?} Cannot set state {:?} to direct.",
                              peer_id.name(),
                              state);
                return;
            }
        };

        if let Some(peer) = self.peers.get_mut(peer_id) {
            peer.state = state;
        }
    }

    pub fn correct_state_to_tunnel(&mut self, peer_id: &PublicId) {
        let state = match self.peers.get(peer_id).map(|peer| &peer.state) {
            Some(&PeerState::Routing(_)) => PeerState::Routing(RoutingConnection::Tunnel),
            Some(&PeerState::Candidate(_)) => PeerState::Candidate(RoutingConnection::Tunnel),
            Some(&PeerState::Connected(_)) => PeerState::Connected(true),
            state => {
                log_or_panic!(LogLevel::Error,
                              "{:?} Cannot set state {:?} to tunnel.",
                              self,
                              state);
                return;
            }
        };
        if let Some(peer) = self.peers.get_mut(peer_id) {
            peer.state = state;
        }
    }

    /// Returns `true` if `tunnel_name` is directly connected and in our section or in
    /// `client_name`'s section. If those sections are the same, `tunnel_name` is also allowed to
    /// match our sibling prefix instead.
    pub fn is_potential_tunnel_node(&self, tunnel_name: &XorName, client_name: &XorName) -> bool {
        if self.our_public_id.name() == tunnel_name || self.our_public_id.name() == client_name ||
           !self.get_peer_by_name(tunnel_name)
                .map(Peer::state)
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
    pub fn set_searching_for_tunnel(&mut self, pub_id: PublicId, valid: bool) -> Vec<PublicId> {
        match self.get_peer(&pub_id).map(Peer::state) {
            Some(&PeerState::Client) |
            Some(&PeerState::JoiningNode) |
            Some(&PeerState::Proxy) |
            Some(&PeerState::Routing(_)) |
            Some(&PeerState::Connected(_)) => return vec![],
            _ => (),
        }
        self.insert_peer(Peer::new(pub_id, PeerState::SearchingForTunnel, valid));

        self.routing_table
            .iter()
            .filter(|tunnel_name| self.is_potential_tunnel_node(tunnel_name, pub_id.name()))
            .filter_map(|name| self.get_peer_by_name(name))
            .map(Peer::pub_id)
            .cloned()
            .collect()
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
        let (us_as_src, them_as_dst, opt_their_info, valid) = match self.peers.remove(&pub_id) {
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
                self.insert_peer(peer);
                return Err(Error::UnexpectedState);
            }
            None => return Err(Error::PeerNotFound),
        };

        let infos = match opt_their_info {
            Some((their_info, msg_id)) => {
                let state = PeerState::CrustConnecting;
                self.insert_peer(Peer::new(pub_id, state, valid));
                Some((our_info, their_info, msg_id))
            }
            None => {
                let state = PeerState::ConnectionInfoReady(our_info);
                self.insert_peer(Peer::new(pub_id, state, valid));
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
                                    peer_info: PubConnectionInfo,
                                    msg_id: MessageId)
                                    -> Result<ConnectionInfoReceivedResult, Error> {
        let peer_id = peer_info.id();

        match self.peers.remove(&peer_id) {
            Some(Peer {
                     state: PeerState::ConnectionInfoReady(our_info),
                     valid,
                     ..
                 }) => {
                let state = PeerState::CrustConnecting;
                self.insert_peer(Peer::new(peer_id, state, valid));
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
                self.insert_peer(Peer::new(peer_id, state, valid));
                Ok(ConnectionInfoReceivedResult::Waiting)
            }
            Some(peer @ Peer { state: PeerState::ConnectionInfoPreparing { .. }, .. }) |
            Some(peer @ Peer { state: PeerState::CrustConnecting, .. }) |
            Some(peer @ Peer { state: PeerState::Connected(_), .. }) => {
                self.insert_peer(peer);
                Ok(ConnectionInfoReceivedResult::Waiting)
            }
            Some(peer @ Peer { state: PeerState::Client, .. }) => {
                self.insert_peer(peer);
                Ok(ConnectionInfoReceivedResult::IsClient)
            }
            Some(peer @ Peer { state: PeerState::JoiningNode, .. }) => {
                self.insert_peer(peer);
                Ok(ConnectionInfoReceivedResult::IsJoiningNode)
            }
            Some(peer @ Peer { state: PeerState::Proxy, .. }) => {
                self.insert_peer(peer);
                Ok(ConnectionInfoReceivedResult::IsProxy)
            }
            Some(peer @ Peer { state: PeerState::Routing(_), .. }) |
            Some(peer @ Peer { state: PeerState::Candidate(_), .. }) => {
                // TODO: We _should_ retry connecting if the peer is connected via tunnel.
                self.insert_peer(peer);
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
                self.insert_peer(Peer::new(peer_id, state, valid));
                let token = rand::random();
                let _ = self.connection_token_map.insert(token, peer_id);
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
        match self.get_peer(&pub_id).map(Peer::state) {
            Some(&PeerState::Connected(_)) |
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
        self.insert_peer(Peer::new(pub_id,
                                   PeerState::ConnectionInfoPreparing {
                                       us_as_src: src,
                                       them_as_dst: dst,
                                       their_info: None,
                                   },
                                   true));
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
    pub fn peers_needing_tunnel(&self) -> Vec<PublicId> {
        self.peers
            .values()
            .filter_map(|peer| match peer.state {
                            PeerState::SearchingForTunnel => Some(peer.pub_id),
                            _ => None,
                        })
            .collect()
    }

    /// Returns `Ok(())` if the given peer is not yet in the routing table but is allowed to
    /// connect.
    pub fn allow_connect(&self, name: &XorName) -> Result<(), RoutingTableError> {
        self.routing_table.need_to_add(name)
    }

    pub fn insert_peer(&mut self, peer: Peer) {
        let _ = self.peers.insert(peer.pub_id, peer);
    }

    /// Removes the given entry, returns the removed peer and if it was a routing node,
    /// the removal details
    pub fn remove_peer(&mut self,
                       pub_id: &PublicId)
                       -> Option<(Peer, Result<RemovalDetails<XorName>, RoutingTableError>)> {
        let remove_candidate = match self.candidate {
            Candidate::None => false,
            Candidate::Expecting { ref old_pub_id, .. } |
            Candidate::AcceptedForResourceProof { ref old_pub_id, .. } => {
                // only consider candidate cleanup via old_id if candidate is also expired.
                // else candidate may simply be restarting.
                old_pub_id == pub_id && self.candidate.is_expired()
            }
            Candidate::ResourceProof { new_pub_id, .. } => new_pub_id == *pub_id,
        };

        if remove_candidate {
            self.candidate = Candidate::None;
        }

        if let Some(peer) = self.peers.remove(pub_id) {
            let removal_details = self.routing_table.remove(peer.name());
            Some((peer, removal_details))
        } else {
            None
        }
    }

    /// Removes the peer with the given id if present, and returns such PublicIDs.
    /// If the peer is also our proxy, or we are theirs,
    /// it is reinserted as a proxy or joining node.
    fn remove_split_peers(&mut self, ids: Vec<PublicId>) -> Vec<PublicId> {
        {
            // Filter out existing routing peers so we do not flag them to invalid
            let filtered_peers = self.peers
                .values_mut()
                .filter(|peer| match peer.state {
                            PeerState::Routing(_) => false,
                            _ => true,
                        });
            for peer in filtered_peers {
                if self.routing_table
                       .need_to_add(peer.pub_id.name())
                       .is_err() {
                    peer.valid = false;
                }
            }
        }

        ids.iter()
            .filter_map(|id| {
                let mut peer = match self.remove_peer(id) {
                    Some((peer, Ok(_))) => {
                        log_or_panic!(LogLevel::Error,
                                      "{:?} RT split peer has returned removal detail.",
                                      self);
                        peer
                    }
                    Some((peer, Err(RoutingTableError::NoSuchPeer))) => peer,
                    _ => return None,
                };

                match peer {
                    Peer {
                        state: PeerState::Routing(RoutingConnection::JoiningNode(_)), ..
                    } |
                    Peer {
                        state: PeerState::Candidate(RoutingConnection::JoiningNode(_)), ..
                    } => {
                        debug!("{:?} Still the Proxy of {}, re-insert peer as JoiningNode",
                               self,
                               id.name());
                        peer.state = PeerState::JoiningNode;
                        self.insert_peer(peer);
                        None
                    }
                    Peer { state: PeerState::Routing(RoutingConnection::Proxy(_)), .. } => {
                        debug!("{:?} Still the JoiningNode of {}, re-insert peer as Proxy",
                               self,
                               id.name());
                        peer.state = PeerState::Proxy;
                        self.insert_peer(peer);
                        None
                    }
                    Peer { pub_id, .. } => Some(pub_id),
                }
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
        for pub_id in self.peers
                .values()
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

#[cfg(all(test, feature = "use-mock-crust"))]
mod tests {
    use super::*;
    use id::FullId;
    use mock_crust::Endpoint;
    use mock_crust::crust::{PrivConnectionInfo, PubConnectionInfo};
    use routing_table::Authority;
    use types::MessageId;
    use xor_name::{XOR_NAME_LEN, XorName};

    fn node_auth(byte: u8) -> Authority<XorName> {
        Authority::ManagedNode(XorName([byte; XOR_NAME_LEN]))
    }

    #[test]
    pub fn connection_info_prepare_receive() {
        let min_section_size = 8;
        let our_pub_id = *FullId::new().public_id();
        let their_pub_id = *FullId::new().public_id();
        let mut peer_mgr = PeerManager::new(min_section_size, our_pub_id);

        let our_connection_info = PrivConnectionInfo {
            id: our_pub_id,
            endpoint: Endpoint(0),
        };
        let their_connection_info = PubConnectionInfo {
            id: their_pub_id,
            endpoint: Endpoint(1),
        };
        // We decide to connect to the peer with `pub_id`:
        let token =
            unwrap!(peer_mgr.get_connection_token(node_auth(0), node_auth(1), their_pub_id));
        // Crust has finished preparing the connection info.
        match peer_mgr.connection_info_prepared(token, our_connection_info.clone()) {
            Ok(ConnectionInfoPreparedResult {
                   pub_id,
                   src,
                   dst,
                   infos: None,
               }) => {
                assert_eq!(their_pub_id, pub_id);
                assert_eq!(node_auth(0), src);
                assert_eq!(node_auth(1), dst);
            }
            result => panic!("Unexpected result: {:?}", result),
        }
        // Finally, we received the peer's connection info.
        match peer_mgr.connection_info_received(node_auth(0),
                                                node_auth(1),
                                                their_connection_info.clone(),
                                                MessageId::new()) {
            Ok(ConnectionInfoReceivedResult::Ready(our_info, their_info)) => {
                assert_eq!(our_connection_info, our_info);
                assert_eq!(their_connection_info, their_info);
            }
            result => panic!("Unexpected result: {:?}", result),
        }
        // Since both connection infos are present, the state should now be `CrustConnecting`.
        match peer_mgr.get_peer(&their_pub_id).map(Peer::state) {
            Some(&PeerState::CrustConnecting) => (),
            state => panic!("Unexpected state: {:?}", state),
        }
    }

    #[test]
    pub fn connection_info_receive_prepare() {
        let min_section_size = 8;
        let our_pub_id = *FullId::new().public_id();
        let their_pub_id = *FullId::new().public_id();
        let mut peer_mgr = PeerManager::new(min_section_size, our_pub_id);
        let our_connection_info = PrivConnectionInfo {
            id: our_pub_id,
            endpoint: Endpoint(0),
        };
        let their_connection_info = PubConnectionInfo {
            id: their_pub_id,
            endpoint: Endpoint(1),
        };
        let original_msg_id = MessageId::new();
        // We received a connection info from the peer and get a token to prepare ours.
        let token = match peer_mgr.connection_info_received(node_auth(0),
                                                            node_auth(1),
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
                assert_eq!(their_pub_id, pub_id);
                assert_eq!(node_auth(1), src);
                assert_eq!(node_auth(0), dst);
                assert_eq!(our_connection_info, our_info);
                assert_eq!(their_connection_info, their_info);
                assert_eq!(original_msg_id, msg_id);
            }
            result => panic!("Unexpected result: {:?}", result),
        }
        // Since both connection infos are present, the state should now be `CrustConnecting`.
        match peer_mgr.get_peer(&their_pub_id).map(Peer::state) {
            Some(&PeerState::CrustConnecting) => (),
            state => panic!("Unexpected state: {:?}", state),
        }
    }
}
