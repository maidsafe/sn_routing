// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    chain::OnlinePayload,
    error::RoutingError,
    id::PublicId,
    resource_prover::RESOURCE_PROOF_DURATION,
    time::{Duration, Instant},
    utils::{LogIdent, XorTargetInterval},
    xor_name::XorName,
    ConnectionInfo,
};
use itertools::Itertools;
use log::LogLevel;
use resource_proof::ResourceProof;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    net::IpAddr,
};

/// Time (in seconds) after which a joining node will get dropped from the map of joining nodes.
const JOINING_NODE_TIMEOUT_SECS: u64 = 900;
/// Duration after which a candidate is considered as expired.
/// Using a larger timeout to allow Online to accumulate via gossip.
const CANDIDATE_EXPIRED_TIMEOUT: Duration =
    Duration::from_secs(RESOURCE_PROOF_DURATION.as_secs() + 90);
/// Time (in seconds) after which the connection to a peer is considered failed.
const CONNECTING_PEER_TIMEOUT_SECS: u64 = 150;
/// Time (in seconds) the node waits for a peer to either become valid once connected to it or to
/// transition once bootstrapped to it.
const CONNECTED_PEER_TIMEOUT_SECS: u64 = 120;

#[cfg(feature = "mock_base")]
#[doc(hidden)]
pub mod test_consts {
    pub const ACK_TIMEOUT_SECS: u64 = crate::ack_manager::ACK_TIMEOUT.as_secs();
    pub const CANDIDATE_EXPIRED_TIMEOUT_SECS: u64 = super::CANDIDATE_EXPIRED_TIMEOUT.as_secs();
    pub const CONNECTING_PEER_TIMEOUT_SECS: u64 = super::CONNECTING_PEER_TIMEOUT_SECS;
    pub const CONNECTED_PEER_TIMEOUT_SECS: u64 = super::CONNECTED_PEER_TIMEOUT_SECS;
    pub const JOINING_NODE_TIMEOUT_SECS: u64 = super::JOINING_NODE_TIMEOUT_SECS;
    pub const RATE_EXCEED_RETRY_MS: u64 = crate::states::RATE_EXCEED_RETRY.as_millis() as u64;
}

/// Our relationship status with a known peer.
#[derive(Debug)]
// FIXME - See https://maidsafe.atlassian.net/browse/MAID-2026 for info on removing this exclusion.
#[allow(clippy::large_enum_variant)]
pub enum PeerState {
    /// We sent our connection info to them and are waiting for the connection.
    Connecting,
    /// We are connected.
    Connected,
    /// We are the proxy for the client
    Client {
        /// Client IP
        ip: IpAddr,
        /// Traffic charged for Client
        traffic: u64,
    },
    /// We are the proxy for the joining node
    JoiningNode,
    /// Connected peer is a joining node and waiting for approval of routing.
    Candidate,
    /// We are connected to the peer who is a full node.
    Node { was_joining: bool },
    /// We are connected to the peer who is our proxy node.
    Proxy,
}

impl<'a> From<&'a ConnectionInfo> for PeerState {
    fn from(src: &'a ConnectionInfo) -> Self {
        match *src {
            ConnectionInfo::Client { ref peer_addr } => PeerState::Client {
                ip: peer_addr.ip(),
                traffic: 0,
            },
            ConnectionInfo::Node { .. } => PeerState::JoiningNode,
        }
    }
}

/// Represents peer we are connected or attempting connection to.
#[derive(Debug)]
pub struct Peer {
    pub_id: PublicId,
    state: PeerState,
    timestamp: Instant,
}

impl Peer {
    pub fn new(pub_id: PublicId, state: PeerState) -> Self {
        Self {
            pub_id,
            state,
            timestamp: Instant::now(),
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

    /// Returns whether we are connected to the peer.
    pub fn is_connected(&self) -> bool {
        match self.state {
            PeerState::Connecting => false,
            PeerState::Connected
            | PeerState::Proxy
            | PeerState::Client { .. }
            | PeerState::JoiningNode
            | PeerState::Candidate
            | PeerState::Node { .. } => true,
        }
    }

    /// Returns `true` if the peer is not connected and has timed out. In this case, it can be
    /// safely removed from the peer map.
    fn is_expired(&self) -> bool {
        let timeout = match self.state {
            PeerState::Connecting => CONNECTING_PEER_TIMEOUT_SECS,
            PeerState::JoiningNode | PeerState::Proxy => JOINING_NODE_TIMEOUT_SECS,
            PeerState::Connected => CONNECTED_PEER_TIMEOUT_SECS,
            PeerState::Candidate | PeerState::Client { .. } | PeerState::Node { .. } => {
                return false;
            }
        };

        self.timestamp.elapsed() >= Duration::from_secs(timeout)
    }

    /// Returns whether the peer is in the `Connecting` state.
    pub fn is_connecting(&self) -> bool {
        match self.state {
            PeerState::Connecting => true,
            _ => false,
        }
    }

    /// Returns whether the peer is a full node.
    pub fn is_node(&self) -> bool {
        match self.state {
            PeerState::Node { .. } => true,
            _ => false,
        }
    }

    /// Returns whether the peer is our proxy node.
    fn is_proxy(&self) -> bool {
        match self.state {
            PeerState::Proxy => true,
            _ => false,
        }
    }

    /// Returns whether the peer is our client.
    fn is_client(&self) -> bool {
        if let PeerState::Client { .. } = self.state {
            true
        } else {
            false
        }
    }

    // If the peer is a client, return its IP, otherwise returns `None`.
    fn client_ip(&self) -> Option<&IpAddr> {
        if let PeerState::Client { ref ip, .. } = self.state {
            Some(ip)
        } else {
            None
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

/// A candidate (if any) may be in different stages of the resource proof process.
/// As they are accepted for resource proof, a timer will start.
/// On expiry of this timer, we will vote for `PurgeCandidate` and set expired_once, but the
/// resource proof will continue until we reach consensus on either `PurgeCandidate` or `Online`.
/// On termination of our part of the resource proof (When our challenge is completed, we will
/// vote the candidate `Online`.
/// Regardless of our own opinion (be it a vote for `Online`, a vote for PurgeCandidate or a
/// vote for both) we will wait for consensus to be reached on either of these and take the
/// first such event to reach consensus as the source of truth.
/// Finally, if `Online` is consensused first, before allowing a new candidate, we wait for its
/// SectionInfo to be consensused, so this new member will process `ExpectCandidate` the same way
/// the other members will.
// FIXME - See https://maidsafe.atlassian.net/browse/MAID-2026 for info on removing this exclusion.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Eq, PartialEq)]
enum Candidate {
    /// No-one is currently in the resource proof process.
    /// We can take on a new candidate on consensus of an `ExpectCandidate` event.
    None,
    /// We accepted a candidate to perform resource proof in this section. We are waiting for
    /// them to send their `CandidateInfo` before starting the actual resource proof.
    AcceptedForResourceProof {
        res_proof_start: Instant,
        expired_once: bool,
    },
    /// We already received the `CandidateInfo` for this node and either:
    /// They are ongoing resource proof with us
    /// They have passed our challenge (and we voted them Online)
    ResourceProof {
        res_proof_start: Instant,
        expired_once: bool,
        online_payload: OnlinePayload,
        challenge: ResourceProofChallenge,
        passed_our_challenge: bool,
    },
}

impl Candidate {
    fn is_expired(&self) -> bool {
        match self {
            Candidate::None => false,
            Candidate::AcceptedForResourceProof {
                res_proof_start, ..
            }
            | Candidate::ResourceProof {
                res_proof_start, ..
            } => res_proof_start.elapsed() > CANDIDATE_EXPIRED_TIMEOUT,
        }
    }

    fn has_expired_once(&self) -> bool {
        match self {
            Candidate::None => false,
            Candidate::AcceptedForResourceProof { expired_once, .. }
            | Candidate::ResourceProof { expired_once, .. } => *expired_once,
        }
    }

    fn set_expired_once(&mut self) {
        match self {
            Candidate::None => (),
            Candidate::AcceptedForResourceProof {
                ref mut expired_once,
                ..
            }
            | Candidate::ResourceProof {
                ref mut expired_once,
                ..
            } => {
                *expired_once = true;
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
/// we have verified, and whom we are connected to.
pub struct PeerManager {
    peers: BTreeMap<PublicId, Peer>,
    our_public_id: PublicId,
    candidate: Candidate,
    disable_client_rate_limiter: bool,
}

impl PeerManager {
    /// Returns a new peer manager with no entries.
    pub fn new(our_public_id: PublicId, disable_client_rate_limiter: bool) -> PeerManager {
        PeerManager {
            peers: BTreeMap::new(),
            our_public_id: our_public_id,
            candidate: Candidate::None,
            disable_client_rate_limiter: disable_client_rate_limiter,
        }
    }

    /// Handle a `BootstrapRequest` message.
    pub fn handle_bootstrap_request(&mut self, pub_id: PublicId, conn_info: &ConnectionInfo) {
        self.insert_peer(pub_id, conn_info.into());
    }

    /// Return true if received CandidateInfo
    #[cfg(all(test, feature = "mock_parsec"))]
    pub fn has_candidate_info(&self) -> bool {
        if let Candidate::ResourceProof { .. } = self.candidate {
            true
        } else {
            false
        }
    }

    /// Our section decided that the candidate should be selected next.
    /// Store start time so we can detect when candidate expires.
    pub fn accept_as_candidate(&mut self) {
        self.candidate = Candidate::AcceptedForResourceProof {
            res_proof_start: Instant::now(),
            expired_once: false,
        };
    }

    /// Verifies proof of resource.  If the response is not the current candidate, or if it fails
    /// validation, returns `Err`.  Otherwise returns the target size, difficulty and the time
    /// elapsed since the candidate was inserted.
    pub fn verify_candidate(
        &mut self,
        new_public_id: &PublicId,
        part_index: usize,
        part_count: usize,
        proof_part: Vec<u8>,
        leading_zero_bytes: u64,
    ) -> Result<(Option<OnlinePayload>, Duration), RoutingError> {
        let (challenge, passed_our_challenge, res_proof_start, online_payload) =
            match self.candidate {
                Candidate::ResourceProof {
                    ref online_payload,
                    ref mut challenge,
                    ref mut passed_our_challenge,
                    ref res_proof_start,
                    ..
                } if !*passed_our_challenge && *new_public_id == online_payload.new_public_id => (
                    challenge,
                    passed_our_challenge,
                    res_proof_start,
                    online_payload,
                ),
                _ => return Err(RoutingError::UnknownCandidate),
            };

        challenge.proof.extend(proof_part);
        if part_index + 1 != part_count {
            return Ok((None, res_proof_start.elapsed()));
        }
        let rp_object = ResourceProof::new(challenge.target_size, challenge.difficulty);
        if rp_object.validate_all(&challenge.seed, &challenge.proof, leading_zero_bytes) {
            // Only succeed once:
            *passed_our_challenge = true;

            Ok((Some(online_payload.clone()), res_proof_start.elapsed()))
        } else {
            Err(RoutingError::FailedResourceProofValidation)
        }
    }

    /// Updates peer's state to `Candidate` in the peer map if it is an unapproved candidate and
    /// returns the whether the candidate needs to perform the resource proof.
    ///
    /// Returns:
    ///
    /// * Ok(true)                      if the peer is an unapproved candidate
    /// * Ok(false)                     if the peer has already been approved
    /// * Err(UnknownCandidate)         if the peer is not in the candidate list
    pub fn handle_candidate_info(
        &mut self,
        online_payload: OnlinePayload,
        target_interval: &XorTargetInterval,
        target_size: usize,
        difficulty: u8,
        seed: Vec<u8>,
        log_ident: &LogIdent,
    ) -> Result<bool, RoutingError> {
        let log_prefix = format!(
            "{} Candidate {}->{}",
            log_ident,
            online_payload.old_public_id.name(),
            online_payload.new_public_id.name()
        );

        let (res_proof_start, expired_once) = match &self.candidate {
            Candidate::AcceptedForResourceProof {
                res_proof_start,
                expired_once,
            } => (*res_proof_start, *expired_once),
            _ => {
                return Ok(false);
            }
        };

        if !target_interval.contains(online_payload.new_public_id.name()) {
            warn!(
                "{} has used a new ID which is not within the required target range.",
                log_prefix
            );
            return Err(RoutingError::InvalidRelocationTargetRange);
        }

        let peer = match self.peers.get_mut(&online_payload.new_public_id) {
            Some(peer) => peer,
            None => {
                log_or_panic!(LogLevel::Error, "{} is not connected to us.", log_prefix);
                return Err(RoutingError::UnknownConnection(
                    online_payload.new_public_id,
                ));
            }
        };

        peer.state = PeerState::Candidate;

        let challenge = ResourceProofChallenge {
            target_size: target_size,
            difficulty: difficulty,
            seed: seed,
            proof: VecDeque::new(),
        };

        self.candidate = Candidate::ResourceProof {
            res_proof_start,
            expired_once,
            online_payload,
            challenge: challenge,
            passed_our_challenge: false,
        };

        Ok(true)
    }

    /// Logs info about ongoing candidate state, if any.
    pub fn show_candidate_status(&self, log_ident: &LogIdent) {
        let mut log_prefix = format!("{} Proof Candidate Status - ", log_ident);
        match self.candidate {
            Candidate::None | Candidate::AcceptedForResourceProof { .. } => {
                trace!("{}No candidate is currently being proofed.", log_prefix)
            }
            Candidate::ResourceProof {
                ref online_payload,
                ref challenge,
                passed_our_challenge,
                ..
            } => {
                log_prefix = format!("{}{}", log_prefix, online_payload.new_public_id.name());
                if passed_our_challenge {
                    log_prefix = format!("{}has passed our challenge ", log_prefix);
                } else if challenge.proof.is_empty() {
                    log_prefix = format!("{}hasn't responded to our challenge yet ", log_prefix);
                } else {
                    let percent_done = challenge.proof.len() * 100 / challenge.target_size;
                    log_prefix = format!(
                        "{}has sent {}% of resource proof ",
                        log_prefix, percent_done
                    );
                }
                trace!("{}and is not yet approved by our section.", log_prefix);
            }
        }
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
    pub fn connected_peers(&self) -> impl Iterator<Item = &Peer> {
        self.peers.values().filter(|peer| peer.is_connected())
    }

    /// Returns if the given peer is in the `Connecting` state.
    pub fn is_connecting(&self, pub_id: &PublicId) -> bool {
        self.peers.get(pub_id).map_or(false, Peer::is_connecting)
    }

    /// Returns if the given peer is our proxy node.
    pub fn is_proxy(&self, pub_id: &PublicId) -> bool {
        self.peers.get(pub_id).map_or(false, Peer::is_proxy)
    }

    /// Returns if the given peer is our client.
    pub fn is_client(&self, pub_id: &PublicId) -> bool {
        self.peers.get(pub_id).map_or(false, Peer::is_client)
    }

    /// Returns if the given peer is or was a joining node.
    pub fn is_or_was_joining_node(&self, pub_id: &PublicId) -> bool {
        self.peers
            .get(pub_id)
            .map_or(false, Peer::is_or_was_joining_node)
    }

    /// Returns the proxy node's name if we have a proxy.
    pub fn get_proxy_name(&self) -> Option<&XorName> {
        self.peers
            .values()
            .find(|peer| match peer.state {
                PeerState::Proxy => true,
                _ => false,
            })
            .map(Peer::name)
    }

    /// Return old public id of expired candidate only once
    pub fn expired_candidate_once(&mut self) -> bool {
        if !self.candidate.has_expired_once() && self.candidate.is_expired() {
            self.candidate.set_expired_once();
            true
        } else {
            false
        }
    }

    /// Remove and return `PublicId`s of expired peers.
    pub fn remove_expired_peers(&mut self) -> Vec<PublicId> {
        let expired_peers = self
            .peers
            .values()
            .filter(|peer| peer.is_expired())
            .map(|peer| *peer.pub_id())
            .collect_vec();

        for id in &expired_peers {
            let _ = self.remove_peer(id);
        }

        expired_peers
    }

    /// Updates the given clients total traffic amount.
    pub fn add_client_traffic(
        &mut self,
        pub_id: &PublicId,
        added_bytes: u64,
        log_ident: &LogIdent,
    ) {
        let _ = self.peers.get_mut(pub_id).map(|peer| {
            if let PeerState::Client {
                ip,
                traffic: old_traffic,
            } = *peer.state()
            {
                let new_traffic = old_traffic.wrapping_add(added_bytes);
                if new_traffic % (100 * 1024 * 1024) < added_bytes {
                    info!(
                        "{} Stats - Client current session traffic from {:?} - {:?}",
                        log_ident, ip, new_traffic
                    );
                }
                peer.state = PeerState::Client {
                    ip,
                    traffic: new_traffic,
                };
            }
        });
    }

    /// Check whether the given peer exceeds the client limit.
    pub fn exceeds_client_limit(&mut self, pub_id: &PublicId) -> bool {
        if self.disable_client_rate_limiter {
            return false;
        }

        let client_ip = self.peers.get(pub_id).and_then(Peer::client_ip);
        let client_ip = if let Some(ip) = client_ip {
            ip
        } else {
            return false;
        };

        // Allow only one client per IP
        self.peers
            .values()
            .filter_map(Peer::client_ip)
            .filter(|other_ip| *other_ip == client_ip)
            .take(2)
            .count()
            >= 2
    }

    /// Inserts the peer in the `Connecting` state, unless already exists.
    pub fn set_connecting(&mut self, pub_id: PublicId) {
        let _ = self
            .peers
            .entry(pub_id)
            .or_insert_with(|| Peer::new(pub_id, PeerState::Connecting));
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

    /// Returns the given peer.
    pub fn get_peer_by_name(&self, name: &XorName) -> Option<&Peer> {
        let id = if let Some(id) = self.peers.keys().find(|id| id.name() == name) {
            id
        } else {
            return None;
        };
        self.get_peer(id)
    }

    /// Returns the `PublicId` of the node with a given name.
    pub fn get_pub_id(&self, name: &XorName) -> Option<&PublicId> {
        self.get_peer_by_name(name).map(Peer::pub_id)
    }

    /// Returns the `PublicId`s of nodes bearing the names.
    pub fn get_pub_ids(&self, names: &BTreeSet<XorName>) -> BTreeSet<PublicId> {
        names
            .iter()
            .filter_map(|name| {
                if name == self.our_public_id.name() {
                    Some(&self.our_public_id)
                } else {
                    self.get_pub_id(name)
                }
            })
            .cloned()
            .collect()
    }

    /// Insert a peer with the given state.
    /// If a peer with the same public id already exists, it is overwritten.
    pub fn insert_peer(&mut self, pub_id: PublicId, state: PeerState) {
        let _ = self.peers.insert(pub_id, Peer::new(pub_id, state));
    }

    /// Forget about the current candidate.
    pub fn reset_candidate(&mut self) {
        self.candidate = Candidate::None;
    }

    /// Removes the given peer. Returns whether the peer was actually present.
    /// If the peer was joining before, it is demoted back to JoiningNode and false is returned.
    pub fn remove_peer(&mut self, pub_id: &PublicId) -> bool {
        if let Some(mut peer) = self.peers.remove(pub_id) {
            if peer.is_or_was_joining_node() && peer.is_node() {
                peer.state = PeerState::JoiningNode;
                let _ = self.peers.insert(peer.pub_id, peer);
                return false;
            }
        } else {
            return false;
        }

        true
    }

    /// Removes the given peer. Returns whether the peer was actually present.
    pub fn remove_peer_no_joining_checks(&mut self, pub_id: &PublicId) -> bool {
        self.peers.remove(pub_id).is_some()
    }
}
