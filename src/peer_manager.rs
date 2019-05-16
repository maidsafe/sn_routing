// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    chain::OnlinePayload,
    crust::CrustUser,
    error::RoutingError,
    id::PublicId,
    resource_prover::RESOURCE_PROOF_DURATION,
    routing_table::Authority,
    signature_accumulator::ACCUMULATION_TIMEOUT,
    time::{Duration, Instant},
    types::MessageId,
    utils::LogIdent,
    xor_name::XorName,
    {PrivConnectionInfo, PubConnectionInfo},
};
use itertools::Itertools;
use log::LogLevel;
use rand;
use resource_proof::ResourceProof;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
    error, fmt,
    net::IpAddr,
};

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
    pub const ACCUMULATION_TIMEOUT_SECS: u64 = super::ACCUMULATION_TIMEOUT.as_secs();
    pub const ACK_TIMEOUT_SECS: u64 = crate::ack_manager::ACK_TIMEOUT.as_secs();
    pub const RESOURCE_PROOF_DURATION_SECS: u64 = super::RESOURCE_PROOF_DURATION.as_secs();
    pub const CONNECTING_PEER_TIMEOUT_SECS: u64 = super::CONNECTING_PEER_TIMEOUT_SECS;
    pub const CONNECTED_PEER_TIMEOUT_SECS: u64 = super::CONNECTED_PEER_TIMEOUT_SECS;
    pub const JOINING_NODE_TIMEOUT_SECS: u64 = super::JOINING_NODE_TIMEOUT_SECS;
    pub const RATE_EXCEED_RETRY_MS: u64 = crate::states::RATE_EXCEED_RETRY.as_millis() as u64;
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
// FIXME - See https://maidsafe.atlassian.net/browse/MAID-2026 for info on removing this exclusion.
#[allow(clippy::large_enum_variant)]
pub enum PeerState {
    /// The peer has bootstrapped to us with the indicated `CrustUser` type (i.e. client or node).
    Bootstrapper {
        /// The crust user variant (i.e. client or node).
        peer_kind: CrustUser,
        /// IP address of peer.
        ip: IpAddr,
    },
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
    Node,
    /// We are connected to the peer who is our proxy node.
    Proxy,
}

/// The result of adding a peer's `PubConnectionInfo`.
// FIXME - See https://maidsafe.atlassian.net/browse/MAID-2026 for info on removing this exclusion.
#[allow(clippy::large_enum_variant)]
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
            PeerState::ConnectionInfoPreparing { .. }
            | PeerState::ConnectionInfoReady(_)
            | PeerState::CrustConnecting => false,
            PeerState::Bootstrapper { .. }
            | PeerState::JoiningNode
            | PeerState::Proxy
            | PeerState::Client { .. }
            | PeerState::Connected
            | PeerState::Candidate
            | PeerState::Node => true,
        }
    }

    /// Returns `true` if the peer is not connected and has timed out. In this case, it can be
    /// safely removed from the peer map.
    fn is_expired(&self) -> bool {
        let timeout = match self.state {
            PeerState::ConnectionInfoPreparing { .. }
            | PeerState::ConnectionInfoReady(_)
            | PeerState::CrustConnecting => CONNECTING_PEER_TIMEOUT_SECS,
            PeerState::JoiningNode | PeerState::Proxy => JOINING_NODE_TIMEOUT_SECS,
            PeerState::Bootstrapper { .. } | PeerState::Connected => CONNECTED_PEER_TIMEOUT_SECS,
            PeerState::Candidate | PeerState::Client { .. } | PeerState::Node => {
                return false;
            }
        };

        self.timestamp.elapsed() >= Duration::from_secs(timeout)
    }

    /// Returns whether the peer is a full node.
    pub fn is_node(&self) -> bool {
        match self.state {
            PeerState::Node => true,
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

    /// Returns whether the peer is a joining node and we are their proxy.
    fn is_joining_node(&self) -> bool {
        match self.state {
            PeerState::JoiningNode => true,
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
        target_interval: (XorName, XorName),
        old_pub_id: PublicId,
    },
    /// We already received the `CandidateInfo` for this node and either:
    /// They are ongoing resource proof with us
    /// They have passed our challenge (and we voted them Online)
    ResourceProof {
        res_proof_start: Instant,
        expired_once: bool,
        old_pub_id: PublicId,
        new_pub_id: PublicId,
        new_client_auth: Authority<XorName>,
        challenge: Option<ResourceProofChallenge>,
        passed_our_challenge: bool,
    },
    /// We consensused the candidate online. We are waiting for the SectionInfo to consensus
    /// and this new node to start handling events before allowing a new candidate.
    ApprovedWaitingSectionInfo { new_pub_id: PublicId },
}

impl Candidate {
    fn is_expired(&self) -> bool {
        match self {
            Candidate::None | Candidate::ApprovedWaitingSectionInfo { .. } => false,
            Candidate::AcceptedForResourceProof {
                res_proof_start, ..
            }
            | Candidate::ResourceProof {
                res_proof_start, ..
            } => {
                // TODO: need better fix. Using a larger timeout to allow Online to accumulate via gossip
                // than the prev timeout for grp-msg accumulation.
                res_proof_start.elapsed() > RESOURCE_PROOF_DURATION + ACCUMULATION_TIMEOUT * 3
            }
        }
    }

    fn has_expired_once(&self) -> bool {
        match self {
            Candidate::None | Candidate::ApprovedWaitingSectionInfo { .. } => false,
            Candidate::AcceptedForResourceProof { expired_once, .. }
            | Candidate::ResourceProof { expired_once, .. } => *expired_once,
        }
    }

    fn set_expired_once(&mut self) {
        match self {
            Candidate::None | Candidate::ApprovedWaitingSectionInfo { .. } => (),
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

    fn old_pub_id(&self) -> Option<&PublicId> {
        match self {
            Candidate::None | Candidate::ApprovedWaitingSectionInfo { .. } => None,
            Candidate::AcceptedForResourceProof { old_pub_id, .. }
            | Candidate::ResourceProof { old_pub_id, .. } => Some(old_pub_id),
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
    connection_token_map: HashMap<u32, PublicId>,
    peers: BTreeMap<PublicId, Peer>,
    our_public_id: PublicId,
    candidate: Candidate,
    disable_client_rate_limiter: bool,
}

impl PeerManager {
    /// Returns a new peer manager with no entries.
    pub fn new(our_public_id: PublicId, disable_client_rate_limiter: bool) -> PeerManager {
        PeerManager {
            connection_token_map: HashMap::new(),
            peers: BTreeMap::new(),
            our_public_id: our_public_id,
            candidate: Candidate::None,
            disable_client_rate_limiter: disable_client_rate_limiter,
        }
    }

    /// Upgrades a `Bootstrapper` to a `Client` or `JoiningNode`.
    pub fn handle_bootstrap_request(&mut self, pub_id: &PublicId, log_ident: &LogIdent) {
        if let Some(peer) = self.peers.get_mut(pub_id) {
            if let PeerState::Bootstrapper { peer_kind, ip } = peer.state {
                match peer_kind {
                    CrustUser::Node => peer.state = PeerState::JoiningNode,
                    CrustUser::Client => peer.state = PeerState::Client { ip, traffic: 0 },
                }
                return;
            }
        }
        log_or_panic!(
            LogLevel::Error,
            "{} does not have {:?} as a bootstrapper.",
            log_ident,
            pub_id
        );
    }

    /// Return true if already has a candidate
    pub fn has_resource_proof_candidate(&self) -> bool {
        self.candidate != Candidate::None
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
    /// replace any ongoing (i.e. unapproved) candidate with the new state
    /// `AcceptedForResourceProof` for the given candidate.
    pub fn accept_as_candidate(
        &mut self,
        old_pub_id: PublicId,
        target_interval: (XorName, XorName),
    ) {
        if self.has_resource_proof_candidate() {
            log_or_panic!(
                LogLevel::Error,
                "accept_as_candidate when processing one already"
            );
        }

        self.candidate = Candidate::AcceptedForResourceProof {
            res_proof_start: Instant::now(),
            expired_once: false,
            old_pub_id: old_pub_id,
            target_interval: target_interval,
        };
    }

    /// Verifies proof of resource.  If the response is not the current candidate, or if it fails
    /// validation, returns `Err`.  Otherwise returns the target size, difficulty and the time
    /// elapsed since the candidate was inserted.
    pub fn verify_candidate(
        &mut self,
        new_pub_id: &PublicId,
        part_index: usize,
        part_count: usize,
        proof_part: Vec<u8>,
        leading_zero_bytes: u64,
    ) -> Result<Option<(usize, u8, Duration)>, RoutingError> {
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
            Ok(Some((
                challenge.target_size,
                challenge.difficulty,
                res_proof_start.elapsed(),
            )))
        } else {
            Err(RoutingError::FailedResourceProofValidation)
        }
    }

    /// Returns a tuple completed using the verified candidate's details.
    pub fn verified_candidate_info(
        &self,
        log_ident: &LogIdent,
    ) -> Result<(PublicId, OnlinePayload), RoutingError> {
        let (new_pub_id, new_client_auth, old_pub_id) = match self.candidate {
            Candidate::ResourceProof {
                ref new_pub_id,
                ref new_client_auth,
                ref old_pub_id,
                passed_our_challenge: true,
                ..
            } => (new_pub_id, new_client_auth, old_pub_id),
            Candidate::ResourceProof {
                ref new_pub_id,
                passed_our_challenge: false,
                ..
            } => {
                info!(
                    "{} Candidate {} has not passed our resource proof challenge in time. Not \
                     sending approval vote to our section.",
                    log_ident,
                    new_pub_id.name()
                );
                return Err(RoutingError::UnknownCandidate);
            }
            Candidate::None
            | Candidate::AcceptedForResourceProof { .. }
            | Candidate::ApprovedWaitingSectionInfo { .. } => {
                return Err(RoutingError::UnknownCandidate)
            }
        };

        if !self.is_connected(new_pub_id) {
            log_or_panic!(
                LogLevel::Error,
                "{} Not connected to {}.",
                log_ident,
                new_pub_id.name()
            );
            return Err(RoutingError::UnknownCandidate);
        }

        Ok((
            *new_pub_id,
            OnlinePayload {
                client_auth: *new_client_auth,
                old_public_id: *old_pub_id,
            },
        ))
    }

    /// Handles accumulated candidate approval. Marks the candidate as `Approved`.
    /// If the candidate was already purged or is unexpected, return false.
    pub fn handle_candidate_online_event(
        &mut self,
        new_pub_id: &PublicId,
        old_pub_id: &PublicId,
    ) -> bool {
        if self.candidate.old_pub_id() == Some(old_pub_id) {
            // Known candidate was accepted.
            // Ignore any information that could be different stored in candidate.
            // Do not accept candidate until we complete our current one.
            self.candidate = Candidate::ApprovedWaitingSectionInfo {
                new_pub_id: *new_pub_id,
            };
            true
        } else {
            // Unkwown candidate, Candidate was purged before: refuse it.
            false
        }
    }

    /// Handles approved accumulated candidate. Returns if the candidate is connected or
    /// `Err` if the peer is not the candidate or we're missing its info.
    pub fn handle_candidate_approval(
        &mut self,
        new_pub_id: &PublicId,
        log_ident: &LogIdent,
    ) -> Result<bool, RoutingError> {
        if let Some(peer) = self.peers.get_mut(new_pub_id) {
            let is_connected = peer.is_connected();
            if !is_connected {
                trace!(
                    "{} Candidate {} not yet connected to us.",
                    log_ident,
                    new_pub_id.name()
                );
            }
            Ok(is_connected)
        } else {
            trace!("{} No peer with name {}", log_ident, new_pub_id.name());
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
    /// * Err(UnknownCandidate)         if the peer is not in the candidate list
    #[allow(clippy::too_many_arguments)]
    pub fn handle_candidate_info(
        &mut self,
        old_pub_id: &PublicId,
        new_pub_id: &PublicId,
        new_client_auth: &Authority<XorName>,
        target_size: usize,
        difficulty: u8,
        seed: Vec<u8>,
        log_ident: &LogIdent,
    ) -> Result<bool, RoutingError> {
        let log_prefix = format!(
            "{} Candidate {}->{}",
            log_ident,
            old_pub_id.name(),
            new_pub_id.name()
        );

        let (res_proof_start, expired_once, target_interval) = match &self.candidate {
            Candidate::AcceptedForResourceProof {
                res_proof_start,
                expired_once,
                old_pub_id: old_id,
                target_interval,
            } if old_id == old_pub_id => (*res_proof_start, *expired_once, *target_interval),
            _ => {
                return Ok(false);
            }
        };

        if *new_pub_id.name() < target_interval.0 || *new_pub_id.name() > target_interval.1 {
            warn!(
                "{} has used a new ID which is not within the required target range.",
                log_prefix
            );
            return Err(RoutingError::InvalidRelocationTargetRange);
        }

        let peer = match self.peers.get_mut(new_pub_id) {
            Some(peer) => peer,
            None => {
                log_or_panic!(LogLevel::Error, "{} is not connected to us.", log_prefix);
                return Err(RoutingError::UnknownConnection(*new_pub_id));
            }
        };

        peer.state = PeerState::Candidate;

        let challenge = Some(ResourceProofChallenge {
            target_size: target_size,
            difficulty: difficulty,
            seed: seed,
            proof: VecDeque::new(),
        });

        self.candidate = Candidate::ResourceProof {
            res_proof_start,
            expired_once,
            new_pub_id: *new_pub_id,
            old_pub_id: *old_pub_id,
            new_client_auth: *new_client_auth,
            challenge: challenge,
            passed_our_challenge: false,
        };

        Ok(true)
    }

    /// Logs info about ongoing candidate state, if any.
    pub fn show_candidate_status(&self, log_ident: &LogIdent) {
        let mut log_prefix = format!("{} Candidate Status - ", log_ident);
        match self.candidate {
            Candidate::None => trace!("{}No candidate is currently being handled.", log_prefix),
            Candidate::AcceptedForResourceProof { ref old_pub_id, .. } => trace!(
                "{}{} has not sent CandidateInfo yet.",
                log_prefix,
                old_pub_id.name()
            ),
            Candidate::ResourceProof {
                ref new_pub_id,
                challenge: None,
                ..
            } => trace!(
                "{}{} is performing resource proof.",
                log_prefix,
                new_pub_id.name()
            ),
            Candidate::ResourceProof {
                ref new_pub_id,
                challenge: Some(ref challenge),
                passed_our_challenge,
                ..
            } => {
                log_prefix = format!("{}{}", log_prefix, new_pub_id.name());
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
            Candidate::ApprovedWaitingSectionInfo { new_pub_id } => trace!(
                "{}{} has not been included in our SectionInfo yet.",
                log_prefix,
                new_pub_id
            ),
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

        if let PeerState::Node = peer.state {
            Ok(false)
        } else {
            peer.state = PeerState::Node;
            Ok(true)
        }
    }

    /// Returns an iterator over all connected peers.
    pub fn connected_peers(&self) -> impl Iterator<Item = &Peer> {
        self.peers.values().filter(|peer| peer.is_connected())
    }

    /// Returns if the given peer is our proxy node.
    pub fn is_proxy(&self, pub_id: &PublicId) -> bool {
        self.peers.get(pub_id).map_or(false, Peer::is_proxy)
    }

    /// Returns if the given peer is our client.
    pub fn is_client(&self, pub_id: &PublicId) -> bool {
        self.peers.get(pub_id).map_or(false, Peer::is_client)
    }

    /// Returns if the given peer is our joining node.
    pub fn is_joining_node(&self, pub_id: &PublicId) -> bool {
        self.peers.get(pub_id).map_or(false, Peer::is_joining_node)
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
    pub fn expired_candidate_old_public_id_once(&mut self) -> Option<PublicId> {
        if !self.candidate.has_expired_once() && self.candidate.is_expired() {
            self.candidate.set_expired_once();
            self.candidate.old_pub_id().cloned()
        } else {
            None
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

    /// Checks whether we can accept more clients.
    pub fn can_accept_client(&self, client_ip: IpAddr) -> bool {
        self.disable_client_rate_limiter
            || !self.peers.values().any(|peer| match *peer.state() {
                PeerState::Client { ip, .. } => client_ip == ip,
                _ => false,
            })
    }

    /// Marks the given peer as direct-connected.
    pub fn set_connected(&mut self, pub_id: &PublicId) {
        if let Some(peer) = self.peers.get_mut(pub_id) {
            peer.timestamp = Instant::now();
            peer.state = PeerState::Connected;
            return;
        }

        self.insert_peer(Peer::new(*pub_id, PeerState::Connected));
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

    /// Inserts the given connection info in the map to wait for the peer's info, or returns both
    /// if that's already present and sets the status to `CrustConnecting`. It also returns the
    /// source and destination authorities for sending the serialised connection info to the peer.
    pub fn connection_info_prepared(
        &mut self,
        token: u32,
        our_info: PrivConnectionInfo,
    ) -> Result<ConnectionInfoPreparedResult, Error> {
        let pub_id = self
            .connection_token_map
            .remove(&token)
            .ok_or(Error::PeerNotFound)?;
        let (us_as_src, them_as_dst, opt_their_info) = match self.peers.remove(&pub_id) {
            Some(Peer {
                state:
                    PeerState::ConnectionInfoPreparing {
                        us_as_src,
                        them_as_dst,
                        their_info,
                    },
                ..
            }) => (us_as_src, them_as_dst, their_info),
            Some(peer) => {
                self.insert_peer(peer);
                return Err(Error::UnexpectedState);
            }
            None => return Err(Error::PeerNotFound),
        };

        let infos = match opt_their_info {
            Some((their_info, msg_id)) => {
                let state = PeerState::CrustConnecting;
                self.insert_peer(Peer::new(pub_id, state));
                Some((our_info, their_info, msg_id))
            }
            None => {
                let state = PeerState::ConnectionInfoReady(our_info);
                self.insert_peer(Peer::new(pub_id, state));
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
    pub fn connection_info_received(
        &mut self,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        peer_info: PubConnectionInfo,
        msg_id: MessageId,
        is_conn_info_req: bool,
    ) -> Result<ConnectionInfoReceivedResult, Error> {
        let pub_id = peer_info.id();

        match self.peers.remove(&pub_id) {
            Some(Peer {
                state: PeerState::ConnectionInfoReady(our_info),
                ..
            }) => {
                let state = PeerState::CrustConnecting;
                self.insert_peer(Peer::new(pub_id, state));
                Ok(ConnectionInfoReceivedResult::Ready(our_info, peer_info))
            }
            Some(Peer {
                state:
                    PeerState::ConnectionInfoPreparing {
                        us_as_src,
                        them_as_dst,
                        their_info: None,
                    },
                ..
            }) => {
                let state = PeerState::ConnectionInfoPreparing {
                    us_as_src: us_as_src,
                    them_as_dst: them_as_dst,
                    their_info: Some((peer_info, msg_id)),
                };
                self.insert_peer(Peer::new(pub_id, state));
                Ok(ConnectionInfoReceivedResult::Waiting)
            }
            Some(
                peer @ Peer {
                    state: PeerState::Bootstrapper { .. },
                    ..
                },
            )
            | Some(
                peer @ Peer {
                    state: PeerState::ConnectionInfoPreparing { .. },
                    ..
                },
            )
            | Some(
                peer @ Peer {
                    state: PeerState::CrustConnecting,
                    ..
                },
            )
            | Some(
                peer @ Peer {
                    state: PeerState::Connected,
                    ..
                },
            ) => {
                self.insert_peer(peer);
                Ok(ConnectionInfoReceivedResult::Waiting)
            }
            Some(
                peer @ Peer {
                    state: PeerState::Client { .. },
                    ..
                },
            ) => {
                self.insert_peer(peer);
                Ok(ConnectionInfoReceivedResult::IsClient)
            }
            Some(
                peer @ Peer {
                    state: PeerState::JoiningNode,
                    ..
                },
            ) => {
                self.insert_peer(peer);
                Ok(ConnectionInfoReceivedResult::IsJoiningNode)
            }
            Some(
                peer @ Peer {
                    state: PeerState::Proxy,
                    ..
                },
            ) => {
                self.insert_peer(peer);
                Ok(ConnectionInfoReceivedResult::IsProxy)
            }
            Some(
                peer @ Peer {
                    state: PeerState::Node,
                    ..
                },
            )
            | Some(
                peer @ Peer {
                    state: PeerState::Candidate,
                    ..
                },
            ) => {
                self.insert_peer(peer);
                Ok(ConnectionInfoReceivedResult::IsConnected)
            }
            None => {
                if !is_conn_info_req {
                    return Ok(ConnectionInfoReceivedResult::Waiting);
                }
                let state = PeerState::ConnectionInfoPreparing {
                    us_as_src: dst,
                    them_as_dst: src,
                    their_info: Some((peer_info, msg_id)),
                };
                self.insert_peer(Peer::new(pub_id, state));
                let token = rand::random();
                let _ = self.connection_token_map.insert(token, pub_id);
                Ok(ConnectionInfoReceivedResult::Prepare(token))
            }
        }
    }

    /// Returns a new token for Crust's `prepare_connection_info` and puts the given peer into
    /// `ConnectionInfoPreparing` status.
    pub fn get_connection_token(
        &mut self,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        pub_id: PublicId,
    ) -> Option<u32> {
        if self.get_peer(&pub_id).is_some() {
            return None;
        }
        let token = rand::random();
        let _ = self.connection_token_map.insert(token, pub_id);
        self.insert_peer(Peer::new(
            pub_id,
            PeerState::ConnectionInfoPreparing {
                us_as_src: src,
                them_as_dst: dst,
                their_info: None,
            },
        ));
        Some(token)
    }

    /// If preparing connection info failed with the given token, prepares and returns a new token.
    pub fn get_new_connection_info_token(&mut self, token: u32) -> Result<u32, Error> {
        let pub_id = self
            .connection_token_map
            .remove(&token)
            .ok_or(Error::PeerNotFound)?;
        let new_token = rand::random();
        let _ = self.connection_token_map.insert(new_token, pub_id);
        Ok(new_token)
    }

    pub fn insert_peer(&mut self, peer: Peer) {
        let _ = self.peers.insert(peer.pub_id, peer);
    }

    /// Forget about the current candidate.
    pub fn reset_candidate(&mut self) {
        self.candidate = Candidate::None;
    }

    /// Forget about the current candidate if it is a member of the given section.
    pub fn reset_candidate_if_member_of(&mut self, members: &BTreeSet<PublicId>) {
        if let Candidate::ApprovedWaitingSectionInfo { ref new_pub_id } = self.candidate {
            if members.contains(new_pub_id) {
                self.candidate = Candidate::None;
            }
        }
    }

    /// Forget about the current candidate if it matches the purged old public id.
    pub fn reset_candidate_with_old_public_id(&mut self, old_pub_id: &PublicId) {
        if Some(old_pub_id) == self.candidate.old_pub_id() {
            self.candidate = Candidate::None;
        }
    }

    /// Removes the given peer. Returns whether the peer was actually present.
    pub fn remove_peer(&mut self, pub_id: &PublicId) -> bool {
        self.peers.remove(pub_id).is_some()
    }
}

#[cfg(all(test, feature = "mock_base"))]
mod tests {
    use super::*;
    use crate::id::FullId;
    use crate::mock_crust::crust::{PrivConnectionInfo, PubConnectionInfo};
    use crate::mock_crust::Endpoint;
    use crate::routing_table::Authority;
    use crate::types::MessageId;
    use crate::xor_name::{XorName, XOR_NAME_LEN};

    fn node_auth(byte: u8) -> Authority<XorName> {
        Authority::ManagedNode(XorName([byte; XOR_NAME_LEN]))
    }

    #[test]
    pub fn connection_info_prepare_receive() {
        let our_pub_id = *FullId::new().public_id();
        let their_pub_id = *FullId::new().public_id();
        let mut peer_mgr = PeerManager::new(our_pub_id, false);

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
            unwrap!(peer_mgr.get_connection_token(node_auth(0), node_auth(1), their_pub_id,));
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
        match peer_mgr.connection_info_received(
            node_auth(0),
            node_auth(1),
            their_connection_info.clone(),
            MessageId::new(),
            false,
        ) {
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
        let our_pub_id = *FullId::new().public_id();
        let their_pub_id = *FullId::new().public_id();
        let mut peer_mgr = PeerManager::new(our_pub_id, false);
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
        let token = match peer_mgr.connection_info_received(
            node_auth(0),
            node_auth(1),
            their_connection_info.clone(),
            original_msg_id,
            true,
        ) {
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
