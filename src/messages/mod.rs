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

mod request;
mod response;

pub use self::request::Request;
pub use self::response::{AccountInfo, Response};
use super::{QUORUM_DENOMINATOR, QUORUM_NUMERATOR};
use ack_manager::Ack;
use data::MAX_IMMUTABLE_DATA_SIZE_IN_BYTES;
use error::{BootstrapResponseError, RoutingError};
use event::Event;
use id::{FullId, PublicId};
use itertools::Itertools;
use lru_time_cache::LruCache;
use maidsafe_utilities::serialisation::{deserialise, serialise};
use peer_manager::SectionMap;
use routing_table::{Prefix, VersionedPrefix, Xorable};
use routing_table::Authority;
use rust_sodium::crypto::{box_, sign};
use sha3::Digest256;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt::{self, Debug, Formatter};
use std::iter;
use std::time::Duration;
use tiny_keccak::sha3_256;
use types::MessageId;
use utils;
use xor_name::XorName;

/// The maximal length of a user message part, in bytes.
pub const MAX_PART_LEN: usize = 20 * 1024;
pub const MAX_PARTS: u32 = ((MAX_IMMUTABLE_DATA_SIZE_IN_BYTES / MAX_PART_LEN as u64) + 1) as u32;

/// Get and refresh messages from nodes have a high priority: They relocate data under churn and are
/// critical to prevent data loss.
pub const RELOCATE_PRIORITY: u8 = 1;
/// Other requests have a lower priority: If they fail due to high traffic, the sender retries.
pub const DEFAULT_PRIORITY: u8 = 2;
/// `Get` requests from clients have the lowest priority: If bandwidth is insufficient, the network
/// needs to prioritise maintaining its structure, data and consensus.
pub const CLIENT_GET_PRIORITY: u8 = 3;

/// Wrapper of all messages.
///
/// This is the only type allowed to be sent / received on the network.
#[derive(Debug, Serialize, Deserialize)]
// FIXME - See https://maidsafe.atlassian.net/browse/MAID-2026 for info on removing this exclusion.
#[cfg_attr(feature = "cargo-clippy", allow(large_enum_variant))]
pub enum Message {
    /// A message sent between two nodes directly
    Direct(DirectMessage),
    /// A message sent across the network (in transit)
    Hop(HopMessage),
    /// A direct message sent via a tunnel because the nodes could not connect directly
    TunnelDirect {
        /// The wrapped message
        content: DirectMessage,
        /// The sender
        src: PublicId,
        /// The receiver
        dst: PublicId,
    },
    /// A hop message sent via a tunnel because the nodes could not connect directly
    TunnelHop {
        /// The wrapped message
        content: HopMessage,
        /// The sender
        src: PublicId,
        /// The receiver
        dst: PublicId,
    },
}

impl Message {
    pub fn priority(&self) -> u8 {
        match *self {
            Message::Direct(ref content) |
            Message::TunnelDirect { ref content, .. } => content.priority(),
            Message::Hop(ref content) |
            Message::TunnelHop { ref content, .. } => content.content.content.priority(),
        }
    }
}

/// Messages sent via a direct connection.
///
/// Allows routing to directly send specific messages between nodes.
#[derive(Serialize, Deserialize)]
// FIXME - See https://maidsafe.atlassian.net/browse/MAID-2026 for info on removing this exclusion.
#[cfg_attr(feature = "cargo-clippy", allow(large_enum_variant))]
pub enum DirectMessage {
    /// Sent from members of a section or group message's source authority to the first hop. The
    /// message will only be relayed once enough signatures have been accumulated.
    MessageSignature(Digest256, sign::Signature),
    /// A signature for the current `BTreeSet` of section's node names
    SectionListSignature(SectionList, sign::Signature),
    /// Sent from a newly connected client to the bootstrap node to prove that it is the owner of
    /// the client's claimed public ID.
    BootstrapRequest(sign::Signature),
    /// Sent from the bootstrap node to a client in response to `BootstrapRequest`. If `true`,
    /// bootstrapping is successful; if `false` the sender is not available as a bootstrap node.
    BootstrapResponse(Result<(), BootstrapResponseError>),
    /// Sent from a node which is still joining the network to another node, to allow the latter to
    /// add the former to its routing table.
    CandidateInfo {
        /// `PublicId` from before relocation.
        old_public_id: PublicId,
        /// `PublicId` from after relocation.
        new_public_id: PublicId,
        /// Signature of concatenated `PublicId`s using the pre-relocation key.
        signature_using_old: sign::Signature,
        /// Signature of concatenated `PublicId`s and `signature_using_old` using the
        /// post-relocation key.
        signature_using_new: sign::Signature,
        /// Client authority from after relocation.
        new_client_auth: Authority<XorName>,
    },
    /// Sent from a node that needs a tunnel to be able to connect to the given peer.
    TunnelRequest(PublicId),
    /// Sent as a response to `TunnelRequest` if the node can act as a tunnel.
    TunnelSuccess(PublicId),
    /// Sent as a response to `TunnelSuccess` if the node is selected to act as a tunnel.
    TunnelSelect(PublicId),
    /// Sent from a tunnel node to indicate that the given peer has disconnected.
    TunnelClosed(PublicId),
    /// Sent to a tunnel node to indicate the tunnel is not needed any more.
    TunnelDisconnect(PublicId),
    /// Request a proof to be provided by the joining node.
    ///
    /// This is sent from member of Group Y to the joining node.
    ResourceProof {
        /// seed of proof
        seed: Vec<u8>,
        /// size of the proof
        target_size: usize,
        /// leading zero bits of the hash of the proof
        difficulty: u8,
    },
    /// Provide a proof to the network
    ///
    /// This is sent from the joining node to member of Group Y
    ResourceProofResponse {
        /// The index of this part of the resource proof.
        part_index: usize,
        /// The total number of parts.
        part_count: usize,
        /// Proof to be presented
        proof: Vec<u8>,
        /// Claimed leading zero bytes to be added to proof's header so that the hash matches
        /// the difficulty requirement
        leading_zero_bytes: u64,
    },
    /// Receipt of a part of a ResourceProofResponse
    ResourceProofResponseReceipt,
    /// Sent from a proxy node to its client to indicate that the client exceeded its rate limit.
    ProxyRateLimitExceeded { ack: Ack },
}

impl DirectMessage {
    /// The priority Crust should send this message with.
    pub fn priority(&self) -> u8 {
        match *self {
            DirectMessage::ResourceProofResponse { .. } => 9,
            _ => 0,
        }
    }
}

/// An individual hop message that represents a part of the route of a message in transit.
///
/// To relay a `SignedMessage` via another node, the `SignedMessage` is wrapped in a `HopMessage`.
/// The `signature` is from the node that sends this directly to a node in its routing table. To
/// prevent Man-in-the-middle attacks, the `content` is signed by the original sender.
#[derive(Serialize, Deserialize)]
pub struct HopMessage {
    /// Wrapped signed message.
    pub content: SignedMessage,
    /// Route number; corresponds to the index of the peer in the section of target peers being
    /// considered for the next hop.
    pub route: u8,
    /// Every node this has already been sent to.
    pub sent_to: BTreeSet<XorName>,
    /// Signature to be validated against the neighbouring sender's public key.
    signature: sign::Signature,
}

impl HopMessage {
    /// Wrap `content` for transmission to the next hop and sign it.
    pub fn new(
        content: SignedMessage,
        route: u8,
        sent_to: BTreeSet<XorName>,
        signing_key: &sign::SecretKey,
    ) -> Result<HopMessage, RoutingError> {
        let bytes_to_sign = serialise(&content)?;
        Ok(HopMessage {
            content: content,
            route: route,
            sent_to: sent_to,
            signature: sign::sign_detached(&bytes_to_sign, signing_key),
        })
    }

    /// Validate that the message is signed by `verification_key` contained in message.
    ///
    /// This does not imply that the message came from a known node. That requires a check against
    /// the routing table to identify the name associated with the `verification_key`.
    pub fn verify(&self, verification_key: &sign::PublicKey) -> Result<(), RoutingError> {
        let signed_bytes = serialise(&self.content)?;
        if sign::verify_detached(&self.signature, &signed_bytes, verification_key) {
            Ok(())
        } else {
            Err(RoutingError::FailedSignature)
        }
    }
}

/// A list of a section's public IDs, together with a list of signatures of a neighbouring section.
#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Hash, Serialize, Deserialize, Debug)]
pub struct SectionList {
    pub prefix: Prefix<XorName>,
    // TODO(MAID-1677): pub signatures: BTreeSet<(PublicId, sign::Signature)>,
    pub_ids: BTreeSet<PublicId>,
}

impl SectionList {
    /// Create
    pub fn new(prefix: Prefix<XorName>, pub_ids: BTreeSet<PublicId>) -> Self {
        SectionList {
            prefix: prefix,
            pub_ids: pub_ids,
        }
    }

    /// Create from any object convertable to an iterator
    pub fn from<I: IntoIterator<Item = PublicId>>(prefix: Prefix<XorName>, pub_ids: I) -> Self {
        Self::new(prefix, pub_ids.into_iter().collect())
    }
}

/// Wrapper around a routing message, signed by the originator of the message.
#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Hash, Serialize, Deserialize)]
pub struct SignedMessage {
    /// A request or response type message.
    content: RoutingMessage,
    /// Nodes sending the message (those expected to sign it)
    src_sections: Vec<SectionList>,
    /// The lists of the sections involved in routing this message, in chronological order.
    // TODO: implement (MAID-1677): sec_lists: Vec<SectionList>,
    /// The IDs and signatures of the source authority's members.
    signatures: BTreeMap<PublicId, sign::Signature>,
}

impl SignedMessage {
    /// Creates a `SignedMessage` with the given `content` and signed by the given `full_id`.
    ///
    /// Requires the list `src_sections` of nodes who should sign this message.
    pub fn new(
        content: RoutingMessage,
        full_id: &FullId,
        mut src_sections: Vec<SectionList>,
    ) -> Result<SignedMessage, RoutingError> {
        src_sections.sort_by_key(|list| list.prefix);
        let sig = sign::sign_detached(&serialise(&content)?, full_id.signing_private_key());
        Ok(SignedMessage {
            content: content,
            src_sections: src_sections,
            signatures: iter::once((*full_id.public_id(), sig)).collect(),
        })
    }

    /// Confirms the signatures.
    // TODO (MAID-1677): verify the sending SectionLists via each hop's signed lists
    pub fn check_integrity(&self, min_section_size: usize) -> Result<(), RoutingError> {
        let signed_bytes = serialise(&self.content)?;
        if !self.find_invalid_sigs(signed_bytes).is_empty() {
            return Err(RoutingError::FailedSignature);
        }
        if !self.has_enough_sigs(min_section_size) {
            return Err(RoutingError::NotEnoughSignatures);
        }
        Ok(())
    }

    /// Returns whether the message is signed by the given public ID.
    pub fn signed_by(&self, pub_id: &PublicId) -> bool {
        self.signatures.contains_key(pub_id)
    }

    /// Returns the number of nodes in the source authority.
    pub fn src_size(&self) -> usize {
        self.src_sections.iter().map(|sl| sl.pub_ids.len()).sum()
    }

    /// Adds the given signature if it is new, without validating it. If the collection of section
    /// lists isn't empty, the signature is only added if `pub_id` is a member of the first section
    /// list.
    pub fn add_signature(&mut self, pub_id: PublicId, sig: sign::Signature) {
        if self.content.src.is_multiple() && self.is_sender(&pub_id) {
            let _ = self.signatures.insert(pub_id, sig);
        }
    }

    /// Adds all signatures from the given message, without validating them.
    pub fn add_signatures(&mut self, msg: SignedMessage) {
        if self.content.src.is_multiple() {
            self.signatures.extend(msg.signatures);
        }
    }

    /// Returns the routing message without cloning it.
    pub fn into_routing_message(self) -> RoutingMessage {
        self.content
    }

    /// The routing message that was signed.
    pub fn routing_message(&self) -> &RoutingMessage {
        &self.content
    }

    /// The priority Crust should send this message with.
    pub fn priority(&self) -> u8 {
        self.content.priority()
    }

    /// Returns whether there are enough signatures from the sender.
    pub fn check_fully_signed(&mut self, min_section_size: usize) -> bool {
        if !self.has_enough_sigs(min_section_size) {
            return false;
        }

        // Remove invalid signatures, then check again that we have enough.
        // We also check (again) that all messages are from valid senders, because the message
        // may have been sent from another node, and we cannot trust that that node correctly
        // controlled which signatures were added.
        // TODO (MAID-1677): we also need to check that the src_sections list corresponds to the
        // section(s) at some point in recent history; i.e. that it was valid; but we shouldn't
        // force it to match our own because our routing table may have changed since.

        let signed_bytes = match serialise(&self.content) {
            Ok(serialised) => serialised,
            Err(error) => {
                warn!("Failed to serialise {:?}: {:?}", self, error);
                return false;
            }
        };
        for invalid_signature in &self.find_invalid_sigs(signed_bytes) {
            let _ = self.signatures.remove(invalid_signature);
        }

        self.has_enough_sigs(min_section_size)
    }

    // Returns true iff `pub_id` is in self.section_lists
    fn is_sender(&self, pub_id: &PublicId) -> bool {
        self.src_sections.iter().any(
            |list| list.pub_ids.contains(pub_id),
        )
    }

    // Returns a list of all invalid signatures (not from an expected key or not cryptographically
    // valid).
    fn find_invalid_sigs(&self, signed_bytes: Vec<u8>) -> Vec<PublicId> {
        let invalid = self.signatures
            .iter()
            .filter_map(|(pub_id, sig)| {
                // Remove if not in sending nodes or signature is invalid:
                let is_valid = if let Authority::Client { ref client_id, .. } = self.content.src {
                    client_id == pub_id &&
                        sign::verify_detached(sig, &signed_bytes, client_id.signing_public_key())
                } else {
                    self.is_sender(pub_id) &&
                        sign::verify_detached(sig, &signed_bytes, pub_id.signing_public_key())
                };
                if is_valid { None } else { Some(*pub_id) }
            })
            .collect_vec();
        if !invalid.is_empty() {
            debug!("{:?}: invalid signatures: {:?}", self, invalid);
        }
        invalid
    }

    // Returns true if there are enough signatures (note that this method does not verify the
    // signatures, it only counts them; it also does not verify `self.src_sections`).
    fn has_enough_sigs(&self, min_section_size: usize) -> bool {
        use Authority::*;
        match self.content.src {
            ClientManager(_) | NaeManager(_) | NodeManager(_) => {
                // Note: there should be exactly one source section, but we use safe code:
                let valid_names: HashSet<_> = self.src_sections
                    .iter()
                    .flat_map(|list| list.pub_ids.iter().map(PublicId::name))
                    .sorted_by(|lhs, rhs| self.content.src.name().cmp_distance(lhs, rhs))
                    .into_iter()
                    .take(min_section_size)
                    .collect();
                let valid_sigs = self.signatures
                    .keys()
                    .filter(|pub_id| valid_names.contains(pub_id.name()))
                    .count();
                // TODO: we should consider replacing valid_names.len() with
                // cmp::min(routing_table.len(), min_section_size)
                // (or just min_section_size, but in that case we will not be able to handle user
                // messages during boot-up).
                valid_sigs * QUORUM_DENOMINATOR > valid_names.len() * QUORUM_NUMERATOR
            }
            Section(_) => {
                // Note: there should be exactly one source section, but we use safe code:
                let num_sending = self.src_sections.iter().fold(0, |count, list| {
                    count + list.pub_ids.len()
                });
                let valid_sigs = self.signatures.len();
                valid_sigs * QUORUM_DENOMINATOR > num_sending * QUORUM_NUMERATOR
            }
            PrefixSection(_) => {
                // Each section must have enough signatures:
                self.src_sections.iter().all(|list| {
                    let valid_sigs = self.signatures
                        .keys()
                        .filter(|pub_id| list.pub_ids.contains(pub_id))
                        .count();
                    valid_sigs * QUORUM_DENOMINATOR > list.pub_ids.len() * QUORUM_NUMERATOR
                })
            }
            ManagedNode(_) | Client { .. } => self.signatures.len() == 1,
        }
    }
}

/// A routing message with source and destination authorities.
#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Hash, Debug, Serialize, Deserialize)]
pub struct RoutingMessage {
    /// Source authority
    pub src: Authority<XorName>,
    /// Destination authority
    pub dst: Authority<XorName>,
    /// The message content
    pub content: MessageContent,
}

impl RoutingMessage {
    /// Create ack for the given message
    pub fn ack_from(msg: &RoutingMessage, src: Authority<XorName>) -> Result<Self, RoutingError> {
        Ok(RoutingMessage {
            src: src,
            dst: msg.src,
            content: MessageContent::Ack(Ack::compute(msg)?, msg.priority()),
        })
    }

    /// Returns the priority Crust should send this message with.
    pub fn priority(&self) -> u8 {
        self.content.priority()
    }

    /// Returns a `DirectMessage::MessageSignature` for this message.
    pub fn to_signature(
        &self,
        signing_key: &sign::SecretKey,
    ) -> Result<DirectMessage, RoutingError> {
        let serialised_msg = serialise(self)?;
        let hash = sha3_256(&serialised_msg);
        let sig = sign::sign_detached(&serialised_msg, signing_key);
        Ok(DirectMessage::MessageSignature(hash, sig))
    }
}

/// The routing message types
///
/// # The bootstrap process
///
///
/// ## Bootstrapping a client
///
/// A newly created `Core`, A, starts in `Disconnected` state and tries to establish a connection to
/// any node B of the network via Crust. When successful, i.e. when receiving an `OnConnect` event,
/// it moves to the `Bootstrapping` state.
///
/// A now sends a `BootstrapRequest` message to B, containing the signature of A's public ID. B
/// responds with a `BootstrapResponse`, indicating success or failure. Once it receives that, A
/// goes into the `Client` state and uses B as its proxy to the network.
///
/// A can now exchange messages with any `Authority`. This completes the bootstrap process for
/// clients.
///
///
/// ## Becoming a node
///
/// If A wants to become a full routing node (`client_restriction == false`), it needs to relocate,
/// i. e. change its name to a value chosen by the network, and then add its peers to its routing
/// table and get added to their routing tables.
///
///
/// ### Relocating on the network
///
/// Once in `JoiningNode` state, A sends a `Relocate` request to the `NaeManager` section authority
/// X of A's current name. X computes a target destination Y to which A should relocate and sends
/// that section's `NaeManager`s an `ExpectCandidate` containing A's current public ID. Each member
/// of Y caches A's public ID, and sends `AcceptAsCandidate` to self section. Once Y receives
/// `AcceptAsCandidate`, sends a `RelocateResponse` back to A, which includes an address space range
/// into which A should relocate and also the public IDs of the members of Y. A then disconnects
/// from the network and reconnects with a new ID which falls within the specified address range.
/// After connecting to the members of Y, it begins the resource proof process. Upon successful
/// completion, A is regarded as a full node and connects to all neighbouring sections' peers.
///
///
/// ### Connecting to the matching section
///
/// To the `ManagedNode` for each public ID it receives from members of Y, A sends its
/// `ConnectionInfo`. It also caches the ID.
///
/// For each `ConnectionInfo` that a node Z receives from A, it decides whether it wants A in its
/// routing table. If yes, and if A's ID is in its ID cache, Z sends its own `ConnectionInfo` back
/// to A and also attempts to connect to A via Crust. A does the same, once it receives the
/// `ConnectionInfo`.
///
///
/// ### Resource Proof Evaluation to approve
/// When nodes Z of section Y receive `CandidateInfo` from A, they reply with a `ResourceProof`
/// request. Node A needs to answer these requests (resolving a hashing challenge) with
/// `ResourceProofResponse`. Members of Y will send out `CandidateApproval` messages to vote for the
/// approval in their section. Once the vote succeeds, the members of Y send `NodeApproval` to A and
/// add it into their routing table. When A receives the `NodeApproval` message, it adds the members
/// of Y to its routing table.
///
#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Hash, Serialize, Deserialize)]
// FIXME - See https://maidsafe.atlassian.net/browse/MAID-2026 for info on removing this exclusion.
#[cfg_attr(feature = "cargo-clippy", allow(large_enum_variant))]
pub enum MessageContent {
    // ---------- Internal ------------
    /// Ask the network to relocate you.
    ///
    /// This is sent by a joining node to its `NaeManager`s with the intent to become a full routing
    /// node with a new ID in an address range chosen by the `NaeManager`s.
    Relocate {
        /// The message's unique identifier.
        message_id: MessageId,
    },
    /// Notify a joining node's `NaeManager` so that it sends a `RelocateResponse`.
    ExpectCandidate {
        /// The joining node's current public ID.
        old_public_id: PublicId,
        /// The joining node's current authority.
        old_client_auth: Authority<XorName>,
        /// The message's unique identifier.
        message_id: MessageId,
    },
    /// Send our Crust connection info encrypted to a node we wish to connect to and for which we
    /// have the keys.
    ConnectionInfoRequest {
        /// Encrypted Crust connection info.
        encrypted_conn_info: Vec<u8>,
        /// Nonce used to provide a salt in the encrypted message.
        nonce: [u8; box_::NONCEBYTES],
        /// The sender's public ID.
        pub_id: PublicId,
        /// The message's unique identifier.
        msg_id: MessageId,
    },
    /// Respond to a `ConnectionInfoRequest` with our Crust connection info encrypted to the
    /// requester.
    ConnectionInfoResponse {
        /// Encrypted Crust connection info.
        encrypted_conn_info: Vec<u8>,
        /// Nonce used to provide a salt in the encrypted message.
        nonce: [u8; box_::NONCEBYTES],
        /// The sender's public ID.
        pub_id: PublicId,
        /// The message's unique identifier.
        msg_id: MessageId,
    },
    /// Reply with the address range into which the joining node should move.
    RelocateResponse {
        /// The interval into which the joining node should join.
        target_interval: (XorName, XorName),
        /// The section that the joining node shall connect to.
        section: (Prefix<XorName>, BTreeSet<PublicId>),
        /// The message's unique identifier.
        message_id: MessageId,
    },
    /// Sent to notify neighbours and own members when our section's member list changed (for now,
    /// only when new nodes join).
    SectionUpdate {
        /// Section prefix and version. Included because this message is sent to both the section's
        /// own members and neighbouring sections.
        versioned_prefix: VersionedPrefix<XorName>,
        /// Members of the section
        members: BTreeSet<PublicId>,
    },
    /// Sent to all connected peers when our own section splits
    SectionSplit(VersionedPrefix<XorName>, XorName),
    /// Sent amongst members of a newly-merged section to allow synchronisation of their routing
    /// tables before notifying other connected peers of the merge.
    ///
    /// The source and destination authorities are both `PrefixSection` types, conveying the
    /// section sending this merge message and the target prefix of the merge respectively.
    OwnSectionMerge(SectionMap),
    /// Sent by members of a newly-merged section to peers outwith the merged section to notify them
    /// of the merge.
    ///
    /// The source authority is a `PrefixSection` conveying the section which just merged. The
    /// first field is the set of members of the section, and the second is the section version.
    OtherSectionMerge(BTreeSet<PublicId>, u64),
    /// Acknowledge receipt of any message except an `Ack`. It contains the hash of the
    /// received message and the priority.
    Ack(Ack, u8),
    /// Part of a user-facing message
    UserMessagePart {
        /// The hash of this user message.
        hash: Digest256,
        /// The unique message ID of this user message.
        msg_id: MessageId,
        /// The number of parts.
        part_count: u32,
        /// The index of this part.
        part_index: u32,
        /// The message priority.
        priority: u8,
        /// Is the message cacheable?
        cacheable: bool,
        /// The `part_index`-th part of the serialised user message.
        payload: Vec<u8>,
    },
    /// Confirm with section that the candidate is about to resource prove.
    ///
    /// Sent from the `NaeManager` to the `NaeManager`.
    AcceptAsCandidate {
        /// The joining node's current public ID.
        old_public_id: PublicId,
        /// The joining node's current authority.
        old_client_auth: Authority<XorName>,
        /// The interval into which the joining node should join.
        target_interval: (XorName, XorName),
        /// The message's unique identifier.
        message_id: MessageId,
    },
    /// Sent among Group Y to vote to accept a joining node.
    CandidateApproval {
        /// The joining node's current public ID.
        new_public_id: PublicId,
        /// Client authority of the candidate.
        new_client_auth: Authority<XorName>,
        /// The `PublicId`s of all routing table contacts shared by the nodes in our section.
        sections: SectionMap,
    },
    /// Approves the joining node as a routing node.
    ///
    /// Sent from Group Y to the joining node.
    NodeApproval {
        /// The routing table shared by the nodes in our group, including the `PublicId`s of our
        /// contacts.
        sections: SectionMap,
    },
}

impl MessageContent {
    /// The priority Crust should send this message with.
    pub fn priority(&self) -> u8 {
        match *self {
            MessageContent::Ack(_, priority) |
            MessageContent::UserMessagePart { priority, .. } => priority,
            _ => 0,
        }
    }
}

impl Debug for DirectMessage {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        use self::DirectMessage::*;
        match *self {
            MessageSignature(ref digest, _) => {
                write!(
                    formatter,
                    "MessageSignature ({}, ..)",
                    utils::format_binary_array(&digest)
                )
            }
            SectionListSignature(ref sec_list, _) => {
                write!(formatter, "SectionListSignature({:?}, ..)", sec_list.prefix)
            }
            BootstrapRequest(_) => write!(formatter, "BootstrapRequest"),
            BootstrapResponse(ref result) => write!(formatter, "BootstrapResponse({:?})", result),
            CandidateInfo { .. } => write!(formatter, "CandidateInfo {{ .. }}"),
            TunnelRequest(pub_id) => write!(formatter, "TunnelRequest({:?})", pub_id),
            TunnelSuccess(pub_id) => write!(formatter, "TunnelSuccess({:?})", pub_id),
            TunnelSelect(pub_id) => write!(formatter, "TunnelSelect({:?})", pub_id),
            TunnelClosed(pub_id) => write!(formatter, "TunnelClosed({:?})", pub_id),
            TunnelDisconnect(pub_id) => write!(formatter, "TunnelDisconnect({:?})", pub_id),
            ResourceProof {
                ref seed,
                ref target_size,
                ref difficulty,
            } => {
                write!(
                    formatter,
                    "ResourceProof {{ seed: {:?}, target_size: {:?}, difficulty: {:?} }}",
                    seed,
                    target_size,
                    difficulty
                )
            }
            ResourceProofResponse {
                part_index,
                part_count,
                ref proof,
                leading_zero_bytes,
            } => {
                write!(
                    formatter,
                    "ResourceProofResponse {{ part {}/{}, proof_len: {:?}, leading_zero_bytes: \
                        {:?} }}",
                    part_index + 1,
                    part_count,
                    proof.len(),
                    leading_zero_bytes
                )
            }
            ResourceProofResponseReceipt => write!(formatter, "ResourceProofResponseReceipt"),
            ProxyRateLimitExceeded { ref ack } => {
                write!(formatter, "ProxyRateLimitExceeded({:?})", ack)
            }
        }
    }
}

impl Debug for HopMessage {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "HopMessage {{ content: {:?}, route: {}, sent_to: .., signature: .. }}",
            self.content,
            self.route
        )
    }
}

impl Debug for SignedMessage {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "SignedMessage {{ content: {:?}, sending nodes: {:?}, signatures: {:?} }}",
            self.content,
            self.src_sections,
            self.signatures.keys().collect_vec()
        )
    }
}

impl Debug for MessageContent {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        use self::MessageContent::*;
        match *self {
            Relocate { ref message_id } => write!(formatter, "Relocate {{ {:?} }}", message_id),
            ExpectCandidate {
                ref old_public_id,
                ref old_client_auth,
                ref message_id,
            } => {
                write!(
                    formatter,
                    "ExpectCandidate {{ {:?}, {:?}, {:?} }}",
                    old_public_id,
                    old_client_auth,
                    message_id
                )
            }
            ConnectionInfoRequest {
                ref pub_id,
                ref msg_id,
                ..
            } => {
                write!(
                    formatter,
                    "ConnectionInfoRequest {{ {:?}, {:?}, .. }}",
                    pub_id,
                    msg_id
                )
            }
            ConnectionInfoResponse {
                ref pub_id,
                ref msg_id,
                ..
            } => {
                write!(
                    formatter,
                    "ConnectionInfoResponse {{ {:?}, {:?}, .. }}",
                    pub_id,
                    msg_id
                )
            }
            RelocateResponse {
                ref target_interval,
                ref section,
                ref message_id,
            } => {
                write!(
                    formatter,
                    "RelocateResponse {{ {:?}, {:?}, {:?} }}",
                    target_interval,
                    section,
                    message_id
                )
            }
            SectionUpdate {
                ref versioned_prefix,
                ref members,
            } => {
                write!(
                    formatter,
                    "SectionUpdate {{ {:?}, {:?} }}",
                    versioned_prefix,
                    members
                )
            }
            SectionSplit(ref ver_pfx, ref joining_node) => {
                write!(formatter, "SectionSplit({:?}, {:?})", ver_pfx, joining_node)
            }
            OwnSectionMerge(ref sections) => write!(formatter, "OwnSectionMerge({:?})", sections),
            OtherSectionMerge(ref section, ref version) => {
                write!(formatter, "OtherSectionMerge({:?}, {:?})", section, version)
            }
            Ack(ack, priority) => write!(formatter, "Ack({:?}, {})", ack, priority),
            UserMessagePart {
                hash,
                part_count,
                part_index,
                priority,
                cacheable,
                ..
            } => {
                write!(
                    formatter,
                    "UserMessagePart {{ {}/{}, priority: {}, cacheable: {}, \
                        {:02x}{:02x}{:02x}.. }}",
                    part_index + 1,
                    part_count,
                    priority,
                    cacheable,
                    hash[0],
                    hash[1],
                    hash[2]
                )
            }
            AcceptAsCandidate {
                ref old_public_id,
                ref old_client_auth,
                ref target_interval,
                ref message_id,
            } => {
                write!(
                    formatter,
                    "AcceptAsCandidate {{ {:?}, {:?}, {:?}, {:?} }}",
                    old_public_id,
                    old_client_auth,
                    target_interval,
                    message_id
                )
            }
            CandidateApproval {
                ref new_public_id,
                ref new_client_auth,
                ref sections,
            } => {
                write!(
                    formatter,
                    "CandidateApproval {{ new: {:?}, client: {:?}, sections: {:?} }}",
                    new_public_id,
                    new_client_auth,
                    sections
                )
            }
            NodeApproval { ref sections } => write!(formatter, "NodeApproval {{ {:?} }}", sections),
        }
    }
}

#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Debug, Hash, Serialize, Deserialize)]
/// A user-visible message: a `Request` or `Response`.
pub enum UserMessage {
    /// A user-visible request message.
    Request(Request),
    /// A user-visible response message.
    Response(Response),
}

impl UserMessage {
    /// Splits up the message into smaller `MessageContent` parts, which can individually be sent
    /// and routed, and then be put back together by the receiver.
    pub fn to_parts(&self, priority: u8) -> Result<Vec<MessageContent>, RoutingError> {
        let payload = serialise(self)?;
        let hash = sha3_256(&payload);
        let msg_id = *self.message_id();
        let len = payload.len();
        let part_count = (len + MAX_PART_LEN - 1) / MAX_PART_LEN;

        Ok(
            (0..part_count)
                .map(|i| {
                    MessageContent::UserMessagePart {
                        hash,
                        msg_id,
                        part_count: part_count as u32,
                        part_index: i as u32,
                        cacheable: self.is_cacheable(),
                        payload: payload[(i * len / part_count)..((i + 1) * len / part_count)]
                            .to_vec(),
                        priority,
                    }
                })
                .collect(),
        )
    }

    /// Puts the given parts of a serialised message together and verifies that it matches the
    /// given hash code. If it does, returns the `UserMessage`.
    pub fn from_parts<'a, I: Iterator<Item = &'a Vec<u8>>>(
        hash: Digest256,
        parts: I,
    ) -> Result<UserMessage, RoutingError> {
        let mut payload = Vec::new();
        for part in parts {
            payload.extend_from_slice(part);
        }
        let user_msg = deserialise(&payload[..])?;
        if hash != sha3_256(&payload) {
            Err(RoutingError::HashMismatch)
        } else {
            Ok(user_msg)
        }
    }

    /// Returns an event indicating that this message was received with the given source and
    /// destination authorities.
    pub fn into_event(self, src: Authority<XorName>, dst: Authority<XorName>) -> Event {
        match self {
            UserMessage::Request(request) => {
                Event::Request {
                    request: request,
                    src: src,
                    dst: dst,
                }
            }
            UserMessage::Response(response) => {
                Event::Response {
                    response: response,
                    src: src,
                    dst: dst,
                }
            }
        }
    }

    /// The unique message ID of this `UserMessage`.
    pub fn message_id(&self) -> &MessageId {
        match *self {
            UserMessage::Request(ref request) => request.message_id(),
            UserMessage::Response(ref response) => response.message_id(),
        }
    }

    fn is_cacheable(&self) -> bool {
        match *self {
            UserMessage::Request(ref request) => request.is_cacheable(),
            UserMessage::Response(ref response) => response.is_cacheable(),
        }
    }
}

/// This assembles `UserMessage`s from `UserMessagePart`s.
/// It maps `(hash, part_count)` of an incoming `UserMessage` to the map containing
/// all `UserMessagePart`s that have already arrived, by `part_index`.
pub struct UserMessageCache(LruCache<(Digest256, u32), BTreeMap<u32, Vec<u8>>>);

impl UserMessageCache {
    pub fn with_expiry_duration(duration: Duration) -> Self {
        UserMessageCache(LruCache::with_expiry_duration(duration))
    }

    /// Adds the given one to the cache of received message parts, returning a `UserMessage` if the
    /// given part was the last missing piece of it.
    pub fn add(
        &mut self,
        hash: Digest256,
        part_count: u32,
        part_index: u32,
        payload: Vec<u8>,
    ) -> Option<UserMessage> {
        {
            let entry = self.0.entry((hash, part_count)).or_insert_with(
                BTreeMap::new,
            );
            if entry.insert(part_index, payload).is_some() {
                debug!(
                    "Duplicate UserMessagePart {}/{} with hash {:02x}{:02x}{:02x}.. \
                        added to cache.",
                    part_index + 1,
                    part_count,
                    hash[0],
                    hash[1],
                    hash[2]
                );
            }

            if entry.len() != part_count as usize {
                return None;
            }
        }

        self.0.remove(&(hash, part_count)).and_then(|part_map| {
            UserMessage::from_parts(hash, part_map.values()).ok()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use data::ImmutableData;
    use id::FullId;
    use maidsafe_utilities::serialisation::serialise;
    use rand;
    use routing_table::{Authority, Prefix};
    use rust_sodium::crypto::sign;
    use std::collections::BTreeSet;
    use std::iter;
    use tiny_keccak::sha3_256;
    use types::MessageId;
    use xor_name::XorName;

    #[test]
    fn signed_message_check_integrity() {
        let min_section_size = 1000;
        let name: XorName = rand::random();
        let full_id = FullId::new();
        let routing_message = RoutingMessage {
            src: Authority::Client {
                client_id: *full_id.public_id(),
                proxy_node_name: name,
            },
            dst: Authority::ClientManager(name),
            content: MessageContent::SectionSplit(Prefix::new(0, name).with_version(0), name),
        };
        let senders = iter::empty().collect();
        let signed_message_result = SignedMessage::new(routing_message.clone(), &full_id, senders);

        let mut signed_message = unwrap!(signed_message_result);

        assert_eq!(routing_message, *signed_message.routing_message());
        assert_eq!(1, signed_message.signatures.len());
        assert_eq!(
            Some(full_id.public_id()),
            signed_message.signatures.keys().next()
        );

        unwrap!(signed_message.check_integrity(min_section_size));

        let full_id = FullId::new();
        let bytes_to_sign = unwrap!(serialise(&(&routing_message, full_id.public_id())));
        let signature = sign::sign_detached(&bytes_to_sign, full_id.signing_private_key());

        signed_message.signatures = iter::once((*full_id.public_id(), signature)).collect();

        // Invalid because it's not signed by the sender:
        assert!(signed_message.check_integrity(min_section_size).is_err());
        // However, the signature itself should be valid:
        assert!(signed_message.has_enough_sigs(min_section_size));
    }

    #[test]
    fn msg_signatures() {
        let min_section_size = 8;

        let full_id_0 = FullId::new();
        let prefix = Prefix::new(0, *full_id_0.public_id().name());
        let full_id_1 = FullId::new();
        let full_id_2 = FullId::new();
        let irrelevant_full_id = FullId::new();
        let data_bytes: Vec<u8> = (0..10).map(|i| i as u8).collect();
        let data = ImmutableData::new(data_bytes);
        let user_msg = UserMessage::Request(Request::PutIData {
            data: data,
            msg_id: MessageId::new(),
        });
        let parts = unwrap!(user_msg.to_parts(1));
        assert_eq!(1, parts.len());
        let part = parts[0].clone();
        let name: XorName = rand::random();
        let routing_message = RoutingMessage {
            src: Authority::ClientManager(name),
            dst: Authority::ClientManager(name),
            content: part,
        };

        let src_sections = vec![
            SectionList::from(
                prefix,
                vec![
                    *full_id_0.public_id(),
                    *full_id_1.public_id(),
                    *full_id_2.public_id(),
                ]
            ),
        ];
        let mut signed_msg = unwrap!(SignedMessage::new(
            routing_message,
            &full_id_0,
            src_sections,
        ));
        assert_eq!(signed_msg.signatures.len(), 1);

        // Try to add a signature which will not correspond to an ID from the sending nodes.
        let irrelevant_sig = match unwrap!(signed_msg.routing_message().to_signature(
            irrelevant_full_id.signing_private_key(),
        )) {
            DirectMessage::MessageSignature(_, sig) => {
                signed_msg.add_signature(*irrelevant_full_id.public_id(), sig);
                sig
            }
            msg => panic!("Unexpected message: {:?}", msg),
        };
        assert_eq!(signed_msg.signatures.len(), 1);
        assert!(!signed_msg.signatures.contains_key(
            irrelevant_full_id.public_id(),
        ));
        assert!(!signed_msg.check_fully_signed(min_section_size));

        // Add a valid signature for ID 1 and an invalid one for ID 2
        match unwrap!(signed_msg.routing_message().to_signature(
            full_id_1.signing_private_key(),
        )) {
            DirectMessage::MessageSignature(hash, sig) => {
                let serialised_msg = unwrap!(serialise(signed_msg.routing_message()));
                assert_eq!(hash, sha3_256(&serialised_msg));
                signed_msg.add_signature(*full_id_1.public_id(), sig);
            }
            msg => panic!("Unexpected message: {:?}", msg),
        }
        let bad_sig = sign::Signature([0; sign::SIGNATUREBYTES]);
        signed_msg.add_signature(*full_id_2.public_id(), bad_sig);
        assert_eq!(signed_msg.signatures.len(), 3);
        assert!(signed_msg.check_fully_signed(min_section_size));

        // Check the bad signature got removed (by check_fully_signed) properly.
        assert_eq!(signed_msg.signatures.len(), 2);
        assert!(!signed_msg.signatures.contains_key(full_id_2.public_id()));

        // Check an irrelevant signature can't be added.
        signed_msg.add_signature(*irrelevant_full_id.public_id(), irrelevant_sig);
        assert_eq!(signed_msg.signatures.len(), 2);
        assert!(!signed_msg.signatures.contains_key(
            irrelevant_full_id.public_id(),
        ));
    }

    #[test]
    fn hop_message_verify() {
        let name: XorName = rand::random();
        let routing_message = RoutingMessage {
            src: Authority::ClientManager(name),
            dst: Authority::ClientManager(name),
            content: MessageContent::SectionSplit(Prefix::new(0, name).with_version(1), name),
        };
        let full_id = FullId::new();
        let senders = iter::empty().collect();
        let signed_message_result = SignedMessage::new(routing_message.clone(), &full_id, senders);
        let signed_message = unwrap!(signed_message_result);

        let (public_signing_key, secret_signing_key) = sign::gen_keypair();
        let hop_message_result = HopMessage::new(
            signed_message.clone(),
            0,
            BTreeSet::new(),
            &secret_signing_key,
        );

        let hop_message = unwrap!(hop_message_result);

        assert_eq!(signed_message, hop_message.content);

        assert!(hop_message.verify(&public_signing_key).is_ok());

        let (public_signing_key, _) = sign::gen_keypair();
        assert!(hop_message.verify(&public_signing_key).is_err());
    }

    #[test]
    fn user_message_parts() {
        let data_bytes: Vec<u8> = (0..(MAX_PART_LEN * 2)).map(|i| i as u8).collect();
        let data = ImmutableData::new(data_bytes);
        let user_msg = UserMessage::Request(Request::PutIData {
            data: data,
            msg_id: MessageId::new(),
        });
        let msg_hash = sha3_256(&unwrap!(serialise(&user_msg)));
        let parts = unwrap!(user_msg.to_parts(42));
        assert_eq!(parts.len(), 3);
        let payloads: Vec<Vec<u8>> = parts
            .into_iter()
            .enumerate()
            .map(|(i, msg)| match msg {
                MessageContent::UserMessagePart {
                    hash,
                    msg_id,
                    part_count,
                    part_index,
                    payload,
                    priority,
                    cacheable,
                } => {
                    assert_eq!(msg_hash, hash);
                    assert_eq!(user_msg.message_id(), &msg_id);
                    assert_eq!(3, part_count);
                    assert_eq!(i, part_index as usize);
                    assert_eq!(42, priority);
                    assert!(!cacheable);
                    payload
                }
                msg => panic!("Unexpected message {:?}", msg),
            })
            .collect();
        let deserialised_user_msg = unwrap!(UserMessage::from_parts(msg_hash, payloads.iter()));
        assert_eq!(user_msg, deserialised_user_msg);
    }
}
