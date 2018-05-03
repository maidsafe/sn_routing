// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod request;
mod response;

pub use self::request::Request;
pub use self::response::{AccountInfo, Response};
use super::{QUORUM_DENOMINATOR, QUORUM_NUMERATOR};
use ack_manager::Ack;
use data::MAX_IMMUTABLE_DATA_SIZE_IN_BYTES;
use error::{BootstrapResponseError, RoutingError};
use event::Event;
use full_info::FullInfo;
use itertools::Itertools;
use lru_time_cache::LruCache;
use maidsafe_utilities::serialisation::{deserialise, serialise};
use peer_manager::SectionMap;
use public_info::PublicInfo;
use routing_table::Authority;
use routing_table::Prefix;
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
pub const MAX_PARTS: u32 = (MAX_IMMUTABLE_DATA_SIZE_IN_BYTES / MAX_PART_LEN as u64 + 1) as u32;

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
        src: PublicInfo,
        /// The receiver
        dst: PublicInfo,
    },
    /// A hop message sent via a tunnel because the nodes could not connect directly
    TunnelHop {
        /// The wrapped message
        content: HopMessage,
        /// The sender
        src: PublicInfo,
        /// The receiver
        dst: PublicInfo,
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
        /// `PublicInfo` from before relocation.
        old_public_info: PublicInfo,
        /// `PublicInfo` from after relocation.
        new_public_info: PublicInfo,
        /// Signature of concatenated `PublicInfo`s using the pre-relocation key.
        signature_using_old: sign::Signature,
        /// Signature of concatenated `PublicInfo`s and `signature_using_old` using the
        /// post-relocation key.
        signature_using_new: sign::Signature,
        /// Client authority from after relocation.
        new_client_auth: Authority,
    },
    /// Sent from a node that needs a tunnel to be able to connect to the given node.
    TunnelRequest(PublicInfo),
    /// Sent as a response to `TunnelRequest` if the node can act as a tunnel.
    TunnelSuccess(PublicInfo),
    /// Sent as a response to `TunnelSuccess` if the node is selected to act as a tunnel.
    TunnelSelect(PublicInfo),
    /// Sent from a tunnel node to indicate that the given node has disconnected.
    TunnelClosed(PublicInfo),
    /// Sent to a tunnel node to indicate the tunnel is not needed any more.
    TunnelDisconnect(PublicInfo),
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
    /// Route number; corresponds to the index of the node in the section of target nodes being
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
    prefix: Prefix,
    // TODO(MAID-1677): pub signatures: BTreeSet<(PublicInfo, sign::Signature)>,
    pub_infos: BTreeSet<PublicInfo>,
}

impl SectionList {
    /// Create
    pub fn new(prefix: Prefix, pub_infos: BTreeSet<PublicInfo>) -> Self {
        SectionList {
            prefix: prefix.with_version(0),
            pub_infos,
        }
    }

    /// Create from any object convertable to an iterator
    pub fn from<I: IntoIterator<Item = PublicInfo>>(prefix: Prefix, pub_infos: I) -> Self {
        Self::new(prefix, pub_infos.into_iter().collect())
    }

    /// Returns the section prefix
    pub fn prefix(&self) -> &Prefix {
        &self.prefix
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
    signatures: BTreeMap<PublicInfo, sign::Signature>,
}

impl SignedMessage {
    /// Creates a `SignedMessage` with the given `content` and signed by the given `full_info`.
    ///
    /// Requires the list `src_sections` of nodes who should sign this message.
    pub fn new(
        content: RoutingMessage,
        full_info: &FullInfo,
        mut src_sections: Vec<SectionList>,
    ) -> Result<SignedMessage, RoutingError> {
        src_sections.sort_by_key(|list| list.prefix);
        let sig = sign::sign_detached(&serialise(&content)?, full_info.secret_sign_key());
        Ok(SignedMessage {
            content: content,
            src_sections: src_sections,
            signatures: iter::once((*full_info.public_info(), sig)).collect(),
        })
    }

    /// Confirms the signatures.
    // TODO (MAID-1677): verify the sending SectionLists via each hop's signed lists
    pub fn check_integrity(&self, group_size: usize) -> Result<(), RoutingError> {
        let signed_bytes = serialise(&self.content)?;
        if !self.find_invalid_sigs(&signed_bytes).is_empty() {
            return Err(RoutingError::FailedSignature);
        }
        if !self.has_enough_sigs(group_size) {
            return Err(RoutingError::NotEnoughSignatures);
        }
        Ok(())
    }

    /// Returns whether the message is signed by the given public ID.
    pub fn signed_by(&self, pub_info: &PublicInfo) -> bool {
        self.signatures.contains_key(pub_info)
    }

    /// Returns the number of nodes in the source authority.
    pub fn src_size(&self) -> usize {
        self.src_sections.iter().map(|sl| sl.pub_infos.len()).sum()
    }

    /// Adds the given signature if it is new, without validating it. If the collection of section
    /// lists isn't empty, the signature is only added if `pub_info` is a member of the first
    /// section list.
    pub fn add_signature(&mut self, pub_info: PublicInfo, sig: sign::Signature) {
        if self.content.src.is_multiple() && self.is_sender(&pub_info) {
            let _ = self.signatures.insert(pub_info, sig);
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
    pub fn check_fully_signed(&mut self, group_size: usize) -> bool {
        if !self.has_enough_sigs(group_size) {
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
        for invalid_signature in &self.find_invalid_sigs(&signed_bytes) {
            let _ = self.signatures.remove(invalid_signature);
        }

        self.has_enough_sigs(group_size)
    }

    // Returns true iff `pub_info` is in self.section_lists
    fn is_sender(&self, pub_info: &PublicInfo) -> bool {
        self.src_sections.iter().any(|list| {
            list.pub_infos.contains(pub_info)
        })
    }

    // Returns a list of all invalid signatures (not from an expected key or not cryptographically
    // valid).
    fn find_invalid_sigs(&self, signed_bytes: &[u8]) -> Vec<PublicInfo> {
        let invalid = self.signatures
            .iter()
            .filter_map(|(pub_info, sig)| {
                // Remove if not in sending nodes or signature is invalid:
                let is_valid =
                    if let Authority::Client { ref client_info, .. } = self.content.src {
                        client_info == pub_info &&
                            sign::verify_detached(sig, signed_bytes, client_info.sign_key())
                    } else {
                        self.is_sender(pub_info) &&
                            sign::verify_detached(sig, signed_bytes, pub_info.sign_key())
                    };
                if is_valid { None } else { Some(*pub_info) }
            })
            .collect_vec();
        if !invalid.is_empty() {
            debug!("{:?}: invalid signatures: {:?}", self, invalid);
        }
        invalid
    }

    // Returns true if there are enough signatures (note that this method does not verify the
    // signatures, it only counts them; it also does not verify `self.src_sections`).
    fn has_enough_sigs(&self, group_size: usize) -> bool {
        use Authority::*;
        match self.content.src {
            ClientManager(_) | NaeManager(_) | NodeManager(_) => {
                // Note: there should be exactly one source section, but we use safe code:
                let valid_names: HashSet<_> = self.src_sections
                    .iter()
                    .flat_map(|list| list.pub_infos.iter().map(PublicInfo::name))
                    .sorted_by(|lhs, rhs| self.content.src.name().cmp_distance(lhs, rhs))
                    .into_iter()
                    .take(group_size)
                    .collect();
                let valid_sigs = self.signatures
                    .keys()
                    .filter(|pub_info| valid_names.contains(&pub_info.name()))
                    .count();
                // TODO: we should consider replacing valid_names.len() with
                // cmp::min(routing_table.len(), group_size)
                // (or just group_size, but in that case we will not be able to handle user
                // messages during boot-up).
                valid_sigs * QUORUM_DENOMINATOR > valid_names.len() * QUORUM_NUMERATOR
            }
            Section(_) => {
                // Note: there should be exactly one source section, but we use safe code:
                let num_sending = self.src_sections.iter().fold(0, |count, list| {
                    count + list.pub_infos.len()
                });
                let valid_sigs = self.signatures.len();
                valid_sigs * QUORUM_DENOMINATOR > num_sending * QUORUM_NUMERATOR
            }
            PrefixSection(_) => {
                // Each section must have enough signatures:
                self.src_sections.iter().all(|list| {
                    let valid_sigs = self.signatures
                        .keys()
                        .filter(|pub_info| list.pub_infos.contains(pub_info))
                        .count();
                    valid_sigs * QUORUM_DENOMINATOR > list.pub_infos.len() * QUORUM_NUMERATOR
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
    pub src: Authority,
    /// Destination authority
    pub dst: Authority,
    /// The message content
    pub content: MessageContent,
}

impl RoutingMessage {
    /// Create ack for the given message
    pub fn ack_from(msg: &RoutingMessage, src: Authority) -> Result<Self, RoutingError> {
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
/// i. e. change its name to a value chosen by the network, and then add its nodes to its routing
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
/// completion, A is regarded as a full node and connects to all neighbouring sections' nodes.
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
        old_public_info: PublicInfo,
        /// The joining node's current authority.
        old_client_auth: Authority,
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
        pub_info: PublicInfo,
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
        /// The sender's public info.
        pub_info: PublicInfo,
        /// The message's unique identifier.
        msg_id: MessageId,
    },
    /// Reply with the address range into which the joining node should move.
    RelocateResponse {
        /// The interval into which the joining node should join.
        target_interval: (XorName, XorName),
        /// The section that the joining node shall connect to.
        section: (Prefix, BTreeSet<PublicInfo>),
        /// The message's unique identifier.
        message_id: MessageId,
    },
    /// Sent to notify neighbours and own members when our section's member list changed (for now,
    /// only when new nodes join).
    SectionUpdate {
        /// Section prefix. Included because this message is sent to both the section's
        /// own members and neighbouring sections.
        prefix: Prefix,
        /// Members of the section
        members: BTreeSet<PublicInfo>,
    },
    /// Sent to all connected nodes when our own section splits
    SectionSplit(Prefix, XorName),
    /// Sent amongst members of a newly-merged section to allow synchronisation of their routing
    /// tables before notifying other connected nodes of the merge.
    ///
    /// The source and destination authorities are both `PrefixSection` types, conveying the
    /// section sending this merge message and the target prefix of the merge respectively.
    OwnSectionMerge(SectionMap),
    /// Sent by members of a newly-merged section to nodes outwith the merged section to notify them
    /// of the merge.
    ///
    /// The source authority is a `PrefixSection` conveying the section which just merged. The
    /// first field is the set of members of the section, and the second is the section version.
    OtherSectionMerge(BTreeSet<PublicInfo>, u64),
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
        old_public_info: PublicInfo,
        /// The joining node's current authority.
        old_client_auth: Authority,
        /// The interval into which the joining node should join.
        target_interval: (XorName, XorName),
        /// The message's unique identifier.
        message_id: MessageId,
    },
    /// Sent among Group Y to vote to accept a joining node.
    CandidateApproval {
        /// The joining node's current public ID.
        new_public_info: PublicInfo,
        /// Client authority of the candidate.
        new_client_auth: Authority,
        /// The `PublicInfo`s of all routing table contacts shared by the nodes in our section.
        sections: SectionMap,
    },
    /// Approves the joining node as a routing node.
    ///
    /// Sent from Group Y to the joining node.
    NodeApproval {
        /// The routing table shared by the nodes in our group, including the `PublicInfo`s of our
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
            TunnelRequest(pub_info) => write!(formatter, "TunnelRequest({:?})", pub_info),
            TunnelSuccess(pub_info) => write!(formatter, "TunnelSuccess({:?})", pub_info),
            TunnelSelect(pub_info) => write!(formatter, "TunnelSelect({:?})", pub_info),
            TunnelClosed(pub_info) => write!(formatter, "TunnelClosed({:?})", pub_info),
            TunnelDisconnect(pub_info) => write!(formatter, "TunnelDisconnect({:?})", pub_info),
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
                ref old_public_info,
                ref old_client_auth,
                ref message_id,
            } => {
                write!(
                    formatter,
                    "ExpectCandidate {{ {:?}, {:?}, {:?} }}",
                    old_public_info,
                    old_client_auth,
                    message_id
                )
            }
            ConnectionInfoRequest {
                ref pub_info,
                ref msg_id,
                ..
            } => {
                write!(
                    formatter,
                    "ConnectionInfoRequest {{ {:?}, {:?}, .. }}",
                    pub_info,
                    msg_id
                )
            }
            ConnectionInfoResponse {
                ref pub_info,
                ref msg_id,
                ..
            } => {
                write!(
                    formatter,
                    "ConnectionInfoResponse {{ {:?}, {:?}, .. }}",
                    pub_info,
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
                ref prefix,
                ref members,
            } => write!(formatter, "SectionUpdate {{ {:?}, {:?} }}", prefix, members),
            SectionSplit(ref prefix, ref joining_node) => {
                write!(formatter, "SectionSplit({:?}, {:?})", prefix, joining_node)
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
                ref old_public_info,
                ref old_client_auth,
                ref target_interval,
                ref message_id,
            } => {
                write!(
                    formatter,
                    "AcceptAsCandidate {{ {:?}, {:?}, {:?}, {:?} }}",
                    old_public_info,
                    old_client_auth,
                    target_interval,
                    message_id
                )
            }
            CandidateApproval {
                ref new_public_info,
                ref new_client_auth,
                ref sections,
            } => {
                write!(
                    formatter,
                    "CandidateApproval {{ new: {:?}, client: {:?}, sections: {:?} }}",
                    new_public_info,
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
    pub fn into_event(self, src: Authority, dst: Authority) -> Event {
        match self {
            UserMessage::Request(request) => Event::Request {
                request: request,
                src: src,
                dst: dst,
            },
            UserMessage::Response(response) => Event::Response {
                response: response,
                src: src,
                dst: dst,
            },
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

            if entry.len() as u32 != part_count {
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
    use full_info::FullInfo;
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
        let group_size = 1000;
        let name: XorName = rand::random();
        let full_info = FullInfo::node_new(1u8);
        let routing_message = RoutingMessage {
            src: Authority::Client {
                client_info: *full_info.public_info(),
                proxy_node_name: name,
            },
            dst: Authority::ClientManager(name),
            content: MessageContent::SectionSplit(Prefix::new(0, name, 0), name),
        };
        let senders = iter::empty().collect();
        let signed_message_result =
            SignedMessage::new(routing_message.clone(), &full_info, senders);

        let mut signed_message = unwrap!(signed_message_result);

        assert_eq!(routing_message, *signed_message.routing_message());
        assert_eq!(1, signed_message.signatures.len());
        assert_eq!(
            Some(full_info.public_info()),
            signed_message.signatures.keys().next()
        );

        unwrap!(signed_message.check_integrity(group_size));

        let full_info = FullInfo::node_new(1u8);
        let bytes_to_sign = unwrap!(serialise(&(&routing_message, full_info.public_info())));
        let signature = sign::sign_detached(&bytes_to_sign, full_info.secret_sign_key());

        signed_message.signatures = iter::once((*full_info.public_info(), signature)).collect();

        // Invalid because it's not signed by the sender:
        assert!(signed_message.check_integrity(group_size).is_err());
        // However, the signature itself should be valid:
        assert!(signed_message.has_enough_sigs(group_size));
    }

    #[test]
    fn msg_signatures() {
        let group_size = 8;

        let full_info_0 = FullInfo::node_new(1u8);
        let prefix = Prefix::new(0, full_info_0.public_info().name(), 0);
        let full_info_1 = FullInfo::node_new(1u8);
        let full_info_2 = FullInfo::node_new(1u8);
        let irrelevant_full_info = FullInfo::node_new(1u8);
        let data_bytes: Vec<u8> = (0..10).collect();
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
                    *full_info_0.public_info(),
                    *full_info_1.public_info(),
                    *full_info_2.public_info(),
                ]
            ),
        ];
        let mut signed_msg = unwrap!(SignedMessage::new(
            routing_message,
            &full_info_0,
            src_sections,
        ));
        assert_eq!(signed_msg.signatures.len(), 1);

        // Try to add a signature which will not correspond to an ID from the sending nodes.
        let irrelevant_sig = match unwrap!(signed_msg.routing_message().to_signature(
            irrelevant_full_info.secret_sign_key(),
        )) {
            DirectMessage::MessageSignature(_, sig) => {
                signed_msg.add_signature(*irrelevant_full_info.public_info(), sig);
                sig
            }
            msg => panic!("Unexpected message: {:?}", msg),
        };
        assert_eq!(signed_msg.signatures.len(), 1);
        assert!(!signed_msg.signatures.contains_key(
            irrelevant_full_info.public_info(),
        ));
        assert!(!signed_msg.check_fully_signed(group_size));

        // Add a valid signature for ID 1 and an invalid one for ID 2
        match unwrap!(signed_msg.routing_message().to_signature(
            full_info_1.secret_sign_key(),
        )) {
            DirectMessage::MessageSignature(hash, sig) => {
                let serialised_msg = unwrap!(serialise(signed_msg.routing_message()));
                assert_eq!(hash, sha3_256(&serialised_msg));
                signed_msg.add_signature(*full_info_1.public_info(), sig);
            }
            msg => panic!("Unexpected message: {:?}", msg),
        }
        let bad_sig = sign::Signature([0; sign::SIGNATUREBYTES]);
        signed_msg.add_signature(*full_info_2.public_info(), bad_sig);
        assert_eq!(signed_msg.signatures.len(), 3);
        assert!(signed_msg.check_fully_signed(group_size));

        // Check the bad signature got removed (by check_fully_signed) properly.
        assert_eq!(signed_msg.signatures.len(), 2);
        assert!(!signed_msg.signatures.contains_key(
            full_info_2.public_info(),
        ));

        // Check an irrelevant signature can't be added.
        signed_msg.add_signature(*irrelevant_full_info.public_info(), irrelevant_sig);
        assert_eq!(signed_msg.signatures.len(), 2);
        assert!(!signed_msg.signatures.contains_key(
            irrelevant_full_info.public_info(),
        ));
    }

    #[test]
    fn hop_message_verify() {
        let name: XorName = rand::random();
        let routing_message = RoutingMessage {
            src: Authority::ClientManager(name),
            dst: Authority::ClientManager(name),
            content: MessageContent::SectionSplit(Prefix::new(0, name, 1), name),
        };
        let full_info = FullInfo::node_new(1u8);
        let senders = iter::empty().collect();
        let signed_message_result =
            SignedMessage::new(routing_message.clone(), &full_info, senders);
        let signed_message = unwrap!(signed_message_result);

        let (public_signing_key, secret_sign_key) = sign::gen_keypair();
        let hop_message_result =
            HopMessage::new(signed_message.clone(), 0, BTreeSet::new(), &secret_sign_key);

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
