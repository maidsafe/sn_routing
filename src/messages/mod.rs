// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod direct;
mod request;
mod response;

pub use self::{
    direct::{DirectMessage, SignedDirectMessage},
    request::Request,
    response::{AccountInfo, Response},
};
use super::{QUORUM_DENOMINATOR, QUORUM_NUMERATOR};
use crate::{
    chain::{GenesisPfxInfo, Proof, ProofSet, ProvingSection, SectionInfo},
    error::{Result, RoutingError},
    event::Event,
    id::{FullId, PublicId},
    routing_table::{Authority, Prefix},
    sha3::Digest256,
    types::MessageId,
    xor_name::XorName,
    XorTargetInterval,
};
use hex_fmt::HexFmt;
use itertools::Itertools;
use maidsafe_utilities::serialisation::serialise;
use safe_crypto::{self, SecretSignKey, Signature};
use std::{
    collections::BTreeSet,
    fmt::{self, Debug, Display, Formatter},
};

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
#[cfg_attr(feature = "mock_serialise", derive(Clone))]
#[derive(Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
// FIXME - See https://maidsafe.atlassian.net/browse/MAID-2026 for info on removing this exclusion.
#[allow(clippy::large_enum_variant)]
pub enum Message {
    /// A message sent between two nodes directly
    Direct(SignedDirectMessage),
    /// A message sent across the network (in transit)
    Hop(HopMessage),
}

/// An individual hop message that represents a part of the route of a message in transit.
///
/// To relay a `SignedMessage` via another node, the `SignedMessage` is wrapped in a `HopMessage`.
/// The `signature` is from the node that sends this directly to a node in its routing table. To
/// prevent Man-in-the-middle attacks, the `content` is signed by the original sender.
#[cfg_attr(feature = "mock_serialise", derive(Clone))]
#[derive(Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct HopMessage {
    /// Wrapped signed message.
    pub content: SignedRoutingMessage,
}

impl HopMessage {
    /// Wrap `content` for transmission to the next hop and sign it.
    pub fn new(content: SignedRoutingMessage) -> Result<HopMessage> {
        Ok(HopMessage { content: content })
    }
}

/// Wrapper around a routing message, signed by the originator of the message.
#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Hash, Serialize, Deserialize)]
pub struct SignedRoutingMessage {
    /// A request or response type message.
    content: RoutingMessage,
    /// Nodes sending the message (those expected to sign it)
    src_section: Option<SectionInfo>,
    /// The IDs and signatures of the source authority's members.
    signatures: ProofSet,
    /// The lists of the sections involved in routing this message, in chronological order.
    /// Each entry proves the authenticity of the previous one. The last one should be known by the
    /// receiver, while the first one proves the `src_section` itself.
    proving_sections: Vec<ProvingSection>,
}

impl SignedRoutingMessage {
    /// Creates a `SignedMessage` with the given `content` and signed by the given `full_id`.
    ///
    /// Requires the list `src_section` of nodes who should sign this message.
    #[allow(clippy::new_ret_no_self)]
    pub fn new<T: Into<Option<SectionInfo>>>(
        content: RoutingMessage,
        full_id: &FullId,
        src_section: T,
    ) -> Result<SignedRoutingMessage> {
        let sk = full_id.signing_private_key();
        let mut signatures = ProofSet::new();
        let _ = signatures.add_proof(Proof::new(*full_id.public_id(), sk, &content)?);
        Ok(SignedRoutingMessage {
            content,
            src_section: src_section.into(),
            signatures,
            proving_sections: Vec::new(),
        })
    }

    /// Confirms the signatures.
    pub fn check_integrity(&self) -> Result<()> {
        let signed_bytes = serialise(&self.content)?;
        if !self.find_invalid_sigs(signed_bytes).is_empty() {
            return Err(RoutingError::FailedSignature);
        }
        if !self.has_enough_sigs() {
            return Err(RoutingError::NotEnoughSignatures);
        }

        // TODO: What needs to be checked if these are `None`?
        if let (&Some(ref src_sec), Some(ref proving_sec)) =
            (&self.src_section, self.proving_sections.first())
        {
            if !proving_sec.validate(src_sec) {
                return Err(RoutingError::InvalidProvingSection);
            }
        }
        for (ps0, ps1) in self.proving_sections.iter().tuple_windows() {
            if !ps1.validate(&ps0.sec_info) {
                return Err(RoutingError::InvalidProvingSection);
            }
        }
        Ok(())
    }

    /// Returns the previous hop: if that hop can be trusted, the message can be trusted, too.
    pub fn previous_hop(&self) -> Option<&SectionInfo> {
        self.proving_sections
            .last()
            .map(|ps| &ps.sec_info)
            .or_else(|| self.src_section.as_ref())
    }

    /// Removes the last hop section from the message. Returns `true` if a hop was removed, and
    /// `false` if there are no more hops left other than the sending section itself.
    pub fn pop_previous_hop(&mut self) -> bool {
        self.proving_sections.pop().is_some()
    }

    /// Appends the proving sections to this message.
    pub fn extend_proving_sections<I>(&mut self, proving_sections: I)
    where
        I: IntoIterator<Item = ProvingSection>,
    {
        self.proving_sections.extend(proving_sections);
    }

    /// Returns the list of section infos from this message's proof chain.
    pub fn section_infos(&self) -> impl Iterator<Item = &SectionInfo> {
        self.src_section
            .iter()
            .chain(self.proving_sections.iter().map(|ps| &ps.sec_info))
    }

    /// Returns the chain of proving sections, from the recipient back to the one proving the
    /// sending section.
    pub fn proving_sections(&self) -> &Vec<ProvingSection> {
        &self.proving_sections
    }

    /// Returns the source section that signed the message itself.
    pub fn source_section(&self) -> Option<&SectionInfo> {
        self.src_section.as_ref()
    }

    /// Returns whether the message is signed by the given public ID.
    #[cfg(test)]
    pub fn signed_by(&self, pub_id: &PublicId) -> bool {
        self.signatures.contains_id(pub_id)
    }

    /// Returns the number of nodes in the source authority.
    pub fn src_size(&self) -> usize {
        self.src_section.as_ref().map_or(0, |si| si.members().len())
    }

    /// Adds a proof if it is new, without validating it.
    pub fn add_proof(&mut self, proof: Proof) {
        if self.content.src.is_multiple() && self.is_sender(proof.pub_id()) {
            let _ = self.signatures.add_proof(proof);
        }
    }

    /// Adds the given signature if it is new, without validating it. If the collection of section
    /// lists isn't empty, the signature is only added if `pub_id` is a member of the first section
    /// list.
    #[cfg(test)]
    pub fn add_signature(&mut self, pub_id: PublicId, sig: Signature) {
        if self.content.src.is_multiple() && self.is_sender(&pub_id) {
            let _ = self.signatures.sigs.insert(pub_id, sig);
        }
    }

    /// Adds all signatures from the given message, without validating them.
    pub fn add_signatures(&mut self, msg: SignedRoutingMessage) {
        if self.content.src.is_multiple() {
            self.signatures.merge(msg.signatures);
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
    pub fn check_fully_signed(&mut self) -> bool {
        if !self.has_enough_sigs() {
            return false;
        }

        // Remove invalid signatures, then check again that we have enough.
        // We also check (again) that all messages are from valid senders, because the message
        // may have been sent from another node, and we cannot trust that that node correctly
        // controlled which signatures were added.
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

        self.has_enough_sigs()
    }

    // Returns true iff `pub_id` is in self.section_lists
    fn is_sender(&self, pub_id: &PublicId) -> bool {
        self.src_section
            .as_ref()
            .map_or(false, |si| si.members().contains(pub_id))
    }

    // Returns a list of all invalid signatures (not from an expected key or not cryptographically
    // valid).
    fn find_invalid_sigs(&self, signed_bytes: Vec<u8>) -> Vec<PublicId> {
        let invalid = self
            .signatures
            .sigs
            .iter()
            .filter_map(|(pub_id, sig)| {
                // Remove if not in sending nodes or signature is invalid:
                let is_valid = if let Authority::Client { ref client_id, .. } = self.content.src {
                    client_id == pub_id
                        && client_id
                            .signing_public_key()
                            .verify_detached(sig, &signed_bytes)
                } else {
                    self.is_sender(pub_id)
                        && pub_id
                            .signing_public_key()
                            .verify_detached(sig, &signed_bytes)
                };
                if is_valid {
                    None
                } else {
                    Some(*pub_id)
                }
            })
            .collect_vec();
        if !invalid.is_empty() {
            debug!("{:?}: invalid signatures: {:?}", self, invalid);
        }
        invalid
    }

    // Returns true if there are enough signatures (note that this method does not verify the
    // signatures, it only counts them; it also does not verify `self.src_section`).
    fn has_enough_sigs(&self) -> bool {
        use crate::Authority::*;

        // Only Clients are allowed to omit the src_section
        if !self.content.src.is_client() && self.src_section.is_none() {
            return false;
        }

        match self.content.src {
            ClientManager(_) | NaeManager(_) | NodeManager(_) | Section(_) | PrefixSection(_) => {
                let valid_sigs = self.signatures.len();
                valid_sigs * QUORUM_DENOMINATOR > self.src_size() * QUORUM_NUMERATOR
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
    /// Returns the priority Crust should send this message with.
    pub fn priority(&self) -> u8 {
        self.content.priority()
    }

    /// Returns the message hash
    pub fn hash(&self) -> Result<Digest256> {
        let serialised_msg = serialise(self)?;
        Ok(safe_crypto::hash(&serialised_msg))
    }

    /// Returns a signature for this message.
    pub fn to_signature(&self, signing_key: &SecretSignKey) -> Result<Signature> {
        let serialised_msg = serialise(self)?;
        let sig = signing_key.sign_detached(&serialised_msg);
        Ok(sig)
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
/// of Y votes for `ExpectCandidate`. Once Y accumulates votes for `ExpectCandidate`, send a
/// `RelocateResponse` back to A, which includes an address space range
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
#[allow(clippy::large_enum_variant)]
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
    /// Reply with the address range into which the joining node should move.
    RelocateResponse {
        /// The interval into which the joining node should join.
        target_interval: XorTargetInterval,
        /// The section that the joining node shall connect to.
        section: (Prefix<XorName>, BTreeSet<PublicId>),
        /// The message's unique identifier.
        message_id: MessageId,
    },
    /// Send a request containing our connection info to a member of a section to connect to us.
    ConnectionRequest {
        /// The sender's public ID.
        pub_id: PublicId,
        /// Encrypted sender's connection info.
        encrypted_conn_info: Vec<u8>,
        /// The message's unique identifier.
        msg_id: MessageId,
    },
    /// Inform neighbours about our new section. The payload is just a unique hash, as the actual
    /// information is included in the `SignedMessage`'s proving sections anyway.
    NeighbourInfo(Digest256),
    /// Inform neighbours that we need to merge, and that the successor of the section info with
    /// the given hash will be the merged section.
    Merge(Digest256),
    /// Part of a user-facing message
    UserMessage {
        /// The content of the user message.
        content: UserMessage,
        /// The message priority.
        priority: u8,
    },
    /// Approves the joining node as a routing node.
    ///
    /// Sent from Group Y to the joining node.
    NodeApproval(GenesisPfxInfo),
    /// Acknowledgement of a consensused section info.
    AckMessage(SectionInfo),
}

impl MessageContent {
    /// The priority Crust should send this message with.
    pub fn priority(&self) -> u8 {
        match *self {
            MessageContent::UserMessage { priority, .. } => priority,
            _ => 0,
        }
    }
}

impl Debug for HopMessage {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "HopMessage {{ content: {:?}, signature: .. }}",
            self.content
        )
    }
}

impl Debug for SignedRoutingMessage {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "SignedRoutingMessage {{ content: {:?}, sending nodes: {:?}, signatures: {:?}, \
             proving_sections: {:?} }}",
            self.content, self.src_section, self.signatures, self.proving_sections
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
            } => write!(
                formatter,
                "ExpectCandidate {{ {:?}, {:?}, {:?} }}",
                old_public_id, old_client_auth, message_id
            ),
            ConnectionRequest {
                ref pub_id,
                ref msg_id,
                ..
            } => write!(
                formatter,
                "ConnectionRequest {{ {:?}, {:?}, .. }}",
                pub_id, msg_id
            ),
            RelocateResponse {
                ref target_interval,
                ref section,
                ref message_id,
            } => write!(
                formatter,
                "RelocateResponse {{ {:?}, {:?}, {:?} }}",
                target_interval, section, message_id
            ),
            NeighbourInfo(ref digest) => {
                write!(formatter, "NeighbourInfo({:.14?})", HexFmt(digest),)
            }
            Merge(ref digest) => write!(formatter, "Merge({:.14?})", HexFmt(digest)),
            UserMessage {
                ref content,
                priority,
                ..
            } => write!(
                formatter,
                "UserMessage {{ content: {:?}, priority: {} }}",
                content, priority,
            ),
            NodeApproval(ref gen_info) => write!(formatter, "NodeApproval {{ {:?} }}", gen_info),
            AckMessage(ref sec_info) => write!(formatter, "AckMessage({:?})", sec_info),
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
    /// Returns an event indicating that this message was received with the given source and
    /// destination authorities.
    pub fn into_event(self, src: Authority<XorName>, dst: Authority<XorName>) -> Event {
        match self {
            UserMessage::Request(request) => Event::RequestReceived {
                request: request,
                src: src,
                dst: dst,
            },
            UserMessage::Response(response) => Event::ResponseReceived {
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

    pub fn is_cacheable(&self) -> bool {
        match *self {
            UserMessage::Request(ref request) => request.is_cacheable(),
            UserMessage::Response(ref response) => response.is_cacheable(),
        }
    }

    /// Returns an object that implements `Display` for printing short, simplified representation of
    /// `UserMessage`.
    pub fn short_display(&self) -> UserMessageShortDisplay {
        UserMessageShortDisplay(self)
    }
}

pub struct UserMessageShortDisplay<'a>(&'a UserMessage);

impl<'a> Display for UserMessageShortDisplay<'a> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self.0 {
            UserMessage::Request(ref r) => write!(f, "Request {{ {:?} }}", r.message_id()),
            UserMessage::Response(ref r) => write!(f, "Response {{ {:?} }}", r.message_id()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::ImmutableData;
    use crate::id::FullId;
    use crate::routing_table::{Authority, Prefix};
    use crate::types::MessageId;
    use crate::xor_name::XorName;
    use maidsafe_utilities::serialisation::serialise;
    use rand;
    use safe_crypto::{self, Signature, SIGNATURE_BYTES};
    use std::iter;
    use unwrap::unwrap;

    #[test]
    fn signed_routing_message_check_integrity() {
        let name: XorName = rand::random();
        let full_id = FullId::new();
        let msg = RoutingMessage {
            src: Authority::Client {
                client_id: *full_id.public_id(),
                proxy_node_name: name,
            },
            dst: Authority::ClientManager(name),
            content: MessageContent::Relocate {
                message_id: MessageId::new(),
            },
        };
        let mut signed_msg = unwrap!(SignedRoutingMessage::new(msg.clone(), &full_id, None));

        assert_eq!(msg, *signed_msg.routing_message());
        assert_eq!(1, signed_msg.signatures.len());
        assert!(signed_msg.signatures.contains_id(full_id.public_id()));

        unwrap!(signed_msg.check_integrity());

        let full_id = FullId::new();
        let bytes_to_sign = unwrap!(serialise(&(&msg, full_id.public_id())));
        let signature = full_id.signing_private_key().sign_detached(&bytes_to_sign);

        signed_msg.signatures.sigs = iter::once((*full_id.public_id(), signature)).collect();

        // Invalid because it's not signed by the sender:
        assert!(signed_msg.check_integrity().is_err());
        // However, the signature itself should be valid:
        assert!(signed_msg.has_enough_sigs());
    }

    #[test]
    fn signed_routing_message_signatures() {
        let full_id_0 = FullId::new();
        let prefix = Prefix::new(0, *full_id_0.public_id().name());
        let full_id_1 = FullId::new();
        let full_id_2 = FullId::new();
        let full_id_3 = FullId::new();
        let irrelevant_full_id = FullId::new();
        let data_bytes: Vec<u8> = (0..10).collect();
        let data = ImmutableData::new(data_bytes);
        let user_msg = UserMessage::Request(Request::PutIData {
            data: data,
            msg_id: MessageId::new(),
        });
        let name: XorName = rand::random();
        let msg = RoutingMessage {
            src: Authority::ClientManager(name),
            dst: Authority::ClientManager(name),
            content: MessageContent::UserMessage {
                content: user_msg,
                priority: 0,
            },
        };

        let src_section_nodes = vec![
            *full_id_0.public_id(),
            *full_id_1.public_id(),
            *full_id_2.public_id(),
            *full_id_3.public_id(),
        ];
        let src_section = unwrap!(SectionInfo::new(
            src_section_nodes.into_iter().collect(),
            prefix,
            None,
        ));
        let mut signed_msg = unwrap!(SignedRoutingMessage::new(msg, &full_id_0, src_section));
        assert_eq!(signed_msg.signatures.len(), 1);

        // Try to add a signature which will not correspond to an ID from the sending nodes.
        let irrelevant_sig = match signed_msg
            .routing_message()
            .to_signature(irrelevant_full_id.signing_private_key())
        {
            Ok(sig) => {
                signed_msg.add_signature(*irrelevant_full_id.public_id(), sig);
                sig
            }
            err => panic!("Unexpected error: {:?}", err),
        };
        assert_eq!(signed_msg.signatures.len(), 1);
        assert!(!signed_msg
            .signatures
            .contains_id(irrelevant_full_id.public_id()));
        assert!(!signed_msg.check_fully_signed());

        // Add a valid signature for IDs 1 and 2 and an invalid one for ID 3
        for full_id in &[full_id_1, full_id_2] {
            match signed_msg
                .routing_message()
                .to_signature(full_id.signing_private_key())
            {
                Ok(sig) => {
                    signed_msg.add_signature(*full_id.public_id(), sig);
                }
                err => panic!("Unexpected error: {:?}", err),
            }
        }

        let bad_sig = Signature::from_bytes([0; SIGNATURE_BYTES]);
        signed_msg.add_signature(*full_id_3.public_id(), bad_sig);
        assert_eq!(signed_msg.signatures.len(), 4);
        assert!(signed_msg.check_fully_signed());

        // Check the bad signature got removed (by check_fully_signed) properly.
        assert_eq!(signed_msg.signatures.len(), 3);
        assert!(!signed_msg.signatures.contains_id(full_id_3.public_id()));

        // Check an irrelevant signature can't be added.
        signed_msg.add_signature(*irrelevant_full_id.public_id(), irrelevant_sig);
        assert_eq!(signed_msg.signatures.len(), 3);
        assert!(!signed_msg
            .signatures
            .contains_id(irrelevant_full_id.public_id(),));
    }
}
