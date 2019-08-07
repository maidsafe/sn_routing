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
use crate::{
    chain::{Chain, GenesisPfxInfo, SectionInfo, SectionProofChain},
    error::{Result, RoutingError},
    event::Event,
    id::{FullId, PublicId},
    routing_table::{Authority, Prefix},
    sha3::Digest256,
    types::MessageId,
    xor_name::XorName,
    BlsPublicKeySet, BlsPublicKeyShare, BlsSignature, BlsSignatureShare, XorTargetInterval,
};
use hex_fmt::HexFmt;
use log::LogLevel;
use maidsafe_utilities::serialisation::serialise;
use safe_crypto::{self, SecretSignKey, Signature};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::{self, Debug, Display, Formatter},
    mem,
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

/// Metadata needed for verification of the sender
#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Hash, Serialize, Deserialize)]
pub struct FullSecurityMetadata {
    proof: SectionProofChain,
    sender_prefix: Prefix<XorName>,
    signature: BlsSignature,
}

impl FullSecurityMetadata {
    pub fn verify_sig(&self, bytes: Vec<u8>) -> bool {
        self.proof.last_public_key().verify(&self.signature, bytes)
    }

    pub fn validate_proof(&self) -> bool {
        self.proof.validate()
    }

    pub fn prefix(&self) -> &Prefix<XorName> {
        &self.sender_prefix
    }

    pub fn proof_chain(&self) -> &SectionProofChain {
        &self.proof
    }
}

#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Hash, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum SecurityMetadata {
    None,
    Partial(BTreeMap<BlsPublicKeyShare, BlsSignatureShare>),
    Signed(BlsSignature),
    Full(FullSecurityMetadata),
}

/// Wrapper around a routing message, signed by the originator of the message.
#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Hash, Serialize, Deserialize)]
pub struct SignedRoutingMessage {
    /// A request or response type message.
    content: RoutingMessage,
    /// Nodes sending the message (those expected to sign it)
    src_section: Option<SectionInfo>,
    /// Optional metadata for verifying the sender
    security_metadata: SecurityMetadata,
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
        let mut signatures = BTreeMap::new();
        let pk_share = BlsPublicKeyShare(*full_id.public_id());
        let sig = content.to_signature(sk)?;
        let _ = signatures.insert(pk_share, sig);
        Ok(SignedRoutingMessage {
            content,
            src_section: src_section.into(),
            security_metadata: SecurityMetadata::Partial(signatures),
        })
    }

    /// Creates a `SignedRoutingMessage` without security metadata
    pub fn insecure<T: Into<Option<SectionInfo>>>(
        content: RoutingMessage,
        src_section: T,
    ) -> SignedRoutingMessage {
        SignedRoutingMessage {
            content,
            src_section: src_section.into(),
            security_metadata: SecurityMetadata::None,
        }
    }

    /// Confirms the signatures.
    pub fn check_integrity(&self) -> Result<()> {
        match self.security_metadata {
            SecurityMetadata::None => Ok(()),
            SecurityMetadata::Partial(_) | SecurityMetadata::Signed(_) => {
                Err(RoutingError::FailedSignature)
            }
            SecurityMetadata::Full(ref security_metadata) => {
                let signed_bytes = serialise(&self.content)?;
                if !security_metadata.verify_sig(signed_bytes) {
                    return Err(RoutingError::FailedSignature);
                }
                if !security_metadata.validate_proof() {
                    return Err(RoutingError::InvalidProvingSection);
                }
                Ok(())
            }
        }
    }

    /// Checks if the message can be trusted according to the Chain
    pub fn check_trust(&self, chain: &Chain) -> bool {
        match self.security_metadata {
            SecurityMetadata::Full(ref security_metadata) => {
                chain.check_trust(security_metadata.prefix(), security_metadata.proof_chain())
            }
            SecurityMetadata::None => true,
            _ => false,
        }
    }

    /// Returns the source section that signed the message itself.
    pub fn source_section(&self) -> Option<&SectionInfo> {
        self.src_section.as_ref()
    }

    /// Returns the number of nodes in the source authority.
    pub fn src_size(&self) -> usize {
        self.src_section.as_ref().map_or(0, |si| si.members().len())
    }

    /// Adds a proof if it is new, without validating it.
    pub fn add_signature_share(
        &mut self,
        pk_share: BlsPublicKeyShare,
        sig_share: BlsSignatureShare,
    ) {
        if let SecurityMetadata::Partial(ref mut sigs) = self.security_metadata {
            let _ = sigs.insert(pk_share, sig_share);
        }
    }

    /// Adds all signatures from the given message, without validating them.
    pub fn add_signature_shares(&mut self, mut msg: SignedRoutingMessage) {
        if self.content.src.is_multiple() {
            if let (
                SecurityMetadata::Partial(self_shares),
                SecurityMetadata::Partial(other_shares),
            ) = (&mut self.security_metadata, &mut msg.security_metadata)
            {
                self_shares.append(other_shares);
            }
        }
    }

    /// Combines the signatures into a single BLS signature
    pub fn combine_signatures(&mut self, pk_set: &BlsPublicKeySet) {
        if let SecurityMetadata::Partial(sigs) =
            mem::replace(&mut self.security_metadata, SecurityMetadata::None)
        {
            if let Some(full_sig) =
                pk_set.combine_signatures(sigs.iter().map(|(key, sig)| (*key, sig)))
            {
                self.security_metadata = SecurityMetadata::Signed(full_sig);
            } else {
                log_or_panic!(
                    LogLevel::Error,
                    "Combining signatures failed on {:?}!",
                    self
                );
            }
        } else {
            warn!("Tried to call combine_signatures on {:?}", self);
        }
    }

    /// Generate and attach the full proof for the recipient
    pub fn attach_proof(&mut self, chain: &Chain) {
        if let SecurityMetadata::Signed(sig) =
            mem::replace(&mut self.security_metadata, SecurityMetadata::None)
        {
            let signed_bytes = match serialise(&self.content) {
                Ok(serialised) => serialised,
                Err(error) => {
                    warn!("Failed to serialise {:?}: {:?}", self, error);
                    return;
                }
            };
            let proof_chain = chain.prove(&self.content.dst, &sig, &signed_bytes);
            let proof = FullSecurityMetadata {
                proof: proof_chain,
                sender_prefix: *chain.our_prefix(),
                signature: sig,
            };
            self.security_metadata = SecurityMetadata::Full(proof);
        } else {
            warn!("Tried to call attach_proof on {:?}", self);
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
    pub fn check_fully_signed(&mut self, pk_set: &BlsPublicKeySet) -> bool {
        if !self.has_enough_sigs(pk_set) {
            return false;
        }

        // Remove invalid signatures, then check again that we have enough.
        // We also check (again) that all messages are from valid senders, because the message
        // may have been sent from another node, and we cannot trust that that node correctly
        // controlled which signatures were added.

        let invalid_sigs = match self.security_metadata {
            // unfortunately, `match`es had to be split because of the borrow checker;
            // the two cases below can return early as they have nothing left to do
            SecurityMetadata::None => {
                return false;
            }
            SecurityMetadata::Signed(_) | SecurityMetadata::Full(_) => {
                return true;
            }
            // this is the only case in which we actually have to do further checks
            SecurityMetadata::Partial(_) => {
                let signed_bytes = match serialise(&self.content) {
                    Ok(serialised) => serialised,
                    Err(error) => {
                        warn!("Failed to serialise {:?}: {:?}", self, error);
                        return false;
                    }
                };
                self.find_invalid_sigs(signed_bytes)
            }
        };

        if let SecurityMetadata::Partial(ref mut sigs) = self.security_metadata {
            // the mutable borrow in this case made it impossible to find the invalid sigs and
            // check for enough sigs in the same match
            for invalid_signature in invalid_sigs {
                let _ = sigs.remove(&invalid_signature);
            }
        }

        self.has_enough_sigs(pk_set)
    }

    // Returns a list of all invalid signatures (not from an expected key or not cryptographically
    // valid).
    fn find_invalid_sigs(&self, signed_bytes: Vec<u8>) -> Vec<BlsPublicKeyShare> {
        match self.security_metadata {
            SecurityMetadata::None | SecurityMetadata::Signed(_) | SecurityMetadata::Full(_) => {
                vec![]
            }
            SecurityMetadata::Partial(ref sigs) => {
                let invalid: Vec<_> = sigs
                    .iter()
                    .filter(|&(key, sig)| !key.verify(sig, &signed_bytes))
                    .map(|(key, _)| *key)
                    .collect();
                if !invalid.is_empty() {
                    debug!("{:?}: invalid signatures: {:?}", self, invalid);
                }
                invalid
            }
        }
    }

    // Returns true if there are enough signatures (note that this method does not verify the
    // signatures, it only counts them; it also does not verify `self.src_section`).
    fn has_enough_sigs(&self, pk_set: &BlsPublicKeySet) -> bool {
        // Only Clients are allowed to omit the src_section
        if !self.content.src.is_client() && self.src_section.is_none() {
            return false;
        }

        match &self.security_metadata {
            SecurityMetadata::None => !self.content.src.is_multiple(),
            SecurityMetadata::Partial(sig_shares) => sig_shares.len() > pk_set.threshold(),
            SecurityMetadata::Signed(_) | SecurityMetadata::Full(_) => true,
        }
    }

    #[cfg(test)]
    pub fn signatures(&self) -> Option<&BTreeMap<BlsPublicKeyShare, BlsSignatureShare>> {
        match &self.security_metadata {
            SecurityMetadata::Partial(sigs) => Some(sigs),
            _ => None,
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
    AckMessage {
        /// The prefix of our section when we acknowledge their SectionInfo of version ack_version.
        src_prefix: Prefix<XorName>,
        /// The version acknowledged.
        ack_version: u64,
    },
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
        let security_metadata_str = match self.security_metadata {
            SecurityMetadata::None => "None",
            SecurityMetadata::Partial(_) => "Partial",
            SecurityMetadata::Signed(_) => "Signed",
            SecurityMetadata::Full(_) => "Full",
        };
        write!(
            formatter,
            "SignedRoutingMessage {{ content: {:?}, sending nodes: {:?}, \
             security_metadata: {:?} }}",
            self.content, self.src_section, security_metadata_str
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
            AckMessage {
                ref src_prefix,
                ref ack_version,
            } => write!(formatter, "AckMessage({:?}, {})", src_prefix, ack_version),
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
    use rand;
    use safe_crypto::{self, Signature, SIGNATURE_BYTES};
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
        assert_eq!(1, signed_msg.signatures().expect("no signatures").len());
        assert!(signed_msg
            .signatures()
            .expect("no signatures")
            .contains_key(&BlsPublicKeyShare(*full_id.public_id())));

        assert!(signed_msg.check_integrity().is_err());

        signed_msg.security_metadata = SecurityMetadata::None;

        assert!(signed_msg.check_integrity().is_ok());
    }

    #[test]
    fn signed_routing_message_signatures() {
        let full_id_0 = FullId::new();
        let prefix = Prefix::new(0, *full_id_0.public_id().name());
        let full_id_1 = FullId::new();
        let full_id_2 = FullId::new();
        let full_id_3 = FullId::new();
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
        let pk_set = BlsPublicKeySet::from_section_info(src_section.clone());
        let mut signed_msg = unwrap!(SignedRoutingMessage::new(msg, &full_id_0, src_section));
        assert_eq!(signed_msg.signatures().expect("no signatures").len(), 1);

        assert!(!signed_msg.check_fully_signed(&pk_set));

        // Add a valid signature for IDs 1 and 2 and an invalid one for ID 3
        for full_id in &[full_id_1, full_id_2] {
            match signed_msg
                .routing_message()
                .to_signature(full_id.signing_private_key())
            {
                Ok(sig) => {
                    signed_msg.add_signature_share(BlsPublicKeyShare(*full_id.public_id()), sig);
                }
                err => panic!("Unexpected error: {:?}", err),
            }
        }

        let bad_sig = Signature::from_bytes([0; SIGNATURE_BYTES]);
        signed_msg.add_signature_share(BlsPublicKeyShare(*full_id_3.public_id()), bad_sig);
        assert_eq!(signed_msg.signatures().expect("no signatures").len(), 4);
        assert!(signed_msg.check_fully_signed(&pk_set));

        // Check the bad signature got removed (by check_fully_signed) properly.
        assert_eq!(signed_msg.signatures().expect("no signatures").len(), 3);
        assert!(!signed_msg
            .signatures()
            .expect("no signatures")
            .contains_key(&BlsPublicKeyShare(*full_id_3.public_id())));
    }
}
