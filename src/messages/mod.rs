// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod direct;

pub use self::direct::{BootstrapResponse, DirectMessage, SignedDirectMessage};
use crate::{
    chain::{Chain, EldersInfo, GenesisPfxInfo, SectionKeyInfo, SectionProofChain},
    crypto::{self, signing::Signature, Digest256},
    error::{Result, RoutingError},
    id::{FullId, PublicId},
    routing_table::{Authority, Prefix},
    types::MessageId,
    xor_name::XorName,
    BlsPublicKeySet, BlsPublicKeyShare, BlsSignature, BlsSignatureShare,
};
use hex_fmt::HexFmt;
use log::LogLevel;
use maidsafe_utilities::serialisation::serialise;
use std::{
    collections::BTreeMap,
    fmt::{self, Debug, Formatter},
    mem,
};

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

/// Metadata needed for verification of the sender.
/// Contain shares of the section signature before combining into a BLS signature
/// and into a FullSecurityMetadata.
#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Hash, Serialize, Deserialize)]
pub struct PartialSecurityMetadata {
    proof: SectionProofChain,
    shares: BTreeMap<BlsPublicKeyShare, BlsSignatureShare>,
    pk_set: BlsPublicKeySet,
}

impl Debug for PartialSecurityMetadata {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "PartialSecurityMetadata {{ proof.blocks_len: {}, proof: {:?}, .. }}",
            self.proof.blocks_len(),
            self.proof
        )
    }
}

/// Metadata needed for verification of the sender.
#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Hash, Serialize, Deserialize)]
pub struct FullSecurityMetadata {
    proof: SectionProofChain,
    signature: BlsSignature,
}

impl FullSecurityMetadata {
    pub fn verify_sig(&self, bytes: &[u8]) -> bool {
        self.proof.last_public_key().verify(&self.signature, bytes)
    }

    pub fn last_public_key_info(&self) -> &SectionKeyInfo {
        self.proof.last_public_key_info()
    }

    pub fn validate_proof(&self) -> bool {
        self.proof.validate()
    }

    pub fn proof_chain(&self) -> &SectionProofChain {
        &self.proof
    }
}

impl Debug for FullSecurityMetadata {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "FullSecurityMetadata {{ proof.blocks_len: {}, proof: {:?}, .. }}",
            self.proof.blocks_len(),
            self.proof
        )
    }
}

/// Metadata needed for verification of the single node sender.
#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Hash, Serialize, Deserialize)]
pub struct SingleSrcSecurityMetadata {
    public_id: PublicId,
    signature: Signature,
}

impl SingleSrcSecurityMetadata {
    pub fn verify_sig(&self, bytes: &[u8]) -> bool {
        self.public_id.verify(bytes, &self.signature)
    }
}

impl Debug for SingleSrcSecurityMetadata {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "SingleSrcSecurityMetadata {{ public_id: {:?}, .. }}",
            self.public_id
        )
    }
}

#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Hash, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum SecurityMetadata {
    None,
    Partial(PartialSecurityMetadata),
    Full(FullSecurityMetadata),
    Single(SingleSrcSecurityMetadata),
}

impl Debug for SecurityMetadata {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match &self {
            SecurityMetadata::None => write!(formatter, "None"),
            SecurityMetadata::Partial(pmd) => write!(formatter, "{:?}", pmd),
            SecurityMetadata::Full(smd) => write!(formatter, "{:?}", smd),
            SecurityMetadata::Single(smd) => write!(formatter, "{:?}", smd),
        }
    }
}

/// Wrapper around a routing message, signed by the originator of the message.
#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Hash, Serialize, Deserialize)]
pub struct SignedRoutingMessage {
    /// A request or response type message.
    content: RoutingMessage,
    /// Optional metadata for verifying the sender
    security_metadata: SecurityMetadata,
}

impl SignedRoutingMessage {
    /// Creates a `SignedMessage` with the given `content` and signed by the given `full_id`.
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        content: RoutingMessage,
        full_id: &FullId,
        pk_set: BlsPublicKeySet,
        proof: SectionProofChain,
    ) -> Result<SignedRoutingMessage> {
        let mut signatures = BTreeMap::new();
        let pk_share = BlsPublicKeyShare(*full_id.public_id());
        let sig = full_id.sign(&serialise(&content)?);
        let _ = signatures.insert(pk_share, sig);
        let partial_metadata = PartialSecurityMetadata {
            shares: signatures,
            pk_set,
            proof,
        };
        Ok(SignedRoutingMessage {
            content,
            security_metadata: SecurityMetadata::Partial(partial_metadata),
        })
    }

    /// Creates a `SignedRoutingMessage` security metadata from a single source
    pub fn single_source(
        content: RoutingMessage,
        full_id: &FullId,
    ) -> Result<SignedRoutingMessage> {
        let single_metadata = SingleSrcSecurityMetadata {
            public_id: *full_id.public_id(),
            signature: full_id.sign(&serialise(&content)?),
        };

        Ok(SignedRoutingMessage {
            content,
            security_metadata: SecurityMetadata::Single(single_metadata),
        })
    }

    /// Creates a `SignedRoutingMessage` without security metadata
    #[cfg(all(test, feature = "mock_base"))]
    pub fn insecure(content: RoutingMessage) -> SignedRoutingMessage {
        SignedRoutingMessage {
            content,
            security_metadata: SecurityMetadata::None,
        }
    }

    /// Confirms the signatures.
    pub fn check_integrity(&self) -> Result<()> {
        match self.security_metadata {
            SecurityMetadata::None | SecurityMetadata::Partial(_) => {
                Err(RoutingError::FailedSignature)
            }
            SecurityMetadata::Single(ref security_metadata) => {
                if self.content.src.single_signing_name()
                    != Some(security_metadata.public_id.name())
                {
                    // Signature is not from the source node.
                    return Err(RoutingError::InvalidMessage);
                }

                let signed_bytes = serialise(&self.content)?;
                if !security_metadata.verify_sig(&signed_bytes) {
                    return Err(RoutingError::FailedSignature);
                }
                Ok(())
            }
            SecurityMetadata::Full(ref security_metadata) => {
                let signed_bytes = serialise(&self.content)?;
                if !security_metadata.verify_sig(&signed_bytes) {
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
                chain.check_trust(security_metadata.proof_chain())
            }
            SecurityMetadata::None | SecurityMetadata::Single(_) => true,
            SecurityMetadata::Partial(_) => false,
        }
    }

    /// Returns the security metadata validating the message.
    pub fn source_section_key_info(&self) -> Option<&SectionKeyInfo> {
        match self.security_metadata {
            SecurityMetadata::None | SecurityMetadata::Partial(_) | SecurityMetadata::Single(_) => {
                None
            }
            SecurityMetadata::Full(ref security_metadata) => {
                Some(security_metadata.last_public_key_info())
            }
        }
    }

    /// Adds a proof if it is new, without validating it.
    #[cfg(test)]
    pub fn add_signature_share(
        &mut self,
        pk_share: BlsPublicKeyShare,
        sig_share: BlsSignatureShare,
    ) {
        if let SecurityMetadata::Partial(ref mut partial) = self.security_metadata {
            let _ = partial.shares.insert(pk_share, sig_share);
        }
    }

    /// Adds all signatures from the given message, without validating them.
    pub fn add_signature_shares(&mut self, mut msg: SignedRoutingMessage) {
        if self.content.src.is_multiple() {
            if let (
                SecurityMetadata::Partial(self_partial),
                SecurityMetadata::Partial(other_partial),
            ) = (&mut self.security_metadata, &mut msg.security_metadata)
            {
                self_partial.shares.append(&mut other_partial.shares);
            }
        }
    }

    /// Combines the signatures into a single BLS signature
    pub fn combine_signatures(&mut self) {
        match mem::replace(&mut self.security_metadata, SecurityMetadata::None) {
            SecurityMetadata::Partial(partial) => {
                if let Some(full_sig) = partial
                    .pk_set
                    .combine_signatures(partial.shares.iter().map(|(key, sig)| (*key, sig)))
                {
                    self.security_metadata = SecurityMetadata::Full(FullSecurityMetadata {
                        proof: partial.proof,
                        signature: full_sig,
                    });
                } else {
                    log_or_panic!(
                        LogLevel::Error,
                        "Combining signatures failed on {:?}!",
                        self
                    );
                }
            }
            SecurityMetadata::Full(_) => {
                log_or_panic!(
                    LogLevel::Warn,
                    "Tried to call combine_signatures on {:?}",
                    self
                );
            }
            SecurityMetadata::None | SecurityMetadata::Single(_) => (),
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

    /// Returns whether there are enough signatures from the sender.
    pub fn check_fully_signed(&mut self) -> bool {
        if !self.has_enough_sigs() {
            return false;
        }

        // Remove invalid signatures, then check again that we have enough.
        // We also check (again) that all messages are from valid senders, because the message
        // may have been sent from another node, and we cannot trust that that node correctly
        // controlled which signatures were added.

        let invalid_sigs = match self.security_metadata {
            // unfortunately, `match`es had to be split because of the borrow checker;
            // the three cases below can return early as they have nothing left to do
            SecurityMetadata::None | SecurityMetadata::Single(_) => {
                return false;
            }
            SecurityMetadata::Full(_) => {
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
                self.find_invalid_sigs(&signed_bytes)
            }
        };

        if let SecurityMetadata::Partial(ref mut partial) = self.security_metadata {
            // the mutable borrow in this case made it impossible to find the invalid sigs and
            // check for enough sigs in the same match
            for invalid_signature in invalid_sigs {
                let _ = partial.shares.remove(&invalid_signature);
            }
        }

        self.has_enough_sigs()
    }

    // Returns a list of all invalid signatures (not from an expected key or not cryptographically
    // valid).
    fn find_invalid_sigs(&self, signed_bytes: &[u8]) -> Vec<BlsPublicKeyShare> {
        match self.security_metadata {
            SecurityMetadata::None | SecurityMetadata::Full(_) | SecurityMetadata::Single(_) => vec![],
            SecurityMetadata::Partial(ref partial) => {
                let invalid: Vec<_> = partial
                    .shares
                    .iter()
                    .filter(|&(key, sig)| !key.verify(sig, signed_bytes))
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
    // signatures, it only counts them).
    fn has_enough_sigs(&self) -> bool {
        match &self.security_metadata {
            SecurityMetadata::None => !self.content.src.is_multiple(),
            SecurityMetadata::Partial(partial) => partial.shares.len() > partial.pk_set.threshold(),
            SecurityMetadata::Full(_) | SecurityMetadata::Single(_) => true,
        }
    }

    #[cfg(test)]
    pub fn signatures(&self) -> Option<&BTreeMap<BlsPublicKeyShare, BlsSignatureShare>> {
        match &self.security_metadata {
            SecurityMetadata::Partial(partial) => Some(&partial.shares),
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
    /// Returns the message hash
    pub fn hash(&self) -> Result<Digest256> {
        let serialised_msg = serialise(self)?;
        Ok(crypto::sha3_256(&serialised_msg))
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
    /// Send a request containing our connection info to a member of a section to connect to us.
    ConnectionRequest {
        /// The sender's public ID.
        pub_id: PublicId,
        /// Sender's connection info.
        conn_info: Vec<u8>,
        /// The message's unique identifier.
        msg_id: MessageId,
    },
    /// Inform neighbours about our new section.
    NeighbourInfo(EldersInfo),
    /// Inform neighbours that we need to merge, and that the successor of the section info with
    /// the given hash will be the merged section.
    Merge(Digest256),
    /// User-facing message
    UserMessage(Vec<u8>),
    /// Approves the joining node as a routing node.
    ///
    /// Sent from Group Y to the joining node.
    NodeApproval(GenesisPfxInfo),
    /// Acknowledgement of a consensused section info.
    AckMessage {
        /// The prefix of our section when we acknowledge their EldersInfo of version ack_version.
        src_prefix: Prefix<XorName>,
        /// The version acknowledged.
        ack_version: u64,
    },
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
            "SignedRoutingMessage {{ content: {:?}, security_metadata: {:?} }}",
            self.content, self.security_metadata
        )
    }
}

impl Debug for MessageContent {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        use self::MessageContent::*;
        match *self {
            ConnectionRequest {
                ref pub_id,
                ref msg_id,
                ..
            } => write!(
                formatter,
                "ConnectionRequest({:?}, {:?}, ..)",
                pub_id, msg_id
            ),
            NeighbourInfo(ref info) => write!(formatter, "NeighbourInfo({:?})", info),
            Merge(ref digest) => write!(formatter, "Merge({:.14?})", HexFmt(digest)),
            UserMessage(ref content) => write!(formatter, "UserMessage({:?})", content,),
            NodeApproval(ref gen_info) => write!(formatter, "NodeApproval({:?})", gen_info),
            AckMessage {
                ref src_prefix,
                ref ack_version,
            } => write!(formatter, "AckMessage({:?}, {})", src_prefix, ack_version),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chain::SectionKeyInfo,
        crypto::signing::{Signature, SIGNATURE_LENGTH},
        id::FullId,
        routing_table::{Authority, Prefix},
        xor_name::XorName,
    };
    use rand;
    use std::collections::BTreeSet;
    use unwrap::unwrap;

    #[test]
    fn signed_routing_message_check_integrity() {
        let full_id = FullId::new();
        let full_id_2 = FullId::new();
        let prefix = Prefix::new(0, *full_id.public_id().name());
        let pub_ids: BTreeSet<_> = vec![*full_id.public_id(), *full_id_2.public_id()]
            .into_iter()
            .collect();
        let dummy_elders_info = unwrap!(EldersInfo::new(pub_ids, prefix, None));
        let dummy_pk_set = BlsPublicKeySet::from_elders_info(dummy_elders_info.clone());
        let dummy_key_info = SectionKeyInfo::from_elders_info(&dummy_elders_info);
        let dummy_proof = SectionProofChain::from_genesis(dummy_key_info);

        let msg = RoutingMessage {
            src: Authority::Node(rand::random()),
            dst: Authority::Section(rand::random()),
            content: MessageContent::UserMessage(vec![0, 1, 2, 3, 4]),
        };
        let mut signed_msg = unwrap!(SignedRoutingMessage::new(
            msg.clone(),
            &full_id,
            dummy_pk_set,
            dummy_proof,
        ));

        assert_eq!(msg, *signed_msg.routing_message());
        assert_eq!(1, signed_msg.signatures().expect("no signatures").len());
        assert!(signed_msg
            .signatures()
            .expect("no signatures")
            .contains_key(&BlsPublicKeyShare(*full_id.public_id())));

        assert!(signed_msg.check_integrity().is_err());

        signed_msg.security_metadata = SecurityMetadata::None;

        assert!(signed_msg.check_integrity().is_err());
    }

    #[test]
    fn signed_routing_message_signatures() {
        let full_id_0 = FullId::new();
        let prefix = Prefix::new(0, *full_id_0.public_id().name());
        let full_id_1 = FullId::new();
        let full_id_2 = FullId::new();
        let full_id_3 = FullId::new();
        let content = (0..10).collect();
        let name: XorName = rand::random();
        let msg = RoutingMessage {
            src: Authority::Section(name),
            dst: Authority::Section(name),
            content: MessageContent::UserMessage(content),
        };

        let src_section_nodes = vec![
            *full_id_0.public_id(),
            *full_id_1.public_id(),
            *full_id_2.public_id(),
            *full_id_3.public_id(),
        ];
        let src_section = unwrap!(EldersInfo::new(
            src_section_nodes.into_iter().collect(),
            prefix,
            None,
        ));
        let pk_set = BlsPublicKeySet::from_elders_info(src_section.clone());
        let dummy_key_info = SectionKeyInfo::from_elders_info(&src_section);
        let dummy_proof = SectionProofChain::from_genesis(dummy_key_info);
        let mut signed_msg = unwrap!(SignedRoutingMessage::new(
            msg,
            &full_id_0,
            pk_set,
            dummy_proof
        ));
        assert_eq!(signed_msg.signatures().expect("no signatures").len(), 1);

        assert!(!signed_msg.check_fully_signed());

        // Add a valid signature for IDs 1 and 2 and an invalid one for ID 3
        for full_id in &[full_id_1, full_id_2] {
            let sig = full_id.sign(&unwrap!(serialise(signed_msg.routing_message())));
            signed_msg.add_signature_share(BlsPublicKeyShare(*full_id.public_id()), sig);
        }

        let bad_sig = unwrap!(Signature::from_bytes(&[0; SIGNATURE_LENGTH]));
        signed_msg.add_signature_share(BlsPublicKeyShare(*full_id_3.public_id()), bad_sig);
        assert_eq!(signed_msg.signatures().expect("no signatures").len(), 4);
        assert!(signed_msg.check_fully_signed());

        // Check the bad signature got removed (by check_fully_signed) properly.
        assert_eq!(signed_msg.signatures().expect("no signatures").len(), 3);
        assert!(!signed_msg
            .signatures()
            .expect("no signatures")
            .contains_key(&BlsPublicKeyShare(*full_id_3.public_id())));
    }
}
