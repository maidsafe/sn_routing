// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod direct;

pub use self::direct::{
    BootstrapResponse, DirectMessage, JoinRequest, MemberKnowledge, SignedDirectMessage,
};
use crate::{
    chain::{
        Chain, EldersInfo, GenesisPfxInfo, SectionKeyInfo, SectionKeyShare, SectionProofChain,
    },
    crypto::{self, signing::Signature, Digest256},
    error::{Result, RoutingError},
    id::{FullId, PublicId},
    location::Location,
    xor_space::{Prefix, XorName},
};
use log::LogLevel;
use maidsafe_utilities::serialisation::serialise;
use std::{
    collections::BTreeSet,
    fmt::{self, Debug, Formatter},
    mem,
};

/// Wrapper of all messages.
///
/// This is the only type allowed to be sent / received on the network.
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
#[derive(Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct HopMessage {
    /// Wrapped signed message.
    pub content: SignedRoutingMessage,
}

impl HopMessage {
    /// Wrap `content` for transmission to the next hop and sign it.
    pub fn new(content: SignedRoutingMessage) -> Result<Self> {
        Ok(Self { content })
    }
}

/// Metadata needed for verification of the sender.
/// Contain shares of the section signature before combining into a BLS signature
/// and into a FullSecurityMetadata.
#[derive(Eq, PartialEq, Clone, Hash, Serialize, Deserialize)]
pub struct PartialSecurityMetadata {
    proof: SectionProofChain,
    shares: BTreeSet<(usize, bls::SignatureShare)>,
    pk_set: bls::PublicKeySet,
}

impl PartialSecurityMetadata {
    fn find_invalid_sigs(&self, signed_bytes: &[u8]) -> Vec<(usize, bls::SignatureShare)> {
        let key_set = &self.pk_set;
        self.shares
            .iter()
            .filter(|&(idx, sig)| !key_set.public_key_share(idx).verify(sig, &signed_bytes))
            .map(|(idx, sig)| (*idx, sig.clone()))
            .collect()
    }
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
#[derive(Eq, PartialEq, Clone, Hash, Serialize, Deserialize)]
pub struct FullSecurityMetadata {
    proof: SectionProofChain,
    signature: bls::Signature,
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

#[derive(Eq, PartialEq, Clone, Hash, Serialize, Deserialize)]
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
            Self::None => write!(formatter, "None"),
            Self::Partial(pmd) => write!(formatter, "{:?}", pmd),
            Self::Full(smd) => write!(formatter, "{:?}", smd),
            Self::Single(smd) => write!(formatter, "{:?}", smd),
        }
    }
}

/// Wrapper around a routing message, signed by the originator of the message.
#[derive(Eq, PartialEq, Clone, Hash, Serialize, Deserialize)]
pub struct SignedRoutingMessage {
    /// A request or response type message.
    content: RoutingMessage,
    /// Optional metadata for verifying the sender
    security_metadata: SecurityMetadata,
}

impl SignedRoutingMessage {
    /// Creates a `SignedMessage` with the given `content` and signed by the given `full_id`.
    pub fn new(
        content: RoutingMessage,
        section_share: &SectionKeyShare,
        pk_set: bls::PublicKeySet,
        proof: SectionProofChain,
    ) -> Result<Self> {
        let mut signatures = BTreeSet::new();
        let sig = section_share.key.sign(&serialise(&content)?);
        let _ = signatures.insert((section_share.index, sig));
        let partial_metadata = PartialSecurityMetadata {
            shares: signatures,
            pk_set,
            proof,
        };
        Ok(Self {
            content,
            security_metadata: SecurityMetadata::Partial(partial_metadata),
        })
    }

    /// Creates a `SignedRoutingMessage` security metadata from a single source
    pub fn single_source(content: RoutingMessage, full_id: &FullId) -> Result<Self> {
        let single_metadata = SingleSrcSecurityMetadata {
            public_id: *full_id.public_id(),
            signature: full_id.sign(&serialise(&content)?),
        };

        Ok(Self {
            content,
            security_metadata: SecurityMetadata::Single(single_metadata),
        })
    }

    /// Creates a `SignedRoutingMessage` without security metadata
    #[cfg(all(test, feature = "mock_base"))]
    pub fn insecure(content: RoutingMessage) -> Self {
        Self {
            content,
            security_metadata: SecurityMetadata::None,
        }
    }

    /// Creates a `SignedRoutingMessage` from content and security metadata.
    /// Note: this function does not verify the metadata matches the content. Need to call
    /// `check_integrity` for that.
    pub fn from_parts(content: RoutingMessage, security_metadata: SecurityMetadata) -> Self {
        Self {
            content,
            security_metadata,
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

    /// Adds all signatures from the given message, without validating them.
    pub fn add_signature_shares(&mut self, mut msg: Self) {
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
                if let Ok(full_sig) = partial
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
                        "Combining signatures failed on {:?}! Part Shares: {:?}, Part Set: {:?}, \
                         Partial: {:?}",
                        self,
                        partial.shares,
                        partial.pk_set,
                        partial,
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

    /// Returns the content and the security metadata.
    pub fn into_parts(self) -> (RoutingMessage, SecurityMetadata) {
        (self.content, self.security_metadata)
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

        let invalid_signatures = match self.security_metadata {
            // unfortunately, `match`es had to be split because of the borrow checker;
            // the three cases below can return early as they have nothing left to do
            SecurityMetadata::None | SecurityMetadata::Single(_) => {
                return false;
            }
            SecurityMetadata::Full(_) => {
                return true;
            }
            // this is the only case in which we actually have to do further checks
            SecurityMetadata::Partial(ref mut partial) => {
                let signed_bytes = match serialise(&self.content) {
                    Ok(serialised) => serialised,
                    Err(error) => {
                        warn!("Failed to serialise {:?}: {:?}", self, error);
                        return false;
                    }
                };

                let invalid_signatures = partial.find_invalid_sigs(&signed_bytes);
                for invalid_signature in &invalid_signatures {
                    let _ = partial.shares.remove(invalid_signature);
                }
                invalid_signatures
            }
        };

        if !invalid_signatures.is_empty() {
            debug!("{:?}: invalid signatures: {:?}", self, invalid_signatures);
        }

        self.has_enough_sigs()
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

    #[cfg(all(test, feature = "mock"))]
    pub(crate) fn proof_chain(&self) -> Option<&SectionProofChain> {
        match &self.security_metadata {
            SecurityMetadata::Full(md) => Some(&md.proof),
            SecurityMetadata::Partial(md) => Some(&md.proof),
            SecurityMetadata::Single(_) | SecurityMetadata::None => None,
        }
    }
}

/// A routing message with source and destination locations.
#[derive(Eq, PartialEq, Clone, Hash, Debug, Serialize, Deserialize)]
pub struct RoutingMessage {
    /// Source location
    pub src: Location<XorName>,
    /// Destination location
    pub dst: Location<XorName>,
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
/// A can now exchange messages with any `Location`. This completes the bootstrap process for
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
/// Once in `JoiningNode` state, A sends a `Relocate` request to the `NaeManager` section location
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
#[derive(Eq, PartialEq, Clone, Hash, Serialize, Deserialize)]
// FIXME - See https://maidsafe.atlassian.net/browse/MAID-2026 for info on removing this exclusion.
#[allow(clippy::large_enum_variant)]
pub enum MessageContent {
    /// Inform neighbours about our new section.
    NeighbourInfo(EldersInfo),
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
    /// Update sent to Adults and Infants by Elders
    GenesisUpdate(GenesisPfxInfo),
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
        match self {
            NeighbourInfo(info) => write!(formatter, "NeighbourInfo({:?})", info),
            UserMessage(content) => write!(formatter, "UserMessage({:?})", content,),
            NodeApproval(gen_info) => write!(formatter, "NodeApproval({:?})", gen_info),
            AckMessage {
                src_prefix,
                ack_version,
            } => write!(formatter, "AckMessage({:?}, {})", src_prefix, ack_version),
            GenesisUpdate(info) => write!(formatter, "GenesisUpdate({:?})", info),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chain::SectionKeyInfo,
        parsec::generate_bls_threshold_secret_key,
        rng::{self, MainRng},
        unwrap, Prefix,
    };
    use rand::{self, Rng};
    use std::iter;

    #[test]
    fn combine_signatures() {
        let mut rng = rng::new();
        let sk_set = generate_bls_threshold_secret_key(&mut rng, 4);
        let pk_set = sk_set.public_keys();

        let sk_share_0 = SectionKeyShare::new_with_position(0, sk_set.secret_key_share(0));
        let sk_share_1 = SectionKeyShare::new_with_position(1, sk_set.secret_key_share(1));

        let msg = gen_message(&mut rng);
        let proof = make_proof_chain(&pk_set);

        let mut signed_msg_0 = unwrap!(SignedRoutingMessage::new(
            msg.clone(),
            &sk_share_0,
            pk_set.clone(),
            proof.clone(),
        ));
        assert!(!signed_msg_0.check_fully_signed());
        assert!(signed_msg_0.check_integrity().is_err());

        let signed_msg_1 = unwrap!(SignedRoutingMessage::new(msg, &sk_share_1, pk_set, proof));
        signed_msg_0.add_signature_shares(signed_msg_1);
        assert!(signed_msg_0.check_fully_signed());

        signed_msg_0.combine_signatures();
        unwrap!(signed_msg_0.check_integrity());
    }

    #[test]
    fn invalid_signatures() {
        let mut rng = rng::new();
        let sk_set = generate_bls_threshold_secret_key(&mut rng, 4);
        let pk_set = sk_set.public_keys();

        let sk_share_0 = SectionKeyShare::new_with_position(0, sk_set.secret_key_share(0));
        let sk_share_1 = SectionKeyShare::new_with_position(1, sk_set.secret_key_share(1));
        let sk_share_2 = SectionKeyShare::new_with_position(2, sk_set.secret_key_share(2));

        let msg = gen_message(&mut rng);
        let proof = make_proof_chain(&pk_set);

        // Message with valid signature
        let mut signed_msg_0 = unwrap!(SignedRoutingMessage::new(
            msg.clone(),
            &sk_share_0,
            pk_set.clone(),
            proof.clone()
        ));

        // Message with invalid signature
        let invalid_signature_share = sk_share_1.key.sign(b"bad message");
        let metadata = SecurityMetadata::Partial(PartialSecurityMetadata {
            pk_set: pk_set.clone(),
            proof: proof.clone(),
            shares: iter::once((1, invalid_signature_share)).collect(),
        });
        let signed_msg_1 = SignedRoutingMessage::from_parts(msg.clone(), metadata);

        signed_msg_0.add_signature_shares(signed_msg_1);

        // There is enough signature shares in total, but not enough valid ones, so the message is
        // not fully signed.
        assert!(!signed_msg_0.check_fully_signed());
        assert!(signed_msg_0.check_integrity().is_err());

        // Another valid signature
        let signed_msg_2 = unwrap!(SignedRoutingMessage::new(msg, &sk_share_2, pk_set, proof));
        signed_msg_0.add_signature_shares(signed_msg_2);

        // There are now two valid signatures which is enough.
        assert!(signed_msg_0.check_fully_signed());

        signed_msg_0.combine_signatures();
        unwrap!(signed_msg_0.check_integrity());
    }

    fn make_proof_chain(pk_set: &bls::PublicKeySet) -> SectionProofChain {
        let version = 0u64;
        let prefix = Prefix::default();
        let section_key_info = SectionKeyInfo::new(version, prefix, pk_set.public_key());
        SectionProofChain::from_genesis(section_key_info)
    }

    fn gen_message(rng: &mut MainRng) -> RoutingMessage {
        use rand::distributions::Standard;

        let name = rng.gen();
        RoutingMessage {
            src: Location::Section(name),
            dst: Location::Section(name),
            content: MessageContent::UserMessage(rng.sample_iter(Standard).take(6).collect()),
        }
    }
}
