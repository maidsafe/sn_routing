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
        EldersInfo, GenesisPfxInfo, SectionKeyInfo, SectionKeyShare, SectionProofChain, TrustStatus,
    },
    crypto::{self, signing::Signature, Digest256},
    error::{Result, RoutingError},
    id::{FullId, PublicId},
    location::Location,
    states::common::{from_network_bytes, partial_from_network_bytes, to_network_bytes},
    utils::LogIdent,
    xor_space::{Prefix, XorName},
};
use bincode::serialize;
use bytes::Bytes;
use log::LogLevel;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{
    collections::BTreeSet,
    fmt::{self, Debug, Formatter},
    mem,
};

/// Wrapper of all messages.
///
/// This is the only type allowed to be sent / received on the network.
#[derive(Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum Message {
    /// A message sent between two nodes directly
    Direct(SignedDirectMessage),
    /// A message sent across the network (in transit)
    Hop(SignedRoutingMessage),
}

#[derive(Debug, Eq, PartialEq, Hash, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum PartialMessage {
    /// A message sent between two nodes directly
    Direct(SignedDirectMessage),
    /// A message sent across the network (in transit)
    Hop(PartialSignedRoutingMessage),
}

#[allow(clippy::large_enum_variant)]
pub enum MessageWithBytes {
    Hop(HopMessageWithBytes),
    Direct(SignedDirectMessage, Bytes),
}

impl MessageWithBytes {
    pub fn partial_from_bytes(bytes: Bytes) -> Result<Self> {
        match partial_from_network_bytes(&bytes)? {
            PartialMessage::Hop(msg_partial) => Ok(Self::Hop(HopMessageWithBytes::new_from_parts(
                None,
                msg_partial,
                bytes,
            ))),
            PartialMessage::Direct(msg) => Ok(Self::Direct(msg, bytes)),
        }
    }
}

/// An individual hop message that will be relayed to its destination.
#[derive(Eq, PartialEq, Clone)]
pub struct HopMessageWithBytes {
    /// Wrapped signed message.
    full_content: Option<SignedRoutingMessage>,
    /// Partial SignedRoutingMessage infos
    partial_content: PartialSignedRoutingMessage,
    /// Serialized Message as received or sent to quic_p2p.
    full_message_bytes: Bytes,
    /// Crypto hash of the full message.
    full_message_crypto_hash: Digest256,
}

impl HopMessageWithBytes {
    /// Serialize message and keep both SignedRoutingMessage and Bytes.
    pub fn new(full_content: SignedRoutingMessage, log_ident: &LogIdent) -> Result<Self> {
        let hop_msg_result = {
            let (full_content, full_message_bytes) = {
                let full_message = Message::Hop(full_content);
                let full_message_bytes = to_network_bytes(&full_message)?;

                if let Message::Hop(full_content) = full_message {
                    (full_content, full_message_bytes)
                } else {
                    unreachable!("Created as Hop can only match Hop.")
                }
            };

            let partial_content = PartialSignedRoutingMessage {
                dst: full_content.routing_message().dst,
            };

            Self::new_from_parts(Some(full_content), partial_content, full_message_bytes)
        };

        trace!(
            "{} Creating message hash({:?}) {:?}",
            log_ident,
            hop_msg_result.full_message_crypto_hash,
            hop_msg_result
                .full_content
                .as_ref()
                .expect("New HopMessageWithBytes need full_content")
                .routing_message(),
        );

        Ok(hop_msg_result)
    }

    fn new_from_parts(
        full_content: Option<SignedRoutingMessage>,
        partial_content: PartialSignedRoutingMessage,
        full_message_bytes: Bytes,
    ) -> Self {
        let full_message_crypto_hash = crypto::sha3_256(&full_message_bytes);

        Self {
            full_content,
            partial_content,
            full_message_bytes,
            full_message_crypto_hash,
        }
    }

    pub fn take_or_deserialize_signed_routing_message(&mut self) -> Result<SignedRoutingMessage> {
        self.take_signed_routing_message()
            .map_or_else(|| self.deserialize_signed_routing_message(), Ok)
    }

    pub fn full_message_bytes(&self) -> &Bytes {
        &self.full_message_bytes
    }

    pub fn full_message_crypto_hash(&self) -> &Digest256 {
        &self.full_message_crypto_hash
    }

    pub fn message_dst(&self) -> &Location {
        &self.partial_content.dst
    }

    fn take_signed_routing_message(&mut self) -> Option<SignedRoutingMessage> {
        self.full_content.take()
    }

    fn deserialize_signed_routing_message(&self) -> Result<SignedRoutingMessage> {
        match from_network_bytes(&self.full_message_bytes)? {
            Message::Hop(msg) => Ok(msg),
            Message::Direct(_msg) => Err(RoutingError::InvalidMessage),
        }
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
    pub fn last_public_key_info(&self) -> &SectionKeyInfo {
        self.proof.last_public_key_info()
    }

    pub fn verify<'a, I>(
        &self,
        content: &RoutingMessage,
        their_key_infos: I,
    ) -> Result<VerifyStatus, RoutingError>
    where
        I: IntoIterator<Item = (&'a Prefix<XorName>, &'a SectionKeyInfo)>,
    {
        if !self.proof.validate() {
            return Err(RoutingError::InvalidProvingSection);
        }

        let public_key = match self.proof.check_trust(their_key_infos) {
            TrustStatus::Trusted(key) => key,
            TrustStatus::ProofTooNew => return Ok(VerifyStatus::ProofTooNew),
            TrustStatus::ProofInvalid => return Err(RoutingError::UntrustedMessage),
        };

        let signed_bytes = serialize(content)?;
        if !public_key.verify(&self.signature, &signed_bytes) {
            return Err(RoutingError::FailedSignature);
        }

        Ok(VerifyStatus::Full)
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
    pub fn verify(&self, content: &RoutingMessage) -> Result<VerifyStatus, RoutingError> {
        if content.src.single_signing_name() != Some(self.public_id.name()) {
            // Signature is not from the source node.
            return Err(RoutingError::InvalidMessage);
        }

        let signed_bytes = serialize(content)?;
        if !self.public_id.verify(&signed_bytes, &self.signature) {
            return Err(RoutingError::FailedSignature);
        }

        Ok(VerifyStatus::Full)
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
#[derive(Debug, Eq, PartialEq, Clone, Hash, Deserialize)]
pub struct PartialSignedRoutingMessage {
    /// Destination location
    pub dst: Location,
}

/// Wrapper around a routing message, signed by the originator of the message.
/// Serialized as simple tupple to ease partial deserialization.
#[derive(Eq, PartialEq, Clone, Hash)]
pub struct SignedRoutingMessage {
    /// A request or response type message.
    content: RoutingMessage,
    /// Optional metadata for verifying the sender
    security_metadata: SecurityMetadata,
}

impl Serialize for SignedRoutingMessage {
    fn serialize<S: Serializer>(&self, serialiser: S) -> std::result::Result<S::Ok, S::Error> {
        (
            &self.content.dst,
            &self.content.src,
            &self.content.content,
            &self.security_metadata,
        )
            .serialize(serialiser)
    }
}

impl<'de> Deserialize<'de> for SignedRoutingMessage {
    fn deserialize<D: Deserializer<'de>>(deserialiser: D) -> std::result::Result<Self, D::Error> {
        let (dst, src, content, security_metadata) = Deserialize::deserialize(deserialiser)?;
        Ok(Self {
            content: RoutingMessage { src, dst, content },
            security_metadata,
        })
    }
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
        let sig = section_share.key.sign(&serialize(&content)?);
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
            signature: full_id.sign(&serialize(&content)?),
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

    /// Verify this message is properly signed and trusted.
    pub fn verify<'a, I>(&self, their_key_infos: I) -> Result<VerifyStatus, RoutingError>
    where
        I: IntoIterator<Item = (&'a Prefix<XorName>, &'a SectionKeyInfo)>,
    {
        match &self.security_metadata {
            SecurityMetadata::None | SecurityMetadata::Partial(_) => {
                Err(RoutingError::FailedSignature)
            }
            SecurityMetadata::Single(security_metadata) => security_metadata.verify(&self.content),
            SecurityMetadata::Full(security_metadata) => {
                security_metadata.verify(&self.content, their_key_infos)
            }
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
                let signed_bytes = match serialize(&self.content) {
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
    pub src: Location,
    /// Destination location
    pub dst: Location,
    /// The message content
    pub content: MessageContent,
}

impl RoutingMessage {
    /// Returns the message hash
    pub fn hash(&self) -> Result<Digest256> {
        let serialised_msg = serialize(self)?;
        Ok(crypto::sha3_256(&serialised_msg))
    }
}

#[derive(Eq, PartialEq, Clone, Hash, Serialize, Deserialize)]
// FIXME - See https://maidsafe.atlassian.net/browse/MAID-2026 for info on removing this exclusion.
#[allow(clippy::large_enum_variant)]
/// Content
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

#[derive(Eq, PartialEq, Debug)]
pub enum VerifyStatus {
    // The message has been fully verified.
    Full,
    // The message trust and integrity cannot be verified because it's proof is too new. It should
    // be relayed to other nodes who might be able to verify it.
    ProofTooNew,
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
    use std::{collections::BTreeMap, iter};

    #[test]
    fn combine_signatures() {
        let mut rng = rng::new();
        let sk_set = generate_bls_threshold_secret_key(&mut rng, 4);
        let pk_set = sk_set.public_keys();

        let sk_share_0 = SectionKeyShare::new_with_position(0, sk_set.secret_key_share(0));
        let sk_share_1 = SectionKeyShare::new_with_position(1, sk_set.secret_key_share(1));

        let msg = gen_message(&mut rng);
        let proof = make_proof_chain(&pk_set);
        let their_key_infos = make_their_key_infos(&pk_set);

        let mut signed_msg_0 = unwrap!(SignedRoutingMessage::new(
            msg.clone(),
            &sk_share_0,
            pk_set.clone(),
            proof.clone(),
        ));
        assert!(!signed_msg_0.check_fully_signed());
        assert!(signed_msg_0.verify(&their_key_infos).is_err());

        let signed_msg_1 = unwrap!(SignedRoutingMessage::new(msg, &sk_share_1, pk_set, proof));
        signed_msg_0.add_signature_shares(signed_msg_1);
        assert!(signed_msg_0.check_fully_signed());

        signed_msg_0.combine_signatures();
        assert_eq!(
            unwrap!(signed_msg_0.verify(&their_key_infos)),
            VerifyStatus::Full
        );
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
        let their_key_infos = make_their_key_infos(&pk_set);

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
        assert!(signed_msg_0.verify(&their_key_infos).is_err());

        // Another valid signature
        let signed_msg_2 = unwrap!(SignedRoutingMessage::new(msg, &sk_share_2, pk_set, proof));
        signed_msg_0.add_signature_shares(signed_msg_2);

        // There are now two valid signatures which is enough.
        assert!(signed_msg_0.check_fully_signed());

        signed_msg_0.combine_signatures();
        assert_eq!(
            unwrap!(signed_msg_0.verify(&their_key_infos)),
            VerifyStatus::Full
        );
    }

    fn make_section_key_info(pk_set: &bls::PublicKeySet) -> SectionKeyInfo {
        let version = 0u64;
        let prefix = Prefix::default();
        SectionKeyInfo::new(version, prefix, pk_set.public_key())
    }

    #[test]
    fn serialise_and_partial_at_hop_message() {
        let mut rng = rng::new();
        let full_id = FullId::gen(&mut rng);
        let msg = gen_message(&mut rng);

        let signed_msg_org = unwrap!(SignedRoutingMessage::single_source(msg, &full_id,));

        let msg = unwrap!(HopMessageWithBytes::new(
            signed_msg_org.clone(),
            &LogIdent::new("node")
        ));
        let bytes = msg.full_message_bytes();
        let full_msg = unwrap!(from_network_bytes(bytes));
        let partial_msg = unwrap!(partial_from_network_bytes(bytes));
        let partial_msg_head = unwrap!(partial_from_network_bytes(&bytes.slice(0, 40)));

        let expected_partial = PartialMessage::Hop(PartialSignedRoutingMessage {
            dst: signed_msg_org.routing_message().dst,
        });
        let signed_msg = if let Message::Hop(signed_msg) = full_msg {
            Some(signed_msg)
        } else {
            None
        };

        assert_eq!(partial_msg, expected_partial);
        assert_eq!(partial_msg_head, expected_partial);
        assert_eq!(signed_msg, Some(signed_msg_org))
    }

    fn make_proof_chain(pk_set: &bls::PublicKeySet) -> SectionProofChain {
        SectionProofChain::from_genesis(make_section_key_info(pk_set))
    }

    fn make_their_key_infos(
        pk_set: &bls::PublicKeySet,
    ) -> BTreeMap<Prefix<XorName>, SectionKeyInfo> {
        let key_info = make_section_key_info(pk_set);
        iter::once((*key_info.prefix(), key_info)).collect()
    }

    fn gen_message(rng: &mut MainRng) -> RoutingMessage {
        use rand::distributions::Standard;

        RoutingMessage {
            src: Location::Section(rng.gen()),
            dst: Location::Section(rng.gen()),
            content: MessageContent::UserMessage(rng.sample_iter(Standard).take(6).collect()),
        }
    }
}
