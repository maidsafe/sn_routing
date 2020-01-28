// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod direct;
mod security_metadata;
mod with_bytes;

use self::security_metadata::{
    FullSecurityMetadata, PartialSecurityMetadata, SingleSrcSecurityMetadata,
};
pub use self::{
    direct::{BootstrapResponse, DirectMessage, JoinRequest, MemberKnowledge, SignedDirectMessage},
    security_metadata::SecurityMetadata,
    with_bytes::{HopMessageWithBytes, MessageWithBytes},
};
use crate::{
    chain::{EldersInfo, GenesisPfxInfo, SectionKeyInfo, SectionKeyShare, SectionProofSlice},
    crypto::{self, Digest256},
    error::{Result, RoutingError},
    id::FullId,
    location::Location,
    relocation::RelocateDetails,
    xor_space::{Prefix, XorName},
};
use bincode::serialize;
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
        proof: SectionProofSlice,
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

    /// Verifies this message is properly signed and trusted.
    pub fn verify<'a, I>(&'a self, their_key_infos: I) -> Result<VerifyStatus, RoutingError>
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
            SecurityMetadata::Full(ref security_metadata) => security_metadata.last_new_key_info(),
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
    pub(crate) fn proof_chain(&self) -> Option<&SectionProofSlice> {
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
    /// Send to a node being relocated from its own section.
    Relocate(Box<RelocateDetails>),
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
            Relocate(payload) => write!(formatter, "Relocate({:?})", payload),
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

impl VerifyStatus {
    pub fn require_full(self) -> Result<(), RoutingError> {
        match self {
            Self::Full => Ok(()),
            Self::ProofTooNew => Err(RoutingError::UntrustedMessage),
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

    fn make_proof_chain(pk_set: &bls::PublicKeySet) -> SectionProofSlice {
        SectionProofSlice::from_genesis(make_section_key_info(pk_set))
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
