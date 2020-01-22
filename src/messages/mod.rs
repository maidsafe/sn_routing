// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

pub(crate) mod security_metadata;

use crate::{
    chain::{
        Chain, EldersInfo, GenesisPfxInfo, SectionKeyInfo, SectionKeyShare, SectionProofChain,
    },
    crypto::{self, Digest256},
    error::{Result, RoutingError},
    id::FullId,
    location::Location,
    parsec,
    relocation::{RelocatePayload, SignedRelocateDetails},
    xor_space::{Prefix, XorName},
    ConnectionInfo,
};
use bytes::Bytes;
use log::LogLevel;
use maidsafe_utilities::serialisation::{deserialise, serialise};
use security_metadata::{
    FullSecurityMetadata, PartialSecurityMetadata, SecurityMetadata, SingleSrcSecurityMetadata,
};
use std::{
    collections::BTreeSet,
    fmt::{self, Debug, Formatter},
    hash::{Hash, Hasher},
    mem,
};

/// A valid (signed) message
#[derive(Eq, PartialEq, Clone, Hash, Serialize, Deserialize)]
pub struct Message {
    /// unsigned message
    pub inner: Inner,
    ///sig : Message is only valid if signed
    pub sig: SecurityMetadata,
}

impl Message {
    /// Network message as sent over wire
    pub fn new_section_message(
        inner: Inner,
        section_share: &SectionKeyShare,
        pk_set: bls::PublicKeySet,
        proof: SectionProofChain,
    ) -> Result<Self> {
        let mut signatures = BTreeSet::new();
        let sig = section_share.key.sign(&serialise(&inner)?);
        let _ = signatures.insert((section_share.index, sig));
        let partial_metadata = PartialSecurityMetadata {
            shares: signatures,
            pk_set,
            proof,
        };
        Ok(Self {
            inner,
            sig: SecurityMetadata::Partial(partial_metadata),
        })
    }

    pub fn hash(&self) -> Result<Digest256> {
        let serialised_msg = serialise(self)?;
        Ok(crypto::sha3_256(&serialised_msg))
    }

    /// Creates a `Message` security metadata from a single source
    pub fn new_single_source_mesage(inner: Inner, full_id: &FullId) -> Result<Self> {
        let single_metadata = SingleSrcSecurityMetadata {
            public_id: *full_id.public_id(),
            signature: full_id.sign(&serialise(&inner)?),
        };

        Ok(Self {
            inner,
            sig: SecurityMetadata::Single(single_metadata),
        })
    }
    /// Creates a `SignedRoutingMessage` without security metadata
    #[cfg(all(test, feature = "mock_base"))]
    pub fn insecure(content: RoutingMessage) -> Self {
        Self {
            inner,
            sig: SecurityMetadata::None,
        }
    }

    /// Creates a `SignedRoutingMessage` from content and security metadata.
    /// Note: this function does not verify the metadata matches the content. Need to call
    /// `check_integrity` for that.
    pub fn from_parts(inner: Inner, sig: SecurityMetadata) -> Self {
        Self { inner, sig }
    }

    /// Confirms the signatures.
    pub fn check_integrity(&self) -> Result<()> {
        match self.sig {
            SecurityMetadata::None | SecurityMetadata::Partial(_) => {
                Err(RoutingError::FailedSignature)
            }
            SecurityMetadata::Single(ref security_metadata) => {
                if self.inner.src.single_signing_name()
                    != Some(security_metadata.public_id().name())
                {
                    // Signature is not from the source node.
                    return Err(RoutingError::InvalidMessage);
                }

                let signed_bytes = serialise(&self.inner)?;
                if !security_metadata.verify_sig(&signed_bytes) {
                    return Err(RoutingError::FailedSignature);
                }
                Ok(())
            }
            SecurityMetadata::Full(ref security_metadata) => {
                let signed_bytes = serialise(&self.inner)?;
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
        match self.sig {
            SecurityMetadata::Full(ref security_metadata) => {
                chain.check_trust(security_metadata.proof_chain())
            }
            SecurityMetadata::None | SecurityMetadata::Single(_) => true,
            SecurityMetadata::Partial(_) => false,
        }
    }

    /// Returns the security metadata validating the message.
    pub fn source_section_key_info(&self) -> Option<&SectionKeyInfo> {
        match self.sig {
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
        if self.inner.src.is_multiple() {
            if let (
                SecurityMetadata::Partial(self_partial),
                SecurityMetadata::Partial(other_partial),
            ) = (&mut self.sig, &mut msg.sig)
            {
                self_partial.shares().append(&mut other_partial.shares());
            }
        }
    }

    /// Combines the signatures into a single BLS signature
    pub fn combine_signatures(&mut self) {
        match mem::replace(&mut self.sig, SecurityMetadata::None) {
            SecurityMetadata::Partial(partial) => {
                if let Ok(full_sig) = partial
                    .pk_set()
                    .combine_signatures(partial.shares().iter().map(|(key, sig)| (*key, sig)))
                {
                    self.sig = SecurityMetadata::Full(FullSecurityMetadata {
                        proof: partial.proof(),
                        signature: full_sig,
                    });
                } else {
                    log_or_panic!(
                        LogLevel::Error,
                        "Combining signatures failed on {:?}! Part Shares: {:?}, Part Set: {:?}, \
                         Partial: {:?}",
                        self,
                        partial.shares(),
                        partial.pk_set(),
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
    pub fn into_parts(self) -> (Inner, SecurityMetadata) {
        (self.inner, self.sig)
    }

    /// The routing message that was signed.
    pub fn inner(&self) -> &Inner {
        &self.inner
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

        let invalid_signatures = match self.sig {
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
                let signed_bytes = match serialise(&self.inner) {
                    Ok(serialised) => serialised,
                    Err(error) => {
                        warn!("Failed to serialise {:?}: {:?}", self, error);
                        return false;
                    }
                };

                let invalid_signatures = partial.find_invalid_sigs(&signed_bytes);
                for invalid_signature in &invalid_signatures {
                    let _ = partial.shares().remove(invalid_signature);
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
        match &self.sig {
            SecurityMetadata::None => !self.inner.src.is_multiple(),
            SecurityMetadata::Partial(partial) => {
                partial.shares().len() > partial.pk_set().threshold()
            }
            SecurityMetadata::Full(_) | SecurityMetadata::Single(_) => true,
        }
    }

    pub(crate) fn to_network_bytes(&self) -> Result<Bytes, RoutingError> {
        Ok(Bytes::from(serialise(&self)?))
    }

    pub(crate) fn from_network_bytes(data: &Bytes) -> Result<Self, RoutingError> {
        deserialise(&data[..]).map_err(RoutingError::SerialisationError)
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

/// A message content with source and destination locations.
#[derive(Eq, PartialEq, Clone, Hash, Serialize, Deserialize)]
pub struct Inner {
    /// Source location
    pub src: Location,
    /// Destination location
    pub dst: Location,
    /// The message content
    pub content: MessageContent,
}

impl Inner {
    /// construct a new message
    pub fn new(src: Location, dst: Location, content: MessageContent) -> Self {
        Self { src, dst, content }
    }
    pub(crate) fn variant(&self) -> MessageContent {
        self.content
    }
    pub(crate) fn src(&self) -> Location {
        self.src
    }
    pub(crate) fn dst(&self) -> Location {
        self.dst
    }
    /// Returns
    pub fn hash(&self) -> Result<Digest256> {
        let serialised_msg = serialise(self)?;
        Ok(crypto::sha3_256(&serialised_msg))
    }
    pub(crate) fn to_network_bytes(&self) -> Result<Bytes, RoutingError> {
        Ok(Bytes::from(serialise(&self)?))
    }

    pub(crate) fn from_network_bytes(data: &Bytes) -> Result<Self, RoutingError> {
        deserialise(&data[..]).map_err(RoutingError::SerialisationError)
    }
}

#[derive(Eq, PartialEq, Clone, Serialize, Deserialize)]
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
    /// Sent from members of a section or group message's source location to the first hop. The
    /// message will only be relayed once enough signatures have been accumulated.
    MessageSignature(Box<Message>),
    /// Sent from a newly connected peer to the bootstrap node to request connection infos of
    /// members of the section matching the given name.
    BootstrapRequest(XorName),
    /// Sent from the bootstrap node to a peer in response to `BootstrapRequest`. It can either
    /// accept the peer into the section, or redirect it to another set of bootstrap peers
    BootstrapResponse(BootstrapResponse),
    /// Sent from a bootstrapping peer to the section that responded with a
    /// `BootstrapResponse::Join` to its `BootstrapRequest`.
    JoinRequest(Box<JoinRequest>),
    /// Sent from members of a section to a joining node in response to `ConnectionRequest`
    ConnectionResponse,
    /// Sent from Adults and Infants to Elders. Updates Elders about the sender's knowledge of its
    /// own section.
    MemberKnowledge(MemberKnowledge),
    /// Parsec request message
    ParsecRequest(u64, parsec::Request),
    /// Parsec response message
    ParsecResponse(u64, parsec::Response),
    /// Send from a section to the node being relocated.
    Relocate(Box<SignedRelocateDetails>),
}

/// Response to a BootstrapRequest
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Debug, Hash)]
pub enum BootstrapResponse {
    /// This response means that the new peer is clear to join the section. The connection infos of
    /// the section elders and the section prefix are provided.
    Join(EldersInfo),
    /// The new peer should retry bootstrapping with another section. The set of connection infos
    /// of the members of that section is provided.
    Rebootstrap(Vec<ConnectionInfo>),
}

/// Request to join a section
#[derive(Eq, Clone, PartialEq, Serialize, Deserialize, Hash)]
pub struct JoinRequest {
    /// The section version to join
    pub elders_version: u64,
    /// If the peer is being relocated, contains `RelocatePayload`. Otherwise contains `None`.
    pub relocate_payload: Option<RelocatePayload>,
}

/// Node's knowledge about its own section.
#[derive(Default, Clone, Copy, Eq, PartialEq, Serialize, Deserialize, Debug, Hash)]
pub struct MemberKnowledge {
    pub elders_version: u64,
    pub parsec_version: u64,
}

impl MemberKnowledge {
    pub fn update(&mut self, other: MemberKnowledge) {
        self.elders_version = self.elders_version.max(other.elders_version);
        self.parsec_version = self.parsec_version.max(other.parsec_version);
    }
}

impl Debug for Inner {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "Inner Message  content: {:?}", self)
    }
}

impl Debug for Message {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "Message  content: {:?}, security_metadata: {:?}",
            self.inner, self.sig
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
            MessageSignature(msg) => write!(formatter, "MessageSignature({:?})", msg),
            BootstrapRequest(name) => write!(formatter, "BootstrapRequest({})", name),
            BootstrapResponse(response) => write!(formatter, "BootstrapResponse({:?})", response),
            JoinRequest(join_request) => write!(
                formatter,
                "JoinRequest({}, {:?})",
                join_request.elders_version,
                join_request
                    .relocate_payload
                    .as_ref()
                    .map(|payload| payload.details.content())
            ),
            ConnectionResponse => write!(formatter, "ConnectionResponse"),
            ParsecRequest(v, _) => write!(formatter, "ParsecRequest({}, _)", v),
            ParsecResponse(v, _) => write!(formatter, "ParsecResponse({}, _)", v),
            MemberKnowledge(payload) => write!(formatter, "{:?}", payload),
            Relocate(payload) => write!(formatter, "Relocate({:?})", payload.content()),
        }
    }
}
// Note: we need explicit impl here, because `parsec::Request` and `parsec::Response` don't
// implement `Hash`.
// We don't need explicit `PartialEq` impl, because `parsec::Request/Response` do implement it.
// So it's OK to silence this clippy lint:
#[allow(clippy::derive_hash_xor_eq)]
impl Hash for MessageContent {
    fn hash<H: Hasher>(&self, state: &mut H) {
        mem::discriminant(self).hash(state);
        use self::MessageContent::*;
        match self {
            NeighbourInfo(info) => info.hash(state),
            UserMessage(content) => content.hash(state),
            NodeApproval(gen_info) => gen_info.hash(state),
            AckMessage {
                src_prefix,
                ack_version,
            } => self.hash(state),
            GenesisUpdate(info) => info.hash(state),
            MessageSignature(msg) => msg.hash(state),
            BootstrapRequest(name) => name.hash(state),
            BootstrapResponse(response) => response.hash(state),
            JoinRequest(join_request) => join_request.hash(state),
            ConnectionResponse => (),
            MemberKnowledge(payload) => payload.hash(state),
            ParsecRequest(version, request) => {
                version.hash(state);
                // Fake hash via serialisation
                serialise(&request).ok().hash(state)
            }
            ParsecResponse(version, response) => {
                version.hash(state);
                // Fake hash via serialisation
                serialise(&response).ok().hash(state)
            }
            Relocate(details) => details.hash(state),
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

        let mut signed_msg_0 = unwrap!(Message::new_section_message(
            msg.clone(),
            &sk_share_0,
            pk_set.clone(),
            proof.clone(),
        ));
        assert!(!signed_msg_0.check_fully_signed());
        assert!(signed_msg_0.check_integrity().is_err());

        let signed_msg_1 = unwrap!(Message::new_Section_message(
            msg,
            &sk_share_1,
            pk_set,
            proof
        ));
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
        let mut signed_msg_0 = unwrap!(Message::new_Section_message(
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
        let signed_msg_1 = Message::from_parts(msg.clone(), metadata);

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
