// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod accumulating_message;
mod direct;
mod src_authority;
mod variant;
mod with_bytes;

pub use self::{
    accumulating_message::AccumulatingMessage,
    direct::SignedDirectMessage,
    src_authority::SrcAuthority,
    variant::{BootstrapResponse, JoinRequest, MemberKnowledge, Variant},
    with_bytes::{HopMessageWithBytes, MessageWithBytes},
};
use crate::{
    chain::SectionKeyInfo,
    error::{Result, RoutingError},
    id::{FullId, P2pNode},
    location::{DstLocation, SrcLocation},
    xor_space::{Prefix, XorName},
};
use bincode::serialize;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::{self, Debug, Formatter};

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
    pub dst: DstLocation,
}

/// Wrapper around a routing message, signed by the originator of the message.
/// Serialized as simple tupple to ease partial deserialization.
#[derive(Eq, PartialEq, Clone, Hash)]
pub struct SignedRoutingMessage {
    /// A request or response type message.
    content: RoutingMessage,
    /// Source authority.
    src_authority: SrcAuthority,
}

impl Serialize for SignedRoutingMessage {
    fn serialize<S: Serializer>(&self, serialiser: S) -> std::result::Result<S::Ok, S::Error> {
        (
            &self.content.dst,
            &self.content.src,
            &self.content.content,
            &self.src_authority,
        )
            .serialize(serialiser)
    }
}

impl<'de> Deserialize<'de> for SignedRoutingMessage {
    fn deserialize<D: Deserializer<'de>>(deserialiser: D) -> std::result::Result<Self, D::Error> {
        let (dst, src, content, src_authority) = Deserialize::deserialize(deserialiser)?;
        Ok(Self {
            content: RoutingMessage { src, dst, content },
            src_authority,
        })
    }
}

impl SignedRoutingMessage {
    /// Creates a `SignedRoutingMessage` security metadata from a single source
    pub fn single_source(content: RoutingMessage, full_id: &FullId) -> Result<Self> {
        let src_authority = SrcAuthority::Node {
            public_id: *full_id.public_id(),
            signature: full_id.sign(&serialize(&content)?),
        };

        Ok(Self {
            content,
            src_authority,
        })
    }

    /// Creates a `SignedRoutingMessage` from content and security metadata.
    /// Note: this function does not verify the metadata matches the content. Need to call
    /// `check_integrity` for that.
    pub fn from_parts(content: RoutingMessage, src_authority: SrcAuthority) -> Self {
        Self {
            content,
            src_authority,
        }
    }

    /// Verifies this message is properly signed and trusted.
    pub fn verify<'a, I>(&'a self, their_key_infos: I) -> Result<VerifyStatus, RoutingError>
    where
        I: IntoIterator<Item = (&'a Prefix<XorName>, &'a SectionKeyInfo)>,
    {
        self.src_authority.verify(&self.content, their_key_infos)
    }

    /// Returns the security metadata validating the message.
    pub fn source_section_key_info(&self) -> Option<&SectionKeyInfo> {
        self.src_authority.last_new_key_info()
    }

    /// Returns the content and the security metadata.
    pub fn into_parts(self) -> (RoutingMessage, SrcAuthority) {
        (self.content, self.src_authority)
    }

    /// The routing message that was signed.
    pub fn routing_message(&self) -> &RoutingMessage {
        &self.content
    }

    pub(crate) fn into_queued(self) -> QueuedMessage {
        QueuedMessage::Hop(self)
    }
}

/// A routing message with source and destination locations.
#[derive(Eq, PartialEq, Clone, Hash, Debug, Serialize, Deserialize)]
pub struct RoutingMessage {
    /// Source location
    pub src: SrcLocation,
    /// Destination location
    pub dst: DstLocation,
    /// The message content
    pub content: Variant,
}

impl Debug for SignedRoutingMessage {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "SignedRoutingMessage {{ content: {:?}, src_authority: {:?} }}",
            self.content, self.src_authority
        )
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

pub enum QueuedMessage {
    Hop(SignedRoutingMessage),
    Direct(P2pNode, Variant),
}
