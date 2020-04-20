// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod accumulating_message;
mod hash;
mod src_authority;
mod variant;
mod with_bytes;

pub use self::{
    accumulating_message::{AccumulatingMessage, PlainMessage},
    hash::MessageHash,
    src_authority::SrcAuthority,
    variant::{BootstrapResponse, JoinRequest, MemberKnowledge, Variant},
    with_bytes::MessageWithBytes,
};
use crate::{
    error::{Result, RoutingError},
    id::{FullId, PublicId},
    location::DstLocation,
    section::SectionKeyInfo,
    xor_space::{Prefix, XorName},
};
use bytes::Bytes;
use itertools::Itertools;
use std::{
    fmt::{self, Debug, Formatter},
    net::SocketAddr,
};

/// Message sent over the network.
#[derive(Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct Message {
    /// Destination location.
    pub dst: DstLocation,
    /// Source authority.
    pub src: SrcAuthority,
    /// The body of the message.
    pub variant: Variant,
}

/// Partially deserialized message.
#[derive(Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Debug)]
pub struct PartialMessage {
    /// Destination location.
    pub dst: DstLocation,
}

impl PartialMessage {
    /// Deserialize the message.
    pub fn from_bytes(bytes: &Bytes) -> Result<Self> {
        Ok(bincode::deserialize(&bytes[..])?)
    }
}

impl Message {
    /// Deserialize the message.
    pub(crate) fn from_bytes(bytes: &Bytes) -> Result<Self> {
        Ok(bincode::deserialize(&bytes[..])?)
    }

    /// Serialize the message.
    pub(crate) fn to_bytes(&self) -> Result<Bytes> {
        Ok(bincode::serialize(self)?.into())
    }

    /// Creates a message from single node.
    pub(crate) fn single_src(src: &FullId, dst: DstLocation, variant: Variant) -> Result<Self> {
        let serialized = serialize_for_node_signing(src.public_id(), &dst, &variant)?;
        let signature = src.sign(&serialized);

        Ok(Self {
            dst,
            src: SrcAuthority::Node {
                public_id: *src.public_id(),
                signature,
            },
            variant,
        })
    }

    /// Verify this message is properly signed and trusted.
    pub(crate) fn verify<'a, I>(&'a self, their_key_infos: I) -> Result<VerifyStatus>
    where
        I: IntoIterator<Item = (&'a Prefix<XorName>, &'a SectionKeyInfo)>,
    {
        self.src.verify(&self.dst, &self.variant, their_key_infos)
    }

    /// Returns the latest section key from the message proof.
    pub fn source_section_key_info(&self) -> Option<&SectionKeyInfo> {
        match &self.src {
            SrcAuthority::Node { .. } => None,
            SrcAuthority::Section { proof, .. } => proof.last_new_key_info(),
        }
    }

    pub(crate) fn into_queued(self, sender: Option<SocketAddr>) -> QueuedMessage {
        QueuedMessage {
            message: self,
            sender,
        }
    }

    pub(crate) fn to_partial(&self) -> PartialMessage {
        PartialMessage { dst: self.dst }
    }
}

impl Debug for Message {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        formatter
            .debug_struct("Message")
            .field("src", &self.src.location())
            .field("dst", &self.dst)
            .field("variant", &self.variant)
            .finish()
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

pub struct QueuedMessage {
    pub message: Message,
    pub sender: Option<SocketAddr>,
}

pub fn log_verify_failure<'a, T, I>(msg: &T, error: &RoutingError, their_key_infos: I)
where
    T: Debug,
    I: IntoIterator<Item = (&'a Prefix<XorName>, &'a SectionKeyInfo)>,
{
    log_or_panic!(
        log::Level::Error,
        "Verification failed: {:?} - {:?} --- [{:?}]",
        msg,
        error,
        their_key_infos.into_iter().format(", ")
    )
}

fn serialize_for_section_signing(dst: &DstLocation, variant: &Variant) -> Result<Vec<u8>> {
    Ok(bincode::serialize(&(dst, variant))?)
}

fn serialize_for_node_signing(
    src: &PublicId,
    dst: &DstLocation,
    variant: &Variant,
) -> Result<Vec<u8>> {
    Ok(bincode::serialize(&(src, dst, variant))?)
}
