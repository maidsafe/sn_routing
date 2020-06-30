// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod accumulating_message;
mod hash;
mod message_accumulator;
mod src_authority;
mod variant;

pub use self::{
    accumulating_message::{AccumulatingMessage, PlainMessage},
    hash::MessageHash,
    message_accumulator::MessageAccumulator,
    src_authority::SrcAuthority,
    variant::{BootstrapResponse, JoinRequest, Variant},
};
use crate::{
    error::{Result, RoutingError},
    id::FullId,
    location::DstLocation,
    section::SectionProofChain,
};

use bytes::Bytes;
use err_derive::Error;
use itertools::Itertools;
use std::{
    fmt::{self, Debug, Formatter},
    net::SocketAddr,
};
use xor_name::Prefix;

/// Message sent over the network.
#[derive(Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct Message {
    /// Destination location.
    dst: DstLocation,
    /// Source authority.
    /// Messages do not need to sign this field as it is all verifiable (i.e. if the sig validates
    /// agains the public key and we know the pub key then we are good. If the proof is not recognised we
    /// ask for a longer chain that can be recognised). Therefor we don't need to sign this field.
    src: SrcAuthority,
    /// The body of the message.
    variant: Variant,
    /// Source's knowledge of the destination section key. If present, the destination can use it
    /// to determine the length of the proof of messages sent to the source so the source would
    /// trust it (the proof needs to start at this key).
    dst_key: Option<bls::PublicKey>,

    /// Serialised message, this is a signed and fully serialised message ready to send.
    #[serde(skip)]
    serialized: Bytes,
    #[serde(skip)]
    hash: MessageHash,
}

impl Message {
    /// Deserialize the message. Only called on message receipt.
    pub(crate) fn from_bytes(bytes: &Bytes) -> Result<Self, CreateError> {
        let mut msg: Message = bincode::deserialize(&bytes[..])?;

        let signed_bytes = bincode::serialize(&SignableView {
            dst: &msg.dst,
            dst_key: msg.dst_key.as_ref(),
            variant: &msg.variant,
        })?;

        match msg.src.clone() {
            SrcAuthority::Node {
                public_id,
                signature,
            } => {
                if public_id.verify(&signed_bytes, &signature) {
                    msg.serialized = bytes.clone();
                    msg.hash = MessageHash::from_bytes(bytes);
                    Ok(msg)
                } else {
                    Err(CreateError::FailedSignature)
                }
            }
            SrcAuthority::Section {
                signature,
                proof_chain,
                ..
            } => {
                // FIXME Assumes the nodes proof last key is the one signing this message
                if proof_chain.last_key().verify(&signature, &signed_bytes) {
                    msg.serialized = bytes.clone();
                    msg.hash = MessageHash::from_bytes(bytes);
                    Ok(msg)
                } else {
                    Err(CreateError::FailedSignature)
                }
            }
        }
    }

    /// send across wire
    pub(crate) fn to_bytes(&self) -> Bytes {
        self.serialized.clone()
    }

    /// Creates a signed message where signature is assumed valid.
    fn new_signed(
        src: SrcAuthority,
        dst: DstLocation,
        dst_key: Option<bls::PublicKey>,
        variant: Variant,
    ) -> Result<Message, CreateError> {
        let mut msg = Message {
            dst,
            src,
            variant,
            dst_key,
            serialized: Default::default(),
            hash: Default::default(),
        };

        msg.serialized = bincode::serialize(&msg)?.into();
        msg.hash = MessageHash::from_bytes(&msg.serialized);

        Ok(msg)
    }

    /// Creates a signed message from single node.
    pub(crate) fn single_src(
        src: &FullId,
        dst: DstLocation,
        dst_key: Option<bls::PublicKey>,
        variant: Variant,
    ) -> Result<Self, CreateError> {
        let serialized = bincode::serialize(&SignableView {
            dst: &dst,
            dst_key: dst_key.as_ref(),
            variant: &variant,
        })?;
        let signature = src.sign(&serialized);
        let src = SrcAuthority::Node {
            public_id: *src.public_id(),
            signature,
        };

        Self::new_signed(src, dst, dst_key, variant)
    }

    /// Creates a message but does not enforce that it is valid. Use only for testing.
    #[cfg(all(test, feature = "mock"))]
    pub(crate) fn unverified(
        src: SrcAuthority,
        dst: DstLocation,
        dst_key: Option<bls::PublicKey>,
        variant: Variant,
    ) -> Result<Self, CreateError> {
        Self::new_signed(src, dst, dst_key, variant)
    }

    /// Verify this message is properly signed and trusted.
    pub(crate) fn verify<'a, I>(&'a self, their_keys: I) -> Result<VerifyStatus>
    where
        I: IntoIterator<Item = (&'a Prefix, &'a bls::PublicKey)>,
    {
        self.src
            .verify(&self.dst, self.dst_key.as_ref(), &self.variant, their_keys)
    }

    pub(crate) fn into_queued(self, sender: Option<SocketAddr>) -> QueuedMessage {
        QueuedMessage {
            message: self,
            sender,
        }
    }

    /// Getter
    pub fn dst(&self) -> &DstLocation {
        &self.dst
    }

    /// Getter
    pub fn variant(&self) -> &Variant {
        &self.variant
    }

    /// Getter
    pub fn src(&self) -> &SrcAuthority {
        &self.src
    }

    /// Getter
    pub fn dst_key(&self) -> &Option<bls::PublicKey> {
        &self.dst_key
    }
    /// Getter
    pub fn hash(&self) -> &MessageHash {
        &self.hash
    }

    // Extend the current message proof so it starts at `new_first_key` while keeping the last key
    // (and therefore the signature) intact.
    #[cfg_attr(feature = "mock_base", allow(clippy::trivially_copy_pass_by_ref))]
    pub(crate) fn extend_proof_chain(
        mut self,
        new_first_key: &bls::PublicKey,
        section_proof_chain: &SectionProofChain,
    ) -> Result<Self, ExtendProofChainError> {
        let proof_chain = match &mut self.src {
            SrcAuthority::Section { proof_chain, .. } => proof_chain,
            SrcAuthority::Node { .. } => return Err(ExtendProofChainError::MustBeSection),
        };

        if proof_chain.has_key(new_first_key) {
            return Err(ExtendProofChainError::AlreadySufficient);
        }

        let index_from = if let Some(index) = section_proof_chain.index_of(new_first_key) {
            index
        } else {
            return Err(ExtendProofChainError::InvalidFirstKey);
        };

        let index_to = if let Some(index) = section_proof_chain.index_of(proof_chain.last_key()) {
            index
        } else {
            return Err(ExtendProofChainError::InvalidLastKey);
        };

        *proof_chain = section_proof_chain.slice(index_from..=index_to);

        Ok(Self::new_signed(
            self.src,
            self.dst,
            self.dst_key,
            self.variant,
        )?)
    }
}

impl Debug for Message {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        formatter
            .debug_struct("Message")
            .field("src", &self.src.src_location())
            .field("dst", &self.dst)
            .field("variant", &self.variant)
            .finish()
    }
}

#[derive(Eq, PartialEq, Debug)]
pub enum VerifyStatus {
    // The message has been fully verified.
    Full,
    // The message trust and integrity cannot be verified because it's proof is not trusted by us,
    // even though it is valid. The message should be relayed to other nodes who might be able to
    // verify it.
    Unknown,
}

impl VerifyStatus {
    pub fn require_full(self) -> Result<(), RoutingError> {
        match self {
            Self::Full => Ok(()),
            Self::Unknown => Err(RoutingError::UntrustedMessage),
        }
    }
}

pub struct QueuedMessage {
    pub message: Message,
    pub sender: Option<SocketAddr>,
}

pub fn log_verify_failure<'a, T, I>(msg: &T, error: &RoutingError, their_keys: I)
where
    T: Debug,
    I: IntoIterator<Item = (&'a Prefix, &'a bls::PublicKey)>,
{
    log_or_panic!(
        log::Level::Error,
        "Verification failed: {:?} - {:?} --- [{:?}]",
        msg,
        error,
        their_keys.into_iter().format(", ")
    )
}

/// Status of an incomming message.
pub enum MessageStatus {
    /// Message is useful and should be handled.
    Useful,
    /// Message is useless and should be discarded.
    Useless,
    /// Message trust can't be established.
    Untrusted,
    /// We don't know how to handle the message because we are not in the right state (e.g. it
    /// needs elder but we are not)
    Unknown,
}

#[derive(Debug, Error)]
pub enum CreateError {
    #[error(display = "bincode error: {}", _0)]
    Bincode(#[error(source)] bincode::Error),
    #[error(display = "signature check failed")]
    FailedSignature,
}

impl From<CreateError> for RoutingError {
    fn from(src: CreateError) -> Self {
        match src {
            CreateError::Bincode(inner) => Self::Bincode(inner),
            CreateError::FailedSignature => Self::FailedSignature,
        }
    }
}

/// Error returned from `SrcAuthority::extend_proof`.
#[derive(Debug, Error)]
pub enum ExtendProofChainError {
    #[error(display = "extending proof chain not supported on messages with Node src")]
    MustBeSection,
    #[error(display = "invalid first key")]
    InvalidFirstKey,
    #[error(display = "invalid last key")]
    InvalidLastKey,
    #[error(display = "proof chain already sufficient")]
    AlreadySufficient,
    #[error(display = "failed to re-create the message: {}", _0)]
    Create(#[error(source)] CreateError),
}

// View of a message that can be serialized for the purpose of signing.
#[derive(Serialize)]
pub(crate) struct SignableView<'a> {
    // TODO: why don't we include also `src`?
    dst: &'a DstLocation,
    dst_key: Option<&'a bls::PublicKey>,
    variant: &'a Variant,
}
