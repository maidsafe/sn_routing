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

pub(crate) use self::{
    accumulating_message::{AccumulatingMessage, PlainMessage},
    message_accumulator::MessageAccumulator,
    variant::{BootstrapResponse, JoinRequest, Variant},
};
pub use self::{hash::MessageHash, src_authority::SrcAuthority};
use crate::{
    error::{Error, Result},
    id::FullId,
    location::DstLocation,
    section::{ExtendError, SectionProofChain, TrustStatus},
};

use bytes::Bytes;
use err_derive::Error;
use itertools::Itertools;
use std::fmt::{self, Debug, Formatter};
use xor_name::Prefix;

/// Message sent over the network.
#[derive(Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub(crate) struct Message {
    /// Source authority.
    /// Messages do not need to sign this field as it is all verifiable (i.e. if the sig validates
    /// agains the public key and we know the pub key then we are good. If the proof is not recognised we
    /// ask for a longer chain that can be recognised). Therefor we don't need to sign this field.
    src: SrcAuthority,
    /// Destination location.
    dst: DstLocation,
    /// The body of the message.
    variant: Variant,
    /// Proof chain to verify the message trust. Does not need to be signed.
    proof_chain: Option<SectionProofChain>,
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

        match &msg.src {
            SrcAuthority::Node {
                public_id,
                signature,
            } => {
                if !public_id.verify(&signed_bytes, signature) {
                    error!("Failed signature: {:?}", msg);
                    return Err(CreateError::FailedSignature);
                }
            }
            SrcAuthority::Section { signature, .. } => {
                if let Some(proof_chain) = msg.proof_chain.as_ref() {
                    // FIXME Assumes the nodes proof last key is the one signing this message
                    if !proof_chain.last_key().verify(signature, &signed_bytes) {
                        error!("Failed signature: {:?}", msg);
                        return Err(CreateError::FailedSignature);
                    }
                }
            }
        }

        msg.serialized = bytes.clone();
        msg.hash = MessageHash::from_bytes(bytes);

        Ok(msg)
    }

    /// send across wire
    pub(crate) fn to_bytes(&self) -> Bytes {
        self.serialized.clone()
    }

    /// Creates a signed message where signature is assumed valid.
    fn new_signed(
        src: SrcAuthority,
        dst: DstLocation,
        variant: Variant,
        proof_chain: Option<SectionProofChain>,
        dst_key: Option<bls::PublicKey>,
    ) -> Result<Message, CreateError> {
        let mut msg = Message {
            dst,
            src,
            proof_chain,
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
        variant: Variant,
        proof_chain: Option<SectionProofChain>,
        dst_key: Option<bls::PublicKey>,
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

        Self::new_signed(src, dst, variant, proof_chain, dst_key)
    }

    /// Creates a message but does not enforce that it is valid. Use only for testing.
    #[cfg(all(test, feature = "mock"))]
    pub(crate) fn unverified(
        src: SrcAuthority,
        dst: DstLocation,
        variant: Variant,
        proof_chain: Option<SectionProofChain>,
        dst_key: Option<bls::PublicKey>,
    ) -> Result<Self, CreateError> {
        Self::new_signed(src, dst, variant, proof_chain, dst_key)
    }

    /// Verify this message is properly signed and trusted.
    pub(crate) fn verify<'a, I>(&'a self, trusted_keys: I) -> Result<VerifyStatus>
    where
        I: IntoIterator<Item = (&'a Prefix, &'a bls::PublicKey)>,
    {
        let bytes = bincode::serialize(&SignableView {
            dst: &self.dst,
            dst_key: self.dst_key.as_ref(),
            variant: &self.variant,
        })?;

        match &self.src {
            SrcAuthority::Node {
                public_id,
                signature,
            } => {
                if !public_id.verify(&bytes, signature) {
                    return Err(Error::FailedSignature);
                }

                // Variant-specific verification.
                let trusted_keys = trusted_keys
                    .into_iter()
                    .filter(|(known_prefix, _)| known_prefix.matches(public_id.name()))
                    .map(|(_, key)| key);
                self.variant.verify(self.proof_chain.as_ref(), trusted_keys)
            }
            SrcAuthority::Section { prefix, signature } => {
                // Proof chain is requires for section-src messages.
                let proof_chain = if let Some(proof_chain) = self.proof_chain.as_ref() {
                    proof_chain
                } else {
                    return Err(Error::InvalidMessage);
                };

                if !proof_chain.last_key().verify(signature, &bytes) {
                    return Err(Error::FailedSignature);
                }

                let trusted_keys = trusted_keys
                    .into_iter()
                    .filter(|(known_prefix, _)| prefix.is_compatible(known_prefix))
                    .map(|(_, key)| key);

                match proof_chain.check_trust(trusted_keys) {
                    TrustStatus::Trusted => Ok(VerifyStatus::Full),
                    TrustStatus::Unknown => Ok(VerifyStatus::Unknown),
                    TrustStatus::Invalid => Err(Error::UntrustedMessage),
                }
            }
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

    /// Returns the attached proof chain, if any.
    pub(crate) fn proof_chain(&self) -> Result<&SectionProofChain> {
        self.proof_chain.as_ref().ok_or(Error::InvalidMessage)
    }

    /// Returns the last key of the attached the proof chain, if any.
    pub(crate) fn proof_chain_last_key(&self) -> Result<&bls::PublicKey> {
        self.proof_chain().map(|proof_chain| proof_chain.last_key())
    }

    // Extend the current message proof chain so it starts at `new_first_key` while keeping the
    // last key (and therefore the signature) intact.
    #[cfg_attr(feature = "mock", allow(clippy::trivially_copy_pass_by_ref))]
    pub(crate) fn extend_proof_chain(
        mut self,
        new_first_key: &bls::PublicKey,
        section_proof_chain: &SectionProofChain,
    ) -> Result<Self, ExtendProofChainError> {
        if let Some(proof_chain) = self.proof_chain.as_mut() {
            proof_chain.extend(new_first_key, section_proof_chain)?;
        } else {
            return Err(ExtendProofChainError::NoProofChain);
        }

        Ok(Self::new_signed(
            self.src,
            self.dst,
            self.variant,
            self.proof_chain,
            self.dst_key,
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
    pub fn require_full(self) -> Result<(), Error> {
        match self {
            Self::Full => Ok(()),
            Self::Unknown => Err(Error::UntrustedMessage),
        }
    }
}

pub fn log_verify_failure<'a, T, I>(msg: &T, error: &Error, their_keys: I)
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

impl From<CreateError> for Error {
    fn from(src: CreateError) -> Self {
        match src {
            CreateError::Bincode(inner) => Self::Bincode(inner),
            CreateError::FailedSignature => Self::FailedSignature,
        }
    }
}

/// Error returned from `Message::extend_proof_chain`.
#[derive(Debug, Error)]
pub enum ExtendProofChainError {
    #[error(display = "message has no proof chain")]
    NoProofChain,
    #[error(display = "failed to extend proof chain: {}", _0)]
    Extend(#[error(source)] ExtendError),
    #[error(display = "failed to re-create message: {}", _0)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{consensus, rng, section};
    use std::iter;

    #[test]
    fn extend_proof_chain() {
        let mut rng = rng::new();

        let full_id = FullId::gen(&mut rng);

        let sk0 = consensus::test_utils::gen_secret_key(&mut rng);
        let pk0 = sk0.public_key();

        let sk1 = consensus::test_utils::gen_secret_key(&mut rng);
        let pk1 = sk1.public_key();

        let mut full_proof_chain = SectionProofChain::new(sk0.public_key());
        let pk1_sig = sk0.sign(&bincode::serialize(&pk1).unwrap());
        let _ = full_proof_chain.push(pk1, pk1_sig);

        let (elders_info, _) = section::gen_elders_info(&mut rng, Default::default(), 3);
        let elders_info = consensus::test_utils::proven(&sk1, elders_info);

        let variant = Variant::NodeApproval(elders_info);
        let message = Message::single_src(
            &full_id,
            DstLocation::Direct,
            variant,
            Some(full_proof_chain.slice(1..)),
            Some(pk1),
        )
        .unwrap();

        assert_eq!(
            message
                .verify(iter::once((&Prefix::default(), &pk1)))
                .unwrap(),
            VerifyStatus::Full
        );
        assert_eq!(
            message
                .verify(iter::once((&Prefix::default(), &pk0)))
                .unwrap(),
            VerifyStatus::Unknown
        );

        let message = message.extend_proof_chain(&pk0, &full_proof_chain).unwrap();

        assert_eq!(
            message
                .verify(iter::once((&Prefix::default(), &pk0)))
                .unwrap(),
            VerifyStatus::Full
        );
    }
}
