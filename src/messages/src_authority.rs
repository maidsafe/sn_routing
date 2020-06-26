// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{SignableView, Variant, VerifyStatus};
use crate::{
    crypto::signing::Signature as SimpleSignature,
    error::{Result, RoutingError},
    id::{P2pNode, PublicId},
    location::{DstLocation, SrcLocation},
    section::{SectionProofChain, TrustStatus},
};

use std::net::SocketAddr;
use xor_name::Prefix;

/// Source authority of a message.
#[derive(Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
/// Src of message and authority to send it. Authority is validated by the signature.
/// Messages do not need to sign this field as it is all verifiable (i.e. if the sig validates
/// agains the pub key and we know th epub key then we are good. If the proof is not recodnised we
/// ask for a longer chain that can be recodnised). Therefor we don't need to sign this field.
pub enum SrcAuthority {
    /// Authority of a single node.
    Node {
        /// Id of the source node.
        public_id: PublicId,
        /// ed-25519 signature of the message corresponding to the public key of the source node.
        signature: SimpleSignature,
    },
    /// Authority of a whole section.
    Section {
        /// Prefix of the source section.
        prefix: Prefix,
        /// BLS signature of the message corresponding to the source section public key.
        signature: bls::Signature,
        /// Proof chain whole last key is the section public key corresponding to the signature.
        proof_chain: SectionProofChain,
    },
}

impl SrcAuthority {
    pub(crate) fn src_location(&self) -> SrcLocation {
        match self {
            Self::Node { public_id, .. } => SrcLocation::Node(*public_id.name()),
            Self::Section { prefix, .. } => SrcLocation::Section(*prefix),
        }
    }

    pub(crate) fn check_is_section(&self) -> Result<()> {
        if self.is_section() {
            Ok(())
        } else {
            Err(RoutingError::BadLocation)
        }
    }

    pub(crate) fn is_section(&self) -> bool {
        matches!(self, Self::Section { .. })
    }

    pub(crate) fn as_node(&self) -> Result<&PublicId> {
        match self {
            Self::Node { public_id, .. } => Ok(public_id),
            Self::Section { .. } => Err(RoutingError::BadLocation),
        }
    }

    // If this is `Section`, return the last section key, otherwise error.
    pub(crate) fn as_section_key(&self) -> Result<&bls::PublicKey> {
        match self {
            Self::Section { proof_chain, .. } => Ok(proof_chain.last_key()),
            Self::Node { .. } => Err(RoutingError::BadLocation),
        }
    }

    // If this is `Section`, returns the prefix and the latest key, otherwise error.
    pub(crate) fn as_section_prefix_and_key(&self) -> Result<(&Prefix, &bls::PublicKey)> {
        match self {
            Self::Section {
                prefix,
                proof_chain,
                ..
            } => Ok((prefix, proof_chain.last_key())),
            Self::Node { .. } => Err(RoutingError::BadLocation),
        }
    }

    pub(crate) fn to_sender_node(&self, sender: Option<SocketAddr>) -> Result<P2pNode> {
        let pub_id = *self.as_node()?;
        let conn_info = sender.ok_or(RoutingError::InvalidSource)?;
        Ok(P2pNode::new(pub_id, conn_info))
    }

    pub(crate) fn verify<'a, I>(
        &'a self,
        dst: &DstLocation,
        dst_key: Option<&bls::PublicKey>,
        variant: &Variant,
        trusted_key_infos: I,
    ) -> Result<VerifyStatus>
    where
        I: IntoIterator<Item = (&'a Prefix, &'a bls::PublicKey)>,
    {
        let bytes = bincode::serialize(&SignableView {
            dst,
            dst_key,
            variant,
        })?;

        match self {
            Self::Node {
                public_id,
                signature,
            } => {
                if !public_id.verify(&bytes, signature) {
                    return Err(RoutingError::FailedSignature);
                }
            }
            Self::Section {
                prefix,
                signature,
                proof_chain,
            } => {
                let trusted_key_infos = trusted_key_infos
                    .into_iter()
                    .filter(|(known_prefix, _)| prefix.is_compatible(known_prefix))
                    .map(|(_, key_info)| key_info);

                match proof_chain.check_trust(trusted_key_infos) {
                    TrustStatus::Trusted => (),
                    TrustStatus::Unknown => return Ok(VerifyStatus::Unknown),
                    TrustStatus::Invalid => return Err(RoutingError::UntrustedMessage),
                };

                let bytes = bincode::serialize(&SignableView {
                    dst,
                    dst_key,
                    variant,
                })?;

                if !proof_chain.last_key().verify(signature, &bytes) {
                    return Err(RoutingError::FailedSignature);
                }
            }
        }

        Ok(VerifyStatus::Full)
    }

    // Extend the current message proof so it starts at `new_first_key` while keeping the last key
    // (and therefore the signature) intact.
    #[cfg_attr(feature = "mock_base", allow(clippy::trivially_copy_pass_by_ref))]
    pub(crate) fn extend_proof_chain(
        &mut self,
        new_first_key: &bls::PublicKey,
        section_proof_chain: &SectionProofChain,
    ) -> Result<(), ExtendProofError> {
        let proof_chain = match self {
            Self::Section { proof_chain, .. } => proof_chain,
            Self::Node { .. } => return Err(ExtendProofError::MustBeSection),
        };

        if proof_chain.has_key(new_first_key) {
            return Err(ExtendProofError::ProofAlreadySufficient);
        }

        let index_from = if let Some(index) = section_proof_chain.index_of(new_first_key) {
            index
        } else {
            return Err(ExtendProofError::InvalidFirstKey);
        };

        let index_to = if let Some(index) = section_proof_chain.index_of(proof_chain.last_key()) {
            index
        } else {
            return Err(ExtendProofError::InvalidLastKey);
        };

        *proof_chain = section_proof_chain.slice(index_from..=index_to);

        Ok(())
    }
}

/// Error returned from `SrcAuthority::extend_proof`.
#[derive(Debug)]
pub enum ExtendProofError {
    /// Only SecAuthority::Section supports proof extension.
    MustBeSection,
    /// The new first key is invalid/unknown
    InvalidFirstKey,
    /// The last key of the current proof is invalid/unknown. Perhaps the message was not created
    /// by our section?
    InvalidLastKey,
    /// The proof already contains the new first key and so doesn't need to be extended.
    ProofAlreadySufficient,
}
