// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{Variant, VerifyStatus};
use crate::{
    crypto::signing::Signature as SimpleSignature,
    error::{Result, RoutingError},
    id::{P2pNode, PublicId},
    location::{DstLocation, SrcLocation},
    section::{SectionProofChain, TrustStatus},
};

use std::net::SocketAddr;
use xor_name::{Prefix, XorName};

#[derive(Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum SrcAuthority {
    Node {
        public_id: PublicId,
        signature: SimpleSignature,
    },
    Section {
        prefix: Prefix<XorName>,
        signature: bls::Signature,
        proof: SectionProofChain,
    },
}

impl SrcAuthority {
    pub fn location(&self) -> SrcLocation {
        match self {
            Self::Node { public_id, .. } => SrcLocation::Node(*public_id.name()),
            Self::Section { prefix, .. } => SrcLocation::Section(*prefix),
        }
    }

    pub fn check_is_section(&self) -> Result<()> {
        if self.is_section() {
            Ok(())
        } else {
            Err(RoutingError::BadLocation)
        }
    }

    pub fn is_section(&self) -> bool {
        matches!(self, Self::Section { .. })
    }

    pub fn as_node(&self) -> Result<&PublicId> {
        match self {
            Self::Node { public_id, .. } => Ok(public_id),
            Self::Section { .. } => Err(RoutingError::BadLocation),
        }
    }

    // If this is `Section`, return the last section key, otherwise error.
    pub fn as_section_key(&self) -> Result<&bls::PublicKey> {
        match self {
            Self::Section { proof, .. } => Ok(proof.last_key()),
            Self::Node { .. } => Err(RoutingError::BadLocation),
        }
    }

    // If this is `Section`, returns the prefix and the latest key, otherwise error.
    pub fn as_section_prefix_and_key(&self) -> Result<(&Prefix<XorName>, &bls::PublicKey)> {
        match self {
            Self::Section { prefix, proof, .. } => Ok((prefix, proof.last_key())),
            Self::Node { .. } => Err(RoutingError::BadLocation),
        }
    }

    pub fn to_sender_node(&self, sender: Option<SocketAddr>) -> Result<P2pNode> {
        let pub_id = *self.as_node()?;
        let conn_info = sender.ok_or(RoutingError::InvalidSource)?;
        Ok(P2pNode::new(pub_id, conn_info))
    }

    pub fn verify<'a, I>(
        &'a self,
        dst: &DstLocation,
        dst_key: Option<&bls::PublicKey>,
        variant: &Variant,
        trusted_key_infos: I,
    ) -> Result<VerifyStatus>
    where
        I: IntoIterator<Item = (&'a Prefix<XorName>, &'a bls::PublicKey)>,
    {
        match self {
            Self::Node {
                public_id,
                signature,
            } => {
                let bytes = super::serialize_for_node_signing(public_id, dst, dst_key, variant)?;
                if !public_id.verify(&bytes, signature) {
                    return Err(RoutingError::FailedSignature);
                }
            }
            Self::Section {
                prefix,
                signature,
                proof,
            } => {
                let trusted_key_infos = trusted_key_infos
                    .into_iter()
                    .filter(|(known_prefix, _)| prefix.is_compatible(known_prefix))
                    .map(|(_, key_info)| key_info);

                match proof.check_trust(trusted_key_infos) {
                    TrustStatus::Trusted => (),
                    TrustStatus::Unknown => return Ok(VerifyStatus::Unknown),
                    TrustStatus::Invalid => return Err(RoutingError::UntrustedMessage),
                };

                let bytes = super::serialize_for_section_signing(dst, dst_key, variant)?;
                if !proof.last_key().verify(signature, &bytes) {
                    return Err(RoutingError::FailedSignature);
                }
            }
        }

        Ok(VerifyStatus::Full)
    }

    // Extend the current message proof so it starts at `new_first_key` while keeping the last key
    // (and therefore the signature) intact.
    #[cfg_attr(feature = "mock_base", allow(clippy::trivially_copy_pass_by_ref))]
    pub fn extend_proof(
        &mut self,
        new_first_key: &bls::PublicKey,
        section_proof_chain: &SectionProofChain,
    ) -> Result<(), ExtendProofError> {
        let proof = match self {
            Self::Section { proof, .. } => proof,
            Self::Node { .. } => return Err(ExtendProofError::MustBeSection),
        };

        if proof.has_key(new_first_key) {
            return Err(ExtendProofError::ProofAlreadySufficient);
        }

        let index_from = if let Some(index) = section_proof_chain.index_of(new_first_key) {
            index
        } else {
            return Err(ExtendProofError::InvalidFirstKey);
        };

        let index_to = if let Some(index) = section_proof_chain.index_of(proof.last_key()) {
            index
        } else {
            return Err(ExtendProofError::InvalidLastKey);
        };

        *proof = section_proof_chain.slice(index_from..=index_to);

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
