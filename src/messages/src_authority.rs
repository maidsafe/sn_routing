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
    xor_space::{Prefix, XorName},
};
use std::net::SocketAddr;

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

    pub fn as_node(&self) -> Result<&PublicId> {
        match self {
            Self::Node { public_id, .. } => Ok(public_id),
            Self::Section { .. } => Err(RoutingError::BadLocation),
        }
    }

    pub fn as_section(&self) -> Result<&Prefix<XorName>> {
        match self {
            Self::Section { prefix, .. } => Ok(prefix),
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

    // If this is `Section`, returns the prefix and the latest key, otherwise `None`.
    pub(crate) fn section_prefix_and_key(&self) -> Option<(&Prefix<XorName>, &bls::PublicKey)> {
        match self {
            SrcAuthority::Section { prefix, proof, .. } => Some((prefix, proof.last_key())),
            SrcAuthority::Node { .. } => None,
        }
    }
}
