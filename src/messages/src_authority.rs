// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::VerifyStatus;
use crate::{
    chain::{SectionKeyInfo, SectionProofSlice, TrustStatus},
    crypto::signing::Signature as SimpleSignature,
    error::{Result, RoutingError},
    id::{P2pNode, PublicId},
    location::SrcLocation,
    xor_space::{Prefix, XorName},
    ConnectionInfo,
};

#[derive(Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum SrcAuthority {
    Node {
        public_id: PublicId,
        signature: SimpleSignature,
    },
    Section {
        prefix: Prefix<XorName>,
        signature: bls::Signature,
        proof: SectionProofSlice,
    },
}

impl SrcAuthority {
    pub fn location(&self) -> SrcLocation {
        match self {
            Self::Node { public_id, .. } => SrcLocation::Node(*public_id),
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

    pub fn to_sender_node(&self, sender: Option<ConnectionInfo>) -> Result<P2pNode> {
        let pub_id = *self.as_node()?;
        let conn_info = sender.ok_or(RoutingError::InvalidSource)?;
        Ok(P2pNode::new(pub_id, conn_info))
    }

    pub fn verify<'a, I>(
        &'a self,
        serialized_content: &[u8],
        their_key_infos: I,
    ) -> Result<VerifyStatus>
    where
        I: IntoIterator<Item = (&'a Prefix<XorName>, &'a SectionKeyInfo)>,
    {
        match self {
            Self::Node {
                public_id,
                signature,
            } => {
                if !public_id.verify(serialized_content, signature) {
                    return Err(RoutingError::FailedSignature);
                }
            }
            Self::Section {
                signature, proof, ..
            } => {
                let public_key = match proof.check_trust(their_key_infos) {
                    TrustStatus::Trusted(key) => key,
                    TrustStatus::ProofTooNew => return Ok(VerifyStatus::ProofTooNew),
                    TrustStatus::ProofInvalid => return Err(RoutingError::UntrustedMessage),
                };

                if !public_key.verify(signature, serialized_content) {
                    return Err(RoutingError::FailedSignature);
                }
            }
        }

        Ok(VerifyStatus::Full)
    }
}
