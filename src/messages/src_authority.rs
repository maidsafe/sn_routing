// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{RoutingMessage, VerifyStatus};
use crate::{
    chain::{SectionKeyInfo, SectionProofSlice, TrustStatus},
    crypto::signing::Signature,
    error::{Result, RoutingError},
    id::PublicId,
    xor_space::{Prefix, XorName},
};
use bincode::serialize;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Debug, Formatter};

#[derive(Eq, PartialEq, Clone, Hash, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum SrcAuthority {
    Section {
        proof: SectionProofSlice,
        signature: bls::Signature,
    },
    Node {
        public_id: PublicId,
        signature: Signature,
    },
}

impl SrcAuthority {
    pub fn verify<'a, I>(
        &'a self,
        content: &RoutingMessage,
        their_key_infos: I,
    ) -> Result<VerifyStatus, RoutingError>
    where
        I: IntoIterator<Item = (&'a Prefix<XorName>, &'a SectionKeyInfo)>,
    {
        match self {
            Self::Node {
                public_id,
                signature,
            } => {
                if content.src.single_signing_name() != Some(public_id.name()) {
                    // Signature is not from the source node.
                    return Err(RoutingError::InvalidMessage);
                }

                let signed_bytes = serialize(content)?;
                if !public_id.verify(&signed_bytes, signature) {
                    return Err(RoutingError::FailedSignature);
                }
            }
            Self::Section { proof, signature } => {
                let public_key = match proof.check_trust(their_key_infos) {
                    TrustStatus::Trusted(key) => key,
                    TrustStatus::ProofTooNew => return Ok(VerifyStatus::ProofTooNew),
                    TrustStatus::ProofInvalid => return Err(RoutingError::UntrustedMessage),
                };

                let signed_bytes = serialize(content)?;
                if !public_key.verify(signature, &signed_bytes) {
                    return Err(RoutingError::FailedSignature);
                }
            }
        }

        Ok(VerifyStatus::Full)
    }

    pub fn last_new_key_info(&self) -> Option<&SectionKeyInfo> {
        match self {
            Self::Section { proof, .. } => proof.last_new_key_info(),
            Self::Node { .. } => None,
        }
    }
}

impl Debug for SrcAuthority {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match self {
            Self::Section { proof, .. } => write!(
                formatter,
                "Section {{ proof.blocks_len: {}, proof: {:?}, .. }}",
                proof.blocks_len(),
                proof
            ),
            Self::Node { public_id, .. } => {
                write!(formatter, "Node {{ public_id: {:?}, .. }}", public_id)
            }
        }
    }
}
