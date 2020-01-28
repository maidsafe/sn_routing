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

/// Metadata needed for verification of the sender.
#[derive(Eq, PartialEq, Clone, Hash, Serialize, Deserialize)]
pub struct FullSecurityMetadata {
    pub proof: SectionProofSlice,
    pub signature: bls::Signature,
}

impl FullSecurityMetadata {
    pub fn last_new_key_info(&self) -> Option<&SectionKeyInfo> {
        self.proof.last_new_key_info()
    }

    pub fn verify<'a, I>(
        &'a self,
        content: &RoutingMessage,
        their_key_infos: I,
    ) -> Result<VerifyStatus, RoutingError>
    where
        I: IntoIterator<Item = (&'a Prefix<XorName>, &'a SectionKeyInfo)>,
    {
        let public_key = match self.proof.check_trust(their_key_infos) {
            TrustStatus::Trusted(key) => key,
            TrustStatus::ProofTooNew => return Ok(VerifyStatus::ProofTooNew),
            TrustStatus::ProofInvalid => return Err(RoutingError::UntrustedMessage),
        };

        let signed_bytes = serialize(content)?;
        if public_key.verify(&self.signature, &signed_bytes) {
            Ok(VerifyStatus::Full)
        } else {
            Err(RoutingError::FailedSignature)
        }
    }
}

impl Debug for FullSecurityMetadata {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "FullSecurityMetadata {{ proof.blocks_len: {}, proof: {:?}, .. }}",
            self.proof.blocks_len(),
            self.proof
        )
    }
}

/// Metadata needed for verification of the single node sender.
#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Hash, Serialize, Deserialize)]
pub struct SingleSrcSecurityMetadata {
    pub public_id: PublicId,
    pub signature: Signature,
}

impl SingleSrcSecurityMetadata {
    pub fn verify(&self, content: &RoutingMessage) -> Result<VerifyStatus, RoutingError> {
        if content.src.single_signing_name() != Some(self.public_id.name()) {
            // Signature is not from the source node.
            return Err(RoutingError::InvalidMessage);
        }

        let signed_bytes = serialize(content)?;
        if !self.public_id.verify(&signed_bytes, &self.signature) {
            return Err(RoutingError::FailedSignature);
        }

        Ok(VerifyStatus::Full)
    }
}

impl Debug for SingleSrcSecurityMetadata {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "SingleSrcSecurityMetadata {{ public_id: {:?}, .. }}",
            self.public_id
        )
    }
}

#[derive(Eq, PartialEq, Clone, Hash, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum SecurityMetadata {
    Full(FullSecurityMetadata),
    Single(SingleSrcSecurityMetadata),
}

impl Debug for SecurityMetadata {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match &self {
            Self::Full(smd) => write!(formatter, "{:?}", smd),
            Self::Single(smd) => write!(formatter, "{:?}", smd),
        }
    }
}
