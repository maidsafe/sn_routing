// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{DstLocation, SignableView, Variant};
use crate::{consensus::ProofShare, error::Result, section::SectionProofChain};
use xor_name::Prefix;

/// Section-source message that is in the process of signature accumulation.
/// When enough signatures are collected, it can be converted into full `Message` by calling
/// `combine_signatures`.
#[allow(missing_docs)]
#[derive(Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Debug)]
pub struct AccumulatingMessage {
    pub content: PlainMessage,
    pub proof_chain: SectionProofChain,
    pub proof_share: ProofShare,
}

impl AccumulatingMessage {
    /// Create new `AccumulatingMessage`
    pub fn new(
        content: PlainMessage,
        proof_chain: SectionProofChain,
        proof_share: ProofShare,
    ) -> Self {
        Self {
            content,
            proof_chain,
            proof_share,
        }
    }
}

/// Section-source message without signature and proof.
#[derive(Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Debug)]
pub struct PlainMessage {
    /// Prefix of the source section.
    pub src: Prefix,
    /// Destination location.
    pub dst: DstLocation,
    /// The latest key of the destination section according to the sender's knowledge.
    pub dst_key: bls::PublicKey,
    /// Message body.
    pub variant: Variant,
}

impl PlainMessage {
    /// Create ProofShare for this message.
    pub fn prove(
        &self,
        public_key_set: bls::PublicKeySet,
        index: usize,
        secret_key_share: &bls::SecretKeyShare,
    ) -> Result<ProofShare> {
        Ok(ProofShare::new(
            public_key_set,
            index,
            secret_key_share,
            &bincode::serialize(&self.as_signable())?,
        ))
    }

    pub(crate) fn as_signable(&self) -> SignableView {
        SignableView {
            dst: &self.dst,
            dst_key: Some(&self.dst_key),
            variant: &self.variant,
        }
    }
}
