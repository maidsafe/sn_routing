// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    chain::{SectionKeyInfo, SectionProofChain},
    crypto::signing::Signature,
    id::PublicId,
};

use std::{
    collections::BTreeSet,
    fmt::{self, Debug, Formatter},
    hash::Hash,
};

#[derive(Eq, PartialEq, Clone, Hash, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum SecurityMetadata {
    None,
    Partial(PartialSecurityMetadata),
    Full(FullSecurityMetadata),
    Single(SingleSrcSecurityMetadata),
}

impl Debug for SecurityMetadata {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match &self {
            Self::None => write!(formatter, "None"),
            Self::Partial(pmd) => write!(formatter, "{:?}", pmd),
            Self::Full(smd) => write!(formatter, "{:?}", smd),
            Self::Single(smd) => write!(formatter, "{:?}", smd),
        }
    }
}
/// Metadata needed for verification of the sender.
/// Contain shares of the section signature before combining into a BLS signature
/// and into a FullSecurityMetadata.
/// FIXME(DI) This message must then still be signed so must be signed by nodes ed25519 key
#[derive(Eq, PartialEq, Clone, Hash, Serialize, Deserialize)]
pub struct PartialSecurityMetadata {
    proof: SectionProofChain,
    shares: BTreeSet<(usize, bls::SignatureShare)>,
    pk_set: bls::PublicKeySet,
}

impl PartialSecurityMetadata {
    pub(crate) fn find_invalid_sigs(
        &self,
        signed_bytes: &[u8],
    ) -> Vec<(usize, bls::SignatureShare)> {
        let key_set = &self.pk_set;
        self.shares
            .iter()
            .filter(|&(idx, sig)| !key_set.public_key_share(idx).verify(sig, &signed_bytes))
            .map(|(idx, sig)| (*idx, sig.clone()))
            .collect()
    }
    pub(crate) fn shares(&self) -> BTreeSet<(usize, bls::SignatureShare)> {
        self.shares
    }
    pub(crate) fn pk_set(&self) -> bls::PublicKeySet {
        self.pk_set
    }
    pub(crate) fn proof(&self) -> SectionProofChain {
        self.proof
    }
}

impl Debug for PartialSecurityMetadata {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "PartialSecurityMetadata {{ proof.blocks_len: {}, proof: {:?}, .. }}",
            self.proof.blocks_len(),
            self.proof
        )
    }
}

/// Metadata needed for verification of the sender.
#[derive(Eq, PartialEq, Clone, Hash, Serialize, Deserialize)]
pub struct FullSecurityMetadata {
    proof: SectionProofChain,
    signature: bls::Signature,
}

impl FullSecurityMetadata {
    pub fn verify_sig(&self, bytes: &[u8]) -> bool {
        self.proof.last_public_key().verify(&self.signature, bytes)
    }

    pub fn last_public_key_info(&self) -> &SectionKeyInfo {
        self.proof.last_public_key_info()
    }

    pub fn validate_proof(&self) -> bool {
        self.proof.validate()
    }

    pub fn proof_chain(&self) -> &SectionProofChain {
        &self.proof
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
    public_id: PublicId, // FIXME this is the src and must be. We should remove this field
    signature: Signature,
}

impl SingleSrcSecurityMetadata {
    pub fn verify_sig(&self, bytes: &[u8]) -> bool {
        self.public_id.verify(bytes, &self.signature)
    }
    pub fn public_id(&self) -> PublicId {
        self.public_id
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
