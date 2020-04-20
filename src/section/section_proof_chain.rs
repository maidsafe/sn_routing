// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::elders_info::EldersInfo;
use crate::{
    error::Result,
    xor_space::{Prefix, XorName},
};

#[cfg(all(test, feature = "mock"))]
use std::iter;

#[derive(Debug, Eq, PartialEq, Clone, Hash, Serialize, Deserialize)]
pub struct SectionProofBlock {
    key_info: SectionKeyInfo,
    sig: bls::Signature,
}

impl SectionProofBlock {
    pub fn new(key_info: SectionKeyInfo, sig: bls::Signature) -> Self {
        Self { key_info, sig }
    }

    pub fn key_info(&self) -> &SectionKeyInfo {
        &self.key_info
    }

    pub fn verify_with_pk(&self, pk: bls::PublicKey) -> bool {
        if let Ok(to_verify) = self.key_info.serialise_for_signature() {
            pk.verify(&self.sig, to_verify)
        } else {
            false
        }
    }

    pub fn prefix(&self) -> &Prefix<XorName> {
        self.key_info.prefix()
    }

    pub fn version(&self) -> u64 {
        self.key_info.version()
    }
}

#[derive(Debug, Eq, PartialEq, Clone, Hash, Serialize, Deserialize)]
pub struct SectionProofSlice {
    /// The version of the section key to use as root of trust.
    version: u64,
    /// The prefix of section key to use as root of trust.
    prefix: Prefix<XorName>,
    /// chain of trust to the section, if empty use root of trust.
    blocks: Vec<SectionProofBlock>,
}

impl SectionProofSlice {
    #[cfg(any(feature = "mock_base", test))]
    pub fn from_genesis(key_info: SectionKeyInfo) -> Self {
        Self {
            version: key_info.version,
            prefix: key_info.prefix,
            blocks: Vec::new(),
        }
    }

    pub fn last_prefix_version(&self) -> (&Prefix<XorName>, u64) {
        self.blocks
            .last()
            .map(|block| (block.prefix(), block.version()))
            .unwrap_or((&self.prefix, self.version))
    }

    #[cfg(all(test, feature = "mock"))]
    pub fn all_prefix_version(&self) -> impl DoubleEndedIterator<Item = (&Prefix<XorName>, u64)> {
        iter::once((&self.prefix, self.version)).chain(
            self.blocks
                .iter()
                .map(|block| (block.prefix(), block.version())),
        )
    }

    pub fn last_new_key_info(&self) -> Option<&SectionKeyInfo> {
        self.blocks.last().map(|block| block.key_info())
    }

    fn last_trusted_key_info<'a>(
        &'a self,
        last_trusted: &'a SectionKeyInfo,
    ) -> Option<&'a SectionKeyInfo> {
        let block_offset = last_trusted.version().saturating_sub(self.version) as usize;

        if block_offset == 0 {
            if last_trusted.version() != self.version || last_trusted.prefix() != &self.prefix {
                return None;
            }
        } else if let Some(block) = self.blocks.get(block_offset - 1) {
            if block.key_info() != last_trusted {
                return None;
            }
        } else {
            // Root of trust not found
            return None;
        }

        let mut current = last_trusted;
        for block in &self.blocks[block_offset..] {
            if !validate_next_block(current, block) {
                return None;
            }

            current = block.key_info();
        }

        Some(current)
    }

    // Verify this proof chain against the given key infos.
    pub fn check_trust<'a, I>(&'a self, their_key_infos: I) -> TrustStatus<'a>
    where
        I: IntoIterator<Item = (&'a Prefix<XorName>, &'a SectionKeyInfo)>,
    {
        let first_version = self.version;
        let (last_prefix, last_version) = self.last_prefix_version();
        let inclusive_range = first_version..=last_version;

        let mut max_known_version = 0;
        let mut found_prefix_keys = false;

        for proof_key_info in their_key_infos
            .into_iter()
            .filter(|&(pfx, _)| last_prefix.is_compatible(pfx))
            .map(|(_, info)| info)
        {
            max_known_version = std::cmp::max(max_known_version, proof_key_info.version());
            found_prefix_keys = true;

            if inclusive_range.contains(&proof_key_info.version()) {
                // We can validate trust with that key: we are done.
                if let Some(trusted_info) = self.last_trusted_key_info(proof_key_info) {
                    return TrustStatus::Trusted(trusted_info.key());
                } else {
                    return TrustStatus::ProofInvalid;
                }
            }
        }

        if found_prefix_keys && self.version > max_known_version {
            TrustStatus::ProofTooNew
        } else {
            TrustStatus::ProofInvalid
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone, Hash, Serialize, Deserialize)]
pub struct SectionProofChain {
    genesis_key_info: SectionKeyInfo,
    blocks: Vec<SectionProofBlock>,
}

impl SectionProofChain {
    pub fn from_genesis(key_info: SectionKeyInfo) -> Self {
        Self {
            genesis_key_info: key_info,
            blocks: Vec::new(),
        }
    }

    pub fn push(&mut self, block: SectionProofBlock) {
        if !validate_next_block(self.last_key_info(), &block) {
            log_or_panic!(
                log::Level::Error,
                "Invalid next block: {:?} -> {:?}",
                self.last_key_info(),
                block
            );
            return;
        }

        self.blocks.push(block)
    }

    #[cfg(test)]
    pub fn validate(&self) -> bool {
        let mut current = &self.genesis_key_info;
        for block in &self.blocks {
            if !validate_next_block(current, block) {
                return false;
            }

            current = block.key_info();
        }
        true
    }

    pub fn first_key_info(&self) -> &SectionKeyInfo {
        &self.genesis_key_info
    }

    pub fn last_key_info(&self) -> &SectionKeyInfo {
        self.blocks
            .last()
            .map(|block| block.key_info())
            .unwrap_or(&self.genesis_key_info)
    }

    pub fn slice_from(&self, first_index: usize) -> SectionProofSlice {
        if first_index == 0 || self.blocks.is_empty() {
            return SectionProofSlice {
                version: self.genesis_key_info.version,
                prefix: self.genesis_key_info.prefix,
                blocks: self.blocks.clone(),
            };
        }

        let genesis_index = std::cmp::min(first_index, self.blocks.len()) - 1;
        let genesis_key_info = self.blocks[genesis_index].key_info().clone();

        let block_first_index = genesis_index + 1;
        let blocks = if block_first_index >= self.blocks.len() {
            vec![]
        } else {
            self.blocks[block_first_index..].to_vec()
        };

        SectionProofSlice {
            version: genesis_key_info.version,
            prefix: genesis_key_info.prefix,
            blocks,
        }
    }
}

fn validate_next_block(last: &SectionKeyInfo, next: &SectionProofBlock) -> bool {
    if next.version() != last.version() + 1 {
        return false;
    }

    if !next.prefix().is_compatible(last.prefix())
        || next.prefix().bit_count() > last.prefix().bit_count() + 1
    {
        return false;
    }

    if !next.verify_with_pk(*last.key()) {
        return false;
    }

    true
}

#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone, Hash, Serialize, Deserialize)]
pub struct SectionKeyInfo {
    /// The section version. This increases monotonically whenever the set of elders changes.
    /// Identical to `ElderInfo`'s.
    version: u64,
    /// The section prefix. It matches all the members' names.
    prefix: Prefix<XorName>,
    /// The section BLS public key set
    key: bls::PublicKey,
}

impl SectionKeyInfo {
    pub fn new(version: u64, prefix: Prefix<XorName>, key: bls::PublicKey) -> Self {
        Self {
            version,
            prefix,
            key,
        }
    }

    pub fn from_elders_info(elders_info: &EldersInfo, key: bls::PublicKey) -> Self {
        Self::new(elders_info.version(), *elders_info.prefix(), key)
    }

    pub fn key(&self) -> &bls::PublicKey {
        &self.key
    }

    pub fn prefix(&self) -> &Prefix<XorName> {
        &self.prefix
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    pub fn serialise_for_signature(&self) -> Result<Vec<u8>> {
        Ok(bincode::serialize(&self)?)
    }
}

// Result of a message trust check.
#[derive(Debug)]
pub enum TrustStatus<'a> {
    // Message is trusted. Contains the latest section public key.
    Trusted(&'a bls::PublicKey),
    // Message is untrusted because the proof is invalid.
    ProofInvalid,
    // Message trust cannot be determined because the proof starts at version that is newer than
    // our latest one.
    ProofTooNew,
}
