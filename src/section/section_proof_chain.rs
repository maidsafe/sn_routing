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

/// Chain of section BLS keys where every key is proven (signed) by the previous key, except the
/// first one.
#[derive(Debug, Eq, PartialEq, Clone, Hash, Serialize, Deserialize)]
pub struct SectionProofChain {
    head: SectionKeyInfo,
    tail: Vec<SectionProofBlock>,
}

impl SectionProofChain {
    /// Creates new chain consisting of only one block.
    pub fn new(first: SectionKeyInfo) -> Self {
        Self {
            head: first,
            tail: Vec::new(),
        }
    }

    pub(crate) fn push(&mut self, block: SectionProofBlock) {
        if !validate_next_block(self.last_key_info(), &block) {
            log_or_panic!(
                log::Level::Error,
                "Invalid next block: {:?} -> {:?}",
                self.last_key_info(),
                block
            );
            return;
        }

        self.tail.push(block)
    }

    #[cfg(test)]
    pub fn self_validate(&self) -> bool {
        let mut current = &self.head;
        for block in &self.tail {
            if !validate_next_block(current, block) {
                return false;
            }

            current = block.key_info();
        }
        true
    }

    pub(crate) fn first_key_info(&self) -> &SectionKeyInfo {
        &self.head
    }

    pub(crate) fn last_key_info(&self) -> &SectionKeyInfo {
        self.tail
            .last()
            .map(|block| block.key_info())
            .unwrap_or(&self.head)
    }

    #[cfg(all(test, feature = "mock"))]
    pub fn key_infos(&self) -> impl DoubleEndedIterator<Item = &SectionKeyInfo> {
        iter::once(&self.head).chain(self.tail.iter().map(|block| block.key_info()))
    }

    /// Returns a slice of this chain starting at the given index.
    pub(crate) fn slice_from(&self, first_index: usize) -> Self {
        if first_index == 0 || self.tail.is_empty() {
            return self.clone();
        }

        let head_index = std::cmp::min(first_index, self.tail.len()) - 1;
        let head = self.tail[head_index].key_info().clone();

        let tail_first_index = head_index + 1;
        let tail = if tail_first_index >= self.tail.len() {
            vec![]
        } else {
            self.tail[tail_first_index..].to_vec()
        };

        Self { head, tail }
    }

    /// Number of blocks in the chain (including the first block)
    pub(crate) fn len(&self) -> usize {
        1 + self.tail.len()
    }

    /// Verify this proof chain against the given key infos.
    pub(crate) fn check_trust<'a, I>(&'a self, their_key_infos: I) -> TrustStatus<'a>
    where
        I: IntoIterator<Item = (&'a Prefix<XorName>, &'a SectionKeyInfo)>,
    {
        let first_version = self.head.version;
        let last_key_info = self.last_key_info();
        let inclusive_range = first_version..=last_key_info.version;

        let mut max_known_version = 0;
        let mut found_prefix_keys = false;

        for proof_key_info in their_key_infos
            .into_iter()
            .filter(|(prefix, _)| last_key_info.prefix.is_compatible(prefix))
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

        if found_prefix_keys && self.head.version > max_known_version {
            TrustStatus::ProofTooNew
        } else {
            TrustStatus::ProofInvalid
        }
    }

    fn last_trusted_key_info<'a>(
        &'a self,
        last_trusted: &'a SectionKeyInfo,
    ) -> Option<&'a SectionKeyInfo> {
        let block_offset = last_trusted.version().saturating_sub(self.head.version) as usize;

        if block_offset == 0 {
            if last_trusted.version() != self.head.version
                || last_trusted.prefix() != &self.head.prefix
            {
                return None;
            }
        } else if let Some(block) = self.tail.get(block_offset - 1) {
            if block.key_info() != last_trusted {
                return None;
            }
        } else {
            // Root of trust not found
            return None;
        }

        let mut current = last_trusted;
        for block in &self.tail[block_offset..] {
            if !validate_next_block(current, block) {
                return None;
            }

            current = block.key_info();
        }

        Some(current)
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

/// Section BLS public key together with the section prefix and version.
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
    /// Creates new `SectionKeyInfo` for a section with the given prefix and version.
    pub fn new(version: u64, prefix: Prefix<XorName>, key: bls::PublicKey) -> Self {
        Self {
            version,
            prefix,
            key,
        }
    }

    pub(crate) fn from_elders_info(elders_info: &EldersInfo, key: bls::PublicKey) -> Self {
        Self::new(elders_info.version, elders_info.prefix, key)
    }

    pub(crate) fn key(&self) -> &bls::PublicKey {
        &self.key
    }

    pub(crate) fn prefix(&self) -> &Prefix<XorName> {
        &self.prefix
    }

    pub(crate) fn version(&self) -> u64 {
        self.version
    }

    pub(crate) fn serialise_for_signature(&self) -> Result<Vec<u8>> {
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
