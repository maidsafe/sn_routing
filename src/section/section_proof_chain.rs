// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    error::Result,
    xor_space::{Prefix, XorName},
};

#[cfg(test)]
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
        &self.key_info.prefix
    }

    pub fn version(&self) -> u64 {
        self.key_info.version
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

    #[cfg(test)]
    pub(crate) fn key_infos(&self) -> impl DoubleEndedIterator<Item = &SectionKeyInfo> {
        iter::once(&self.head).chain(self.tail.iter().map(|block| block.key_info()))
    }

    /// Returns a slice of this chain starting at the given index.
    pub(crate) fn slice_from(&self, first_index: usize) -> Self {
        if first_index == 0 || self.tail.is_empty() {
            return self.clone();
        }

        let head_index = std::cmp::min(first_index, self.tail.len()) - 1;
        let head = self.tail[head_index].key_info().clone();
        let tail = self.tail[head_index + 1..].to_vec();

        Self { head, tail }
    }

    /// Number of blocks in the chain (including the first block)
    pub(crate) fn len(&self) -> usize {
        1 + self.tail.len()
    }

    /// Verify this proof chain against the given trusted key infos.
    pub(crate) fn check_trust<'a, I>(&'a self, trusted_key_infos: I) -> TrustStatus<'a>
    where
        I: IntoIterator<Item = &'a SectionKeyInfo>,
    {
        let first_version = self.head.version;
        let last_key_info = self.last_key_info();
        let inclusive_range = first_version..=last_key_info.version;

        let mut max_known_version = 0;
        let mut found_prefix_keys = false;

        for trusted_key_info in trusted_key_infos {
            max_known_version = std::cmp::max(max_known_version, trusted_key_info.version);
            found_prefix_keys = true;

            if inclusive_range.contains(&trusted_key_info.version) {
                // We can validate trust with that key: we are done.
                if let Some(new_trusted_key_info) = self.last_trusted_key_info(trusted_key_info) {
                    return TrustStatus::Trusted(&new_trusted_key_info.key);
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
        let block_offset = last_trusted.version.saturating_sub(self.head.version) as usize;

        if block_offset == 0 {
            if last_trusted.version != self.head.version || last_trusted.prefix != self.head.prefix
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
    if next.version() != last.version + 1 {
        return false;
    }

    if !next.prefix().is_compatible(&last.prefix)
        || next.prefix().bit_count() > last.prefix.bit_count() + 1
    {
        return false;
    }

    if !next.verify_with_pk(last.key) {
        return false;
    }

    true
}

/// Section BLS public key together with the section prefix and version.
#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone, Hash, Serialize, Deserialize)]
pub struct SectionKeyInfo {
    /// The section prefix. It matches all the members' names.
    pub prefix: Prefix<XorName>,
    /// The section version. This increases monotonically whenever the set of elders changes.
    /// Identical to `ElderInfo`'s.
    pub version: u64,
    /// The section BLS public key set
    pub key: bls::PublicKey,
}

impl SectionKeyInfo {
    /// Creates new `SectionKeyInfo` for a section with the given prefix and version.
    pub fn new(prefix: Prefix<XorName>, version: u64, key: bls::PublicKey) -> Self {
        Self {
            prefix,
            version,
            key,
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::{self, MainRng, RngCompat};
    use rand_crypto::Rng;

    #[test]
    fn check_trust_trusted() {
        let mut rng = rng::new();
        let prefix: Prefix<_> = "00".parse().unwrap();
        let chain = gen_chain(&mut rng, prefix, 100, 4);

        // If any key in the chain is already trusted, the whole chain is trusted.
        for key_info in chain.key_infos() {
            match chain.check_trust(iter::once(key_info)) {
                TrustStatus::Trusted(_) => (),
                status => panic!("unexpected trust check outcome: {:?}", status),
            }
        }
    }

    #[test]
    fn check_trust_invalid() {
        let mut rng = rng::new();
        let prefix: Prefix<_> = "01".parse().unwrap();
        let mut chain = gen_chain(&mut rng, prefix, 100, 2);

        // Add a block with invalid signature to the chain.
        let (_, invalid_secret_key) = gen_key_info(&mut rng, prefix, 101);
        let (block, secret_key) = gen_block(&mut rng, prefix, 102, &invalid_secret_key);
        chain.tail.push(block); // SectionProofChain::push panics on invalid blocks

        // Add another block with valid signature by the previous block.
        let (block, _) = gen_block(&mut rng, prefix, 103, &secret_key);
        chain.push(block);

        // If we only trust the keys up to, but excluding the invalid block, the trust check fails
        // because the rest of the chain contains invalid block.
        for key_info in chain.key_infos().take(2) {
            match chain.check_trust(iter::once(key_info)) {
                TrustStatus::ProofInvalid => (),
                status => panic!("unexpected trust check outcome: {:?}", status),
            }
        }

        // But if any key at or after the invalid block is trusted, the rest of the chain is
        // trusted as well.
        for key_info in chain.key_infos().skip(2) {
            match chain.check_trust(iter::once(key_info)) {
                TrustStatus::Trusted(_) => (),
                status => panic!("unexpected trust check outcome: {:?}", status),
            }
        }
    }

    #[test]
    fn check_trust_unknown() {
        let mut rng = rng::new();
        let prefix: Prefix<_> = "10".parse().unwrap();
        let chain = gen_chain(&mut rng, prefix, 100, 2);

        // None of the keys in the chain is trusted - the chain might be valid, but its trust status
        // cannot be determined.
        let (trusted_key_info, _) = gen_key_info(&mut rng, prefix, 99);

        match chain.check_trust(iter::once(&trusted_key_info)) {
            TrustStatus::ProofTooNew => (),
            status => panic!("unexpected trust check outcome: {:?}", status),
        }
    }

    fn gen_key_info(
        rng: &mut MainRng,
        prefix: Prefix<XorName>,
        version: u64,
    ) -> (SectionKeyInfo, bls::SecretKey) {
        let mut rng = RngCompat(rng);
        let secret_key: bls::SecretKey = rng.gen();
        let key_info = SectionKeyInfo::new(prefix, version, secret_key.public_key());

        (key_info, secret_key)
    }

    fn gen_block(
        rng: &mut MainRng,
        prefix: Prefix<XorName>,
        version: u64,
        prev_secret_key: &bls::SecretKey,
    ) -> (SectionProofBlock, bls::SecretKey) {
        let (key_info, secret_key) = gen_key_info(rng, prefix, version);
        let signature = prev_secret_key.sign(key_info.serialise_for_signature().unwrap());

        (SectionProofBlock::new(key_info, signature), secret_key)
    }

    fn gen_chain(
        rng: &mut MainRng,
        prefix: Prefix<XorName>,
        first_version: u64,
        len: usize,
    ) -> SectionProofChain {
        let (key_info, mut current_secret_key) = gen_key_info(rng, prefix, first_version);
        let mut chain = SectionProofChain::new(key_info);

        for n in 1..len {
            let (new_block, new_secret_key) =
                gen_block(rng, prefix, first_version + n as u64, &current_secret_key);
            chain.push(new_block);
            current_secret_key = new_secret_key;
        }

        chain
    }
}
