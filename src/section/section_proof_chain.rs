// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::xor_space::{Prefix, XorName};
use std::{collections::HashSet, iter};

/// Block of the section proof chain. Contains the section BLS public key and is signed by the
/// previous block.
#[derive(Debug, Eq, PartialEq, Clone, Hash, Serialize, Deserialize)]
pub struct SectionProofBlock {
    /// The `SectionKeyInfo` containing the section key of this block.
    pub key_info: SectionKeyInfo,
    /// Signature of the above, using the previous block.
    pub signature: bls::Signature,
}

impl SectionProofBlock {
    #[cfg_attr(feature = "mock_base", allow(clippy::trivially_copy_pass_by_ref))]
    pub(crate) fn verify(&self, public_key: &bls::PublicKey) -> bool {
        if let Ok(to_verify) = bincode::serialize(&self.key_info) {
            public_key.verify(&self.signature, to_verify)
        } else {
            false
        }
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

    /// Pushes a new block into the chain. No validation is performed.
    pub fn push(&mut self, block: SectionProofBlock) {
        self.tail.push(block)
    }

    pub(crate) fn first_key_info(&self) -> &SectionKeyInfo {
        &self.head
    }

    pub(crate) fn last_key_info(&self) -> &SectionKeyInfo {
        self.tail
            .last()
            .map(|block| &block.key_info)
            .unwrap_or(&self.head)
    }

    pub(crate) fn key_infos(&self) -> impl DoubleEndedIterator<Item = &SectionKeyInfo> {
        iter::once(&self.head).chain(self.tail.iter().map(|block| &block.key_info))
    }

    /// Returns a slice of this chain starting at the given index.
    pub(crate) fn slice_from(&self, first_index: usize) -> Self {
        if first_index == 0 || self.tail.is_empty() {
            return self.clone();
        }

        let head_index = std::cmp::min(first_index, self.tail.len()) - 1;
        let head = self.tail[head_index].key_info.clone();
        let tail = self.tail[head_index + 1..].to_vec();

        Self { head, tail }
    }

    /// Number of blocks in the chain (including the first block)
    pub(crate) fn len(&self) -> usize {
        1 + self.tail.len()
    }

    /// Check that all the blocks in the chain except the first one have valid signatures.
    /// The first one cannot be verified and requires matching against already trusted keys. Thus
    /// this function alone cannot be used to determine whether this chain is trusted. Use
    /// `check_trust` for that.
    pub(crate) fn self_verify(&self) -> bool {
        let mut current_key = &self.head.key;
        for block in &self.tail {
            if !block.verify(current_key) {
                return false;
            }

            current_key = &block.key_info.key;
        }
        true
    }

    /// Verify this proof chain against the given trusted key infos.
    pub(crate) fn check_trust<'a, I>(&self, trusted_key_infos: I) -> TrustStatus
    where
        I: IntoIterator<Item = &'a SectionKeyInfo>,
    {
        if let Some((index, mut trusted_key)) = self.latest_trusted_key(trusted_key_infos) {
            for block in &self.tail[index..] {
                if !block.verify(trusted_key) {
                    return TrustStatus::Invalid;
                }

                trusted_key = &block.key_info.key;
            }

            TrustStatus::Trusted
        } else if self.self_verify() {
            TrustStatus::Unknown
        } else {
            TrustStatus::Invalid
        }
    }

    // Returns the latest key in this chain that is among the trusted keys, together with its index.
    fn latest_trusted_key<'a, 'b, I>(
        &'a self,
        trusted_key_infos: I,
    ) -> Option<(usize, &'a bls::PublicKey)>
    where
        I: IntoIterator<Item = &'b SectionKeyInfo>,
    {
        let trusted_keys: HashSet<_> = trusted_key_infos
            .into_iter()
            .map(|info| &info.key)
            .collect();
        let last_index = self.len() - 1;

        self.key_infos()
            .rev()
            .enumerate()
            .map(|(rev_index, info)| (last_index - rev_index, &info.key))
            .find(|(_, key)| trusted_keys.contains(key))
    }
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
}

// Result of a message trust check.
#[derive(Debug, Eq, PartialEq)]
pub enum TrustStatus {
    // Proof chain is trusted.
    Trusted,
    // Proof chain is untrusted because one or more blocks in the chain have invalid signatures.
    Invalid,
    // Proof chain is self-validated but its trust cannot be determined because none of the keys
    // in the chain is among the trusted keys.
    Unknown,
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
            assert_eq!(
                chain.check_trust(iter::once(key_info)),
                TrustStatus::Trusted
            )
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
        chain.push(block);

        // Add another block with valid signature by the previous block.
        let (block, _) = gen_block(&mut rng, prefix, 103, &secret_key);
        chain.push(block);

        // If we only trust the keys up to, but excluding the invalid block, the trust check fails
        // because the rest of the chain contains invalid block.
        for key_info in chain.key_infos().take(2) {
            assert_eq!(
                chain.check_trust(iter::once(key_info)),
                TrustStatus::Invalid
            )
        }

        // But if any key at or after the invalid block is trusted, the rest of the chain is
        // trusted as well.
        for key_info in chain.key_infos().skip(2) {
            assert_eq!(
                chain.check_trust(iter::once(key_info)),
                TrustStatus::Trusted
            )
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

        assert_eq!(
            chain.check_trust(iter::once(&trusted_key_info)),
            TrustStatus::Unknown
        )
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
        let signature = prev_secret_key.sign(&bincode::serialize(&key_info).unwrap());

        (
            SectionProofBlock {
                key_info,
                signature,
            },
            secret_key,
        )
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
