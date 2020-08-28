// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use err_derive::Error;
use std::{
    collections::HashSet,
    iter, mem,
    ops::{Bound, RangeBounds},
};

/// Chain of section BLS keys where every key is proven (signed) by the previous key, except the
/// first one.
#[derive(Debug, Eq, PartialEq, Clone, Hash, Serialize, Deserialize)]
pub struct SectionProofChain {
    head: bls::PublicKey,
    tail: Vec<Block>,
}

#[allow(clippy::len_without_is_empty)]
impl SectionProofChain {
    /// Creates new chain consisting of only one block.
    pub fn new(first: bls::PublicKey) -> Self {
        Self {
            head: first,
            tail: Vec::new(),
        }
    }

    /// Pushes a new key into the chain but only if the signature is valid.
    /// Returns whether the chain changed.
    pub(crate) fn push(&mut self, key: bls::PublicKey, signature: bls::Signature) -> bool {
        if self.has_key(&key) {
            trace!("already has key {:?}", key);
            return false;
        }
        let valid = bincode::serialize(&key)
            .map(|bytes| self.last_key().verify(&signature, &bytes))
            .unwrap_or(false);

        if valid {
            self.tail.push(Block { key, signature });
            true
        } else {
            error!(
                "invalid SectionProofChain block signature (last key: {:?})",
                self.last_key()
            );
            false
        }
    }

    /// Pushed a new key into the chain without validating the signature. For testing only.
    #[cfg(any(test, feature = "mock"))]
    pub fn push_without_validation(&mut self, key: bls::PublicKey, signature: bls::Signature) {
        self.tail.push(Block { key, signature })
    }

    /// Returns the first key of the chain.
    pub fn first_key(&self) -> &bls::PublicKey {
        &self.head
    }

    /// Returns the last key of the chain.
    pub fn last_key(&self) -> &bls::PublicKey {
        self.tail
            .last()
            .map(|block| &block.key)
            .unwrap_or(&self.head)
    }

    /// Returns all the keys of the chain as a DoubleEndedIterator.
    pub fn keys(&self) -> impl DoubleEndedIterator<Item = &bls::PublicKey> {
        iter::once(&self.head).chain(self.tail.iter().map(|block| &block.key))
    }

    /// Returns whether this chain contains the given key.
    pub fn has_key(&self, key: &bls::PublicKey) -> bool {
        self.keys().any(|existing_key| existing_key == key)
    }

    /// Returns the index of the key in the chain or `None` if not present in the chain.
    #[cfg_attr(feature = "mock", allow(clippy::trivially_copy_pass_by_ref))]
    pub fn index_of(&self, key: &bls::PublicKey) -> Option<u64> {
        self.keys()
            .position(|existing_key| existing_key == key)
            .map(|index| index as u64)
    }

    /// Returns a subset of this chain specified by the given index range.
    ///
    /// Note: unlike `std::slice`, if the range is invalid or out of bounds, it is silently adjusted
    /// to the nearest valid range and so this function never panics.
    pub fn slice<B: RangeBounds<u64>>(&self, range: B) -> Self {
        let start = match range.start_bound() {
            Bound::Included(index) => *index as usize,
            Bound::Excluded(index) => *index as usize + 1,
            Bound::Unbounded => 0,
        };

        let end = match range.end_bound() {
            Bound::Included(index) => *index as usize + 1,
            Bound::Excluded(index) => *index as usize,
            Bound::Unbounded => self.tail.len() + 1,
        };

        let start = start.min(self.tail.len());
        let end = end.min(self.tail.len() + 1).max(start + 1);

        if start == 0 {
            Self {
                head: self.head,
                tail: self.tail[0..end - 1].to_vec(),
            }
        } else {
            Self {
                head: self.tail[start - 1].key,
                tail: self.tail[start..end - 1].to_vec(),
            }
        }
    }

    /// Number of blocks in the chain (including the first block)
    pub fn len(&self) -> usize {
        1 + self.tail.len()
    }

    /// Index of the last key in the chain.
    pub fn last_key_index(&self) -> u64 {
        self.tail.len() as u64
    }

    /// Check that all the blocks in the chain except the first one have valid signatures.
    /// The first one cannot be verified and requires matching against already trusted keys. Thus
    /// this function alone cannot be used to determine whether this chain is trusted. Use
    /// `check_trust` for that.
    pub fn self_verify(&self) -> bool {
        let mut current_key = &self.head;
        for block in &self.tail {
            if !block.verify(current_key) {
                return false;
            }

            current_key = &block.key;
        }
        true
    }

    /// Verify this proof chain against the given trusted keys.
    pub fn check_trust<'a, I>(&self, trusted_keys: I) -> TrustStatus
    where
        I: IntoIterator<Item = &'a bls::PublicKey>,
    {
        if let Some((index, mut trusted_key)) = self.latest_trusted_key(trusted_keys) {
            for block in &self.tail[index..] {
                if !block.verify(trusted_key) {
                    return TrustStatus::Invalid;
                }

                trusted_key = &block.key;
            }

            TrustStatus::Trusted
        } else if self.self_verify() {
            TrustStatus::Unknown
        } else {
            TrustStatus::Invalid
        }
    }

    // Extend `self` so it starts at `new_first_key` while keeping the last key intact.
    pub(crate) fn extend(
        &mut self,
        new_first_key: &bls::PublicKey,
        full_proof_chain: &Self,
    ) -> Result<(), ExtendError> {
        if self.has_key(new_first_key) {
            return Err(ExtendError::AlreadySufficient);
        }

        let index_from = if let Some(index) = full_proof_chain.index_of(new_first_key) {
            index
        } else {
            return Err(ExtendError::InvalidFirstKey);
        };

        let index_to = if let Some(index) = full_proof_chain.index_of(self.last_key()) {
            index
        } else {
            return Err(ExtendError::InvalidLastKey);
        };

        *self = full_proof_chain.slice(index_from..=index_to);

        Ok(())
    }

    pub(crate) fn merge(&mut self, other: Self) -> Result<(), MergeError> {
        fn check_same_keys<'a>(
            a: impl IntoIterator<Item = &'a bls::PublicKey>,
            b: impl IntoIterator<Item = &'a bls::PublicKey>,
        ) -> Result<(), MergeError> {
            if a.into_iter().zip(b).all(|(a, b)| a == b) {
                Ok(())
            } else {
                Err(MergeError)
            }
        }

        if let Some(first) = self.index_of(other.first_key()) {
            check_same_keys(self.keys().skip(first as usize + 1), other.keys().skip(1))?;

            if self.has_key(other.last_key()) {
                // self:   [a b c]
                // other:    [b]
                // result: [a b c]
                Ok(())
            } else {
                // self:   [a b c]
                // other:    [b c d]
                // result: [a b c d]
                self.tail = mem::take(&mut self.tail)
                    .into_iter()
                    .take(first as usize)
                    .chain(other.tail)
                    .collect();
                Ok(())
            }
        } else if let Some(first) = other.index_of(self.first_key()) {
            check_same_keys(self.keys().skip(1), other.keys().skip(first as usize + 1))?;

            if other.has_key(self.last_key()) {
                // self:     [b]
                // other:  [a b c]
                // result: [a b c]
                self.head = other.head;
                self.tail = other.tail;
                Ok(())
            } else {
                // self:     [b c d]
                // other:  [a b c]
                // result: [a b c d]
                self.head = other.head;
                self.tail = other
                    .tail
                    .into_iter()
                    .take(first as usize)
                    .chain(mem::take(&mut self.tail))
                    .collect();
                Ok(())
            }
        } else {
            Err(MergeError)
        }
    }

    // Returns the latest key in this chain that is among the trusted keys, together with its index.
    fn latest_trusted_key<'a, 'b, I>(
        &'a self,
        trusted_keys: I,
    ) -> Option<(usize, &'a bls::PublicKey)>
    where
        I: IntoIterator<Item = &'b bls::PublicKey>,
    {
        let trusted_keys: HashSet<_> = trusted_keys.into_iter().collect();
        let last_index = self.len() - 1;

        self.keys()
            .rev()
            .enumerate()
            .map(|(rev_index, key)| (last_index - rev_index, key))
            .find(|(_, key)| trusted_keys.contains(key))
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

/// Error returned from `SectionProofChain::extend`
#[derive(Debug, Error)]
pub enum ExtendError {
    #[error(display = "invalid first key")]
    InvalidFirstKey,
    #[error(display = "invalid last key")]
    InvalidLastKey,
    #[error(display = "proof chain already sufficient")]
    AlreadySufficient,
}

/// Error returned from `SectionProofChain::merge`
#[derive(Debug, Error, Eq, PartialEq)]
#[error(display = "incompatible chains cannot be merged")]
pub struct MergeError;

// Block of the section proof chain. Contains the section BLS public key and is signed by the
// previous block. Note that the first key in the chain is not signed and so is not stored in
// `Block`.
#[derive(Debug, Eq, PartialEq, Clone, Hash, Serialize, Deserialize)]
struct Block {
    key: bls::PublicKey,
    signature: bls::Signature,
}

impl Block {
    #[cfg_attr(feature = "mock", allow(clippy::trivially_copy_pass_by_ref))]
    fn verify(&self, public_key: &bls::PublicKey) -> bool {
        bincode::serialize(&self.key)
            .map(|bytes| public_key.verify(&self.signature, &bytes))
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        consensus,
        rng::{self, MainRng},
    };
    use std::{iter, ops::Range};

    #[test]
    fn check_trust_trusted() {
        let mut rng = rng::new();
        let (chain, _) = gen_chain(&mut rng, 4);

        // If any key in the chain is already trusted, the whole chain is trusted.
        for key in chain.keys() {
            assert_eq!(chain.check_trust(iter::once(key)), TrustStatus::Trusted)
        }
    }

    #[test]
    fn check_trust_invalid() {
        let mut rng = rng::new();
        let (mut chain, _) = gen_chain(&mut rng, 2);

        // Add a block with invalid signature to the chain.
        let (_, invalid_secret_key) = gen_keys(&mut rng);
        let (key, signature, secret_key) = gen_block(&mut rng, &invalid_secret_key);
        chain.push_without_validation(key, signature);

        // Add another block with valid signature by the previous block.
        let (key, signature, _) = gen_block(&mut rng, &secret_key);
        let _ = chain.push(key, signature);

        // If we only trust the keys up to, but excluding the invalid block, the trust check fails
        // because the rest of the chain contains invalid block.
        for key in chain.keys().take(2) {
            assert_eq!(chain.check_trust(iter::once(key)), TrustStatus::Invalid)
        }

        // But if any key at or after the invalid block is trusted, the rest of the chain is
        // trusted as well.
        for key in chain.keys().skip(2) {
            assert_eq!(chain.check_trust(iter::once(key)), TrustStatus::Trusted)
        }
    }

    #[test]
    fn check_trust_unknown() {
        let mut rng = rng::new();
        let (chain, _) = gen_chain(&mut rng, 2);

        // None of the keys in the chain is trusted - the chain might be valid, but its trust status
        // cannot be determined.
        let (trusted_key, _) = gen_keys(&mut rng);

        assert_eq!(
            chain.check_trust(iter::once(&trusted_key)),
            TrustStatus::Unknown
        )
    }

    #[test]
    // Clippy complains that range such as `1..1` yield no values, though the slice function still
    // support it.
    #[allow(clippy::reversed_empty_ranges)]
    fn slice() {
        let mut rng = rng::new();
        let (chain, _) = gen_chain(&mut rng, 3);
        let keys: Vec<_> = chain.keys().collect();

        let assert_keys_eq = |chain: SectionProofChain, expected: &[_]| {
            let actual: Vec<_> = chain.keys().collect();
            assert_eq!(&actual[..], expected)
        };

        assert_keys_eq(chain.slice(..), &keys[0..3]);
        assert_keys_eq(chain.slice(0..), &keys[0..3]);
        assert_keys_eq(chain.slice(1..), &keys[1..3]);
        assert_keys_eq(chain.slice(2..), &keys[2..3]);
        assert_keys_eq(chain.slice(3..), &keys[2..3]);
        assert_keys_eq(chain.slice(..0), &keys[0..1]);
        assert_keys_eq(chain.slice(..1), &keys[0..1]);
        assert_keys_eq(chain.slice(..2), &keys[0..2]);
        assert_keys_eq(chain.slice(..3), &keys[0..3]);
        assert_keys_eq(chain.slice(..4), &keys[0..3]);
        assert_keys_eq(chain.slice(..=0), &keys[0..1]);
        assert_keys_eq(chain.slice(..=1), &keys[0..2]);
        assert_keys_eq(chain.slice(..=2), &keys[0..3]);
        assert_keys_eq(chain.slice(..=3), &keys[0..3]);
        assert_keys_eq(chain.slice(0..0), &keys[0..1]);
        assert_keys_eq(chain.slice(0..1), &keys[0..1]);
        assert_keys_eq(chain.slice(0..2), &keys[0..2]);
        assert_keys_eq(chain.slice(0..3), &keys[0..3]);
        assert_keys_eq(chain.slice(0..4), &keys[0..3]);
        assert_keys_eq(chain.slice(1..1), &keys[1..2]);
        assert_keys_eq(chain.slice(1..2), &keys[1..2]);
        assert_keys_eq(chain.slice(1..3), &keys[1..3]);
        assert_keys_eq(chain.slice(2..2), &keys[2..3]);
        assert_keys_eq(chain.slice(2..3), &keys[2..3]);
        assert_keys_eq(chain.slice(0..=0), &keys[0..1]);
        assert_keys_eq(chain.slice(0..=1), &keys[0..2]);
        assert_keys_eq(chain.slice(0..=2), &keys[0..3]);
        assert_keys_eq(chain.slice(0..=3), &keys[0..3]);
    }

    #[test]
    fn merge() {
        let mut rng = rng::new();
        let (chain, _) = gen_chain(&mut rng, 4);

        let check = |a: Range<u64>, b: Range<u64>, expected: Result<Range<u64>, MergeError>| {
            let mut a = chain.slice(a);
            let b = chain.slice(b);
            let result = a.merge(b);

            match expected {
                Ok(range) => {
                    assert_eq!(result, Ok(()));
                    assert_eq!(a, chain.slice(range));
                }
                Err(error) => assert_eq!(result, Err(error)),
            }
        };

        // A: [a]
        // B: [a]
        // R: [a]
        check(0..1, 0..1, Ok(0..1));

        // A: [a]
        // B: [a b]
        // R: [a b]
        check(0..1, 0..2, Ok(0..2));

        // A: [a b]
        // B: [a]
        // R: [a b]
        check(0..2, 0..1, Ok(0..2));

        // A:   [b]
        // B: [a b]
        // R: [a b]
        check(1..2, 0..2, Ok(0..2));

        // A: [a b]
        // B:   [b]
        // R: [a b]
        check(0..2, 1..2, Ok(0..2));

        // A: [a b]
        // B: [a b]
        // R: [a b]
        check(0..2, 0..2, Ok(0..2));

        // A: [a b]
        // B:   [b c]
        // R: [a b c]
        check(0..2, 1..3, Ok(0..3));

        // A:   [b c]
        // B: [a b]
        // R: [a b c]
        check(1..3, 0..2, Ok(0..3));

        // A: [a b c]
        // B:   [b]
        // R: [a b c]
        check(0..3, 1..2, Ok(0..3));

        // A:   [b]
        // B: [a b c]
        // R: [a b c]
        check(1..2, 0..3, Ok(0..3));

        // A: [a]
        // B:   [b]
        // R: Err
        check(0..1, 1..2, Err(MergeError));

        // A: [b]
        // B:   [a]
        // R: Err
        check(1..2, 0..1, Err(MergeError));
    }

    #[test]
    fn merge_fork() {
        // A: [a b c d]
        // B: [a b c x]
        // R: Err

        let mut rng = rng::new();

        let (mut chain0, sk) = gen_chain(&mut rng, 3);
        let mut chain1 = chain0.clone();

        let (c0b0_pk, c0b0_signature, _) = gen_block(&mut rng, &sk);
        let _ = chain0.push(c0b0_pk, c0b0_signature);

        let (c1b0_pk, c1b0_signature, _) = gen_block(&mut rng, &sk);
        let _ = chain1.push(c1b0_pk, c1b0_signature);

        assert_eq!(chain0.merge(chain1), Err(MergeError));
    }

    #[test]
    fn merge_fork_join() {
        // A: [a b c d e]
        // B: [a b c x e]
        // R: Err

        let mut rng = rng::new();

        let (mut chain0, sk) = gen_chain(&mut rng, 3);
        let mut chain1 = chain0.clone();

        let (c0b0_pk, c0b0_signature, c0b0_sk) = gen_block(&mut rng, &sk);
        let _ = chain0.push(c0b0_pk, c0b0_signature);

        let (c1b0_pk, c1b0_signature, c1b0_sk) = gen_block(&mut rng, &sk);
        let _ = chain1.push(c1b0_pk, c1b0_signature);

        let (b1_pk, _) = gen_keys(&mut rng);
        let c0b1_signature = c0b0_sk.sign(&bincode::serialize(&b1_pk).unwrap());
        let _ = chain0.push(b1_pk, c0b1_signature);

        let c1b1_signature = c1b0_sk.sign(&bincode::serialize(&b1_pk).unwrap());
        let _ = chain1.push(b1_pk, c1b1_signature);

        assert_eq!(chain0.merge(chain1), Err(MergeError));
    }

    fn gen_keys(rng: &mut MainRng) -> (bls::PublicKey, bls::SecretKey) {
        let secret_key = consensus::test_utils::gen_secret_key(rng);
        (secret_key.public_key(), secret_key)
    }

    fn gen_block(
        rng: &mut MainRng,
        prev_secret_key: &bls::SecretKey,
    ) -> (bls::PublicKey, bls::Signature, bls::SecretKey) {
        let (public_key, secret_key) = gen_keys(rng);
        let signature = prev_secret_key.sign(&bincode::serialize(&public_key).unwrap());

        (public_key, signature, secret_key)
    }

    fn gen_chain(rng: &mut MainRng, len: usize) -> (SectionProofChain, bls::SecretKey) {
        let (key, mut current_secret_key) = gen_keys(rng);
        let mut chain = SectionProofChain::new(key);

        for _ in 1..len {
            let (new_public_key, new_signature, new_secret_key) =
                gen_block(rng, &current_secret_key);
            let _ = chain.push(new_public_key, new_signature);
            current_secret_key = new_secret_key;
        }

        (chain, current_secret_key)
    }
}
