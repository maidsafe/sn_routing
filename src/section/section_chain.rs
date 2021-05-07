// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::{
    cmp::Ordering,
    collections::HashSet,
    convert::TryFrom,
    fmt::{self, Debug, Formatter},
    iter, mem,
};
use thiserror::Error;

/// Chain of section BLS keys where every key is proven (signed) by its parent key, except the
/// first one.
///
/// # CRDT
///
/// The operations that mutate the chain ([`insert`](Self::insert) and [`merge`](Self::merge)) are
/// commutative, associative and idempotent. This means the chain is a
/// [CRDT](https://en.wikipedia.org/wiki/Conflict-free_replicated_data_type).
///
/// # Forks
///
/// It's possible to insert multiple keys that all have the same parent key. This is called a
/// "fork". The chain implements automatic fork resolution which means that even in the presence of
/// forks the chain presents the blocks in a well-defined unique and deterministic order.
///
/// # Block order
///
/// Block are ordered primarily according to their parent-child relation (parents always precede
/// children) and forks are resolved by additionally ordering the sibling blocks according to the
/// `Ord` relation of their public key. That is, "lower" keys precede "higher" keys.
#[derive(Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(try_from = "Deserialized")]
pub struct SectionChain {
    root: bls::PublicKey,
    tree: Vec<Block>,
}

#[allow(clippy::len_without_is_empty)]
impl SectionChain {
    /// Creates a new chain consisting of only one block.
    pub fn new(root: bls::PublicKey) -> Self {
        Self {
            root,
            tree: Vec::new(),
        }
    }

    /// Insert new key into the chain. `parent_key` must exists in the chain and must validate
    /// `signature`, otherwise error is returned.
    pub fn insert(
        &mut self,
        parent_key: &bls::PublicKey,
        key: bls::PublicKey,
        signature: bls::Signature,
    ) -> Result<(), Error> {
        let parent_index = self.index_of(parent_key).ok_or(Error::KeyNotFound)?;
        let block = Block {
            key,
            signature,
            parent_index,
        };

        if block.verify(parent_key) {
            let _ = self.insert_block(block);
            Ok(())
        } else {
            Err(Error::FailedSignature)
        }
    }

    /// Merges two chains into one.
    ///
    /// This succeeds only if the root key of one of the chain is present in the other one.
    /// Otherwise it returns `Error::InvalidOperation`
    pub fn merge(&mut self, mut other: Self) -> Result<(), Error> {
        let root_index = if let Some(index) = self.index_of(other.root_key()) {
            index
        } else if let Some(index) = other.index_of(self.root_key()) {
            mem::swap(self, &mut other);
            index
        } else {
            return Err(Error::InvalidOperation);
        };

        let mut reindex_map = vec![0; other.len()];
        reindex_map[0] = root_index;

        for (other_index, mut other_block) in other
            .tree
            .into_iter()
            .enumerate()
            .map(|(index, block)| (index + 1, block))
        {
            other_block.parent_index = reindex_map[other_block.parent_index];
            reindex_map[other_index] = self.insert_block(other_block);
        }

        Ok(())
    }

    /// Creates a sub-chain from given `from` and `to` keys.
    /// Returns `Error::KeyNotFound` if the given keys are not present in the chain.
    pub fn get_proof_chain(
        &self,
        from_key: &bls::PublicKey,
        to_key: &bls::PublicKey,
    ) -> Result<Self, Error> {
        self.minimize(vec![from_key, to_key])
    }

    /// Creates a sub-chain from a given key to the end.
    /// Returns `Error::KeyNotFound` if the given from key is not present in the chain.
    pub fn get_proof_chain_to_current(&self, from_key: &bls::PublicKey) -> Result<Self, Error> {
        self.minimize(vec![from_key, self.last_key()])
    }

    /// Creates a minimal sub-chain of `self` that contains all `required_keys`.
    /// Returns `Error::KeyNotFound` if some of `required_keys` is not present in `self`.
    ///
    /// Note: "minimal" means it contains the fewest number of blocks of all such sub-chains.
    pub fn minimize<'a, I>(&self, required_keys: I) -> Result<Self, Error>
    where
        I: IntoIterator<Item = &'a bls::PublicKey>,
    {
        // Note: the returned chain is not always strictly minimal. Consider this chain:
        //
        //     0->1->3->4
        //        |
        //        +->2
        //
        // Then calling `minimize([1, 3])` currently returns
        //
        //     1->3
        //     |
        //     +->2
        //
        // Even though the truly minimal chain containing 1 and 3 is just
        //
        //     1->3
        //
        // This is because 2 lies between 1 and 3 in the underlying `tree` vector and so is
        // currently included.
        //
        // TODO: make this function return the truly minimal chain in all cases.

        let mut min_index = self.len() - 1;
        let mut max_index = 0;

        for key in required_keys {
            let index = self.index_of(key).ok_or(Error::KeyNotFound)?;
            min_index = min_index.min(index);
            max_index = max_index.max(index);
        }

        // To account for forks, we also need to include the closest common ancestors of all the
        // required keys. This is to maintain the invariant that for every key in the chain that is
        // not the root its parent key is also in the chain.
        min_index = self.closest_common_ancestor(min_index, max_index);

        let mut chain = Self::new(if min_index == 0 {
            self.root
        } else {
            self.tree[min_index - 1].key
        });

        for index in min_index..max_index {
            let block = &self.tree[index];

            chain.tree.push(Block {
                key: block.key,
                signature: block.signature.clone(),
                parent_index: block.parent_index - min_index,
            })
        }

        Ok(chain)
    }

    /// Returns a sub-chain of `self` truncated to the last `count` keys.
    /// NOTE: a chain must have at least 1 block, so if `count` is 0 it is treated the same as if
    /// it was 1.
    pub fn truncate(&self, count: usize) -> Self {
        let count = count.max(1);

        let mut tree: Vec<_> = self.branch(self.tree.len()).take(count).cloned().collect();

        let root = if tree.len() >= count {
            tree.pop().map(|block| block.key).unwrap_or(self.root)
        } else {
            self.root
        };

        tree.reverse();

        // Fix the parent indices.
        for (index, block) in tree.iter_mut().enumerate() {
            block.parent_index = index;
        }

        Self { root, tree }
    }

    /// Returns the smallest super-chain of `self` that would be trusted by a peer that trust
    /// `trusted_key`. Ensures that the last key of the resuling chain is the same as the last key
    /// of `self`.
    ///
    /// Returns `Error::KeyNotFound` if any of `trusted_key`, `self.root_key()` or `self.last_key()`
    /// is not present in `super_chain`.
    ///
    /// Returns `Error::InvalidOperation` if `trusted_key` is not reachable from `self.last_key()`.
    pub fn extend(&self, trusted_key: &bls::PublicKey, super_chain: &Self) -> Result<Self, Error> {
        let trusted_key_index = super_chain
            .index_of(trusted_key)
            .ok_or(Error::KeyNotFound)?;
        let last_key_index = super_chain
            .index_of(self.last_key())
            .ok_or(Error::KeyNotFound)?;

        if !super_chain.has_key(self.root_key()) {
            return Err(Error::KeyNotFound);
        }

        if super_chain.is_ancestor(trusted_key_index, last_key_index) {
            super_chain.minimize(vec![trusted_key, self.last_key()])
        } else {
            Err(Error::InvalidOperation)
        }
    }

    /// Iterator over all the keys in the chain in order.
    pub fn keys(&self) -> impl DoubleEndedIterator<Item = &bls::PublicKey> {
        iter::once(&self.root).chain(self.tree.iter().map(|block| &block.key))
    }

    /// Returns the root key of this chain. This is the first key in the chain and is the only key
    /// that doesn't have a parent key.
    pub fn root_key(&self) -> &bls::PublicKey {
        &self.root
    }

    /// Returns the last key of this chain.
    pub fn last_key(&self) -> &bls::PublicKey {
        self.tree
            .last()
            .map(|block| &block.key)
            .unwrap_or(&self.root)
    }

    /// Returns the parent key of the last key or the root key if this chain has only one key.
    pub fn prev_key(&self) -> &bls::PublicKey {
        self.branch(self.tree.len())
            .nth(1)
            .map(|block| &block.key)
            .unwrap_or(&self.root)
    }

    /// Returns whether `key` is present in this chain.
    pub fn has_key(&self, key: &bls::PublicKey) -> bool {
        self.keys().any(|existing_key| existing_key == key)
    }

    /// Given a collection of keys that are already trusted, returns whether this chain is also
    /// trusted. A chain is considered trusted only if at least one of the `trusted_keys` is on its
    /// main branch.
    ///
    /// # Explanation
    ///
    /// Consider this chain that contains fork:
    ///
    /// ```ascii-art
    /// A->B->C
    ///    |
    ///    +->D
    /// ```
    ///
    /// Now if the only trusted key is `D`, then there is no way to prove the chain is trusted,
    /// because this chain would be indistinguishable in terms of trust from any other chain with
    /// the same general "shape", say:
    ///
    /// ```ascii-art
    /// W->X->Y->Z
    ///    |
    ///    +->D
    /// ```
    ///
    /// So an adversary is easily able to forge any such chain.
    ///
    /// When the trusted key is on the main branch, on the other hand:
    ///
    /// ```ascii-art
    /// D->E->F
    ///    |
    ///    +->G
    /// ```
    ///
    /// Then such chain is impossible to forge because the adversary would have to have access to
    /// the secret key corresponding to `D` in order to validly sign `E`. Thus such chain can be
    /// safely considered trusted.
    pub fn check_trust<'a, I>(&self, trusted_keys: I) -> bool
    where
        I: IntoIterator<Item = &'a bls::PublicKey>,
    {
        let trusted_keys: HashSet<_> = trusted_keys.into_iter().collect();
        self.branch(self.tree.len())
            .map(|block| &block.key)
            .chain(iter::once(&self.root))
            .any(|key| trusted_keys.contains(key))
    }

    /// Compare the two keys by their position in the chain. The key that is higher (closer to the
    /// last key) is considered `Greater`. If exactly one of the keys is not in the chain, the other
    /// one is implicitly considered `Greater`. If none are in the chain, they are considered
    /// `Equal`.
    pub fn cmp_by_position(&self, lhs: &bls::PublicKey, rhs: &bls::PublicKey) -> Ordering {
        match (self.index_of(lhs), self.index_of(rhs)) {
            (Some(lhs), Some(rhs)) => lhs.cmp(&rhs),
            (Some(_), None) => Ordering::Greater,
            (None, Some(_)) => Ordering::Less,
            (None, None) => Ordering::Equal,
        }
    }

    /// Returns the number of blocks in the chain. This is always >= 1.
    pub fn len(&self) -> usize {
        1 + self.tree.len()
    }

    /// Returns the number of block on the main branch of the chain - that is - the ones reachable
    /// from the last block.
    ///
    /// NOTE: this is a `O(n)` operation.
    pub fn main_branch_len(&self) -> usize {
        self.branch(self.tree.len()).count() + 1
    }

    fn insert_block(&mut self, new_block: Block) -> usize {
        // Find the index into `self.tree` to insert the new block at so that the block order as
        // described in the `SectionChain` doc comment is maintained.
        let insert_at = self
            .tree
            .iter()
            .enumerate()
            .skip(new_block.parent_index)
            .find(|(_, block)| {
                block.parent_index != new_block.parent_index || block.key >= new_block.key
            })
            .map(|(index, _)| index)
            .unwrap_or(self.tree.len());

        // If the key already exists in the chain, do nothing but still return success to make the
        // `insert` operation idempotent.
        if self.tree.get(insert_at).map(|block| &block.key) != Some(&new_block.key) {
            self.tree.insert(insert_at, new_block);

            // Adjust the parent indices of the keys whose parents are after the inserted key.
            for block in &mut self.tree[insert_at + 1..] {
                if block.parent_index > insert_at {
                    block.parent_index += 1;
                }
            }
        }

        insert_at + 1
    }

    /// Returns the index of the given key. Returns `None` if not present.
    pub fn index_of(&self, key: &bls::PublicKey) -> Option<usize> {
        self.keys()
            .rev()
            .position(|existing_key| existing_key == key)
            .map(|rev_position| self.len() - rev_position - 1)
    }

    fn parent_index_at(&self, index: usize) -> Option<usize> {
        if index == 0 {
            None
        } else {
            self.tree.get(index - 1).map(|block| block.parent_index)
        }
    }

    // Is the key at `lhs` an ancestor of the key at `rhs`?
    fn is_ancestor(&self, lhs: usize, rhs: usize) -> bool {
        let mut index = rhs;
        loop {
            if index == lhs {
                return true;
            }

            if index < lhs {
                return false;
            }

            if let Some(parent_index) = self.parent_index_at(index) {
                index = parent_index;
            } else {
                return false;
            }
        }
    }

    // Returns the index of the closest common ancestor of the keys in the *closed* interval
    // [min_index, max_index].
    fn closest_common_ancestor(&self, mut min_index: usize, mut max_index: usize) -> usize {
        loop {
            if max_index == 0 || min_index == 0 {
                return 0;
            }

            if max_index <= min_index {
                return min_index;
            }

            if let Some(parent_index) = self.parent_index_at(max_index) {
                min_index = min_index.min(parent_index);
            } else {
                return 0;
            }

            max_index -= 1;
        }
    }

    // Iterator over the blocks on the branch that ends at `index` in reverse order.
    // Does not include the root block.
    fn branch(&self, index: usize) -> Branch {
        Branch { chain: self, index }
    }
}

impl Debug for SectionChain {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{:?}", self.keys().format("->"))
    }
}

/// Error resulting from operations on `SectionChain`.
#[allow(missing_docs)]
#[derive(Error, Debug, PartialEq, Eq)]
pub enum Error {
    #[error("signature check failed")]
    FailedSignature,
    #[error("key not found in the chain")]
    KeyNotFound,
    #[error("chain doesn't contain any trusted keys")]
    Untrusted,
    #[error("attempted operation is invalid")]
    InvalidOperation,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
struct Block {
    key: bls::PublicKey,
    signature: bls::Signature,
    parent_index: usize,
}

impl Block {
    fn verify(&self, parent_key: &bls::PublicKey) -> bool {
        bincode::serialize(&self.key)
            .map(|bytes| parent_key.verify(&self.signature, &bytes))
            .unwrap_or(false)
    }
}

// Define a total order on block, to resolve forks.
impl Ord for Block {
    fn cmp(&self, other: &Self) -> Ordering {
        self.key.cmp(&other.key)
    }
}

impl PartialOrd for Block {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// Iterator over the blocks on a single branch of the chain in reverse order.
// Does not include the root block.
struct Branch<'a> {
    chain: &'a SectionChain,
    index: usize,
}

impl<'a> Iterator for Branch<'a> {
    type Item = &'a Block;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index == 0 {
            None
        } else {
            let block = self.chain.tree.get(self.index - 1)?;
            self.index = block.parent_index;
            Some(block)
        }
    }
}

// `SectionChain` is deserialized by first deserializing it into this intermediate structure and
// then converting it into `SectionChain` using `try_from` which fails when the chain is invalid.
// This makes it impossible to obtain invalid `SectionChain` from malformed serialized data, thus
// making `SectionChain` "correct by deserialization".
#[derive(Deserialize)]
#[serde(rename = "SectionChain")]
struct Deserialized {
    root: bls::PublicKey,
    tree: Vec<Block>,
}

impl TryFrom<Deserialized> for SectionChain {
    type Error = IntegrityError;

    fn try_from(src: Deserialized) -> Result<Self, Self::Error> {
        let mut prev_block: Option<&Block> = None;

        for (tree_index, block) in src.tree.iter().enumerate() {
            let parent_key = if block.parent_index == 0 {
                &src.root
            } else if block.parent_index > tree_index {
                return Err(IntegrityError::WrongBlockOrder);
            } else if let Some(key) = src.tree.get(block.parent_index - 1).map(|block| &block.key) {
                key
            } else {
                return Err(IntegrityError::ParentNotFound);
            };

            if !block.verify(parent_key) {
                // Invalid signature
                return Err(IntegrityError::FailedSignature);
            }

            if let Some(prev_block) = prev_block {
                if block.parent_index < prev_block.parent_index {
                    // Wrong order of block that have neither parent-child, not sibling relation.
                    return Err(IntegrityError::WrongBlockOrder);
                }

                if block.parent_index == prev_block.parent_index && block <= prev_block {
                    // Wrong sibling order
                    return Err(IntegrityError::WrongBlockOrder);
                }
            }

            prev_block = Some(block);
        }

        Ok(Self {
            root: src.root,
            tree: src.tree,
        })
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
enum IntegrityError {
    #[error("signature check failed")]
    FailedSignature,
    #[error("parent key not found in the chain")]
    ParentNotFound,
    #[error("chain blocks are in a wrong order")]
    WrongBlockOrder,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_last() {
        let mut expected_keys = vec![];
        let (mut last_sk, pk) = gen_keypair();

        let mut chain = SectionChain::new(pk);
        expected_keys.push(pk);

        for _ in 0..10 {
            let last_pk = &expected_keys[expected_keys.len() - 1];
            let (sk, pk, sig) = gen_signed_keypair(&last_sk);

            assert_eq!(chain.insert(last_pk, pk, sig), Ok(()));

            expected_keys.push(pk);
            last_sk = sk;
        }

        assert_eq!(chain.keys().copied().collect::<Vec<_>>(), expected_keys);
    }

    #[test]
    fn insert_fork() {
        let (sk0, pk0) = gen_keypair();
        let (sk1_a, pk1_a, sig1_a) = gen_signed_keypair(&sk0);
        let (_, pk2_a, sig2_a) = gen_signed_keypair(&sk1_a);
        let (_, pk1_b, sig1_b) = gen_signed_keypair(&sk0);

        let mut chain = SectionChain::new(pk0);
        assert_eq!(chain.insert(&pk0, pk1_a, sig1_a), Ok(()));
        assert_eq!(chain.insert(&pk1_a, pk2_a, sig2_a), Ok(()));
        assert_eq!(chain.insert(&pk0, pk1_b, sig1_b), Ok(()));

        let expected_keys = if pk1_a > pk1_b {
            vec![&pk0, &pk1_b, &pk1_a, &pk2_a]
        } else {
            vec![&pk0, &pk1_a, &pk1_b, &pk2_a]
        };

        let actual_keys: Vec<_> = chain.keys().collect();

        assert_eq!(actual_keys, expected_keys);
    }

    #[test]
    fn insert_duplicate_key() {
        let (sk0, pk0) = gen_keypair();
        let (_, pk1, sig1) = gen_signed_keypair(&sk0);

        let mut chain = SectionChain::new(pk0);
        assert_eq!(chain.insert(&pk0, pk1, sig1.clone()), Ok(()));
        assert_eq!(chain.insert(&pk0, pk1, sig1), Ok(()));
        assert_eq!(chain.keys().collect::<Vec<_>>(), vec![&pk0, &pk1]);
    }

    #[test]
    fn invalid_deserialized_chain_invalid_signature() {
        let (_, pk0) = gen_keypair();
        let (_, pk1) = gen_keypair();

        let bad_sk = bls::SecretKey::random();
        let bad_sig = sign(&bad_sk, &pk1);

        let src = Deserialized {
            root: pk0,
            tree: vec![Block {
                key: pk1,
                signature: bad_sig,
                parent_index: 0,
            }],
        };

        assert_eq!(
            SectionChain::try_from(src),
            Err(IntegrityError::FailedSignature)
        );
    }

    #[test]
    fn invalid_deserialized_chain_wrong_parent_child_order() {
        // 0  2<-1<-+
        // |        |
        // +--------+

        let (sk0, pk0) = gen_keypair();
        let (sk1, pk1, sig1) = gen_signed_keypair(&sk0);
        let (_, pk2, sig2) = gen_signed_keypair(&sk1);

        let src = Deserialized {
            root: pk0,
            tree: vec![
                Block {
                    key: pk2,
                    signature: sig2,
                    parent_index: 2,
                },
                Block {
                    key: pk1,
                    signature: sig1,
                    parent_index: 0,
                },
            ],
        };

        assert_eq!(
            SectionChain::try_from(src),
            Err(IntegrityError::WrongBlockOrder)
        );
    }

    #[test]
    fn invalid_deserialized_chain_wrong_sibling_order() {
        // 0->2 +->1
        // |    |
        // +----+

        let (sk0, pk0) = gen_keypair();

        let block1 = {
            let (_, key, signature) = gen_signed_keypair(&sk0);
            Block {
                key,
                signature,
                parent_index: 0,
            }
        };

        let block2 = {
            let (_, key, signature) = gen_signed_keypair(&sk0);
            Block {
                key,
                signature,
                parent_index: 0,
            }
        };

        let (small, large) = if block1 < block2 {
            (block1, block2)
        } else {
            (block2, block1)
        };

        let src = Deserialized {
            root: pk0,
            tree: vec![large, small],
        };

        assert_eq!(
            SectionChain::try_from(src),
            Err(IntegrityError::WrongBlockOrder)
        );
    }

    #[test]
    fn invalid_deserialized_chain_wrong_unrelated_block_order() {
        // "unrelated" here means the blocks have neither parent-child relation, nor are they
        // siblings.

        // 0->1->2 +->3
        // |       |
        // +-------+

        let (sk0, pk0) = gen_keypair();
        let (sk1, pk1, sig1) = gen_signed_keypair(&sk0);
        let (_, pk2, sig2) = gen_signed_keypair(&sk1);
        let (_, pk3, sig3) = gen_signed_keypair(&sk0);

        let src = Deserialized {
            root: pk0,
            tree: vec![
                Block {
                    key: pk1,
                    signature: sig1,
                    parent_index: 0,
                },
                Block {
                    key: pk2,
                    signature: sig2,
                    parent_index: 1,
                },
                Block {
                    key: pk3,
                    signature: sig3,
                    parent_index: 0,
                },
            ],
        };

        assert_eq!(
            SectionChain::try_from(src),
            Err(IntegrityError::WrongBlockOrder)
        );
    }

    #[test]
    fn merge() {
        let (sk0, pk0) = gen_keypair();
        let (sk1, pk1, sig1) = gen_signed_keypair(&sk0);
        let (sk2, pk2, sig2) = gen_signed_keypair(&sk1);
        let (_, pk3, sig3) = gen_signed_keypair(&sk2);

        // lhs: 0->1->2
        // rhs: 2->3
        // out: 0->1->2->3
        let lhs = make_chain(
            pk0,
            vec![
                (&pk0, pk1, sig1.clone()),
                (&pk1, pk2, sig2.clone()),
                (&pk2, pk3, sig3.clone()),
            ],
        );
        let rhs = make_chain(pk2, vec![(&pk2, pk3, sig3.clone())]);
        assert_eq!(merge_chains(lhs, rhs), Ok(vec![pk0, pk1, pk2, pk3]));

        // lhs: 1->2->3
        // rhs: 0->1
        // out: 0->1->2->3
        let lhs = make_chain(pk1, vec![(&pk1, pk2, sig2), (&pk2, pk3, sig3.clone())]);
        let rhs = make_chain(pk0, vec![(&pk0, pk1, sig1.clone())]);
        assert_eq!(merge_chains(lhs, rhs), Ok(vec![pk0, pk1, pk2, pk3]));

        // lhs: 0->1
        // rhs: 2->3
        // out: Err(Incompatible)
        let lhs = make_chain(pk0, vec![(&pk0, pk1, sig1)]);
        let rhs = make_chain(pk2, vec![(&pk2, pk3, sig3)]);
        assert_eq!(merge_chains(lhs, rhs), Err(Error::InvalidOperation));
    }

    #[test]
    fn merge_fork() {
        let (sk0, pk0) = gen_keypair();
        let (_, pk1, sig1) = gen_signed_keypair(&sk0);
        let (_, pk2, sig2) = gen_signed_keypair(&sk0);

        // rhs: 0->1
        // lhs: 0->2
        // out: Ok(0->1
        //         |
        //         +->2)
        let lhs = make_chain(pk0, vec![(&pk0, pk1, sig1)]);
        let rhs = make_chain(pk0, vec![(&pk0, pk2, sig2)]);

        let expected = if pk1 < pk2 {
            vec![pk0, pk1, pk2]
        } else {
            vec![pk0, pk2, pk1]
        };

        assert_eq!(merge_chains(lhs, rhs), Ok(expected))
    }

    #[test]
    fn minimize() {
        let (sk0, pk0) = gen_keypair();
        let (sk1, pk1, sig1) = gen_signed_keypair(&sk0);
        let (_, pk2, sig2) = gen_signed_keypair(&sk1);

        let chain = make_chain(
            pk0,
            vec![(&pk0, pk1, sig1.clone()), (&pk1, pk2, sig2.clone())],
        );

        assert_eq!(
            chain.minimize(iter::once(&pk0)),
            Ok(make_chain(pk0, vec![]))
        );
        assert_eq!(
            chain.minimize(iter::once(&pk1)),
            Ok(make_chain(pk1, vec![]))
        );
        assert_eq!(
            chain.minimize(iter::once(&pk2)),
            Ok(make_chain(pk2, vec![]))
        );

        assert_eq!(
            chain.minimize(vec![&pk0, &pk1]),
            Ok(make_chain(pk0, vec![(&pk0, pk1, sig1.clone())]))
        );
        assert_eq!(
            chain.minimize(vec![&pk1, &pk2]),
            Ok(make_chain(pk1, vec![(&pk1, pk2, sig2.clone())]))
        );
        assert_eq!(
            chain.minimize(vec![&pk0, &pk1, &pk2]),
            Ok(make_chain(pk0, vec![(&pk0, pk1, sig1), (&pk1, pk2, sig2)]))
        );

        let (_, bad_pk) = gen_keypair();
        assert_eq!(chain.minimize(iter::once(&bad_pk)), Err(Error::KeyNotFound));
    }

    #[test]
    fn minimize_fork() {
        // 0->1->2->3
        //    |
        //    +->4
        let (sk0, pk0) = gen_keypair();
        let (sk1, pk1, sig1) = gen_signed_keypair(&sk0);
        let (sk2, pk2, sig2) = gen_signed_keypair(&sk1);
        let (_, pk3, sig3) = gen_signed_keypair(&sk2);

        // Test both cases (4 < 2 and 4 > 2):
        let k4_small = gen_signed_keypair_filter(&sk1, |pk| pk < &pk2);
        let k4_large = gen_signed_keypair_filter(&sk1, |pk| pk > &pk2);

        for (_, pk4, sig4) in vec![k4_small, k4_large] {
            let chain = make_chain(
                pk0,
                vec![
                    (&pk0, pk1, sig1.clone()),
                    (&pk1, pk2, sig2.clone()),
                    (&pk2, pk3, sig3.clone()),
                    (&pk1, pk4, sig4.clone()),
                ],
            );

            // 1->2->3
            // |
            // +->4
            assert_eq!(
                chain.minimize(vec![&pk3, &pk4]),
                Ok(make_chain(
                    pk1,
                    vec![
                        (&pk1, pk2, sig2.clone()),
                        (&pk2, pk3, sig3.clone()),
                        (&pk1, pk4, sig4)
                    ]
                ))
            );
        }
    }

    // TODO:
    // #[test]
    // fn minimize_trims_unneeded_branches()

    #[test]
    fn truncate() {
        let (sk0, pk0) = gen_keypair();
        let (sk1, pk1, sig1) = gen_signed_keypair(&sk0);
        let (_, pk2, sig2) = gen_signed_keypair(&sk1);

        let chain = make_chain(
            pk0,
            vec![(&pk0, pk1, sig1.clone()), (&pk1, pk2, sig2.clone())],
        );

        assert_eq!(chain.truncate(1), make_chain(pk2, vec![]));
        assert_eq!(
            chain.truncate(2),
            make_chain(pk1, vec![(&pk1, pk2, sig2.clone())])
        );
        assert_eq!(
            chain.truncate(3),
            make_chain(pk0, vec![(&pk0, pk1, sig1), (&pk1, pk2, sig2)])
        );

        // 0 is the same as 1
        assert_eq!(chain.truncate(0), make_chain(pk2, vec![]));
    }

    #[test]
    fn trim_fork() {
        let (sk0, pk0) = gen_keypair();
        let (sk1, pk1, sig1) = gen_signed_keypair(&sk0);
        let (_, pk2, sig2) = gen_signed_keypair(&sk1);
        let (_, pk3, sig3) = gen_signed_keypair(&sk1);

        let chain = make_chain(
            pk0,
            vec![
                (&pk0, pk1, sig1.clone()),
                (&pk1, pk2, sig2.clone()),
                (&pk1, pk3, sig3.clone()),
            ],
        );

        if pk2 < pk3 {
            assert_eq!(chain.truncate(1), make_chain(pk3, vec![]));
            assert_eq!(
                chain.truncate(2),
                make_chain(pk1, vec![(&pk1, pk3, sig3.clone())])
            );
            assert_eq!(
                chain.truncate(3),
                make_chain(pk0, vec![(&pk0, pk1, sig1), (&pk1, pk3, sig3)])
            );
        } else {
            assert_eq!(chain.truncate(1), make_chain(pk2, vec![]));
            assert_eq!(
                chain.truncate(2),
                make_chain(pk1, vec![(&pk1, pk2, sig2.clone())])
            );
            assert_eq!(
                chain.truncate(3),
                make_chain(pk0, vec![(&pk0, pk1, sig1), (&pk1, pk2, sig2)])
            );
        }
    }

    #[test]
    fn extend() {
        let (sk0, pk0) = gen_keypair();
        let (sk1, pk1, sig1) = gen_signed_keypair(&sk0);
        let (sk2, pk2, sig2) = gen_signed_keypair(&sk1);

        // 0->1->2
        let main_chain = make_chain(
            pk0,
            vec![(&pk0, pk1, sig1.clone()), (&pk1, pk2, sig2.clone())],
        );

        // in:      2
        // trusted: 1
        // out:     1->2
        let chain = make_chain(pk2, vec![]);
        assert_eq!(
            chain.extend(&pk1, &main_chain),
            Ok(make_chain(pk1, vec![(&pk1, pk2, sig2.clone())]))
        );

        // in:      2
        // trusted: 0
        // out:     0->1->2
        let chain = make_chain(pk2, vec![]);
        assert_eq!(
            chain.extend(&pk0, &main_chain),
            Ok(make_chain(
                pk0,
                vec![(&pk0, pk1, sig1.clone()), (&pk1, pk2, sig2.clone())]
            ))
        );

        // in:      1->2
        // trusted: 0
        // out:     0->1->2
        let chain = make_chain(pk1, vec![(&pk1, pk2, sig2.clone())]);
        assert_eq!(
            chain.extend(&pk0, &main_chain),
            Ok(make_chain(
                pk0,
                vec![(&pk0, pk1, sig1.clone()), (&pk1, pk2, sig2)]
            ))
        );

        // in:      2->3
        // trusted: 1
        // out:     Error
        let (_, pk3, sig3) = gen_signed_keypair(&sk2);
        let chain = make_chain(pk2, vec![(&pk2, pk3, sig3)]);
        assert_eq!(chain.extend(&pk1, &main_chain), Err(Error::KeyNotFound));

        // in:      2
        // trusted: 2
        // out:     2
        let chain = make_chain(pk2, vec![]);
        assert_eq!(chain.extend(&pk2, &main_chain), Ok(make_chain(pk2, vec![])));

        // in:      1
        // trusted: 0
        // out:     0->1
        let chain = make_chain(pk1, vec![]);
        assert_eq!(
            chain.extend(&pk0, &main_chain),
            Ok(make_chain(pk0, vec![(&pk0, pk1, sig1.clone())]))
        );

        // in:      0->1
        // trusted: 2
        // out:     Error
        let chain = make_chain(pk0, vec![(&pk0, pk1, sig1)]);
        assert_eq!(
            chain.extend(&pk2, &main_chain),
            Err(Error::InvalidOperation)
        );

        // in:      X->Y->2 (forged chain)
        // trusted: 1
        // out:     Error
        let (skx, pkx) = gen_keypair();
        let (sky, pky, sigy) = gen_signed_keypair(&skx);
        let fake_sig2 = sign(&sky, &pk2);
        let chain = make_chain(pkx, vec![(&pkx, pky, sigy), (&pky, pk2, fake_sig2)]);
        assert_eq!(chain.extend(&pk1, &main_chain), Err(Error::KeyNotFound));
    }

    #[test]
    fn extend_unreachable_trusted_key() {
        // main:    0->1->2->3
        //             |
        //             +->4
        let (sk0, pk0) = gen_keypair();
        let (sk1, pk1, sig1) = gen_signed_keypair(&sk0);
        let (sk2, pk2, sig2) = gen_signed_keypair(&sk1);
        let (_, pk3, sig3) = gen_signed_keypair(&sk2);
        let (_, pk4, sig4) = gen_signed_keypair_filter(&sk1, |pk| pk > &pk2);

        let main_chain = make_chain(
            pk0,
            vec![
                (&pk0, pk1, sig1),
                (&pk1, pk2, sig2.clone()),
                (&pk2, pk3, sig3.clone()),
                (&pk1, pk4, sig4),
            ],
        );

        // in:      1->2->3
        // trusted: 4
        // out:     Error::InvalidOperation
        let chain = make_chain(pk1, vec![(&pk1, pk2, sig2), (&pk2, pk3, sig3)]);
        assert_eq!(
            chain.extend(&pk4, &main_chain),
            Err(Error::InvalidOperation)
        );
    }

    #[test]
    fn cmp_by_position() {
        let (sk0, pk0) = gen_keypair();
        let (sk1, pk1, sig1) = gen_signed_keypair(&sk0);
        let (_, pk2, sig2) = gen_signed_keypair(&sk1);

        let main_chain = make_chain(pk0, vec![(&pk0, pk1, sig1), (&pk1, pk2, sig2)]);

        assert_eq!(main_chain.cmp_by_position(&pk0, &pk1), Ordering::Less);
    }

    #[test]
    fn main_branch_len() {
        let (sk0, pk0) = gen_keypair();
        let (_, pk1, sig1) = gen_signed_keypair(&sk0);
        let (_, pk2, sig2) = gen_signed_keypair(&sk0);

        // 0->1
        let chain = make_chain(pk0, vec![(&pk0, pk1, sig1.clone())]);
        assert_eq!(chain.main_branch_len(), 2);

        // 0->1
        // |
        // +->2
        let chain = make_chain(pk0, vec![(&pk0, pk1, sig1), (&pk0, pk2, sig2)]);
        assert_eq!(chain.main_branch_len(), 2);
    }

    fn gen_keypair() -> (bls::SecretKey, bls::PublicKey) {
        let sk = bls::SecretKey::random();
        let pk = sk.public_key();

        (sk, pk)
    }

    fn gen_signed_keypair(
        signing_sk: &bls::SecretKey,
    ) -> (bls::SecretKey, bls::PublicKey, bls::Signature) {
        let (sk, pk) = gen_keypair();
        let signature = sign(signing_sk, &pk);
        (sk, pk, signature)
    }

    // Generate a `(secret_key, public_key, signature)` tuple where `public_key` matches
    // `predicate`.
    fn gen_signed_keypair_filter<F>(
        signing_sk: &bls::SecretKey,
        predicate: F,
    ) -> (bls::SecretKey, bls::PublicKey, bls::Signature)
    where
        F: Fn(&bls::PublicKey) -> bool,
    {
        loop {
            let (sk, pk) = gen_keypair();
            if predicate(&pk) {
                let signature = sign(signing_sk, &pk);
                return (sk, pk, signature);
            }
        }
    }

    fn make_chain(
        root: bls::PublicKey,
        rest: Vec<(&bls::PublicKey, bls::PublicKey, bls::Signature)>,
    ) -> SectionChain {
        let mut chain = SectionChain::new(root);
        for (parent_key, key, signature) in rest {
            assert_eq!(chain.insert(parent_key, key, signature), Ok(()));
        }
        chain
    }

    // Merge `rhs` into `lhs`, verify the resulting chain is valid and return a vector of its keys.
    fn merge_chains(
        mut lhs: SectionChain,
        rhs: SectionChain,
    ) -> Result<Vec<bls::PublicKey>, Error> {
        lhs.merge(rhs)?;
        Ok(lhs.keys().copied().collect())
    }

    fn sign(signing_sk: &bls::SecretKey, pk_to_sign: &bls::PublicKey) -> bls::Signature {
        bincode::serialize(pk_to_sign)
            .map(|bytes| signing_sk.sign(&bytes))
            .expect("failed to serialize public key")
    }
}
