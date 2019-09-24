// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{bls_emu::BlsPublicKeyForSectionKeyInfo, AccumulatingProof, SectionInfo};
use crate::{
    crypto::Digest256, error::RoutingError, BlsPublicKey, BlsPublicKeySet, BlsSignature, Prefix,
    XorName,
};
use itertools::Itertools;
use log::LogLevel;
use maidsafe_utilities::serialisation;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fmt::{self, Debug, Formatter},
    iter, mem,
};
use unwrap::unwrap;

// Number of recent keys we keep: i.e how many other section churns we can handle before a
// message send with a previous version of a section is no longer trusted.
// With low churn rate, a ad hoc 10 should be big enough to avoid losing messages.
const MAX_THEIR_RECENT_KEYS: usize = 10;

/// Section state that is shared among all elders of a section via Parsec consensus.
#[derive(Debug, PartialEq, Eq)]
pub struct SharedState {
    /// The new self section info, that doesn't necessarily have a full set of signatures yet.
    pub new_info: SectionInfo,
    /// The latest few fully signed infos of our own sections.
    /// This is not a `BTreeSet` as it is ordered according to the sequence of pushes into it.
    pub our_infos: NonEmptyList<SectionInfo>,
    /// Maps our neighbours' prefixes to their latest signed section infos.
    /// Note that after a split, the neighbour's latest section info could be the one from the
    /// pre-split parent section, so the value's prefix doesn't always match the key.
    pub neighbour_infos: BTreeMap<Prefix<XorName>, SectionInfo>,
    /// Any change (split or merge) to the section that is currently in progress.
    pub change: PrefixChange,
    // The accumulated `SectionInfo`(self or sibling) and proofs during a split pfx change.
    pub split_cache: Option<(SectionInfo, AccumulatingProof)>,
    /// The set of section info hashes that are currently merging.
    pub merging: BTreeSet<Digest256>,
    /// Our section's key history for Secure Message Delivery
    pub our_history: SectionProofChain,
    /// BLS public keys of other sections
    pub their_keys: BTreeMap<Prefix<XorName>, SectionKeyInfo>,
    /// Other sections' knowledge of us
    pub their_knowledge: BTreeMap<Prefix<XorName>, u64>,
    /// Recent keys removed from their_keys
    pub their_recent_keys: VecDeque<(Prefix<XorName>, SectionKeyInfo)>,
}

impl SharedState {
    pub fn new(section_info: SectionInfo) -> Self {
        let pk_info = SectionKeyInfo::from_section_info(&section_info);
        let our_history = SectionProofChain::from_genesis(pk_info);
        let their_key_info = our_history.last_public_key_info();
        let their_keys = iter::once((*their_key_info.prefix(), their_key_info.clone())).collect();

        Self {
            new_info: section_info.clone(),
            our_infos: NonEmptyList::new(section_info),
            neighbour_infos: Default::default(),
            change: PrefixChange::None,
            split_cache: None,
            merging: Default::default(),
            our_history,
            their_keys,
            their_knowledge: Default::default(),
            their_recent_keys: Default::default(),
        }
    }

    pub fn update_with_genesis_related_info(
        &mut self,
        related_info: &[u8],
    ) -> Result<(), RoutingError> {
        if related_info.is_empty() {
            return Ok(());
        }

        let (
            our_infos,
            our_history,
            neighbour_infos,
            their_keys,
            their_knowledge,
            their_recent_keys,
        ) = serialisation::deserialise(related_info)?;
        if self.our_infos.len() != 1 {
            // Check nodes with a history before genesis match the genesis block:
            if self.our_infos != our_infos {
                log_or_panic!(
                    LogLevel::Error,
                    "update_with_genesis_related_info different our_infos:\n{:?},\n{:?}",
                    self.our_infos,
                    our_infos
                );
            }
            if self.our_history != our_history {
                log_or_panic!(
                    LogLevel::Error,
                    "update_with_genesis_related_info different our_history:\n{:?},\n{:?}",
                    self.our_history,
                    our_history
                );
            }
            if self.neighbour_infos != neighbour_infos {
                log_or_panic!(
                    LogLevel::Error,
                    "update_with_genesis_related_info different neighbour_infos:\n{:?},\n{:?}",
                    self.neighbour_infos,
                    neighbour_infos
                );
            }
            if self.their_keys != their_keys {
                log_or_panic!(
                    LogLevel::Error,
                    "update_with_genesis_related_info different their_keys:\n{:?},\n{:?}",
                    self.their_keys,
                    their_keys
                );
            }
            if self.their_knowledge != their_knowledge {
                log_or_panic!(
                    LogLevel::Error,
                    "update_with_genesis_related_info different their_knowledge:\n{:?},\n{:?}",
                    self.their_knowledge,
                    their_knowledge
                );
            }
            if self.their_recent_keys != their_recent_keys {
                log_or_panic!(
                    LogLevel::Error,
                    "update_with_genesis_related_info different their_recent_keys:\n{:?},\n{:?}",
                    self.their_recent_keys,
                    their_recent_keys
                );
            }
        }
        self.our_infos = our_infos;
        self.our_history = our_history;
        self.neighbour_infos = neighbour_infos;
        self.their_keys = their_keys;
        self.their_knowledge = their_knowledge;
        self.their_recent_keys = their_recent_keys;

        Ok(())
    }

    pub fn get_genesis_related_info(&self) -> Result<Vec<u8>, RoutingError> {
        Ok(serialisation::serialise(&(
            &self.our_infos,
            &self.our_history,
            &self.neighbour_infos,
            &self.their_keys,
            &self.their_knowledge,
            &self.their_recent_keys,
        ))?)
    }

    pub fn our_infos(&self) -> impl Iterator<Item = &SectionInfo> + DoubleEndedIterator {
        self.our_infos.iter()
    }

    /// Returns our own current section info.
    pub fn our_info(&self) -> &SectionInfo {
        &self.our_infos.last()
    }

    pub fn our_prefix(&self) -> &Prefix<XorName> {
        self.our_info().prefix()
    }

    pub fn our_version(&self) -> u64 {
        *self.our_info().version()
    }

    /// Returns our section info with the given hash, if it exists.
    pub fn our_info_by_hash(&self, hash: &Digest256) -> Option<&SectionInfo> {
        self.our_infos
            .iter()
            .find(|sec_info| sec_info.hash() == hash)
    }

    /// Returns `true` if we have accumulated self `AccumulatingEvent::OurMerge`.
    pub(super) fn is_self_merge_ready(&self) -> bool {
        self.merging.contains(self.our_info().hash())
    }

    /// Returns the next section info if both we and our sibling have signalled for merging.
    pub(super) fn try_merge(&mut self) -> Result<Option<SectionInfo>, RoutingError> {
        let their_info = match self.neighbour_infos.get(&self.our_prefix().sibling()) {
            Some(sec_info) => sec_info,
            None => return Ok(None),
        };

        let our_hash = *self.our_info().hash();
        let their_hash = their_info.hash();

        if self.merging.contains(their_hash) && self.merging.contains(&our_hash) {
            let _ = self.merging.remove(their_hash);
            let _ = self.merging.remove(&our_hash);
            self.new_info = self.our_info().merge(their_info)?;
            Ok(Some(self.new_info.clone()))
        } else {
            Ok(None)
        }
    }

    /// Returns `true` if we should merge.
    pub(super) fn should_vote_for_merge<'a, I>(
        &self,
        min_section_size: usize,
        neighbour_infos: I,
    ) -> bool
    where
        I: IntoIterator<Item = &'a SectionInfo>,
    {
        let pfx = self.our_prefix();
        if pfx.is_empty() || self.change == PrefixChange::Splitting {
            return false;
        }

        if self.our_info().members().len() < min_section_size {
            return true;
        }

        let needs_merge = |si: &SectionInfo| {
            pfx.is_compatible(&si.prefix().sibling())
                && (si.members().len() < min_section_size || self.merging.contains(si.hash()))
        };

        neighbour_infos.into_iter().any(needs_merge)
    }

    pub fn push_our_new_info(
        &mut self,
        sec_info: SectionInfo,
        proofs: AccumulatingProof,
        pk_set: &BlsPublicKeySet,
    ) -> Result<(), RoutingError> {
        let proof_block = if let Some(proof_block) =
            SectionProofBlock::from_sec_info_with_proofs(&sec_info, proofs, pk_set)
        {
            proof_block
        } else {
            return Err(RoutingError::InvalidNewSectionInfo);
        };

        self.our_history.push(proof_block);
        self.our_infos.push(sec_info);

        let key_info = self.our_history.last_public_key_info().clone();
        self.update_their_keys(&key_info);
        Ok(())
    }

    /// Updates the entry in `their_keys` for `prefix` to the latest known key; if a split
    /// occurred in the meantime, the keys for sections covering the rest of the address space are
    /// initialised to the old key that was stored for their common ancestor
    /// NOTE: the function as it is currently is not merge-safe.
    pub fn update_their_keys(&mut self, key_info: &SectionKeyInfo) {
        if let Some((&old_pfx, old_version)) = self
            .their_keys
            .iter()
            .find(|(pfx, _)| pfx.is_compatible(key_info.prefix()))
            .map(|(pfx, info)| (pfx, info.version()))
        {
            if old_version >= key_info.version() || old_pfx.is_extension_of(key_info.prefix()) {
                // Do not overwrite newer version or prefix extensions
                return;
            }

            let old_key_info = unwrap!(self.their_keys.remove(&old_pfx));
            self.their_recent_keys
                .push_front((old_pfx, old_key_info.clone()));
            if self.their_recent_keys.len() > MAX_THEIR_RECENT_KEYS {
                let _ = self.their_recent_keys.pop_back();
            }

            trace!("    from {:?} to {:?}", old_key_info, key_info);

            let old_pfx_sibling = old_pfx.sibling();
            let mut current_pfx = key_info.prefix().sibling();
            while !self.their_keys.contains_key(&current_pfx) && current_pfx != old_pfx_sibling {
                let _ = self.their_keys.insert(current_pfx, old_key_info.clone());
                current_pfx = current_pfx.popped().sibling();
            }
        }
        let _ = self.their_keys.insert(*key_info.prefix(), key_info.clone());
    }

    /// Updates the entry in `their_knowledge` for `prefix` to the `version`; if a split
    /// occurred in the meantime, the versions for sections covering the rest of the address space
    /// are initialised to the old version that was stored for their common ancestor
    /// NOTE: the function as it is currently is not merge-safe.
    pub fn update_their_knowledge(&mut self, prefix: Prefix<XorName>, version: u64) {
        if let Some((&old_pfx, &old_version)) = self
            .their_knowledge
            .iter()
            .find(|(pfx, _)| pfx.is_compatible(&prefix))
        {
            if old_version >= version || old_pfx.is_extension_of(&prefix) {
                // Do not overwrite newer version or prefix extensions
                return;
            }

            let _ = self.their_knowledge.remove(&old_pfx);

            trace!(
                "    from {:?}/{:?} to {:?}/{:?}",
                old_pfx,
                old_version,
                prefix,
                version
            );

            let old_pfx_sibling = old_pfx.sibling();
            let mut current_pfx = prefix.sibling();
            while !self.their_knowledge.contains_key(&current_pfx) && current_pfx != old_pfx_sibling
            {
                let _ = self.their_knowledge.insert(current_pfx, old_version);
                current_pfx = current_pfx.popped().sibling();
            }
        }
        let _ = self.their_knowledge.insert(prefix, version);
    }

    /// Returns the reference to their_keys and any recent keys we still hold.
    pub fn get_their_keys_info(&self) -> impl Iterator<Item = (&Prefix<XorName>, &SectionKeyInfo)> {
        self.their_keys
            .iter()
            .chain(self.their_recent_keys.iter().map(|(p, k)| (p, k)))
    }

    #[cfg(feature = "mock_base")]
    /// Returns their_knowledge
    pub fn get_their_knowledge(&self) -> &BTreeMap<Prefix<XorName>, u64> {
        &self.their_knowledge
    }
}

/// The prefix-affecting change (split or merge) to our own section that is currently in progress.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PrefixChange {
    None,
    Splitting,
    Merging,
}

/// Vec-like container that is guaranteed to contain at least one element.
#[derive(PartialEq, Eq, Serialize, Deserialize)]
pub struct NonEmptyList<T> {
    head: Vec<T>,
    tail: T,
}

impl<T> NonEmptyList<T> {
    pub fn new(first: T) -> Self {
        Self {
            head: Vec::new(),
            tail: first,
        }
    }

    pub fn push(&mut self, item: T) {
        self.head.push(mem::replace(&mut self.tail, item))
    }

    pub fn len(&self) -> usize {
        self.head.len() + 1
    }

    pub fn iter(&self) -> impl Iterator<Item = &T> + DoubleEndedIterator {
        self.head.iter().chain(iter::once(&self.tail))
    }

    pub fn last(&self) -> &T {
        &self.tail
    }
}

impl<T> Debug for NonEmptyList<T>
where
    T: Debug,
{
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "[{:?}]", self.iter().format(", "))
    }
}

#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Hash, Serialize, Deserialize)]
pub struct SectionProofBlock {
    key_info: SectionKeyInfo,
    sig: BlsSignature,
}

impl Debug for SectionProofBlock {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "SectionProofBlock {{ key_info: {:?}, sig: .. }}",
            self.key_info()
        )
    }
}

impl SectionProofBlock {
    pub fn from_sec_info_with_proofs(
        sec_info: &SectionInfo,
        proofs: AccumulatingProof,
        pk_set: &BlsPublicKeySet,
    ) -> Option<Self> {
        let key_info = SectionKeyInfo::from_section_info(sec_info);

        let sig_shares = proofs.into_sig_shares();
        let sig = pk_set.combine_signatures(
            sig_shares
                .values()
                .map(|sig_payload| (sig_payload.pub_key_share, &sig_payload.sig_share)),
        );

        sig.map(|sig| SectionProofBlock { key_info, sig })
    }

    pub fn key_info(&self) -> &SectionKeyInfo {
        &self.key_info
    }

    pub fn key(&self) -> &BlsPublicKey {
        self.key_info.key()
    }

    pub fn verify_with_pk(&self, pk: &BlsPublicKey) -> bool {
        if let Some(to_verify) = self.key_info.serialise_for_signature() {
            pk.verify(&self.sig, to_verify)
        } else {
            false
        }
    }
}

#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone, Hash, Serialize, Deserialize)]
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

    pub fn blocks_len(&self) -> usize {
        self.blocks.len()
    }

    pub fn push(&mut self, block: SectionProofBlock) {
        self.blocks.push(block);
    }

    pub fn validate(&self) -> bool {
        let mut current_pk = self.genesis_key_info.key();
        for block in &self.blocks {
            if !block.verify_with_pk(current_pk) {
                return false;
            }
            current_pk = block.key();
        }
        true
    }

    pub fn last_public_key_info(&self) -> &SectionKeyInfo {
        self.blocks
            .last()
            .map(|block| block.key_info())
            .unwrap_or(&self.genesis_key_info)
    }

    pub fn last_public_key(&self) -> &BlsPublicKey {
        self.last_public_key_info().key()
    }

    pub fn all_key_infos(&self) -> impl DoubleEndedIterator<Item = &SectionKeyInfo> {
        iter::once(&self.genesis_key_info).chain(self.blocks.iter().map(|block| block.key_info()))
    }

    pub fn slice_from(&self, first_index: usize) -> SectionProofChain {
        if first_index == 0 || self.blocks.is_empty() {
            return self.clone();
        }

        let genesis_index = std::cmp::min(first_index, self.blocks.len()) - 1;
        let genesis_key_info = self.blocks[genesis_index].key_info().clone();

        let block_first_index = genesis_index + 1;
        let blocks = if block_first_index >= self.blocks.len() {
            vec![]
        } else {
            self.blocks[block_first_index..].to_vec()
        };

        SectionProofChain {
            genesis_key_info,
            blocks,
        }
    }
}

#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Hash, Serialize, Deserialize)]
pub struct SectionKeyInfo {
    // Hold all the information that is signed. When switching to real BLS, SectionKeyInfo
    // will hold the BlsPublicKey, prefix and version and will be the item to sign.
    key_info_holder: BlsPublicKeyForSectionKeyInfo,
}

impl SectionKeyInfo {
    pub fn from_section_info(sec_info: &SectionInfo) -> Self {
        Self {
            key_info_holder: BlsPublicKeyForSectionKeyInfo::from_section_info(sec_info),
        }
    }

    pub fn key(&self) -> &BlsPublicKey {
        self.key_info_holder.key()
    }

    pub fn prefix(&self) -> &Prefix<XorName> {
        self.key_info_holder.internal_section_info().prefix()
    }

    pub fn version(&self) -> &u64 {
        self.key_info_holder.internal_section_info().version()
    }

    pub fn serialise_for_signature(&self) -> Option<Vec<u8>> {
        serialisation::serialise(self.key_info_holder.internal_section_info()).ok()
    }
}

impl Debug for SectionKeyInfo {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "SectionKeyInfo {{ prefix: {:?}, version: {:?}, key: {:?} }}",
            self.prefix(),
            self.version(),
            self.key(),
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{chain::SectionInfo, FullId, Prefix, XorName};
    use std::collections::BTreeSet;
    use std::str::FromStr;
    use unwrap::unwrap;

    fn gen_section_info(pfx: Prefix<XorName>, version: u64) -> SectionInfo {
        let sec_size = 5;
        let mut members = BTreeSet::new();
        for _ in 0..sec_size {
            let id = FullId::within_range(&pfx.range_inclusive());
            let _ = members.insert(*id.public_id());
        }
        unwrap!(SectionInfo::new_for_test(members, pfx, version))
    }

    // start_pfx: the prefix of our section as string
    // updates: our section prefix followed by the prefixes of the sections we update the keys for,
    //          in sequence; every entry in the vector will get its own key.
    // expected: vec of pairs (prefix, index)
    //           the prefix is the prefix of the section whose key we check
    //           the index is the index in the `updates` vector, which should have generated the
    //           key we expect to get for the given prefix
    fn update_keys_and_check(updates: Vec<&str>, expected: Vec<(&str, usize)>) {
        update_keys_and_check_with_version(updates.into_iter().enumerate().collect(), expected)
    }

    fn update_keys_and_check_with_version(
        updates: Vec<(usize, &str)>,
        expected: Vec<(&str, usize)>,
    ) {
        //
        // Arrange
        //
        let keys_to_update = updates
            .into_iter()
            .map(|(version, pfx_str)| {
                let pfx = unwrap!(Prefix::<XorName>::from_str(pfx_str));
                let sec_info = gen_section_info(pfx, version as u64);
                let key_info = SectionKeyInfo::from_section_info(&sec_info);
                (key_info, sec_info)
            })
            .collect::<Vec<_>>();
        let expected_keys = expected
            .into_iter()
            .map(|(pfx_str, index)| {
                let pfx = unwrap!(Prefix::<XorName>::from_str(pfx_str));
                (pfx, Some(index))
            })
            .collect::<Vec<_>>();

        let mut state = {
            let start_section = unwrap!(keys_to_update.first()).1.clone();
            SharedState::new(start_section)
        };

        //
        // Act
        //
        for (key_info, _) in keys_to_update.iter().skip(1) {
            state.update_their_keys(key_info);
        }

        //
        // Assert
        //
        let actual_keys = state
            .get_their_keys_info()
            .map(|(p, info)| {
                (
                    *p,
                    keys_to_update
                        .iter()
                        .position(|(key_info, _)| key_info == info),
                )
            })
            .collect::<Vec<_>>();

        assert_eq!(actual_keys, expected_keys);
    }

    #[test]
    fn single_prefix_multiple_updates() {
        update_keys_and_check(
            vec!["0", "1", "1", "1", "1"],
            vec![("0", 0), ("1", 4), ("1", 3), ("1", 2), ("1", 1)],
        );
    }

    #[test]
    fn single_prefix_multiple_updates_out_of_order() {
        // Late version ignored
        update_keys_and_check_with_version(
            vec![(0, "0"), (0, "1"), (2, "1"), (1, "1"), (3, "1")],
            vec![("0", 0), ("1", 4), ("1", 2), ("1", 1)],
        );
    }

    #[test]
    fn simple_split() {
        update_keys_and_check(
            vec!["0", "10", "11", "101"],
            vec![("0", 0), ("100", 1), ("101", 3), ("11", 2), ("10", 1)],
        );
    }

    #[test]
    fn simple_split_out_of_order() {
        // Late version ignored
        update_keys_and_check_with_version(
            vec![(0, "0"), (5, "10"), (5, "11"), (7, "101"), (6, "10")],
            vec![("0", 0), ("100", 1), ("101", 3), ("11", 2), ("10", 1)],
        );
    }

    #[test]
    fn our_section_not_sibling_of_ancestor() {
        // 01 Not the sibling of the single bit parent prefix of 111
        update_keys_and_check(
            vec!["01", "1", "111"],
            vec![("01", 0), ("10", 1), ("110", 1), ("111", 2), ("1", 1)],
        );
    }

    #[test]
    fn multiple_split() {
        update_keys_and_check(
            vec!["0", "1", "1011001"],
            vec![
                ("0", 0),
                ("100", 1),
                ("1010", 1),
                ("1011000", 1),
                ("1011001", 2),
                ("101101", 1),
                ("10111", 1),
                ("11", 1),
                ("1", 1),
            ],
        );
    }
}
