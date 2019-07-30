// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{ProofSet, ProvingSection, SectionInfo};
use crate::{error::RoutingError, sha3::Digest256, BlsPublicKey, BlsSignature, Prefix, XorName};
use itertools::Itertools;
use maidsafe_utilities::serialisation;
use std::{
    collections::{BTreeSet, HashMap},
    fmt::{self, Debug, Formatter},
    iter, mem,
};
use unwrap::unwrap;

/// Section state that is shared among all elders of a section via Parsec consensus.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedState {
    /// The new self section info, that doesn't necessarily have a full set of signatures yet.
    pub new_info: SectionInfo,
    /// The latest few fully signed infos of our own sections, each with signatures by the previous
    /// one. This is included in every message we relay.
    /// This is not a `BTreeSet` just now as it is ordered according to the sequence of pushes into
    /// it.
    pub our_infos: NonEmptyList<(SectionInfo, ProofSet)>,
    /// Any change (split or merge) to the section that is currently in progress.
    pub change: PrefixChange,
    // The accumulated `SectionInfo`(self or sibling) and proofs during a split pfx change.
    pub split_cache: Option<(SectionInfo, ProofSet)>,
    /// The set of section info hashes that are currently merging.
    pub merging: BTreeSet<Digest256>,
    /// Our section's key history for Secure Message Delivery
    pub our_history: SectionProofChain,
    /// BLS public keys of other sections
    pub their_keys: HashMap<Prefix<XorName>, BlsPublicKey>,
}

impl SharedState {
    pub fn new(section_info: SectionInfo) -> Self {
        let pk = BlsPublicKey::from_section_info(&section_info);
        let our_history = SectionProofChain::from_genesis(pk);
        Self {
            new_info: section_info.clone(),
            our_infos: NonEmptyList::new((section_info, Default::default())),
            change: PrefixChange::None,
            split_cache: None,
            merging: Default::default(),
            our_history,
            their_keys: Default::default(),
        }
    }

    pub fn our_infos(&self) -> impl Iterator<Item = &SectionInfo> + DoubleEndedIterator {
        self.our_infos.iter().map(|(si, _)| si)
    }

    /// Returns our own current section info.
    pub fn our_info(&self) -> &SectionInfo {
        &self.our_infos.last().0
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
            .find(|(sec_info, _)| sec_info.hash() == hash)
            .map(|(sec_info, _)| sec_info)
    }

    /// Returns the section info matching our own name with the given version number.
    pub fn our_info_by_version(&self, version: u64) -> Option<&SectionInfo> {
        self.our_infos
            .iter()
            .find(|(sec_info, _)| *sec_info.version() == version)
            .map(|(sec_info, _)| sec_info)
    }

    /// Returns `true` if we have accumulated self `NetworkEvent::OurMerge`.
    pub(super) fn is_self_merge_ready(&self) -> bool {
        self.merging.contains(self.our_info().hash())
    }

    /// Returns the next section info if both we and our sibling have signalled for merging.
    pub(super) fn try_merge(
        &mut self,
        their_info: &SectionInfo,
    ) -> Result<Option<SectionInfo>, RoutingError> {
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

    /// Returns a list of `ProvingSection`s whose first element proves `from` and whose last
    /// element is `to`.
    pub(super) fn proving_sections_to_own(&self, from: u64, to: u64) -> Vec<ProvingSection> {
        if from < to {
            self.our_infos
                .iter()
                .skip_while(|(sec_info, _)| *sec_info.version() <= from)
                .take_while(|(sec_info, _)| *sec_info.version() <= to)
                .map(|(sec_info, _)| ProvingSection::successor(sec_info))
                .collect()
        } else {
            self.our_infos
                .iter()
                .rev()
                .skip_while(|(sec_info, _)| *sec_info.version() != from)
                .take_while(|(sec_info, _)| *sec_info.version() >= to)
                .tuple_windows()
                .map(|((_, proofs), (sec_info, _))| ProvingSection::signatures(sec_info, proofs))
                .collect()
        }
    }

    /// Updates the entry in `their_keys` for `prefix` to the latest known key; if a split
    /// occurred in the meantime, the keys for sections covering the rest of the address space are
    /// initialised to the old key that was stored for their common ancestor
    /// NOTE: the function as it is currently is not merge-safe.
    pub fn update_their_keys(&mut self, prefix: Prefix<XorName>, key: BlsPublicKey) {
        if let Some(&pfx) = self
            .their_keys
            .keys()
            .find(|pfx| pfx.is_compatible(&prefix))
        {
            let old_key = unwrap!(self.their_keys.remove(&pfx));
            let old_pfx_sibling = pfx.sibling();
            let mut current_pfx = prefix.sibling();
            while !self.their_keys.contains_key(&current_pfx) && current_pfx != old_pfx_sibling {
                let _ = self.their_keys.insert(current_pfx, old_key.clone());
                current_pfx = current_pfx.popped().sibling();
            }
        }
        let _ = self.their_keys.insert(prefix, key);
    }

    #[cfg(test)]
    /// Returns the reference to their_keys
    pub fn get_their_keys(&self) -> &HashMap<Prefix<XorName>, BlsPublicKey> {
        &self.their_keys
    }
}

/// The prefix-affecting change (split or merge) to our own section that is currently in progress.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

impl NonEmptyList<(SectionInfo, ProofSet)> {
    /// Remove infos that are sorted before the info with version equal to `oldest_version`.
    /// If no info has that version, do not remove anything and return 'false'.
    /// Otherwise return `true`
    pub fn clean_older(&mut self, oldest_version: u64) -> bool {
        if *self.tail.0.version() == oldest_version {
            self.head.clear();
            return true;
        }

        match self
            .head
            .binary_search_by_key(&oldest_version, |(si, _)| *si.version())
        {
            Ok(index) => {
                let _ = self.head.drain(0..index);
                true
            }
            Err(_) => oldest_version == 0,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SectionProofBlock {
    key: BlsPublicKey,
    sig: BlsSignature,
}

impl SectionProofBlock {
    pub fn from_sec_info_with_proofs(sec_info: &SectionInfo, proofs: ProofSet) -> Self {
        let key = BlsPublicKey::from_section_info(sec_info);
        let sig = BlsSignature::from_proof_set(proofs);
        SectionProofBlock { key, sig }
    }

    pub fn verify_with_pk(&self, pk: &BlsPublicKey) -> bool {
        let to_verify = self.key.as_event();
        match serialisation::serialise(&to_verify) {
            Ok(data) => pk.verify(&self.sig, data),
            _ => false,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SectionProofChain {
    genesis_pk: BlsPublicKey,
    blocks: Vec<SectionProofBlock>,
}

impl SectionProofChain {
    pub fn from_genesis(pk: BlsPublicKey) -> Self {
        Self {
            genesis_pk: pk,
            blocks: Vec::new(),
        }
    }

    pub fn push(&mut self, block: SectionProofBlock) {
        self.blocks.push(block);
    }

    #[allow(unused)]
    pub fn validate(&self) -> bool {
        let mut current_pk = &self.genesis_pk;
        for block in &self.blocks {
            if !block.verify_with_pk(current_pk) {
                return false;
            }
            current_pk = &block.key;
        }
        true
    }
}

impl Debug for SectionProofChain {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "SectionProofChain(len = {})",
            self.blocks.len() + 1
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{chain::SectionInfo, BlsPublicKey, FullId, Prefix, XorName};
    use std::collections::{BTreeSet, HashMap};
    use std::str::FromStr;
    use unwrap::unwrap;

    fn gen_section_info(pfx: Prefix<XorName>) -> SectionInfo {
        let sec_size = 5;
        let mut members = BTreeSet::new();
        for _ in 0..sec_size {
            let id = FullId::within_range(&pfx.range_inclusive());
            let _ = members.insert(*id.public_id());
        }
        unwrap!(SectionInfo::new(members, pfx, None))
    }

    fn gen_pk(pfx: Prefix<XorName>) -> BlsPublicKey {
        BlsPublicKey::from_section_info(&gen_section_info(pfx))
    }

    // start_pfx: the prefix of our section as string
    // updates: the prefixes of the sections we update the keys for, in sequence; every entry in
    //          the vector will get its own key
    // expected: vec of pairs (prefix, index)
    //           the prefix is the prefix of the section whose key we check
    //           the index is the index in the `updates` vector, which should have generated the
    //           key we expect to get for the given prefix
    fn update_keys_and_check(start_pfx: &str, updates: Vec<&str>, expected: Vec<(&str, usize)>) {
        let keys_to_update = updates
            .into_iter()
            .map(|pfx_str| {
                let pfx = unwrap!(Prefix::<XorName>::from_str(pfx_str));
                (pfx, gen_pk(pfx))
            })
            .collect::<Vec<_>>();
        let expected_keys = expected
            .into_iter()
            .map(|(pfx_str, index)| {
                let pfx = unwrap!(Prefix::<XorName>::from_str(pfx_str));
                (pfx, keys_to_update[index].1.clone())
            })
            .collect::<HashMap<_, _>>();

        let start_section = gen_section_info(unwrap!(Prefix::from_str(start_pfx)));
        let mut state = SharedState::new(start_section);

        for (pfx, key) in keys_to_update {
            state.update_their_keys(pfx, key);
        }

        assert_eq!(state.get_their_keys(), &expected_keys);
    }

    #[test]
    fn single_prefix_multiple_updates() {
        update_keys_and_check("0", vec!["1", "1", "1", "1"], vec![("1", 3)]);
    }

    #[test]
    fn simple_split() {
        update_keys_and_check(
            "0",
            vec!["10", "11", "101"],
            vec![("100", 0), ("11", 1), ("101", 2)],
        );
    }

    #[test]
    fn our_section_not_sibling_of_ancestor() {
        update_keys_and_check(
            "01", // Not the sibling of the single bit parent prefix of 111
            vec!["1", "111"],
            vec![("111", 1), ("110", 0), ("10", 0)],
        );
    }

    #[test]
    fn multiple_split() {
        update_keys_and_check(
            "0",
            vec!["1", "1011001"],
            vec![
                ("11", 0),
                ("100", 0),
                ("1010", 0),
                ("10111", 0),
                ("101101", 0),
                ("1011000", 0),
                ("1011001", 1),
            ],
        );
    }
}
