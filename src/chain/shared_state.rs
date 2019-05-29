// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{ProofSet, ProvingSection, SectionInfo};
use crate::{error::RoutingError, routing_table::DEFAULT_PREFIX, sha3::Digest256, Prefix, XorName};
use itertools::Itertools;
use log::LogLevel;
use std::collections::BTreeSet;

/// Section state that is shared among all elders of a section via Parsec consensus.
#[derive(Debug, PartialEq, Eq)]
pub struct SharedState {
    /// The new self section info, that doesn't necessarily have a full set of signatures yet.
    pub new_info: SectionInfo,
    /// The latest few fully signed infos of our own sections, each with signatures by the previous
    /// one. This is included in every message we relay.
    /// This is not a `BTreeSet` just now as it is ordered according to the sequence of pushes into
    /// it.
    pub our_infos: Vec<(SectionInfo, ProofSet)>,
    /// Any change (split or merge) to the section that is currently in progress.
    pub change: SectionChange,
    // The accumulated `SectionInfo`(self or sibling) and proofs during a split pfx change.
    pub split_cache: Option<(SectionInfo, ProofSet)>,
    /// The set of section info hashes that are currently merging.
    pub merging: BTreeSet<Digest256>,
}

impl SharedState {
    pub fn new(section_info: SectionInfo) -> Self {
        Self {
            new_info: section_info.clone(),
            our_infos: vec![(section_info, Default::default())],
            change: SectionChange::None,
            split_cache: None,
            merging: Default::default(),
        }
    }

    pub fn our_infos(
        &self,
    ) -> impl Iterator<Item = &SectionInfo> + ExactSizeIterator + DoubleEndedIterator {
        self.our_infos.iter().map(|(si, _)| si)
    }

    pub fn opt_our_info(&self) -> Option<&SectionInfo> {
        self.our_infos.last().map(|(si, _)| si)
    }

    /// Returns our own current section info.
    pub fn our_info(&self) -> &SectionInfo {
        // TODO: Replace `our_infos` with a new `NonemptyVec` type that statically guarantees that
        // it's never empty.
        unwrap!(self.opt_our_info())
    }

    pub fn our_prefix(&self) -> &Prefix<XorName> {
        self.opt_our_info()
            .map_or(&DEFAULT_PREFIX, SectionInfo::prefix)
    }

    pub fn our_version(&self) -> u64 {
        self.opt_our_info().map_or(0, |si| *si.version())
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

    /// Remove our infos that are older than the given version.
    pub(super) fn clean_our_infos(&mut self, oldest_version: u64) {
        let version_retention_threshold_index = self
            .our_infos
            .binary_search_by_key(&oldest_version, |(si, _)| *si.version())
            .unwrap_or_else(|_index| {
                if oldest_version > 0 {
                    log_or_panic!(
                        LogLevel::Warn,
                        "Oldest version indicated by neighbours not found in our infos"
                    );
                }
                usize::min_value()
            });
        let _ = self.our_infos.drain(0..version_retention_threshold_index);
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
        if pfx.is_empty() || self.change == SectionChange::Splitting {
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
}

/// The change to our own section that is currently in progress.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SectionChange {
    None,
    Splitting,
    Merging,
}
