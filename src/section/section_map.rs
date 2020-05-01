// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    elders_info::EldersInfo, network_stats::NetworkStats, section_proof_chain::SectionKeyInfo,
};
use crate::{
    id::{P2pNode, PublicId},
    location::DstLocation,
    utils::NonEmptyList,
    xor_space::{Prefix, XorName},
};
use std::{
    cmp::Ordering,
    collections::{BTreeMap, VecDeque},
    iter,
};

// Number of recent keys we keep: i.e how many other section churns we can handle before a
// message sent with a previous version of a section is no longer trusted.
// With low churn rate, an ad hoc 20 should be big enough to avoid losing messages.
const MAX_RECENT_KEYS: usize = 20;

/// Container for storing information about sections in the network.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SectionMap {
    // Our section including its whole history.
    our: NonEmptyList<EldersInfo>,
    // Other sections: maps section prefixes to their latest signed elders infos.
    // Note that after a split, the section's latest section info could be the one from the
    // pre-split parent section, so the value's prefix doesn't always match the key.
    other: BTreeMap<Prefix<XorName>, EldersInfo>,
    // Other section infos that are not immediate successors of the ones we have. Stored here
    // until we get the immediate successor, then moved to `other`.
    other_queued: VecDeque<EldersInfo>,
    // BLS public keys of known sections
    keys: BTreeMap<Prefix<XorName>, SectionKeyInfo>,
    // Recent keys removed from `keys`. Contains at most `MAX_RECENT_KEYS` entries.
    recent_keys: VecDeque<(Prefix<XorName>, SectionKeyInfo)>,
    // Version of our section that other sections know about
    knowledge: BTreeMap<Prefix<XorName>, u64>,
}

impl SectionMap {
    pub fn new(our_info: EldersInfo, our_key: SectionKeyInfo) -> Self {
        Self {
            our: NonEmptyList::new(our_info),
            other: Default::default(),
            other_queued: Default::default(),
            keys: iter::once((*our_key.prefix(), our_key)).collect(),
            recent_keys: Default::default(),
            knowledge: Default::default(),
        }
    }

    /// Get our section info
    pub fn our(&self) -> &EldersInfo {
        self.our.last()
    }

    // Returns whether we have the history of our infos or just the latest one.
    pub fn has_our_history(&self) -> bool {
        self.our.len() > 1
    }

    /// Get `EldersInfo` of a known section with the given prefix.
    pub fn get(&self, prefix: &Prefix<XorName>) -> Option<&EldersInfo> {
        if prefix == self.our.last().prefix() {
            Some(self.our.last())
        } else {
            self.other.get(prefix)
        }
    }

    /// Returns a known section whose prefix is compatible with the given prefix, if any.
    pub fn compatible(&self, prefix: &Prefix<XorName>) -> Option<&EldersInfo> {
        self.all()
            .find(move |(known_prefix, _)| known_prefix.is_compatible(prefix))
            .map(|(_, info)| info)
    }

    /// Find other section containing the given elder.
    pub fn find_other_by_elder(&self, pub_id: &PublicId) -> Option<&EldersInfo> {
        self.other
            .iter()
            .find(|(_, info)| info.contains_elder(pub_id))
            .map(|(_, info)| info)
    }

    /// Returns the known section that is closest to the given name, regardless of whether `name`
    /// belongs in that section or not.
    pub fn closest(&self, name: &XorName) -> (&Prefix<XorName>, &EldersInfo) {
        let mut best_prefix = self.our().prefix();
        let mut best_info = self.our();
        for (prefix, info) in self.all() {
            // TODO: Remove the first check after verifying that section infos are never empty.
            if info.num_elders() > 0 && best_prefix.cmp_distance(prefix, name) == Ordering::Greater
            {
                best_prefix = prefix;
                best_info = info;
            }
        }

        (best_prefix, best_info)
    }

    /// Returns iterator over all known sections.
    pub fn all(&self) -> impl Iterator<Item = (&Prefix<XorName>, &EldersInfo)> + Clone {
        iter::once((self.our.last().prefix(), self.our.last())).chain(&self.other)
    }

    /// Returns iterator over all known sections excluding ours.
    pub fn other(&self) -> impl Iterator<Item = (&Prefix<XorName>, &EldersInfo)> {
        self.other.iter()
    }

    /// Returns the known sections sorted by the distance from a given XorName.
    pub fn sorted_by_distance_to(&self, name: &XorName) -> Vec<(&Prefix<XorName>, &EldersInfo)> {
        let mut result: Vec<_> = self.all().collect();
        result.sort_by(|lhs, rhs| lhs.0.cmp_distance(rhs.0, name));
        result
    }

    /// Returns prefixes of all known sections.
    pub fn prefixes(&self) -> impl Iterator<Item = &Prefix<XorName>> + Clone {
        self.all().map(|(prefix, _)| prefix)
    }

    /// Returns `true` if the `EldersInfo` isn't known to us yet.
    pub fn is_new(&self, elders_info: &EldersInfo) -> bool {
        !self.all().any(|(_, info)| info.is_newer(elders_info))
    }

    /// Returns `true` if the `EldersInfo` isn't known to us yet and is a neighbouring section.
    pub fn is_new_neighbour(&self, elders_info: &EldersInfo) -> bool {
        let our_prefix = self.our().prefix();
        let other_prefix = elders_info.prefix();

        (our_prefix.is_neighbour(other_prefix) || other_prefix.is_extension_of(our_prefix))
            && self.is_new(elders_info)
    }

    /// Returns all elders from all known sections.
    pub fn elders(&self) -> impl Iterator<Item = &P2pNode> {
        self.all()
            .map(|(_, info)| info)
            .flat_map(EldersInfo::elder_nodes)
    }

    /// Returns all elders from our section.
    pub fn our_elders(&self) -> impl Iterator<Item = &P2pNode> + ExactSizeIterator {
        self.our().elder_nodes()
    }

    /// Returns all elders from other sections.
    pub fn other_elders(&self) -> impl Iterator<Item = &P2pNode> {
        self.other.values().flat_map(EldersInfo::elder_nodes)
    }

    /// Returns a `P2pNode` of an elder from a known section.
    pub fn get_elder(&self, name: &XorName) -> Option<&P2pNode> {
        self.all()
            .find(|(prefix, _)| prefix.matches(name))
            .and_then(|(_, elders_info)| elders_info.elder_map().get(name))
    }

    /// Returns whether the given peer is elder in a known sections.
    pub fn is_elder(&self, pub_id: &PublicId) -> bool {
        self.get_elder(pub_id.name()).is_some()
    }

    /// Push the new version of our section.
    pub fn push_our(&mut self, elders_info: EldersInfo) {
        self.our.push(elders_info);
        self.prune_neighbours()
    }

    pub fn add_neighbour(&mut self, elders_info: EldersInfo) {
        // Add all queued infos (including the new one) if they are immediate successors of the ones
        // we already have, otherwise keep them in the queue and try again next time.

        self.other_queued.push_back(elders_info);
        let mut remaining = self.other_queued.len();

        loop {
            if remaining == 0 {
                break;
            }

            if let Some(info) = self.other_queued.pop_front() {
                if self.is_immediate_successor(&info) {
                    self.add_to_other(info);
                    remaining = self.other_queued.len();
                } else {
                    self.other_queued.push_back(info);
                    remaining -= 1;
                }
            } else {
                break;
            }
        }

        self.prune_neighbours();
    }

    // Is the given section immediate successor of a section we already know?
    fn is_immediate_successor(&self, new_info: &EldersInfo) -> bool {
        let not_follow = |old_info: &EldersInfo| {
            new_info.prefix().is_compatible(old_info.prefix())
                && new_info.version() != (old_info.version() + 1)
        };

        !self
            .compatible(new_info.prefix())
            .into_iter()
            .any(not_follow)
    }

    fn add_to_other(&mut self, elders_info: EldersInfo) {
        let prefix = *elders_info.prefix();
        let parent_prefix = elders_info.prefix().popped();
        let sibling_prefix = elders_info.prefix().sibling();
        let new_elders_info_version = elders_info.version();

        if let Some(old_elders_info) = self.other.insert(prefix, elders_info) {
            if old_elders_info.version() > new_elders_info_version {
                log_or_panic!(
                    log::Level::Error,
                    "Ejected newer neighbour info {:?}",
                    old_elders_info
                );
            }
        }

        // If we just split an existing neighbour and we also need its sibling,
        // add the sibling prefix with the parent prefix sigs.
        if let Some(sinfo) = self
            .other
            .get(&parent_prefix)
            .filter(|pinfo| {
                pinfo.version() < new_elders_info_version
                    && self.our().prefix().is_neighbour(&sibling_prefix)
                    && !self.other.contains_key(&sibling_prefix)
            })
            .cloned()
        {
            let _ = self.other.insert(sibling_prefix, sinfo);
        }
    }

    // Remove outdated neighbour infos.
    fn prune_neighbours(&mut self) {
        // Remove invalid neighbour prefix, older version of compatible prefix.
        let to_remove: Vec<_> = self
            .other
            .iter()
            .filter_map(|(prefix, elders_info)| {
                if !self.our().prefix().is_neighbour(prefix) {
                    // we just split making old neighbour no longer needed
                    return Some(*prefix);
                }

                // Remove older compatible neighbour prefixes.
                // DO NOT SUPPORT MERGE: Not consider newer if the older one was extension (split).
                let is_newer =
                    |(other_prefix, other_elders_info): (&Prefix<XorName>, &EldersInfo)| {
                        other_prefix.is_compatible(prefix)
                            && other_elders_info.version() > elders_info.version()
                            && !prefix.is_extension_of(other_prefix)
                    };

                if self.other.iter().any(is_newer) {
                    return Some(*prefix);
                }

                None
            })
            .collect();

        for prefix in to_remove {
            let _ = self.other.remove(&prefix);
        }
    }

    /// Returns the known section keys and any recent keys we still hold.
    pub fn keys(&self) -> impl Iterator<Item = (&Prefix<XorName>, &SectionKeyInfo)> {
        self.keys
            .iter()
            .chain(self.recent_keys.iter().map(|(p, k)| (p, k)))
    }

    pub fn latest_compatible_key(&self, name: &XorName) -> Option<&SectionKeyInfo> {
        self.keys()
            .filter(|(prefix, _)| prefix.matches(name))
            .map(|(_, info)| info)
            .max_by_key(|info| info.version())
    }

    /// Updates the entry in `keys` for `prefix` to the latest known key; if a split
    /// occurred in the meantime, the keys for sections covering the rest of the address space are
    /// initialised to the old key that was stored for their common ancestor
    pub fn update_keys(&mut self, key_info: &SectionKeyInfo) {
        trace!("attempts to update keys for {:?}", key_info);

        if let Some((&old_prefix, old_version)) = self
            .keys
            .iter()
            .find(|(prefix, _)| prefix.is_compatible(key_info.prefix()))
            .map(|(prefix, info)| (prefix, info.version()))
        {
            if old_version >= key_info.version() || old_prefix.is_extension_of(key_info.prefix()) {
                // Do not overwrite newer version or prefix extensions
                return;
            }

            let old_key_info = self
                .keys
                .remove(&old_prefix)
                .expect("Bug in BTreeMap for update_keys");

            self.recent_keys
                .push_front((old_prefix, old_key_info.clone()));
            if self.recent_keys.len() > MAX_RECENT_KEYS {
                let _ = self.recent_keys.pop_back();
            }

            trace!("    from {:?} to {:?}", old_key_info, key_info);

            let old_prefix_sibling = old_prefix.sibling();
            let mut current_prefix = key_info.prefix().sibling();
            while !self.keys.contains_key(&current_prefix) && current_prefix != old_prefix_sibling {
                let _ = self.keys.insert(current_prefix, old_key_info.clone());
                current_prefix = current_prefix.popped().sibling();
            }
        }
        let _ = self.keys.insert(*key_info.prefix(), key_info.clone());
    }

    pub fn get_knowledge(&self, prefix: &Prefix<XorName>) -> Option<u64> {
        self.knowledge.get(prefix).copied()
    }

    /// Returns the version of the public key in our_history that will be trusted by the target
    /// location
    pub fn trusted_key_version(&self, target: &DstLocation) -> u64 {
        let (prefix, &index) = if let Some(pair) = self
            .knowledge
            .iter()
            .filter(|(prefix, _)| target.is_compatible(prefix))
            .min_by_key(|(_, index)| *index)
        {
            pair
        } else {
            return 0;
        };

        if let Some(sibling_index) = self.knowledge.get(&prefix.sibling()) {
            // The sibling section might not have processed the split yet, so it might still be in
            // `target`'s location. Because of that, we need to return index that would be trusted
            // by them too.
            index.min(*sibling_index)
        } else {
            index
        }
    }

    /// Updates the entry in `knowledge` for `prefix` to the `version`; if a split
    /// occurred in the meantime, the versions for sections covering the rest of the address space
    /// are initialised to the old version that was stored for their common ancestor
    pub fn update_knowledge(&mut self, prefix: Prefix<XorName>, version: u64) {
        trace!(
            "update knowledge of section ({:b}) about our section to v{}",
            prefix,
            version,
        );

        if let Some((&old_prefix, &old_version)) = self
            .knowledge
            .iter()
            .find(|(other_prefix, _)| other_prefix.is_compatible(&prefix))
        {
            if old_version >= version || old_prefix.is_extension_of(&prefix) {
                // Do not overwrite newer version or prefix extensions
                return;
            }

            let _ = self.knowledge.remove(&old_prefix);

            trace!(
                "    from ({:b}) v{} to ({:b}) v{}",
                old_prefix,
                old_version,
                prefix,
                version
            );

            let old_prefix_sibling = old_prefix.sibling();
            let mut current_prefix = prefix.sibling();
            while !self.knowledge.contains_key(&current_prefix)
                && current_prefix != old_prefix_sibling
            {
                let _ = self.knowledge.insert(current_prefix, old_version);
                current_prefix = current_prefix.popped().sibling();
            }
        }
        let _ = self.knowledge.insert(prefix, version);
    }

    /// Compute an estimate of the total number of elders in the network from the size of our
    /// routing table.
    ///
    /// Return (estimate, exact), with exact = true iff we have the whole network in our
    /// routing table.
    pub fn network_elder_count_estimate(&self) -> (u64, bool) {
        let known_prefixes = self.prefixes();
        let is_exact = Prefix::default().is_covered_by(known_prefixes.clone());

        // Estimated fraction of the network that we have in our RT.
        // Computed as the sum of 1 / 2^(prefix.bit_count) for all known section prefixes.
        let network_fraction: f64 = known_prefixes
            .map(|p| 1.0 / (p.bit_count() as f64).exp2())
            .sum();

        // Total size estimate = known_nodes / network_fraction
        let network_size = self.elders().count() as f64 / network_fraction;

        (network_size.ceil() as u64, is_exact)
    }

    /// Returns network statistics.
    pub fn network_stats(&self) -> NetworkStats {
        let (total_elders, total_elders_exact) = self.network_elder_count_estimate();

        NetworkStats {
            known_elders: self.elders().count() as u64,
            total_elders,
            total_elders_exact,
        }
    }

    #[cfg(feature = "mock_base")]
    pub fn knowledge(&self) -> &BTreeMap<Prefix<XorName>, u64> {
        &self.knowledge
    }
}
