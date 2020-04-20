// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{elders_info::EldersInfo, section_proof_chain::SectionKeyInfo};
use crate::{
    id::{P2pNode, PublicId},
    location::DstLocation,
    xor_space::{Prefix, XorName},
};
use std::{
    collections::{BTreeMap, VecDeque},
    iter,
};

// Number of recent keys we keep: i.e how many other section churns we can handle before a
// message send with a previous version of a section is no longer trusted.
// With low churn rate, a ad hoc 20 should be big enough to avoid losing messages.
const MAX_RECENT_KEYS: usize = 20;

/// Container for storing information about sections in the network.
/// Note: currently does not store our section, but that may change.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SectionMap {
    // Maps section prefixes to their latest signed elders infos.
    // Note that after a split, the section's latest section info could be the one from the
    // pre-split parent section, so the value's prefix doesn't always match the key.
    other: BTreeMap<Prefix<XorName>, EldersInfo>,
    // BLS public keys of known sections
    keys: BTreeMap<Prefix<XorName>, SectionKeyInfo>,
    // Recent keys removed from `keys`
    recent_keys: VecDeque<(Prefix<XorName>, SectionKeyInfo)>,
    // Version of our section that other sections know about
    knowledge: BTreeMap<Prefix<XorName>, u64>,
}

impl SectionMap {
    pub fn new(our_key: SectionKeyInfo) -> Self {
        Self {
            other: Default::default(),
            keys: iter::once((*our_key.prefix(), our_key)).collect(),
            recent_keys: Default::default(),
            knowledge: Default::default(),
        }
    }

    /// Get `EldersInfo` of a known section with the given prefix.
    pub fn get(&self, prefix: &Prefix<XorName>) -> Option<&EldersInfo> {
        self.other.get(prefix)
    }

    /// Returns a known section whose prefix is compatible with the given prefix, if any.
    pub fn compatible(&self, prefix: &Prefix<XorName>) -> Option<&EldersInfo> {
        self.other
            .iter()
            .find(move |(pfx, _)| pfx.is_compatible(prefix))
            .map(|(_, info)| info)
    }

    /// Find section containing the given member.
    pub fn find_by_member(&self, pub_id: &PublicId) -> Option<(Prefix<XorName>, u64)> {
        self.other
            .values()
            .find(|info| info.is_member(pub_id))
            .map(|info| (*info.prefix(), info.version()))
    }

    /// Returns iterator over all known sections.
    pub fn iter(&self) -> impl Iterator<Item = (&Prefix<XorName>, &EldersInfo)> {
        self.other.iter()
    }

    /// Returns all known section prefixes.
    pub fn prefixes(&self) -> impl Iterator<Item = &Prefix<XorName>> {
        self.other.keys()
    }

    /// Returns all elders from all known sections.
    pub fn elders(&self) -> impl Iterator<Item = &P2pNode> {
        self.other.values().flat_map(EldersInfo::member_nodes)
    }

    /// Returns a `P2pNode` of an elder from a known section.
    pub fn get_elder(&self, name: &XorName) -> Option<&P2pNode> {
        self.other
            .iter()
            .find(|(pfx, _)| pfx.matches(name))
            .and_then(|(_, elders_info)| elders_info.member_map().get(name))
    }

    /// Returns whether the given peer is elder in a known sections.
    pub fn is_elder(&self, pub_id: &PublicId) -> bool {
        self.other.values().any(|info| info.is_member(pub_id))
    }

    pub fn add_neighbour(&mut self, elders_info: EldersInfo, our_prefix: &Prefix<XorName>) {
        let pfx = *elders_info.prefix();
        let parent_pfx = elders_info.prefix().popped();
        let sibling_pfx = elders_info.prefix().sibling();
        let new_elders_info_version = elders_info.version();

        if let Some(old_elders_info) = self.other.insert(pfx, elders_info) {
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
            .get(&parent_pfx)
            .filter(|pinfo| {
                pinfo.version() < new_elders_info_version
                    && our_prefix.is_neighbour(&sibling_pfx)
                    && !self.other.contains_key(&sibling_pfx)
            })
            .cloned()
        {
            let _ = self.other.insert(sibling_pfx, sinfo);
        }

        self.prune_neighbours(our_prefix);
    }

    /// Remove outdated neighbour infos.
    pub fn prune_neighbours(&mut self, our_prefix: &Prefix<XorName>) {
        // Remove invalid neighbour pfx, older version of compatible pfx.
        let to_remove: Vec<_> = self
            .other
            .iter()
            .filter_map(|(pfx, elders_info)| {
                if !our_prefix.is_neighbour(pfx) {
                    // we just split making old neighbour no longer needed
                    return Some(*pfx);
                }

                // Remove older compatible neighbour prefixes.
                // DO NOT SUPPORT MERGE: Not consider newer if the older one was extension (split).
                let is_newer = |(other_pfx, other_elders_info): (&Prefix<XorName>, &EldersInfo)| {
                    other_pfx.is_compatible(pfx)
                        && other_elders_info.version() > elders_info.version()
                        && !pfx.is_extension_of(other_pfx)
                };

                if self.other.iter().any(is_newer) {
                    return Some(*pfx);
                }

                None
            })
            .collect();

        for pfx in to_remove {
            let _ = self.other.remove(&pfx);
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

        if let Some((&old_pfx, old_version)) = self
            .keys
            .iter()
            .find(|(pfx, _)| pfx.is_compatible(key_info.prefix()))
            .map(|(pfx, info)| (pfx, info.version()))
        {
            if old_version >= key_info.version() || old_pfx.is_extension_of(key_info.prefix()) {
                // Do not overwrite newer version or prefix extensions
                return;
            }

            let old_key_info = self
                .keys
                .remove(&old_pfx)
                .expect("Bug in BTreeMap for update_keys");

            self.recent_keys.push_front((old_pfx, old_key_info.clone()));
            if self.recent_keys.len() > MAX_RECENT_KEYS {
                let _ = self.recent_keys.pop_back();
            }

            trace!("    from {:?} to {:?}", old_key_info, key_info);

            let old_pfx_sibling = old_pfx.sibling();
            let mut current_pfx = key_info.prefix().sibling();
            while !self.keys.contains_key(&current_pfx) && current_pfx != old_pfx_sibling {
                let _ = self.keys.insert(current_pfx, old_key_info.clone());
                current_pfx = current_pfx.popped().sibling();
            }
        }
        let _ = self.keys.insert(*key_info.prefix(), key_info.clone());
    }

    pub fn get_knowledge(&self, prefix: &Prefix<XorName>) -> Option<u64> {
        self.knowledge.get(prefix).copied()
    }

    /// Returns the index of the public key in our_history that will be trusted by the target
    /// location
    pub fn proving_index(&self, target: &DstLocation) -> u64 {
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
            "attempts to update knowledge of our elders_info with version {:?} for \
             prefix {:?} ",
            version,
            prefix
        );

        if let Some((&old_pfx, &old_version)) = self
            .knowledge
            .iter()
            .find(|(pfx, _)| pfx.is_compatible(&prefix))
        {
            if old_version >= version || old_pfx.is_extension_of(&prefix) {
                // Do not overwrite newer version or prefix extensions
                return;
            }

            let _ = self.knowledge.remove(&old_pfx);

            trace!(
                "    from {:?}/{:?} to {:?}/{:?}",
                old_pfx,
                old_version,
                prefix,
                version
            );

            let old_pfx_sibling = old_pfx.sibling();
            let mut current_pfx = prefix.sibling();
            while !self.knowledge.contains_key(&current_pfx) && current_pfx != old_pfx_sibling {
                let _ = self.knowledge.insert(current_pfx, old_version);
                current_pfx = current_pfx.popped().sibling();
            }
        }
        let _ = self.knowledge.insert(prefix, version);
    }

    #[cfg(feature = "mock_base")]
    pub fn knowledge(&self) -> &BTreeMap<Prefix<XorName>, u64> {
        &self.knowledge
    }
}
