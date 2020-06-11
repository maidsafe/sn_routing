// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{elders_info::EldersInfo, network_stats::NetworkStats, prefix_map::PrefixMap};
use crate::{
    consensus::Proof,
    id::P2pNode,
    location::DstLocation,
    xor_space::{Prefix, XorName},
};
use std::{cmp::Ordering, collections::BTreeSet, iter};

/// Container for storing information about sections in the network.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SectionMap {
    // Our section.
    our: EldersInfo,
    // Neighbour sections: maps section prefixes to their latest signed elders infos.
    // Note that after a split, the section's latest section info could be the one from the
    // pre-split parent section, so the value's prefix doesn't always match the key.
    neighbours: PrefixMap<EldersInfo>,
    // BLS public keys of known sections excluding ours. The proof is for the whole `(prefix, key)` pair.
    keys: PrefixMap<(bls::PublicKey, Proof)>,
    // Indices of our section keys that are trusted by other sections.
    knowledge: PrefixMap<u64>,
}

impl SectionMap {
    pub fn new(our_info: EldersInfo) -> Self {
        Self {
            our: our_info,
            neighbours: Default::default(),
            keys: Default::default(),
            knowledge: Default::default(),
        }
    }

    /// Get our section info
    pub fn our(&self) -> &EldersInfo {
        &self.our
    }

    /// Returns the known section that is closest to the given name, regardless of whether `name`
    /// belongs in that section or not.
    pub fn closest(&self, name: &XorName) -> (&Prefix<XorName>, &EldersInfo) {
        let mut best_prefix = &self.our().prefix;
        let mut best_info = self.our();
        for (prefix, info) in self.all() {
            // TODO: Remove the first check after verifying that section infos are never empty.
            if !info.elders.is_empty()
                && best_prefix.cmp_distance(prefix, name) == Ordering::Greater
            {
                best_prefix = prefix;
                best_info = info;
            }
        }

        (best_prefix, best_info)
    }

    /// Returns iterator over all known sections.
    pub fn all(&self) -> impl Iterator<Item = (&Prefix<XorName>, &EldersInfo)> + Clone {
        iter::once((&self.our.prefix, &self.our)).chain(&self.neighbours)
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

    /// Returns whether the given name is in any of our neighbour sections.
    pub fn is_in_neighbour(&self, name: &XorName) -> bool {
        self.neighbours.contains_matching(name)
    }

    /// Returns all elders from all known sections.
    pub fn elders(&self) -> impl Iterator<Item = &P2pNode> {
        self.all().flat_map(|(_, info)| info.elders.values())
    }

    /// Returns all elders from our section.
    pub fn our_elders(&self) -> impl Iterator<Item = &P2pNode> + ExactSizeIterator {
        self.our().elders.values()
    }

    /// Returns all elders from neighbour sections.
    pub fn neighbour_elders(&self) -> impl Iterator<Item = &P2pNode> {
        self.neighbours
            .values()
            .flat_map(|info| info.elders.values())
    }

    /// Returns a `P2pNode` of an elder from a known section.
    pub fn get_elder(&self, name: &XorName) -> Option<&P2pNode> {
        let elders_info = if self.our.prefix.matches(name) {
            &self.our
        } else {
            &self.neighbours.get_matching(name)?.1
        };

        elders_info.elders.get(name)
    }

    /// Returns whether the given peer is elder in a known sections.
    pub fn is_elder(&self, name: &XorName) -> bool {
        self.get_elder(name).is_some()
    }

    /// Set the new version of our section.
    pub fn set_our(&mut self, elders_info: EldersInfo) {
        self.our = elders_info;
        self.prune_neighbours()
    }

    pub fn add_neighbour(&mut self, elders_info: EldersInfo) {
        let _ = self.neighbours.insert(elders_info.prefix, elders_info);
        self.prune_neighbours();
    }

    // Remove sections that are no longer our neighbours.
    fn prune_neighbours(&mut self) {
        let our_prefix = &self.our.prefix;
        self.neighbours
            .retain(|prefix, _| our_prefix.is_neighbour(prefix))
    }

    /// Returns the known section keys.
    pub fn keys(&self) -> impl Iterator<Item = (&Prefix<XorName>, &bls::PublicKey)> {
        self.keys.iter().map(|(prefix, (key, _))| (prefix, key))
    }

    #[cfg_attr(feature = "mock_base", allow(clippy::trivially_copy_pass_by_ref))]
    pub fn has_key(&self, key: &bls::PublicKey) -> bool {
        self.keys.values().any(|(known_key, _)| known_key == key)
    }

    /// Returns the latest known key for the prefix that matches `name`.
    pub fn key_by_name(&self, name: &XorName) -> Option<&bls::PublicKey> {
        self.keys.get_matching(name).map(|(_, (key, _))| key)
    }

    /// Updates the entry in `keys` for `prefix` to the latest known key; if a split
    /// occurred in the meantime, the keys for sections covering the rest of the address space are
    /// initialised to the old key that was stored for their common ancestor
    #[cfg_attr(feature = "mock_base", allow(clippy::trivially_copy_pass_by_ref))]
    pub fn update_keys(&mut self, prefix: Prefix<XorName>, new_key: bls::PublicKey, proof: Proof) {
        trace!("update key for {:?}: {:?}", prefix, new_key);
        let _ = self.keys.insert(prefix, (new_key, proof));
    }

    /// Returns the index of the public key in our_history that will be trusted by the given
    /// section.
    pub fn knowledge_by_section(&self, prefix: &Prefix<XorName>) -> u64 {
        self.knowledge
            .get_equal_or_ancestor(prefix)
            .map(|(_, index)| *index)
            .unwrap_or(0)
    }

    /// Returns the index of the public key in our_history that will be trusted by the given
    /// location
    pub fn knowledge_by_location(&self, dst: &DstLocation) -> u64 {
        let name = if let Some(name) = dst.name() {
            name
        } else {
            return 0;
        };

        let (prefix, &index) = if let Some(pair) = self.knowledge.get_matching(name) {
            pair
        } else {
            return 0;
        };

        // TODO: we might not need to do this anymore because we have the bounce untrusted messages
        // mechanism now.
        if let Some((_, sibling_index)) = self.knowledge.get_equal_or_ancestor(&prefix.sibling()) {
            // The sibling section might not have processed the split yet, so it might still be in
            // `dst`'s location. Because of that, we need to return index that would be trusted
            // by them too.
            index.min(*sibling_index)
        } else {
            index
        }
    }

    /// Updates the entry in `knowledge` for `prefix` to `new_index`; if a split
    /// occurred in the meantime, the index for sections covering the rest of the address space
    /// are initialised to the old index that was stored for their common ancestor
    pub fn update_knowledge(&mut self, prefix: Prefix<XorName>, new_index: u64) {
        trace!(
            "update knowledge of section ({:b}) about our section to {}",
            prefix,
            new_index,
        );

        // FIXME: we should always update even if it means overwriting newer with older, because we
        // must always obey section decisions.
        if let Some((_, &old_index)) = self.knowledge.get_equal_or_ancestor(&prefix) {
            if old_index > new_index {
                // Do not overwrite newer index
                return;
            }
        }

        let _ = self.knowledge.insert(prefix, new_index);
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

    /// Get `EldersInfo` of a known section with the given prefix.
    #[cfg(test)]
    pub fn get(&self, prefix: &Prefix<XorName>) -> Option<&EldersInfo> {
        if *prefix == self.our.prefix {
            Some(&self.our)
        } else {
            self.neighbours.get(prefix)
        }
    }

    /// Returns iterator over all neighbours sections.
    #[cfg(any(test, feature = "mock_base"))]
    pub fn neighbours(&self) -> impl Iterator<Item = (&Prefix<XorName>, &EldersInfo)> {
        self.neighbours.iter()
    }
}

// Neighbour section elders that got removed/demoted.
#[derive(Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct NeighbourEldersRemoved(pub BTreeSet<P2pNode>);

impl NeighbourEldersRemoved {
    pub fn builder(sections: &SectionMap) -> NeighbourEldersRemovedBuilder {
        NeighbourEldersRemovedBuilder(sections.neighbour_elders().cloned().collect())
    }
}

pub struct NeighbourEldersRemovedBuilder(BTreeSet<P2pNode>);

impl NeighbourEldersRemovedBuilder {
    pub fn build(mut self, sections: &SectionMap) -> NeighbourEldersRemoved {
        for p2p_node in sections.neighbour_elders() {
            let _ = self.0.remove(p2p_node);
        }

        NeighbourEldersRemoved(self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        consensus,
        id::FullId,
        location::DstLocation,
        rng::{self, MainRng},
    };
    use rand::Rng;

    #[test]
    fn update_keys_single_prefix_multiple_updates() {
        let mut rng = rng::new();
        let k0 = gen_key(&mut rng);
        let k1 = gen_key(&mut rng);
        let k2 = gen_key(&mut rng);

        update_keys_and_check(
            &mut rng,
            "0",
            vec![("1", &k0), ("1", &k1), ("1", &k2)],
            vec![("1", &k2)],
        );
    }

    #[test]
    fn update_keys_existing_old_key() {
        let mut rng = rng::new();
        let k0 = gen_key(&mut rng);
        let k1 = gen_key(&mut rng);

        update_keys_and_check(
            &mut rng,
            "0",
            vec![("1", &k0), ("1", &k1), ("1", &k0)],
            vec![("1", &k0)],
        );
    }

    #[test]
    fn update_keys_complete_split() {
        let mut rng = rng::new();
        let k0 = gen_key(&mut rng);
        let k1 = gen_key(&mut rng);
        let k2 = gen_key(&mut rng);

        update_keys_and_check(
            &mut rng,
            "0",
            vec![("1", &k0), ("10", &k1), ("11", &k2)],
            vec![("10", &k1), ("11", &k2)],
        );
    }

    #[test]
    fn update_keys_partial_split() {
        let mut rng = rng::new();
        let k0 = gen_key(&mut rng);
        let k1 = gen_key(&mut rng);

        update_keys_and_check(
            &mut rng,
            "0",
            vec![("1", &k0), ("10", &k1)],
            vec![("1", &k0), ("10", &k1)],
        );
    }

    #[test]
    fn update_keys_indirect_complete_split() {
        let mut rng = rng::new();
        let k0 = gen_key(&mut rng);
        let k1 = gen_key(&mut rng);
        let k2 = gen_key(&mut rng);
        let k3 = gen_key(&mut rng);
        let k4 = gen_key(&mut rng);

        update_keys_and_check(
            &mut rng,
            "0",
            vec![
                ("1", &k0),
                ("100", &k1),
                ("101", &k2),
                ("110", &k3),
                ("111", &k4),
            ],
            vec![("100", &k1), ("101", &k2), ("110", &k3), ("111", &k4)],
        );
    }

    #[test]
    fn update_keys_indirect_partial_split() {
        let mut rng = rng::new();
        let k0 = gen_key(&mut rng);
        let k1 = gen_key(&mut rng);
        let k2 = gen_key(&mut rng);

        update_keys_and_check(
            &mut rng::new(),
            "0",
            vec![("1", &k0), ("100", &k1), ("101", &k2)],
            vec![("1", &k0), ("100", &k1), ("101", &k2)],
        );
    }

    #[test]
    fn update_keys_split_out_of_order() {
        let mut rng = rng::new();
        let k0 = gen_key(&mut rng);
        let k1 = gen_key(&mut rng);
        let k2 = gen_key(&mut rng);
        let k3 = gen_key(&mut rng);
        let k4 = gen_key(&mut rng);

        // Late keys ignored
        update_keys_and_check(
            &mut rng,
            "0",
            vec![
                ("1", &k0),
                ("10", &k1),
                ("11", &k2),
                ("101", &k3),
                ("10", &k4),
            ],
            vec![("10", &k1), ("101", &k3), ("11", &k2)],
        );
    }

    #[test]
    fn update_their_knowledge_after_split_from_one_sibling() {
        let mut rng = rng::new();
        update_their_knowledge_and_check_proving_index(
            &mut rng,
            vec![("1", 1), ("10", 2)],
            vec![("10", 1), ("11", 1)],
        )
    }

    #[test]
    fn update_their_knowledge_after_split_from_both_siblings() {
        let mut rng = rng::new();
        update_their_knowledge_and_check_proving_index(
            &mut rng,
            vec![("1", 1), ("10", 2), ("11", 2)],
            vec![("10", 2), ("11", 2)],
        )
    }

    // Create a `SectionMap` and apply a series of `update_keys` calls to it, then verify the stored
    // keys are as expected.
    //
    // updates:  updates to `SectionMap::keys` as a sequence of (prefix, key) pairs that are
    //           applied in sequenceby calling `update_keys`
    // expected: vec of pairs (prefix, key) of the expected keys for each prefix, in the expected
    //           order.
    fn update_keys_and_check(
        rng: &mut MainRng,
        our_prefix: &str,
        updates: Vec<(&str, &bls::PublicKey)>,
        expected: Vec<(&str, &bls::PublicKey)>,
    ) {
        let elders_info = gen_elders_info(rng, our_prefix.parse().unwrap());
        let mut map = SectionMap::new(elders_info);

        for (prefix, key) in updates {
            let proof = consensus::test_utils::prove(rng, key);
            map.update_keys(prefix.parse().unwrap(), *key, proof);
        }

        let actual: Vec<_> = map.keys().map(|(prefix, key)| (*prefix, key)).collect();
        let expected: Vec<(Prefix<_>, _)> = expected
            .into_iter()
            .map(|(prefix, key)| (prefix.parse().unwrap(), key))
            .collect();
        assert_eq!(actual, expected);
    }

    // Perform a series of updates to `knowledge`, then verify that the proving indices for
    // the given dst locations are as expected.
    //
    // - `updates` - pairs of (prefix, version) to pass to `update_knowledge`
    // - `expected_trusted_key_versions` - pairs of (prefix, version) where the dst location name is
    //   generated such that it matches `prefix` and `version` is the expected trusted key version.
    fn update_their_knowledge_and_check_proving_index(
        rng: &mut MainRng,
        updates: Vec<(&str, u64)>,
        expected_trusted_key_indices: Vec<(&str, u64)>,
    ) {
        let mut map = SectionMap::new(gen_elders_info(rng, Default::default()));

        for (prefix_str, version) in updates {
            let prefix = prefix_str.parse().unwrap();
            map.update_knowledge(prefix, version);
        }

        for (dst_name_prefix_str, expected_index) in expected_trusted_key_indices {
            let dst_name_prefix: Prefix<_> = dst_name_prefix_str.parse().unwrap();
            let dst_name = dst_name_prefix.substituted_in(rng.gen());
            let dst = DstLocation::Section(dst_name);

            assert_eq!(map.knowledge_by_location(&dst), expected_index);
        }
    }

    fn gen_elders_info(rng: &mut MainRng, prefix: Prefix<XorName>) -> EldersInfo {
        let sec_size = 5;
        let members = (0..sec_size)
            .map(|index| {
                let pub_id = *FullId::within_range(rng, &prefix.range_inclusive()).public_id();
                (
                    *pub_id.name(),
                    P2pNode::new(pub_id, ([127, 0, 0, 1], 9000 + index).into()),
                )
            })
            .collect();

        EldersInfo::new(members, prefix)
    }

    fn gen_key(rng: &mut MainRng) -> bls::PublicKey {
        consensus::test_utils::gen_secret_key(rng).public_key()
    }
}
