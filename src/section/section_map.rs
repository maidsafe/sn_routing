// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    elders_info::EldersInfo, network_stats::NetworkStats, prefix_map::PrefixMap,
    section_proof_chain::SectionProofChain,
};
use crate::{consensus::Proven, id::P2pNode, location::DstLocation};

use serde::Serialize;
use std::{
    cmp::Ordering,
    collections::{BTreeSet, HashSet},
    iter,
};
use xor_name::{Prefix, XorName};

/// Container for storing information about sections in the network.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SectionMap {
    // Our section.
    our: Proven<EldersInfo>,
    // Neighbour sections: maps section prefixes to their latest signed elders infos.
    neighbours: PrefixMap<Proven<EldersInfo>>,
    // BLS public keys of known sections excluding ours.
    keys: PrefixMap<Proven<(Prefix, bls::PublicKey)>>,
    // Indices of our section keys that are trusted by other sections.
    knowledge: PrefixMap<Proven<(Prefix, u64)>>,
}

impl SectionMap {
    pub fn new(our_info: Proven<EldersInfo>) -> Self {
        Self {
            our: our_info,
            neighbours: Default::default(),
            keys: Default::default(),
            knowledge: Default::default(),
        }
    }

    /// Get our section info
    pub fn our(&self) -> &EldersInfo {
        &self.our.value
    }

    /// Get our section info with its proof.
    pub fn proven_our(&self) -> &Proven<EldersInfo> {
        &self.our
    }

    /// Returns the known section that is closest to the given name, regardless of whether `name`
    /// belongs in that section or not.
    pub fn closest(&self, name: &XorName) -> &EldersInfo {
        self.all()
            .min_by(|lhs, rhs| lhs.prefix.cmp_distance(&rhs.prefix, name))
            .unwrap_or(&self.our.value)
    }

    /// Returns iterator over all known sections.
    pub fn all(&self) -> impl Iterator<Item = &EldersInfo> + Clone {
        iter::once(&self.our)
            .chain(self.neighbours.iter())
            .map(|info| &info.value)
    }

    /// Returns the known sections sorted by the distance from a given XorName.
    pub fn sorted_by_distance_to(&self, name: &XorName) -> Vec<&EldersInfo> {
        let mut result: Vec<_> = self.all().collect();
        result.sort_by(|lhs, rhs| lhs.prefix.cmp_distance(&rhs.prefix, name));
        result
    }

    /// Get `EldersInfo` of a known section with the given prefix.
    pub fn get(&self, prefix: &Prefix) -> Option<&EldersInfo> {
        if *prefix == self.our.value.prefix {
            Some(&self.our.value)
        } else {
            self.neighbours.get(prefix).map(|info| &info.value)
        }
    }

    /// Returns prefixes of all known sections.
    pub fn prefixes(&self) -> impl Iterator<Item = &Prefix> + Clone {
        self.all().map(|elders_info| &elders_info.prefix)
    }

    /// Returns all elders from all known sections.
    pub fn elders(&self) -> impl Iterator<Item = &P2pNode> {
        self.all().flat_map(|info| info.elders.values())
    }

    /// Returns all elders from our section.
    pub fn our_elders(&self) -> impl Iterator<Item = &P2pNode> + ExactSizeIterator {
        self.our().elders.values()
    }

    /// Returns all elders from neighbour sections.
    pub fn neighbour_elders(&self) -> impl Iterator<Item = &P2pNode> {
        self.neighbours
            .iter()
            .flat_map(|info| info.value.elders.values())
    }

    /// Returns a `P2pNode` of an elder from a known section.
    pub fn get_elder(&self, name: &XorName) -> Option<&P2pNode> {
        let elders_info = if self.our.value.prefix.matches(name) {
            &self.our.value
        } else {
            &self.neighbours.get_matching(name)?.value
        };

        elders_info.elders.get(name)
    }

    /// Returns whether the given peer is elder in a known sections.
    pub fn is_elder(&self, name: &XorName) -> bool {
        self.get_elder(name).is_some()
    }

    /// Merge two `SectionMap`s into one.
    /// TODO: make this operation commutative, associative and idempotent (CRDT)
    /// TODO: return bool indicating whether anything changed.
    pub fn merge(&mut self, other: Self, section_chain: &SectionProofChain) {
        match cmp_section_chain_position(&self.our, &other.our, section_chain) {
            Some(Ordering::Less) => {
                self.our = other.our;
            }
            Some(Ordering::Equal) if self.our.value.elders.len() < other.our.value.elders.len() => {
                // Note: our `EldersInfo` is normally signed with the previous key, except the very
                // first one which is signed with the latest key. This means that the first and
                // second `EldersInfo`s are signed with the same key and so comparing only the keys
                // is not enough to decide which one is newer. To break the ties, we use the fact
                // that the first `EldersInfo` always has only one elder and the second one has
                // two.
                self.our = other.our;
            }
            Some(Ordering::Greater) | Some(Ordering::Equal) | None => (),
        }

        // FIXME: these operations are not commutative:

        for entry in other.neighbours {
            if entry.verify(section_chain) {
                let _ = self.neighbours.insert(entry);
            }
        }

        for entry in other.keys {
            if entry.verify(section_chain) {
                let _ = self.keys.insert(entry);
            }
        }

        for entry in other.knowledge {
            if entry.verify(section_chain) {
                let _ = self.knowledge.insert(entry);
            }
        }
    }

    /// Update the `EldersInfo` of our section.
    pub fn update_our_info(
        &mut self,
        elders_info: Proven<EldersInfo>,
        section_chain: &SectionProofChain,
    ) -> bool {
        if !elders_info.verify(section_chain) {
            return false;
        }

        if elders_info != self.our {
            self.our = elders_info;
            self.prune_neighbours();
            true
        } else {
            false
        }
    }

    pub fn update_neighbour_info(&mut self, elders_info: Proven<EldersInfo>) -> bool {
        // TODO: verify
        // if !elders_info.verify(section_chain) {
        //     return false;
        // }

        if let Some(old) = self.neighbours.insert(elders_info.clone()) {
            if old == elders_info {
                return false;
            }
        }

        self.prune_neighbours();

        true
    }

    /// Updates the entry in `keys` for `prefix` to the latest known key.
    pub fn update_their_key(&mut self, new_key: Proven<(Prefix, bls::PublicKey)>) -> bool {
        // TODO: verify against section chain

        trace!(
            "update key for {:?}: {:?}",
            new_key.value.0,
            new_key.value.1
        );

        if let Some(old) = self.keys.insert(new_key.clone()) {
            if old == new_key {
                return false;
            }
        }

        true
    }

    // Remove sections that are no longer our neighbours.
    fn prune_neighbours(&mut self) {
        let our_prefix = &self.our.value.prefix;
        let to_remove: Vec<_> = self
            .neighbours
            .prefixes()
            .filter(|prefix| {
                can_prune_neighbour(
                    our_prefix,
                    prefix,
                    self.neighbours
                        .descendants(prefix)
                        .map(|info| &info.value.prefix),
                )
            })
            .copied()
            .collect();

        for prefix in to_remove {
            let _ = self.neighbours.remove(&prefix);
        }
    }

    /// Returns the known section keys.
    pub fn keys(&self) -> impl Iterator<Item = (&Prefix, &bls::PublicKey)> {
        self.keys
            .iter()
            .map(|entry| (&entry.value.0, &entry.value.1))
    }

    #[cfg_attr(feature = "mock", allow(clippy::trivially_copy_pass_by_ref))]
    pub fn has_key(&self, key: &bls::PublicKey) -> bool {
        self.keys.iter().any(|entry| entry.value.1 == *key)
    }

    /// Returns the latest known key for the prefix that matches `name`.
    pub fn key_by_name(&self, name: &XorName) -> Option<&bls::PublicKey> {
        self.keys.get_matching(name).map(|entry| &entry.value.1)
    }

    /// Returns the index of the public key in our_history that will be trusted by the given
    /// section.
    pub fn knowledge_by_section(&self, prefix: &Prefix) -> u64 {
        self.knowledge
            .get_equal_or_ancestor(prefix)
            .map(|entry| entry.value.1)
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

        let (prefix, index) = if let Some(entry) = self.knowledge.get_matching(name) {
            (&entry.value.0, entry.value.1)
        } else {
            return 0;
        };

        // TODO: we might not need to do this anymore because we have the bounce untrusted messages
        // mechanism now.
        if let Some(sibling_entry) = self.knowledge.get_equal_or_ancestor(&prefix.sibling()) {
            // The sibling section might not have processed the split yet, so it might still be in
            // `dst`'s location. Because of that, we need to return index that would be trusted
            // by them too.
            index.min(sibling_entry.value.1)
        } else {
            index
        }
    }

    /// Updates the entry in `knowledge` for `prefix` to `new_index`; if a split
    /// occurred in the meantime, the index for sections covering the rest of the address space
    /// are initialised to the old index that was stored for their common ancestor
    pub fn update_knowledge(&mut self, new_index: Proven<(Prefix, u64)>) {
        trace!(
            "update knowledge of section ({:b}) about our section to {}",
            new_index.value.0,
            new_index.value.1,
        );

        let _ = self.knowledge.insert(new_index);
    }

    /// Compute an estimate of the total number of elders in the network from the size of our
    /// sn_routing table.
    ///
    /// Return (estimate, exact), with exact = true iff we have the whole network in our
    /// sn_routing table.
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

    /// Returns iterator over all neighbours sections.
    pub fn neighbours(&self) -> impl Iterator<Item = &EldersInfo> {
        self.neighbours.iter().map(|info| &info.value)
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

// Check whether we can remove `other` from our neighbours given `our` prefix and all `known`
// descendants of `other`.
//
// We can remove `other` if:
// - it is not our neighbour anymore, or
// - the intersection of the address space covered by `other` and our neighbourhood is fully
//   covered by prefixes we know.
//
// Example:
// - We are (00) and we know (1). Then we add (10). Now (10) covers the whole address space of (1)
//   that is also in our neighbourhood (because (11) is not our neighbour) which means we can
//   remove (1).
// - We are (000) and we know (1). Then we add (100). None of (101), (110) and (111) is our
//   neighbour which means that (100) again covers the whole address space of (1) that is in our
//   neighbourhood so we can remove (1)
// - We are (0) and we know (1). Then we add (10). We can't remove (1) yet because we don't know
//   (11) which is also our neighbour.
fn can_prune_neighbour<'a, I>(our: &Prefix, other: &Prefix, known: I) -> bool
where
    I: IntoIterator<Item = &'a Prefix>,
{
    let known: HashSet<_> = known
        .into_iter()
        .filter(|prefix| prefix.is_extension_of(other))
        .collect();

    fn check(our: &Prefix, other: &Prefix, known: &HashSet<&Prefix>) -> bool {
        if !other.is_neighbour(our) && !other.is_extension_of(our) {
            return true;
        }

        if known.contains(other) {
            return true;
        }

        if other.bit_count() >= our.bit_count() {
            return false;
        }

        let child0 = other.pushed(false);
        let child1 = other.pushed(true);

        check(our, &child0, known) && check(our, &child1, known)
    };

    check(our, other, &known)
}

fn cmp_section_chain_position<T: Serialize>(
    lhs: &Proven<T>,
    rhs: &Proven<T>,
    section_chain: &SectionProofChain,
) -> Option<Ordering> {
    match (lhs.self_verify(), rhs.self_verify()) {
        (true, true) => (),
        (true, false) => return Some(Ordering::Greater),
        (false, true) => return Some(Ordering::Less),
        (false, false) => return None,
    }

    let lhs_index = section_chain.index_of(&lhs.proof.public_key);
    let rhs_index = section_chain.index_of(&rhs.proof.public_key);

    match (lhs_index, rhs_index) {
        (Some(lhs_index), Some(rhs_index)) => Some(lhs_index.cmp(&rhs_index)),
        (Some(_), None) => Some(Ordering::Greater),
        (None, Some(_)) => Some(Ordering::Less),
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        consensus,
        location::DstLocation,
        rng::{self, MainRng},
        section,
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

    #[test]
    fn closest() {
        let mut rng = rng::new();
        let sk = consensus::test_utils::gen_secret_key(&mut rng);

        let p00: Prefix = "00".parse().unwrap();
        let p01: Prefix = "01".parse().unwrap();
        let p10: Prefix = "10".parse().unwrap();
        let p11: Prefix = "11".parse().unwrap();

        // Create map containing sections (00), (01) and (10)
        let mut map = SectionMap::new(gen_proven_elders_info(&mut rng, &sk, p00));
        let _ = map.update_neighbour_info(gen_proven_elders_info(&mut rng, &sk, p01));
        let _ = map.update_neighbour_info(gen_proven_elders_info(&mut rng, &sk, p10));

        let n00 = p00.substituted_in(rng.gen());
        let n01 = p01.substituted_in(rng.gen());
        let n10 = p10.substituted_in(rng.gen());
        let n11 = p11.substituted_in(rng.gen());

        assert_eq!(map.closest(&n00).prefix, p00);
        assert_eq!(map.closest(&n01).prefix, p01);
        assert_eq!(map.closest(&n10).prefix, p10);
        assert_eq!(map.closest(&n11).prefix, p10);
    }

    #[test]
    fn prune_neighbours() {
        let mut rng = rng::new();
        let sk = consensus::test_utils::gen_secret_key(&mut rng);

        let p00 = "00".parse().unwrap();
        let section00 = gen_proven_elders_info(&mut rng, &sk, p00);
        let mut map = SectionMap::new(section00);

        let p1 = "1".parse().unwrap();
        let section1 = gen_proven_elders_info(&mut rng, &sk, p1);
        let _ = map.update_neighbour_info(section1);

        assert!(map.prefixes().any(|&prefix| prefix == p1));

        // (10) is a neighbour of (00), but (11) is not. So by inserting (10),
        // we no longer need (1)
        let p10 = "10".parse().unwrap();
        let section10 = gen_proven_elders_info(&mut rng, &sk, p10);
        let _ = map.update_neighbour_info(section10);

        assert!(map.prefixes().any(|&prefix| prefix == p10));
        assert!(map.prefixes().all(|&prefix| prefix != p1));
    }

    // Create a `SectionMap` and apply a series of `update_keys` calls to it, then verify the stored
    // keys are as expected.
    //
    // updates:  updates to `SectionMap::keys` as a sequence of (prefix, key) pairs that are
    //           applied in sequence by calling `update_keys`
    // expected: vec of pairs (prefix, key) of the expected keys for each prefix, in the expected
    //           order.
    fn update_keys_and_check(
        rng: &mut MainRng,
        our_prefix: &str,
        updates: Vec<(&str, &bls::PublicKey)>,
        expected: Vec<(&str, &bls::PublicKey)>,
    ) {
        let sk = consensus::test_utils::gen_secret_key(rng);
        let elders_info = gen_proven_elders_info(rng, &sk, our_prefix.parse().unwrap());

        let mut map = SectionMap::new(elders_info);

        for (prefix, key) in updates {
            let prefix = prefix.parse().unwrap();
            let proof = consensus::test_utils::prove(&sk, &(&prefix, key));
            let proven = Proven::new((prefix, *key), proof);
            let _ = map.update_their_key(proven);
        }

        let actual: Vec<_> = map.keys().map(|(prefix, key)| (*prefix, key)).collect();
        let expected: Vec<(Prefix, _)> = expected
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
        let sk = consensus::test_utils::gen_secret_key(rng);
        let elders_info = gen_proven_elders_info(rng, &sk, Default::default());

        let mut map = SectionMap::new(elders_info);

        for (prefix_str, version) in updates {
            let prefix = prefix_str.parse().unwrap();
            let payload = consensus::test_utils::proven(&sk, (prefix, version));
            map.update_knowledge(payload);
        }

        for (dst_name_prefix_str, expected_index) in expected_trusted_key_indices {
            let dst_name_prefix: Prefix = dst_name_prefix_str.parse().unwrap();
            let dst_name = dst_name_prefix.substituted_in(rng.gen());
            let dst = DstLocation::Section(dst_name);

            assert_eq!(map.knowledge_by_location(&dst), expected_index);
        }
    }

    fn gen_proven_elders_info(
        rng: &mut MainRng,
        sk: &bls::SecretKey,
        prefix: Prefix,
    ) -> Proven<EldersInfo> {
        let (elders_info, _) = section::gen_elders_info(rng, prefix, 5);
        consensus::test_utils::proven(sk, elders_info)
    }

    fn gen_key(rng: &mut MainRng) -> bls::PublicKey {
        consensus::test_utils::gen_secret_key(rng).public_key()
    }
}
