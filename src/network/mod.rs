// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

// TODO: remove prefix_map from sn_messaging::node
// mod prefix_map;
mod stats;

use self::stats::NetworkStats;
use crate::{
    agreement::{verify_proof, Proof, ProvenUtils},
    peer::PeerUtils,
    section::SectionAuthorityProviderUtils,
};

use secured_linked_list::SecuredLinkedList;
use sn_messaging::node::{
    Network, OtherSection, Peer, PrefixMap, Proven, SectionAuthorityProvider,
};
use std::iter;
use xor_name::{Prefix, XorName};

pub trait NetworkUtils {
    fn new() -> Self;

    fn closest(&self, name: &XorName) -> Option<&SectionAuthorityProvider>;

    /// Returns iterator over all known sections.
    fn all(&self) -> Box<dyn Iterator<Item = &SectionAuthorityProvider> + '_>;

    /// Get `SectionAuthorityProvider` of a known section with the given prefix.
    fn get(&self, prefix: &Prefix) -> Option<&SectionAuthorityProvider>;

    /// Returns all elders from all known sections.
    fn elders(&'_ self) -> Box<dyn Iterator<Item = Peer> + '_>;

    /// Returns a `Peer` of an elder from a known section.
    fn get_elder(&self, name: &XorName) -> Option<Peer>;

    /// Merge two `Network`s into one.
    /// TODO: make this operation commutative, associative and idempotent (CRDT)
    /// TODO: return bool indicating whether anything changed.
    fn merge(&mut self, other: Network, section_chain: &SecuredLinkedList);

    /// Update the info about a section.
    ///
    /// If this is for our sibling section, then `section_auth` is signed by them and so the signing
    /// key is not in our `section_chain`. To prove the key is valid, it must be accompanied by an
    /// additional `key_proof` which signs it using a key that is present in `section_chain`.
    ///
    /// If this is for a non-sibling section, then currently we require the info to be signed by our
    /// section (so we need to accumulate the signature for it first) and so `key_proof` is not
    /// needed in that case.
    fn update_section(
        &mut self,
        section_auth: Proven<SectionAuthorityProvider>,
        key_proof: Option<Proof>,
        section_chain: &SecuredLinkedList,
    ) -> bool;

    /// Returns the known section keys.
    fn keys(&self) -> Box<dyn Iterator<Item = (&Prefix, &bls::PublicKey)> + '_>;

    /// Returns the latest known key for the prefix that matches `name`.
    fn key_by_name(&self, name: &XorName) -> Option<&bls::PublicKey>;

    /// Returns the latest known key for a section with `prefix`.
    /// If this returns `None` that means the latest known key is the genesis key.
    fn key_by_prefix(&self, prefix: &Prefix) -> Option<&bls::PublicKey>;

    /// Returns the section_auth and the latest known key for the prefix that matches `name`,
    /// excluding self section.
    fn section_by_name(
        &self,
        name: &XorName,
    ) -> (Option<&bls::PublicKey>, Option<&SectionAuthorityProvider>);

    /// Returns network statistics.
    fn network_stats(&self, our: &SectionAuthorityProvider) -> NetworkStats;

    fn network_elder_counts(&self, our: &SectionAuthorityProvider) -> (u64, u64, bool);
}

impl NetworkUtils for Network {
    fn new() -> Self {
        Self {
            sections: PrefixMap::new(),
        }
    }

    /// Returns the known section that is closest to the given name, regardless of whether `name`
    /// belongs in that section or not.
    fn closest(&self, name: &XorName) -> Option<&SectionAuthorityProvider> {
        self.all()
            .min_by(|lhs, rhs| lhs.prefix.cmp_distance(&rhs.prefix, name))
    }

    /// Returns iterator over all known sections.
    fn all(&self) -> Box<dyn Iterator<Item = &SectionAuthorityProvider> + '_> {
        Box::new(self.sections.iter().map(|info| &info.section_auth.value))
    }

    /// Get `SectionAuthorityProvider` of a known section with the given prefix.
    fn get(&self, prefix: &Prefix) -> Option<&SectionAuthorityProvider> {
        self.sections
            .get(prefix)
            .map(|info| &info.section_auth.value)
    }

    /// Returns all elders from all known sections.
    fn elders(&'_ self) -> Box<dyn Iterator<Item = Peer> + '_> {
        Box::new(self.all().flat_map(|info| info.peers()))
    }

    /// Returns a `Peer` of an elder from a known section.
    fn get_elder(&self, name: &XorName) -> Option<Peer> {
        self.sections
            .get_matching(name)?
            .section_auth
            .value
            .get_addr(name)
            .map(|addr| {
                let mut peer = Peer::new(*name, addr);
                peer.set_reachable(true);
                peer
            })
    }

    /// Merge two `Network`s into one.
    /// TODO: make this operation commutative, associative and idempotent (CRDT)
    /// TODO: return bool indicating whether anything changed.
    fn merge(&mut self, other: Network, section_chain: &SecuredLinkedList) {
        // FIXME: these operations are not commutative:

        for entry in other.sections {
            if entry.verify(section_chain) {
                let _ = self.sections.insert(entry);
            }
        }
    }

    /// Update the info about a section.
    ///
    /// If this is for our sibling section, then `section_auth` is signed by them and so the signing
    /// key is not in our `section_chain`. To prove the key is valid, it must be accompanied by an
    /// additional `key_proof` which signs it using a key that is present in `section_chain`.
    ///
    /// If this is for a non-sibling section, then currently we require the info to be signed by our
    /// section (so we need to accumulate the signature for it first) and so `key_proof` is not
    /// needed in that case.
    fn update_section(
        &mut self,
        section_auth: Proven<SectionAuthorityProvider>,
        key_proof: Option<Proof>,
        section_chain: &SecuredLinkedList,
    ) -> bool {
        let info = OtherSection {
            section_auth: section_auth.clone(),
            key_proof,
        };

        if !info.verify(section_chain) {
            return false;
        }

        if let Some(old) = self.sections.insert(info) {
            if old.section_auth == section_auth {
                return false;
            }
        }

        true
    }

    /// Returns the known section keys.
    fn keys(&self) -> Box<dyn Iterator<Item = (&Prefix, &bls::PublicKey)> + '_> {
        Box::new(self.sections.iter().map(|entry| {
            (
                &entry.section_auth.value.prefix,
                &entry.section_auth.value.section_key,
            )
        }))
    }

    /// Returns the latest known key for the prefix that matches `name`.
    fn key_by_name(&self, name: &XorName) -> Option<&bls::PublicKey> {
        self.sections
            .get_matching(name)
            .map(|entry| &entry.section_auth.value.section_key)
    }

    /// Returns the latest known key for a section with `prefix`.
    /// If this returns `None` that means the latest known key is the genesis key.
    fn key_by_prefix(&self, prefix: &Prefix) -> Option<&bls::PublicKey> {
        self.sections
            .get_equal_or_ancestor(prefix)
            .map(|entry| &entry.section_auth.value.section_key)
    }

    /// Returns the section_auth and the latest known key for the prefix that matches `name`,
    /// excluding self section.
    fn section_by_name(
        &self,
        name: &XorName,
    ) -> (Option<&bls::PublicKey>, Option<&SectionAuthorityProvider>) {
        (
            self.sections
                .get_matching(name)
                .map(|entry| &entry.section_auth.value.section_key),
            self.sections
                .get_matching(name)
                .map(|entry| &entry.section_auth.value),
        )
    }

    /// Returns network statistics.
    fn network_stats(&self, our: &SectionAuthorityProvider) -> NetworkStats {
        let (known_elders, total_elders, total_elders_exact) = self.network_elder_counts(our);

        NetworkStats {
            known_elders,
            total_elders,
            total_elders_exact,
        }
    }

    // Compute an estimate of the total number of elders in the network from the size of our
    // routing table.
    //
    // Return (known, total, exact), where `exact` indicates whether `total` is an exact number of
    // an estimate.
    fn network_elder_counts(&self, our: &SectionAuthorityProvider) -> (u64, u64, bool) {
        let known_prefixes = iter::once(&our.prefix).chain(
            self.sections
                .iter()
                .map(|info| &info.section_auth.value.prefix),
        );
        let is_exact = Prefix::default().is_covered_by(known_prefixes.clone());

        // Estimated fraction of the network that we have in our RT.
        // Computed as the sum of 1 / 2^(prefix.bit_count) for all known section prefixes.
        let network_fraction: f64 = known_prefixes
            .map(|p| 1.0 / (p.bit_count() as f64).exp2())
            .sum();

        let known = our.elder_count() + self.elders().count();
        let total = known as f64 / network_fraction;

        (known as u64, total.ceil() as u64, is_exact)
    }
}

pub trait OtherSectionUtils {
    fn verify(&self, section_chain: &SecuredLinkedList) -> bool;
}

impl OtherSectionUtils for OtherSection {
    fn verify(&self, section_chain: &SecuredLinkedList) -> bool {
        if let Some(key_proof) = &self.key_proof {
            section_chain.has_key(&key_proof.public_key)
                && verify_proof(key_proof, &self.section_auth.proof.public_key)
                && self.section_auth.self_verify()
        } else {
            self.section_auth.verify(section_chain)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{agreement, section};
    use rand::Rng;

    #[test]
    fn closest() {
        let sk = bls::SecretKey::random();
        let chain = SecuredLinkedList::new(sk.public_key());

        let p01: Prefix = "01".parse().unwrap();
        let p10: Prefix = "10".parse().unwrap();
        let p11: Prefix = "11".parse().unwrap();

        // Create map containing sections (00), (01) and (10)
        let mut map = Network::new();
        let _ = map.update_section(gen_proven_section_auth(&sk, p01), None, &chain);
        let _ = map.update_section(gen_proven_section_auth(&sk, p10), None, &chain);

        let mut rng = rand::thread_rng();
        let n01 = p01.substituted_in(rng.gen());
        let n10 = p10.substituted_in(rng.gen());
        let n11 = p11.substituted_in(rng.gen());

        assert_eq!(map.closest(&n01).map(|i| &i.prefix), Some(&p01));
        assert_eq!(map.closest(&n10).map(|i| &i.prefix), Some(&p10));
        assert_eq!(map.closest(&n11).map(|i| &i.prefix), Some(&p10));
    }

    fn gen_proven_section_auth(
        sk: &bls::SecretKey,
        prefix: Prefix,
    ) -> Proven<SectionAuthorityProvider> {
        let (section_auth, _, _) = section::test_utils::gen_section_authority_provider(prefix, 5);
        agreement::test_utils::proven(sk, section_auth).unwrap()
    }
}
