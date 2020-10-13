// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{EldersInfo, MemberInfo, Network, Section, SectionKeyShare, SectionProofChain};
use crate::{
    consensus::Proven,
    error::{Error, Result},
    location::DstLocation,
    messages::MessageHash,
    peer::Peer,
    relocation::{self, RelocateAction, RelocateDetails, RelocatePromise},
};
use serde::Serialize;
use std::fmt::Debug;
use xor_name::{Prefix, XorName};

/// Section state that is shared among all elders of a section via consensus.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) struct SharedState {
    /// Info about our section.
    pub section: Section,
    /// Info about the rest of the network.
    pub network: Network,
}

impl SharedState {
    /// Creates a minimal `SharedState` initially containing only info about our section elders
    /// (`elders_info`).
    ///
    /// # Panics
    ///
    /// Panics if the key used to sign `elders_info` is not present in `section_chain`.
    pub fn new(section_chain: SectionProofChain, elders_info: Proven<EldersInfo>) -> Self {
        Self {
            section: Section::new(section_chain, elders_info),
            network: Network::new(),
        }
    }

    /// Creates `SharedState` for the first node in the network
    pub fn first_node(peer: Peer) -> Result<(Self, SectionKeyShare)> {
        let (section, section_key_share) = Section::first_node(peer)?;

        let state = Self {
            section,
            network: Network::new(),
        };

        Ok((state, section_key_share))
    }

    // Merge two `SharedState`s into one.
    // TODO: return `bool` indicating whether anything changed.
    pub fn merge(&mut self, other: Self) -> Result<(), Error> {
        self.section.merge(other.section)?;
        self.network.merge(other.network, self.section.chain());

        Ok(())
    }

    // Clear all data except that which is needed for non-elders.
    pub fn demote(&mut self) {
        *self = self.to_minimal();
    }

    pub fn update_our_info(&mut self, elders_info: Proven<EldersInfo>) -> bool {
        if self.section.update_elders(elders_info) {
            self.network.prune_neighbours(self.section.prefix());
            true
        } else {
            false
        }
    }

    pub fn update_neighbour_info(&mut self, elders_info: Proven<EldersInfo>) -> bool {
        if self.network.update_neighbour_info(elders_info) {
            self.network.prune_neighbours(self.section.prefix());
            true
        } else {
            false
        }
    }

    pub fn update_our_key(&mut self, key: Proven<bls::PublicKey>) -> bool {
        self.section.update_chain(key.value, key.proof.signature)
    }

    pub fn update_their_key(&mut self, key: Proven<(Prefix, bls::PublicKey)>) -> bool {
        if key.value.0 == *self.section.prefix() {
            // Ignore our keys. Use `update_our_key` for that.
            return false;
        }

        self.network.update_their_key(key)
    }

    pub fn to_minimal(&self) -> Self {
        Self {
            section: self.section.to_minimal(),
            network: Network::new(),
        }
    }

    /// Returns adults from our own section.
    pub fn our_adults(&self) -> impl Iterator<Item = &Peer> {
        self.section.adults()
    }

    /// Returns our members that are either joined or are left but still elders.
    pub fn active_members(&self) -> impl Iterator<Item = &Peer> {
        self.section.active_members()
    }

    /// All section keys we know of, including the past keys of our section.
    pub fn section_keys(&self) -> impl Iterator<Item = (&Prefix, &bls::PublicKey)> {
        self.section
            .chain()
            .keys()
            .map(move |key| (self.section.prefix(), key))
            .chain(self.network.keys())
    }

    pub fn section_key_by_location(&self, dst: &DstLocation) -> &bls::PublicKey {
        if let Some(name) = dst.name() {
            self.section_key_by_name(name)
        } else {
            // We don't know the section if `dst` is `Direct`, so return the root key which should
            // be trusted by everyone.
            self.section.chain().first_key()
        }
    }

    pub fn section_key_by_name(&self, name: &XorName) -> &bls::PublicKey {
        if self.section.prefix().matches(name) {
            self.section.chain().last_key()
        } else {
            self.network
                .key_by_name(name)
                .unwrap_or_else(|| self.section.chain().first_key())
        }
    }

    /// Update our knowledge of their section and their knowledge of ours. Returns the actions to
    /// perform (if any).
    pub fn update_section_knowledge(
        &self,
        our_name: &XorName,
        src_prefix: &Prefix,
        src_key: &bls::PublicKey,
        dst_key: Option<&bls::PublicKey>,
        hash: &MessageHash,
    ) -> Vec<UpdateSectionKnowledgeAction> {
        use UpdateSectionKnowledgeAction::*;

        let is_neighbour = self.section.prefix().is_neighbour(src_prefix);

        // There will be at most two actions returned because the only possible action combinations
        // are these:
        // - `[]`
        // - `[VoteTheirKey]`
        // - `[VoteTheirKey, VoteTheirKnowledge]`
        // - `[SendNeighbourInfo]`
        // - `[SendNeighbourInfo, VoteTheirKnowledge]`
        let mut actions = Vec::with_capacity(2);
        let mut vote_send_neighbour_info = false;

        if !src_prefix.matches(our_name) && !self.network.has_key(src_key) {
            // Only vote `TheirKeyInfo` for non-neighbours. For neighbours, we update the keys
            // via `NeighbourInfo`.
            if is_neighbour {
                vote_send_neighbour_info = true;
            } else {
                actions.push(VoteTheirKey {
                    prefix: *src_prefix,
                    key: *src_key,
                });
            }
        }

        if let Some(dst_key) = dst_key {
            let old = self.network.knowledge_by_section(src_prefix);
            let new = self.section.chain().index_of(dst_key).unwrap_or(0);

            if new > old {
                actions.push(VoteTheirKnowledge {
                    prefix: *src_prefix,
                    key_index: new,
                })
            }

            if is_neighbour && new < self.section.chain().last_key_index() {
                vote_send_neighbour_info = true;
            }
        }

        if vote_send_neighbour_info {
            // TODO: if src has split, consider sending to all child prefixes that are still our
            // neighbours.
            actions.push(SendNeighbourInfo {
                dst: *src_prefix,
                nonce: *hash,
            })
        }

        actions
    }

    pub fn compute_relocations(
        &self,
        churn_name: &XorName,
        churn_signature: &bls::Signature,
    ) -> Vec<(MemberInfo, RelocateAction)> {
        self.section
            .members()
            .joined_proven()
            .filter(|info| relocation::check(info.value.peer.age(), churn_signature))
            .map(|info| (info.value, self.create_relocation_action(info, churn_name)))
            .collect()
    }

    pub fn create_relocation_details(
        &self,
        info: &MemberInfo,
        destination: XorName,
    ) -> RelocateDetails {
        let destination_key = *self
            .network
            .key_by_name(&destination)
            .unwrap_or_else(|| self.section.chain().first_key());

        RelocateDetails {
            pub_id: *info.peer.name(),
            destination,
            destination_key,
            age: info.peer.age().saturating_add(1),
        }
    }

    fn create_relocation_action(
        &self,
        info: &Proven<MemberInfo>,
        churn_name: &XorName,
    ) -> RelocateAction {
        let destination = relocation::compute_destination(info.value.peer.name(), churn_name);

        if self.section.is_elder(info.value.peer.name()) {
            RelocateAction::Delayed(RelocatePromise {
                name: *info.value.peer.name(),
                destination,
            })
        } else {
            RelocateAction::Instant(self.create_relocation_details(&info.value, destination))
        }
    }
}

#[derive(Debug)]
pub(crate) enum UpdateSectionKnowledgeAction {
    VoteTheirKey { prefix: Prefix, key: bls::PublicKey },
    VoteTheirKnowledge { prefix: Prefix, key_index: u64 },
    SendNeighbourInfo { dst: Prefix, nonce: MessageHash },
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        consensus,
        crypto::{keypair_within_range, name, Keypair},
        peer::Peer,
        rng::{self, MainRng},
        section::EldersInfo,
        MIN_AGE,
    };

    use rand::{seq::SliceRandom, Rng};
    use std::{
        collections::{BTreeMap, HashMap},
        iter,
        str::FromStr,
    };
    use xor_name::{Prefix, XorName};

    // Note: The following tests were move over from the former `chain` module.

    enum SecInfoGen<'a> {
        New(Prefix, usize),
        Add(&'a EldersInfo),
        Remove(&'a EldersInfo),
    }

    fn gen_section_info(
        rng: &mut MainRng,
        gen: SecInfoGen,
    ) -> (EldersInfo, HashMap<XorName, Keypair>) {
        match gen {
            SecInfoGen::New(prefix, n) => {
                let mut keypairs = HashMap::new();
                let mut members = BTreeMap::new();
                for _ in 0..n {
                    let some_keypair = keypair_within_range(rng, &prefix.range_inclusive());
                    let peer_addr = ([127, 0, 0, 1], 9999).into();
                    let name = name(&some_keypair.public);
                    let _ = members.insert(name, Peer::new(name, peer_addr, MIN_AGE));
                    let _ = keypairs.insert(name, some_keypair);
                }
                (EldersInfo::new(members, prefix), keypairs)
            }
            SecInfoGen::Add(info) => {
                let mut members = info.elders.clone();
                let some_keypair = keypair_within_range(rng, &info.prefix.range_inclusive());
                let peer_addr = ([127, 0, 0, 1], 9999).into();
                let name = name(&some_keypair.public);
                let _ = members.insert(name, Peer::new(name, peer_addr, MIN_AGE));
                let mut keypairs = HashMap::new();
                let _ = keypairs.insert(name, some_keypair);
                (EldersInfo::new(members, info.prefix), keypairs)
            }
            SecInfoGen::Remove(info) => {
                let elders = info.elders.clone();
                (EldersInfo::new(elders, info.prefix), Default::default())
            }
        }
    }

    fn add_neighbour_elders_info(
        state: &mut SharedState,
        our_id: &XorName,
        neighbour_info: Proven<EldersInfo>,
    ) {
        assert!(
            !neighbour_info.value.prefix.matches(our_id),
            "Only add neighbours."
        );
        let _ = state.network.update_neighbour_info(neighbour_info);
    }

    fn gen_state<T>(rng: &mut MainRng, sections: T) -> (SharedState, XorName, bls::SecretKey)
    where
        T: IntoIterator<Item = (Prefix, usize)>,
    {
        let mut our_id = None;
        let mut section_members = vec![];
        for (prefix, size) in sections {
            let (info, ids) = gen_section_info(rng, SecInfoGen::New(prefix, size));
            if our_id.is_none() {
                our_id = ids.keys().next().cloned();
            }

            section_members.push(info);
        }

        let our_pub_id = our_id.expect("our id");
        let mut sections_iter = section_members.into_iter();

        let sk = consensus::test_utils::gen_secret_key(rng);

        let elders_info = sections_iter.next().expect("section members");
        let elders_info = consensus::test_utils::proven(&sk, elders_info);

        let mut state = SharedState::new(SectionProofChain::new(sk.public_key()), elders_info);

        for info in sections_iter {
            let info = consensus::test_utils::proven(&sk, info);
            add_neighbour_elders_info(&mut state, &our_pub_id, info);
        }

        (state, our_pub_id, sk)
    }

    fn gen_00_state(rng: &mut MainRng) -> (SharedState, XorName, bls::SecretKey) {
        let elder_size: usize = 7;
        gen_state(
            rng,
            vec![
                (Prefix::from_str("00").unwrap(), elder_size),
                (Prefix::from_str("01").unwrap(), elder_size),
                (Prefix::from_str("10").unwrap(), elder_size),
            ],
        )
    }

    fn check_infos_for_duplication(state: &SharedState) {
        let mut prefixes: Vec<Prefix> = vec![];
        for info in iter::once(state.section.elders_info()).chain(state.network.all()) {
            if let Some(prefix) = prefixes.iter().find(|x| x.is_compatible(&info.prefix)) {
                panic!(
                    "Found compatible prefixes! {:?} and {:?}",
                    prefix, info.prefix
                );
            }
            prefixes.push(info.prefix);
        }
    }

    #[test]
    fn generate_state() {
        let mut rng = rng::new();

        let (state, our_id, _) = gen_00_state(&mut rng);

        assert!(state.section.elders_info().elders.contains_key(&our_id));
        assert_eq!(state.network.get(&Prefix::default()), None);
        assert!(state.section.chain().self_verify());
        check_infos_for_duplication(&state);
    }

    #[test]
    fn neighbour_info_cleaning() {
        let mut rng = rng::new();
        let (mut state, our_id, sk) = gen_00_state(&mut rng);
        for _ in 0..100 {
            let (new_info, _) = {
                let old_info: Vec<_> = state.network.all().collect();
                let info = old_info.choose(&mut rng).expect("neighbour infos");
                if rng.gen_bool(0.5) {
                    gen_section_info(&mut rng, SecInfoGen::Add(info))
                } else {
                    gen_section_info(&mut rng, SecInfoGen::Remove(info))
                }
            };

            let new_info = consensus::test_utils::proven(&sk, new_info);
            add_neighbour_elders_info(&mut state, &our_id, new_info);
            assert!(state.section.chain().self_verify());
            check_infos_for_duplication(&state);
        }
    }
}
