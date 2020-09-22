// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{quorum_count, EldersInfo, MemberInfo, SectionMap, SectionMembers, SectionProofChain};
use crate::{
    consensus::{Proof, Proven},
    error::Error,
    id::P2pNode,
    location::DstLocation,
    messages::MessageHash,
    network_params::NetworkParams,
    relocation::{self, RelocateAction, RelocateDetails, RelocatePromise},
};

use std::{
    collections::{BTreeMap, BTreeSet},
    convert::TryInto,
    fmt::Debug,
};
use xor_name::{Prefix, XorName};

/// Section state that is shared among all elders of a section via consensus.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) struct SharedState {
    /// Our section's key history for Secure Message Delivery
    pub our_history: SectionProofChain,
    /// Info about all members of our section.
    pub our_members: SectionMembers,
    /// Info about known sections in the network.
    pub sections: SectionMap,
}

impl SharedState {
    /// Creates a minimal `SharedState` initially containing only info about our section elders
    /// (`elders_info`).
    ///
    /// # Panics
    ///
    /// Panics if the key used to sign `elders_info` is not present in `section_chain`.
    pub fn new(section_chain: SectionProofChain, elders_info: Proven<EldersInfo>) -> Self {
        assert!(section_chain.has_key(&elders_info.proof.public_key));

        Self {
            our_history: section_chain,
            sections: SectionMap::new(elders_info),
            our_members: SectionMembers::default(),
        }
    }

    // Merge two `SharedState`s into one.
    // TODO: return `bool` indicating whether anything changed.
    pub fn merge(&mut self, other: Self) -> Result<(), Error> {
        if !other.our_history.self_verify() {
            return Err(Error::InvalidMessage);
        }

        self.our_history
            .merge(other.our_history)
            .map_err(|_| Error::UntrustedMessage)?;

        self.sections.merge(other.sections, &self.our_history);

        self.our_members.merge(other.our_members, &self.our_history);
        self.our_members
            .remove_not_matching_our_prefix(&self.sections.our().prefix);

        Ok(())
    }

    // Clear all data except that which is needed for non-elders.
    pub fn demote(&mut self) {
        *self = self.to_minimal();
    }

    pub fn update_our_info(&mut self, elders_info: Proven<EldersInfo>) -> bool {
        if self
            .sections
            .update_our_info(elders_info, &self.our_history)
        {
            self.our_members
                .remove_not_matching_our_prefix(&self.sections.our().prefix);
            true
        } else {
            false
        }
    }

    pub fn update_neighbour_info(&mut self, elders_info: Proven<EldersInfo>) -> bool {
        self.sections.update_neighbour_info(elders_info)
    }

    pub fn update_our_key(&mut self, key: Proven<bls::PublicKey>) -> bool {
        self.our_history.push(key.value, key.proof.signature)
    }

    pub fn update_their_key(&mut self, key: Proven<(Prefix, bls::PublicKey)>) -> bool {
        if key.value.0 == *self.our_prefix() {
            // Ignore our keys. Use `update_our_key` for that.
            return false;
        }

        self.sections.update_their_key(key)
    }

    pub fn to_minimal(&self) -> Self {
        let first_key_index = self.our_info_signing_key_index();

        Self {
            our_history: self.our_history.slice(first_key_index..),
            our_members: Default::default(),
            sections: SectionMap::new(self.sections.proven_our().clone()),
        }
    }

    /// Returns our own current elders info.
    pub fn our_info(&self) -> &EldersInfo {
        self.sections.our()
    }

    // Creates the shortest proof chain that includes both the key at `their_knowledge`
    // (if provided) and the key our current `elders_info` was signed with.
    pub fn create_proof_chain_for_our_info(
        &self,
        their_knowledge: Option<u64>,
    ) -> SectionProofChain {
        let first_index = self.our_info_signing_key_index();
        let first_index = their_knowledge.unwrap_or(first_index).min(first_index);
        self.our_history.slice(first_index..)
    }

    /// Returns our own current section's prefix.
    pub fn our_prefix(&self) -> &Prefix {
        &self.our_info().prefix
    }

    /// Returns adults from our own section.
    pub fn our_adults(&self) -> impl Iterator<Item = &P2pNode> {
        self.our_members
            .adults()
            .filter(move |p2p_node| !self.is_peer_our_elder(p2p_node.name()))
    }

    /// Returns our members that are either joined or are left but still elders.
    pub fn active_members(&self) -> impl Iterator<Item = &P2pNode> {
        self.our_members
            .all()
            .filter(move |info| {
                self.our_members.is_joined(info.p2p_node.name())
                    || self.is_peer_our_elder(info.p2p_node.name())
            })
            .map(|info| &info.p2p_node)
    }

    /// Checks if given name is an elder in our section or one of our neighbour sections.
    pub fn is_peer_elder(&self, name: &XorName) -> bool {
        self.sections.is_elder(name)
    }

    /// Returns whether the given peer is elder in our section.
    pub fn is_peer_our_elder(&self, name: &XorName) -> bool {
        self.our_info().elders.contains_key(name)
    }

    /// Returns whether the given peer adult or elder.
    pub fn is_peer_adult_or_elder(&self, name: &XorName) -> bool {
        self.our_members.is_adult(name) || self.is_peer_our_elder(name)
    }

    /// All section keys we know of, including the past keys of our section.
    pub fn section_keys(&self) -> impl Iterator<Item = (&Prefix, &bls::PublicKey)> {
        self.our_history
            .keys()
            .map(move |key| (self.our_prefix(), key))
            .chain(self.sections.keys())
    }

    pub fn section_key_by_location(&self, dst: &DstLocation) -> &bls::PublicKey {
        if let Some(name) = dst.name() {
            self.section_key_by_name(name)
        } else {
            // We don't know the section if `dst` is `Direct`, so return the root key which should
            // be trusted by everyone.
            self.our_history.first_key()
        }
    }

    pub fn section_key_by_name(&self, name: &XorName) -> &bls::PublicKey {
        if self.our_prefix().matches(name) {
            self.our_history.last_key()
        } else {
            self.sections
                .key_by_name(name)
                .unwrap_or_else(|| self.our_history.first_key())
        }
    }

    /// Update the member. Returns whether it actually changed anything.
    pub fn update_member(&mut self, member_info: MemberInfo, proof: Proof) -> bool {
        self.our_members
            .update(member_info, proof, &self.our_history)
    }

    /// Generate a new section info(s) based on the current set of members.
    /// Returns a set of EldersInfos to vote for.
    pub fn promote_and_demote_elders(
        &self,
        network_params: &NetworkParams,
        our_name: &XorName,
    ) -> Vec<EldersInfo> {
        if let Some((our_info, other_info)) = self.try_split(network_params, our_name) {
            return vec![our_info, other_info];
        }

        let expected_elders_map = self.elder_candidates(network_params.elder_size);
        let expected_elders: BTreeSet<_> = expected_elders_map.keys().collect();
        let current_elders: BTreeSet<_> = self.our_info().elders.keys().collect();

        if expected_elders == current_elders {
            vec![]
        } else if expected_elders.len() < quorum_count(current_elders.len()) {
            warn!("ignore attempt to reduce the number of elders too much");
            vec![]
        } else {
            let new_info = EldersInfo::new(expected_elders_map, self.our_info().prefix);
            vec![new_info]
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

        let is_neighbour = self.our_prefix().is_neighbour(src_prefix);

        // There will be at most two actions returned because the only possible action combinations
        // are these:
        // - `[]`
        // - `[VoteTheirKey]`
        // - `[VoteTheirKey, VoteTheirKnowledge]`
        // - `[SendNeighbourInfo]`
        // - `[SendNeighbourInfo, VoteTheirKnowledge]`
        let mut actions = Vec::with_capacity(2);
        let mut vote_send_neighbour_info = false;

        if !src_prefix.matches(our_name) && !self.sections.has_key(src_key) {
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
            let old = self.sections.knowledge_by_section(src_prefix);
            let new = self.our_history.index_of(dst_key).unwrap_or(0);

            if new > old {
                actions.push(VoteTheirKnowledge {
                    prefix: *src_prefix,
                    key_index: new,
                })
            }

            if is_neighbour && new < self.our_history.last_key_index() {
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
        self.our_members
            .joined_proven()
            .filter(|info| relocation::check(info.value.age, churn_signature))
            .map(|info| {
                (
                    info.value.clone(),
                    self.create_relocation_action(info, churn_name),
                )
            })
            .collect()
    }

    pub fn create_relocation_details(
        &self,
        info: &MemberInfo,
        destination: XorName,
    ) -> RelocateDetails {
        let destination_key = *self
            .sections
            .key_by_name(&destination)
            .unwrap_or_else(|| self.our_history.first_key());

        RelocateDetails {
            pub_id: *info.p2p_node.public_id(),
            destination,
            destination_key,
            age: info.age.saturating_add(1),
        }
    }

    fn create_relocation_action(
        &self,
        info: &Proven<MemberInfo>,
        churn_name: &XorName,
    ) -> RelocateAction {
        let destination = relocation::compute_destination(info.value.p2p_node.name(), churn_name);

        if self.is_peer_our_elder(info.value.p2p_node.name()) {
            RelocateAction::Delayed(RelocatePromise {
                name: *info.value.p2p_node.name(),
                destination,
            })
        } else {
            RelocateAction::Instant(self.create_relocation_details(&info.value, destination))
        }
    }

    // Tries to split our section.
    // If we have enough mature nodes for both subsections, returns the elders infos of the two
    // subsections. Otherwise returns `None`.
    fn try_split(
        &self,
        network_params: &NetworkParams,
        our_name: &XorName,
    ) -> Option<(EldersInfo, EldersInfo)> {
        let next_bit_index = if let Ok(index) = self.our_prefix().bit_count().try_into() {
            index
        } else {
            // Already at the longest prefix, can't split further.
            return None;
        };

        let next_bit = our_name.bit(next_bit_index);

        let (our_new_size, sibling_new_size) = self
            .our_members
            .adults()
            .map(|p2p_node| p2p_node.name().bit(next_bit_index) == next_bit)
            .fold((0, 0), |(ours, siblings), is_our_prefix| {
                if is_our_prefix {
                    (ours + 1, siblings)
                } else {
                    (ours, siblings + 1)
                }
            });

        // If either of the two new sections will not contain enough entries, return `false`.
        if our_new_size < network_params.recommended_section_size
            || sibling_new_size < network_params.recommended_section_size
        {
            return None;
        }

        let our_prefix = self.our_prefix().pushed(next_bit);
        let other_prefix = self.our_prefix().pushed(!next_bit);

        let our_elders = self.our_members.elder_candidates_matching_prefix(
            &our_prefix,
            network_params.elder_size,
            self.sections.our(),
        );
        let other_elders = self.our_members.elder_candidates_matching_prefix(
            &other_prefix,
            network_params.elder_size,
            self.sections.our(),
        );

        let our_info = EldersInfo::new(our_elders, our_prefix);
        let other_info = EldersInfo::new(other_elders, other_prefix);

        Some((our_info, other_info))
    }

    // Returns the candidates for elders out of all the nodes in the section, even out of the
    // relocating nodes if there would not be enough instead.
    fn elder_candidates(&self, elder_size: usize) -> BTreeMap<XorName, P2pNode> {
        self.our_members
            .elder_candidates(elder_size, self.sections.our())
    }

    fn our_info_signing_key_index(&self) -> u64 {
        // NOTE: we assume that the key the current `EldersInfo` is signed with is always
        // present in our section proof chain. This is currently guaranteed, because we use the
        // `SectionUpdateBarrier` and so we always update the current `EldersInfo` and the current
        // section key at the same time.
        self.our_history
            .index_of(&self.sections.proven_our().proof.public_key)
            .unwrap_or_else(|| unreachable!("our EldersInfo signed with unknown key"))
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
        id::{FullId, P2pNode, PublicId},
        rng::{self, MainRng},
        section::EldersInfo,
    };

    use rand::{seq::SliceRandom, Rng};
    use std::{
        collections::{BTreeMap, HashMap},
        str::FromStr,
    };
    use xor_name::Prefix;

    // Note: The following tests were move over from the former `chain` module.

    enum SecInfoGen<'a> {
        New(Prefix, usize),
        Add(&'a EldersInfo),
        Remove(&'a EldersInfo),
    }

    fn gen_section_info(
        rng: &mut MainRng,
        gen: SecInfoGen,
    ) -> (EldersInfo, HashMap<PublicId, FullId>) {
        match gen {
            SecInfoGen::New(prefix, n) => {
                let mut full_ids = HashMap::new();
                let mut members = BTreeMap::new();
                for _ in 0..n {
                    let some_id = FullId::within_range(rng, &prefix.range_inclusive());
                    let peer_addr = ([127, 0, 0, 1], 9999).into();
                    let pub_id = *some_id.public_id();
                    let _ = members.insert(*pub_id.name(), P2pNode::new(pub_id, peer_addr));
                    let _ = full_ids.insert(*some_id.public_id(), some_id);
                }
                (EldersInfo::new(members, prefix), full_ids)
            }
            SecInfoGen::Add(info) => {
                let mut members = info.elders.clone();
                let some_id = FullId::within_range(rng, &info.prefix.range_inclusive());
                let peer_addr = ([127, 0, 0, 1], 9999).into();
                let pub_id = *some_id.public_id();
                let _ = members.insert(*pub_id.name(), P2pNode::new(pub_id, peer_addr));
                let mut full_ids = HashMap::new();
                let _ = full_ids.insert(pub_id, some_id);
                (EldersInfo::new(members, info.prefix), full_ids)
            }
            SecInfoGen::Remove(info) => {
                let elders = info.elders.clone();
                (EldersInfo::new(elders, info.prefix), Default::default())
            }
        }
    }

    fn add_neighbour_elders_info(
        state: &mut SharedState,
        our_id: &PublicId,
        neighbour_info: Proven<EldersInfo>,
    ) {
        assert!(
            !neighbour_info.value.prefix.matches(our_id.name()),
            "Only add neighbours."
        );
        let _ = state.sections.update_neighbour_info(neighbour_info);
    }

    fn gen_state<T>(rng: &mut MainRng, sections: T) -> (SharedState, PublicId, bls::SecretKey)
    where
        T: IntoIterator<Item = (Prefix, usize)>,
    {
        let mut our_id = None;
        let mut section_members = vec![];
        for (prefix, size) in sections {
            let (info, ids) = gen_section_info(rng, SecInfoGen::New(prefix, size));
            if our_id.is_none() {
                our_id = ids.values().next().cloned();
            }

            section_members.push(info);
        }

        let our_id = our_id.expect("our id");
        let our_pub_id = *our_id.public_id();
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

    fn gen_00_state(rng: &mut MainRng) -> (SharedState, PublicId, bls::SecretKey) {
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
        for info in state.sections.all() {
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

        assert_eq!(
            state
                .sections
                .get(&Prefix::from_str("00").unwrap())
                .map(|info| info.elders.contains_key(our_id.name())),
            Some(true)
        );
        assert_eq!(state.sections.get(&Prefix::from_str("").unwrap()), None);
        assert!(state.our_history.self_verify());
        check_infos_for_duplication(&state);
    }

    #[test]
    fn neighbour_info_cleaning() {
        let mut rng = rng::new();
        let (mut state, our_id, sk) = gen_00_state(&mut rng);
        for _ in 0..100 {
            let (new_info, _) = {
                let old_info: Vec<_> = state.sections.neighbours().collect();
                let info = old_info.choose(&mut rng).expect("neighbour infos");
                if rng.gen_bool(0.5) {
                    gen_section_info(&mut rng, SecInfoGen::Add(info))
                } else {
                    gen_section_info(&mut rng, SecInfoGen::Remove(info))
                }
            };

            let new_info = consensus::test_utils::proven(&sk, new_info);
            add_neighbour_elders_info(&mut state, &our_id, new_info);
            assert!(state.our_history.self_verify());
            check_infos_for_duplication(&state);
        }
    }
}
