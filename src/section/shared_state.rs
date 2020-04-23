// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    AgeCounter, EldersInfo, MemberState, SectionKeyInfo, SectionMap, SectionMembers,
    SectionProofBlock, SectionProofChain,
};
use crate::{
    consensus::AccumulatedEvent,
    error::Result,
    id::{P2pNode, PublicId},
    network_params::NetworkParams,
    relocation::{self, RelocateDetails},
    xor_space::{Prefix, XorName, Xorable},
};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fmt::Debug,
    net::SocketAddr,
};

/// Section state that is shared among all elders of a section via Parsec consensus.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedState {
    /// Indicate whether nodes are shared state because genesis event was seen
    #[serde(skip)]
    pub handled_genesis_event: bool,
    /// Our section's key history for Secure Message Delivery
    pub our_history: SectionProofChain,
    /// Info about all members of our section.
    pub our_members: SectionMembers,
    /// Info about known sections in the network.
    pub sections: SectionMap,
    /// Backlog of completed events that need to be processed when churn completes.
    pub churn_event_backlog: VecDeque<AccumulatedEvent>,
    /// Queue of pending relocations.
    pub relocate_queue: VecDeque<RelocateDetails>,
}

impl SharedState {
    pub fn new(
        elders_info: EldersInfo,
        bls_keys: bls::PublicKeySet,
        ages: BTreeMap<PublicId, AgeCounter>,
    ) -> Self {
        let pk_info = SectionKeyInfo::from_elders_info(&elders_info, bls_keys.public_key());
        let our_history = SectionProofChain::from_genesis(pk_info);
        let our_key_info = our_history.last_key_info().clone();
        let our_members = SectionMembers::new(&elders_info, &ages);

        Self {
            handled_genesis_event: false,
            our_history,
            sections: SectionMap::new(elders_info, our_key_info),
            our_members,
            churn_event_backlog: Default::default(),
            relocate_queue: VecDeque::new(),
        }
    }

    pub fn update(&mut self, new: Option<Self>) {
        if self.handled_genesis_event {
            log_or_panic!(
                log::Level::Error,
                "shared state update - genesis event already handled",
            );
        }

        if let Some(new) = new {
            if self.sections.has_our_history() && *self != new {
                log_or_panic!(
                    log::Level::Error,
                    "shared state update - mismatch: old: {:?} --- new: {:?}",
                    self,
                    new
                );
            }

            *self = new;
        }

        self.handled_genesis_event = true;
    }

    /// Returns our own current section info.
    pub fn our_info(&self) -> &EldersInfo {
        self.sections.our()
    }

    /// Returns our own current section's prefix.
    pub fn our_prefix(&self) -> &Prefix<XorName> {
        self.our_info().prefix()
    }

    /// Returns adults from our own section.
    pub fn our_adults(&self) -> impl Iterator<Item = &P2pNode> {
        self.our_members
            .mature()
            .filter(move |p2p_node| !self.is_peer_our_elder(p2p_node.public_id()))
    }

    /// Returns all nodes we know (our members + neighbour elders).
    pub fn known_nodes(&self) -> impl Iterator<Item = &P2pNode> {
        self.our_members
            .active()
            .map(|info| &info.p2p_node)
            .chain(self.sections.other_elders())
    }

    /// Checks if given `PublicId` is an elder in our section or one of our neighbour sections.
    pub fn is_peer_elder(&self, pub_id: &PublicId) -> bool {
        self.sections.is_elder(pub_id)
    }

    /// Returns whether the given peer is elder in our section.
    pub fn is_peer_our_elder(&self, pub_id: &PublicId) -> bool {
        self.our_info().is_member(pub_id)
    }

    pub fn find_p2p_node_from_addr(&self, socket_addr: &SocketAddr) -> Option<&P2pNode> {
        self.known_nodes()
            .find(|p2p_node| p2p_node.peer_addr() == socket_addr)
    }

    /// Adds new member if its name matches our prefix and it's not already joined.
    /// Returns whether the member was actually added.
    pub fn add_member(&mut self, p2p_node: P2pNode, age: u8, safe_section_size: usize) -> bool {
        if !self.our_prefix().matches(p2p_node.name()) {
            trace!("not adding node {} - not matching our prefix", p2p_node);
            return false;
        }

        if self.our_members.contains(p2p_node.public_id()) {
            trace!("not adding node {} - already a member", p2p_node);
            return false;
        }

        let pub_id = *p2p_node.public_id();

        self.our_members.add(p2p_node, age);
        self.increment_age_counters(&pub_id, safe_section_size);

        true
    }

    pub fn remove_member(
        &mut self,
        pub_id: &PublicId,
        safe_section_size: usize,
    ) -> (Option<SocketAddr>, MemberState) {
        match self.our_members.get(pub_id.name()).map(|info| &info.state) {
            Some(MemberState::Left) | None => {
                trace!("not removing node {} - not a member", pub_id);
                return (None, MemberState::Left);
            }
            Some(MemberState::Relocating { .. }) => (),
            Some(MemberState::Joined) => self.increment_age_counters(pub_id, safe_section_size),
        }

        self.relocate_queue
            .retain(|details| &details.pub_id != pub_id);
        self.our_members.remove(pub_id)
    }

    /// Remove all entries from `our_members` whose name does not match our prefix.
    pub fn remove_our_members_not_matching_our_prefix(&mut self) {
        self.our_members
            .remove_not_matching_our_prefix(self.sections.our().prefix())
    }

    /// Find section which has member with the given id
    pub fn find_section_by_member(&self, pub_id: &PublicId) -> Option<&EldersInfo> {
        if self.our_members.contains(pub_id) {
            Some(self.sections.our())
        } else {
            self.sections.find_other_by_member(pub_id)
        }
    }

    /// Returns the `P2pNode` of all non-elders in the section
    pub fn adults_and_infants_p2p_nodes(&self) -> impl Iterator<Item = &P2pNode> {
        self.our_members
            .joined()
            .filter(move |info| !self.our_info().is_member(info.p2p_node.public_id()))
            .map(|info| &info.p2p_node)
    }

    /// Return prefixes of all our neighbours
    pub fn neighbour_prefixes(&self) -> BTreeSet<Prefix<XorName>> {
        self.sections.other().map(|(prefix, _)| *prefix).collect()
    }

    /// Generate a new section info(s) based on the current set of members.
    /// Returns a set of EldersInfos to vote for.
    pub fn promote_and_demote_elders(
        &mut self,
        our_name: &XorName,
        network_params: &NetworkParams,
    ) -> Result<Option<Vec<EldersInfo>>> {
        if let Some((our_info, other_info)) = self.try_split(our_name, network_params)? {
            return Ok(Some(vec![our_info, other_info]));
        }

        let expected_elders_map = self.elder_candidates(network_params.elder_size);
        let expected_elders: BTreeSet<_> = expected_elders_map.values().cloned().collect();
        let current_elders: BTreeSet<_> = self.our_info().member_nodes().cloned().collect();

        if expected_elders == current_elders {
            Ok(None)
        } else {
            let old_size = self.our_info().len();

            let new_info = EldersInfo::new(
                expected_elders_map,
                *self.our_info().prefix(),
                Some(self.our_info()),
            )?;

            if self.our_info().len() < network_params.elder_size
                && old_size >= network_params.elder_size
            {
                panic!(
                    "Merging situation encountered! Not supported: {:?}",
                    self.our_info()
                );
            }

            Ok(Some(vec![new_info]))
        }
    }

    pub fn push_our_new_info(&mut self, elders_info: EldersInfo, proof_block: SectionProofBlock) {
        self.our_history.push(proof_block);
        self.sections.push_our(elders_info);
        self.sections.update_keys(self.our_history.last_key_info());
    }

    pub fn poll_relocation(&mut self) -> Option<RelocateDetails> {
        // Delay relocation until all backlogged churn events have been handled. Only allow one
        // relocation at a time.
        if !self.churn_event_backlog.is_empty() {
            return None;
        }

        let details = loop {
            if let Some(details) = self.relocate_queue.pop_back() {
                if self.our_members.contains(&details.pub_id) {
                    break details;
                } else {
                    trace!("Not relocating {} - not a member", details.pub_id);
                }
            } else {
                return None;
            }
        };

        if self.is_peer_our_elder(&details.pub_id) {
            warn!(
                "Not relocating {} - The peer is still our elder.",
                details.pub_id,
            );

            // Keep the details in the queue so when the node is demoted we can relocate it.
            self.relocate_queue.push_back(details);
            return None;
        }

        trace!("relocating member {}", details.pub_id);
        Some(details)
    }

    // Tries to split our section.
    // If we have enough mature nodes for both subsections, returns the elders infos of the two
    // subsections. Otherwise returns `None`.
    fn try_split(
        &self,
        our_name: &XorName,
        network_params: &NetworkParams,
    ) -> Result<Option<(EldersInfo, EldersInfo)>> {
        let next_bit_index = self.our_prefix().bit_count();
        let next_bit = our_name.bit(next_bit_index);

        let (our_new_size, sibling_new_size) = self
            .our_members
            .mature()
            .map(|p2p_node| p2p_node.name().bit(next_bit_index) == next_bit)
            .fold((0, 0), |(ours, siblings), is_our_prefix| {
                if is_our_prefix {
                    (ours + 1, siblings)
                } else {
                    (ours, siblings + 1)
                }
            });

        // If either of the two new sections will not contain enough entries, return `false`.
        if our_new_size < network_params.safe_section_size
            || sibling_new_size < network_params.safe_section_size
        {
            return Ok(None);
        }

        let our_prefix = self.our_prefix().pushed(next_bit);
        let other_prefix = self.our_prefix().pushed(!next_bit);

        let our_elders = self
            .our_members
            .elder_candidates_matching_prefix(&our_prefix, network_params.elder_size);
        let other_elders = self
            .our_members
            .elder_candidates_matching_prefix(&other_prefix, network_params.elder_size);

        let our_info = EldersInfo::new(our_elders, our_prefix, Some(self.our_info()))?;
        let other_info = EldersInfo::new(other_elders, other_prefix, Some(self.our_info()))?;

        Ok(Some((our_info, other_info)))
    }

    // Returns the candidates for elders out of all the nodes in the section, even out of the
    // relocating nodes if there would not be enough instead.
    fn elder_candidates(&self, elder_size: usize) -> BTreeMap<XorName, P2pNode> {
        let mut elders = self.our_members.elder_candidates(elder_size);

        // Ensure that we can still handle one node lost when relocating.
        // Ensure that the node we eject are the one we want to relocate first.
        let missing = elder_size.saturating_sub(elders.len());
        elders.extend(self.elder_candidates_from_relocating(missing));
        elders
    }

    /// Returns the `count` candidates for elders out of currently relocating nodes. Use this
    /// method when we don't have enough non-relocating nodes in the section to become elders.
    fn elder_candidates_from_relocating<'a>(
        &'a self,
        count: usize,
    ) -> impl Iterator<Item = (XorName, P2pNode)> + 'a {
        self.relocate_queue
            .iter()
            .map(|details| details.pub_id.name())
            .filter_map(move |name| self.our_members.get(name))
            .filter(|info| info.state != MemberState::Left)
            .take(count)
            .map(|info| (*info.p2p_node.name(), info.p2p_node.clone()))
    }

    // Increment the age counters of the members.
    fn increment_age_counters(&mut self, trigger_node: &PublicId, safe_section_size: usize) {
        let our_section_size = self.our_members.joined().count();
        let our_prefix = self.sections.our().prefix();

        // Is network startup in progress?
        let startup = *our_prefix == Prefix::default() && our_section_size < safe_section_size;

        // As a measure against sybil attacks, we don't increment the age counters on infant churn
        // once we completed the startup phase.
        if !startup
            && !self.our_members.is_mature(trigger_node)
            && !self.is_peer_our_elder(trigger_node)
        {
            trace!(
                "Not incrementing age counters on infant churn (section size: {})",
                our_section_size,
            );
            return;
        }

        let relocating_state = self.create_relocating_state();
        let first_key_info = self.our_history.first_key_info();

        for member_info in self.our_members.joined_mut() {
            if member_info.p2p_node.public_id() == trigger_node {
                continue;
            }

            // During network startup we go through accelerated ageing.
            if startup {
                member_info.increment_age();
                continue;
            }

            if !member_info.increment_age_counter() {
                continue;
            }

            let destination = relocation::compute_destination(
                our_prefix,
                member_info.p2p_node.name(),
                trigger_node.name(),
            );
            if our_prefix.matches(&destination) {
                // Relocation destination inside the current section - ignoring.
                trace!(
                    "increment_age_counters: Ignoring relocation for {:?}",
                    member_info.p2p_node.public_id()
                );
                continue;
            }

            trace!(
                "Change state to Relocating {}",
                member_info.p2p_node.public_id()
            );
            member_info.state = relocating_state;

            let destination_key_info = self
                .sections
                .latest_compatible_key(&destination)
                .unwrap_or(first_key_info)
                .clone();

            let details = RelocateDetails {
                pub_id: *member_info.p2p_node.public_id(),
                destination,
                destination_key_info,
                // TODO: why the +1 ?
                age: member_info.age() + 1,
            };

            self.relocate_queue.push_front(details);
        }

        trace!("increment_age_counters: {:?}", self.our_members);
    }

    // Return a relocating state of a node relocating now.
    // Ensure that node knows enough to trust node_knowledge proving index.
    fn create_relocating_state(&self) -> MemberState {
        let node_knowledge = self.sections.get_knowledge(self.our_prefix()).unwrap_or(0);
        MemberState::Relocating { node_knowledge }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        consensus::generate_bls_threshold_secret_key,
        id::P2pNode,
        location::DstLocation,
        rng::{self, MainRng},
        section::EldersInfo,
        unwrap, FullId, Prefix, XorName,
    };
    use rand::Rng;
    use std::{collections::BTreeMap, str::FromStr};

    fn gen_elders_info(rng: &mut MainRng, pfx: Prefix<XorName>, version: u64) -> EldersInfo {
        let sec_size = 5;
        let mut members = BTreeMap::new();
        (0..sec_size).for_each(|index| {
            let pub_id = *FullId::within_range(rng, &pfx.range_inclusive()).public_id();
            let _ = members.insert(
                pub_id,
                P2pNode::new(pub_id, ([127, 0, 0, 1], 9000 + index).into()),
            );
        });
        unwrap!(EldersInfo::new_for_test(members, pfx, version))
    }

    // start_pfx: the prefix of our section as string
    // updates: our section prefix followed by the prefixes of the sections we update the keys for,
    //          in sequence; every entry in the vector will get its own key.
    // expected: vec of pairs (prefix, index)
    //           the prefix is the prefix of the section whose key we check
    //           the index is the index in the `updates` vector, which should have generated the
    //           key we expect to get for the given prefix
    fn update_keys_and_check(rng: &mut MainRng, updates: Vec<&str>, expected: Vec<(&str, usize)>) {
        update_keys_and_check_with_version(rng, updates.into_iter().enumerate().collect(), expected)
    }

    fn update_keys_and_check_with_version(
        rng: &mut MainRng,
        updates: Vec<(usize, &str)>,
        expected: Vec<(&str, usize)>,
    ) {
        // Arrange
        //
        let keys_to_update = updates
            .into_iter()
            .map(|(version, pfx_str)| {
                let pfx = unwrap!(Prefix::<XorName>::from_str(pfx_str));
                let elders_info = gen_elders_info(rng, pfx, version as u64);
                let bls_keys = generate_bls_threshold_secret_key(rng, 1).public_keys();
                let key_info =
                    SectionKeyInfo::from_elders_info(&elders_info, bls_keys.public_key());
                (key_info, elders_info, bls_keys)
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
            let start_section = unwrap!(keys_to_update.first());
            let info = start_section.1.clone();
            let keys = start_section.2.clone();
            SharedState::new(info, keys, Default::default())
        };

        // Act
        //
        for (key_info, _, _) in keys_to_update.iter().skip(1) {
            state.sections.update_keys(key_info);
        }

        // Assert
        //
        let actual_keys = state
            .sections
            .keys()
            .map(|(p, info)| {
                (
                    *p,
                    keys_to_update
                        .iter()
                        .position(|(key_info, _, _)| key_info == info),
                )
            })
            .collect::<Vec<_>>();

        assert_eq!(actual_keys, expected_keys);
    }

    #[test]
    fn single_prefix_multiple_updates() {
        update_keys_and_check(
            &mut rng::new(),
            vec!["0", "1", "1", "1", "1"],
            vec![("0", 0), ("1", 4), ("1", 3), ("1", 2), ("1", 1)],
        );
    }

    #[test]
    fn single_prefix_multiple_updates_out_of_order() {
        // Late version ignored
        update_keys_and_check_with_version(
            &mut rng::new(),
            vec![(0, "0"), (0, "1"), (2, "1"), (1, "1"), (3, "1")],
            vec![("0", 0), ("1", 4), ("1", 2), ("1", 1)],
        );
    }

    #[test]
    fn simple_split() {
        update_keys_and_check(
            &mut rng::new(),
            vec!["0", "10", "11", "101"],
            vec![("0", 0), ("100", 1), ("101", 3), ("11", 2), ("10", 1)],
        );
    }

    #[test]
    fn simple_split_out_of_order() {
        // Late version ignored
        update_keys_and_check_with_version(
            &mut rng::new(),
            vec![(0, "0"), (5, "10"), (5, "11"), (7, "101"), (6, "10")],
            vec![("0", 0), ("100", 1), ("101", 3), ("11", 2), ("10", 1)],
        );
    }

    #[test]
    fn our_section_not_sibling_of_ancestor() {
        // 01 Not the sibling of the single bit parent prefix of 111
        update_keys_and_check(
            &mut rng::new(),
            vec!["01", "1", "111"],
            vec![("01", 0), ("10", 1), ("110", 1), ("111", 2), ("1", 1)],
        );
    }

    #[test]
    fn multiple_split() {
        update_keys_and_check(
            &mut rng::new(),
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

    // Perform a series of updates to `their_knowledge`, then verify that the proving indices for
    // the given dst locations are as expected.
    //
    // - `updates` - pairs of (prefix, version) to pass to `update_their_knowledge`
    // - `expected_proving_indices` - pairs of (prefix, index) where the dst location name is
    //   generated such that it matches `prefix` and `index` is the expected proving index.
    fn update_their_knowledge_and_check_proving_index(
        rng: &mut MainRng,
        updates: Vec<(&str, u64)>,
        expected_proving_indices: Vec<(&str, u64)>,
    ) {
        let mut state = SharedState::new(
            gen_elders_info(rng, Default::default(), 0),
            generate_bls_threshold_secret_key(rng, 1).public_keys(),
            Default::default(),
        );

        for (prefix_str, version) in updates {
            let prefix = unwrap!(prefix_str.parse());
            state.sections.update_knowledge(prefix, version);
        }

        for (dst_name_prefix_str, expected_index) in expected_proving_indices {
            let dst_name_prefix: Prefix<_> = unwrap!(dst_name_prefix_str.parse());
            let dst_name = dst_name_prefix.substituted_in(rng.gen());
            let dst = DstLocation::Section(dst_name);

            assert_eq!(state.sections.proving_index(&dst), expected_index);
        }
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
}
