// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    member_info::{MemberInfo, MemberState},
    section_proof_chain::SectionProofChain,
    EldersInfo,
};
use crate::{consensus::Proof, id::P2pNode};

use itertools::Itertools;
use std::{
    cmp::Ordering,
    collections::{btree_map::Entry, BTreeMap},
    mem,
};
use xor_name::{Prefix, XorName};

/// Container for storing information about members of our section.
#[derive(Default, Debug, Eq, Serialize, Deserialize)]
pub struct SectionMembers {
    members: BTreeMap<XorName, MemberInfo>,
    // Members of our sibling section immediately after the last split.
    // Note: this field is not part of the shared state.
    #[serde(skip)]
    post_split_siblings: BTreeMap<XorName, MemberInfo>,
}

impl SectionMembers {
    /// Returns an iterator over the members that are not in the `Left` state.
    pub fn active(&self) -> impl Iterator<Item = &MemberInfo> {
        self.members
            .values()
            .filter(|member| member.state != MemberState::Left)
    }

    /// Returns an iterator over the members that have state == `Joined`.
    pub fn joined(&self) -> impl Iterator<Item = &MemberInfo> {
        self.members
            .values()
            .filter(|member| member.state == MemberState::Joined)
    }

    /// Returns mutable iterator over the members that have state == `Joined`.
    pub fn joined_mut(&mut self) -> impl Iterator<Item = &mut MemberInfo> {
        self.members
            .values_mut()
            .filter(|member| member.state == MemberState::Joined)
    }

    /// Returns nodes from our section with age greater than `MIN_AGE`
    pub fn mature(&self) -> impl Iterator<Item = &P2pNode> {
        self.joined()
            .filter(|info| info.is_mature())
            .map(|info| &info.p2p_node)
    }

    /// Get info for the member with the given name.
    pub fn get(&self, name: &XorName) -> Option<&MemberInfo> {
        self.members.get(name)
    }

    /// Returns a section member `P2pNode`
    pub fn get_p2p_node(&self, name: &XorName) -> Option<&P2pNode> {
        self.members
            .get(name)
            .or_else(|| self.post_split_siblings.get(name))
            .map(|info| &info.p2p_node)
    }

    /// Returns the candidates for elders out of all the nodes in this section.
    pub fn elder_candidates(
        &self,
        elder_size: usize,
        current_elders: &EldersInfo,
    ) -> BTreeMap<XorName, P2pNode> {
        elder_candidates(elder_size, current_elders, self.joined())
    }

    /// Returns the candidates for elders out of all nodes matching the prefix.
    pub fn elder_candidates_matching_prefix(
        &self,
        prefix: &Prefix,
        elder_size: usize,
        current_elders: &EldersInfo,
    ) -> BTreeMap<XorName, P2pNode> {
        elder_candidates(
            elder_size,
            current_elders,
            self.joined()
                .filter(|info| prefix.matches(info.p2p_node.name())),
        )
    }

    /// Check if the given `XorName` is an active member of our section.
    pub fn contains(&self, name: &XorName) -> bool {
        self.members
            .get(name)
            .map(|info| info.state != MemberState::Left)
            .unwrap_or(false)
    }

    /// Returns whether the given peer is an active (not left) member of our section.
    pub fn is_active(&self, name: &XorName) -> bool {
        self.members
            .get(name)
            .map(|info| info.state != MemberState::Left)
            .unwrap_or(false)
    }

    /// Returns whether the given peer is mature (adult or elder)
    pub fn is_mature(&self, name: &XorName) -> bool {
        self.members
            .get(name)
            .map(|info| info.is_mature())
            .unwrap_or(false)
    }

    /// Adds a member to our section.
    pub fn add(&mut self, p2p_node: P2pNode, age: u8, proof: Proof) {
        match self.members.entry(*p2p_node.name()) {
            Entry::Occupied(mut entry) => {
                if entry.get().state == MemberState::Left {
                    // Node rejoining
                    // TODO: To properly support rejoining, either keep the previous age or set the
                    // new age to max(old_age, new_age)
                    let info = entry.get_mut();
                    info.state = MemberState::Joined;
                    info.set_age(age);
                    info.proof = proof;
                } else {
                    // Node already joined - this should not happen.
                    log_or_panic!(
                        log::Level::Error,
                        "Adding member that already exists: {}",
                        p2p_node,
                    );
                }
            }
            Entry::Vacant(entry) => {
                // Node joining for the first time.
                let _ = entry.insert(MemberInfo::new(age, p2p_node.clone(), proof));
            }
        }
    }

    /// Remove a member from our section. Returns the removed `MemberInfo` or `None` if there was
    /// no such member.
    pub fn remove(&mut self, name: &XorName, proof: Proof) -> Option<MemberInfo> {
        if let Some(info) = self
            .members
            .get_mut(name)
            // TODO: Probably should actually remove them
            .filter(|info| info.state != MemberState::Left)
        {
            let output = info.clone();
            info.state = MemberState::Left;
            info.proof = proof;
            Some(output)
        } else {
            // FIXME: we should still insert it in the `Left` state
            log_or_panic!(
                log::Level::Error,
                "Removing member that doesn't exist: {}",
                name
            );

            None
        }
    }

    /// Remove all members whose name does not match our prefix and assigns them to
    /// `post_split_siblings`.
    pub fn remove_not_matching_our_prefix(&mut self, prefix: &Prefix) {
        let (members, siblings) = mem::take(&mut self.members)
            .into_iter()
            .partition(|(name, _)| prefix.matches(name));
        self.members = members;
        self.post_split_siblings = siblings;
    }

    /// Iterate through member infos to ensure they are section approved.
    pub fn verify(&self, history: &SectionProofChain) -> bool {
        self.members
            .values()
            .all(|member_info| member_info.verify(history))
            && self
                .post_split_siblings
                .values()
                .all(|member_info| member_info.verify(history))
    }
}

impl PartialEq for SectionMembers {
    fn eq(&self, other: &Self) -> bool {
        self.members == other.members
    }
}

// Returns the nodes that should become the next elders out of the given members.
fn elder_candidates<'a, I>(
    elder_size: usize,
    current_elders: &EldersInfo,
    members: I,
) -> BTreeMap<XorName, P2pNode>
where
    I: IntoIterator<Item = &'a MemberInfo>,
{
    members
        .into_iter()
        .sorted_by(|lhs, rhs| cmp_elder_candidates(lhs, rhs, current_elders))
        .map(|info| (*info.p2p_node.name(), info.p2p_node.clone()))
        .take(elder_size)
        .collect()
}

// Compare candidates for the next elders. The one comparing `Less` is more likely to become
// elder.
fn cmp_elder_candidates(
    lhs: &MemberInfo,
    rhs: &MemberInfo,
    current_elders: &EldersInfo,
) -> Ordering {
    // Older nodes are preferred. In case of a tie, prefer current elders. If still a tie, break
    // it comparing by the proof signatures because it's impossible for a node to predict its
    // signature and therefore game its chances of promotion.
    rhs.age_counter
        .cmp(&lhs.age_counter)
        .then_with(|| {
            let lhs_is_elder = current_elders.elders.contains_key(lhs.p2p_node.name());
            let rhs_is_elder = current_elders.elders.contains_key(rhs.p2p_node.name());

            match (lhs_is_elder, rhs_is_elder) {
                (true, false) => Ordering::Less,
                (false, true) => Ordering::Greater,
                _ => Ordering::Equal,
            }
        })
        .then_with(|| lhs.proof.signature.cmp(&rhs.proof.signature))
}
