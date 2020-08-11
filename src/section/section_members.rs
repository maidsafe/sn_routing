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
use crate::{
    consensus::{Proof, Proven},
    id::P2pNode,
};

use itertools::Itertools;
use std::{
    cmp::Ordering,
    collections::{btree_map::Entry, BTreeMap},
    hash::{Hash, Hasher},
    mem,
};
use xor_name::{Prefix, XorName};

/// Container for storing information about members of our section.
#[derive(Clone, Default, Debug, Eq, Serialize, Deserialize)]
pub struct SectionMembers {
    members: BTreeMap<XorName, Proven<MemberInfo>>,
    // Members of our sibling section immediately after the last split.
    // Note: this field is not part of the shared state.
    // TODO: do we still need this?
    #[serde(skip)]
    post_split_siblings: BTreeMap<XorName, Proven<MemberInfo>>,
}

impl SectionMembers {
    /// Returns an iterator over the members that are not in the `Left` state.
    pub fn active(&self) -> impl Iterator<Item = &MemberInfo> {
        self.members
            .values()
            .map(|info| &info.value)
            .filter(|member| member.state != MemberState::Left)
    }

    /// Returns an iterator over the members that have state == `Joined`.
    pub fn joined(&self) -> impl Iterator<Item = &MemberInfo> {
        self.members
            .values()
            .map(|info| &info.value)
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
        self.members.get(name).map(|info| &info.value)
    }

    /// Returns a section member `P2pNode`
    pub fn get_p2p_node(&self, name: &XorName) -> Option<&P2pNode> {
        self.members
            .get(name)
            .or_else(|| self.post_split_siblings.get(name))
            .map(|info| &info.value.p2p_node)
    }

    /// Returns the candidates for elders out of all the nodes in this section.
    pub fn elder_candidates(
        &self,
        elder_size: usize,
        current_elders: &EldersInfo,
    ) -> BTreeMap<XorName, P2pNode> {
        elder_candidates(
            elder_size,
            current_elders,
            self.members
                .values()
                .filter(|info| info.value.state == MemberState::Joined),
        )
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
            self.members.values().filter(|info| {
                info.value.state == MemberState::Joined
                    && prefix.matches(info.value.p2p_node.name())
            }),
        )
    }

    /// Check if the given `XorName` is or was a member of our section.
    // pub fn contains(&self, name: &XorName) -> bool {
    //     self.members.contains_key(name)
    // }

    /// Returns whether the given peer is a joined member of our section.
    pub fn is_joined(&self, name: &XorName) -> bool {
        self.members
            .get(name)
            .map(|info| info.value.state == MemberState::Joined)
            .unwrap_or(false)
    }

    /// Returns whether the given peer is mature (adult or elder)
    pub fn is_mature(&self, name: &XorName) -> bool {
        self.members
            .get(name)
            .map(|info| info.value.is_mature())
            .unwrap_or(false)
    }

    /// Update a member of our section.
    /// Returns whether anything actually changed.
    pub fn update(
        &mut self,
        new_info: MemberInfo,
        proof: Proof,
        section_chain: &SectionProofChain,
    ) -> bool {
        match self.members.entry(*new_info.p2p_node.name()) {
            Entry::Vacant(entry) => {
                let new_info = Proven::new(new_info, proof);
                if new_info.verify(section_chain) {
                    let _ = entry.insert(new_info);
                    true
                } else {
                    false
                }
            }
            Entry::Occupied(mut entry) if entry.get().value.state == MemberState::Joined => {
                // TODO: To maintain commutativity, if new_info is `Joined`, only apply it if its
                // `age` is greater that the current age.

                let new_info = Proven::new(new_info, proof);
                if new_info.verify(section_chain) {
                    let _ = entry.insert(new_info);
                    true
                } else {
                    false
                }
            }
            Entry::Occupied(_) => false,
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

impl Hash for SectionMembers {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.members.hash(state)
    }
}

// Returns the nodes that should become the next elders out of the given members.
fn elder_candidates<'a, I>(
    elder_size: usize,
    current_elders: &EldersInfo,
    members: I,
) -> BTreeMap<XorName, P2pNode>
where
    I: IntoIterator<Item = &'a Proven<MemberInfo>>,
{
    members
        .into_iter()
        .sorted_by(|lhs, rhs| cmp_elder_candidates(lhs, rhs, current_elders))
        .map(|info| (*info.value.p2p_node.name(), info.value.p2p_node.clone()))
        .take(elder_size)
        .collect()
}

// Compare candidates for the next elders. The one comparing `Less` is more likely to become
// elder.
fn cmp_elder_candidates(
    lhs: &Proven<MemberInfo>,
    rhs: &Proven<MemberInfo>,
    current_elders: &EldersInfo,
) -> Ordering {
    // Older nodes are preferred. In case of a tie, prefer current elders. If still a tie, break
    // it comparing by the proof signatures because it's impossible for a node to predict its
    // signature and therefore game its chances of promotion.
    rhs.value
        .age
        .cmp(&lhs.value.age)
        .then_with(|| {
            let lhs_is_elder = current_elders
                .elders
                .contains_key(lhs.value.p2p_node.name());
            let rhs_is_elder = current_elders
                .elders
                .contains_key(rhs.value.p2p_node.name());

            match (lhs_is_elder, rhs_is_elder) {
                (true, false) => Ordering::Less,
                (false, true) => Ordering::Greater,
                _ => Ordering::Equal,
            }
        })
        .then_with(|| lhs.proof.signature.cmp(&rhs.proof.signature))
}
