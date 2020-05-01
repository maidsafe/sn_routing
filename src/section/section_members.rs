// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    elders_info::EldersInfo,
    member_info::{AgeCounter, MemberInfo, MemberState, MIN_AGE_COUNTER},
};
use crate::{
    id::{P2pNode, PublicId},
    xor_space::{Prefix, XorName},
};
use itertools::Itertools;
use std::{
    cmp::Ordering,
    collections::{btree_map::Entry, BTreeMap},
    mem,
    net::SocketAddr,
};

/// Container for storing information about members of our section.
#[derive(Debug, Eq, Serialize, Deserialize)]
pub struct SectionMembers {
    members: BTreeMap<XorName, MemberInfo>,
    // Number that gets incremented every time a node joins or leaves our section - that is, every
    // time `members` changes.
    version: u64,

    // Members of our sibling section immediately after the last split.
    // Note: this field is not part of the shared state.
    #[serde(skip)]
    post_split_siblings: BTreeMap<XorName, MemberInfo>,
}

impl SectionMembers {
    /// Constructs the container initially with the section elders.
    pub fn new(elders_info: &EldersInfo, ages: &BTreeMap<PublicId, AgeCounter>) -> Self {
        let members = elders_info
            .elders
            .values()
            .map(|p2p_node| {
                let info = MemberInfo {
                    age_counter: *ages.get(p2p_node.public_id()).unwrap_or(&MIN_AGE_COUNTER),
                    state: MemberState::Joined,
                    p2p_node: p2p_node.clone(),
                    section_version: 0,
                };
                (*p2p_node.name(), info)
            })
            .collect();

        Self {
            members,
            version: 0,
            post_split_siblings: Default::default(),
        }
    }

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

    /// Returns joined adults and elders from our section.
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
    pub fn elder_candidates(&self, elder_size: usize) -> BTreeMap<XorName, P2pNode> {
        elder_candidates(elder_size, self.joined())
    }

    /// Returns the candidates for elders out of all nodes matching the prefix.
    pub fn elder_candidates_matching_prefix(
        &self,
        prefix: &Prefix<XorName>,
        elder_size: usize,
    ) -> BTreeMap<XorName, P2pNode> {
        elder_candidates(
            elder_size,
            self.joined()
                .filter(|info| prefix.matches(info.p2p_node.name())),
        )
    }

    /// Check if the given `PublicId` is an active member of our section.
    pub fn contains(&self, pub_id: &PublicId) -> bool {
        self.members
            .get(pub_id.name())
            .map(|info| info.state != MemberState::Left)
            .unwrap_or(false)
    }

    /// Returns whether the given peer is an active (not left) member of our section.
    pub fn is_active(&self, pub_id: &PublicId) -> bool {
        self.members
            .get(pub_id.name())
            .map(|info| info.state != MemberState::Left)
            .unwrap_or(false)
    }

    /// Returns whether the given peer is mature (adult or elder)
    pub fn is_mature(&self, pub_id: &PublicId) -> bool {
        self.members
            .get(pub_id.name())
            .map(|info| info.is_mature())
            .unwrap_or(false)
    }

    /// Returns the age counters of all our members.
    pub fn get_age_counters(&self) -> BTreeMap<PublicId, AgeCounter> {
        self.members
            .values()
            .map(|member_info| (*member_info.p2p_node.public_id(), member_info.age_counter))
            .collect()
    }

    /// Adds a member to our section.
    pub fn add(&mut self, p2p_node: P2pNode, age: u8) {
        match self.members.entry(*p2p_node.name()) {
            Entry::Occupied(mut entry) => {
                if entry.get().state == MemberState::Left {
                    // Node rejoining
                    // TODO: To properly support rejoining, either keep the previous age or set the
                    // new age to max(old_age, new_age)
                    entry.get_mut().state = MemberState::Joined;
                    entry.get_mut().set_age(age);
                    entry.get_mut().section_version = self.version;

                    self.increment_version();
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

                let _ = entry.insert(MemberInfo::new(age, p2p_node.clone(), self.version));
                self.increment_version();
            }
        }
    }

    /// Remove a member from our section. Returns the SocketAddr and the state of the member before
    /// the removal.
    pub fn remove(&mut self, pub_id: &PublicId) -> (Option<SocketAddr>, MemberState) {
        if let Some(info) = self
            .members
            .get_mut(pub_id.name())
            // TODO: Probably should actually remove them
            .filter(|info| info.state != MemberState::Left)
        {
            let member_state = info.state;
            let member_addr = *info.p2p_node.peer_addr();

            info.state = MemberState::Left;
            self.increment_version();

            (Some(member_addr), member_state)
        } else {
            log_or_panic!(
                log::Level::Error,
                "Removing member that doesn't exist: {}",
                pub_id
            );

            (None, MemberState::Left)
        }
    }

    /// Remove all members whose name does not match our prefix and assigns them to
    /// `post_split_siblings`.
    pub fn remove_not_matching_our_prefix(&mut self, prefix: &Prefix<XorName>) {
        let (members, siblings) = mem::take(&mut self.members)
            .into_iter()
            .partition(|(name, _)| prefix.matches(name));
        self.members = members;
        self.post_split_siblings = siblings;
    }

    fn increment_version(&mut self) {
        self.version = self.version.wrapping_add(1);
    }
}

impl PartialEq for SectionMembers {
    fn eq(&self, other: &Self) -> bool {
        self.members == other.members && self.version == other.version
    }
}

// Returns the nodes that should become the next elders out of the given members.
fn elder_candidates<'a, I>(elder_size: usize, members: I) -> BTreeMap<XorName, P2pNode>
where
    I: IntoIterator<Item = &'a MemberInfo>,
{
    members
        .into_iter()
        .sorted_by(|info1, info2| cmp_elder_candidates(info1, info2))
        .into_iter()
        .map(|info| (*info.p2p_node.name(), info.p2p_node.clone()))
        .take(elder_size)
        .collect()
}

// Compare candidates for the next elders. The one comparing `Less` is more likely to become
// elder.
fn cmp_elder_candidates(lhs: &MemberInfo, rhs: &MemberInfo) -> Ordering {
    // Older nodes are preferred. In case of a tie, nodes joining earlier are preferred.
    rhs.age_counter
        .cmp(&lhs.age_counter)
        .then(lhs.section_version.cmp(&rhs.section_version))
}
