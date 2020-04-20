// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    chain::{AgeCounter, EldersInfo, MemberInfo, MemberState, MIN_AGE_COUNTER},
    id::{P2pNode, PublicId},
    xor_space::{Prefix, XorName},
};
use std::{
    collections::{btree_map::Entry, BTreeMap},
    mem,
    net::SocketAddr,
};

/// Container for storing information about members of our section.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SectionMembers {
    members: BTreeMap<XorName, MemberInfo>,
    // Number that gets incremented every time a node joins or leaves our section - that is, every
    // time `members` changes.
    section_version: u64,
}

impl SectionMembers {
    /// Constructs the container initially with the section elders.
    pub fn new(elders_info: &EldersInfo, ages: &BTreeMap<PublicId, AgeCounter>) -> Self {
        let members = elders_info
            .member_nodes()
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
            section_version: 0,
        }
    }

    /// Returns an iterator over the members that have not state == `Left`.
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
        self.members.get(name).map(|info| &info.p2p_node)
    }

    /// Check if the given `PublicId` is a member of our section.
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
                    entry.get_mut().section_version = self.section_version;

                    self.increment_section_version();
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

                let _ = entry.insert(MemberInfo::new(age, p2p_node.clone(), self.section_version));
                self.increment_section_version();
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
            self.increment_section_version();

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

    /// Remove all members whose name does not match our prefix and returns them.
    pub fn remove_not_matching_prefix(
        &mut self,
        prefix: &Prefix<XorName>,
    ) -> BTreeMap<XorName, MemberInfo> {
        let (members, others) = mem::take(&mut self.members)
            .into_iter()
            .partition(|(name, _)| prefix.matches(name));
        self.members = members;
        others
    }

    fn increment_section_version(&mut self) {
        self.section_version = self.section_version.wrapping_add(1);
    }
}
