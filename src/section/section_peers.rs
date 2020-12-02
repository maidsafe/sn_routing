// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    member_info::{MemberInfo, PeerState},
    EldersInfo,
};
use crate::{consensus::Proven, peer::Peer};

use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::{
    cmp::Ordering,
    collections::{
        btree_map::{self, Entry},
        BTreeMap,
    },
    hash::{Hash, Hasher},
    mem,
};
use xor_name::{Prefix, XorName};

/// Container for storing information about members of our section.
#[derive(Clone, Default, Debug, Eq, Serialize, Deserialize)]
pub(crate) struct SectionPeers {
    members: BTreeMap<XorName, Proven<MemberInfo>>,
}

impl SectionPeers {
    /// Returns an iterator over all current (joined) and past (left) members.
    pub fn all(&self) -> impl Iterator<Item = &MemberInfo> {
        self.members.values().map(|info| &info.value)
    }

    /// Returns an iterator over the members that have state == `Joined`.
    pub fn joined(&self) -> impl Iterator<Item = &MemberInfo> {
        self.members
            .values()
            .map(|info| &info.value)
            .filter(|member| member.state == PeerState::Joined)
    }

    /// Returns joined nodes from our section with age greater than `MIN_AGE`
    pub fn mature(&self) -> impl Iterator<Item = &Peer> {
        self.joined()
            .filter(|info| info.is_mature())
            .map(|info| &info.peer)
    }

    /// Get info for the member with the given name.
    pub fn get(&self, name: &XorName) -> Option<&MemberInfo> {
        self.members.get(name).map(|info| &info.value)
    }

    /// Returns the candidates for elders out of all the nodes in this section.
    pub fn elder_candidates(&self, elder_size: usize, current_elders: &EldersInfo) -> Vec<Peer> {
        elder_candidates(
            elder_size,
            current_elders,
            self.members
                .values()
                .filter(|info| info.value.state == PeerState::Joined),
        )
    }

    /// Returns the candidates for elders out of all nodes matching the prefix.
    pub fn elder_candidates_matching_prefix(
        &self,
        prefix: &Prefix,
        elder_size: usize,
        current_elders: &EldersInfo,
    ) -> Vec<Peer> {
        elder_candidates(
            elder_size,
            current_elders,
            self.members.values().filter(|info| {
                info.value.state == PeerState::Joined && prefix.matches(info.value.peer.name())
            }),
        )
    }

    /// Returns whether the given peer is a joined member of our section.
    pub fn is_joined(&self, name: &XorName) -> bool {
        self.members
            .get(name)
            .map(|info| info.value.state == PeerState::Joined)
            .unwrap_or(false)
    }

    /// Returns whether the given peer is known to us (joined or left)
    pub fn is_known(&self, name: &XorName) -> bool {
        self.members.contains_key(name)
    }

    /// Update a member of our section.
    /// Returns whether anything actually changed.
    pub fn update(&mut self, new_info: Proven<MemberInfo>) -> bool {
        match self.members.entry(*new_info.value.peer.name()) {
            Entry::Vacant(entry) => {
                let _ = entry.insert(new_info);
                true
            }
            Entry::Occupied(mut entry) => {
                // To maintain commutativity, the only allowed transitions are:
                // - Joined -> Joined if the new age is greater than the old age
                // - Joined -> Left
                // - Joined -> Relocated
                // - Relocated -> Left (should not happen, but needed for consistency)
                match (entry.get().value.state, new_info.value.state) {
                    (PeerState::Joined, PeerState::Joined)
                        if new_info.value.peer.age() > entry.get().value.peer.age() => {}
                    (PeerState::Joined, PeerState::Left)
                    | (PeerState::Joined, PeerState::Relocated(_))
                    | (PeerState::Relocated(_), PeerState::Left) => {}
                    _ => return false,
                };

                let _ = entry.insert(new_info);
                true
            }
        }
    }

    /// Remove all members whose name does not match `prefix`.
    pub fn prune_not_matching(&mut self, prefix: &Prefix) {
        self.members = mem::take(&mut self.members)
            .into_iter()
            .filter(|(name, _)| prefix.matches(name))
            .collect();
    }
}

impl PartialEq for SectionPeers {
    fn eq(&self, other: &Self) -> bool {
        self.members == other.members
    }
}

impl Hash for SectionPeers {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.members.hash(state)
    }
}

pub struct IntoIter(btree_map::IntoIter<XorName, Proven<MemberInfo>>);

impl Iterator for IntoIter {
    type Item = Proven<MemberInfo>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|(_, info)| info)
    }
}

impl IntoIterator for SectionPeers {
    type IntoIter = IntoIter;
    type Item = <Self::IntoIter as Iterator>::Item;

    fn into_iter(self) -> Self::IntoIter {
        IntoIter(self.members.into_iter())
    }
}

// Returns the nodes that should become the next elders out of the given members, sorted by names.
fn elder_candidates<'a, I>(elder_size: usize, current_elders: &EldersInfo, members: I) -> Vec<Peer>
where
    I: IntoIterator<Item = &'a Proven<MemberInfo>>,
{
    members
        .into_iter()
        .sorted_by(|lhs, rhs| cmp_elder_candidates(lhs, rhs, current_elders))
        .map(|info| info.value.peer)
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
        .peer
        .age()
        .cmp(&lhs.value.peer.age())
        .then_with(|| {
            let lhs_is_elder = current_elders.elders.contains_key(lhs.value.peer.name());
            let rhs_is_elder = current_elders.elders.contains_key(rhs.value.peer.name());

            match (lhs_is_elder, rhs_is_elder) {
                (true, false) => Ordering::Less,
                (false, true) => Ordering::Greater,
                _ => Ordering::Equal,
            }
        })
        .then_with(|| lhs.proof.signature.cmp(&rhs.proof.signature))
}
