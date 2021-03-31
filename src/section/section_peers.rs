// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    member_info::{MemberInfo, PeerState},
    SectionAuthorityProvider,
};
use crate::{agreement::Proven, peer::Peer};

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

    /// Get proven info for the member with the given name.
    pub fn get_proven(&self, name: &XorName) -> Option<&Proven<MemberInfo>> {
        self.members.get(name)
    }

    /// Returns the candidates for elders out of all the nodes in this section.
    pub fn elder_candidates(
        &self,
        elder_size: usize,
        current_elders: &SectionAuthorityProvider,
    ) -> Vec<Peer> {
        elder_candidates(
            elder_size,
            current_elders,
            self.members
                .values()
                .filter(|info| is_active(&info.value, current_elders))
                .filter(|info| info.value.peer.is_reachable()),
        )
    }

    /// Returns the candidates for elders out of all nodes matching the prefix.
    pub fn elder_candidates_matching_prefix(
        &self,
        prefix: &Prefix,
        elder_size: usize,
        current_elders: &SectionAuthorityProvider,
    ) -> Vec<Peer> {
        elder_candidates(
            elder_size,
            current_elders,
            self.members.values().filter(|info| {
                info.value.state == PeerState::Joined
                    && prefix.matches(info.value.peer.name())
                    && info.value.peer.is_reachable()
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
// It is assumed that `members` contains only "active" peers (see the `is_active` function below
// for explanation)
fn elder_candidates<'a, I>(
    elder_size: usize,
    current_elders: &SectionAuthorityProvider,
    members: I,
) -> Vec<Peer>
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

// Compare candidates for the next elders. The one comparing `Less` wins.
fn cmp_elder_candidates(
    lhs: &Proven<MemberInfo>,
    rhs: &Proven<MemberInfo>,
    current_elders: &SectionAuthorityProvider,
) -> Ordering {
    // Older nodes are preferred. In case of a tie, prefer current elders. If still a tie, break
    // it comparing by the proof signatures because it's impossible for a node to predict its
    // signature and therefore game its chances of promotion.
    cmp_elder_candidates_by_peer_state(&lhs.value.state, &rhs.value.state)
        .then_with(|| rhs.value.peer.age().cmp(&lhs.value.peer.age()))
        .then_with(|| {
            let lhs_is_elder = is_elder(&lhs.value, current_elders);
            let rhs_is_elder = is_elder(&rhs.value, current_elders);

            match (lhs_is_elder, rhs_is_elder) {
                (true, false) => Ordering::Less,
                (false, true) => Ordering::Greater,
                _ => Ordering::Equal,
            }
        })
        .then_with(|| lhs.proof.signature.cmp(&rhs.proof.signature))
}

// Compare candidates for the next elders according to their peer state. The one comparing `Less`
// wins. `Joined` is preferred over `Relocated` which is preferred over `Left`.
// NOTE: we only consider `Relocated` peers as elder candidates if we don't have enough `Joined`
// members to reach `ELDER_SIZE`.
fn cmp_elder_candidates_by_peer_state(lhs: &PeerState, rhs: &PeerState) -> Ordering {
    use PeerState::*;

    match (lhs, rhs) {
        (Joined, Joined) | (Relocated(_), Relocated(_)) => Ordering::Equal,
        (Joined, Relocated(_)) | (_, Left) => Ordering::Less,
        (Relocated(_), Joined) | (Left, _) => Ordering::Greater,
    }
}

// A peer is considered active if either it is joined or it is a current elder who is being
// relocated. This is because such elder still fulfils its duties and only when demoted can it
// leave.
fn is_active(info: &MemberInfo, current_elders: &SectionAuthorityProvider) -> bool {
    match info.state {
        PeerState::Joined => true,
        PeerState::Relocated(_) if is_elder(info, current_elders) => true,
        _ => false,
    }
}

fn is_elder(info: &MemberInfo, current_elders: &SectionAuthorityProvider) -> bool {
    current_elders.elders.contains_key(info.peer.name())
}
