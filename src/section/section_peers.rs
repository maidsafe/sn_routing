// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::SectionAuthorityProviderUtils;
use crate::{peer::PeerUtils, section::MemberInfoUtils};
use itertools::Itertools;
use sn_messaging::node::{
    MemberInfo, Peer, PeerState, Proven, SectionAuthorityProvider, SectionPeers,
};
use std::{
    cmp::Ordering,
    collections::btree_map::{self, Entry},
    mem,
};
use xor_name::{Prefix, XorName};

/// Container for storing information about members of our section.
pub trait SectionPeersUtils {
    /// Returns an iterator over all current (joined) and past (left) members.
    fn all(&self) -> Box<dyn Iterator<Item = &MemberInfo> + '_>;

    /// Returns an iterator over the members that have state == `Joined`.
    fn joined(&self) -> Box<dyn Iterator<Item = &MemberInfo> + '_>;

    /// Returns joined nodes from our section with age greater than `MIN_AGE`
    fn mature(&self) -> Box<dyn Iterator<Item = &Peer> + '_>;

    /// Get info for the member with the given name.
    fn get(&self, name: &XorName) -> Option<&MemberInfo>;

    /// Get proven info for the member with the given name.
    fn get_proven(&self, name: &XorName) -> Option<&Proven<MemberInfo>>;

    /// Returns the candidates for elders out of all the nodes in this section.
    fn elder_candidates(
        &self,
        elder_size: usize,
        current_elders: &SectionAuthorityProvider,
    ) -> Vec<Peer>;

    /// Returns the candidates for elders out of all nodes matching the prefix.
    fn elder_candidates_matching_prefix(
        &self,
        prefix: &Prefix,
        elder_size: usize,
        current_elders: &SectionAuthorityProvider,
    ) -> Vec<Peer>;

    /// Returns whether the given peer is a joined member of our section.
    fn is_joined(&self, name: &XorName) -> bool;

    /// Update a member of our section.
    /// Returns whether anything actually changed.
    fn update(&mut self, new_info: Proven<MemberInfo>) -> bool;

    /// Remove all members whose name does not match `prefix`.
    fn prune_not_matching(&mut self, prefix: &Prefix);
}

impl SectionPeersUtils for SectionPeers {
    /// Returns an iterator over all current (joined) and past (left) members.
    fn all(&self) -> Box<dyn Iterator<Item = &MemberInfo> + '_> {
        Box::new(self.members.values().map(|info| &info.value))
    }

    /// Returns an iterator over the members that have state == `Joined`.
    fn joined(&self) -> Box<dyn Iterator<Item = &MemberInfo> + '_> {
        Box::new(
            self.members
                .values()
                .map(|info| &info.value)
                .filter(|member| member.state == PeerState::Joined),
        )
    }

    /// Returns joined nodes from our section with age greater than `MIN_AGE`
    fn mature(&self) -> Box<dyn Iterator<Item = &Peer> + '_> {
        Box::new(
            self.joined()
                .filter(|info| info.is_mature())
                .map(|info| &info.peer),
        )
    }

    /// Get info for the member with the given name.
    fn get(&self, name: &XorName) -> Option<&MemberInfo> {
        self.members.get(name).map(|info| &info.value)
    }

    /// Get proven info for the member with the given name.
    fn get_proven(&self, name: &XorName) -> Option<&Proven<MemberInfo>> {
        self.members.get(name)
    }

    /// Returns the candidates for elders out of all the nodes in this section.
    fn elder_candidates(
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
    fn elder_candidates_matching_prefix(
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
    fn is_joined(&self, name: &XorName) -> bool {
        self.members
            .get(name)
            .map(|info| info.value.state == PeerState::Joined)
            .unwrap_or(false)
    }

    /// Update a member of our section.
    /// Returns whether anything actually changed.
    fn update(&mut self, new_info: Proven<MemberInfo>) -> bool {
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
    fn prune_not_matching(&mut self, prefix: &Prefix) {
        self.members = mem::take(&mut self.members)
            .into_iter()
            .filter(|(name, _)| prefix.matches(name))
            .collect();
    }
}

pub struct IntoIter(btree_map::IntoIter<XorName, Proven<MemberInfo>>);

impl Iterator for IntoIter {
    type Item = Proven<MemberInfo>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|(_, info)| info)
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
    current_elders.contains_elder(info.peer.name())
}
