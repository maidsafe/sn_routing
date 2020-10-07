// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    member_info::{MemberInfo, PeerState},
    section_proof_chain::SectionProofChain,
    EldersInfo,
};
use crate::{
    consensus::{Proof, Proven},
    peer::Peer,
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
pub struct SectionPeers {
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

    /// Returns an iterator over the members that have state == `Joined` together with their proofs.
    pub fn joined_proven(&self) -> impl Iterator<Item = &Proven<MemberInfo>> {
        self.members
            .values()
            .filter(|member| member.value.state == PeerState::Joined)
    }

    /// Returns nodes from our section with age greater than `MIN_AGE`
    pub fn adults(&self) -> impl Iterator<Item = &Peer> {
        self.joined()
            .filter(|info| info.is_adult())
            .map(|info| &info.peer)
    }

    /// Get info for the member with the given name.
    pub fn get(&self, name: &XorName) -> Option<&MemberInfo> {
        self.members.get(name).map(|info| &info.value)
    }

    /// Returns the candidates for elders out of all the nodes in this section.
    pub fn elder_candidates(
        &self,
        elder_size: usize,
        current_elders: &EldersInfo,
    ) -> BTreeMap<XorName, Peer> {
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
    ) -> BTreeMap<XorName, Peer> {
        elder_candidates(
            elder_size,
            current_elders,
            self.members.values().filter(|info| {
                info.value.state == PeerState::Joined && prefix.matches(info.value.peer.name())
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
            .map(|info| info.value.state == PeerState::Joined)
            .unwrap_or(false)
    }

    /// Returns whether the given peer has age > MIN_AGE.
    pub fn is_adult(&self, name: &XorName) -> bool {
        self.members
            .get(name)
            .map(|info| info.value.is_adult())
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
        match self.members.entry(*new_info.peer.name()) {
            Entry::Vacant(entry) => {
                let new_info = Proven::new(new_info, proof);
                if new_info.verify(section_chain) {
                    let _ = entry.insert(new_info);
                    true
                } else {
                    false
                }
            }
            Entry::Occupied(mut entry) => {
                // To maintain commutativity, the only allowed transitions are:
                // - Joined -> Joined if the new age is greater than the old age
                // - Joined -> Left
                // - Joined -> Relocated
                // - Relocated -> Left (should not happen, but needed for consistency)
                match (entry.get().value.state, new_info.state) {
                    (PeerState::Joined, PeerState::Joined)
                        if new_info.peer.age() > entry.get().value.peer.age() => {}
                    (PeerState::Joined, PeerState::Left)
                    | (PeerState::Joined, PeerState::Relocated(_))
                    | (PeerState::Relocated(_), PeerState::Left) => {}
                    _ => return false,
                };

                let new_info = Proven::new(new_info, proof);
                if new_info.verify(section_chain) {
                    let _ = entry.insert(new_info);
                    true
                } else {
                    false
                }
            }
        }
    }

    /// Remove all members whose name does not match our prefix.
    pub fn remove_not_matching_our_prefix(&mut self, prefix: &Prefix) {
        self.members = mem::take(&mut self.members)
            .into_iter()
            .filter(|(name, _)| prefix.matches(name))
            .collect();
    }

    /// Merge two `SectionPeers` into one.
    pub fn merge(&mut self, other: Self, section_chain: &SectionProofChain) {
        for (_, info) in other.members {
            let _ = self.update(info.value, info.proof, section_chain);
        }
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

// Returns the nodes that should become the next elders out of the given members.
fn elder_candidates<'a, I>(
    elder_size: usize,
    current_elders: &EldersInfo,
    members: I,
) -> BTreeMap<XorName, Peer>
where
    I: IntoIterator<Item = &'a Proven<MemberInfo>>,
{
    members
        .into_iter()
        .sorted_by(|lhs, rhs| cmp_elder_candidates(lhs, rhs, current_elders))
        .map(|info| (*info.value.peer.name(), info.value.peer))
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
