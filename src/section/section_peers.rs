// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::node_op::NodeOp;
use crate::agreement::SectionSigned;

use serde::{Deserialize, Serialize};
use std::{
    collections::{btree_map, BTreeMap},
    hash::{Hash, Hasher},
    mem,
};
use xor_name::{Prefix, XorName};

/// Container for storing information about members of our section.
#[derive(Clone, Default, Debug, Eq, Serialize, Deserialize)]
pub struct SectionPeers {
    members: BTreeMap<XorName, SectionSigned<NodeOp>>,
}

impl SectionPeers {
    /// Returns an iterator over all current node_ops.
    pub fn all(&self) -> impl Iterator<Item = &NodeOp> {
        self.members.values().map(|info| &info.value)
    }

    /// Returns an iterator over all current members.
    pub fn members(&self) -> impl Iterator<Item = &SectionSigned<NodeOp>> {
        self.members.values()
    }

    /// Get info for the member with the given name.
    pub fn get(&self, name: &XorName) -> Option<&NodeOp> {
        self.members.get(name).map(|info| &info.value)
    }

    /// Take info for the member with the given name.
    pub fn take(&mut self, name: &XorName) -> Option<SectionSigned<NodeOp>> {
        self.members.remove(name)
    }

    pub fn add(&mut self, op: SectionSigned<NodeOp>) {
        let _ = self.members.insert(*op.value.peer.name(), op);
    }

    /// Get proven info for the member with the given name.
    pub fn get_proven(&self, name: &XorName) -> Option<&SectionSigned<NodeOp>> {
        self.members.get(name)
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

pub struct IntoIter(btree_map::IntoIter<XorName, SectionSigned<NodeOp>>);

impl Iterator for IntoIter {
    type Item = SectionSigned<NodeOp>;

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

// // A peer is considered active if either it is joined or it is a current elder who is being
// // relocated. This is because such elder still fulfils its duties and only when demoted can it
// // leave.
// fn is_active(info: &NodeOp, current_elders: &SectionAuthorityProvider) -> bool {
//     match info.state {
//         PeerState::Joined => true,
//         PeerState::Relocated(_) if is_elder(info, current_elders) => true,
//         _ => false,
//     }
// }

// fn is_elder(info: &NodeOp, current_elders: &SectionAuthorityProvider) -> bool {
//     current_elders.contains_elder(info.peer.name())
// }
