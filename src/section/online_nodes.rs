// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    node_op::{NodeOp, PeerState},
    section_peers::SectionPeers,
    SectionAuthorityProvider,
};
use crate::{agreement::SectionSigned, peer::Peer};

use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use xor_name::{Prefix, XorName};

/// Container for storing information about members of our section.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct OnlineNodes {
    section_auth: SectionSigned<SectionAuthorityProvider>,
    // Any online node not in SAP is an Adult
    pub(crate) online_nodes: SectionPeers,
}

impl OnlineNodes {
    /// Construtor
    pub fn new(section_auth: SectionSigned<SectionAuthorityProvider>) -> Self {
        OnlineNodes {
            section_auth,
            online_nodes: SectionPeers::default(),
        }
    }

    pub fn section_auth(&self) -> &SectionSigned<SectionAuthorityProvider> {
        &self.section_auth
    }

    pub fn set_section_auth(&mut self, section_auth: &SectionSigned<SectionAuthorityProvider>) {
        self.section_auth = section_auth.clone();
    }

    /// Returns an iterator of Ops over current online_nodes.
    pub fn all(&self) -> impl Iterator<Item = &NodeOp> {
        self.online_nodes.all()
    }

    /// Returns an iterator of SectionSigned<NodeOp> over current online_nodes.
    pub fn members(&self) -> impl Iterator<Item = &SectionSigned<NodeOp>> {
        self.online_nodes.members()
    }

    pub fn peers(&self) -> &SectionPeers {
        &self.online_nodes
    }

    /// Returns adults
    pub fn adults(&self) -> impl Iterator<Item = &Peer> {
        self.all()
            .filter(move |op| !self.section_auth.value.contains_elder(op.peer.name()))
            .map(|op| &op.peer)
    }

    /// Take info for the member with the given name.
    pub fn take(&mut self, name: &XorName) -> Option<SectionSigned<NodeOp>> {
        self.online_nodes.take(name)
    }

    pub fn add(&mut self, op: SectionSigned<NodeOp>) {
        self.online_nodes.add(op);
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
            self.online_nodes
                .members()
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
            self.online_nodes.members().filter(|info| {
                info.value.state == PeerState::Joined
                    && prefix.matches(info.value.peer.name())
                    && info.value.peer.is_reachable()
            }),
        )
    }

    /// Remove all members whose name does not match `prefix`.
    pub fn prune_not_matching(&mut self, prefix: &Prefix) {
        self.online_nodes.prune_not_matching(prefix)
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
    I: IntoIterator<Item = &'a SectionSigned<NodeOp>>,
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
    lhs: &SectionSigned<NodeOp>,
    rhs: &SectionSigned<NodeOp>,
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

fn is_elder(info: &NodeOp, current_elders: &SectionAuthorityProvider) -> bool {
    current_elders.contains_elder(info.peer.name())
}
