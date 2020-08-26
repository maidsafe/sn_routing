// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#[cfg(test)]
use crate::{id::FullId, rng::MainRng};
use crate::{
    id::{P2pNode, PublicId},
    Prefix, XorName,
};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::{
    borrow::Borrow,
    collections::BTreeMap,
    fmt::{self, Debug, Formatter},
};

/// The information about all elders of a section at one point in time. Each elder is always a
/// member of exactly one current section, but a new `EldersInfo` is created whenever the elders
/// change, due to an elder being added or removed, or the section splitting or merging.
#[derive(Default, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Serialize, Deserialize)]
pub struct EldersInfo {
    /// The section's complete set of elders as a map from their name to a `P2pNode`.
    pub elders: BTreeMap<XorName, P2pNode>,
    /// The section prefix. It matches all the members' names.
    pub prefix: Prefix,
}

impl EldersInfo {
    /// Creates a new `EldersInfo` with the given members, prefix and version.
    pub fn new(elders: BTreeMap<XorName, P2pNode>, prefix: Prefix) -> Self {
        Self { elders, prefix }
    }

    pub(crate) fn elder_ids(&self) -> impl Iterator<Item = &PublicId> {
        self.elders.values().map(P2pNode::public_id)
    }

    /// Returns the index of the elder with `name` in this set of elders.
    /// This is useful for BLS signatures where the signature share needs to be mapped to a
    /// "field element" which is typically a numeric index.
    pub(crate) fn position(&self, name: &XorName) -> Option<usize> {
        self.elders.keys().position(|other_name| other_name == name)
    }
}

impl Borrow<Prefix> for EldersInfo {
    fn borrow(&self) -> &Prefix {
        &self.prefix
    }
}

impl Debug for EldersInfo {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "EldersInfo {{ prefix: ({:b}), elders: {{{}}} }}",
            self.prefix,
            self.elders.values().format(", "),
        )
    }
}

/// Returns the number of vote for a quorum of this section such that:
/// quorum_count * QUORUM_DENOMINATOR > elder_size * QUORUM_NUMERATOR
#[cfg(feature = "mock")]
#[inline]
pub const fn quorum_count(elder_size: usize) -> usize {
    use crate::{QUORUM_DENOMINATOR, QUORUM_NUMERATOR};

    1 + (elder_size * QUORUM_NUMERATOR) / QUORUM_DENOMINATOR
}

// Generate random `EldersInfo` for testing purposes.
#[cfg(test)]
pub(crate) fn gen_elders_info(
    rng: &mut MainRng,
    prefix: Prefix,
    count: usize,
) -> (EldersInfo, Vec<FullId>) {
    use rand::Rng;
    use std::net::SocketAddr;

    fn gen_socket_addr(rng: &mut MainRng) -> SocketAddr {
        let ip: [u8; 4] = rng.gen();
        let port: u16 = rng.gen();
        SocketAddr::from((ip, port))
    }

    let mut full_ids: Vec<_> = (0..count).map(|_| FullId::gen(rng)).collect();
    // Clippy false positive - https://github.com/rust-lang/rust-clippy/issues/5754
    // (note the issue is closed, but it probably hasn't been merged into stable yet)
    #[allow(clippy::unnecessary_sort_by)]
    full_ids.sort_by(|lhs, rhs| lhs.public_id().name().cmp(rhs.public_id().name()));

    let elders = full_ids
        .iter()
        .map(|full_id| {
            let addr = gen_socket_addr(rng);
            let p2p_node = P2pNode::new(*full_id.public_id(), addr);
            (*p2p_node.public_id().name(), p2p_node)
        })
        .collect();

    (EldersInfo::new(elders, prefix), full_ids)
}
