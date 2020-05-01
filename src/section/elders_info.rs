// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    consensus::ProofSet,
    id::{P2pNode, PublicId},
    Prefix, XorName, QUORUM_DENOMINATOR, QUORUM_NUMERATOR,
};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::{
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
    /// The section version. This increases monotonically whenever the set of elders changes.
    /// Thus `EldersInfo`s with compatible prefixes always have different versions.
    pub version: u64,
    /// The section prefix. It matches all the members' names.
    pub prefix: Prefix<XorName>,
}

impl EldersInfo {
    /// Creates a new `EldersInfo` with the given members, prefix and version.
    pub fn new(elders: BTreeMap<XorName, P2pNode>, prefix: Prefix<XorName>, version: u64) -> Self {
        Self {
            elders,
            version,
            prefix,
        }
    }

    pub(crate) fn elder_ids(&self) -> impl Iterator<Item = &PublicId> {
        self.elders.values().map(P2pNode::public_id)
    }

    /// Returns `true` if the proofs are from a quorum of this section.
    pub(crate) fn is_quorum(&self, proofs: &ProofSet) -> bool {
        proofs
            .ids()
            .filter(|id| self.elders.contains_key(id.name()))
            .count()
            >= quorum_count(self.elders.len())
    }

    /// Returns `true` if the proofs are from all members of this section.
    pub(crate) fn is_total_consensus(&self, proofs: &ProofSet) -> bool {
        proofs
            .ids()
            .filter(|id| self.elders.contains_key(id.name()))
            .count()
            == self.elders.len()
    }

    /// Returns whether this `EldersInfo` is compatible and newer than the other.
    pub(crate) fn is_newer(&self, other: &Self) -> bool {
        self.prefix.is_compatible(&other.prefix) && self.version > other.version
    }
}

impl Debug for EldersInfo {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "EldersInfo {{ prefix: ({:b}), version: {}, elders: {{{}}} }}",
            self.prefix,
            self.version,
            self.elders.values().format(", "),
        )
    }
}

/// Returns the number of vote for a quorum of this section such that:
/// quorum_count * QUORUM_DENOMINATOR > elder_size * QUORUM_NUMERATOR
#[inline]
pub const fn quorum_count(elder_size: usize) -> usize {
    1 + (elder_size * QUORUM_NUMERATOR) / QUORUM_DENOMINATOR
}
