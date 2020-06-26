// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    id::{P2pNode, PublicId},
    Prefix, XorName, QUORUM_DENOMINATOR, QUORUM_NUMERATOR,
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

    /// Returns `true` if the proofs are from a quorum of this section.
    pub(crate) fn is_quorum<'a, I>(&self, names: I) -> bool
    where
        I: IntoIterator<Item = &'a XorName>,
    {
        names
            .into_iter()
            .filter(|name| self.elders.contains_key(name))
            .count()
            >= quorum_count(self.elders.len())
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
#[inline]
pub const fn quorum_count(elder_size: usize) -> usize {
    1 + (elder_size * QUORUM_NUMERATOR) / QUORUM_DENOMINATOR
}
