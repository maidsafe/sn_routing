// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    consensus::ProofSet,
    crypto::{self, Digest256},
    error::RoutingError,
    id::{P2pNode, PublicId},
    Prefix, XorName, QUORUM_DENOMINATOR, QUORUM_NUMERATOR,
};
use bincode::serialize;
use itertools::Itertools;
use serde::{de::Error as SerdeDeError, Deserialize, Deserializer, Serialize, Serializer};
use std::{
    collections::BTreeMap,
    fmt::{self, Debug, Formatter},
};

/// The information about all elders of a section at one point in time. Each elder is always a
/// member of exactly one current section, but a new `EldersInfo` is created whenever the elders
/// change, due to an elder being added or removed, or the section splitting or merging.
#[derive(Default, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct EldersInfo {
    /// The section's complete set of elders as a map from their name to a `P2pNode`.
    elders: BTreeMap<XorName, P2pNode>,
    /// The section version. This increases monotonically whenever the set of elders changes.
    /// Thus `EldersInfo`s with compatible prefixes always have different versions.
    version: u64,
    /// The section prefix. It matches all the members' names.
    prefix: Prefix<XorName>,
    /// The hash of the predecessor section, except if this is the network's genesis section.
    prev_hash: Option<Digest256>,
    /// The hash of the above fields. This is not serialized, and computed after deserialization.
    hash: Digest256,
}

impl Serialize for EldersInfo {
    fn serialize<S: Serializer>(&self, serialiser: S) -> Result<S::Ok, S::Error> {
        (&self.elders, self.version, &self.prefix, &self.prev_hash).serialize(serialiser)
    }
}

impl<'de> Deserialize<'de> for EldersInfo {
    fn deserialize<D: Deserializer<'de>>(deserialiser: D) -> Result<Self, D::Error> {
        let (members, version, prefix, prev_hash) = Deserialize::deserialize(deserialiser)?;
        Self::new_with_fields(members, version, prefix, prev_hash)
            .map_err(|err| D::Error::custom(format!("failed to construct elders info: {:?}", err)))
    }
}

impl EldersInfo {
    /// Creates a `SectionInfo` with the given members, prefix and predecessors.
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        members: BTreeMap<XorName, P2pNode>,
        prefix: Prefix<XorName>,
        prev: Option<&Self>,
    ) -> Result<Self, RoutingError> {
        let version = if let Some(prev) = prev {
            prev.version() + 1
        } else {
            0
        };

        Self::new_with_fields(members, version, prefix, prev.map(Self::hash).copied())
    }

    pub fn elder_map(&self) -> &BTreeMap<XorName, P2pNode> {
        &self.elders
    }

    pub fn contains_elder(&self, pub_id: &PublicId) -> bool {
        self.elders.contains_key(pub_id.name())
    }

    pub fn elder_nodes(&self) -> impl Iterator<Item = &P2pNode> + ExactSizeIterator {
        self.elders.values()
    }

    pub fn elder_ids(&self) -> impl Iterator<Item = &PublicId> {
        self.elders.values().map(P2pNode::public_id)
    }

    pub fn elder_names(&self) -> impl Iterator<Item = &XorName> {
        self.elders.values().map(P2pNode::name)
    }

    pub fn num_elders(&self) -> usize {
        self.elders.len()
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    pub fn prefix(&self) -> &Prefix<XorName> {
        &self.prefix
    }

    #[cfg(feature = "mock_base")]
    pub fn prev_hash(&self) -> Option<&Digest256> {
        self.prev_hash.as_ref()
    }

    pub fn hash(&self) -> &Digest256 {
        &self.hash
    }

    /// Returns `true` if the proofs are from a quorum of this section.
    pub fn is_quorum(&self, proofs: &ProofSet) -> bool {
        proofs.ids().filter(|id| self.contains_elder(id)).count() >= quorum_count(self.num_elders())
    }

    /// Returns `true` if the proofs are from all members of this section.
    pub fn is_total_consensus(&self, proofs: &ProofSet) -> bool {
        proofs.ids().filter(|id| self.contains_elder(id)).count() == self.num_elders()
    }

    /// Returns `true` if `self` is a successor of `other_info`, according to its hash.
    pub fn is_successor_of(&self, other_info: &Self) -> bool {
        self.prev_hash.as_ref() == Some(&other_info.hash)
    }

    /// Returns whether this `EldersInfo` is compatible and newer than the other.
    pub fn is_newer(&self, other: &Self) -> bool {
        self.prefix().is_compatible(other.prefix()) && self.version() > other.version()
    }

    #[cfg(any(test, feature = "mock_base"))]
    pub fn new_for_test(
        members: BTreeMap<PublicId, P2pNode>,
        prefix: Prefix<XorName>,
        version: u64,
    ) -> Result<Self, RoutingError> {
        let members = members
            .into_iter()
            .map(|(pub_id, node)| (*pub_id.name(), node))
            .collect();
        Self::new_with_fields(members, version, prefix, None)
    }

    /// Creates a new instance with the given fields, and computes its hash.
    fn new_with_fields(
        elders: BTreeMap<XorName, P2pNode>,
        version: u64,
        prefix: Prefix<XorName>,
        prev_hash: Option<Digest256>,
    ) -> Result<Self, RoutingError> {
        let hash = {
            let fields = (&elders, version, &prefix, &prev_hash);
            crypto::sha3_256(&serialize(&fields)?)
        };
        Ok(Self {
            elders,
            version,
            prefix,
            prev_hash,
            hash,
        })
    }
}

impl Debug for EldersInfo {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "EldersInfo {{ prefix: ({:b}), version: {}, members: {{{}}} }}",
            self.prefix,
            self.version,
            self.elder_nodes().format(", "),
        )
    }
}

/// Returns the number of vote for a quorum of this section such that:
/// quorum_count * QUORUM_DENOMINATOR > elder_size * QUORUM_NUMERATOR
#[inline]
pub const fn quorum_count(elder_size: usize) -> usize {
    1 + (elder_size * QUORUM_NUMERATOR) / QUORUM_DENOMINATOR
}

#[cfg(feature = "mock_base")]
/// Test helper to create arbitrary elders nfo.
pub fn elders_info_for_test(
    members: BTreeMap<PublicId, P2pNode>,
    prefix: Prefix<XorName>,
    version: u64,
) -> Result<EldersInfo, RoutingError> {
    EldersInfo::new_for_test(members, prefix, version)
}
