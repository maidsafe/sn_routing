// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use super::{NetworkEvent, ProofSet};
use crate::error::RoutingError;
use crate::id::PublicId;
use crate::parsec;
use crate::routing_table::Prefix;
use crate::sha3::Digest256;
use crate::XorName;
use crate::{QUORUM_DENOMINATOR, QUORUM_NUMERATOR};
use maidsafe_utilities::serialisation;
use safe_crypto;
use serde::de::Error as SerdeDeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::cmp;
use std::collections::BTreeSet;
use std::fmt::{self, Debug, Display, Formatter};

/// The configuration of a section at one point in time. Each node is always a member of exactly
/// one current section, but a new `SectionInfo` is created whenever the section changes, due to a
/// node being added or removed, or the section splitting or merging.
#[derive(Default, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct SectionInfo {
    /// The complete list of the section's members' IDs.
    members: BTreeSet<PublicId>,
    /// The section version. This increases monotonically whenever the section changes.
    /// Thus `SectionInfo`s with compatible prefixes always have different versions.
    version: u64,
    /// The section prefix. It matches all the members' names.
    prefix: Prefix<XorName>,
    /// The predecessor sections' hashes. This has exactly one entry, except that it is empty for
    /// the network's genesis section, and contains both halves after a merge.
    prev_hash: BTreeSet<Digest256>,
    /// The hash of the above fields. This is not serialized, and computed after deserialization.
    hash: Digest256,
}

impl Serialize for SectionInfo {
    fn serialize<S: Serializer>(&self, serialiser: S) -> Result<S::Ok, S::Error> {
        (&self.members, self.version, &self.prefix, &self.prev_hash).serialize(serialiser)
    }
}

impl<'de> Deserialize<'de> for SectionInfo {
    fn deserialize<D: Deserializer<'de>>(deserialiser: D) -> Result<Self, D::Error> {
        let (members, version, prefix, prev_hash): (
            BTreeSet<PublicId>,
            u64,
            Prefix<XorName>,
            BTreeSet<Digest256>,
        ) = Deserialize::deserialize(deserialiser)?;
        Self::new_with_fields(members, version, prefix, prev_hash)
            .map_err(|err| D::Error::custom(format!("failed to construct section info: {:?}", err)))
    }
}

impl SectionInfo {
    /// Creates a `SectionInfo` with the given members, prefix and predecessors.
    #[allow(clippy::new_ret_no_self)]
    pub fn new<'a, I: IntoIterator<Item = &'a SectionInfo>>(
        members: BTreeSet<PublicId>,
        prefix: Prefix<XorName>,
        prev: I,
    ) -> Result<Self, RoutingError> {
        let mut version = 0;
        let mut prev_hash = BTreeSet::new();
        for prev_info in prev {
            version = cmp::max(version, prev_info.version() + 1);
            let _ = prev_hash.insert(prev_info.hash);
        }
        Self::new_with_fields(members, version, prefix, prev_hash)
    }

    /// Creates a new `SectionInfo` by merging this and the other one.
    pub fn merge(&self, other: &SectionInfo) -> Result<Self, RoutingError> {
        let members = self.members.iter().chain(&other.members).cloned().collect();
        Self::new(members, self.prefix.popped(), vec![self, other])
    }

    pub fn members(&self) -> &BTreeSet<PublicId> {
        &self.members
    }

    pub fn member_names(&self) -> BTreeSet<XorName> {
        self.members.iter().map(PublicId::name).cloned().collect()
    }

    pub fn version(&self) -> &u64 {
        &self.version
    }

    pub fn prefix(&self) -> &Prefix<XorName> {
        &self.prefix
    }

    pub fn prev_hash(&self) -> &BTreeSet<Digest256> {
        &self.prev_hash
    }

    pub fn hash(&self) -> &Digest256 {
        &self.hash
    }

    /// Returns `true` if the proofs are from a quorum of this section.
    pub fn is_quorum(&self, proofs: &ProofSet) -> bool {
        proofs.ids().filter(|id| self.members.contains(id)).count() * QUORUM_DENOMINATOR
            > self.members.len() * QUORUM_NUMERATOR
    }

    /// Returns `true` if `self` is a successor of `other_info`, according to its hash.
    pub fn is_successor_of(&self, other_info: &SectionInfo) -> bool {
        self.prev_hash.contains(&other_info.hash)
    }

    /// Returns `true` if the `proofs` are a quorum of `self` and valid signatures of
    /// `other_event`.
    pub fn proves(&self, other_info: &SectionInfo, proofs: &ProofSet) -> bool {
        let other_event: parsec::Observation<NetworkEvent, PublicId> =
            parsec::Observation::OpaquePayload(NetworkEvent::SectionInfo(other_info.clone()));
        self.is_quorum(proofs) && proofs.validate_signatures(&other_event)
    }

    /// Returns `true` if the `proofs` are a quorum of `self` and valid signatures of
    /// `other_event`, and if `other_info` is a valid successor of `self`.
    pub fn proves_successor(&self, other_info: &SectionInfo, proofs: &ProofSet) -> bool {
        other_info.is_successor_of(self) && self.proves(other_info, proofs)
    }

    /// To NetworkEvent::SectionInfo event
    pub fn into_network_event(self) -> NetworkEvent {
        NetworkEvent::SectionInfo(self)
    }

    /// Creates a new instance with the given fields, and computes its hash.
    fn new_with_fields(
        members: BTreeSet<PublicId>,
        version: u64,
        prefix: Prefix<XorName>,
        prev_hash: BTreeSet<Digest256>,
    ) -> Result<Self, RoutingError> {
        let hash = {
            let fields = (&members, version, &prefix, &prev_hash);
            safe_crypto::hash(&serialisation::serialise(&fields)?)
        };
        Ok(SectionInfo {
            members,
            version,
            prefix,
            prev_hash,
            hash,
        })
    }
}

impl Debug for SectionInfo {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "SectionInfo(prefix: {:?}, members: {:?}, prev_hash_len: {}, version: {})",
            self.prefix,
            self.members,
            self.prev_hash.len(),
            self.version
        )
    }
}

impl Display for SectionInfo {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        writeln!(formatter, "SectionInfo {{")?;
        writeln!(formatter, "\t\tprefix: {:?},", self.prefix)?;
        writeln!(formatter, "\t\tversion: {:?},", self.version)?;
        writeln!(formatter, "\t\tprev_hash_len: {},", self.prev_hash.len())?;
        write!(formatter, "\t\tmembers: [")?;
        for (index, member) in self.members.iter().enumerate() {
            let comma = if index == self.members.len() - 1 {
                ""
            } else {
                ","
            };
            write!(formatter, " {}{}", member.name(), comma)?;
        }
        writeln!(formatter, " ]")?;
        writeln!(formatter, "\t}}")
    }
}
