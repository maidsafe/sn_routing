// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::Prefix;
use crate::xor_name::{XorName, Xorable};
use std::fmt::{self, Binary, Debug, Display, Formatter};

/// An entity that can act as a source or destination of a message.
///
/// `Client` and `ManagedNode` are single-node authorities (i.e. no verification of messages from
/// additional sources needed); other authorities require agreement by a quorum of some set.
/// `NodeManager`, `ClientManager` and `NaeManager` use _group_ verification of messages: they
/// require quorum agreement from the group of nodes closest to the source, while `Section` and
/// `PrefixSection` use _section_ verification: the set from which a quorum is required is all
/// members of the section (`Section`) or of all sections matching the prefix (`PrefixSection`).
#[derive(Serialize, Deserialize, PartialEq, PartialOrd, Eq, Ord, Clone, Copy, Hash)]
#[allow(clippy::large_enum_variant)]
pub enum Authority<N: Xorable + Clone + Copy + Binary + Default> {
    /// A single section whose prefix matches the given name
    Section(N),
    /// A set of nodes with names sharing a common prefix - may span multiple `Section`s present in
    /// the routing table or only a part of a `Section`
    PrefixSection(Prefix<N>),
    /// A single node
    Node(N),
}

impl<N: Xorable + Clone + Copy + Binary + Default> Authority<N> {
    /// Returns `true` if the authority consists of multiple nodes, otherwise `false`.
    pub fn is_multiple(&self) -> bool {
        match self {
            Authority::Section(_) | Authority::PrefixSection(_) => true,
            Authority::Node(_) => false,
        }
    }

    /// Returns `true` if the authority is a single node, and `false` otherwise.
    pub fn is_single(&self) -> bool {
        match self {
            Authority::Section(_) | Authority::PrefixSection(_) => false,
            Authority::Node(_) => true,
        }
    }

    /// Returns the name of authority.
    pub fn name(&self) -> N {
        match self {
            Authority::Section(name) | Authority::Node(name) => *name,
            Authority::PrefixSection(prefix) => prefix.lower_bound(),
        }
    }

    /// Returns if the authority is compatible with that prefix
    pub fn is_compatible(&self, other_prefix: &Prefix<N>) -> bool {
        match self {
            Authority::Section(name) | Authority::Node(name) => other_prefix.matches(name),
            Authority::PrefixSection(prefix) => other_prefix.is_compatible(prefix),
        }
    }
}

impl Authority<XorName> {
    /// provide the name mathching a single node's public key
    pub fn single_signing_name(&self) -> Option<&XorName> {
        match *self {
            Authority::Section(_) | Authority::PrefixSection(_) => None,
            Authority::Node(ref name) => Some(name),
        }
    }
}

impl<N: Xorable + Clone + Copy + Binary + Default + Display> Debug for Authority<N> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match *self {
            Authority::Section(ref name) => write!(formatter, "Section(name: {})", name),
            Authority::PrefixSection(ref prefix) => {
                write!(formatter, "PrefixSection(prefix: {:?})", prefix)
            }
            Authority::Node(ref name) => write!(formatter, "Node(name: {})", name),
        }
    }
}
