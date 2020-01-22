// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::xor_space::{Prefix, XorName};
use std::fmt::{self, Debug, Formatter};

/// A `Location` is a source or destination of a message.
///
/// `Node` is single-node location (i.e. no verification of messages from
/// additional sources needed). It's name is the `Authority::key` other
/// locations require agreement by a quorum of `Elders`.
// FIXME (di) - This should be `Src` and `Dst` types where `Src` can be prefix or node and dst can be
// section or node and no more. Dst section cannot fail, dst node cna fail.
// src node canot fail, src prefix can fail and we return last known key in that case. The sender
// must then give us a new chain to prove the message.
// src::prefix MUST BE SIGNED BY BLS all others ed25519
#[derive(Serialize, Deserialize, PartialEq, PartialOrd, Eq, Ord, Clone, Copy, Hash)]
pub enum Location {
    /// A single section whose prefix matches the given name
    Section(XorName),
    /// A set of nodes with names sharing a common prefix - may span multiple `Section`s present in
    /// the routing table or only a part of a `Section`
    PrefixSection(Prefix<XorName>),
    /// A single node
    Node(XorName),
}

impl Location {
    /// Returns `true` if the location consists of multiple nodes, otherwise `false`.
    pub fn is_multiple(&self) -> bool {
        match self {
            Self::Section(_) | Self::PrefixSection(_) => true,
            Self::Node(_) => false,
        }
    }

    /// Returns `true` if the location is a single node, and `false` otherwise.
    pub fn is_single(&self) -> bool {
        match self {
            Self::Section(_) | Self::PrefixSection(_) => false,
            Self::Node(_) => true,
        }
    }

    /// Returns the name of location.
    pub fn name(&self) -> XorName {
        match self {
            Self::Section(name) | Self::Node(name) => *name,
            Self::PrefixSection(prefix) => prefix.lower_bound(),
        }
    }

    /// Returns if the location is compatible with that prefix
    pub fn is_compatible(&self, other_prefix: &Prefix<XorName>) -> bool {
        match self {
            Self::Section(name) | Self::Node(name) => other_prefix.matches(name),
            Self::PrefixSection(prefix) => other_prefix.is_compatible(prefix),
        }
    }
}

impl Location {
    /// provide the name mathching a single node's public key
    pub fn single_signing_name(&self) -> Option<&XorName> {
        match *self {
            Self::Section(_) | Self::PrefixSection(_) => None,
            Self::Node(ref name) => Some(name),
        }
    }
}

impl Debug for Location {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match *self {
            Self::Section(ref name) => write!(formatter, "Section(name: {})", name),
            Self::PrefixSection(ref prefix) => {
                write!(formatter, "PrefixSection(prefix: {:?})", prefix)
            }
            Self::Node(ref name) => write!(formatter, "Node(name: {})", name),
        }
    }
}
