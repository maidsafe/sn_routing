// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::xor_space::{Prefix, XorName, Xorable};
use std::fmt::{self, Binary, Debug, Display, Formatter};

/// A `Location` is a source or destination of a message.
///
/// `Node` is single-node location (i.e. no verification of messages from
/// additional sources needed). It's name is the `Authority::key` other
/// locations require agreement by a quorum of `Elders`.
#[derive(Serialize, Deserialize, PartialEq, PartialOrd, Eq, Ord, Clone, Copy, Hash)]
pub enum Location<N: Xorable + Clone + Copy + Binary + Default> {
    /// A single section whose prefix matches the given name
    Section(N),
    /// A set of nodes with names sharing a common prefix - may span multiple `Section`s present in
    /// the routing table or only a part of a `Section`
    PrefixSection(Prefix<N>),
    /// A single node
    Node(N),
}

impl<N: Xorable + Clone + Copy + Binary + Default> Location<N> {
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
    pub fn name(&self) -> N {
        match self {
            Self::Section(name) | Self::Node(name) => *name,
            Self::PrefixSection(prefix) => prefix.lower_bound(),
        }
    }

    /// Returns if the location is compatible with that prefix
    pub fn is_compatible(&self, other_prefix: &Prefix<N>) -> bool {
        match self {
            Self::Section(name) | Self::Node(name) => other_prefix.matches(name),
            Self::PrefixSection(prefix) => other_prefix.is_compatible(prefix),
        }
    }
}

impl Location<XorName> {
    /// provide the name mathching a single node's public key
    pub fn single_signing_name(&self) -> Option<&XorName> {
        match *self {
            Self::Section(_) | Self::PrefixSection(_) => None,
            Self::Node(ref name) => Some(name),
        }
    }
}

impl<N: Xorable + Clone + Copy + Binary + Default + Display> Debug for Location<N> {
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
