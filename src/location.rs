// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::xor_space::{Prefix, XorName};

/// Source location
#[derive(Serialize, Deserialize, PartialEq, PartialOrd, Eq, Ord, Clone, Copy, Hash, Debug)]
pub enum SrcLocation {
    /// A single node with the given name.
    Node(XorName),
    /// A single section with the given prefix.
    Section(Prefix<XorName>),
}

impl SrcLocation {
    /// Returns `true` if the location is a single node, and `false` otherwise.
    pub fn is_single(&self) -> bool {
        match self {
            Self::Node(_) => true,
            Self::Section(_) => false,
        }
    }

    /// Returns `true` if the location consists of multiple nodes, otherwise `false`.
    pub fn is_multiple(&self) -> bool {
        !self.is_single()
    }

    /// provide the name mathching a single node's public key
    pub(crate) fn single_signing_name(&self) -> Option<&XorName> {
        match self {
            Self::Node(name) => Some(name),
            Self::Section(_) => None,
        }
    }
}

/// Destination location
#[derive(Serialize, Deserialize, PartialEq, PartialOrd, Eq, Ord, Clone, Copy, Hash, Debug)]
pub enum DstLocation {
    /// A single section whose prefix matches the given name
    Section(XorName),
    /// A set of nodes with names sharing a common prefix - may span multiple `Section`s present in
    /// the routing table or only a part of a `Section`
    PrefixSection(Prefix<XorName>),
    /// A single node
    Node(XorName),
}

impl DstLocation {
    /// Returns `true` if the location is a single node, and `false` otherwise.
    pub fn is_single(&self) -> bool {
        match self {
            Self::Section(_) | Self::PrefixSection(_) => false,
            Self::Node(_) => true,
        }
    }

    /// Returns `true` if the location consists of multiple nodes, otherwise `false`.
    pub fn is_multiple(&self) -> bool {
        !self.is_single()
    }

    /// Returns the name of location.
    pub fn name(&self) -> XorName {
        match self {
            Self::Section(name) | Self::Node(name) => *name,
            Self::PrefixSection(prefix) => prefix.lower_bound(),
        }
    }

    /// Returns if the location is compatible with that prefix
    pub(crate) fn is_compatible(&self, other_prefix: &Prefix<XorName>) -> bool {
        match self {
            Self::Section(name) | Self::Node(name) => other_prefix.matches(name),
            Self::PrefixSection(prefix) => other_prefix.is_compatible(prefix),
        }
    }
}
