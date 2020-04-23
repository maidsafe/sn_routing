// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    error::{Result, RoutingError},
    xor_space::{Prefix, XorName},
};

/// Message source location.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize, Debug)]
pub enum SrcLocation {
    /// A single node with the given name.
    Node(XorName),
    /// A section with the given prefix.
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

    /// Returns whether the given name is part of this location
    pub fn contains(&self, name: &XorName) -> bool {
        match self {
            SrcLocation::Node(self_name) => name == self_name,
            SrcLocation::Section(self_prefix) => self_prefix.matches(name),
        }
    }
}

/// Message destination location.
#[derive(Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize, Debug)]
pub enum DstLocation {
    /// Destination is a single node with the given name.
    Node(XorName),
    /// Destination are the nodes of the section whose prefix matches the given name.
    Section(XorName),
    /// Destination are the nodes whose name is matched by the given prefix.
    Prefix(Prefix<XorName>),
    /// Destination is the node at the `ConnectionInfo` the message is directly sent to.
    Direct,
}

impl DstLocation {
    /// Returns `true` if the location is a single node, and `false` otherwise.
    pub fn is_single(&self) -> bool {
        match self {
            Self::Node(_) | Self::Direct => true,
            Self::Section(_) | Self::Prefix(_) => false,
        }
    }

    /// Returns `true` if the location consists of multiple nodes, otherwise `false`.
    pub fn is_multiple(&self) -> bool {
        !self.is_single()
    }

    /// Returns if the location is compatible with that prefix
    pub fn is_compatible(&self, other_prefix: &Prefix<XorName>) -> bool {
        match self {
            Self::Section(name) | Self::Node(name) => other_prefix.matches(name),
            Self::Prefix(prefix) => other_prefix.is_compatible(prefix),
            Self::Direct => false,
        }
    }

    /// If this location is `Node`, returns its name, otherwise error.
    pub fn as_node(&self) -> Result<&XorName> {
        match self {
            Self::Node(name) => Ok(name),
            Self::Section(_) | Self::Prefix(_) | Self::Direct => Err(RoutingError::BadLocation),
        }
    }

    /// If this location is `Section`, returns its name, otherwise error.
    pub fn as_section(&self) -> Result<&XorName> {
        match self {
            Self::Section(name) => Ok(name),
            Self::Node(_) | Self::Prefix(_) | Self::Direct => Err(RoutingError::BadLocation),
        }
    }

    /// If this location is `Prefix`, returns it, otherwise error.
    pub fn as_prefix(&self) -> Result<&Prefix<XorName>> {
        match self {
            Self::Prefix(prefix) => Ok(prefix),
            Self::Node(_) | Self::Section(_) | Self::Direct => Err(RoutingError::BadLocation),
        }
    }

    /// Returns whether the given name of the given prefix is part of this location.
    ///
    /// # Panics
    ///
    /// Panics if `prefix` does not match `name`.
    pub fn contains(&self, name: &XorName, prefix: &Prefix<XorName>) -> bool {
        assert!(prefix.matches(name));

        match self {
            DstLocation::Node(self_name) => name == self_name,
            DstLocation::Section(self_name) => prefix.matches(self_name),
            DstLocation::Prefix(self_prefix) => prefix.is_compatible(self_prefix),
            DstLocation::Direct => true,
        }
    }
}
