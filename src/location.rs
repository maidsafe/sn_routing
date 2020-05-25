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
    /// Returns whether this location is a section.
    pub fn is_section(&self) -> bool {
        match self {
            Self::Section(_) => true,
            Self::Node(_) => false,
        }
    }

    /// Returns whether the given name is part of this location
    pub(crate) fn contains(&self, name: &XorName) -> bool {
        match self {
            SrcLocation::Node(self_name) => name == self_name,
            SrcLocation::Section(self_prefix) => self_prefix.matches(name),
        }
    }

    /// Returns this location as `DstLocation`
    pub(crate) fn to_dst(&self) -> DstLocation {
        match self {
            Self::Node(name) => DstLocation::Node(*name),
            Self::Section(prefix) => DstLocation::Section(prefix.name()),
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
    /// Destination is the node at the `ConnectionInfo` the message is directly sent to.
    Direct,
}

impl DstLocation {
    /// Returns whether this location is a section.
    pub fn is_section(&self) -> bool {
        match self {
            Self::Section(_) => true,
            Self::Node(_) | Self::Direct => false,
        }
    }

    /// Returns if the location is compatible with that prefix
    pub(crate) fn is_compatible(&self, other_prefix: &Prefix<XorName>) -> bool {
        match self {
            Self::Section(name) | Self::Node(name) => other_prefix.matches(name),
            Self::Direct => false,
        }
    }

    /// If this location is `Node`, returns its name, otherwise `Err(BadLocation)`.
    pub(crate) fn as_node(&self) -> Result<&XorName> {
        match self {
            Self::Node(name) => Ok(name),
            Self::Section(_) | Self::Direct => Err(RoutingError::BadLocation),
        }
    }

    /// Returns `Ok` if this location is section, `Err(BadLocation)` otherwise.
    pub(crate) fn check_is_section(&self) -> Result<()> {
        match self {
            Self::Section(_) => Ok(()),
            Self::Node(_) | Self::Direct => Err(RoutingError::BadLocation),
        }
    }

    /// Returns whether the given name of the given prefix is part of this location.
    ///
    /// # Panics
    ///
    /// Panics if `prefix` does not match `name`.
    pub(crate) fn contains(&self, name: &XorName, prefix: &Prefix<XorName>) -> bool {
        assert!(prefix.matches(name));

        match self {
            DstLocation::Node(self_name) => name == self_name,
            DstLocation::Section(self_name) => prefix.matches(self_name),
            DstLocation::Direct => true,
        }
    }
}
