// Copyright 2015 MaidSafe.net limited.
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

use super::{Prefix, Xorable};
use id::PublicId;
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
pub enum Authority<N: Xorable + Clone + Copy + Binary + Default> {
    /// Manager of a Client.  XorName is the hash of the Client's `client_key`.
    ClientManager(N),
    /// Manager of a network-addressable element, i.e. the group matching this name.
    /// `XorName` is the name of the element in question.
    NaeManager(N),
    /// Manager of a ManagedNode.  XorName is that of the ManagedNode.
    NodeManager(N),
    /// A set of nodes with names sharing a common prefix.
    Section(N),
    /// A set of nodes with names sharing a common prefix - may span multiple `Section`s present in
    /// the routing table or only a part of a `Section`
    PrefixSection(Prefix<N>),
    /// A non-client node (i.e. a vault) which is managed by NodeManagers.  XorName is provided
    /// by the network relocation process immediately after bootstrapping.
    ManagedNode(N),
    /// A Client.
    Client {
        /// The Public ID of the client.
        client_id: PublicId,
        /// The name of the single ManagedNode which the Client connects to and proxies all messages
        /// through.
        proxy_node_name: N,
    },
}

impl<N: Xorable + Clone + Copy + Binary + Default> Authority<N> {
    /// Returns `true` if the authority consists of multiple nodes, otherwise `false`.
    pub fn is_multiple(&self) -> bool {
        match *self {
            Authority::Section(_) |
            Authority::PrefixSection(_) |
            Authority::ClientManager(_) |
            Authority::NaeManager(_) |
            Authority::NodeManager(_) => true,
            Authority::ManagedNode(_) |
            Authority::Client { .. } => false,
        }
    }

    /// Returns `true` if the authority is a single node, and `false` otherwise.
    pub fn is_single(&self) -> bool {
        match *self {
            Authority::ClientManager(_) |
            Authority::NaeManager(_) |
            Authority::Section(_) |
            Authority::PrefixSection(_) |
            Authority::NodeManager(_) => false,
            Authority::ManagedNode(_) |
            Authority::Client { .. } => true,
        }
    }

    /// Returns `true` if a client, `false` if a node or section.
    pub fn is_client(&self) -> bool {
        if let Authority::Client { .. } = *self {
            true
        } else {
            false
        }
    }

    /// Returns the name of authority.
    pub fn name(&self) -> N {
        match *self {
            Authority::ClientManager(ref name) |
            Authority::NaeManager(ref name) |
            Authority::NodeManager(ref name) |
            Authority::Section(ref name) |
            Authority::ManagedNode(ref name) => *name,
            Authority::PrefixSection(ref prefix) => prefix.lower_bound(),
            Authority::Client { ref proxy_node_name, .. } => *proxy_node_name,
        }
    }
}

impl<N: Xorable + Clone + Copy + Binary + Default + Display> Debug for Authority<N> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match *self {
            Authority::ClientManager(ref name) => {
                write!(formatter, "ClientManager(name: {})", name)
            }
            Authority::NaeManager(ref name) => write!(formatter, "NaeManager(name: {})", name),
            Authority::NodeManager(ref name) => write!(formatter, "NodeManager(name: {})", name),
            Authority::Section(ref name) => write!(formatter, "Section(name: {})", name),
            Authority::PrefixSection(ref prefix) => {
                write!(formatter, "PrefixSection(prefix: {:?})", prefix)
            }
            Authority::ManagedNode(ref name) => write!(formatter, "ManagedNode(name: {})", name),
            Authority::Client {
                ref proxy_node_name,
                ref client_id,
            } => {
                write!(
                    formatter,
                    "Client {{ client_name: {}, proxy_node_name: {} }}",
                    client_id.name(),
                    proxy_node_name
                )
            }
        }
    }
}
