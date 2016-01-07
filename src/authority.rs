// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use xor_name::XorName;
use sodiumoxide::crypto::{hash, sign};
use std::fmt::{Debug, Formatter};

/// An entity that can act as a source or destination of a message.
///
/// An `Authority` can be an individual client or node, or a group of nodes.
#[derive(RustcEncodable, RustcDecodable, PartialEq, PartialOrd, Eq, Ord, Clone, Hash)]
pub enum Authority {
    /// Manager of a Client.  XorName is the hash of the Client's `client_key`.
    ClientManager(XorName),
    /// Manager of a network-addressable element.  XorName is the name of the element in question.
    NaeManager(XorName),
    /// Manager of a ManagedNode.  XorName is that of the ManagedNode.
    NodeManager(XorName),
    /// A non-client node (i.e. a vault) which is managed by NodeManagers.  XorName is provided
    /// by the network relocation process immediately after bootstrapping.
    ManagedNode(XorName),
    /// A Client.
    Client {
        /// The client's public signing key.  The hash of this specifies the location of the Client
        /// in the network address space.
        client_key: sign::PublicKey,
        /// The name of the single ManagedNode which the Client connects to and proxies all messages
        /// through.
        proxy_node_name: XorName,
    },
}

impl Authority {
    /// Returns true if group authority, otherwise false.
    pub fn is_group(&self) -> bool {
        match *self {
            Authority::ClientManager(_) => true,
            Authority::NaeManager(_) => true,
            Authority::NodeManager(_) => true,
            Authority::ManagedNode(_) => false,
            Authority::Client { .. } => false,
        }
    }

    /// Returns the name of authority.
    pub fn get_name(&self) -> &XorName {
        match *self {
            Authority::ClientManager(ref name) => name,
            Authority::NaeManager(ref name) => name,
            Authority::NodeManager(ref name) => name,
            Authority::ManagedNode(ref name) => name,
            Authority::Client { ref proxy_node_name, .. } => proxy_node_name,
        }
    }
}

impl Debug for Authority {
    fn fmt(&self, f: &mut Formatter) -> ::std::fmt::Result {
        match *self {
            Authority::ClientManager(ref name) => write!(f, "ClientManager(name:{:?})", name),
            Authority::NaeManager(ref name) => write!(f, "NaeManager(name:{:?})", name),
            Authority::NodeManager(ref name) => write!(f, "NodeManager(name:{:?})", name),
            Authority::ManagedNode(ref name) => write!(f, "ManagedNode(name:{:?})", name),
            Authority::Client { ref client_key, ref proxy_node_name, } => {
                write!(f,
                       "Client {{ client_name: {:?}, proxy_node_name: {:?} }}",
                       XorName::new(hash::sha512::hash(&client_key[..]).0),
                       proxy_node_name)
            }
        }
    }
}
