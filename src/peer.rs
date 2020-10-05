// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use serde::Serialize;
use std::{hash::Hash, net::SocketAddr};
use xor_name::XorName;

/// Network p2p peer identity.
/// When a node knows another p2p_node as a `Peer` it's implicitly connected to it. This is separate
/// from being connected at the network layer, which currently is handled by quic-p2p.
#[derive(Clone, Copy, Debug, Hash, PartialEq, PartialOrd, Ord, Eq, Serialize, Deserialize)]
pub struct Peer {
    pub name: XorName,
    pub addr: SocketAddr,
}

impl Peer {
    /// Creates a new `Peer` given a `Name` and a `ConnectionInfo`.
    pub fn new(name: XorName, addr: SocketAddr) -> Self {
        Self { name, addr }
    }

    /// Returns the `XorName` of the peer.
    pub fn name(&self) -> &XorName {
        &self.name
    }

    /// Returns the `SocketAddr`.
    pub fn addr(&self) -> &SocketAddr {
        &self.addr
    }
}
