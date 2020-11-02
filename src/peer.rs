// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use serde::{Deserialize, Serialize};
use std::{
    fmt::{self, Display, Formatter},
    hash::Hash,
    net::SocketAddr,
};
use xor_name::XorName;

/// Network p2p peer identity.
/// When a node knows another p2p_node as a `Peer` it's implicitly connected to it. This is separate
/// from being connected at the network layer, which currently is handled by quic-p2p.
#[derive(Clone, Copy, Debug, Hash, PartialEq, PartialOrd, Ord, Eq, Serialize, Deserialize)]
pub struct Peer {
    name: XorName,
    addr: SocketAddr,
    age: u8,
}

impl Peer {
    /// Creates a new `Peer` given `Name`, `SocketAddr` and `age`.
    pub fn new(name: XorName, addr: SocketAddr, age: u8) -> Self {
        Self { name, addr, age }
    }

    /// Returns the `XorName` of the peer.
    pub fn name(&self) -> &XorName {
        &self.name
    }

    /// Returns the `SocketAddr`.
    pub fn addr(&self) -> &SocketAddr {
        &self.addr
    }

    /// Returns the age.
    pub fn age(&self) -> u8 {
        self.age
    }

    // Converts this info into one with the input age.
    pub fn with_age(self, age: u8) -> Self {
        Self { age, ..self }
    }

    // Converts this info into one with the age increased by one.
    pub fn increment_age(self) -> Self {
        Self {
            age: self.age.saturating_add(1),
            ..self
        }
    }
}

impl Display for Peer {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{} at {}", self.name, self.addr)
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    use crate::MIN_AGE;

    use super::*;
    use proptest::prelude::*;
    use xor_name::XOR_NAME_LEN;

    pub(crate) fn arbitrary_xor_name() -> impl Strategy<Value = XorName> {
        any::<[u8; XOR_NAME_LEN]>().prop_map(XorName)
    }

    pub(crate) fn arbitrary_peer() -> impl Strategy<Value = Peer> {
        (arbitrary_xor_name(), any::<SocketAddr>(), MIN_AGE..)
            .prop_map(|(name, addr, age)| Peer::new(name, addr, age))
    }
}
