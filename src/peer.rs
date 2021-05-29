// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use sn_messaging::node::Peer;
use std::net::SocketAddr;
use xor_name::{XorName, XOR_NAME_LEN};

///
pub trait PeerUtils {
    /// Creates a new `Peer` given `Name`, `SocketAddr`.
    fn new(name: XorName, addr: SocketAddr) -> Self;

    /// Set the reachable flag.
    fn set_reachable(&mut self, reachable: bool);

    /// Returns the `XorName` of the peer.
    fn name(&self) -> &XorName;

    /// Returns the `SocketAddr`.
    fn addr(&self) -> &SocketAddr;

    /// Returns the age.
    fn age(&self) -> u8;

    /// Returns the reachable flag.
    fn is_reachable(&self) -> bool;
}

impl PeerUtils for Peer {
    /// Creates a new `Peer` given `Name`, `SocketAddr`.
    fn new(name: XorName, addr: SocketAddr) -> Self {
        Self {
            name,
            addr,
            reachable: false,
        }
    }

    /// Set the reachable flag.
    fn set_reachable(&mut self, reachable: bool) {
        self.reachable = reachable;
    }

    /// Returns the `XorName` of the peer.
    fn name(&self) -> &XorName {
        &self.name
    }

    /// Returns the `SocketAddr`.
    fn addr(&self) -> &SocketAddr {
        &self.addr
    }

    /// Returns the age.
    fn age(&self) -> u8 {
        self.name[XOR_NAME_LEN - 1]
    }

    /// Returns the reachable flag.
    fn is_reachable(&self) -> bool {
        self.reachable
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    use super::*;
    use proptest::{collection::SizeRange, prelude::*};
    use xor_name::XOR_NAME_LEN;

    pub(crate) fn arbitrary_bytes() -> impl Strategy<Value = [u8; XOR_NAME_LEN]> {
        any::<[u8; XOR_NAME_LEN]>()
    }

    // Generate Vec<Peer> where no two peers have the same name.
    pub(crate) fn arbitrary_unique_peers(
        count: impl Into<SizeRange>,
        age: impl Strategy<Value = u8>,
    ) -> impl Strategy<Value = Vec<Peer>> {
        proptest::collection::btree_map(arbitrary_bytes(), (any::<SocketAddr>(), age), count)
            .prop_map(|peers| {
                peers
                    .into_iter()
                    .map(|(mut bytes, (addr, age))| {
                        bytes[XOR_NAME_LEN - 1] = age;
                        let name = XorName(bytes);
                        Peer::new(name, addr)
                    })
                    .collect()
            })
    }
}
