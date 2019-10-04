// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::id::PublicId;
use std::collections::BTreeSet;

/// A container for information about other nodes in the network.
///
/// This keeps track of which nodes we know of, which ones we have tried to connect to, which IDs
/// we have verified, and whom we are connected to.
#[derive(Default)]
pub struct PeerManager {
    peers: BTreeSet<PublicId>,
}

impl PeerManager {
    /// Returns a new peer manager with no entries.
    pub fn new() -> PeerManager {
        PeerManager {
            peers: BTreeSet::new(),
        }
    }

    /// Marks the given peer as direct-connected.
    pub fn set_connected(&mut self, pub_id: PublicId) {
        let _ = self.peers.insert(pub_id);
    }

    /// Returns `true` if the peer is connected to us.
    pub fn is_connected(&self, pub_id: &PublicId) -> bool {
        self.peers.contains(pub_id)
    }

    /// Removes the given peer. Returns whether the peer was actually present.
    pub fn remove_peer(&mut self, pub_id: &PublicId) -> bool {
        self.peers.remove(pub_id)
    }
}
