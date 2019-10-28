// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use fxhash::FxHashSet as HashSet;
use std::net::SocketAddr;

#[derive(Default)]
pub struct PeerMap {
    clients: HashSet<SocketAddr>,
}

impl PeerMap {
    pub fn new() -> Self {
        Self::default()
    }

    // Inserts a new client entry
    pub fn insert_client(&mut self, peer_addr: SocketAddr) {
        let _ = self.clients.insert(peer_addr);
    }

    // Inserts a new client entry
    pub fn remove_client(&mut self, peer_addr: &SocketAddr) {
        let _ = self.clients.remove(&peer_addr);
    }

    // Return true if we know of that peer as a client
    pub fn is_known_client(&self, peer_addr: &SocketAddr) -> bool {
        self.clients.contains(peer_addr)
    }
}
