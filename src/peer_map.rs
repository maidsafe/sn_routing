// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::ConnectionInfo;
use fxhash::FxHashMap as HashMap;
use std::net::SocketAddr;

#[derive(Default)]
pub struct PeerMap {
    connections: HashMap<SocketAddr, ConnectionInfo>,
}

impl PeerMap {
    pub fn new() -> Self {
        Self::default()
    }

    // Marks the connection as established at the network layer.
    pub fn connect(&mut self, conn_info: ConnectionInfo) {
        let _ = self.connections.insert(conn_info.peer_addr, conn_info);
    }

    // Marks the connection as severed at the network layer.
    pub fn disconnect(&mut self, socket_addr: SocketAddr) -> Option<ConnectionInfo> {
        self.connections.remove(&socket_addr)
    }

    // Removes all peers. Returns an iterator over the connection infos of the removed peers.
    pub fn remove_all<'a>(&'a mut self) -> impl Iterator<Item = ConnectionInfo> + 'a {
        self.connections.drain().map(|(_, conn_info)| conn_info)
    }

    // Returns `true` if we have the connection info for a given socket address.
    pub fn has(&self, socket_addr: &SocketAddr) -> bool {
        self.connections.contains_key(socket_addr)
    }
}
