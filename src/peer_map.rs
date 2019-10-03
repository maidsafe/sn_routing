// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{id::PublicId, quic_p2p::NodeInfo};
use fxhash::FxHashMap;
use std::net::SocketAddr;

/// This structure holds the bi-directional association between peers public id and their network
/// connection info. This association can be create in two ways:
/// 1. When both pieces of information (public id and connection info) are obtained at the same
///    time, call `insert`. This happens when a third party (other members of the section) sends
///    them to us.
/// 2. Otherwise its a two step process: first, when the connection to the peer is established at
///    the network layer, call `connect`. Then when their public id is received, call `identify`.
///    This happens when the peer connects to us and then sends us a message which contains their
///    public id.
#[derive(Default)]
pub struct PeerMap {
    forward: FxHashMap<PublicId, NodeInfo>,
    reverse: FxHashMap<SocketAddr, PublicId>,
    pending: FxHashMap<SocketAddr, PendingConnection>,
}

// TODO (quic-p2p): correctly handle these pathological scenarios:
//
// 1. Non-unique public id:
//      1. There is existing connection with pub id P and conn info C
//      2. We get another connection with conn info D
//      3. We receive a DirectMessage over connection D but with pub id P
//
// 2. Non-unique connection info:
//      1. There is existing connection with pub id P and conn info C
//      2. We receive a DirectMessage over connection C but with pub id R
//

impl PeerMap {
    pub fn new() -> Self {
        Self::default()
    }

    // Marks the connection as established at the network layer. This is the first step in creating
    // an association between public id and connection info. The second step is to call `identify`.
    // TODO: remove this `allow` when https://github.com/rust-lang/rust-clippy/issues/4219
    // is fixed.
    #[allow(clippy::map_entry)]
    pub fn connect(&mut self, conn_info: NodeInfo) {
        let socket_addr = conn_info.peer_addr;
        if !self.reverse.contains_key(&socket_addr) {
            let _ = self
                .pending
                .insert(socket_addr, PendingConnection::from(conn_info));
        }
    }

    // Marks the connection as severed at the network layer. Returns the peers public id if the
    // connection has been associated with one.
    pub fn disconnect(&mut self, socket_addr: SocketAddr) -> Option<PublicId> {
        let _ = self.pending.remove(&socket_addr);

        if let Some(pub_id) = self.reverse.remove(&socket_addr) {
            let _ = self.forward.remove(&pub_id);
            Some(pub_id)
        } else {
            None
        }
    }

    // Associate a network layer connection, that was previously established via `connect`, with
    // the peers public id.
    pub fn identify(&mut self, pub_id: PublicId, socket_addr: SocketAddr) {
        if let Some(pending) = self.pending.remove(&socket_addr) {
            let _ = self
                .forward
                .insert(pub_id, pending.into_connection_info(socket_addr));
            let _ = self.reverse.insert(socket_addr, pub_id);
        }
    }

    // Inserts a new entry into the peer map. This is equivalent to calling `connect` followed by
    // `identify` and can be used when we obtain both the public id and the connection info at the
    // same time (for example when a third party sends them to us).
    pub fn insert(&mut self, pub_id: PublicId, node_info: NodeInfo) {
        let _ = self.pending.remove(&node_info.peer_addr);
        let _ = self.reverse.insert(node_info.peer_addr, pub_id);
        let _ = self.forward.insert(pub_id, node_info);
    }

    // Removes the peer. If we were connected to the peer, returns its connection info. Otherwise
    // returns `None`.
    pub fn remove(&mut self, pub_id: &PublicId) -> Option<NodeInfo> {
        let conn_info = self.forward.remove(pub_id)?;
        let _ = self.reverse.remove(&conn_info.peer_addr);
        Some(conn_info)
    }

    // Removes all peers. Returns an iterator over the connection infos of the removed peers.
    pub fn remove_all<'a>(&'a mut self) -> impl Iterator<Item = NodeInfo> + 'a {
        self.reverse.clear();
        self.forward.drain().map(|(_, conn_info)| conn_info).chain(
            self.pending
                .drain()
                .map(|(socket_addr, pending)| pending.into_connection_info(socket_addr)),
        )
    }

    // Get connection info of the peer with the given public id.
    pub fn get_connection_info<'a>(&'a self, pub_id: &PublicId) -> Option<&'a NodeInfo> {
        self.forward.get(pub_id)
    }

    // Returns an iterator over the public IDs of connected peers
    pub fn connected_ids(&self) -> impl Iterator<Item = &PublicId> {
        self.forward.keys()
    }

    // Returns `true` if we have the connection info for a given public ID
    pub fn has(&self, pub_id: &PublicId) -> bool {
        self.forward.contains_key(pub_id)
    }
}

struct PendingConnection {
    peer_cert_der: Vec<u8>,
}

impl From<NodeInfo> for PendingConnection {
    fn from(conn_info: NodeInfo) -> Self {
        Self {
            peer_cert_der: conn_info.peer_cert_der,
        }
    }
}

impl PendingConnection {
    fn into_connection_info(self, peer_addr: SocketAddr) -> NodeInfo {
        NodeInfo {
            peer_addr,
            peer_cert_der: self.peer_cert_der,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::FullId;
    use unwrap::unwrap;

    #[test]
    fn connect_then_identify_then_disconnect() {
        let mut peer_map = PeerMap::new();
        let conn_info = connection_info("198.51.100.0:5555");
        let pub_id = *FullId::new().public_id();

        assert!(peer_map.get_connection_info(&pub_id).is_none());

        peer_map.connect(conn_info.clone());
        assert!(peer_map.get_connection_info(&pub_id).is_none());

        peer_map.identify(pub_id, conn_info.peer_addr);
        assert_eq!(peer_map.get_connection_info(&pub_id), Some(&conn_info));

        let outcome = peer_map.disconnect(conn_info.peer_addr);
        assert_eq!(outcome, Some(pub_id));
        assert!(peer_map.get_connection_info(&pub_id).is_none());
    }

    #[test]
    fn insert() {
        let mut peer_map = PeerMap::new();
        let conn_info = connection_info("198.51.100.0:5555");
        let pub_id = *FullId::new().public_id();

        assert!(peer_map.get_connection_info(&pub_id).is_none());

        peer_map.insert(pub_id, conn_info.clone());
        assert_eq!(peer_map.get_connection_info(&pub_id), Some(&conn_info));
    }

    fn connection_info(addr: &str) -> NodeInfo {
        let peer_addr: SocketAddr = unwrap!(addr.parse());
        NodeInfo {
            peer_addr,
            peer_cert_der: vec![],
        }
    }
}
