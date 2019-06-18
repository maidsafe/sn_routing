// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{id::PublicId, quic_p2p::NodeInfo, ConnectionInfo};
use std::{collections::HashMap, net::SocketAddr};

/// Map between public ids and connection infos.
#[derive(Default)]
pub struct PeerMap {
    forward: HashMap<PublicId, ConnectionInfo>,
    reverse: HashMap<SocketAddr, PublicId>,
    pending: HashMap<SocketAddr, PendingConnection>,
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

    // Handles `ConnectedTo` event from the network layer.
    // TODO: remove this `allow` when https://github.com/rust-lang/rust-clippy/issues/4219
    // is fixed.
    #[allow(clippy::map_entry)]
    pub fn handle_connected_to(&mut self, conn_info: ConnectionInfo) {
        let socket_addr = conn_info.peer_addr();
        if !self.reverse.contains_key(&socket_addr) {
            let _ = self
                .pending
                .insert(socket_addr, PendingConnection::from(conn_info));
        }
    }

    // Handles `ConnectionFailure` event from the network layer. Returns the `PublicId` of the peer,
    // if the connection to them was previously established. Otherwise returns `None`.
    pub fn handle_connection_failure(&mut self, socket_addr: SocketAddr) -> Option<PublicId> {
        let _ = self.pending.remove(&socket_addr);

        if let Some(pub_id) = self.reverse.remove(&socket_addr) {
            let _ = self.forward.remove(&pub_id);
            Some(pub_id)
        } else {
            None
        }
    }

    // Handles received `DirectMessage`.
    pub fn handle_direct_message(&mut self, pub_id: PublicId, socket_addr: SocketAddr) {
        if let Some(peer_type) = self.pending.remove(&socket_addr) {
            let _ = self
                .forward
                .insert(pub_id, peer_type.into_connection_info(socket_addr));
            let _ = self.reverse.insert(socket_addr, pub_id);
        }
    }

    // Handles received `ConnectionRequest` message.
    pub fn handle_connection_request(&mut self, pub_id: PublicId, node_info: NodeInfo) {
        let _ = self.pending.remove(&node_info.peer_addr);
        let _ = self.reverse.insert(node_info.peer_addr, pub_id);
        let _ = self
            .forward
            .insert(pub_id, ConnectionInfo::Node { node_info });
    }

    // Removes the peer. If we were connected to the peer, returns its `Peer` info. Otherwise
    // returns `None`.
    pub fn remove(&mut self, pub_id: &PublicId) -> Option<ConnectionInfo> {
        let conn_info = self.forward.remove(pub_id)?;
        let _ = self.reverse.remove(&conn_info.peer_addr());
        Some(conn_info)
    }

    // Removes all peers. Returns an iterator over the `Peer` infos of the removed peers.
    pub fn remove_all<'a>(&'a mut self) -> impl Iterator<Item = ConnectionInfo> + 'a {
        self.reverse.clear();
        self.forward.drain().map(|(_, conn_info)| conn_info).chain(
            self.pending
                .drain()
                .map(|(socket_addr, peer_type)| peer_type.into_connection_info(socket_addr)),
        )
    }

    // Get connection info of the peer with the given public id.
    pub fn get_connection_info<'a>(&'a self, pub_id: &PublicId) -> Option<&'a ConnectionInfo> {
        self.forward.get(pub_id)
    }
}

enum PendingConnection {
    Client,
    Node { peer_cert_der: Vec<u8> },
}

impl From<ConnectionInfo> for PendingConnection {
    fn from(conn_info: ConnectionInfo) -> Self {
        match conn_info {
            ConnectionInfo::Client { .. } => PendingConnection::Client,
            ConnectionInfo::Node {
                node_info: NodeInfo { peer_cert_der, .. },
            } => PendingConnection::Node { peer_cert_der },
        }
    }
}

impl PendingConnection {
    fn into_connection_info(self, peer_addr: SocketAddr) -> ConnectionInfo {
        match self {
            PendingConnection::Client => ConnectionInfo::Client { peer_addr },
            PendingConnection::Node { peer_cert_der } => ConnectionInfo::Node {
                node_info: NodeInfo {
                    peer_addr,
                    peer_cert_der,
                },
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::FullId;
    use unwrap::unwrap;

    #[test]
    fn connected_to_then_direct_message_then_connection_failure() {
        let mut peer_map = PeerMap::new();
        let conn_info = conn_info("198.51.100.0:5555");
        let pub_id = *FullId::new().public_id();

        assert!(peer_map.get_connection_info(&pub_id).is_none());

        peer_map.handle_connected_to(conn_info.clone());
        assert!(peer_map.get_connection_info(&pub_id).is_none());

        peer_map.handle_direct_message(pub_id, conn_info.peer_addr());
        assert_eq!(peer_map.get_connection_info(&pub_id), Some(&conn_info));

        let outcome = peer_map.handle_connection_failure(conn_info.peer_addr());
        assert_eq!(outcome, Some(pub_id));
        assert!(peer_map.get_connection_info(&pub_id).is_none());
    }

    #[test]
    fn connection_request() {
        let mut peer_map = PeerMap::new();
        let node_info = node_info("198.51.100.0:5555");
        let conn_info = ConnectionInfo::Node {
            node_info: node_info.clone(),
        };
        let pub_id = *FullId::new().public_id();

        assert!(peer_map.get_connection_info(&pub_id).is_none());

        peer_map.handle_connection_request(pub_id, node_info.clone());
        assert_eq!(peer_map.get_connection_info(&pub_id), Some(&conn_info));
    }

    fn conn_info(addr: &str) -> ConnectionInfo {
        ConnectionInfo::Node {
            node_info: node_info(addr),
        }
    }

    fn node_info(addr: &str) -> NodeInfo {
        let peer_addr: SocketAddr = unwrap!(addr.parse());
        NodeInfo {
            peer_addr,
            peer_cert_der: vec![],
        }
    }
}
