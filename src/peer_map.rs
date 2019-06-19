// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{id::PublicId, quic_p2p::NodeInfo, ConnectionInfo};
use log::LogLevel;
use std::{
    collections::hash_map::{Entry, HashMap},
    mem,
    net::SocketAddr,
};

/// Maps `PublicId`s to network layer peer details (socket addresses, etc...) and handles the
/// low-level connection management.
#[derive(Default)]
pub struct PeerMap {
    routing_to_network: HashMap<PublicId, ConnectionInfo>,
    network_to_routing: HashMap<SocketAddr, State>,
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
    pub fn handle_connected_to(
        &mut self,
        conn_info: ConnectionInfo,
    ) -> Result<PublicId, ConnectionError> {
        match self.network_to_routing.entry(conn_info.peer_addr()) {
            Entry::Vacant(entry) => {
                let _ = entry.insert(State::Network(PeerType::from(conn_info)));
                Err(ConnectionError::Incomplete)
            }
            Entry::Occupied(mut entry) => match *entry.get() {
                State::Network(_) => Err(ConnectionError::Incomplete),
                State::Routing(pub_id) => {
                    *entry.get_mut() = State::Complete(pub_id);
                    Ok(pub_id)
                }
                State::Complete(_) => Err(ConnectionError::AlreadyConnected),
            },
        }
    }

    // Handles `ConnectionFailure` event from the network layer. Returns the `PublicId` of the peer,
    // if the connection to them was previously established. Otherwise returns `None`.
    pub fn handle_connection_failure(&mut self, socket_addr: SocketAddr) -> Option<PublicId> {
        match self.network_to_routing.remove(&socket_addr) {
            Some(State::Complete(pub_id)) => {
                let _ = self.routing_to_network.remove(&pub_id);
                Some(pub_id)
            }
            Some(_) | None => None,
        }
    }

    // Handles received `DirectMessage`.
    pub fn handle_direct_message(
        &mut self,
        pub_id: PublicId,
        socket_addr: SocketAddr,
    ) -> Result<ConnectionInfo, ConnectionError> {
        if let Some(routing_peer) = self.network_to_routing.get_mut(&socket_addr) {
            match mem::replace(routing_peer, State::Complete(pub_id)) {
                State::Network(peer) => {
                    let conn_info = peer.into_connection_info(socket_addr);
                    let _ = self.routing_to_network.insert(pub_id, conn_info.clone());
                    Ok(conn_info)
                }
                State::Routing(_) => Self::invalid_state(),
                State::Complete(_) => Err(ConnectionError::AlreadyConnected),
            }
        } else {
            Self::invalid_state()
        }
    }

    // Handles received `ConnectionRequest` message.
    pub fn handle_connection_request(
        &mut self,
        pub_id: PublicId,
        node_info: NodeInfo,
    ) -> Result<(), ConnectionError> {
        match self.network_to_routing.entry(node_info.peer_addr) {
            Entry::Vacant(entry) => {
                let _ = entry.insert(State::Routing(pub_id));
                let _ = self
                    .routing_to_network
                    .insert(pub_id, ConnectionInfo::Node { node_info });
                Err(ConnectionError::Incomplete)
            }
            Entry::Occupied(mut entry) => {
                match mem::replace(entry.get_mut(), State::Routing(pub_id)) {
                    State::Network(peer) => {
                        *entry.get_mut() = State::Complete(pub_id);
                        let conn_info = peer.into_connection_info(node_info.peer_addr);
                        let _ = self.routing_to_network.insert(pub_id, conn_info);
                        Ok(())
                    }
                    State::Routing(_) => Err(ConnectionError::Incomplete),
                    State::Complete(old_pub_id) => {
                        *entry.get_mut() = State::Complete(old_pub_id);
                        Err(ConnectionError::AlreadyConnected)
                    }
                }
            }
        }
    }

    // Removes the peer. If we were connected to the peer, returns its `Peer` info. Otherwise
    // returns `None`.
    pub fn remove(&mut self, pub_id: &PublicId) -> Option<ConnectionInfo> {
        if let Some(conn_info) = self.routing_to_network.remove(pub_id) {
            let _ = self.network_to_routing.remove(&conn_info.peer_addr());
            Some(conn_info)
        } else {
            None
        }
    }

    // Removes all peers. Returns an iterator over the `Peer` infos of the removed peers.
    pub fn remove_all<'a>(&'a mut self) -> impl Iterator<Item = ConnectionInfo> + 'a {
        self.network_to_routing.clear();
        self.routing_to_network
            .drain()
            .map(|(_, conn_info)| conn_info)
    }

    // Get connection info of the peer with the given public id.
    pub fn get_connection_info<'a>(&'a self, pub_id: &PublicId) -> Option<&'a ConnectionInfo> {
        self.routing_to_network.get(pub_id)
    }

    fn invalid_state<T>() -> Result<T, ConnectionError> {
        log_or_panic!(
            LogLevel::Error,
            "Received DirectMessage from peer not connected at the network layer."
        );
        Err(ConnectionError::Incomplete)
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub enum ConnectionError {
    // Connection is incomplete. That is, the network-layer connection is established, but we don't
    // know the peer's public id yet, or we do know the id, but the network-layer connection is not
    // yet established
    Incomplete,
    // Connection is already fully established
    AlreadyConnected,
}

enum State {
    // Connected at network layer.
    Network(PeerType),
    // Identified at routing layer.
    Routing(PublicId),
    // Connected and identified at both layers.
    Complete(PublicId),
}

enum PeerType {
    Client,
    Node { peer_cert_der: Vec<u8> },
}

impl From<ConnectionInfo> for PeerType {
    fn from(conn_info: ConnectionInfo) -> Self {
        match conn_info {
            ConnectionInfo::Client { .. } => PeerType::Client,
            ConnectionInfo::Node {
                node_info: NodeInfo { peer_cert_der, .. },
            } => PeerType::Node { peer_cert_der },
        }
    }
}

impl PeerType {
    fn into_connection_info(self, peer_addr: SocketAddr) -> ConnectionInfo {
        match self {
            PeerType::Client => ConnectionInfo::Client { peer_addr },
            PeerType::Node { peer_cert_der } => ConnectionInfo::Node {
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
    fn connected_to_then_direct_message() {
        let mut peer_map = PeerMap::new();

        let conn_info = conn_info("198.51.100.0:5555");
        let socket_addr = conn_info.peer_addr();
        let pub_id = *FullId::new().public_id();

        assert_eq!(
            peer_map.handle_connected_to(conn_info.clone()),
            Err(ConnectionError::Incomplete)
        );

        assert_eq!(
            peer_map.handle_direct_message(pub_id, socket_addr),
            Ok(conn_info)
        );
    }

    #[test]
    fn connected_to_then_multiple_direct_messages() {
        let mut peer_map = PeerMap::new();

        let conn_info = conn_info("198.51.100.0:5555");
        let socket_addr = conn_info.peer_addr();
        let pub_id = *FullId::new().public_id();

        assert_eq!(
            peer_map.handle_connected_to(conn_info.clone()),
            Err(ConnectionError::Incomplete)
        );

        assert_eq!(
            peer_map.handle_direct_message(pub_id, socket_addr),
            Ok(conn_info)
        );
        assert_eq!(
            peer_map.handle_direct_message(pub_id, socket_addr),
            Err(ConnectionError::AlreadyConnected)
        );
        assert_eq!(
            peer_map.handle_direct_message(pub_id, socket_addr),
            Err(ConnectionError::AlreadyConnected)
        );
    }

    #[test]
    fn connected_to_then_connection_failure() {
        let mut peer_map = PeerMap::new();

        let conn_info = conn_info("198.51.100.0:5555");
        let socket_addr = conn_info.peer_addr();

        assert_eq!(
            peer_map.handle_connected_to(conn_info),
            Err(ConnectionError::Incomplete)
        );
        assert!(peer_map.handle_connection_failure(socket_addr).is_none());
    }

    #[test]
    #[should_panic(expected = "DirectMessage from peer not connected at the network layer")]
    fn direct_message_only() {
        let mut peer_map = PeerMap::new();

        let conn_info = conn_info("198.51.100.0:5555");
        let socket_addr = conn_info.peer_addr();
        let pub_id = *FullId::new().public_id();

        let _ = peer_map.handle_direct_message(pub_id, socket_addr);
    }

    #[test]
    fn connection_request_then_connected_to() {
        let mut peer_map = PeerMap::new();

        let node_info = node_info("198.51.100.0:5555");
        let pub_id = *FullId::new().public_id();

        assert_eq!(
            peer_map.handle_connection_request(pub_id, node_info.clone()),
            Err(ConnectionError::Incomplete)
        );
        assert_eq!(
            peer_map.handle_connected_to(ConnectionInfo::Node { node_info }),
            Ok(pub_id)
        );
    }

    #[test]
    fn connected_to_then_connect_request() {
        let mut peer_map = PeerMap::new();

        let node_info = node_info("198.51.100.0:5555");
        let pub_id = *FullId::new().public_id();

        assert_eq!(
            peer_map.handle_connected_to(ConnectionInfo::Node {
                node_info: node_info.clone()
            }),
            Err(ConnectionError::Incomplete)
        );
        assert_eq!(
            peer_map.handle_connection_request(pub_id, node_info),
            Ok(())
        );
    }

    // TODO: cover edge cases

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
