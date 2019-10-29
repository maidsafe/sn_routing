// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{id::PublicId, xor_name::XorName, ConnectionInfo};
use fxhash::{FxHashMap as HashMap, FxHashSet as HashSet};
use std::{collections::hash_map::Entry, net::SocketAddr};

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
    forward: HashMap<XorName, ConnectionInfo>,
    reverse: HashMap<SocketAddr, HashSet<PublicId>>,
    pending: HashMap<SocketAddr, PendingConnection>,
    clients: HashSet<SocketAddr>,
}

impl PeerMap {
    pub fn new() -> Self {
        Self::default()
    }

    // Marks the connection as established at the network layer.
    // TODO: remove this `allow` when https://github.com/rust-lang/rust-clippy/issues/4219
    // is fixed and stabilized.
    #[allow(clippy::map_entry)]
    pub fn connect(&mut self, conn_info: ConnectionInfo) {
        let socket_addr = conn_info.peer_addr;
        if !self.reverse.contains_key(&socket_addr) {
            let _ = self
                .pending
                .insert(socket_addr, PendingConnection::from(conn_info));
        }
    }

    // Marks the connection as severed at the network layer. Returns an iterator over all the
    // public ids associated with that connection, if any.
    pub fn disconnect(&mut self, socket_addr: SocketAddr) -> Vec<PublicId> {
        let _ = self.pending.remove(&socket_addr);
        let removed_pub_ids: Vec<_> = self
            .reverse
            .remove(&socket_addr)
            .into_iter()
            .flatten()
            .collect();

        for pub_id in &removed_pub_ids {
            let _ = self.forward.remove(pub_id.name());
        }

        removed_pub_ids
    }

    // Associate a network layer connection, that was previously established via `connect`, with
    // the peers public id.
    pub fn identify(&mut self, pub_id: PublicId, socket_addr: SocketAddr) {
        let forward = &mut self.forward;
        let (conn_info, pub_ids) = if let Some(pending) = self.pending.remove(&socket_addr) {
            (
                pending.into_connection_info(socket_addr),
                self.reverse.entry(socket_addr).or_default(),
            )
        } else if let Some(pub_ids) = self.reverse.get_mut(&socket_addr) {
            if let Some(conn_info) = pub_ids
                .iter()
                .next()
                .and_then(|other_id| forward.get(other_id.name()))
            {
                (conn_info.clone(), pub_ids)
            } else {
                return;
            }
        } else {
            return;
        };

        let _ = forward.insert(*pub_id.name(), conn_info);
        let _ = pub_ids.insert(pub_id);
    }

    // Inserts a new entry into the peer map. This is equivalent to calling `connect` followed by
    // `identify` and can be used when we obtain both the public id and the connection info at the
    // same time (for example when a third party sends them to us).
    pub fn insert(&mut self, pub_id: PublicId, conn_info: ConnectionInfo) {
        let _ = self.pending.remove(&conn_info.peer_addr);
        let _ = self
            .reverse
            .entry(conn_info.peer_addr)
            .or_default()
            .insert(pub_id);
        let _ = self.forward.insert(*pub_id.name(), conn_info);
    }

    // Removes the peer. If we were connected to the peer, returns its connection info. Otherwise
    // returns `None`.
    pub fn remove(&mut self, pub_id: &PublicId) -> Option<ConnectionInfo> {
        let conn_info = self.forward.remove(pub_id.name())?;

        if let Entry::Occupied(mut entry) = self.reverse.entry(conn_info.peer_addr) {
            let _ = entry.get_mut().remove(pub_id);
            if entry.get().is_empty() {
                let _ = entry.remove();
                return Some(conn_info);
            }
        }

        None
    }

    // Removes all peers. Returns an iterator over the connection infos of the removed peers.
    pub fn remove_all<'a>(&'a mut self) -> impl Iterator<Item = ConnectionInfo> + 'a {
        self.reverse.clear();
        self.forward.drain().map(|(_, conn_info)| conn_info).chain(
            self.pending
                .drain()
                .map(|(socket_addr, pending)| pending.into_connection_info(socket_addr)),
        )
    }

    // Get connection info of the peer with the given public id.
    pub fn get_connection_info<N: AsRef<XorName>>(&self, name: N) -> Option<&ConnectionInfo> {
        self.forward.get(name.as_ref())
    }

    // Get PublicId for XorName
    pub fn get_id(&self, name: &XorName) -> Option<&PublicId> {
        self.forward
            .get(name)
            .and_then(|conn_info| self.reverse.get(&conn_info.peer_addr))
            .and_then(|pub_ids| pub_ids.iter().find(|pub_id| pub_id.name() == name))
    }

    // Returns an iterator over the public IDs of connected peers
    pub fn connected_ids(&self) -> impl Iterator<Item = &PublicId> {
        self.reverse.values().flatten()
    }

    // Returns `true` if we have the connection info for a given public ID
    pub fn has<N: AsRef<XorName>>(&self, name: N) -> bool {
        self.forward.contains_key(name.as_ref())
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

struct PendingConnection {
    peer_cert_der: Vec<u8>,
}

impl From<ConnectionInfo> for PendingConnection {
    fn from(conn_info: ConnectionInfo) -> Self {
        Self {
            peer_cert_der: conn_info.peer_cert_der,
        }
    }
}

impl PendingConnection {
    fn into_connection_info(self, peer_addr: SocketAddr) -> ConnectionInfo {
        ConnectionInfo {
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
        assert_eq!(outcome, vec![pub_id]);
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

    fn connection_info(addr: &str) -> ConnectionInfo {
        let peer_addr: SocketAddr = unwrap!(addr.parse());
        ConnectionInfo {
            peer_addr,
            peer_cert_der: vec![],
        }
    }
}
