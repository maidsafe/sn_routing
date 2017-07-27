// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use id::PublicId;
use itertools::Itertools;
use message_filter::MessageFilter;
use std::collections::{BTreeSet, HashMap};
use std::collections::hash_map::Entry;
use std::time::Duration;

/// The maximum number of pairs of nodes that this node will act as a tunnel for.
const MAX_TUNNEL_CLIENT_PAIRS: usize = 40;

/// A container for managing tunnel connections.
///
/// The Kademlia routing scheme requires specific nodes to be directly connected to each other,
/// which may not always be possible due to e. g. NAT devices. Tunnel nodes act as proxies in these
/// cases, relaying messages between the two nodes in a way that is transparent to the rest of the
/// routing logic.
pub struct Tunnels {
    /// Maps the peer we failed to directly connect to to the one that acts as a tunnel.
    tunnels: HashMap<PublicId, PublicId>,
    /// Contains peers that are looking for a tunnel, with the lower ID first. Only once it sends
    /// a message to the latter via us, the pair is moved to `clients`.
    new_clients: MessageFilter<(PublicId, PublicId)>,
    /// Contains all pairs of names we act as a tunnel node for, with the lower ID first.
    clients: BTreeSet<(PublicId, PublicId)>,
}

impl Tunnels {
    /// Returns `true` if we are acting as a tunnel for the given clients.
    pub fn has_clients(&self, src_id: PublicId, dst_id: PublicId) -> bool {
        if src_id < dst_id {
            self.clients.contains(&(src_id, dst_id))
        } else {
            self.clients.contains(&(dst_id, src_id))
        }
    }

    /// Returns the ordered pair if the given client pair is eligible for tunnelling. If that is
    /// the case, adds them to the `new_clients` map.
    pub fn consider_clients(
        &mut self,
        src_id: PublicId,
        dst_id: PublicId,
    ) -> Option<(PublicId, PublicId)> {
        if self.clients.len() >= MAX_TUNNEL_CLIENT_PAIRS || self.tunnels.contains_key(&src_id) ||
            self.tunnels.contains_key(&dst_id)
        {
            return None;
        }
        let (id0, id1) = if src_id < dst_id {
            (src_id, dst_id)
        } else {
            (dst_id, src_id)
        };
        let _ = self.new_clients.insert(&(id0, id1));
        Some((id0, id1))
    }

    /// Returns `true` if the given client pair can be made permanent, and does so.
    ///
    /// `consider_clients` must be called with the client pair before this.
    pub fn accept_clients(&mut self, src_id: PublicId, dst_id: PublicId) -> bool {
        let pair = (src_id, dst_id);
        if self.new_clients.contains(&pair) {
            self.new_clients.remove(&pair);
            self.clients.insert(pair);
            true
        } else {
            false
        }
    }

    /// Removes all pairs with the given client and returns a list of all clients that used us as a
    /// tunnel for them.
    pub fn drop_client(&mut self, pub_id: &PublicId) -> Vec<PublicId> {
        let pairs = self.clients
            .iter()
            .filter(|pair| pair.0 == *pub_id || pair.1 == *pub_id)
            .cloned()
            .collect_vec();
        pairs
            .into_iter()
            .map(|pair| {
                self.clients.remove(&pair);
                if pair.0 == *pub_id { pair.1 } else { pair.0 }
            })
            .collect()
    }

    /// Removes the pair matching `src_id` and `dst_id` from our tunnel clients
    pub fn drop_client_pair(&mut self, src_id: PublicId, dst_id: PublicId) -> bool {
        let (id0, id1) = if src_id < dst_id {
            (src_id, dst_id)
        } else {
            (dst_id, src_id)
        };

        self.clients.remove(&(id0, id1))
    }

    /// Adds the given `tunnel_id` as a tunnel to `dst_id` if one is needed, otherwise returns
    /// `false`.
    pub fn add(&mut self, dst_id: PublicId, tunnel_id: PublicId) -> bool {
        match self.tunnels.entry(dst_id) {
            Entry::Occupied(_) => false,
            Entry::Vacant(entry) => {
                let _ = entry.insert(tunnel_id);
                true
            }
        }
    }

    /// Removes the given tunnel to the given destination, and return whether it was present.
    pub fn remove(&mut self, dst_id: PublicId, tunnel_id: PublicId) -> bool {
        if let Entry::Occupied(entry) = self.tunnels.entry(dst_id) {
            if entry.get() == &tunnel_id {
                let _ = entry.remove();
                return true;
            }
        }
        false
    }

    /// Removes and the peer that is acting as a tunnel for the given peer, if any.
    pub fn remove_tunnel_for(&mut self, dst_id: &PublicId) -> Option<PublicId> {
        self.tunnels.remove(dst_id)
    }

    /// Is the given `tunnel_id` acting as a tunnel node?
    pub fn is_tunnel_node(&self, tunnel_id: &PublicId) -> bool {
        self.tunnels.values().any(|id| id == tunnel_id)
    }

    /// Removes the given tunnel node and returns a list of all peers it was acting as a tunnel
    /// for.
    pub fn remove_tunnel(&mut self, tunnel_id: &PublicId) -> Vec<PublicId> {
        let dst_ids = self.tunnels
            .iter()
            .filter(|&(_, id)| id == tunnel_id)
            .map(|(&dst_id, _)| dst_id)
            .collect_vec();
        for dst_id in &dst_ids {
            let _ = self.tunnels.remove(dst_id);
        }
        dst_ids
    }

    /// Returns the peer that is acting as a tunnel to the given peer, if any.
    pub fn tunnel_for(&self, dst_id: &PublicId) -> Option<&PublicId> {
        self.tunnels.get(dst_id)
    }

    /// Returns the number of client pairs we are acting as a tunnel for.
    pub fn client_count(&self) -> usize {
        self.clients.len()
    }

    /// Returns the number of peers we are indirectly connected to via a tunnel.
    pub fn tunnel_count(&self) -> usize {
        self.tunnels.len()
    }
}

impl Default for Tunnels {
    fn default() -> Tunnels {
        Tunnels {
            tunnels: HashMap::new(),
            new_clients: MessageFilter::with_expiry_duration(Duration::from_secs(60)),
            clients: BTreeSet::new(),
        }
    }
}

#[cfg(all(test, feature = "use-mock-crust"))]
mod tests {
    use super::*;
    use id::FullId;
    use itertools::Itertools;

    #[test]
    fn tunnel_nodes_test() {
        let our_id = *FullId::new().public_id();
        let their_id = *FullId::new().public_id();
        let mut tunnels: Tunnels = Default::default();
        assert_eq!(None, tunnels.tunnel_for(&our_id));
        // Peer 1 is acting as a tunnel for peer 0.
        tunnels.add(our_id, their_id);
        assert_eq!(Some(&their_id), tunnels.tunnel_for(&our_id));
        assert_eq!(None, tunnels.tunnel_for(&their_id));
        tunnels.remove(our_id, their_id);
        assert_eq!(None, tunnels.tunnel_for(&our_id));
    }

    #[test]
    fn remove_tunnel_test() {
        let mut sorted_ids = vec![];
        for _ in 0..5 {
            sorted_ids.push(*FullId::new().public_id());
        }
        sorted_ids.sort();

        let mut tunnels: Tunnels = Default::default();
        // Peer 0 is acting as a tunnel for 1 and 2, but not 3.
        tunnels.add(sorted_ids[1], sorted_ids[0]);
        tunnels.add(sorted_ids[2], sorted_ids[0]);
        tunnels.add(sorted_ids[3], sorted_ids[4]);
        let removed_peers = tunnels.remove_tunnel(&sorted_ids[0]).into_iter().sorted();
        assert_eq!(&[sorted_ids[1], sorted_ids[2]], &*removed_peers);
        assert_eq!(None, tunnels.tunnel_for(&sorted_ids[1]));
        assert_eq!(None, tunnels.tunnel_for(&sorted_ids[2]));
        assert_eq!(Some(&sorted_ids[4]), tunnels.tunnel_for(&sorted_ids[3]));
    }

    #[test]
    fn clients_test() {
        let mut sorted_ids = vec![];
        for _ in 0..6 {
            sorted_ids.push(*FullId::new().public_id());
        }
        sorted_ids.sort();

        let mut tunnels: Tunnels = Default::default();
        // We are directly connected to 1, but not 0.
        tunnels.add(sorted_ids[0], sorted_ids[1]);
        // consider_clients has not been called yet.
        assert!(!tunnels.accept_clients(sorted_ids[1], sorted_ids[2]));
        assert!(!tunnels.accept_clients(sorted_ids[3], sorted_ids[4]));
        // Reject 0 as client, as we are not directly connected to them.
        assert_eq!(None, tunnels.consider_clients(sorted_ids[5], sorted_ids[0]));
        assert_eq!(
            Some((sorted_ids[1], sorted_ids[2])),
            tunnels.consider_clients(sorted_ids[1], sorted_ids[2])
        );
        assert_eq!(
            Some((sorted_ids[3], sorted_ids[4])),
            tunnels.consider_clients(sorted_ids[4], sorted_ids[3])
        );
        assert!(tunnels.accept_clients(sorted_ids[1], sorted_ids[2]));
        assert!(tunnels.accept_clients(sorted_ids[3], sorted_ids[4]));
        assert!(tunnels.has_clients(sorted_ids[2], sorted_ids[1]));
        assert!(tunnels.has_clients(sorted_ids[3], sorted_ids[4]));
    }
}
