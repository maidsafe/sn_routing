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

use itertools::Itertools;
use message_filter::MessageFilter;
use public_info::PublicInfo;
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
    tunnels: HashMap<PublicInfo, PublicInfo>,
    /// Contains peers that are looking for a tunnel, with the lower ID first. Only once it sends
    /// a message to the latter via us, the pair is moved to `clients`.
    new_clients: MessageFilter<(PublicInfo, PublicInfo)>,
    /// Contains all pairs of names we act as a tunnel node for, with the lower ID first.
    clients: BTreeSet<(PublicInfo, PublicInfo)>,
}

impl Tunnels {
    /// Returns `true` if we are acting as a tunnel for the given clients.
    pub fn has_clients(&self, src_info: PublicInfo, dst_info: PublicInfo) -> bool {
        if src_info < dst_info {
            self.clients.contains(&(src_info, dst_info))
        } else {
            self.clients.contains(&(dst_info, src_info))
        }
    }

    /// Returns the ordered pair if the given client pair is eligible for tunnelling. If that is
    /// the case, adds them to the `new_clients` map.
    pub fn consider_clients(
        &mut self,
        src_info: PublicInfo,
        dst_info: PublicInfo,
    ) -> Option<(PublicInfo, PublicInfo)> {
        if self.clients.len() >= MAX_TUNNEL_CLIENT_PAIRS || self.tunnels.contains_key(&src_info) ||
            self.tunnels.contains_key(&dst_info)
        {
            return None;
        }
        let (id0, id1) = if src_info < dst_info {
            (src_info, dst_info)
        } else {
            (dst_info, src_info)
        };
        let _ = self.new_clients.insert(&(id0, id1));
        Some((id0, id1))
    }

    /// Returns `true` if the given client pair can be made permanent, and does so.
    ///
    /// `consider_clients` must be called with the client pair before this.
    pub fn accept_clients(&mut self, src_info: PublicInfo, dst_info: PublicInfo) -> bool {
        let pair = (src_info, dst_info);
        if self.new_clients.contains(&pair) {
            self.new_clients.remove(&pair);
            let _fixme = self.clients.insert(pair);
            true
        } else {
            false
        }
    }

    /// Removes all pairs with the given client and returns a list of all clients that used us as a
    /// tunnel for them.
    pub fn drop_client(&mut self, pub_info: &PublicInfo) -> Vec<PublicInfo> {
        let pairs = self.clients
            .iter()
            .filter(|pair| pair.0 == *pub_info || pair.1 == *pub_info)
            .cloned()
            .collect_vec();
        pairs
            .into_iter()
            .map(|pair| {
                let _fixme = self.clients.remove(&pair);
                if pair.0 == *pub_info { pair.1 } else { pair.0 }
            })
            .collect()
    }

    /// Removes the pair matching `src_info` and `dst_info` from our tunnel clients
    pub fn drop_client_pair(&mut self, src_info: PublicInfo, dst_info: PublicInfo) -> bool {
        let (id0, id1) = if src_info < dst_info {
            (src_info, dst_info)
        } else {
            (dst_info, src_info)
        };

        self.clients.remove(&(id0, id1))
    }

    /// Adds the given `tunnel_info` as a tunnel to `dst_info` if one is needed, otherwise returns
    /// `false`.
    pub fn add(&mut self, dst_info: PublicInfo, tunnel_info: PublicInfo) -> bool {
        match self.tunnels.entry(dst_info) {
            Entry::Occupied(_) => false,
            Entry::Vacant(entry) => {
                let _ = entry.insert(tunnel_info);
                true
            }
        }
    }

    /// Removes the given tunnel to the given destination, and return whether it was present.
    pub fn remove(&mut self, dst_info: PublicInfo, tunnel_info: PublicInfo) -> bool {
        if let Entry::Occupied(entry) = self.tunnels.entry(dst_info) {
            if entry.get() == &tunnel_info {
                let _ = entry.remove();
                return true;
            }
        }
        false
    }

    /// Removes and the peer that is acting as a tunnel for the given peer, if any.
    pub fn remove_tunnel_for(&mut self, dst_info: &PublicInfo) -> Option<PublicInfo> {
        self.tunnels.remove(dst_info)
    }

    /// Is the given `tunnel_info` acting as a tunnel node?
    pub fn is_tunnel_node(&self, tunnel_info: &PublicInfo) -> bool {
        self.tunnels.values().any(|id| id == tunnel_info)
    }

    /// Removes the given tunnel node and returns a list of all peers it was acting as a tunnel
    /// for.
    pub fn remove_tunnel(&mut self, tunnel_info: &PublicInfo) -> Vec<PublicInfo> {
        let dst_infos = self.tunnels
            .iter()
            .filter(|&(_, id)| id == tunnel_info)
            .map(|(&dst_info, _)| dst_info)
            .collect_vec();
        for dst_info in &dst_infos {
            let _ = self.tunnels.remove(dst_info);
        }
        dst_infos
    }

    /// Returns the peer that is acting as a tunnel to the given peer, if any.
    pub fn tunnel_for(&self, dst_info: &PublicInfo) -> Option<&PublicInfo> {
        self.tunnels.get(dst_info)
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
    use full_info::FullInfo;
    use itertools::Itertools;

    #[test]
    fn tunnel_nodes_test() {
        let our_info = *FullInfo::node_new(1u8).public_info();
        let their_info = *FullInfo::node_new(1u8).public_info();
        let mut tunnels: Tunnels = Default::default();
        assert_eq!(None, tunnels.tunnel_for(&our_info));
        // Peer 1 is acting as a tunnel for peer 0.
        let _fixme = tunnels.add(our_info, their_info);
        assert_eq!(Some(&their_info), tunnels.tunnel_for(&our_info));
        assert_eq!(None, tunnels.tunnel_for(&their_info));
        let _fixme = tunnels.remove(our_info, their_info);
        assert_eq!(None, tunnels.tunnel_for(&our_info));
    }

    #[test]
    fn remove_tunnel_test() {
        let mut sorted_infos = vec![];
        for _ in 0..5 {
            sorted_infos.push(*FullInfo::node_new(1u8).public_info());
        }
        sorted_infos.sort();

        let mut tunnels: Tunnels = Default::default();
        // Peer 0 is acting as a tunnel for 1 and 2, but not 3.
        let _fixme = tunnels.add(sorted_infos[1], sorted_infos[0]);
        let _fixme = tunnels.add(sorted_infos[2], sorted_infos[0]);
        let _fixme = tunnels.add(sorted_infos[3], sorted_infos[4]);
        let removed_peers = tunnels.remove_tunnel(&sorted_infos[0]).into_iter().sorted();
        assert_eq!(&[sorted_infos[1], sorted_infos[2]], &*removed_peers);
        assert_eq!(None, tunnels.tunnel_for(&sorted_infos[1]));
        assert_eq!(None, tunnels.tunnel_for(&sorted_infos[2]));
        assert_eq!(Some(&sorted_infos[4]), tunnels.tunnel_for(&sorted_infos[3]));
    }

    #[test]
    fn clients_test() {
        let mut sorted_infos = vec![];
        for _ in 0..6 {
            sorted_infos.push(*FullInfo::node_new(1u8).public_info());
        }
        sorted_infos.sort();

        let mut tunnels: Tunnels = Default::default();
        // We are directly connected to 1, but not 0.
        let _fixme = tunnels.add(sorted_infos[0], sorted_infos[1]);
        // consider_clients has not been called yet.
        assert!(!tunnels.accept_clients(sorted_infos[1], sorted_infos[2]));
        assert!(!tunnels.accept_clients(sorted_infos[3], sorted_infos[4]));
        // Reject 0 as client, as we are not directly connected to them.
        assert_eq!(
            None,
            tunnels.consider_clients(sorted_infos[5], sorted_infos[0])
        );
        assert_eq!(
            Some((sorted_infos[1], sorted_infos[2])),
            tunnels.consider_clients(sorted_infos[1], sorted_infos[2])
        );
        assert_eq!(
            Some((sorted_infos[3], sorted_infos[4])),
            tunnels.consider_clients(sorted_infos[4], sorted_infos[3])
        );
        assert!(tunnels.accept_clients(sorted_infos[1], sorted_infos[2]));
        assert!(tunnels.accept_clients(sorted_infos[3], sorted_infos[4]));
        assert!(tunnels.has_clients(sorted_infos[2], sorted_infos[1]));
        assert!(tunnels.has_clients(sorted_infos[3], sorted_infos[4]));
    }
}
