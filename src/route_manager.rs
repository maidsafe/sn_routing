// Copyright 2017 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.1.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use crust::PeerId;
use error::RoutingError;
use id::PublicId;
use peer_manager::{Peer, PeerManager};
use routing_table::{OtherMergeDetails, OwnMergeDetails, OwnMergeState, Prefix, RemovalDetails,
                    RoutingTable};
use routing_table::Error as RoutingTableError;
use std::{fmt, mem};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::time::{Duration, Instant};
use xor_name::XorName;

/// Time (in seconds) the node waits for connection from an expected node.
const NODE_CONNECT_TIMEOUT_SECS: u64 = 60;

pub type SectionMap = BTreeMap<Prefix<XorName>, BTreeSet<PublicId>>;

/// A container for information about other nodes in the network.
///
/// This keeps track of which nodes we know of, which ones we have tried to connect to, which IDs
/// we have verified, whom we are directly connected to or via a tunnel.
pub struct RouteManager {
    /// Peers we expect to connect to
    expected_peers: HashMap<XorName, Instant>,
    routing_table: RoutingTable<XorName>,
}

impl RouteManager {
    /// Returns a new routing table manager.
    pub fn new(min_section_size: usize, our_name: XorName) -> RouteManager {
        RouteManager {
            expected_peers: HashMap::new(),
            routing_table: RoutingTable::<XorName>::new(our_name, min_section_size),
        }
    }

    /// Clears the routing table and resets this node's public ID.
    pub fn reset_routing_table(&mut self, our_name: XorName) {
        if !self.routing_table.is_empty() {
            warn!("{:?} Reset to {:?} from non-empty routing table {:?}.",
                  self,
                  our_name,
                  self.routing_table)
        }

        let min_section_size = self.routing_table.min_section_size();
        self.routing_table = RoutingTable::new(our_name, min_section_size);
    }

    /// Add prefixes into routing table.
    pub fn add_prefixes(&mut self, prefixes: Vec<Prefix<XorName>>) -> Result<(), RoutingError> {
        Ok(self.routing_table.add_prefixes(prefixes)?)
    }

    /// Returns the routing table.
    pub fn routing_table(&self) -> &RoutingTable<XorName> {
        &self.routing_table
    }

    /// Notes that a new peer should be expected. This should only be called for peers not already
    /// in our routing table.
    pub fn expect_peer(&mut self, id: &PublicId) {
        let _ = self.expected_peers.insert(*id.name(), Instant::now());
    }

    /// Tries to add the given peer to the routing table. If successful, this returns `Ok(true)` if
    /// the addition should cause our section to split or `Ok(false)` if the addition shouldn't
    /// cause a split.
    pub fn add_to_routing_table(&mut self, pub_id: &PublicId) -> Result<bool, RoutingTableError> {
        let _ = self.expected_peers.remove(pub_id.name());

        let should_split = self.routing_table.add(*pub_id.name())?;
        Ok(should_split)
    }

    /// Splits the indicated section and returns the `PeerId`s of any peers to which we should not
    /// remain connected.
    pub fn split_section(&mut self,
                         peer_mgr: &mut PeerManager,
                         prefix: Prefix<XorName>)
                         -> (Vec<(XorName, PeerId)>, Option<Prefix<XorName>>) {
        let (names_to_drop, our_new_prefix) = self.routing_table.split(prefix);
        for name in &names_to_drop {
            info!("{:?} Dropped {:?} from the routing table.", self, name);
        }

        let ids_to_drop = peer_mgr.split_section(self.routing_table.our_prefix(), names_to_drop);

        let old_expected_peers = mem::replace(&mut self.expected_peers, HashMap::new());
        self.expected_peers = old_expected_peers.into_iter()
            .filter(|&(ref name, _)| self.routing_table.need_to_add(name) == Ok(()))
            .collect();

        (ids_to_drop, our_new_prefix)
    }

    /// Adds the given prefix to the routing table, splitting or merging as necessary. Returns the
    /// list of peers that have been dropped and need to be disconnected.
    pub fn add_prefix(&mut self,
                      peer_mgr: &mut PeerManager,
                      prefix: Prefix<XorName>)
                      -> Vec<(XorName, PeerId)> {
        let names_to_drop = self.routing_table.add_prefix(prefix);
        let old_expected_peers = mem::replace(&mut self.expected_peers, HashMap::new());
        self.expected_peers = old_expected_peers.into_iter()
            .filter(|&(ref name, _)| self.routing_table.need_to_add(name) == Ok(()))
            .collect();
        peer_mgr.add_prefix(names_to_drop)
    }

    /// Wraps `RoutingTable::should_merge` with an extra check.
    ///
    /// Returns sender prefix, merge prefix, then sections.
    pub fn should_merge(&self,
                        peer_mgr: &PeerManager)
                        -> Option<(Prefix<XorName>, Prefix<XorName>, SectionMap)> {
        if !self.routing_table.they_want_to_merge() && !self.expected_peers.is_empty() {
            return None;
        }
        self.routing_table.should_merge().map(|merge_details| {
            let sections = merge_details.sections
                .into_iter()
                .map(|(prefix, members)| {
                    (prefix, peer_mgr.get_pub_ids(&members).into_iter().collect())
                })
                .collect();
            (merge_details.sender_prefix, merge_details.merge_prefix, sections)
        })
    }

    // Returns the `OwnMergeState` from `RoutingTable` which defines what further action needs to be
    // taken by the node, and the list of peers to which we should now connect (only those within
    // the merging sections for now).
    pub fn merge_own_section(&mut self,
                             sender_prefix: Prefix<XorName>,
                             merge_prefix: Prefix<XorName>,
                             sections: SectionMap)
                             -> (OwnMergeState<XorName>, Vec<PublicId>) {
        let needed = sections.iter()
            .flat_map(|(_, pub_ids)| pub_ids)
            .filter(|pub_id| !self.routing_table.has(pub_id.name()))
            .cloned()
            .collect();

        let sections_as_names = sections.into_iter()
            .map(|(prefix, members)| {
                (prefix, members.into_iter().map(|pub_id| *pub_id.name()).collect::<BTreeSet<_>>())
            })
            .collect();

        let own_merge_details = OwnMergeDetails {
            sender_prefix: sender_prefix,
            merge_prefix: merge_prefix,
            sections: sections_as_names,
        };
        let mut expected_peers = mem::replace(&mut self.expected_peers, HashMap::new());
        expected_peers.extend(own_merge_details.sections
            .values()
            .flat_map(|section| section.iter())
            .filter_map(|name| if self.routing_table.has(name) {
                None
            } else {
                Some((*name, Instant::now()))
            }));
        self.expected_peers = expected_peers;
        (self.routing_table.merge_own_section(own_merge_details), needed)
    }

    pub fn merge_other_section(&mut self,
                               prefix: Prefix<XorName>,
                               section: BTreeSet<PublicId>)
                               -> HashSet<PublicId> {
        let merge_details = OtherMergeDetails {
            prefix: prefix,
            section: section.iter().map(|public_id| *public_id.name()).collect(),
        };
        let needed_names = self.routing_table.merge_other_section(merge_details);
        self.expected_peers.extend(needed_names.iter().map(|name| (*name, Instant::now())));
        section.into_iter().filter(|pub_id| needed_names.contains(pub_id.name())).collect()
    }

    /// Removes timed out expected peers (those we tried to connect to).
    pub fn remove_expired_expected(&mut self) {
        let mut expired_expected = Vec::new();
        for (name, timestamp) in &self.expected_peers {
            if timestamp.elapsed() >= Duration::from_secs(NODE_CONNECT_TIMEOUT_SECS) {
                expired_expected.push(*name);
            }
        }
        for name in expired_expected {
            let _ = self.expected_peers.remove(&name);
        }
    }

    /// Are we expecting a connection from this name?
    pub fn is_expected(&self, name: &XorName) -> bool {
        self.expected_peers.contains_key(name)
    }

    /// Clear all expected peers
    #[cfg(feature = "use-mock-crust")]
    pub fn clear_expected(&mut self) {
        self.expected_peers.clear();
    }

    /// Returns `Ok(())` if the given peer is not yet in the routing table but is allowed to
    /// connect.
    pub fn allow_connect(&self, name: &XorName) -> Result<(), RoutingTableError> {
        self.routing_table.need_to_add(name)
    }

    /// Removes the given entry, returns the removed peer and if it was a routing node,
    /// the removal details
    pub fn remove_peer(&mut self,
                       peer_mgr: &mut PeerManager,
                       peer_id: &PeerId)
                       -> Option<(Peer, Result<RemovalDetails<XorName>, RoutingTableError>)> {
        if let Some(peer) = peer_mgr.remove_peer_from_map(peer_id) {
            let removal_details = self.routing_table.remove(peer.name());
            Some((peer, removal_details))
        } else {
            None
        }
    }

    /// Returns the public IDs of all routing table entries, sorted by section.
    pub fn pub_ids_by_section(&self, peer_mgr: &PeerManager) -> SectionMap {
        self.routing_table
            .all_sections()
            .into_iter()
            .map(|(prefix, names)| (prefix, peer_mgr.get_pub_ids(&names)))
            .collect()
    }
}

impl fmt::Debug for RouteManager {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter,
               "Node({}({:b}))",
               self.routing_table.our_name(),
               self.routing_table.our_prefix())
    }
}
