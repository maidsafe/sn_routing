// Copyright 2015 MaidSafe.net limited.
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

// This is used two ways: inline tests, and integration tests (with use-mock-crust).
// There's no point configuring each item which is only used in one of these.
#![cfg(any(test, feature = "use-mock-crust"))]
#![allow(unused, missing_docs)]

use super::{Destination, Error, RoutingTable};
use super::prefix::Prefix;
use MIN_GROUP_SIZE;
use maidsafe_utilities::SeededRng;
use rand::Rng;
use routing_table::{Iter, OtherMergeDetails, OwnMergeDetails, OwnMergeState};
use routing_table::xorable::Xorable;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt::{Binary, Debug};
use std::hash::Hash;
use std::iter::IntoIterator;

type OwnMergeInfo = (BTreeSet<Prefix<u64>>, OwnMergeDetails<u64>);
type OtherMergeInfo = (BTreeSet<Prefix<u64>>, OtherMergeDetails<u64>);

/// A simulated network, consisting of a set of "nodes" (routing tables) and a random number
/// generator.
#[derive(Default)]
struct Network {
    rng: SeededRng,
    nodes: HashMap<u64, RoutingTable<u64>>,
}

impl Network {
    /// Creates a new empty network with a seeded random number generator.
    fn new(optional_seed: Option<[u32; 4]>) -> Network {
        Network {
            rng: optional_seed.map_or_else(SeededRng::new, SeededRng::from_seed),
            nodes: HashMap::new(),
        }
    }

    /// Adds a new node to the network and makes it join its new group, splitting if necessary.
    fn add_node(&mut self) {
        let name = self.random_free_name(); // The new node's name.
        if self.nodes.is_empty() {
            // If this is the first node, just add it and return.
            assert!(self.nodes.insert(name, RoutingTable::new(name, MIN_GROUP_SIZE)).is_none());
            return;
        }

        let mut new_table = {
            let close_node = self.close_node(name);
            let close_peer = &self.nodes[&close_node];
            unwrap!(RoutingTable::new_with_groups(name,
                                                  MIN_GROUP_SIZE,
                                                  close_peer.prefixes()
                                                      .into_iter()
                                                      .map(|prefix| (prefix, None))))
        };

        let mut split_prefixes = BTreeSet::new();
        // TODO: needs to verify how to broadcasting such info
        for node in self.nodes.values_mut() {
            match node.add(name) {
                Ok(true) => {
                    split_prefixes.insert(*node.our_group_prefix());
                }
                Ok(false) => {}
                Err(e) => trace!("failed to add node with error {:?}", e),
            }
            match new_table.add(*node.our_name()) {
                Ok(true) => {
                    let prefix = *new_table.our_group_prefix();
                    let _ = new_table.split(prefix);
                }
                Ok(false) => {}
                Err(e) => trace!("failed to add node into new with error {:?}", e),
            }
        }
        assert!(self.nodes.insert(name, new_table).is_none());
        for split_prefix in &split_prefixes {
            for node in self.nodes.values_mut() {
                let _ = node.split(*split_prefix);
            }
        }
    }

    fn store_merge_info<T: PartialEq + Debug>(merge_info: &mut HashMap<Prefix<u64>, T>,
                                              prefix: Prefix<u64>,
                                              new_info: T) {
        if let Some(content) = merge_info.get(&prefix) {
            assert_eq!(new_info, *content);
            return;
        }
        let _ = merge_info.insert(prefix, new_info);
    }

    // TODO: remove this when https://github.com/Manishearth/rust-clippy/issues/1279 is resolved
    #[cfg_attr(feature="clippy", allow(for_kv_map))]
    /// Drops a node and, if necessary, merges groups to restore the group requirement.
    fn drop_node(&mut self) {
        let keys = self.keys();
        let name = *unwrap!(self.rng.choose(&keys));
        let _ = self.nodes.remove(&name);
        let mut merge_own_info: HashMap<Prefix<u64>, OwnMergeInfo> = HashMap::new();
        // TODO: needs to verify how to broadcasting such info
        for node in self.nodes.values_mut() {
            if node.iter().any(|&name_in_table| name_in_table == name) {
                let removed_node_is_in_our_group = node.is_in_our_group(&name);
                let removal_details = unwrap!(node.remove(&name));
                assert_eq!(name, removal_details.name);
                assert_eq!(removed_node_is_in_our_group,
                           removal_details.was_in_our_group);
                if let Some(info) = removal_details.targets_and_merge_details {
                    Network::store_merge_info(&mut merge_own_info, *node.our_group_prefix(), info);
                }
            } else {
                match node.remove(&name) {
                    Err(Error::NoSuchPeer) => {}
                    Err(error) => panic!("Expected NoSuchPeer, but got {:?}", error),
                    Ok(details) => panic!("Expected NoSuchPeer, but got {:?}", details),
                }
            }
        }

        while !merge_own_info.is_empty() {
            let mut merge_other_info: HashMap<Prefix<u64>, OtherMergeInfo> = HashMap::new();
            // handle broadcast of merge_own_group
            let own_info = merge_own_info;
            merge_own_info = HashMap::new();
            for (_, (target_prefixes, merge_own_details)) in own_info {
                let targets = self.nodes_covered_by_prefixes(&target_prefixes);
                for target in targets {
                    let target_node = unwrap!(self.nodes.get_mut(&target));
                    match target_node.merge_own_group(merge_own_details.clone()) {
                        OwnMergeState::Initialised { targets, merge_details } => {
                            Network::store_merge_info(&mut merge_own_info,
                                                      *target_node.our_group_prefix(),
                                                      (targets, merge_details));
                        }
                        OwnMergeState::Ongoing |
                        OwnMergeState::AlreadyMerged => (),
                        OwnMergeState::Completed { targets, merge_details } => {
                            Network::store_merge_info(&mut merge_other_info,
                                                      *target_node.our_group_prefix(),
                                                      (targets, merge_details));
                            // add needed contacts
                            let needed = target_node.needed().clone();
                            for needed_contact in needed.iter().flat_map(Iter::iterate) {
                                let _ = target_node.add(*needed_contact);
                            }
                        }
                    }
                }
            }

            // handle broadcast of merge_other_group
            for (_, (target_prefixes, merge_other_details)) in merge_other_info {
                let targets = self.nodes_covered_by_prefixes(&target_prefixes);
                for target in targets {
                    let target_node = unwrap!(self.nodes.get_mut(&target));
                    let contacts = target_node.merge_other_group(merge_other_details.clone());
                    // add missing contacts
                    for contact in contacts {
                        let _ = target_node.add(contact);
                    }
                }
            }
        }
    }

    fn nodes_covered_by_prefixes(&self, prefixes: &BTreeSet<Prefix<u64>>) -> Vec<u64> {
        self.nodes
            .keys()
            .filter(|&name| prefixes.iter().any(|prefix| prefix.matches(name)))
            .cloned()
            .collect()
    }

    /// Returns a random name that is not taken by any node yet.
    fn random_free_name(&mut self) -> u64 {
        loop {
            let name = self.rng.gen();
            if !self.nodes.contains_key(&name) {
                return name;
            }
        }
    }

    /// Verifies that a message sent from node `src` would arrive at destination `dst` via the
    /// given `route`.
    fn send_message(&self, src: u64, dst: Destination<u64>, route: usize) {
        let mut received = Vec::new(); // These nodes have received but not handled the message.
        let mut handled = HashSet::new(); // These nodes have received and handled the message.
        received.push(src);
        while let Some(node) = received.pop() {
            handled.insert(node); // `node` is now handling the message and relaying it.
            if Destination::Node(node) != dst {
                for target in unwrap!(self.nodes[&node].targets(&dst, src, route)) {
                    if !handled.contains(&target) && !received.contains(&target) {
                        received.push(target);
                    }
                }
            }
        }
        match dst {
            Destination::Node(node) => assert!(handled.contains(&node)),
            Destination::Group(address) => {
                let close_node = self.close_node(address);
                for node in unwrap!(self.nodes[&close_node].close_names(&address)) {
                    assert!(handled.contains(&node));
                }
            }
        }
    }

    /// Returns any node that's close to the given address. Panics if the network is empty or no
    /// node is found.
    fn close_node(&self, address: u64) -> u64 {
        let target = Destination::Group(address);
        unwrap!(self.nodes
            .iter()
            .find(|&(_, table)| table.is_recipient(&target))
            .map(|(&peer, _)| peer))
    }

    /// Returns all node names.
    fn keys(&self) -> Vec<u64> {
        self.nodes.keys().cloned().collect()
    }
}

#[test]
fn node_to_node_message() {
    let mut network = Network::new(None);
    for _ in 0..100 {
        network.add_node();
    }
    let keys = network.keys();
    for _ in 0..20 {
        let src = *unwrap!(network.rng.choose(&keys));
        let dst = *unwrap!(network.rng.choose(&keys));
        for route in 0..MIN_GROUP_SIZE {
            network.send_message(src, Destination::Node(dst), route);
        }
    }
}

#[test]
fn node_to_group_message() {
    let mut network = Network::new(None);
    for _ in 0..100 {
        network.add_node();
    }
    let keys = network.keys();
    for _ in 0..20 {
        let src = *unwrap!(network.rng.choose(&keys));
        let dst = network.rng.gen();
        for route in 0..MIN_GROUP_SIZE {
            network.send_message(src, Destination::Group(dst), route);
        }
    }
}

fn verify_invariant(network: &Network) {
    verify_network_invariant(network.nodes.values());
}

pub fn verify_network_invariant<'a, T, U>(nodes: U)
    where T: Binary + Clone + Copy + Debug + Default + Hash + Xorable + 'a,
          U: IntoIterator<Item = &'a RoutingTable<T>>
{
    let mut groups: HashMap<Prefix<T>, (T, HashSet<T>)> = HashMap::new();
    // first, collect all groups in the network
    for node in nodes {
        for prefix in node.groups.keys() {
            let mut group_content = node.groups[prefix].clone();
            if *prefix == node.our_group_prefix {
                group_content.insert(*node.our_name());
            }
            if let Some(&mut (ref mut src, ref mut group)) = groups.get_mut(prefix) {
                assert!(*group == group_content,
                        "Group with prefix {:?} doesn't agree between nodes {:?} and {:?}\n\
                        {:?}: {:?}, {:?}: {:?}",
                        prefix,
                        node.our_name,
                        src,
                        node.our_name,
                        group_content,
                        src,
                        group);
                continue;
            }
            let _ = groups.insert(*prefix, (node.our_name, group_content));
        }
        node.verify_invariant();
    }
    // check that prefixes are disjoint
    for prefix1 in groups.keys() {
        for prefix2 in groups.keys() {
            if prefix1 == prefix2 {
                continue;
            }
            if prefix1.is_compatible(prefix2) {
                panic!("Group prefixes should be disjoint, but these are not:\n\
                    Group {:?}, according to node {:?}: {:?}\n\
                    Group {:?}, according to node {:?}: {:?}",
                       prefix1,
                       groups[prefix1].0,
                       groups[prefix1].1,
                       prefix2,
                       groups[prefix2].0,
                       groups[prefix2].1);
            }
        }
    }

    // check that each group contains names agreeing with its prefix
    for (prefix, data) in &groups {
        for name in &data.1 {
            if !prefix.matches(name) {
                panic!("Group members should match the prefix, but {:?} \
                    does not match {:?}",
                       name,
                       prefix);
            }
        }
    }

    // check that groups cover the whole namespace
    assert!(Prefix::<T>::new(0, Default::default()).is_covered_by(groups.keys()));
}

#[test]
fn groups_have_identical_routing_tables() {
    let mut network = Network::new(None);
    for _ in 0..100 {
        network.add_node();
    }
    verify_invariant(&network);
}

#[test]
fn merging_groups() {
    let mut network = Network::new(None);
    for _ in 0..100 {
        network.add_node();
        verify_invariant(&network);
    }
    assert!(network.nodes
        .iter()
        .all(|(_, table)| if table.num_of_groups() < 3 {
            trace!("{:?}", table);
            false
        } else {
            true
        }));
    for _ in 0..95 {
        network.drop_node();
        verify_invariant(&network);
    }
    assert!(network.nodes
        .iter()
        .all(|(_, table)| if table.num_of_groups() > 1 {
            trace!("{:?}", table);
            false
        } else {
            true
        }));
}
