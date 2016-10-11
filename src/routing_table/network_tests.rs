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

#![cfg(test)]

use maidsafe_utilities::SeededRng;
use rand::Rng;
use std::collections::{BTreeSet, HashMap, HashSet};
use super::{Destination, Error, RoutingTable};

const MIN_GROUP_SIZE: usize = 8;

#[derive(Clone, Eq, PartialEq)]
struct Contact(u64);

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

        let mut new_table = RoutingTable::new(name, MIN_GROUP_SIZE);
        let mut split_prefix = BTreeSet::new();
        // TODO: needs to verify how to broadcasting such info
        for node in self.nodes.values_mut() {
            match node.add(name) {
                Ok(result) => {
                    split_prefix.insert(result);
                }
                Err(e) => trace!("failed to add node with error {:?}", e),
            }
            match new_table.add(*node.our_name()) {
                Ok(Some(prefix)) => {
                    let _ = new_table.split(prefix);
                }
                Ok(None) => {}
                Err(e) => trace!("failed to add node into new with error {:?}", e),
            }
        }
        assert!(self.nodes.insert(name, new_table).is_none());
        for split in &split_prefix {
            if let Some(prefix) = *split {
                for node in self.nodes.values_mut() {
                    let _ = node.split(prefix);
                }
            }
        }
    }

    /// Drops a node and, if necessary, merges groups to restore the group requirement.
    fn drop_node(&mut self) {
        let keys = self.keys();
        let name = *unwrap!(self.rng.choose(&keys));
        let _ = self.nodes.remove(&name);
        // TODO: needs to verify how to broadcasting such info
        for node in self.nodes.values_mut() {
            if node.iter().any(|&name_in_table| name_in_table == name) {
                let removed_node_is_in_our_group = node.is_in_our_group(&name);
                let removal_details = unwrap!(node.remove(&name));
                assert_eq!(name, removal_details.name);
                assert_eq!(removed_node_is_in_our_group,
                           removal_details.was_in_our_group);
                match removal_details.targets_and_merge_details {
                    // TODO: shall a panic be raised in case of failure?
                    None => {}
                    Some((_targets, own_merge_details)) => {
                        let _ = node.merge_own_group(&own_merge_details);
                    }
                }
            } else {
                match node.remove(&name) {
                    Err(Error::NoSuchPeer) => {}
                    Err(error) => panic!("Expected NoSuchPeer, but got {:?}", error),
                    Ok(details) => panic!("Expected NoSuchPeer, but got {:?}", details),
                }
            }
        }
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
                for target in unwrap!(self.nodes[&node].targets(&dst, route)) {
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

fn verify_invariant(network: &mut Network) {
    let keys = network.keys();
    for _ in 0..20 {
        let address = network.rng.gen();
        let close_peer = network.close_node(address);
        let group = unwrap!(network.nodes[&close_peer].close_names(&address));
        for &node in &keys {
            match network.nodes[&node].close_names(&address) {
                None => assert!(!group.contains(&address)),
                Some(nodes) => {
                    if network.nodes[&node].is_recipient(&Destination::Group(address)) {
                        assert_eq!(group, nodes);
                    } else {
                        for candidate in &group {
                            assert!(nodes.contains(&candidate));
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn groups_have_identical_routing_tables() {
    let mut network = Network::new(None);
    for _ in 0..100 {
        network.add_node();
    }
    verify_invariant(&mut network);
}

#[test]
fn merging_groups() {
    let mut network = Network::new(None);
    for i in 0..100 {
        network.add_node();
        if i % 5 == 0 {
            verify_invariant(&mut network);
        }
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
        // if i % 5 == 0 {
        //     verify_invariant(&mut network);
        // }
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
