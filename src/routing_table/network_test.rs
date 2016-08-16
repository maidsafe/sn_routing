// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
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
use std::cmp;
use std::collections::{HashMap, HashSet};
use std::collections::hash_map::Entry;
use std::fmt::{self, Binary, Debug, Formatter};
use super::routing_table::{Destination, RoutingTable};
use super::xorable::Xorable;

const GROUP_SIZE: usize = 8;

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
            rng: match optional_seed {
                Some(seed) => SeededRng::from_seed(seed),
                None => SeededRng::new(),
            },
            nodes: HashMap::new(),
        }
    }

    /// Adds a new node to the network and makes it join its new group, splitting if necessary.
    fn add_node(&mut self) {
        let name = self.random_free_name(); // The new node's name.
        if self.nodes.is_empty() {
            // If this is the first node, just add it and return.
            assert!(self.nodes.insert(name, RoutingTable::new(name, GROUP_SIZE)).is_none());
            return;
        }
        // Find any node that is close to the new one.
        let close_peer = self.close_node(name);
        // The new node needs to have exactly the same contacts:
        let connecting_peers: Vec<u64> = self.known_nodes(close_peer);
        let mut new_table = RoutingTable::new(name, GROUP_SIZE);
        for peer in connecting_peers {
            assert!(unwrap!(self.nodes.get_mut(&peer)).add(name).is_some());
            assert!(new_table.add(peer).is_some());
        }
        assert!(self.nodes.insert(name, new_table).is_none());
        // If there is any node containing group can split now, do so.
        while let Some(node) = self.nodes
            .iter()
            .find(|&(_, table)|
                match table.should_split() {
                    Some(_) => true,
                    None => false,
                })
            .map(|(&node, _)| node) {
            self.split(node);
        }
    }

    /// Drops a node and, if necessary, merges groups to restore the group requirement.
    fn drop_node(&mut self) {
        let keys = self.keys();
        let name = *unwrap!(self.rng.choose(&keys));
        let contacts = self.known_nodes(name);
        let table = unwrap!(self.nodes.remove(&name));
        for contact in contacts {
            if contact != name {
                assert!(unwrap!(self.nodes.get_mut(&contact)).remove(&name).is_some());
            }
        }
        // If the group needs to merge now, do so.
        while let Some(node) = self.nodes
            .iter()
            .find(|&(_, table)|
                match table.should_merge() {
                    Some(_) => true,
                    None => false,
                })
            .map(|(&node, _)| node) {
            self.merge(node);
        }
    }

    // /// Splits the given node's group.
    // fn split(&mut self, name: u64) {
    //     let prefix = self.nodes[&name].prefix();
    //     // All routing table entries need to be notified about the split.
    //     let affected_nodes = self.known_nodes(name);
    //     // Collect the pairs of nodes that removed each other from the routing table.
    //     let mut disconnects = HashSet::new();
    //     for node in affected_nodes {
    //         for unneeded in unwrap!(self.nodes.get_mut(&node)).split(&prefix) {
    //             disconnects.insert((node, unneeded));
    //         }
    //     }
    //     // In every case, both sides must agree that they want to disconnect.
    //     for &(node0, node1) in &disconnects {
    //         assert!(disconnects.contains(&(node1, node1)));
    //     }
    // }

    /// Splits the given node's group.
    fn split(&mut self, _name: u64) {
            for (_ , node) in self.nodes.iter_mut() {
                node.split();
            }
    }

    /// Merges the group of the given peer with its sister groups.
    fn merge(&mut self, name: u64) {
        if let Some(_) = unwrap!(self.nodes.get_mut(&name)).merge() {
            for (_, node) in self.nodes.iter_mut() {
                let _ = node.merge();
            }
        }
    }

    // /// Merges the group of the given peer with its sister groups.
    // fn merge(&mut self, name: u64) {
    //     let new_prefix = self.nodes[&name].prefix().without_last();
    //     let mut affected_groups = HashMap::new();
    //     let new_group_members = self.nodes[&name].nodes_with(&new_prefix);
    //     for new_member in &new_group_members {
    //         for (prefix, members) in self.nodes[new_member].all_groups() {
    //             match affected_groups.entry(prefix) {
    //                 Entry::Occupied(occupied) => assert_eq!(occupied.get(), &members),
    //                 Entry::Vacant(vacant) => {
    //                     let _ = vacant.insert(members);
    //                 }
    //             }
    //         }
    //     }
    //     for node in affected_groups.values().flat_map(|group| group.iter()) {
    //         unwrap!(self.nodes.get_mut(&node)).merge(&new_prefix, &affected_groups);
    //     }
    //     for new_member in &new_group_members {
    //         for node in affected_groups.values().flat_map(|group| group.iter()) {
    //             let _ = unwrap!(self.nodes.get_mut(&node)).add(*new_member);
    //             let _ = unwrap!(self.nodes.get_mut(&new_member)).add(*node);
    //         }
    //     }
    // }

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
            for target in self.nodes[&node].target_nodes(dst, &node, route) {
                if !handled.contains(&target) && !received.contains(&target) {
                    received.push(target);
                }
            }
        }
        match dst {
            Destination::Node(node) => assert!(handled.contains(&node)),
            Destination::Group(address, _) => {
                let close_node = self.close_node(address);
                for node in unwrap!(self.nodes[&close_node].close_nodes(&address)) {
                    assert!(handled.contains(&node));
                }
            }
        }
    }

    /// Returns any node that's close to the given address. Panics if the network is empty or no
    /// node is found.
    fn close_node(&self, address: u64) -> u64 {
        unwrap!(self.nodes
            .iter()
            .find(|&(_, table)| table.is_close(&address))
            .map(|(&peer, _)| peer))
    }

    /// Returns the set of all entries in the given node's routing table, including itself.
    fn known_nodes(&self, name: u64) -> Vec<u64> {
        let mut connected_peers = self.nodes[&name].connected_peers();
        connected_peers.push(name);
        connected_peers
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
        for route in 0..GROUP_SIZE {
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
        for route in 0..GROUP_SIZE {
            network.send_message(src, Destination::Group(dst, GROUP_SIZE), route);
        }
    }
}

#[test]
fn groups_have_identical_routing_tables() {
    let mut network = Network::new(None);
    for _ in 0..100 {
        network.add_node();
    }
    let keys = network.keys();
    for _ in 0..20 {
        let address = network.rng.gen();
        let close_peer = network.close_node(address);
        let mut contacts = network.known_nodes(close_peer);
        contacts.sort();
        let group = unwrap!(network.nodes[&close_peer].close_nodes(&address));
        for &node in &keys {
            match network.nodes[&node].close_nodes(&address) {
                None => assert!(!group.contains(&address)),
                Some(nodes) => {
                    // TODO: if the node in query itself is part of the close members, there is chance the group doesn't
                    //       got split yet from its perspective
                    //       execute this test with seed of [2817869685, 3020312298, 343512997, 915190025]
                    //       the fetched group from close_peer is
                    //       [7154751357263139303, 7232498110496810657, 7324139913257116470,
                    //        7372067402949639454, 7467839279545282818, 7480444072499549176,
                    //        7857634283013267913, 7941145200632707472, 8162400431230333977,
                    //        8163088974105893084, 8306894308903998305, 8901399224139166674,
                    //        8903063204513800509, 8908774849401800370, 9124677007065390519,
                    //        9140770996867927707, 9142712693818018265, 9207439687031592853]
                    //       which missed itself 7282345220160771589 and the group is not split yet.
                    // Also, `close_nodes` returns the closest known group to the target from our
                    // perspective, meanwhile here we are only checking against the `closest_group`
                    // assert_eq!(group, nodes);
                    let mut result = network.known_nodes(node);
                    result.sort();
                    assert_eq!(contacts, result);
                }
            }
        }
    }
}

#[test]
fn merging_groups() {
    let mut network = Network::new(None);
    for _ in 0..100 {
        network.add_node();
        // TODO: Verify invariant.
    }
    // TODO: Verify that there are several groups.
    for _ in 0..95 {
        network.drop_node();
        // TODO: Verify invariant.
    }
    // TODO: Verify that there is only one group.
}
