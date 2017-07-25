// Copyright 2015 MaidSafe.net limited.
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

// This is used two ways: inline tests, and integration tests (with use-mock-crust).
// There's no point configuring each item which is only used in one of these.
#![cfg(any(test, feature = "use-mock-crust"))]
#![allow(dead_code, missing_docs)]

use super::{Error, RoutingTable};
use super::authority::Authority;
use super::prefix::Prefix;
use maidsafe_utilities::SeededRng;
use rand::Rng;
use routing_table::{OwnMergeState, Sections};
use routing_table::xorable::Xorable;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Binary, Debug};
use std::hash::Hash;
use std::iter::IntoIterator;

/// A simulated network, consisting of a set of "nodes" (routing tables) and a random number
/// generator.
#[derive(Default)]
struct Network {
    min_section_size: usize,
    rng: SeededRng,
    nodes: BTreeMap<u64, RoutingTable<u64>>,
}

impl Network {
    /// Creates a new empty network with specified minimum section size and a seeded random number
    /// generator.
    fn new(min_section_size: usize, optional_seed: Option<[u32; 4]>) -> Network {
        Network {
            min_section_size: min_section_size,
            rng: optional_seed.map_or_else(SeededRng::new, SeededRng::from_seed),
            nodes: BTreeMap::new(),
        }
    }

    /// Get min_section_size
    pub fn min_section_size(&self) -> usize {
        self.min_section_size
    }

    /// Adds a new node to the network and makes it join its new section, splitting if necessary.
    fn add_node(&mut self) {
        let name = self.random_free_name(); // The new node's name.
        if self.nodes.is_empty() {
            // If this is the first node, just add it and return.
            let result = self.nodes.insert(
                name,
                RoutingTable::new(name, self.min_section_size),
            );
            assert!(result.is_none());
            return;
        }

        let mut new_table = RoutingTable::new(name, self.min_section_size);
        {
            let close_node = self.close_node(name);
            let close_peer = &self.nodes[&close_node];
            unwrap!(
                new_table.add_prefixes(
                    close_peer
                        .all_sections()
                        .into_iter()
                        .map(|(pfx, (version, _))| pfx.with_version(version))
                        .collect(),
                )
            );
        }

        let mut split_prefixes = BTreeSet::new();
        for node in self.nodes.values_mut() {
            if let Err(e) = node.add(name) {
                trace!("failed to add node with error {:?}", e);
            }
            if node.should_split() {
                let _ = split_prefixes.insert(node.our_versioned_prefix());
            }
            if let Err(e) = new_table.add(*node.our_name()) {
                trace!("failed to add node into new with error {:?}", e);
            }
            if new_table.should_split() {
                let ver_pfx = new_table.our_versioned_prefix();
                let _ = split_prefixes.insert(ver_pfx);
                let _ = new_table.split(ver_pfx);
            }
        }

        assert!(self.nodes.insert(name, new_table).is_none());
        for &ver_pfx in &split_prefixes {
            for node in self.nodes.values_mut() {
                let _ = node.split(ver_pfx);
            }
        }
    }

    fn store_merge_info<T: PartialEq + Debug>(
        merge_info: &mut BTreeMap<Prefix<u64>, T>,
        prefix: Prefix<u64>,
        new_info: T,
    ) {
        if let Some(content) = merge_info.get(&prefix) {
            assert_eq!(new_info, *content);
            return;
        }
        let _ = merge_info.insert(prefix, new_info);
    }

    // TODO: remove this when https://github.com/Manishearth/rust-clippy/issues/1279 is resolved
    #[cfg_attr(feature = "cargo-clippy", allow(for_kv_map))]
    /// Drops a node and, if necessary, merges sections to restore the section requirement.
    fn drop_node(&mut self) {
        let keys = self.keys();
        let name = *unwrap!(self.rng.choose(&keys));
        let _ = self.nodes.remove(&name);
        let mut merge_own_info: BTreeMap<Prefix<u64>, Sections<u64>> = BTreeMap::new();
        // TODO: needs to verify how to broadcasting such info
        for node in self.nodes.values_mut() {
            if node.iter().any(|&name_in_table| name_in_table == name) {
                let removed_node_is_in_our_section = node.is_in_our_section(&name);
                let removal_details = unwrap!(node.remove(&name));
                assert_eq!(name, removal_details.name);
                assert_eq!(
                    removed_node_is_in_our_section,
                    removal_details.was_in_our_section
                );
                if node.should_merge() {
                    let info = node.all_sections();
                    Network::store_merge_info(&mut merge_own_info, *node.our_prefix(), info);
                }
            } else {
                match node.remove(&name) {
                    Err(Error::NoSuchPeer) => {}
                    Err(error) => panic!("Expected NoSuchPeer, but got {:?}", error),
                    Ok(details) => panic!("Expected NoSuchPeer, but got {:?}", details),
                }
            }
        }

        let mut expected_peers = BTreeMap::new();
        while !merge_own_info.is_empty() {
            let mut merge_other_info = BTreeMap::new();
            // handle broadcast of merge_own_section
            let own_info = merge_own_info;
            merge_own_info = BTreeMap::new();
            for (sender_pfx, sections) in own_info {
                let nodes = self.nodes_covered_by_prefixes(&[sender_pfx.sibling()]);
                for node in &nodes {
                    let target_node = unwrap!(self.nodes.get_mut(node));
                    let node_expected = expected_peers.entry(*node).or_insert_with(BTreeSet::new);
                    for (_, &(_, ref section)) in &sections {
                        node_expected.extend(section.iter().filter(|name| !target_node.has(name)));
                    }
                    let merge_pfx = sender_pfx.popped();
                    let version = sections
                        .iter()
                        .filter(|&(pfx, _)| pfx.is_extension_of(&merge_pfx))
                        .map(|(_, &(v, _))| v + 1)
                        .max();
                    let merge_ver_pfx = merge_pfx.with_version(unwrap!(version));
                    let ver_pfxs = sections.iter().map(|(pfx, &(v, _))| pfx.with_version(v));
                    match target_node.merge_own_section(merge_ver_pfx, ver_pfxs) {
                        OwnMergeState::AlreadyMerged => (),
                        OwnMergeState::Completed {
                            targets,
                            versioned_prefix,
                            section,
                        } => {
                            Network::store_merge_info(
                                &mut merge_other_info,
                                *target_node.our_prefix(),
                                (targets, versioned_prefix, section),
                            );
                            // Forcibly add new connections.
                            for name in node_expected.clone() {
                                // Try adding each node we should be connected to.
                                // Ignore failures and ignore splits.
                                if let Err(e) = target_node.add(name) {
                                    panic!("Error adding node: {:?}", e);
                                }
                                node_expected.remove(&name);
                            }
                            if node_expected.is_empty() && target_node.should_merge() {
                                Network::store_merge_info(
                                    &mut merge_own_info,
                                    *target_node.our_prefix(),
                                    target_node.all_sections(),
                                );
                            }
                        }
                    }
                }
            }

            // handle broadcast of merge_other_section
            for (_, (target_prefixes, ver_pfx, section)) in merge_other_info {
                let targets = self.nodes_covered_by_prefixes(&target_prefixes);
                for target in targets {
                    let target_node = unwrap!(self.nodes.get_mut(&target));
                    let contacts = target_node.merge_other_section(ver_pfx, section.clone());
                    // add missing contacts
                    for contact in contacts {
                        let _ = target_node.add(contact);
                    }
                    if target_node.should_merge() {
                        Network::store_merge_info(
                            &mut merge_own_info,
                            *target_node.our_prefix(),
                            target_node.all_sections(),
                        );
                    }
                }
            }
        }
    }

    fn nodes_covered_by_prefixes<'a, T>(&self, prefixes: T) -> Vec<u64>
    where
        T: IntoIterator<Item = &'a Prefix<u64>> + Copy,
    {
        self.nodes
            .keys()
            .filter(|&name| {
                prefixes.into_iter().any(|prefix| prefix.matches(name))
            })
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
    fn send_message(&self, src: u64, dst: Authority<u64>, route: usize) {
        let mut received = Vec::new(); // These nodes have received but not handled the message.
        let mut handled = BTreeSet::new(); // These nodes have received and handled the message.
        received.push(src);
        while let Some(node) = received.pop() {
            handled.insert(node); // `node` is now handling the message and relaying it.
            for target in unwrap!(self.nodes[&node].targets(&dst, src, route)) {
                if !handled.contains(&target) && !received.contains(&target) {
                    received.push(target);
                }
            }
        }
        if dst.is_single() {
            assert!(
                handled.contains(&dst.name()),
                "Message to {:?} only handled by {:?}",
                dst,
                handled
            );
        } else {
            let close_node = self.close_node(dst.name());
            for node in unwrap!(self.nodes[&close_node].close_names(&dst.name())) {
                assert!(handled.contains(&node));
            }
        }
    }

    /// Returns any node that's close to the given address. Panics if the network is empty or no
    /// node is found.
    fn close_node(&self, address: u64) -> u64 {
        let target = Authority::Section(address);
        unwrap!(
            self.nodes
                .iter()
                .find(|&(_, table)| table.in_authority(&target))
                .map(|(&peer, _)| peer)
        )
    }

    /// Returns all node names.
    fn keys(&self) -> Vec<u64> {
        self.nodes.keys().cloned().collect()
    }
}

#[test]
fn node_to_node_message() {
    let mut network = Network::new(8, None);
    for _ in 0..100 {
        network.add_node();
    }
    let keys = network.keys();
    for _ in 0..20 {
        let src = *unwrap!(network.rng.choose(&keys));
        let dst = *unwrap!(network.rng.choose(&keys));
        for route in 0..network.min_section_size {
            network.send_message(src, Authority::ManagedNode(dst), route);
        }
    }
}

#[test]
fn node_to_section_message() {
    let mut network = Network::new(8, None);
    for _ in 0..100 {
        network.add_node();
    }
    let keys = network.keys();
    for _ in 0..20 {
        let src = *unwrap!(network.rng.choose(&keys));
        let dst = network.rng.gen();
        for route in 0..network.min_section_size {
            network.send_message(src, Authority::Section(dst), route);
        }
    }
}

fn verify_invariant(network: &Network) {
    verify_network_invariant(network.nodes.values());
}

pub fn verify_network_invariant<'a, T, U>(nodes: U)
where
    T: Binary + Clone + Copy + Debug + Default + Hash + Xorable + 'a,
    U: IntoIterator<Item = &'a RoutingTable<T>>,
{
    let mut sections: BTreeMap<Prefix<T>, _> = BTreeMap::new();
    // first, collect all sections in the network
    for node in nodes {
        node.verify_invariant();
        for prefix in node.prefixes() {
            let section_content = if prefix == node.our_prefix {
                (node.our_version, node.our_section.clone())
            } else {
                node.sections[&prefix].clone()
            };
            if let Some(&mut (ref mut src, ref mut section)) = sections.get_mut(&prefix) {
                assert_eq!(
                    *section,
                    section_content,
                    "Section with prefix {:?} doesn't agree between nodes {:?} and {:?}\n\
                            {:?}: {:?}, {:?}: {:?}",
                    prefix,
                    node.our_name,
                    src,
                    node.our_name,
                    section_content,
                    src,
                    section
                );
                continue;
            }
            let _ = sections.insert(prefix, (node.our_name, section_content));
        }
    }
    // check that prefixes are disjoint
    for prefix1 in sections.keys() {
        for prefix2 in sections.keys() {
            if prefix1 == prefix2 {
                continue;
            }
            if prefix1.is_compatible(prefix2) {
                panic!(
                    "Section prefixes should be disjoint, but these are not:\n\
                    Section {:?}, according to node {:?}: {:?}\n\
                    Section {:?}, according to node {:?}: {:?}",
                    prefix1,
                    sections[prefix1].0,
                    sections[prefix1].1,
                    prefix2,
                    sections[prefix2].0,
                    sections[prefix2].1
                );
            }
        }
    }

    // check that each section contains names agreeing with its prefix
    for (prefix, &(_, (_, ref data))) in &sections {
        for name in data {
            if !prefix.matches(name) {
                panic!(
                    "Section members should match the prefix, but {:?} \
                    does not match {:?}",
                    name,
                    prefix
                );
            }
        }
    }

    // check that sections cover the whole namespace
    assert!(Prefix::default().is_covered_by(sections.keys()));
}

#[test]
fn sections_have_identical_routing_tables() {
    let mut network = Network::new(8, None);
    for _ in 0..100 {
        network.add_node();
        verify_invariant(&network);
    }
}

#[test]
fn merging_sections() {
    let mut network = Network::new(8, None);
    for _ in 0..100 {
        network.add_node();
        verify_invariant(&network);
    }
    assert!(network.nodes.iter().all(
        |(_, table)| if table.num_of_sections() <
            2
        {
            trace!("{:?}", table);
            false
        } else {
            true
        },
    ));
    for _ in 0..95 {
        network.drop_node();
        verify_invariant(&network);
    }
    assert!(network.nodes.iter().all(
        |(_, table)| if table.num_of_sections() >
            0
        {
            trace!("{:?}", table);
            false
        } else {
            true
        },
    ));
}
