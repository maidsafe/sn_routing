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

use super::{create_connected_nodes_until_split, poll_all, poll_and_resend,
            verify_invariant_for_all_nodes};
use fake_clock::FakeClock;
use rand::Rng;
use routing::{Event, EventStream, Prefix, XOR_NAME_LEN, XorName};
use routing::mock_crust::Network;
use routing::test_consts::ACK_TIMEOUT_SECS;
use std::collections::{BTreeMap, BTreeSet};

// See docs for `create_connected_nodes_with_cache_until_split` for details on `prefix_lengths`.
fn merge(prefix_lengths: Vec<usize>) {
    let min_section_size = 8;
    let network = Network::new(min_section_size, None);
    let mut rng = network.new_rng();
    let mut nodes = create_connected_nodes_until_split(&network, prefix_lengths, false);
    verify_invariant_for_all_nodes(&mut nodes);

    // Drop nodes from a section with the shortest prefix until we get a merge event for the empty
    // prefix.
    let mut min_prefix = *nodes[0].routing_table().our_prefix();
    loop {
        rng.shuffle(&mut nodes);
        let mut index = nodes.len();
        for (i, node) in nodes.iter().enumerate() {
            let this_prefix = *node.routing_table().our_prefix();
            if this_prefix.bit_count() < min_prefix.bit_count() {
                min_prefix = this_prefix;
                index = i;
                break;
            } else if this_prefix == min_prefix {
                index = i;
            }
        }

        let removed = nodes.remove(index);
        drop(removed);
        poll_and_resend(&mut nodes, &mut []);
        let mut merge_events_missing = nodes.len();
        for node in &mut *nodes {
            while let Ok(event) = node.try_next_ev() {
                match event {
                    Event::NodeAdded(..) |
                    Event::NodeLost(..) |
                    Event::Tick => (),
                    Event::SectionMerge(prefix) => {
                        if prefix.bit_count() == 0 {
                            merge_events_missing -= 1;
                        }
                    }
                    event => panic!("{} got unexpected event: {:?}", node.name(), event),
                }
            }
        }
        verify_invariant_for_all_nodes(&mut nodes);
        if merge_events_missing == 0 {
            return;
        }
    }
}

#[test]
fn merge_three_sections_into_one() {
    merge(vec![1, 2, 2])
}

#[test]
fn merge_four_unbalanced_sections_into_one() {
    merge(vec![1, 2, 3, 3])
}

#[test]
fn merge_four_balanced_sections_into_one() {
    merge(vec![2, 2, 2, 2])
}

#[test]
fn merge_five_sections_into_one() {
    merge(vec![1, 3, 3, 3, 3])
}

#[test]
fn concurrent_merge() {
    let min_section_size = 5;
    let network = Network::new(min_section_size, None);
    let mut rng = network.new_rng();
    let mut nodes = create_connected_nodes_until_split(&network, vec![2, 2, 2, 2], false);
    verify_invariant_for_all_nodes(&mut nodes);
    rng.shuffle(&mut nodes);

    // Choose two sections to drop nodes from, one of `00`/`01` and the other one of `10`/`11`.
    let prefix_0_to_drop_from = Prefix::new(1, XorName([0; XOR_NAME_LEN])).pushed(rng.gen());
    let prefix_1_to_drop_from = Prefix::new(1, XorName([255; XOR_NAME_LEN])).pushed(rng.gen());

    // Create a map with <section, number of members> as key/value for these two sections.
    let mut section_map = BTreeMap::new();
    for node in nodes.iter() {
        let prefix = *node.routing_table().our_prefix();
        if prefix == prefix_0_to_drop_from || prefix == prefix_1_to_drop_from {
            *section_map.entry(prefix).or_insert(0) += 1;
        }
    }

    // Drop enough nodes (without polling) from each of the two sections to take them just below
    // `min_section_size`.
    for (prefix, len) in &mut section_map {
        while *len >= min_section_size {
            let index = unwrap!(nodes.iter().position(|node| {
                node.routing_table().our_prefix() == prefix
            }));
            let removed = nodes.remove(index);
            drop(removed);
            *len -= 1;
        }
    }

    // Poll the nodes, check the invariant and ensure the network has merged to `0` and `1`.
    poll_and_resend(&mut nodes, &mut []);
    verify_invariant_for_all_nodes(&mut nodes);
    let mut prefixes = BTreeSet::new();
    for node in nodes.iter() {
        prefixes.insert(*node.routing_table().our_prefix());
    }
    assert_eq!(prefixes.len(), 2);
}

#[test]
fn merge_exclude_reconnecting_peers() {
    let min_section_size = 3;
    let network = Network::new(min_section_size, None);
    let mut rng = network.new_rng();
    let mut nodes = create_connected_nodes_until_split(&network, vec![1, 1], false);
    verify_invariant_for_all_nodes(&mut nodes);
    rng.shuffle(&mut nodes);

    // Choose one section to drop nodes from.
    let prefix_to_drop_from = Prefix::new(1, XorName([0; XOR_NAME_LEN]));

    let mut nodes_count = nodes
        .iter()
        .filter(|node| {
            node.routing_table().our_prefix() == &prefix_to_drop_from
        })
        .count();

    // Drop enough nodes (without polling) from that section to just below `min_section_size`.
    while nodes_count >= min_section_size {
        let index = unwrap!(nodes.iter().position(|node| {
            node.routing_table().our_prefix() == &prefix_to_drop_from
        }));
        let removed = nodes.remove(index);
        drop(removed);
        nodes_count -= 1;
    }

    // Poll the nodes, check the invariant and ensure the network has merged to `()`.
    for _ in 0..min_section_size {
        poll_all(&mut nodes, &mut []);
        FakeClock::advance_time(ACK_TIMEOUT_SECS * 1000 + 1);
    }
    poll_all(&mut nodes, &mut []);

    verify_invariant_for_all_nodes(&mut nodes);
    let mut prefixes = BTreeSet::new();
    for node in nodes.iter() {
        prefixes.insert(*node.routing_table().our_prefix());
    }
    assert_eq!(prefixes.len(), 1, "prefixes: {:?}", prefixes);
}
