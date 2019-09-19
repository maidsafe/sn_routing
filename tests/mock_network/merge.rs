// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    count_sections, create_connected_nodes_until_split, current_sections, poll_and_resend,
    verify_invariant_for_all_nodes, TestNode,
};
use itertools::Itertools;
use rand::Rng;
use routing::{mock::Network, Event, EventStream, Prefix, XorName, XOR_NAME_LEN};

// See docs for `create_connected_nodes_with_cache_until_split` for details on `prefix_lengths`.
fn merge(prefix_lengths: Vec<usize>) {
    let min_section_size = 4;
    let network = Network::new(min_section_size, None);
    let mut rng = network.new_rng();
    let mut nodes = create_connected_nodes_until_split(&network, prefix_lengths, false);
    verify_invariant_for_all_nodes(&network, &mut nodes);

    // Drop nodes from a section with the shortest prefix until we get a merge event for the empty
    // prefix.
    let mut min_prefix = *nodes[0].our_prefix();
    loop {
        warn!("Current Prefixes: {:?}", current_sections(&nodes));
        rng.shuffle(&mut nodes);
        let mut index = nodes.len();
        for (i, node) in nodes.iter().enumerate() {
            let this_prefix = *node.our_prefix();
            if this_prefix.bit_count() < min_prefix.bit_count() {
                min_prefix = this_prefix;
                index = i;
                break;
            } else if this_prefix == min_prefix {
                index = i;
            }
        }

        let removed = nodes.remove(index);
        warn!(
            "Dropped: {}. Current Prefixes: {:?}",
            removed.name(),
            current_sections(&nodes)
        );
        drop(removed);
        poll_and_resend(&mut nodes);
        let mut merge_events_missing = nodes.len();
        for node in &mut *nodes {
            while let Ok(event) = node.try_next_ev() {
                match event {
                    Event::NodeAdded(..) | Event::NodeLost(..) | Event::TimerTicked => (),
                    Event::SectionMerged(prefix) => {
                        if prefix.is_empty() {
                            merge_events_missing -= 1;
                        }
                    }
                    event => panic!("{} got unexpected event: {:?}", node.name(), event),
                }
            }
        }
        verify_invariant_for_all_nodes(&network, &mut nodes);
        if merge_events_missing == 0 {
            return;
        }
    }
}

#[test]
#[ignore]
fn merge_three_sections_into_one() {
    merge(vec![1, 2, 2])
}

#[test]
#[ignore]
fn merge_four_unbalanced_sections_into_one() {
    merge(vec![1, 2, 3, 3])
}

#[test]
#[ignore]
fn merge_four_balanced_sections_into_one() {
    merge(vec![2, 2, 2, 2])
}

#[test]
#[ignore]
fn merge_five_sections_into_one() {
    merge(vec![1, 3, 3, 3, 3])
}

#[test]
#[ignore]
fn concurrent_merge() {
    let min_section_size = 4;
    let network = Network::new(min_section_size, None);
    let mut rng = network.new_rng();
    let mut nodes = create_connected_nodes_until_split(&network, vec![2, 2, 2, 3, 3], false);
    verify_invariant_for_all_nodes(&network, &mut nodes);
    rng.shuffle(&mut nodes);

    // Choose two random sections to drop nodes from:
    // Not sibling sections as we would only merge 2 sections instead of 4.
    // Not one without sibling as this section would merge with 2 other sections.
    //
    // This setup also allows testing concurrent merges where one of the merging section is not
    // a neighbour of either of the other two merging sections.
    let prefixes_to_drop_from = {
        let mut sections = current_sections(&nodes).into_iter().collect_vec();
        rng.shuffle(&mut sections);

        let any_sibling = |others: &[Prefix<XorName>], prefix: &Prefix<XorName>| {
            others.iter().any(|p| p.sibling() == *prefix)
        };
        sections
            .iter()
            .enumerate()
            .filter(|(idx, prefix)| {
                !any_sibling(&sections[0..*idx], prefix) && any_sibling(&sections[0..], prefix)
            })
            .map(|(_, prefix)| prefix)
            .take(2)
            .cloned()
            .collect_vec()
    };

    // Shrink the two sections to exactly `min_section_size`.
    for pfx in &prefixes_to_drop_from {
        let len = nodes.iter().filter(|node| node.our_prefix() == pfx).count();
        for _ in min_section_size..len {
            let index = unwrap!(nodes.iter().position(|node| node.our_prefix() == pfx));
            drop(nodes.remove(index));
            poll_and_resend(&mut nodes);
        }
    }

    // No sections should have merged yet.
    assert_eq!(count_sections(&nodes), 5);

    // Drop one more node (without polling) from each of the two sections to take them just below
    // `min_section_size`.
    for pfx in &prefixes_to_drop_from {
        let index = unwrap!(nodes.iter().position(|node| node.our_prefix() == pfx));
        drop(nodes.remove(index));
    }

    // Poll the nodes, check the invariant and ensure the network has merged to 3 sections.
    poll_and_resend(&mut nodes);
    verify_invariant_for_all_nodes(&network, &mut nodes);
    assert_eq!(count_sections(&nodes), 3);
}

#[test]
#[ignore]
fn merge_drop_multiple_nodes() {
    let min_section_size = 7;
    let nodes_to_drop = (min_section_size - 1) / 3;
    assert!(
        nodes_to_drop > 1,
        "min_section_size needs to be large enough to drop multiple nodes"
    );
    let network = Network::new(min_section_size, None);
    let mut rng = network.new_rng();
    let mut nodes = create_connected_nodes_until_split(&network, vec![1, 1], false);
    verify_invariant_for_all_nodes(&network, &mut nodes);
    rng.shuffle(&mut nodes);

    // Choose one section to drop nodes from.
    let prefix_to_drop_from = Prefix::new(1, XorName([0; XOR_NAME_LEN]));
    let matches_prefix = |node: &TestNode| *node.our_prefix() == prefix_to_drop_from;

    // Bring down the section size to exactly `min_section_size`.
    let len = nodes.iter().filter(|n| matches_prefix(n)).count();
    for _ in min_section_size..len {
        let index = unwrap!(nodes.iter().position(matches_prefix));
        drop(nodes.remove(index));
        poll_and_resend(&mut nodes);
    }

    // The sections shouldn't have merged yet.
    assert_eq!(count_sections(&nodes), 2);

    // Drop multiple nodes (without polling) from that section to trigger the merge.
    for _ in 0..nodes_to_drop {
        let index = unwrap!(nodes.iter().position(matches_prefix));
        drop(nodes.remove(index));
    }

    poll_and_resend(&mut nodes);
    verify_invariant_for_all_nodes(&network, &mut nodes);
    assert_eq!(count_sections(&nodes), 1);
}
