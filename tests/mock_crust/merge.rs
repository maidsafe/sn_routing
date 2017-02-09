// Copyright 2016 MaidSafe.net limited.
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

use rand::Rng;
use routing::{Event, EventStream};
use routing::mock_crust::Network;
use super::{create_connected_nodes_until_split, poll_and_resend, verify_invariant_for_all_nodes};

// See docs for `create_connected_nodes_with_cache_until_split` for details on `prefix_lengths`.
fn merge(prefix_lengths: Vec<usize>) {
    let min_section_size = 8;
    let network = Network::new(min_section_size, None);
    let mut rng = network.new_rng();
    let mut nodes = create_connected_nodes_until_split(&network, prefix_lengths, false);
    verify_invariant_for_all_nodes(&nodes);

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

        info!("Killing {:?}", nodes[index].name());
        let removed = nodes.remove(index);
        drop(removed);
        poll_and_resend(&mut nodes, &mut []);
        let mut merge_events_missing = nodes.len();
        for node in &mut *nodes {
            while let Ok(event) = node.try_next_ev() {
                match event {
                    Event::NodeAdded(..) |
                    Event::NodeLost(..) |
                    // TODO: possibly ban splitting here, we really should only be merging?
                    Event::SectionSplit(_) |
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
        verify_invariant_for_all_nodes(&nodes);
        if merge_events_missing == 0 {
            return;
        }
    }
}

#[ignore]
#[test]
fn merge_three_sections_into_one() {
    merge(vec![1, 2, 2])
}

#[ignore]
#[test]
fn merge_four_unbalanced_sections_into_one() {
    merge(vec![1, 2, 3, 3])
}

#[ignore]
#[test]
fn merge_four_balanced_sections_into_one() {
    merge(vec![2, 2, 2, 2])
}

#[ignore]
#[test]
fn merge_five_sections_into_one() {
    merge(vec![1, 3, 3, 3, 3])
}
