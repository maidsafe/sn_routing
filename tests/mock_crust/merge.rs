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

use rand::distributions::{IndependentSample, Range};
use routing::Event;
use routing::mock_crust::Network;
use super::{create_connected_nodes_with_cache_until_split, poll_and_resend,
            verify_invariant_for_all_nodes};

#[test]
fn merge_three_groups_into_one() {
    // Create a network comprising three groups, one with a prefix `bit_count` of 1 and two with
    // prefix `bit_count`s of 2.
    let min_group_size = 8;
    let network = Network::new(min_group_size, None);
    let mut rng = network.new_rng();
    let mut nodes = create_connected_nodes_with_cache_until_split(&network, 3);
    verify_invariant_for_all_nodes(&nodes);

    // Drop nodes from the group with the short prefix until we get a merge event
    'outer: loop {
        let range = Range::new(0, nodes.len());
        let index = range.ind_sample(&mut rng);
        if unwrap!(nodes[index].routing_table()).our_group_prefix().bit_count() != 1 {
            continue;
        }
        let _ = nodes.remove(index);
        poll_and_resend(&mut nodes, &mut []);
        for node in &nodes {
            while let Ok(event) = node.event_rx.try_recv() {
                match event {
                    Event::NodeLost(..) |
                    Event::Tick => (),
                    Event::GroupMerge(..) => break 'outer,
                    event => panic!("Got unexpected event: {:?}", event),
                }
            }
        }
    }

    verify_invariant_for_all_nodes(&nodes);
}
