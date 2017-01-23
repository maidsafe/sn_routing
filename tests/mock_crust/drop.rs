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
use routing::mock_crust::{Config, Network};
use super::{TestNode, create_connected_nodes, poll_all, verify_invariant_for_all_nodes};

// Drop node at index and verify its own section receives NodeLost.
fn drop_node(nodes: &mut Vec<TestNode>, index: usize) {
    let node = nodes.remove(index);
    let name = node.name();
    let close_names = node.close_names();

    drop(node);

    let _ = poll_all(nodes, &mut []);

    for node in nodes.iter_mut().filter(|n| close_names.contains(&n.name())) {
        loop {
            match node.try_next_ev() {
                Ok(Event::NodeLost(lost_name, _)) if lost_name == name => break,
                Ok(_) => (),
                Err(_) => panic!("Event::NodeLost({:?}) not received", name),
            }
        }
    }
}

#[test]
fn node_drops() {
    let min_section_size = 8;
    let network = Network::new(min_section_size, None);
    let mut nodes = create_connected_nodes(&network, min_section_size + 2);
    drop_node(&mut nodes, 0);

    verify_invariant_for_all_nodes(&nodes);
}

#[test]
#[cfg_attr(feature = "cargo-clippy", allow(needless_range_loop))]
fn node_restart() {
    let min_section_size = 2;
    let network = Network::new(min_section_size, None);
    let mut rng = network.new_rng();
    let mut nodes = create_connected_nodes(&network, min_section_size);

    let config = Config::with_contacts(&[nodes[0].handle.endpoint()]);

    // Drop one node, causing the remaining nodes to end up with too few entries
    // in their routing tables and to request a restart.
    let index = rng.gen_range(1, nodes.len());
    drop_node(&mut nodes, index);

    for node in &mut nodes[1..] {
        expect_next_event!(node, Event::RestartRequired);
    }

    // Restart the nodes that requested it
    for index in 1..nodes.len() {
        nodes[index] = TestNode::builder(&network).config(config.clone()).create();
        poll_all(&mut nodes, &mut []);
    }

    verify_invariant_for_all_nodes(&nodes);
}
