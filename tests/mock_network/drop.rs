// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    create_connected_nodes, poll_all, poll_and_resend, verify_invariant_for_all_nodes, TestNode,
};
use rand::Rng;
use routing::{mock::Network, Event, EventStream};

// Drop node at index and verify its own section detected it.
fn drop_node(nodes: &mut Vec<TestNode>, index: usize) {
    let node = nodes.remove(index);
    let name = node.name();
    let close_names = node.close_names();

    drop(node);

    // Using poll_all instead of poll_and_resend here to only let the other nodes realise the node
    // got disconnected, but not make more progress.
    let _ = poll_all(nodes);

    for node in nodes.iter_mut().filter(|n| close_names.contains(&n.name())) {
        assert!(!node.inner.is_connected(name));
    }
}

#[test]
fn node_drops() {
    let min_section_size = 8;
    let network = Network::new(min_section_size, None);
    let mut nodes = create_connected_nodes(&network, min_section_size + 2);
    drop_node(&mut nodes, 0);

    // Trigger poll_and_resend to allow remaining nodes to gossip and
    // update their chain accordingly.
    poll_and_resend(&mut nodes);
    verify_invariant_for_all_nodes(&network, &mut nodes);
}

#[test]
fn node_restart() {
    // Idea of test: if a node disconnects from all other nodes, it should restart
    // (with the exception of the first node which is special).
    let min_section_size = 5;
    let network = Network::new(min_section_size, None);
    let mut rng = network.new_rng();
    let mut nodes = create_connected_nodes(&network, min_section_size);

    // Drop all but last node in random order:
    while nodes.len() > 1 {
        let index = rng.gen_range(0, nodes.len());
        drop_node(&mut nodes, index);
    }

    expect_next_event!(nodes[0], Event::RestartRequired);
}
