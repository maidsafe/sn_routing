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

use super::{TestNode, create_connected_nodes, poll_all, verify_invariant_for_all_nodes};
use routing::{Event, EventStream};
use routing::mock_crust::Network;

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
                _ => panic!("Event::NodeLost({:?}) not received", name),
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

    verify_invariant_for_all_nodes(&mut nodes);
}

#[test]
fn node_restart() {
    // Idea of test: if a node disconnects from all other nodes, it should restart
    // (with the exception of the first node which is special).
    let min_section_size = 5;
    let network = Network::new(min_section_size, None);
    let mut nodes = create_connected_nodes(&network, min_section_size);

    // Drop all but last node:
    while nodes.len() > 1 {
        drop_node(&mut nodes, 0);
    }

    poll_all(&mut nodes, &mut []);

    expect_next_event!(nodes[0], Event::RestartRequired);
}
