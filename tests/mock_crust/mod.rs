// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod accumulate;
mod cache;
mod churn;
mod client_restrictions;
mod drop;
mod merge;
mod requests;
mod utils;

pub use self::utils::{
    add_connected_nodes_until_split, count_sections, create_connected_clients,
    create_connected_nodes, create_connected_nodes_until_split, current_sections, gen_bytes,
    gen_immutable_data, gen_range, gen_range_except, poll_all, poll_and_resend,
    remove_nodes_which_failed_to_connect, sort_nodes_by_distance_to,
    verify_invariant_for_all_nodes, Nodes, TestClient, TestNode,
};
use routing::mock_crust::{Endpoint, Network};
use routing::{BootstrapConfig, Event, EventStream, Prefix, XorName, XOR_NAME_LEN};

pub const MIN_SECTION_SIZE: usize = 3;

// -----  Miscellaneous tests below  -----

fn test_nodes(percentage_size: usize) {
    let size = MIN_SECTION_SIZE * percentage_size / 100;
    let network = Network::new(MIN_SECTION_SIZE, None);
    let mut nodes = create_connected_nodes(&network, size);
    verify_invariant_for_all_nodes(&mut nodes);
}

#[test]
fn disconnect_on_rebootstrap() {
    let network = Network::new(MIN_SECTION_SIZE, None);
    let mut nodes = create_connected_nodes(&network, 2);
    // Try to bootstrap to another than the first node. With network size 2, this should fail.
    let bootstrap_config = BootstrapConfig::with_contacts(&[nodes[1].handle.endpoint()]);
    nodes.push(
        TestNode::builder(&network)
            .bootstrap_config(bootstrap_config)
            .endpoint(Endpoint(2))
            .create(),
    );
    let _ = poll_all(&mut nodes, &mut []);
    // When retrying to bootstrap, we should have disconnected from the bootstrap node.
    assert!(!unwrap!(nodes.last()).handle.is_connected(&nodes[1].handle));
    expect_next_event!(unwrap!(nodes.last_mut()), Event::Terminate);
}

#[test]
fn single_section() {
    let sec_size = 10;
    let network = Network::new(sec_size, None);
    let mut nodes = create_connected_nodes(&network, sec_size);
    verify_invariant_for_all_nodes(&mut nodes);
}

#[test]
fn less_than_section_size_nodes() {
    test_nodes(80)
}

#[test]
fn equal_section_size_nodes() {
    test_nodes(100);
}

#[test]
fn more_than_section_size_nodes() {
    test_nodes(600);
}

#[test]
fn client_connects_to_nodes() {
    let network = Network::new(MIN_SECTION_SIZE, None);
    let mut nodes = create_connected_nodes(&network, MIN_SECTION_SIZE + 1);
    let _ = create_connected_clients(&network, &mut nodes, 1);
}

#[test]
fn node_joins_in_front() {
    let network = Network::new(MIN_SECTION_SIZE, None);
    let mut nodes = create_connected_nodes(&network, 2 * MIN_SECTION_SIZE);
    let bootstrap_config = BootstrapConfig::with_contacts(&[nodes[0].handle.endpoint()]);
    nodes.insert(
        0,
        TestNode::builder(&network)
            .bootstrap_config(bootstrap_config)
            .create(),
    );
    poll_and_resend(&mut nodes, &mut []);

    verify_invariant_for_all_nodes(&mut nodes);
}

#[test]
fn multiple_joining_nodes() {
    let network = Network::new(MIN_SECTION_SIZE, None);
    let mut nodes = create_connected_nodes(&network, MIN_SECTION_SIZE);
    let bootstrap_config = BootstrapConfig::with_contacts(&[nodes[0].handle.endpoint()]);

    while nodes.len() < 40 {
        info!("Size {}", nodes.len());

        // Try adding five nodes at once, possibly to the same section. This makes sure one section
        // can handle this, either by adding the nodes in sequence or by rejecting some.
        let count = 5;
        for _ in 0..count {
            nodes.push(
                TestNode::builder(&network)
                    .bootstrap_config(bootstrap_config.clone())
                    .create(),
            );
        }

        poll_and_resend(&mut nodes, &mut []);
        let removed_count = remove_nodes_which_failed_to_connect(&mut nodes, count);
        let nodes_added: Vec<_> = nodes
            .iter()
            .rev()
            .take(count - removed_count)
            .map(|node| node.name())
            .collect();
        info!("Added Nodes: {:?}", nodes_added);
        verify_invariant_for_all_nodes(&mut nodes);
    }
}

#[test]
fn multi_split() {
    let network = Network::new(MIN_SECTION_SIZE, None);
    let mut nodes = create_connected_nodes_until_split(&network, vec![2, 2, 2, 2], false);
    verify_invariant_for_all_nodes(&mut nodes);
}

#[test]
fn simultaneous_joining_nodes() {
    // Create a network with two sections:
    let network = Network::new(MIN_SECTION_SIZE, None);
    let mut nodes = create_connected_nodes_until_split(&network, vec![1, 1], false);
    let bootstrap_config = BootstrapConfig::with_contacts(&[nodes[0].handle.endpoint()]);

    // Add two nodes simultaneously, to two different sections:
    // We now have two sections, with prefixes 0 and 1. Make one joining node contact each section,
    // and tell each section to allocate a name in its own section when `Relocate` is received.
    // This is to test that the routing table gets updated correctly (previously one new node would
    // miss the new node added to the neighbouring section).
    let (name0, name1) = (XorName([0u8; XOR_NAME_LEN]), XorName([255u8; XOR_NAME_LEN]));
    let prefix0 = Prefix::new(1, name0);

    for node in &mut *nodes {
        if prefix0.matches(&node.name()) {
            node.inner.set_next_relocation_dst(Some(name0));
        } else {
            node.inner.set_next_relocation_dst(Some(name1));
        }
    }

    let node = TestNode::builder(&network)
        .bootstrap_config(bootstrap_config.clone())
        .create();
    let prefix = Prefix::new(1, node.name());
    nodes.push(node);
    loop {
        let node = TestNode::builder(&network)
            .bootstrap_config(bootstrap_config.clone())
            .create();
        if !prefix.matches(&node.name()) {
            nodes.push(node);
            break;
        }
    }

    poll_and_resend(&mut nodes, &mut []);
    verify_invariant_for_all_nodes(&mut nodes);
}

#[test]
fn check_close_names_for_min_section_size_nodes() {
    let nodes = create_connected_nodes(&Network::new(MIN_SECTION_SIZE, None), MIN_SECTION_SIZE);
    let close_sections_complete = nodes
        .iter()
        .all(|n| nodes.iter().all(|m| m.close_names().contains(&n.name())));
    assert!(close_sections_complete);
}
