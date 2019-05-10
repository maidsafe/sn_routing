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
    poll_and_resend_until, remove_nodes_which_failed_to_connect, sort_nodes_by_distance_to,
    verify_invariant_for_all_nodes, Nodes, TestClient, TestNode,
};
use fake_clock::FakeClock;
use routing::mock_crust::{Endpoint, Network};
use routing::{Authority, BootstrapConfig, Event, EventStream, Prefix, XorName, XOR_NAME_LEN};

pub const MIN_SECTION_SIZE: usize = 3;

// -----  Miscellaneous tests below  -----

fn nodes_in_authority(nodes: &[TestNode], name: &XorName) -> Vec<XorName> {
    nodes
        .iter()
        .filter(|node| node.inner.in_authority(&Authority::Section(*name)))
        .map(TestNode::name)
        .collect()
}

fn nodes_with_candidate(nodes: &[TestNode]) -> Vec<XorName> {
    nodes
        .iter()
        .filter(|node| {
            node.inner
                .node_state_unchecked()
                .has_resource_proof_candidate()
        })
        .map(TestNode::name)
        .collect()
}

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
    expect_next_event!(unwrap!(nodes.last_mut()), Event::Terminated);
}

#[test]
fn candidate_timeout_resource_proof() {
    let network = Network::new(MIN_SECTION_SIZE, None);
    let mut nodes = create_connected_nodes_until_split(&network, vec![1, 1], false);
    let bootstrap_config = BootstrapConfig::with_contacts(&[nodes[0].handle.endpoint()]);
    nodes.insert(
        0,
        TestNode::builder(&network)
            .bootstrap_config(bootstrap_config)
            .create(),
    );

    // Initiate connection until the candidate switch to ProvingNode:
    info!("Candidate joining name: {}", nodes[0].name());
    poll_and_resend_until(&mut nodes, &mut [], &|nodes| {
        nodes[0].inner.is_proving_node()
    });
    let proving_node = nodes.remove(0);

    assert!(
        proving_node.inner.is_proving_node(),
        "Accepted as candidate"
    );

    // Continue without the joining node until all nodes idle:
    info!("Candidate new name: {}", proving_node.name());
    poll_and_resend(&mut nodes, &mut []);

    assert_eq!(
        nodes_in_authority(&nodes, &proving_node.name()),
        nodes_with_candidate(&nodes),
        "All members of destination section accepted node as candidate"
    );

    // Continue after candidate time out:
    FakeClock::advance_time(60 * 60 * 1000);
    poll_and_resend(&mut nodes, &mut []);

    assert_eq!(
        Vec::<XorName>::new(),
        nodes_with_candidate(&nodes),
        "All members have rejected the candidate"
    );
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
            .map(TestNode::name)
            .collect();
        info!("Added Nodes: {:?}", nodes_added);
        verify_invariant_for_all_nodes(&mut nodes);
        assert!(
            !nodes_added.is_empty(),
            "Should always handle at least one node"
        );
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
