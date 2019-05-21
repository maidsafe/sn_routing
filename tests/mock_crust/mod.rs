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
    add_connected_nodes_until_sized, add_connected_nodes_until_split, count_sections,
    create_connected_clients, create_connected_nodes, create_connected_nodes_until_split,
    current_sections, gen_bytes, gen_immutable_data, gen_range, gen_range_except, poll_all,
    poll_and_resend, poll_and_resend_until, remove_nodes_which_failed_to_connect,
    sort_nodes_by_distance_to, verify_invariant_for_all_nodes, Nodes, TestClient, TestNode,
};
use fake_clock::FakeClock;
use itertools::Itertools;
use rand::Rng;
use routing::mock_crust::{Endpoint, Network};
use routing::{test_consts, BootstrapConfig, Event, EventStream, Prefix, PublicId, XorName};

pub const MIN_SECTION_SIZE: usize = 3;

// -----  Miscellaneous tests below  -----

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
    let mut nodes = create_connected_nodes(&network, MIN_SECTION_SIZE);
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
        nodes.iter().map(TestNode::name).collect_vec(),
        nodes_with_candidate(&nodes),
        "All members of destination section accepted node as candidate"
    );

    // Continue after candidate time out:
    FakeClock::advance_time(
        1000 * (test_consts::RESOURCE_PROOF_DURATION_SECS
            + test_consts::ACCUMULATION_TIMEOUT_SECS * 3),
    );
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

fn simultaneous_joining_nodes(
    network: Network<PublicId>,
    mut nodes: Nodes,
    prefixes_to_add_to: &[Prefix<XorName>],
    set_next_relocation_interval: bool,
) {
    let mut rng = network.new_rng();
    rng.shuffle(&mut nodes);

    let next_relocation_dsts = prefixes_to_add_to
        .iter()
        .map(|prefix| prefix.substituted_in(rng.gen()))
        .collect_vec();

    let prefix_and_dst_in_other_section = prefixes_to_add_to
        .iter()
        .zip(next_relocation_dsts.iter().rev());

    for (prefix, dst_other) in prefix_and_dst_in_other_section {
        let interval = if set_next_relocation_interval {
            Some((prefix.lower_bound(), prefix.upper_bound()))
        } else {
            None
        };
        nodes
            .iter_mut()
            .filter(|node| prefix.is_compatible(&node.chain().our_prefix()))
            .for_each(|node| {
                trace!(
                    "simultaneous_joining_nodes: set_next_relocation_dst {:?} -> {:?}",
                    node.name(),
                    dst_other
                );
                node.inner.set_next_relocation_dst(Some(*dst_other));
                node.inner.set_next_relocation_interval(interval);
            });
    }

    for prefix in prefixes_to_add_to {
        let bootstrap_config = BootstrapConfig::with_contacts(&[unwrap!(nodes
            .iter()
            .find(|node| prefix.is_compatible(&node.chain().our_prefix())))
        .handle
        .endpoint()]);
        loop {
            let node = TestNode::builder(&network)
                .bootstrap_config(bootstrap_config.clone())
                .create();
            if prefix.matches(&node.name()) {
                trace!("simultaneous_joining_nodes: new node {:?}", node.name());
                nodes.push(node);
                break;
            }
        }
    }

    poll_and_resend(&mut nodes, &mut []);
    verify_invariant_for_all_nodes(&mut nodes);
}

#[test]
fn simultaneous_joining_nodes_two_sections() {
    // Create a network with two sections:
    let network = Network::new(MIN_SECTION_SIZE, None);
    let nodes = create_connected_nodes_until_split(&network, vec![1, 1], false);
    let mut rng = network.new_rng();

    let sections = {
        let mut sections = current_sections(&nodes).into_iter().collect_vec();
        rng.shuffle(&mut sections);
        sections
    };

    simultaneous_joining_nodes(network, nodes, &sections, false);
}

#[test]
fn simultaneous_joining_nodes_three_section_with_one_ready_to_split() {
    let _ = maidsafe_utilities::log::init(false);

    // Create a network with three sections:
    let network = Network::new(MIN_SECTION_SIZE, None);
    let mut nodes = create_connected_nodes_until_split(&network, vec![1, 2, 2], false);

    let mut rng = network.new_rng();
    let sections = {
        let mut sections = current_sections(&nodes).into_iter().collect_vec();
        rng.shuffle(&mut sections);
        sections
    };

    // Identify prefixes to add node to for setup so the shorter prefix split with a single node.
    // Identify 2 prefixes to add node to for the test: one trigger a split, one in other section.
    let (prefixes_to_extend, small_prefix_to_add) = {
        let small_prefix = *unwrap!(sections.iter().find(|prefix| prefix.bit_count() == 1));
        let small_prefix_0 = small_prefix.clone().pushed(false);
        let small_prefix_1 = small_prefix.clone().pushed(true);

        let num_in_section = |prefix: &Prefix<XorName>| {
            nodes
                .iter()
                .filter(|node| prefix.matches(&node.name()))
                .count()
        };

        // Keep the initially smaller half smaller as all node may already be in
        // the bigger section
        let small_prefix_to_add =
            if num_in_section(&small_prefix_1) > num_in_section(&small_prefix_0) {
                small_prefix_0
            } else {
                small_prefix_1
            };
        let split_size = nodes[0].chain().min_split_size();

        (
            vec![
                (small_prefix_to_add.clone(), split_size - 1),
                (small_prefix_to_add.sibling(), split_size),
            ],
            small_prefix_to_add,
        )
    };

    add_connected_nodes_until_sized(&network, &mut nodes, &prefixes_to_extend, false);

    let target_prefixes = sections
        .iter()
        .filter(|prefix| prefix.bit_count() == 2)
        .chain(Some(&small_prefix_to_add))
        .cloned()
        .collect_vec();
    simultaneous_joining_nodes(network, nodes, &target_prefixes, true);
}

#[test]
fn check_close_names_for_min_section_size_nodes() {
    let nodes = create_connected_nodes(&Network::new(MIN_SECTION_SIZE, None), MIN_SECTION_SIZE);
    let close_sections_complete = nodes
        .iter()
        .all(|n| nodes.iter().all(|m| m.close_names().contains(&n.name())));
    assert!(close_sections_complete);
}
