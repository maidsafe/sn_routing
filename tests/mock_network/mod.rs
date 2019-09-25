// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod accumulate;
mod churn;
mod drop;
mod merge;
mod messages;
mod secure_message_delivery;
mod utils;

pub use self::utils::{
    add_connected_nodes_until_one_away_from_split, add_connected_nodes_until_split,
    clear_relocation_overrides, count_sections, create_connected_nodes,
    create_connected_nodes_until_split, current_sections, gen_bytes, gen_range, gen_range_except,
    poll_all, poll_and_resend, poll_and_resend_until, remove_nodes_which_failed_to_connect,
    sort_nodes_by_distance_to, verify_invariant_for_all_nodes, Nodes, TestNode,
};
use fake_clock::FakeClock;
use itertools::Itertools;
use rand::Rng;
use routing::{
    mock::Network, test_consts, Event, EventStream, NetworkConfig, Prefix, XorName,
    XorTargetInterval,
};

pub const MIN_SECTION_SIZE: usize = 3;

// -----  Miscellaneous tests below  -----

fn nodes_with_candidate(nodes: &[TestNode]) -> Vec<XorName> {
    nodes
        .iter()
        .filter(|node| node.inner.elder_state_unchecked().has_candidate())
        .map(TestNode::name)
        .collect()
}

fn test_nodes(percentage_size: usize) {
    let size = MIN_SECTION_SIZE * percentage_size / 100;
    let network = Network::new(MIN_SECTION_SIZE, None);
    let mut nodes = create_connected_nodes(&network, size);
    verify_invariant_for_all_nodes(&network, &mut nodes);
}

fn nodes_with_prefix_mut<'a>(
    nodes: &'a mut [TestNode],
    prefix: &'a Prefix<XorName>,
) -> impl Iterator<Item = &'a mut TestNode> {
    nodes
        .iter_mut()
        .filter(move |node| prefix.matches(&node.name()))
}

#[test]
// TODO (quic-p2p): This test requires bootstrap blacklist which isn't implemented in quic-p2p.
#[ignore]
fn disconnect_on_rebootstrap() {
    let network = Network::new(MIN_SECTION_SIZE, None);
    let mut nodes = create_connected_nodes(&network, 2);

    // Try to bootstrap to another than the first node. With network size 2, this should fail.
    let config = NetworkConfig::node().with_hard_coded_contact(nodes[1].endpoint());
    nodes.push(TestNode::builder(&network).network_config(config).create());
    let _ = poll_all(&mut nodes);

    // When retrying to bootstrap, we should have disconnected from the bootstrap node.
    assert!(!network.is_connected(&nodes[2].endpoint(), &nodes[1].endpoint()));

    expect_next_event!(unwrap!(nodes.last_mut()), Event::Terminated);
}

#[test]
fn candidate_expiration() {
    let network = Network::new(MIN_SECTION_SIZE, None);
    let mut nodes = create_connected_nodes(&network, MIN_SECTION_SIZE);
    let network_config = NetworkConfig::node().with_hard_coded_contact(nodes[0].endpoint());
    nodes.insert(
        0,
        TestNode::builder(&network)
            .network_config(network_config)
            .create(),
    );

    // Initiate connection until the candidate switch to ProvingNode:
    info!("Candidate joining name: {}", nodes[0].name());
    poll_and_resend_until(&mut nodes, &|nodes| nodes[0].inner.is_proving_node(), None);
    let proving_node = nodes.remove(0);

    assert!(
        proving_node.inner.is_proving_node(),
        "Accepted as candidate"
    );

    // Continue without the joining node until all nodes accept the candidate:
    info!("Candidate new name: {}", proving_node.name());
    poll_and_resend_until(
        &mut nodes,
        &|nodes| {
            nodes
                .iter()
                .all(|node| node.inner.elder_state_unchecked().has_candidate())
        },
        None,
    );

    assert_eq!(
        nodes.iter().map(TestNode::name).collect_vec(),
        nodes_with_candidate(&nodes),
        "All members of destination section accepted node as candidate"
    );

    // Continue after candidate time out:
    FakeClock::advance_time(1000 * test_consts::CANDIDATE_EXPIRED_TIMEOUT_SECS);
    poll_and_resend(&mut nodes);

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
    verify_invariant_for_all_nodes(&network, &mut nodes);
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
fn node_joins_in_front() {
    let network = Network::new(MIN_SECTION_SIZE, None);
    let mut nodes = create_connected_nodes(&network, 2 * MIN_SECTION_SIZE);
    let network_config = NetworkConfig::node().with_hard_coded_contact(nodes[0].endpoint());
    nodes.insert(
        0,
        TestNode::builder(&network)
            .network_config(network_config)
            .create(),
    );
    poll_and_resend(&mut nodes);

    verify_invariant_for_all_nodes(&network, &mut nodes);
}

#[test]
fn joining_node_with_ignoring_candidate_info() {
    let network = Network::new(MIN_SECTION_SIZE, None);
    let mut nodes = create_connected_nodes(&network, MIN_SECTION_SIZE);
    let config = NetworkConfig::node().with_hard_coded_contact(nodes[0].endpoint());
    // Make half of the elders ingoring the candidate_info to simulate lagging.
    // Without the resending, this will block the joining node to be approved.
    for node in nodes.iter_mut().take(MIN_SECTION_SIZE / 2) {
        node.inner.set_ignore_candidate_info_counter(1);
    }
    nodes.push(TestNode::builder(&network).network_config(config).create());
    let dummy = |_nodes: &[TestNode]| false;
    poll_and_resend_until(&mut nodes, &dummy, Some(20));
    verify_invariant_for_all_nodes(&network, &mut nodes);
}

#[test]
fn multiple_joining_nodes() {
    let network = Network::new(MIN_SECTION_SIZE, None);
    let mut nodes = create_connected_nodes(&network, MIN_SECTION_SIZE);

    while nodes.len() < 40 {
        info!("Size {}", nodes.len());

        // Try adding five nodes at once, possibly to the same section. This makes sure one section
        // can handle this, either by adding the nodes in sequence or by rejecting some.
        let count = 5;
        for _ in 0..count {
            let network_config = NetworkConfig::node().with_hard_coded_contact(nodes[0].endpoint());
            nodes.push(
                TestNode::builder(&network)
                    .network_config(network_config)
                    .create(),
            );
        }

        poll_and_resend(&mut nodes);
        let removed_count = remove_nodes_which_failed_to_connect(&mut nodes, count);
        let nodes_added: Vec<_> = nodes
            .iter()
            .rev()
            .take(count - removed_count)
            .map(TestNode::name)
            .collect();
        info!("Added Nodes: {:?}", nodes_added);
        verify_invariant_for_all_nodes(&network, &mut nodes);
        assert!(
            !nodes_added.is_empty(),
            "Should always handle at least one node"
        );
    }
}

#[test]
fn multi_split() {
    let network = Network::new(MIN_SECTION_SIZE, None);
    let mut nodes = create_connected_nodes_until_split(&network, vec![2, 2, 2, 2]);
    verify_invariant_for_all_nodes(&network, &mut nodes);
}

struct SimultaneousJoiningNode {
    // Destination section prefix: Use as relocation_dst for nodes in src_section_prefix.
    dst_section_prefix: Prefix<XorName>,
    // Section prefix that will match the initial id of the node to add.
    src_section_prefix: Prefix<XorName>,
    // The relocation_interval to set for nodes in the section with dst_section_prefix:
    // Must be within dst_section_prefix. If none let production code decide.
    dst_relocation_interval_prefix: Option<Prefix<XorName>>,
    // The prefix to find the proxy within.
    proxy_prefix: Prefix<XorName>,
}

// Proceed with testing joining nodes at the same time with the given configuration.
fn simultaneous_joining_nodes(
    network: Network,
    mut nodes: Nodes,
    nodes_to_add_setup: &[SimultaneousJoiningNode],
) {
    //
    // Arrange
    // Setup nodes so relocation will happen as specified by nodes_to_add_setup.
    //
    let mut rng = network.new_rng();
    rng.shuffle(&mut nodes);

    let mut nodes_to_add = Vec::new();
    for setup in nodes_to_add_setup {
        // Set the specified relocation destination on the nodes of the given prefixes
        let relocation_dst = setup.dst_section_prefix.substituted_in(rng.gen());
        nodes_with_prefix_mut(&mut nodes, &setup.src_section_prefix)
            .for_each(|node| node.inner.set_next_relocation_dst(Some(relocation_dst)));

        // Set the specified relocation interval on the nodes of the given prefixes
        let relocation_interval = setup
            .dst_relocation_interval_prefix
            .map(|prefix| XorTargetInterval::new(prefix.range_inclusive()));
        nodes_with_prefix_mut(&mut nodes, &setup.dst_section_prefix).for_each(|node| {
            node.inner
                .set_next_relocation_interval(relocation_interval.clone())
        });

        // Create nodes and find proxies from the given prefixes
        let node_to_add = {
            // Get random new TestNode from within src_prefix
            loop {
                // Get random bootstrap node from within proxy_prefix
                let config = {
                    let mut compatible_proxies =
                        nodes_with_prefix_mut(&mut nodes, &setup.proxy_prefix).collect_vec();
                    rng.shuffle(&mut compatible_proxies);

                    NetworkConfig::node().with_hard_coded_contact(unwrap!(nodes.first()).endpoint())
                };

                let node = TestNode::builder(&network).network_config(config).create();
                if setup.src_section_prefix.matches(&node.name()) {
                    break node;
                }
            }
        };
        nodes_to_add.push(node_to_add);
    }

    //
    // Act
    // Add new nodes and process until complete
    //
    nodes.extend(nodes_to_add.into_iter());
    poll_and_resend(&mut nodes);

    //
    // Assert
    // Verify that the new nodes are now full nodes part of a section and other invariants.
    //
    let non_full_nodes = nodes
        .iter()
        .filter(|node| !node.inner.is_elder())
        .map(TestNode::name)
        .collect_vec();
    assert!(
        non_full_nodes.is_empty(),
        "Should be full node: {:?}",
        non_full_nodes
    );
    verify_invariant_for_all_nodes(&network, &mut nodes);
}

#[test]
fn simultaneous_joining_nodes_two_sections() {
    // Create a network with two sections:
    let network = Network::new(MIN_SECTION_SIZE, None);
    let nodes = create_connected_nodes_until_split(&network, vec![1, 1]);

    let prefix_0 = Prefix::default().pushed(false);
    let prefix_1 = Prefix::default().pushed(true);

    // Relocate nodes to the section they were spawned in with a proxy from prefix_0
    let nodes_to_add_setup = vec![
        SimultaneousJoiningNode {
            dst_section_prefix: prefix_0,
            src_section_prefix: prefix_0,
            dst_relocation_interval_prefix: None,
            proxy_prefix: prefix_0,
        },
        SimultaneousJoiningNode {
            dst_section_prefix: prefix_1,
            src_section_prefix: prefix_1,
            dst_relocation_interval_prefix: None,
            proxy_prefix: prefix_0,
        },
    ];
    simultaneous_joining_nodes(network, nodes, &nodes_to_add_setup);
}

#[test]
fn simultaneous_joining_nodes_two_sections_switch_section() {
    // Create a network with two sections:
    let network = Network::new(MIN_SECTION_SIZE, None);
    let nodes = create_connected_nodes_until_split(&network, vec![1, 1]);

    let prefix_0 = Prefix::default().pushed(false);
    let prefix_1 = Prefix::default().pushed(true);

    // Relocate nodes to the section they were not spawned in with a proxy from prefix_0
    let nodes_to_add_setup = vec![
        SimultaneousJoiningNode {
            dst_section_prefix: prefix_0,
            src_section_prefix: prefix_1,
            dst_relocation_interval_prefix: None,
            proxy_prefix: prefix_0,
        },
        SimultaneousJoiningNode {
            dst_section_prefix: prefix_1,
            src_section_prefix: prefix_0,
            dst_relocation_interval_prefix: None,
            proxy_prefix: prefix_0,
        },
    ];
    simultaneous_joining_nodes(network, nodes, &nodes_to_add_setup);
}

#[test]
fn simultaneous_joining_nodes_three_section_with_one_ready_to_split() {
    // TODO: Use same section size once we have a reliable message relay that handle split.
    // Allow for more routes otherwise NodeApproval get losts during soak test.
    let min_section_size = MIN_SECTION_SIZE + 1;

    // Create a network with three sections:
    let network = Network::new(min_section_size, None);
    let mut nodes = create_connected_nodes_until_split(&network, vec![1, 2, 2]);

    // The created sections
    let sections = current_sections(&nodes).into_iter().collect_vec();
    let small_prefix = *unwrap!(sections.iter().find(|prefix| prefix.bit_count() == 1));
    let long_prefix_0 = *unwrap!(sections.iter().find(|prefix| prefix.bit_count() == 2));
    let long_prefix_1 = long_prefix_0.sibling();

    // Setup the network so the small_prefix will split with one more node in small_prefix_to_add.
    let small_prefix_to_add = *unwrap!(add_connected_nodes_until_one_away_from_split(
        &network,
        &mut nodes,
        &[small_prefix],
    )
    .first());

    // First node will trigger the split: src, destination and proxy together.
    // Other nodes validate getting relocated to a section with a proxy from section splitting
    // which will no longer be a neighbour after the split.
    let nodes_to_add_setup = vec![
        SimultaneousJoiningNode {
            dst_section_prefix: small_prefix,
            src_section_prefix: small_prefix,
            dst_relocation_interval_prefix: Some(small_prefix_to_add),
            proxy_prefix: small_prefix,
        },
        SimultaneousJoiningNode {
            dst_section_prefix: long_prefix_0,
            src_section_prefix: small_prefix,
            dst_relocation_interval_prefix: Some(long_prefix_0),
            proxy_prefix: long_prefix_0.with_flipped_bit(0).with_flipped_bit(1),
        },
        SimultaneousJoiningNode {
            dst_section_prefix: long_prefix_1,
            src_section_prefix: long_prefix_0,
            dst_relocation_interval_prefix: Some(long_prefix_1),
            proxy_prefix: long_prefix_1.with_flipped_bit(0).with_flipped_bit(1),
        },
    ];
    simultaneous_joining_nodes(network, nodes, &nodes_to_add_setup);
}

#[test]
fn check_close_names_for_min_section_size_nodes() {
    let nodes = create_connected_nodes(&Network::new(MIN_SECTION_SIZE, None), MIN_SECTION_SIZE);
    let close_sections_complete = nodes
        .iter()
        .all(|n| nodes.iter().all(|m| m.close_names().contains(&n.name())));
    assert!(close_sections_complete);
}

#[test]
fn check_section_info_ack() {
    //
    // Arrange
    //
    let min_section_size = 8;
    let network = Network::new(min_section_size, None);

    //
    // Act
    //
    let nodes = create_connected_nodes_until_split(&network, vec![1, 1]);
    let node_with_sibling_knowledge: Vec<_> = nodes
        .iter()
        .filter(|node| {
            node.chain()
                .get_their_knowldege()
                .contains_key(&node.chain().our_prefix().sibling())
        })
        .map(|node| node.id())
        .collect();

    //
    // Assert
    //
    let expected_all: Vec<_> = nodes.iter().map(|node| node.id()).collect();
    assert_eq!(node_with_sibling_knowledge, expected_all);
}

#[test]
fn vote_prune() {
    // Create a network with a single large section, this is will trigger parsec pruning
    let min_section_size = 3;
    let network = Network::new(min_section_size, None);
    let nodes = create_connected_nodes(&network, 10 * min_section_size);
    assert!(nodes
        .iter()
        .any(|node| node.chain().parsec_prune_accumulated() > 0));
}
