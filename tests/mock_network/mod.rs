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
mod messages;
mod node_ageing;
mod secure_message_delivery;
mod utils;

pub use self::utils::*;
use itertools::Itertools;
use rand::{seq::SliceRandom, Rng};
use routing::{
    mock::Environment, Event, EventStream, FullId, NetworkConfig, NetworkParams, Prefix,
    RelocationOverrides, XorName,
};
use std::collections::BTreeMap;

pub const LOWERED_ELDER_SIZE: usize = 3;

// -----  Miscellaneous tests below  -----

// fn nodes_with_candidate(nodes: &[TestNode]) -> Vec<XorName> {
// nodes
// .iter()
// .filter(|node| node.inner.elder_state_unchecked().has_candidate())
// .map(TestNode::name)
// .collect()
// }

fn test_nodes(percentage_size: usize) {
    let size = LOWERED_ELDER_SIZE * percentage_size / 100;
    let env = Environment::new(NetworkParams {
        elder_size: LOWERED_ELDER_SIZE,
        safe_section_size: LOWERED_ELDER_SIZE,
    });
    let mut nodes = create_connected_nodes(&env, size);
    verify_invariant_for_all_nodes(&env, &mut nodes);
}

pub fn count_sections_members_if_split(nodes: &[TestNode]) -> BTreeMap<Prefix<XorName>, usize> {
    let mut counts = BTreeMap::new();
    for pfx in nodes.iter().map(node_prefix_if_split) {
        // Populate both sub-prefixes so the map keys cover the full address space.
        // Needed as we use the keys to match sub-prefix of new node and we need to find it.
        *counts.entry(pfx).or_default() += 1;
        let _ = counts.entry(pfx.sibling()).or_default();
    }
    counts
}

pub fn node_prefix_if_split(node: &TestNode) -> Prefix<XorName> {
    let prefix = node.our_prefix();

    let sub_prefix = [prefix.pushed(false), prefix.pushed(true)]
        .iter()
        .find(|ref pfx| pfx.matches(&node.name()))
        .cloned();
    unwrap!(sub_prefix)
}

fn new_node_prefix_without_split(
    node: &TestNode,
    count_if_split_node: &BTreeMap<Prefix<XorName>, usize>,
    safe_section_size: usize,
) -> Option<Prefix<XorName>> {
    let (sub_prefix, count) = unwrap!(count_if_split_node
        .iter()
        .find(|(pfx, _)| pfx.matches(&node.name())));

    if *count < safe_section_size * 2 - 1 {
        return Some(*sub_prefix);
    }
    None
}

fn can_accept_node_without_split(
    count_if_split_node: &BTreeMap<Prefix<XorName>, usize>,
    safe_section_size: usize,
) -> bool {
    count_if_split_node
        .values()
        .any(|count| *count < safe_section_size * 2 - 1)
}

fn create_node_with_contact(env: &Environment, contact: &mut TestNode) -> TestNode {
    let config = NetworkConfig::node().with_hard_coded_contact(contact.endpoint());
    TestNode::builder(&env).network_config(config).create()
}

#[test]
// TODO (quic-p2p): This test requires bootstrap blacklist which isn't implemented in quic-p2p.
#[ignore]
fn disconnect_on_rebootstrap() {
    let env = Environment::new(NetworkParams {
        elder_size: LOWERED_ELDER_SIZE,
        safe_section_size: LOWERED_ELDER_SIZE,
    });
    let mut nodes = create_connected_nodes(&env, 2);

    // Try to bootstrap to another than the first node. With network size 2, this should fail.
    let config = NetworkConfig::node().with_hard_coded_contact(nodes[1].endpoint());
    nodes.push(TestNode::builder(&env).network_config(config).create());
    let _ = poll_all(&mut nodes);

    // When retrying to bootstrap, we should have disconnected from the bootstrap node.
    assert!(!env.is_connected(&nodes[2].endpoint(), &nodes[1].endpoint()));

    expect_next_event!(unwrap!(nodes.last_mut()), Event::Terminated);
}

// TODO: either modify this test or remove it
// #[test]
// fn candidate_expiration() {
// let env = Environment::new(LOWERED_ELDER_SIZE, LOWERED_ELDER_SIZE * 2, None);
// let mut nodes = create_connected_nodes(&env, LOWERED_ELDER_SIZE);
// let network_config = NetworkConfig::node().with_hard_coded_contact(nodes[0].endpoint());
// nodes.insert(
// 0,
// TestNode::builder(&env)
// .network_config(network_config)
// .create(),
// );
//
// Initiate connection until the candidate switch to ProvingNode:
// info!("Candidate joining name: {}", nodes[0].name());
// poll_and_resend_until(&mut nodes, &|nodes| nodes[0].inner.is_proving_node(), None);
// let proving_node = nodes.remove(0);
//
// assert!(
// proving_node.inner.is_proving_node(),
// "Accepted as candidate"
// );
//
// Continue without the joining node until all nodes accept the candidate:
// info!("Candidate new name: {}", proving_node.name());
// poll_and_resend_until(
// &mut nodes,
// &|nodes| {
// nodes
// .iter()
// .all(|node| node.inner.elder_state_unchecked().has_candidate())
// },
// None,
// );
//
// assert_eq!(
// nodes.iter().map(TestNode::name).collect_vec(),
// nodes_with_candidate(&nodes),
// "All members of destination section accepted node as candidate"
// );
//
// Continue after candidate time out:
// FakeClock::advance_time(1000 * test_consts::CANDIDATE_EXPIRED_TIMEOUT_SECS);
// poll_and_resend(&mut nodes);
//
// assert_eq!(
// Vec::<XorName>::new(),
// nodes_with_candidate(&nodes),
// "All members have rejected the candidate"
// );
// }

#[test]
fn single_section() {
    let sec_size = 10;
    let env = Environment::new(NetworkParams {
        elder_size: sec_size,
        safe_section_size: sec_size,
    });
    let mut nodes = create_connected_nodes(&env, sec_size);
    verify_invariant_for_all_nodes(&env, &mut nodes);
}

#[test]
fn less_than_section_size_nodes() {
    test_nodes(80);
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
    let env = Environment::new(NetworkParams {
        elder_size: LOWERED_ELDER_SIZE,
        safe_section_size: LOWERED_ELDER_SIZE,
    });
    let mut nodes = create_connected_nodes(&env, 2 * LOWERED_ELDER_SIZE);
    let network_config = NetworkConfig::node().with_hard_coded_contact(nodes[0].endpoint());
    nodes.insert(
        0,
        TestNode::builder(&env)
            .network_config(network_config)
            .create(),
    );
    poll_and_resend(&mut nodes);

    verify_invariant_for_all_nodes(&env, &mut nodes);
}

// Only run for mock parsec, as with DKG Joining node timeouts waiting for NodeApproval.
// Elder go on to process it and take it on as an Elder.
// This would not be an issue if Joining did not time out, or if elder processed them quicker.
// This should be solved by Taking on all queued Adults before processing Elder change.
#[test]
#[cfg_attr(not(feature = "mock"), ignore)]
fn multiple_joining_nodes() {
    let env = Environment::new(NetworkParams {
        elder_size: LOWERED_ELDER_SIZE,
        safe_section_size: LOWERED_ELDER_SIZE,
    });
    let mut nodes = create_connected_nodes(&env, LOWERED_ELDER_SIZE);

    while nodes.len() < 25 {
        let initial_size = nodes.len();
        info!("Size {}", nodes.len());

        let mut count_if_split_node = count_sections_members_if_split(&nodes);
        let safe_section_size = unwrap!(nodes[0].inner.safe_section_size());

        // Try adding five nodes at once, possibly to the same section. This makes sure one section
        // can handle this, either by adding the nodes in sequence or by rejecting some.
        // Ensure we do not create a situation when a recursive split will occur.
        let count = 5;
        for _ in 0..count {
            if !can_accept_node_without_split(&count_if_split_node, safe_section_size) {
                break;
            }

            loop {
                let node = create_node_with_contact(&env, &mut nodes[0]);
                let valid_sub_prefix =
                    new_node_prefix_without_split(&node, &count_if_split_node, safe_section_size);

                if let Some(sub_prefix) = valid_sub_prefix {
                    *unwrap!(count_if_split_node.get_mut(&sub_prefix)) += 1;
                    nodes.push(node);
                    break;
                } else {
                    info!("Invalid node {:?}, {:?}", node.name(), count_if_split_node);
                }
            }
        }
        let count = nodes.len() - initial_size;

        poll_and_resend(&mut nodes);
        let removed_count = remove_nodes_which_failed_to_connect(&mut nodes, count);
        let nodes_added: Vec<_> = nodes
            .iter()
            .rev()
            .take(count - removed_count)
            .map(TestNode::name)
            .collect();
        info!("Added Nodes: {:?}", nodes_added);
        verify_invariant_for_all_nodes(&env, &mut nodes);
        assert!(
            !nodes_added.is_empty(),
            "Should always handle at least one node"
        );
    }
}

#[test]
fn multi_split() {
    let env = Environment::new(NetworkParams {
        elder_size: LOWERED_ELDER_SIZE,
        safe_section_size: LOWERED_ELDER_SIZE,
    });
    let mut nodes = create_connected_nodes_until_split(&env, vec![2, 2, 2, 2]);
    verify_invariant_for_all_nodes(&env, &mut nodes);
}

struct SimultaneousJoiningNode {
    // Destination section prefix: Use as relocation_dst for nodes in src_section_prefix.
    dst_section_prefix: Prefix<XorName>,
    // Section prefix that will match the initial id of the node to add.
    src_section_prefix: Prefix<XorName>,
    // The prefix to find the proxy within.
    proxy_prefix: Prefix<XorName>,
}

// Proceed with testing joining nodes at the same time with the given configuration.
fn simultaneous_joining_nodes(
    env: Environment,
    mut nodes: Nodes,
    nodes_to_add_setup: &[SimultaneousJoiningNode],
) {
    // Arrange
    // Setup nodes so relocation will happen as specified by nodes_to_add_setup.
    //
    let mut rng = env.new_rng();
    nodes.shuffle(&mut rng);

    let mut overrides = RelocationOverrides::new();

    let mut nodes_to_add = Vec::new();
    for setup in nodes_to_add_setup {
        // Set the specified relocation destination on the nodes of the given prefixes
        let relocation_dst = setup.dst_section_prefix.substituted_in(rng.gen());
        overrides.set(setup.src_section_prefix, relocation_dst);

        // Create nodes and find proxies from the given prefixes
        let node_to_add = {
            // Get random new TestNode from within src_prefix
            loop {
                // Get random bootstrap node from within proxy_prefix
                let config = {
                    let mut compatible_proxies =
                        nodes_with_prefix_mut(&mut nodes, &setup.proxy_prefix).collect_vec();
                    compatible_proxies.shuffle(&mut rng);

                    NetworkConfig::node()
                        .with_hard_coded_contact(unwrap!(nodes.first_mut()).endpoint())
                };

                let node = TestNode::builder(&env).network_config(config).create();
                if setup.src_section_prefix.matches(&node.name()) {
                    break node;
                }
            }
        };
        nodes_to_add.push(node_to_add);
    }

    // Act
    // Add new nodes and process until complete
    //
    nodes.extend(nodes_to_add);
    poll_and_resend(&mut nodes);

    // Assert
    // Verify that the sections all have enough elders and other invariants
    //
    let non_approved = nodes
        .iter()
        .filter(|node| !node.inner.is_approved())
        .map(TestNode::name)
        .collect_vec();
    assert!(
        non_approved.is_empty(),
        "Should be approved: {:?}",
        non_approved
    );

    let mut elders_count_by_prefix = BTreeMap::new();
    for node in nodes.iter() {
        if let Some(prefix) = node.inner.our_prefix() {
            let entry = elders_count_by_prefix.entry(*prefix).or_insert(0);
            if node.inner.is_elder() {
                *entry += 1;
            }
        }
    }
    let prefixes_not_enough_elders = elders_count_by_prefix
        .into_iter()
        .filter(|(_, num_elders)| *num_elders < env.elder_size())
        .map(|(prefix, _)| prefix)
        .collect::<Vec<_>>();
    assert!(
        prefixes_not_enough_elders.is_empty(),
        "Prefixes with too few elders: {:?}",
        prefixes_not_enough_elders
    );
    verify_invariant_for_all_nodes(&env, &mut nodes);
}

#[test]
fn simultaneous_joining_nodes_two_sections() {
    // Create a network with two sections:
    let env = Environment::new(NetworkParams {
        elder_size: LOWERED_ELDER_SIZE,
        safe_section_size: LOWERED_ELDER_SIZE,
    });
    let nodes = create_connected_nodes_until_split(&env, vec![1, 1]);

    let prefix_0 = Prefix::default().pushed(false);
    let prefix_1 = Prefix::default().pushed(true);

    // Relocate nodes to the section they were spawned in with a proxy from prefix_0
    let nodes_to_add_setup = vec![
        SimultaneousJoiningNode {
            dst_section_prefix: prefix_0,
            src_section_prefix: prefix_0,
            proxy_prefix: prefix_0,
        },
        SimultaneousJoiningNode {
            dst_section_prefix: prefix_1,
            src_section_prefix: prefix_1,
            proxy_prefix: prefix_0,
        },
    ];
    simultaneous_joining_nodes(env, nodes, &nodes_to_add_setup);
}

#[test]
fn simultaneous_joining_nodes_two_sections_switch_section() {
    // Create a network with two sections:
    let env = Environment::new(NetworkParams {
        elder_size: LOWERED_ELDER_SIZE,
        safe_section_size: LOWERED_ELDER_SIZE,
    });
    let nodes = create_connected_nodes_until_split(&env, vec![1, 1]);

    let prefix_0 = Prefix::default().pushed(false);
    let prefix_1 = Prefix::default().pushed(true);

    // Relocate nodes to the section they were not spawned in with a proxy from prefix_0
    let nodes_to_add_setup = vec![
        SimultaneousJoiningNode {
            dst_section_prefix: prefix_0,
            src_section_prefix: prefix_1,
            proxy_prefix: prefix_0,
        },
        SimultaneousJoiningNode {
            dst_section_prefix: prefix_1,
            src_section_prefix: prefix_0,
            proxy_prefix: prefix_0,
        },
    ];
    simultaneous_joining_nodes(env, nodes, &nodes_to_add_setup);
}

#[test]
fn simultaneous_joining_nodes_three_section_with_one_ready_to_split() {
    // TODO: Use same section size once we have a reliable message relay that handle split.
    // Allow for more routes otherwise NodeApproval get losts during soak test.
    let elder_size = LOWERED_ELDER_SIZE + 1;
    let safe_section_size = LOWERED_ELDER_SIZE + 1;

    // Create a network with three sections:
    let env = Environment::new(NetworkParams {
        elder_size,
        safe_section_size,
    });
    let mut nodes = create_connected_nodes_until_split(&env, vec![1, 2, 2]);

    // The created sections
    let sections = current_sections(&nodes).collect_vec();
    let small_prefix = *unwrap!(sections.iter().find(|prefix| prefix.bit_count() == 1));
    let long_prefix_0 = *unwrap!(sections.iter().find(|prefix| prefix.bit_count() == 2));
    let long_prefix_1 = long_prefix_0.sibling();

    // Setup the network so the small_prefix will split with one more node in small_prefix_to_add.
    let _ =
        *unwrap!(
            add_connected_nodes_until_one_away_from_split(&env, &mut nodes, &[small_prefix],)
                .first()
        );

    // First node will trigger the split: src, destination and proxy together.
    // Other nodes validate getting relocated to a section with a proxy from section splitting
    // which will no longer be a neighbour after the split.
    let nodes_to_add_setup = vec![
        SimultaneousJoiningNode {
            dst_section_prefix: small_prefix,
            src_section_prefix: small_prefix,
            proxy_prefix: small_prefix,
        },
        SimultaneousJoiningNode {
            dst_section_prefix: long_prefix_0,
            src_section_prefix: small_prefix,
            proxy_prefix: long_prefix_0.with_flipped_bit(0).with_flipped_bit(1),
        },
        SimultaneousJoiningNode {
            dst_section_prefix: long_prefix_1,
            src_section_prefix: long_prefix_0,
            proxy_prefix: long_prefix_1.with_flipped_bit(0).with_flipped_bit(1),
        },
    ];
    simultaneous_joining_nodes(env, nodes, &nodes_to_add_setup);
}

#[test]
fn check_close_names_for_elder_size_nodes() {
    let nodes = create_connected_nodes(
        &Environment::new(NetworkParams {
            elder_size: LOWERED_ELDER_SIZE,
            safe_section_size: LOWERED_ELDER_SIZE,
        }),
        LOWERED_ELDER_SIZE,
    );
    let close_sections_complete = nodes
        .iter()
        .all(|n| nodes.iter().all(|m| m.close_names().contains(&n.name())));
    assert!(close_sections_complete);
}

#[test]
fn check_section_info_ack() {
    // Arrange
    //
    let elder_size = 8;
    let safe_section_size = 8;
    let env = Environment::new(NetworkParams {
        elder_size,
        safe_section_size,
    });

    // Act
    //
    let nodes = create_connected_nodes_until_split(&env, vec![1, 1]);
    let node_with_sibling_knowledge: Vec<_> = nodes
        .iter()
        .filter(|node| {
            node.inner
                .get_their_knowledge()
                .contains_key(&node.our_prefix().sibling())
        })
        .map(|node| node.id())
        .collect();

    // Assert
    //
    let expected_all_elder: Vec<_> = nodes
        .iter()
        .filter(|node| node.inner.is_elder())
        .map(|node| node.id())
        .collect();
    assert_eq!(node_with_sibling_knowledge, expected_all_elder);
}

#[test]
fn carry_out_parsec_pruning() {
    let init_network_size = 7;
    let elder_size = 8;
    let safe_section_size = 8;
    let env = Environment::new(NetworkParams {
        elder_size,
        safe_section_size,
    });
    let mut nodes = create_connected_nodes(&env, init_network_size);
    poll_and_resend(&mut nodes);

    let parsec_versions = |nodes: &Nodes| {
        nodes
            .iter()
            .map(|node| unwrap!(node.inner.elder_state()).parsec_last_version())
            .collect_vec()
    };

    let initial_parsec_versions = parsec_versions(&nodes);

    let mut rng = env.new_rng();
    // Keeps polling and dispatching user data till trigger a pruning.
    let max_gossips = 1_000;
    for _ in 0..max_gossips {
        let event = gen_vec(&mut rng, 10_000);
        nodes.iter_mut().for_each(|node| {
            let _ = node
                .inner
                .elder_state_mut()
                .map(|state| state.vote_for_user_event(event.clone()));
        });
        poll_and_resend(&mut nodes);

        let new_parsec_versions = parsec_versions(&nodes);
        if initial_parsec_versions
            .iter()
            .zip(new_parsec_versions.iter())
            .all(|(vi, vn)| vi < vn)
        {
            break;
        }
    }

    let expected = initial_parsec_versions.iter().map(|v| v + 1).collect_vec();
    let actual = parsec_versions(&nodes);
    assert_eq!(expected, actual);

    let node = create_node_with_contact(&env, &mut nodes[0]);
    nodes.push(node);

    poll_and_resend(&mut nodes);

    verify_invariant_for_all_nodes(&env, &mut nodes);
}

// The paused node does not participate until resumed, so we need enough elders to reach
// consensus even without it.
const NODE_PAUSE_AND_RESUME_PARAMS: NetworkParams = NetworkParams {
    elder_size: 4,
    safe_section_size: 4,
};

#[test]
fn node_pause_and_resume_simple() {
    let env = Environment::new(NODE_PAUSE_AND_RESUME_PARAMS);
    let nodes = create_connected_nodes(&env, 2 * env.safe_section_size() - 2);
    let new_node_id = FullId::gen(&mut env.new_rng());
    node_pause_and_resume(env, nodes, new_node_id)
}

#[test]
fn node_pause_and_resume_during_split() {
    let env = Environment::new(NODE_PAUSE_AND_RESUME_PARAMS);

    let mut nodes = create_connected_nodes(&env, env.safe_section_size());
    let prefix =
        add_connected_nodes_until_one_away_from_split(&env, &mut nodes, &[Prefix::default()])[0];

    let new_node_id = FullId::within_range(&mut env.new_rng(), &prefix.range_inclusive());
    node_pause_and_resume(env, nodes, new_node_id)
}

// Pause a random node, then add new node with the given id, then resume the paused node and verify
// everything still works as expected.
fn node_pause_and_resume(env: Environment, mut nodes: Nodes, new_node_id: FullId) {
    let index = env.new_rng().gen_range(0, nodes.len());
    let paused_id = nodes[index].id();
    let state = unwrap!(nodes.remove(index).inner.pause());

    // Verify the other nodes do not see the node as going offline.
    poll_and_resend(&mut nodes);
    assert!(nodes
        .iter()
        .all(|n| !n.inner.is_elder() || n.inner.is_peer_our_member(&paused_id)));

    // Do some work while the node is paused.
    let config = NetworkConfig::node().with_hard_coded_contact(nodes[0].endpoint());
    let node = TestNode::builder(&env)
        .network_config(config)
        .full_id(new_node_id)
        .create();
    nodes.push(node);
    info!(
        "node_pause_and_resume: adding node {}",
        nodes.last().unwrap().name()
    );

    poll_and_resend_with_options(&mut nodes, PollOptions::default().fire_join_timeout(false));

    // Resume the node and verify it caugh up to the changes in the network.
    nodes.push(TestNode::resume(&env, state));
    poll_and_resend(&mut nodes);
    verify_invariant_for_all_nodes(&env, &mut nodes);
}
