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
pub mod utils;

use self::utils::*;
use itertools::Itertools;
use rand::{seq::SliceRandom, Rng};
use routing::{
    event::Event, mock::Environment, test_consts, NetworkParams, PausedState, Prefix,
    TransportConfig,
};
use sn_fake_clock::FakeClock;
use std::collections::BTreeMap;

// -----  Miscellaneous tests below  -----

fn test_nodes(percentage_size: usize) {
    let size = MIN_ELDER_SIZE * percentage_size / 100;
    let env = Environment::new(NetworkParams {
        elder_size: MIN_ELDER_SIZE,
        // Require at least one non-elder to make things more interesting.
        recommended_section_size: MIN_ELDER_SIZE + 1,
    });
    let nodes = create_connected_nodes(&env, size);
    verify_invariants_for_nodes(&env, &nodes);
}

fn create_node_with_contact(env: &Environment, contact: &mut TestNode) -> TestNode {
    let config = TransportConfig::node().with_hard_coded_contact(contact.endpoint());
    TestNode::builder(&env).transport_config(config).create()
}

#[test]
// TODO (quic-p2p): This test requires bootstrap blacklist which isn't implemented in quic-p2p.
#[ignore]
fn disconnect_on_rebootstrap() {
    let env = Environment::new(NetworkParams {
        elder_size: MIN_ELDER_SIZE,
        recommended_section_size: MIN_ELDER_SIZE,
    });
    let mut nodes = create_connected_nodes(&env, 2);

    // Try to bootstrap to another than the first node. With network size 2, this should fail.
    let config = TransportConfig::node().with_hard_coded_contact(nodes[1].endpoint());
    nodes.push(TestNode::builder(&env).transport_config(config).create());
    poll_all(&env, &mut nodes);

    // When retrying to bootstrap, we should have disconnected from the bootstrap node.
    assert!(!env.is_connected(&nodes[2].endpoint(), &nodes[1].endpoint()));

    expect_next_event!(nodes.last_mut().unwrap(), Event::Terminated);
}

#[test]
fn single_section() {
    let sec_size = 10;
    let env = Environment::new(NetworkParams {
        recommended_section_size: sec_size,
        ..Default::default()
    });
    let nodes = create_connected_nodes(&env, sec_size);
    verify_invariants_for_nodes(&env, &nodes);
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
        elder_size: MIN_ELDER_SIZE,
        recommended_section_size: MIN_ELDER_SIZE,
    });
    let mut nodes = create_connected_nodes(&env, 2 * MIN_ELDER_SIZE);
    let transport_config = TransportConfig::node().with_hard_coded_contact(nodes[0].endpoint());
    nodes.insert(
        0,
        TestNode::builder(&env)
            .transport_config(transport_config)
            .create(),
    );

    poll_until(&env, &mut nodes, |nodes| node_joined(nodes, 0));
    verify_invariants_for_nodes(&env, &nodes);
}

#[test]
fn multiple_joining_nodes() {
    let env = Environment::new(NetworkParams {
        elder_size: MIN_ELDER_SIZE,
        recommended_section_size: MIN_ELDER_SIZE,
    });

    let iterations = 10;
    let min_adds_per_iteration = 2;
    let max_adds_per_iteration = 10;

    let mut rng = env.new_rng();
    let mut nodes = create_connected_nodes(&env, MIN_ELDER_SIZE);

    for _ in 0..iterations {
        let adds = rng.gen_range(min_adds_per_iteration, max_adds_per_iteration + 1);
        let mut nodes_to_add: Vec<_> = (0..adds)
            .map(|_| create_node_with_contact(&env, &mut nodes[0]))
            .collect();

        info!(
            "Simultaneously adding nodes: {}",
            nodes_to_add.iter().map(|node| node.name()).format(", ")
        );

        let first_index = nodes.len();

        nodes.append(&mut nodes_to_add);

        poll_until(&env, &mut nodes, |nodes| {
            all_nodes_joined(nodes, first_index..nodes.len())
        });
    }
}

#[test]
fn single_split() {
    let env = Environment::new(NetworkParams {
        elder_size: MIN_ELDER_SIZE,
        // The smallest `recommended_section_size` where when a split happens, the set of elders
        // post-split in at least one of the sub-sections might be completely different from the
        // set of elders pre-split. This setup exposed a bug before and we want to have it covered.
        recommended_section_size: MIN_ELDER_SIZE + 3,
    });
    let mut nodes = vec![];
    trigger_split(&env, &mut nodes, &Prefix::default());
}

#[test]
fn multi_split() {
    let env = Environment::new(NetworkParams {
        elder_size: MIN_ELDER_SIZE,
        recommended_section_size: MIN_ELDER_SIZE + 1,
    });
    let nodes = create_connected_nodes_until_split(&env, &[2, 2, 2, 2]);
    verify_invariants_for_nodes(&env, &nodes);
}

struct SimultaneousJoiningNode {
    // Destination section prefix: Use as relocation_dst for nodes in src_section_prefix.
    _dst_section_prefix: Prefix,
    // Section prefix that will match the initial id of the node to add.
    src_section_prefix: Prefix,
    // The prefix to find the proxy within.
    proxy_prefix: Prefix,
}

// Proceed with testing joining nodes at the same time with the given configuration.
fn simultaneous_joining_nodes(
    env: Environment,
    mut nodes: Vec<TestNode>,
    nodes_to_add_setup: &[SimultaneousJoiningNode],
) {
    // Setup nodes so relocation will happen as specified by nodes_to_add_setup.
    //
    let mut rng = env.new_rng();
    nodes.shuffle(&mut rng);

    // TODO: relocation overrides are gone. Figure out how to get by without them.
    // let mut overrides = RelocationOverrides::new();

    let mut nodes_to_add = Vec::new();
    for setup in nodes_to_add_setup {
        // TODO: relocation overrides are gone...
        // // Set the specified relocation destination on the nodes of the given prefixes
        // let relocation_dst = setup.dst_section_prefix.substituted_in(rng.gen());
        // overrides.set(setup.src_section_prefix, relocation_dst);

        // Create nodes and find proxies from the given prefixes
        let node_to_add = {
            // Get random new TestNode from within src_prefix
            loop {
                // Get random bootstrap node from within proxy_prefix
                let config = {
                    let mut compatible_proxies =
                        nodes_with_prefix_mut(&mut nodes, &setup.proxy_prefix).collect_vec();
                    compatible_proxies.shuffle(&mut rng);

                    TransportConfig::node()
                        .with_hard_coded_contact(nodes.first_mut().unwrap().endpoint())
                };

                let node = TestNode::builder(&env).transport_config(config).create();
                if setup.src_section_prefix.matches(node.name()) {
                    break node;
                }
            }
        };
        nodes_to_add.push(node_to_add);
    }

    let first_index = nodes.len();
    nodes.extend(nodes_to_add);

    poll_until(&env, &mut nodes, |nodes| {
        all_nodes_joined(nodes, first_index..nodes.len())
            && all_sections_have_enough_elders(&env, nodes)
    });

    verify_invariants_for_nodes(&env, &nodes);
}

fn all_sections_have_enough_elders(env: &Environment, nodes: &[TestNode]) -> bool {
    let elders_count_by_prefix = nodes
        .iter()
        .filter(|node| node.inner.is_elder())
        .filter_map(|node| node.inner.our_prefix())
        .fold(BTreeMap::<_, usize>::new(), |mut counts, prefix| {
            *counts.entry(*prefix).or_default() += 1;
            counts
        });

    let mut prefixes_not_enough_elders = elders_count_by_prefix
        .into_iter()
        .filter(|(_, num_elders)| *num_elders < env.elder_size())
        .map(|(prefix, _)| prefix)
        .peekable();

    if prefixes_not_enough_elders.peek().is_none() {
        true
    } else {
        trace!(
            "Prefixes with too few elders: {:?}",
            prefixes_not_enough_elders.format(", ")
        );
        false
    }
}

#[test]
fn simultaneous_joining_nodes_two_sections() {
    // Create a network with two sections:
    let env = Environment::new(NetworkParams {
        elder_size: MIN_ELDER_SIZE,
        recommended_section_size: MIN_ELDER_SIZE,
    });
    let nodes = create_connected_nodes_until_split(&env, &[1, 1]);

    let prefix_0 = Prefix::default().pushed(false);
    let prefix_1 = Prefix::default().pushed(true);

    // Relocate nodes to the section they were spawned in with a proxy from prefix_0
    let nodes_to_add_setup = vec![
        SimultaneousJoiningNode {
            _dst_section_prefix: prefix_0,
            src_section_prefix: prefix_0,
            proxy_prefix: prefix_0,
        },
        SimultaneousJoiningNode {
            _dst_section_prefix: prefix_1,
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
        elder_size: MIN_ELDER_SIZE,
        recommended_section_size: MIN_ELDER_SIZE,
    });
    let nodes = create_connected_nodes_until_split(&env, &[1, 1]);

    let prefix_0 = Prefix::default().pushed(false);
    let prefix_1 = Prefix::default().pushed(true);

    // Relocate nodes to the section they were not spawned in with a proxy from prefix_0
    let nodes_to_add_setup = vec![
        SimultaneousJoiningNode {
            _dst_section_prefix: prefix_0,
            src_section_prefix: prefix_1,
            proxy_prefix: prefix_0,
        },
        SimultaneousJoiningNode {
            _dst_section_prefix: prefix_1,
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
    let elder_size = MIN_ELDER_SIZE + 1;
    let recommended_section_size = MIN_ELDER_SIZE + 1;

    // Create a network with three sections:
    let env = Environment::new(NetworkParams {
        elder_size,
        recommended_section_size,
    });
    let mut nodes = create_connected_nodes_until_split(&env, &[1, 2, 2]);

    // The created sections
    let sections = current_sections(&nodes).collect_vec();
    let short_prefix = *sections
        .iter()
        .find(|prefix| prefix.bit_count() == 1)
        .unwrap();
    let long_prefix_0 = *sections
        .iter()
        .find(|prefix| prefix.bit_count() == 2)
        .unwrap();
    let long_prefix_1 = long_prefix_0.sibling();

    // Setup the network so the short_prefix will split with one more node in short_prefix_to_add.
    let _ = add_connected_nodes_until_one_away_from_split(&env, &mut nodes, &short_prefix);

    // First node will trigger the split: src, destination and proxy together.
    // Other nodes validate getting relocated to a section with a proxy from section splitting
    // which will no longer be a neighbour after the split.
    let nodes_to_add_setup = vec![
        SimultaneousJoiningNode {
            _dst_section_prefix: short_prefix,
            src_section_prefix: short_prefix,
            proxy_prefix: short_prefix,
        },
        SimultaneousJoiningNode {
            _dst_section_prefix: long_prefix_0,
            src_section_prefix: short_prefix,
            proxy_prefix: long_prefix_0.with_flipped_bit(0).with_flipped_bit(1),
        },
        SimultaneousJoiningNode {
            _dst_section_prefix: long_prefix_1,
            src_section_prefix: long_prefix_0,
            proxy_prefix: long_prefix_1.with_flipped_bit(0).with_flipped_bit(1),
        },
    ];
    simultaneous_joining_nodes(env, nodes, &nodes_to_add_setup);
}

#[test]
fn check_close_names_for_elder_size_nodes() {
    let env = Environment::new(NetworkParams {
        elder_size: MIN_ELDER_SIZE,
        recommended_section_size: MIN_ELDER_SIZE,
    });
    let mut nodes = create_connected_nodes(&env, MIN_ELDER_SIZE);

    poll_until(&env, &mut nodes, |nodes| {
        nodes
            .iter()
            .all(|n| nodes.iter().all(|m| m.close_names().contains(n.name())))
    })
}

#[test]
fn sibling_knowledge_update_after_split() {
    let env = Environment::new(NetworkParams {
        elder_size: MIN_ELDER_SIZE,
        recommended_section_size: MIN_ELDER_SIZE,
    });

    let mut nodes = create_connected_nodes_until_split(&env, &[1, 1]);

    poll_until(&env, &mut nodes, |nodes| {
        for node in nodes {
            if !node.inner.is_elder() {
                trace!("Node {} is not elder yet", node.name());
                return false;
            }

            if node.inner.get_their_knowledge(&node.our_prefix().sibling()) == 0 {
                trace!("Node {} does not have sibling knowledge yet", node.name());
                return false;
            }
        }

        true
    });
}

#[test]
fn node_pause_and_resume_simple() {
    let env = Environment::new(NetworkParams {
        elder_size: MIN_ELDER_SIZE,
        recommended_section_size: MIN_ELDER_SIZE + 1,
    });

    let mut nodes = create_connected_nodes(&env, env.recommended_section_size());
    let paused_state = pause_node_and_poll(&env, &mut nodes);

    add_node_to_section(&env, &mut nodes, &Prefix::default());
    poll_until(&env, &mut nodes, |nodes| {
        node_joined(nodes, nodes.len() - 1)
    });
    let new_id = *nodes.last().unwrap().id();

    nodes.push(TestNode::resume(paused_state));

    // If the paused node is elder, verify it caught up to the new node joining.
    if nodes.last().unwrap().inner.is_elder() {
        poll_until(&env, &mut nodes, |nodes| {
            nodes
                .last()
                .unwrap()
                .inner
                .is_peer_our_member(new_id.name())
        })
    }

    verify_invariants_for_nodes(&env, &nodes);
}

#[test]
fn node_pause_and_resume_during_split() {
    let env = Environment::new(NetworkParams {
        elder_size: MIN_ELDER_SIZE,
        recommended_section_size: MIN_ELDER_SIZE + 1,
    });

    let mut nodes = vec![];
    add_mature_nodes(
        &env,
        &mut nodes,
        &Prefix::default(),
        env.recommended_section_size(),
        env.recommended_section_size(),
    );

    let paused_state = pause_node_and_poll(&env, &mut nodes);
    nodes.push(TestNode::resume(paused_state));

    poll_until(&env, &mut nodes, |nodes| {
        section_split(nodes, &Prefix::default())
    });

    verify_invariants_for_nodes(&env, &nodes);
}

// Pauses a random node and poll the network for a while. Returns the paused state.
fn pause_node_and_poll(env: &Environment, nodes: &mut Vec<TestNode>) -> PausedState {
    let index = env.new_rng().gen_range(0, nodes.len());
    let name = *nodes[index].name();
    let state = nodes.remove(index).inner.pause().unwrap();

    // Poll the network for a while and verify the other nodes do not see the node as going offline.
    let start_time = FakeClock::now();

    // Let at most this much time to pass to make sure the paused node is not detected as unresponsive.
    let poll_duration = (test_consts::RESEND_MAX_ATTEMPTS - 1) as u32 * test_consts::RESEND_DELAY;

    poll_until(&env, nodes, |_| start_time.elapsed() >= poll_duration);

    assert!(nodes
        .iter()
        .filter(|node| node.our_prefix().matches(&name) && node.inner.is_elder())
        .all(|node| node.inner.is_peer_our_member(&name)));

    state
}

#[test]
fn neighbour_update() {
    // 1. Create two sections, A and B.
    // 2. Change the set of elders of B.
    // 3. Send a message from A to B to make B send update to A.
    // 4. Verify A's view of B is up to date.

    let env = Environment::new(NetworkParams {
        elder_size: MIN_ELDER_SIZE,
        recommended_section_size: MIN_ELDER_SIZE + 1,
    });
    let mut rng = env.new_rng();
    let mut nodes = create_connected_nodes_until_split(&env, &[1, 1]);

    let prefix_a = Prefix::default().pushed(rng.gen());
    let prefix_b = prefix_a.sibling();

    // A's view of B is initially up to date.
    assert!(section_knowledge_is_up_to_date(
        &nodes,
        &prefix_a,
        &prefix_b,
        env.elder_size()
    ));

    // Remove at most elder_size - 1 elders, so section A still knows at least one elder from B and
    // so can still contact them.
    let num_elders_to_remove = rng.gen_range(1, MIN_ELDER_SIZE);
    info!(
        "Removing {} elders from {:?}",
        num_elders_to_remove, prefix_b
    );

    // Add nodes that will replace the removed elders.
    for _ in 0..num_elders_to_remove {
        add_node_to_section(&env, &mut nodes, &prefix_b);
    }
    poll_until(&env, &mut nodes, |nodes| {
        all_nodes_joined(nodes, 0..nodes.len())
    });

    // Remove some elders from B.
    for _ in 0..num_elders_to_remove {
        let name = remove_elder_from_section(&mut nodes, &prefix_b);
        poll_until(&env, &mut nodes, |nodes| node_left(nodes, &name));
    }

    // Now A's knowledge of B is out of date.
    assert!(!section_knowledge_is_up_to_date(
        &nodes,
        &prefix_a,
        &prefix_b,
        env.elder_size()
    ));

    // Send a message from A to B to trigger the update.
    send_user_message(&mut nodes, prefix_a, prefix_b, gen_vec(&mut rng, 10));
    poll_until(&env, &mut nodes, |nodes| {
        section_knowledge_is_up_to_date(nodes, &prefix_a, &prefix_b, env.elder_size())
    });
}
