// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::utils::*;
use rand::{
    distributions::{Distribution, Standard},
    seq::{IteratorRandom, SliceRandom},
    Rng,
};
use routing::{
    mock::Environment, rng::MainRng, NetworkParams, Prefix, RelocationOverrides, XorName, MIN_AGE,
};
use std::iter;

// These params are selected such that there can be a section size which allows relocation and at the same time
// allows churn to happen which doesn't trigger split or allow churn to not increase age.
const NETWORK_PARAMS: NetworkParams = NetworkParams {
    elder_size: MIN_ELDER_SIZE,
    recommended_section_size: MIN_ELDER_SIZE + 4,
};

#[test]
fn relocate_without_split() {
    let env = Environment::new(NETWORK_PARAMS);
    let mut overrides = RelocationOverrides::new();

    let mut rng = env.new_rng();
    let mut nodes = create_connected_nodes_until_split(&env, &[1, 1]);
    verify_invariants_for_nodes(&env, &nodes);

    let prefixes: Vec<_> = current_sections(&nodes).collect();
    let source_prefix = *prefixes.choose(&mut rng).unwrap();
    let target_prefix = *choose_other_prefix(&mut rng, &prefixes, &source_prefix);

    // Add another node to the source prefix. This is the node that will be relocated.
    add_node_to_section(&env, &mut nodes, &source_prefix);
    let mut relocate_index = nodes.len() - 1;
    poll_until(&env, &mut nodes, |nodes| node_joined(nodes, relocate_index));

    let destination = target_prefix.substituted_in(rng.gen());
    overrides.set(source_prefix, destination);

    // Create enough churn events so that the age of the new node increases which causes it to
    // be relocated.
    relocate_index = churn_until_age_counter(&env, &mut nodes, &source_prefix, relocate_index, 32);
    poll_until(&env, &mut nodes, |nodes| {
        node_relocated(nodes, relocate_index, &source_prefix, &target_prefix)
    });
}

#[test]
fn relocate_causing_split() {
    // Note: this test doesn't always trigger split in the target section. This is because when the
    // target section receives the bootstrap request from the relocating node, it still has its
    // pre-split prefix which it gives to the node. So the node then generates random name matching
    // that prefix which will fall into the split-triggering subsection only ~50% of the time.
    //
    // We might consider trying to figure a way to force the relocation into the correct
    // sub-interval, but the test is still useful as is for soak testing.

    // Relocate node into a section which is one node shy of splitting.
    let env = Environment::new(NETWORK_PARAMS);
    let mut overrides = RelocationOverrides::new();

    let mut rng = env.new_rng();
    let mut nodes = create_connected_nodes_until_split(&env, &[1, 1]);

    let prefixes: Vec<_> = current_sections(&nodes).collect();
    let source_prefix = *prefixes.choose(&mut rng).unwrap();
    let target_prefix = *choose_other_prefix(&mut rng, &prefixes, &source_prefix);

    let trigger_prefix =
        add_connected_nodes_until_one_away_from_split(&env, &mut nodes, &target_prefix);

    add_node_to_section(&env, &mut nodes, &source_prefix);
    let mut relocate_index = nodes.len() - 1;
    poll_until(&env, &mut nodes, |nodes| node_joined(nodes, relocate_index));

    let destination = trigger_prefix.substituted_in(rng.gen());
    overrides.set(source_prefix, destination);

    // Trigger relocation.
    relocate_index = churn_until_age_counter(&env, &mut nodes, &source_prefix, relocate_index, 32);
    poll_until(&env, &mut nodes, |nodes| {
        node_relocated(&nodes, relocate_index, &source_prefix, &target_prefix)
    });

    // Check whether the destination section split.
    let split = nodes_with_prefix(&nodes, &target_prefix)
        .all(|node| node.our_prefix().is_extension_of(&target_prefix));
    debug!(
        "The target section {:?} {} split",
        target_prefix,
        if split { "did" } else { "did not" },
    );
}

// This test is ignored because it currently fails in the following case:
// A node is relocated to the target section, successfully bootstraps and is about to send
// `JoinRequest`. At the same time, the target section splits. One half of the former section
// matches the new name of the relocated node, but does not match the relocate destination. The
// other half is the other way around. Both thus reject the `JoinRequest` and the node relocation
// fails.
// TODO: find a way to address this issue.
#[ignore]
#[test]
fn relocate_during_split() {
    // Relocate node into a section which is undergoing split.
    let env = Environment::new(NETWORK_PARAMS);
    let mut overrides = RelocationOverrides::new();

    let mut rng = env.new_rng();
    let mut nodes = create_connected_nodes_until_split(&env, &[1, 1]);

    let prefixes: Vec<_> = current_sections(&nodes).collect();
    let source_prefix = *prefixes.choose(&mut rng).unwrap();
    let target_prefix = *choose_other_prefix(&mut rng, &prefixes, &source_prefix);

    add_node_to_section(&env, &mut nodes, &source_prefix);
    let mut relocate_index = nodes.len() - 1;
    poll_until(&env, &mut nodes, |nodes| node_joined(nodes, relocate_index));

    let _ = add_connected_nodes_until_one_away_from_split(&env, &mut nodes, &target_prefix);

    let destination = target_prefix.substituted_in(rng.gen());
    overrides.set(source_prefix, destination);

    // Create churn so we are one churn away from relocation.
    relocate_index = churn_until_age_counter(&env, &mut nodes, &source_prefix, relocate_index, 31);

    // Add new node, but do not poll yet.
    add_node_to_section(&env, &mut nodes, &target_prefix);

    // One more churn to trigger the relocation.
    relocate_index = churn_until_age_counter(&env, &mut nodes, &source_prefix, relocate_index, 32);

    // Poll now, so the add and the relocation happen simultaneously.
    poll_until(&env, &mut nodes, |nodes| {
        node_relocated(nodes, relocate_index, &source_prefix, &target_prefix)
    })
}

// Test that during startup phase all churn events cause age increments.
#[test]
fn startup_phase() {
    let env = Environment::new(NETWORK_PARAMS);
    let mut nodes = vec![];

    // Only the first `recommended_section_size - 1` adds cause age increments, the rest does not.
    for i in 0..(env.recommended_section_size() + 1) {
        trace!("add node {}", i);
        add_node_to_section(&env, &mut nodes, &Prefix::default());

        poll_until(&env, &mut nodes, |nodes| {
            node_joined(nodes, nodes.len() - 1)
        });

        poll_until(&env, &mut nodes, |nodes| {
            check_root_section_age_counters_after_only_adds(&env, nodes)
        })
    }
}

// Verify that the age counters of all the nodes in the root section are as expected, assuming we
// were only adding nodes, not removing.
fn check_root_section_age_counters_after_only_adds(env: &Environment, nodes: &[TestNode]) -> bool {
    // Maximum number of churn events a node can experience during the startup phase:
    // The startup phase last only while the section has less than recommended_section_size nodes which
    // means it has been through at most recommended_section_size - 1 adds. We need to subtract one to
    // discount the node itself because its age is not affected by its own churn.
    let max_startup_churn_events = nodes.len().min(env.recommended_section_size() - 1) - 1;

    for i in 0..nodes.len() {
        assert!(
            nodes[i]
                .inner
                .our_prefix()
                .map(|prefix| *prefix == Prefix::default())
                .unwrap_or(true),
            "the root section has split"
        );

        // The number of churn events that the i-th node experienced during the startup phase.
        let startup_churn_events = max_startup_churn_events.saturating_sub(i) as u8;

        let expected_age = (MIN_AGE + startup_churn_events) as u32;
        let expected_age_counter = 2u32.pow(expected_age);
        let actual_age_counter = node_age_counter(&nodes, nodes[i].name());

        if actual_age_counter != expected_age_counter {
            trace!(
                "node {} (name: {}) age counter: {} (expected: {})",
                i,
                nodes[i].name(),
                actual_age_counter,
                expected_age_counter,
            );
            return false;
        }
    }

    true
}

fn choose_other_prefix<'a, R: Rng>(
    rng: &mut R,
    prefixes: &'a [Prefix],
    except: &Prefix,
) -> &'a Prefix {
    assert!(prefixes.iter().any(|prefix| prefix != except));

    iter::repeat(())
        .filter_map(|_| prefixes.choose(rng))
        .find(|prefix| *prefix != except)
        .unwrap()
}

// Removes random node from the given section but makes sure it's not the node at the given index.
// Returns the index of the removed node and its name.
fn remove_random_node_from_section_except(
    rng: &mut MainRng,
    nodes: &mut Vec<TestNode>,
    prefix: &Prefix,
    index_to_not_remove: usize,
) -> (usize, XorName) {
    if let Some(index) = indexed_nodes_with_prefix(nodes, prefix)
        .filter(|(index, _)| *index != index_to_not_remove)
        .map(|(index, _)| index)
        .choose(rng)
    {
        let node = nodes.remove(index);
        info!(
            "Removing node {} from {:?} (was elder: {})",
            node.name(),
            prefix,
            node.inner.is_elder(),
        );
        (index, *node.name())
    } else {
        panic!(
            "Section {:?} does not have any nodes that can be removed",
            prefix
        );
    }
}

// Keep adding and removing nodes until the node at the given index reaches the given age counter.
// Returns the new index of the node in case it changed due to some nodes being removed.
fn churn_until_age_counter(
    env: &Environment,
    nodes: &mut Vec<TestNode>,
    prefix: &Prefix,
    mut node_index: usize,
    target_age_counter: u32,
) -> usize {
    // Keep the section size such that relocations can happen but splits can't.
    // We need NETWORK_PARAMS.elder_size + 1 excluding relocating node for it to be demoted.
    let min_section_size = (NETWORK_PARAMS.elder_size + 1) + 1;

    // Ensure we are increasing age at each churn event.
    let max_section_size = NETWORK_PARAMS.recommended_section_size - 1;
    assert!(min_section_size < max_section_size);

    // Store the name here in case it changes due to relocation.
    let node_name = *nodes[node_index].name();

    let mut rng = env.new_rng();

    loop {
        let current_age_counter = node_age_counter(nodes, &node_name);

        info!(
            "churn_until_age_counter - node {}, age_counter {}/{}",
            nodes[node_index].name(),
            current_age_counter,
            target_age_counter
        );

        if current_age_counter >= target_age_counter {
            break;
        }

        let section_size = nodes_with_prefix(nodes, prefix).count();
        let churn = if section_size <= min_section_size {
            Churn::Add
        } else if section_size >= max_section_size {
            Churn::Remove
        } else {
            rng.gen()
        };

        match churn {
            Churn::Add => {
                // We are making lot of churn here and so it might happen that other section's view
                // of this section could become so out-of-date that none of the nodes they know is
                // still online. If we picked such node for the bootstrap node, the bootstrapping
                // would fail because the node would keep redirecting the joining node to
                // non-existing peers. To avoid this and to keep things simple, we make sure we
                // bootstrap off a node from the same section that we are joining.
                let bootstrap_index = indexed_nodes_with_prefix(nodes, prefix)
                    .choose(&mut rng)
                    .map(|(index, _)| index)
                    .unwrap();
                add_node_to_section_using_bootstrap_node(env, nodes, prefix, bootstrap_index);
                poll_until(env, nodes, |nodes| node_joined(nodes, nodes.len() - 1));
            }
            Churn::Remove => {
                let (removed_index, removed_name) =
                    remove_random_node_from_section_except(&mut rng, nodes, prefix, node_index);

                if removed_index < node_index {
                    node_index -= 1;
                }

                poll_until(env, nodes, |nodes| node_left(nodes, &removed_name));

                // Using threshold of 3 because removing one node can trigger another one to be
                // relocated, but we still want to be left with at least one known node.
                update_neighbours_and_poll(env, nodes, 3);
            }
        }
    }

    node_index
}

// Returns whether the relocation of node at `node_index` from `source_prefix` to `target_prefix`
// is complete.
fn node_relocated(
    nodes: &[TestNode],
    node_index: usize,
    source_prefix: &Prefix,
    target_prefix: &Prefix,
) -> bool {
    let relocated_name = nodes[node_index].name();

    for node in elders_with_prefix(nodes, source_prefix) {
        if node.inner.is_peer_our_member(&relocated_name) {
            trace!(
                "Node {} is member of the source section {:?} according to {}",
                relocated_name,
                source_prefix,
                node.name()
            );
            return false;
        }
    }

    for node in elders_with_prefix(nodes, target_prefix) {
        let node_prefix = node.inner.our_prefix().unwrap();
        if node_prefix.is_extension_of(target_prefix) && !node_prefix.matches(relocated_name) {
            // Target section has split and the relocated node is in the other sub-section than this node.
            continue;
        }

        if !node.inner.is_peer_our_member(&relocated_name) {
            trace!(
                "Node {} is not member of the target section {:?} according to {}",
                relocated_name,
                target_prefix,
                node.name()
            );
            return false;
        }
    }

    true
}

// Returns the age counter of the node with the given name.
fn node_age_counter(nodes: &[TestNode], name: &XorName) -> u32 {
    if let Some(counter) = nodes
        .iter()
        .filter_map(|node| node.inner.member_age_counter(name))
        .max()
    {
        counter
    } else {
        panic!("{} is not a member known to any node", name)
    }
}

#[derive(Debug, Eq, PartialEq)]
enum Churn {
    Add,
    Remove,
}

impl Distribution<Churn> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Churn {
        if rng.gen() {
            Churn::Add
        } else {
            Churn::Remove
        }
    }
}
