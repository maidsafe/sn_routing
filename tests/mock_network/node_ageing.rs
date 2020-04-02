// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    add_connected_nodes_until_one_away_from_split, add_node_to_section,
    create_connected_nodes_until_split, current_sections, indexed_nodes_with_prefix,
    nodes_with_prefix, poll_and_resend, poll_and_resend_with_options,
    verify_invariant_for_all_nodes, PollOptions, TestNode, LOWERED_ELDER_SIZE,
};
use rand::{
    distributions::{Distribution, Standard},
    seq::{IteratorRandom, SliceRandom},
    Rng,
};
use routing::{
    mock::Environment, rng::MainRng, NetworkParams, Prefix, PublicId, RelocationOverrides, XorName,
};
use std::iter;

// These params are selected such that there can be a section size which allows relocation and at the same time
// allows churn to happen which doesn't trigger split or allow churn to not increase age.
const NETWORK_PARAMS: NetworkParams = NetworkParams {
    elder_size: LOWERED_ELDER_SIZE,
    safe_section_size: LOWERED_ELDER_SIZE + 4,
};

#[test]
fn relocate_without_split() {
    let env = Environment::new(NETWORK_PARAMS);
    let mut overrides = RelocationOverrides::new();

    let mut rng = env.new_rng();
    let mut nodes = create_connected_nodes_until_split(&env, &[1, 1]);
    verify_invariant_for_all_nodes(&env, &mut nodes);

    let prefixes: Vec<_> = current_sections(&nodes).collect();
    let source_prefix = *prefixes.choose(&mut rng).unwrap();
    let target_prefix = *choose_other_prefix(&mut rng, &prefixes, &source_prefix);

    // Add another node to the source prefix. This is the node that will be relocated.
    add_node_to_section(&env, &mut nodes, &source_prefix);
    poll_and_resend(&mut nodes);
    let mut relocate_index = nodes.len() - 1;

    let destination = target_prefix.substituted_in(rng.gen());
    overrides.set(source_prefix, destination);

    // Create enough churn events so that the age of the new node increases which causes it to
    // be relocated.
    relocate_index = churn_until_age_counter(&env, &mut nodes, &source_prefix, relocate_index, 32);
    poll_and_resend(&mut nodes);
    verify_node_relocated(&nodes, relocate_index, &source_prefix, &target_prefix)
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
    poll_and_resend(&mut nodes);
    let relocate_index = nodes.len() - 1;

    let destination = trigger_prefix.substituted_in(rng.gen());
    overrides.set(source_prefix, destination);

    // Trigger relocation.
    let relocate_index =
        churn_until_age_counter(&env, &mut nodes, &source_prefix, relocate_index, 32);
    poll_and_resend(&mut nodes);
    verify_node_relocated(&nodes, relocate_index, &source_prefix, &target_prefix);

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
    poll_and_resend(&mut nodes);
    let mut relocate_index = nodes.len() - 1;

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
    poll_and_resend_with_options(
        &mut nodes,
        PollOptions::default().continue_if(move |nodes| {
            !node_relocated(nodes, relocate_index, &source_prefix, &target_prefix)
        }),
    )
}

fn choose_other_prefix<'a, R: Rng>(
    rng: &mut R,
    prefixes: &'a [Prefix<XorName>],
    except: &Prefix<XorName>,
) -> &'a Prefix<XorName> {
    assert!(prefixes.iter().any(|prefix| prefix != except));

    iter::repeat(())
        .filter_map(|_| prefixes.choose(rng))
        .find(|prefix| *prefix != except)
        .unwrap()
}

// Removes random node from the given section but makes sure it's not the node at the given index.
// Returns the index and the id of the removed node.
fn remove_random_node_from_section_except(
    rng: &mut MainRng,
    nodes: &mut Vec<TestNode>,
    prefix: &Prefix<XorName>,
    index_to_not_remove: usize,
) -> (usize, PublicId) {
    if let Some(index) = indexed_nodes_with_prefix(nodes, prefix)
        .filter(|(index, _)| *index != index_to_not_remove)
        .map(|(index, _)| index)
        .choose(rng)
    {
        let node = nodes.remove(index);
        info!("Remove node {} from {:?}", node.name(), prefix);
        (index, *node.id())
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
    prefix: &Prefix<XorName>,
    mut node_index: usize,
    target_age_counter: u32,
) -> usize {
    // Keep the section size such that relocations can happen but splits can't.
    // We need NETWORK_PARAMS.elder_size + 1 excluding relocating node for it to be demoted.
    let min_section_size = (NETWORK_PARAMS.elder_size + 1) + 1;

    // Ensure we are increasing age at each churn event.
    let max_section_size = NETWORK_PARAMS.safe_section_size - 1;
    assert!(min_section_size < max_section_size);

    let mut rng = env.new_rng();

    loop {
        let current_age_counter = node_age_counter(nodes, nodes[node_index].name());

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
                add_node_to_section(env, nodes, prefix);
                poll_and_resend_with_options(
                    nodes,
                    PollOptions::default()
                        .continue_if(|nodes| !node_joined(nodes, nodes.len() - 1)),
                );
            }
            Churn::Remove => {
                let (removed_index, id) =
                    remove_random_node_from_section_except(&mut rng, nodes, prefix, node_index);

                if removed_index < node_index {
                    node_index -= 1;
                }

                poll_and_resend_with_options(
                    nodes,
                    PollOptions::default().continue_if(move |nodes| !node_left(nodes, &id)),
                );
            }
        }
    }

    node_index
}

// Returns whether all nodes from its section recognize the node at the given index as joined.
fn node_joined(nodes: &[TestNode], node_index: usize) -> bool {
    let id = nodes[node_index].id();

    nodes
        .iter()
        .filter(|node| node.inner.is_elder())
        .filter(|node| {
            node.inner
                .our_prefix()
                .map(|prefix| prefix.matches(id.name()))
                .unwrap_or(false)
        })
        .all(|node| node.inner.is_peer_our_member(&id))
}

// Returns whether all nodes recognize the node with the given id as left.
fn node_left(nodes: &[TestNode], id: &PublicId) -> bool {
    nodes
        .iter()
        .filter(|node| node.inner.is_elder())
        .all(|node| !node.inner.is_peer_our_member(id))
}

// Returns whether the relocation of node at `node_index` from `source_prefix` to `target_prefix`
// is complete.
fn node_relocated(
    nodes: &[TestNode],
    node_index: usize,
    source_prefix: &Prefix<XorName>,
    target_prefix: &Prefix<XorName>,
) -> bool {
    let relocated_id = nodes[node_index].id();

    for node in nodes_with_prefix(nodes, source_prefix) {
        if !node.inner.is_elder() {
            continue;
        }

        if node.inner.is_peer_our_member(&relocated_id) {
            trace!(
                "Node {} is member of the source section {:?} according to {}",
                relocated_id.name(),
                source_prefix,
                node.name()
            );
            return false;
        }
    }

    for node in nodes_with_prefix(nodes, target_prefix) {
        if !node.inner.is_elder() {
            continue;
        }

        let node_prefix = node.inner.our_prefix().unwrap();
        if node_prefix.is_extension_of(target_prefix) && !node_prefix.matches(relocated_id.name()) {
            // Target section has split and the relocated node is in the other sub-section than this node.
            continue;
        }

        if !node.inner.is_peer_our_member(&relocated_id) {
            trace!(
                "Node {} is not member of the target section {:?} according to {}",
                relocated_id.name(),
                target_prefix,
                node.name()
            );
            return false;
        }
    }

    true
}

fn verify_node_relocated(
    nodes: &[TestNode],
    node_index: usize,
    source_prefix: &Prefix<XorName>,
    target_prefix: &Prefix<XorName>,
) {
    assert!(
        node_relocated(nodes, node_index, source_prefix, target_prefix),
        "Node {} did not get relocated from {:?} to {:?}",
        nodes[node_index].name(),
        source_prefix,
        target_prefix
    );
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
