// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    add_connected_nodes_until_one_away_from_split, create_connected_nodes_until_split,
    create_connected_nodes_until_split_with_options, current_sections, nodes_with_prefix,
    nodes_with_prefix_mut, poll_and_resend_with_options, ChurnOptions, PollOptions, TestNode,
    LOWERED_ELDER_SIZE,
};
use rand::{Rand, Rng};
use routing::{
    mock::Network, FullId, NetworkConfig, NetworkParams, Prefix, PublicId, XorName, MIN_AGE,
};
use std::{iter, slice};

// These params are selected such that there can be a section size which allows relocation and at the same time
// allows churn to happen which doesn't trigger split.
const NETWORK_PARAMS: NetworkParams = NetworkParams {
    elder_size: LOWERED_ELDER_SIZE,
    safe_section_size: LOWERED_ELDER_SIZE + 3,
};

#[test]
fn relocate_without_split() {
    let network = Network::new(NETWORK_PARAMS);
    let mut rng = network.new_rng();
    let mut nodes = create_connected_nodes_until_split_with_options(
        &network,
        vec![1, 1],
        ChurnOptions {
            suppress_relocation: true,
        },
    );

    let prefixes: Vec<_> = current_sections(&nodes).collect();

    // `nodes[0]` is the oldest node, so it's the first one to be relocated when its age increases.
    // So let's pick the prefix it is in as the source prefix.
    let source_prefix = *find_matching_prefix(&prefixes, &nodes[0].name());
    let target_prefix = *choose_other_prefix(&mut rng, &prefixes, &source_prefix);

    let destination = target_prefix.substituted_in(rng.gen());
    for node in nodes_with_prefix_mut(&mut nodes, &source_prefix) {
        node.inner.set_next_relocation_dst(Some(destination));
    }

    // Create enough churn events so that the age of the oldest node increases which causes it to
    // be relocated.
    let oldest_age_counter = oldest_age_counter_after_only_adds(&nodes);
    let num_churns = oldest_age_counter.next_power_of_two() - oldest_age_counter;

    // Keep the section size such that relocations can happen but splits can't.
    section_churn(
        num_churns,
        &network,
        &mut nodes,
        &source_prefix,
        NETWORK_PARAMS.elder_size + 1,
        NETWORK_PARAMS.elder_size + 2,
    );

    poll_and_resend_with_options(
        &mut nodes,
        PollOptions::default()
            .continue_if(move |nodes| !node_relocated(nodes, 0, &source_prefix, &target_prefix))
            .fire_join_timeout(false),
    )
}

#[test]
fn relocate_causing_split() {
    // Relocate node into a section which is one node shy of splitting.
    let network = Network::new(NETWORK_PARAMS);
    let mut rng = network.new_rng();
    let mut nodes = create_connected_nodes_until_split_with_options(
        &network,
        vec![1, 1],
        ChurnOptions {
            suppress_relocation: true,
        },
    );
    let oldest_age_counter = oldest_age_counter_after_only_adds(&nodes);

    let prefixes: Vec<_> = current_sections(&nodes).collect();
    let source_prefix = *find_matching_prefix(&prefixes, &nodes[0].name());
    let target_prefix = *choose_other_prefix(&mut rng, &prefixes, &source_prefix);

    let _ = add_connected_nodes_until_one_away_from_split(
        &network,
        &mut nodes,
        slice::from_ref(&target_prefix),
        ChurnOptions {
            suppress_relocation: true,
        },
    );

    let destination = target_prefix.substituted_in(rng.gen());
    for node in nodes_with_prefix_mut(&mut nodes, &source_prefix) {
        node.inner.set_next_relocation_dst(Some(destination));
    }

    // Trigger relocation.
    let num_churns = oldest_age_counter.next_power_of_two() - oldest_age_counter;
    section_churn(
        num_churns,
        &network,
        &mut nodes,
        &source_prefix,
        NETWORK_PARAMS.elder_size + 1,
        NETWORK_PARAMS.elder_size + 2,
    );

    poll_and_resend_with_options(
        &mut nodes,
        PollOptions::default()
            .continue_if(move |nodes| !node_relocated(nodes, 0, &source_prefix, &target_prefix))
            .fire_join_timeout(false),
    )
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
    let network = Network::new(NETWORK_PARAMS);
    let mut rng = network.new_rng();
    let mut nodes = create_connected_nodes_until_split_with_options(
        &network,
        vec![1, 1],
        ChurnOptions {
            suppress_relocation: true,
        },
    );
    let oldest_age_counter = oldest_age_counter_after_only_adds(&nodes);

    let prefixes: Vec<_> = current_sections(&nodes).collect();
    let source_prefix = *unwrap!(rng.choose(&prefixes));
    let target_prefix = *choose_other_prefix(&mut rng, &prefixes, &source_prefix);

    let _ = add_connected_nodes_until_one_away_from_split(
        &network,
        &mut nodes,
        slice::from_ref(&target_prefix),
        ChurnOptions {
            suppress_relocation: true,
        },
    );

    let destination = target_prefix.substituted_in(rng.gen());
    for node in nodes_with_prefix_mut(&mut nodes, &source_prefix) {
        node.inner.set_next_relocation_dst(Some(destination));
    }

    // Create churn so we are one churn away from relocation.
    let num_churns = oldest_age_counter.next_power_of_two() - oldest_age_counter - 1;
    section_churn(
        num_churns,
        &network,
        &mut nodes,
        &source_prefix,
        NETWORK_PARAMS.elder_size + 1,
        NETWORK_PARAMS.elder_size + 2,
    );

    // Add new node, but do not poll yet.
    add_node_to_prefix(&network, &mut nodes, &target_prefix);

    // One more churn to trigger the relocation.
    section_churn(1, &network, &mut nodes, &source_prefix, 6, 7);

    // Poll now, so the add and the relocation happen simultaneously.
    poll_and_resend_with_options(
        &mut nodes,
        PollOptions::default()
            .continue_if(move |nodes| !node_relocated(nodes, 0, &source_prefix, &target_prefix))
            .fire_join_timeout(true),
    )
}

#[test]
fn relocation_request() {
    // Create two sections and make one of them request a node from the other one.
    let network = Network::new(NETWORK_PARAMS);
    let mut rng = network.new_rng();
    let mut nodes = create_connected_nodes_until_split(&network, vec![1, 1]);

    let prefixes: Vec<_> = current_sections(&nodes).collect();
    let request_prefix = *unwrap!(rng.choose(&prefixes));
    let respond_prefix = *choose_other_prefix(&mut rng, &prefixes, &request_prefix);

    // Add a couple of nodes to the responder section to make sure it can fulfil the request.
    change_section_size(
        &network,
        &mut nodes,
        &respond_prefix,
        NETWORK_PARAMS.elder_size + 1,
    );

    // Request a node
    let mut old_request_size = 0;

    // Clippy false positive, already reported: https://github.com/rust-lang/rust-clippy/issues/4732
    #[allow(clippy::explicit_counter_loop)]
    for node in nodes_with_prefix_mut(&mut nodes, &request_prefix) {
        old_request_size += 1;
        unwrap!(node.inner.request_node());
    }

    poll_and_resend_with_options(
        &mut nodes,
        PollOptions::default().continue_if(move |nodes| {
            let new_request_size = nodes_with_prefix(nodes, &request_prefix).count();
            new_request_size <= old_request_size
        }),
    )
}

#[test]
fn refuse_relocation_request() {
    let network = Network::new(NETWORK_PARAMS);
    let mut rng = network.new_rng();
    let mut nodes = create_connected_nodes_until_split(&network, vec![1, 2, 2]);

    let prefixes: Vec<_> = current_sections(&nodes).collect();
    let request_prefix = *unwrap!(rng.choose(&prefixes));
    let refuse_prefix = *choose_other_prefix(&mut rng, &prefixes, &request_prefix);
    let accept_prefix = *unwrap!(iter::repeat(())
        .filter_map(|_| rng.choose(&prefixes))
        .find(|prefix| { **prefix != request_prefix && **prefix != refuse_prefix }));

    let refuse_size = NETWORK_PARAMS.elder_size;
    change_section_size(&network, &mut nodes, &refuse_prefix, refuse_size);

    let accept_size = NETWORK_PARAMS.elder_size + 1;
    change_section_size(&network, &mut nodes, &accept_prefix, accept_size);

    // Force the relocation request to go to the section with insufficient nodes first.
    for node in nodes_with_prefix_mut(&mut nodes, &request_prefix) {
        node.inner
            .set_next_relocation_request_recipient(Some(refuse_prefix.name()));
    }

    // Trigger the relocation request.
    let mut old_request_size = 0;

    // Clippy false positive, already reported: https://github.com/rust-lang/rust-clippy/issues/4732
    #[allow(clippy::explicit_counter_loop)]
    for node in nodes_with_prefix_mut(&mut nodes, &request_prefix) {
        old_request_size += 1;
        unwrap!(node.inner.request_node());
    }

    poll_and_resend_with_options(
        &mut nodes,
        PollOptions::default().continue_if(move |nodes| {
            let new_request_size = nodes_with_prefix(nodes, &request_prefix).count();
            new_request_size <= old_request_size
        }),
    );

    assert_eq!(
        nodes_with_prefix(&nodes, &refuse_prefix).count(),
        refuse_size
    );
    assert_eq!(
        nodes_with_prefix(&nodes, &accept_prefix).count(),
        accept_size - 1
    );
}

// Age counter of the oldest node in the network assuming no nodes were removed or relocated - only
// added.
fn oldest_age_counter_after_only_adds(nodes: &[TestNode]) -> usize {
    // 2^MIN_AGE is the starting value of the age counter.
    // There is at most `safe_section_size - 2` churn events that cause age counter bumps.
    2usize.pow(u32::from(MIN_AGE)) + (nodes.len() - 1).min(NETWORK_PARAMS.safe_section_size - 2)
}

fn find_matching_prefix<'a>(
    prefixes: &'a [Prefix<XorName>],
    name: &XorName,
) -> &'a Prefix<XorName> {
    unwrap!(prefixes.iter().find(|prefix| prefix.matches(name)))
}

fn choose_other_prefix<'a, R: Rng>(
    rng: &mut R,
    prefixes: &'a [Prefix<XorName>],
    except: &Prefix<XorName>,
) -> &'a Prefix<XorName> {
    assert!(prefixes.iter().any(|prefix| prefix != except));
    unwrap!(iter::repeat(())
        .filter_map(|_| rng.choose(prefixes))
        .find(|prefix| *prefix != except))
}

fn add_node_to_prefix(network: &Network, nodes: &mut Vec<TestNode>, prefix: &Prefix<XorName>) {
    let mut rng = network.new_rng();

    let bootstrap_index = unwrap!(iter::repeat(())
        .map(|_| rng.gen_range(0, nodes.len()))
        .find(|index| nodes[*index].inner.is_elder()));

    let config = NetworkConfig::node().with_hard_coded_contact(nodes[bootstrap_index].endpoint());
    let full_id = FullId::within_range(&mut rng, &prefix.range_inclusive());
    nodes.push(
        TestNode::builder(network)
            .network_config(config)
            .full_id(full_id)
            .create(),
    )
}

fn remove_node_from_prefix(nodes: &mut Vec<TestNode>, prefix: &Prefix<XorName>) -> TestNode {
    // Remove the last (youngest) node in the section.
    let index = nodes.len()
        - unwrap!(nodes
            .iter()
            .rev()
            .position(|node| prefix.matches(&node.name())))
        - 1;
    nodes.remove(index)
}

// Make the given section churn the given number of times, while maintaining the section size in
// the given interval.
fn section_churn(
    count: usize,
    network: &Network,
    nodes: &mut Vec<TestNode>,
    prefix: &Prefix<XorName>,
    min_section_size: usize,
    max_section_size: usize,
) {
    assert!(min_section_size < max_section_size);

    let mut rng = network.new_rng();
    let next_relocation_dst = unwrap!(nodes_with_prefix(nodes, prefix).next())
        .inner
        .next_relocation_dst();

    for _ in 0..count {
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
                add_node_to_prefix(network, nodes, prefix);
                unwrap!(nodes.last_mut())
                    .inner
                    .set_next_relocation_dst(next_relocation_dst);
                poll_until_joined(nodes);
            }
            Churn::Remove => {
                let id = remove_node_from_prefix(nodes, prefix).id();
                poll_until_left(nodes, &id);
            }
        }
    }
}

// Add or remove nodes to/from the given section until it has the desired size.
fn change_section_size(
    network: &Network,
    nodes: &mut Vec<TestNode>,
    prefix: &Prefix<XorName>,
    new_size: usize,
) {
    // Disable relocation by making all relocations go to the same section.
    let mut old_size = 0;
    for node in nodes_with_prefix_mut(nodes, prefix) {
        node.inner.set_next_relocation_dst(Some(prefix.name()));
        old_size += 1;
    }

    if new_size > old_size {
        for _ in old_size..new_size {
            add_node_to_prefix(network, nodes, prefix);
            // Also disable relocations for the new node.
            unwrap!(nodes.last_mut())
                .inner
                .set_next_relocation_dst(Some(prefix.name()));
            poll_until_joined(nodes);
        }
    } else if new_size < old_size {
        for _ in new_size..old_size {
            let id = remove_node_from_prefix(nodes, prefix).id();
            poll_until_left(nodes, &id);
        }
    }
}

// Poll until the last node joins.
fn poll_until_joined(nodes: &mut [TestNode]) {
    poll_and_resend_with_options(
        nodes,
        PollOptions::default()
            .continue_if(|nodes| !node_joined(nodes, nodes.len() - 1))
            .fire_join_timeout(false),
    )
}

// Poll until node with the given id leaves.
fn poll_until_left(nodes: &mut [TestNode], id: &PublicId) {
    poll_and_resend_with_options(
        nodes,
        PollOptions::default()
            .continue_if(move |nodes| !node_left(nodes, id))
            .fire_join_timeout(false),
    )
}

// Returns whether all nodes from its section recognize the node at the given index as joined.
fn node_joined(nodes: &[TestNode], node_index: usize) -> bool {
    let id = nodes[node_index].id();

    nodes
        .iter()
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
    nodes.iter().all(|node| !node.inner.is_peer_our_member(id))
}

// Returns whether the relocation of node at `node_index` from `source_prefix` to `target_prefix`
// is complete.
fn node_relocated(
    nodes: &[TestNode],
    node_index: usize,
    source_prefix: &Prefix<XorName>,
    target_prefix: &Prefix<XorName>,
) -> bool {
    let node_name = nodes[node_index].name();
    for node in nodes {
        let prefixes = node.inner.prefixes();

        let in_source = prefixes
            .iter()
            .filter(|prefix| prefix.is_compatible(source_prefix))
            .any(|prefix| {
                // TODO: check all members, not just elders.
                node.inner.section_elders(prefix).contains(&node_name)
            });
        if in_source {
            return false;
        }

        let in_target = prefixes
            .iter()
            .filter(|prefix| prefix.is_compatible(target_prefix))
            .any(|prefix| {
                // TODO: check all members, not just elders.
                node.inner.section_elders(prefix).contains(&node_name)
            });
        if !in_target {
            return false;
        }
    }

    true
}

#[derive(Eq, PartialEq)]
enum Churn {
    Add,
    Remove,
}

impl Rand for Churn {
    fn rand<R: Rng>(rng: &mut R) -> Self {
        if rng.gen() {
            Self::Add
        } else {
            Self::Remove
        }
    }
}
