// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    add_connected_nodes_until_one_away_from_split, create_connected_nodes_until_split,
    current_sections, poll_and_resend_with_options, PollOptions, TestNode, MIN_SECTION_SIZE,
};
use rand::Rng;
use routing::{mock::Network, FullId, NetworkConfig, Prefix, XorName};
use std::{iter, slice};

#[test]
fn relocate_without_split() {
    // Create a network of two sections, then trigger relocation of a random node from one section
    // into the other section.
    let network = Network::new(MIN_SECTION_SIZE, None);
    let mut rng = network.new_rng();
    let mut nodes = create_connected_nodes_until_split(&network, vec![1, 1]);

    let prefixes: Vec<_> = current_sections(&nodes).collect();
    assert!(prefixes.len() > 1);

    let source_prefix = *unwrap!(rng.choose(&prefixes));
    let target_prefix = *choose_other_prefix(&mut rng, &prefixes, &source_prefix);

    let relocate_index = choose_node_from_section(&mut rng, &nodes, &source_prefix);
    let relocate_id = nodes[relocate_index].id();

    let destination = gen_name_in_prefix(&mut rng, &target_prefix);

    // Trigger relocation.
    for node in nodes
        .iter_mut()
        .filter(|node| source_prefix.matches(&node.name()))
    {
        // TODO: When relocation trigger is implemented, change this test to use it instead of this
        // explicit method.
        node.inner.trigger_relocation(relocate_id, destination);
    }

    poll_and_resend_with_options(
        &mut nodes,
        PollOptions::default()
            .continue_if(move |nodes| {
                !relocation_complete(nodes, relocate_index, &source_prefix, &target_prefix)
            })
            .fire_join_timeout(false),
    )
}

#[test]
fn relocate_causing_split() {
    // Create a network with at least two sections. Pick two sections: source and destination. Add
    // enough nodes to the destination section so it is one node shy of split. Then relocate a
    // random node from the source section to the destination section.
    let network = Network::new(MIN_SECTION_SIZE, None);
    let mut rng = network.new_rng();

    let mut nodes = create_connected_nodes_until_split(&network, vec![1, 1]);

    let prefixes: Vec<_> = current_sections(&nodes).collect();
    assert!(prefixes.len() > 1);

    let source_prefix = *unwrap!(rng.choose(&prefixes));
    let target_prefix = *choose_other_prefix(&mut rng, &prefixes, &source_prefix);

    let _ = add_connected_nodes_until_one_away_from_split(
        &network,
        &mut nodes,
        slice::from_ref(&target_prefix),
    );

    let relocate_index = choose_node_from_section(&mut rng, &nodes, &source_prefix);
    let relocate_id = nodes[relocate_index].id();

    let destination = gen_name_in_prefix(&mut rng, &target_prefix);

    // Trigger relocation.
    for node in nodes
        .iter_mut()
        .filter(|node| source_prefix.matches(&node.name()))
    {
        node.inner.trigger_relocation(relocate_id, destination);
    }

    poll_and_resend_with_options(
        &mut nodes,
        PollOptions::default()
            .continue_if(move |nodes| {
                !relocation_complete(nodes, relocate_index, &source_prefix, &target_prefix)
            })
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
    // Create a network with at least two sections. Pick two sections: source and destination. Add
    // enough nodes to the destination section so it is one node shy of split. Then add one more
    // node to it and simultaneously relocate another random node from the source section to it.
    let network = Network::new(MIN_SECTION_SIZE, None);
    let mut rng = network.new_rng();

    let mut nodes = create_connected_nodes_until_split(&network, vec![1, 1]);

    let prefixes: Vec<_> = current_sections(&nodes).collect();
    assert!(prefixes.len() > 1);

    let source_prefix = *unwrap!(rng.choose(&prefixes));
    let target_prefix = *choose_other_prefix(&mut rng, &prefixes, &source_prefix);

    let _ = add_connected_nodes_until_one_away_from_split(
        &network,
        &mut nodes,
        slice::from_ref(&target_prefix),
    );

    let relocate_index = choose_node_from_section(&mut rng, &nodes, &source_prefix);
    let relocate_id = nodes[relocate_index].id();

    let destination = gen_name_in_prefix(&mut rng, &target_prefix);

    // Add new node, but do not poll yet.
    let full_id = FullId::within_range(&target_prefix.range_inclusive());
    // Make sure the bootstrap node is not the relocated node.
    // TODO: remove this restriction. We should be able to bootstrap via the relocated node too,
    // once its relocation completes.
    let bootstrap_index = unwrap!(iter::repeat(())
        .map(|_| rng.gen_range(0, nodes.len()))
        .find(|index| *index != relocate_index));

    let node = TestNode::builder(&network)
        .network_config(
            NetworkConfig::node().with_hard_coded_contact(nodes[bootstrap_index].endpoint()),
        )
        .full_id(full_id)
        .create();
    nodes.push(node);

    // Trigger relocation.
    for node in nodes
        .iter_mut()
        .filter(|node| source_prefix.matches(&node.name()))
    {
        node.inner.trigger_relocation(relocate_id, destination);
    }

    // Poll now, so the add and the relocation happen simultaneously.
    poll_and_resend_with_options(
        &mut nodes,
        PollOptions::default()
            .continue_if(move |nodes| {
                !relocation_complete(nodes, relocate_index, &source_prefix, &target_prefix)
            })
            .fire_join_timeout(true),
    )
}

fn choose_other_prefix<'a, R: Rng>(
    rng: &mut R,
    prefixes: &'a [Prefix<XorName>],
    except: &Prefix<XorName>,
) -> &'a Prefix<XorName> {
    unwrap!(iter::repeat(())
        .filter_map(|_| rng.choose(prefixes))
        .find(|prefix| *prefix != except))
}

fn gen_name_in_prefix<R: Rng>(rng: &mut R, prefix: &Prefix<XorName>) -> XorName {
    unwrap!(rng.gen_iter().find(|name| prefix.matches(name)))
}

fn choose_node_from_section<R: Rng>(
    rng: &mut R,
    nodes: &[TestNode],
    prefix: &Prefix<XorName>,
) -> usize {
    unwrap!(iter::repeat(())
        .map(|_| rng.gen_range(0, nodes.len()))
        .find(|index| prefix.matches(&nodes[*index].name())))
}

// Returns whether the relocation of node at `node_index` from `source_prefix` to `target_prefix`
// is complete.
fn relocation_complete(
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
