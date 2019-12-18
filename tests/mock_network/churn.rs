// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    count_sections, create_connected_nodes, create_connected_nodes_until_split, current_sections,
    gen_elder_index, gen_range, poll_and_resend, verify_invariant_for_all_nodes, TestNode,
};
use itertools::Itertools;
use rand::Rng;
use routing::{
    mock::Network,
    test_consts::{UNRESPONSIVE_THRESHOLD, UNRESPONSIVE_WINDOW},
    Authority, Event, EventStream, NetworkConfig, NetworkParams, XorName, QUORUM_DENOMINATOR,
    QUORUM_NUMERATOR,
};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

/// Randomly removes some nodes.
///
/// Limits the number of nodes simultaneously dropped from a section such that the section still
/// remains functional (capable of reaching consensus), also accounting for the fact that any
/// dropped node might trigger relocation of other nodes. This limit is currently possibly too
/// conservative and might change in the future, but it still allows removing at least one node per
/// section.
///
/// If `max_per_pfx` is set, never drops more than that number of nodes per section.
///
/// Note: it's necessary to call `poll_all` afterwards, as this function doesn't call it itself.
fn drop_random_nodes<R: Rng>(
    rng: &mut R,
    nodes: &mut Vec<TestNode>,
    max_per_pfx: Option<usize>,
) -> BTreeSet<XorName> {
    #[derive(Default)]
    struct SectionInfo {
        initial_elder_count: usize,
        initial_other_count: usize,
        dropped_elder_count: usize,
        dropped_other_count: usize,
    };

    // 10% probability that a node will be dropped.
    let drop_probability = 0.1;

    let mut sections = HashMap::<_, SectionInfo>::new();
    for node in nodes.iter() {
        let prefix = *node.our_prefix();
        let info = sections.entry(prefix).or_default();
        if node.inner.is_elder() {
            info.initial_elder_count += 1;
        } else {
            info.initial_other_count += 1;
        }
    }

    let mut dropped_indices = Vec::new();
    let mut dropped_names = BTreeSet::new();

    for (index, node) in nodes.iter().enumerate() {
        if rng.gen_range(0.0, 1.0) >= drop_probability {
            continue;
        }

        let section = unwrap!(sections.get_mut(node.our_prefix()));
        let elder_size = unwrap!(node.inner.elder_size());
        let remaining = section.initial_elder_count + section.initial_other_count
            - section.dropped_other_count
            - section.dropped_elder_count;
        let dropped = section.dropped_elder_count + section.dropped_other_count;

        // Check the optional additional drop limit.
        if let Some(max_per_pfx) = max_per_pfx {
            if dropped + 1 > max_per_pfx {
                continue;
            }
        }

        // Don't drop any other node if an elder is already scheduled for drop.
        if section.dropped_elder_count > 0 {
            continue;
        }

        // Don't drop below elder_size nodes.
        if remaining <= elder_size {
            continue;
        }

        // If there already are other drops scheduled, make sure we remain with at least one
        // more node above elder_size. This is because one of those other drops might trigger
        // relocation of one of the existing elders and we wouldn't have anyone to replace it with
        // otherwise.
        if dropped > 0 && remaining <= elder_size + 1 {
            continue;
        }

        if node.inner.is_elder() {
            // Don't drop elder if a non-elder is already scheduled for drop.
            if section.dropped_other_count > 0 {
                continue;
            }

            section.dropped_elder_count += 1;
        } else {
            section.dropped_other_count += 1;
        }

        dropped_indices.push(index);
    }

    // Must drop from the end, so the indices are not invalidated.
    dropped_indices.sort();
    for index in dropped_indices.into_iter().rev() {
        assert!(dropped_names.insert(nodes.remove(index).name()));
    }

    dropped_names
}

/// Adds node per existing prefix using a random proxy. Returns new node indices.
/// skip_some_prefixes: skip adding to prefixes randomly to allowing sections to merge
/// when this is executed in the same iteration as `drop_random_nodes`.
fn add_nodes<R: Rng>(
    rng: &mut R,
    network: &Network,
    nodes: &mut Vec<TestNode>,
    skip_some_prefixes: bool,
) -> BTreeSet<usize> {
    let mut prefixes: BTreeSet<_> = nodes
        .iter()
        .filter_map(|node| node.inner.our_prefix())
        .copied()
        .collect();

    let mut added_nodes = Vec::new();
    while !prefixes.is_empty() {
        let proxy_index = if nodes.len() > unwrap!(nodes[0].inner.elder_size()) {
            gen_elder_index(rng, nodes)
        } else {
            0
        };
        let network_config =
            NetworkConfig::node().with_hard_coded_contact(nodes[proxy_index].endpoint());
        let node = TestNode::builder(network)
            .network_config(network_config)
            .create();
        if let Some(&pfx) = prefixes.iter().find(|pfx| pfx.matches(&node.name())) {
            assert!(prefixes.remove(&pfx));
            if skip_some_prefixes && !rng.gen_weighted_bool(prefixes.len() as u32) {
                continue;
            }
            added_nodes.push(node);
        }
    }

    if !added_nodes.is_empty() {
        warn!(
            "    adding {{{}}}",
            added_nodes.iter().map(|node| node.name()).format(", ")
        );
    }

    let mut min_index = 1;
    let mut added_indices = BTreeSet::new();
    for added_node in added_nodes {
        let index = gen_range(rng, min_index, nodes.len() + 1);
        nodes.insert(index, added_node);
        min_index = index + 1;
        let _ = added_indices.insert(index);
    }

    added_indices
}

/// Checks if the given indices have been accepted to the network.
/// Returns the names of added nodes and indices of failed nodes.
fn check_added_indices(
    nodes: &mut Vec<TestNode>,
    new_indices: BTreeSet<usize>,
) -> (BTreeSet<XorName>, Vec<usize>) {
    let mut added = BTreeSet::new();
    let mut failed = Vec::new();
    for (index, node) in nodes.iter_mut().enumerate() {
        if !new_indices.contains(&index) {
            continue;
        }

        loop {
            match node.inner.try_next_ev() {
                Err(_) => {
                    failed.push(index);
                    break;
                }
                Ok(Event::Connected(_)) => {
                    assert!(added.insert(node.name()));
                    break;
                }
                _ => (),
            }
        }
    }

    (added, failed)
}

// Shuffle nodes excluding the first node
fn shuffle_nodes<R: Rng>(rng: &mut R, nodes: &mut Vec<TestNode>) {
    rng.shuffle(&mut nodes[1..]);
}

/// Adds node per existing prefix. Returns new node names if successfully added.
/// allow_add_failure: Allows nodes to fail getting accepted. It would also
/// skip adding to prefixes randomly to allowing sections to merge when this is executed
/// in the same iteration as `drop_random_nodes`.
///
/// Note: This fn will call `poll_and_resend` itself
fn add_nodes_and_poll<R: Rng>(
    rng: &mut R,
    network: &Network,
    mut nodes: &mut Vec<TestNode>,
    allow_add_failure: bool,
) -> BTreeSet<XorName> {
    let new_indices = add_nodes(rng, &network, nodes, allow_add_failure);
    poll_and_resend(&mut nodes);
    let (added_names, failed_indices) = check_added_indices(nodes, new_indices);

    if !allow_add_failure && !failed_indices.is_empty() {
        panic!("Unable to add new nodes. {} failed.", failed_indices.len());
    }

    // Drop failed_indices and poll remaining nodes to clear pending states.
    for index in failed_indices.into_iter().rev() {
        drop(nodes.remove(index));
    }

    poll_and_resend(&mut nodes);
    shuffle_nodes(rng, nodes);

    added_names
}

// Churns the given network randomly. Returns any newly added indices.
// If introducing churn, would either drop/add nodes in each prefix.
fn random_churn<R: Rng>(
    rng: &mut R,
    network: &Network,
    nodes: &mut Vec<TestNode>,
    max_prefixes_len: usize,
) -> BTreeSet<usize> {
    // 20% chance to not churn.
    if rng.gen_weighted_bool(5) {
        return BTreeSet::new();
    }

    let section_count = count_sections(nodes);
    if section_count < max_prefixes_len {
        return add_nodes(rng, &network, nodes, false);
    }

    // Use elder_size rather than section size to prevent collapsing any groups.
    let max_drop = (unwrap!(nodes[0].inner.elder_size()) - 1)
        * (QUORUM_DENOMINATOR - QUORUM_NUMERATOR)
        / QUORUM_DENOMINATOR;
    assert!(max_drop > 0);
    let dropped_nodes = drop_random_nodes(rng, nodes, Some(max_drop));
    warn!("Dropping nodes: {:?}", dropped_nodes);
    BTreeSet::new()
}

#[derive(Eq, PartialEq, Hash, Debug)]
struct MessageKey {
    content: Vec<u8>,
    src: Authority<XorName>,
    dst: Authority<XorName>,
}

/// A set of expectations: Which nodes, groups and sections are supposed to receive a request.
#[derive(Default)]
struct Expectations {
    /// The Put requests expected to be received.
    messages: HashSet<MessageKey>,
    /// The section or section members of receiving groups or sections, at the time of sending.
    sections: HashMap<Authority<XorName>, HashSet<XorName>>,
}

impl Expectations {
    /// Sends a request using the nodes specified by `src`, and adds the expectation. Panics if not
    /// enough nodes sent a section message, or if an individual sending node could not be found.
    fn send_and_expect(
        &mut self,
        content: &[u8],
        src: Authority<XorName>,
        dst: Authority<XorName>,
        nodes: &mut [TestNode],
        elder_size: usize,
    ) {
        let mut sent_count = 0;
        for node in nodes
            .iter_mut()
            .filter(|node| node.inner.is_elder() && node.is_recipient(&src))
        {
            unwrap!(node.inner.send_message(src, dst, content.to_vec()));
            sent_count += 1;
        }
        if src.is_multiple() {
            assert!(
                sent_count * QUORUM_DENOMINATOR > elder_size * QUORUM_NUMERATOR,
                "sent_count: {}. elder_size: {}",
                sent_count,
                elder_size
            );
        } else {
            assert_eq!(sent_count, 1);
        }
        self.expect(
            nodes,
            dst,
            MessageKey {
                content: content.to_vec(),
                src,
                dst,
            },
        )
    }

    /// Adds the expectation that the nodes belonging to `dst` receive the message.
    fn expect(&mut self, nodes: &mut [TestNode], dst: Authority<XorName>, key: MessageKey) {
        if dst.is_multiple() && !self.sections.contains_key(&dst) {
            let is_recipient = |n: &&TestNode| n.inner.is_elder() && n.is_recipient(&dst);
            let section = nodes
                .iter()
                .filter(is_recipient)
                .map(TestNode::name)
                .collect();
            let _ = self.sections.insert(dst, section);
        }
        let _ = self.messages.insert(key);
    }

    /// Verifies that all sent messages have been received by the appropriate nodes.
    fn verify(mut self, nodes: &mut [TestNode], new_to_old_map: &BTreeMap<XorName, XorName>) {
        // The minimum of the section lengths when sending and now. If a churn event happened, both
        // cases are valid: that the message was received before or after that. The number of
        // recipients thus only needs to reach a quorum for the minimum number of node at one point.
        let section_size_added_removed: HashMap<_, _> = self
            .sections
            .iter_mut()
            .map(|(dst, section)| {
                let is_recipient = |n: &&TestNode| n.inner.is_elder() && n.is_recipient(dst);
                let old_section = section.clone();
                let new_section: HashSet<_> = nodes
                    .iter()
                    .filter(is_recipient)
                    .map(TestNode::name)
                    .collect();
                section.extend(new_section.clone());

                let added: BTreeSet<_> = new_section.difference(&old_section).copied().collect();
                let removed: BTreeSet<_> = old_section.difference(&new_section).copied().collect();
                let count = old_section.len() - removed.len();

                (*dst, (count, added, removed))
            })
            .collect();
        let mut section_msgs_received = HashMap::new(); // The count of received section messages.
        for node in nodes {
            let curr_name = node.name();
            let orig_name = new_to_old_map.get(&curr_name).copied().unwrap_or(curr_name);

            while let Ok(event) = node.try_next_ev() {
                if let Event::MessageReceived { content, src, dst } = event {
                    let key = MessageKey { content, src, dst };

                    if dst.is_multiple() {
                        let checker = |entry: &HashSet<XorName>| entry.contains(&orig_name);
                        if !self.sections.get(&key.dst).map_or(false, checker) {
                            if let Authority::Section(_) = dst {
                                trace!(
                                    "Unexpected request for node {}: {:?} / {:?}",
                                    orig_name,
                                    key,
                                    self.sections
                                );
                            } else {
                                panic!(
                                    "Unexpected request for node {}: {:?} / {:?}",
                                    orig_name, key, self.sections
                                );
                            }
                        } else {
                            *section_msgs_received.entry(key).or_insert(0usize) += 1;
                        }
                    } else {
                        assert_eq!(
                            orig_name,
                            dst.name(),
                            "Receiver does not match destination {}: {:?}, {:?}",
                            node.inner,
                            orig_name,
                            dst.name()
                        );
                        assert!(
                            self.messages.remove(&key),
                            "Unexpected request for node {}: {:?}",
                            node.name(),
                            key
                        );
                    }
                }
            }
        }

        for key in self.messages {
            // All received messages for single nodes were removed: if any are left, they failed.
            assert!(key.dst.is_multiple(), "Failed to receive request {:?}", key);

            let (section_size, added, removed) = &section_size_added_removed[&key.dst];

            let count = section_msgs_received.remove(&key).unwrap_or(0);
            assert!(
                count * QUORUM_DENOMINATOR > section_size * QUORUM_NUMERATOR,
                "Only received {} out of {} (added: {:?}, removed: {:?}) messages {:?}.",
                count,
                section_size,
                added,
                removed,
                key
            );
        }
    }
}

fn send_and_receive<R: Rng>(rng: &mut R, nodes: &mut [TestNode], elder_size: usize) {
    // Create random content and pick random sending and receiving nodes.
    let content: Vec<_> = rng.gen_iter().take(100).collect();
    let index0 = gen_elder_index(rng, nodes);
    let index1 = gen_elder_index(rng, nodes);
    let auth_n0 = Authority::Node(nodes[index0].name());
    let auth_n1 = Authority::Node(nodes[index1].name());
    let auth_g0 = Authority::Section(rng.gen());
    let auth_g1 = Authority::Section(rng.gen());
    let section_name: XorName = rng.gen();
    let auth_s0 = Authority::Section(section_name);
    // this makes sure we have two different sections if there exists more than one
    let auth_s1 = Authority::Section(!section_name);

    let mut expectations = Expectations::default();

    // Test messages from a node to itself, another node, a group and a section...
    expectations.send_and_expect(&content, auth_n0, auth_n0, nodes, elder_size);
    expectations.send_and_expect(&content, auth_n0, auth_n1, nodes, elder_size);
    expectations.send_and_expect(&content, auth_n0, auth_g0, nodes, elder_size);
    expectations.send_and_expect(&content, auth_n0, auth_s0, nodes, elder_size);
    // ... and from a section to itself, another section, a group and a node...
    expectations.send_and_expect(&content, auth_g0, auth_g0, nodes, elder_size);
    expectations.send_and_expect(&content, auth_g0, auth_g1, nodes, elder_size);
    expectations.send_and_expect(&content, auth_g0, auth_s0, nodes, elder_size);
    expectations.send_and_expect(&content, auth_g0, auth_n0, nodes, elder_size);
    // ... and from a section to itself, another section, a group and a node...
    expectations.send_and_expect(&content, auth_s0, auth_s0, nodes, elder_size);
    expectations.send_and_expect(&content, auth_s0, auth_s1, nodes, elder_size);
    expectations.send_and_expect(&content, auth_s0, auth_g0, nodes, elder_size);
    expectations.send_and_expect(&content, auth_s0, auth_n0, nodes, elder_size);

    poll_and_resend(nodes);

    expectations.verify(nodes, &Default::default());
}

#[test]
fn aggressive_churn() {
    let elder_size = 4;
    let safe_section_size = 4;
    let target_section_num = 5;
    let target_network_size = 35;
    let network = Network::new(NetworkParams {
        elder_size,
        safe_section_size,
    });
    let mut rng = network.new_rng();

    // Create an initial network, increase until we have several sections, then
    // decrease back to elder_size, then increase to again.
    let mut nodes = create_connected_nodes(&network, elder_size);

    warn!(
        "Churn [{} nodes, {} sections]: adding nodes",
        nodes.len(),
        count_sections(&nodes)
    );

    // Add nodes to trigger splits.
    while count_sections(&nodes) < target_section_num || nodes.len() < target_network_size {
        let added = add_nodes_and_poll(&mut rng, &network, &mut nodes, false);
        if !added.is_empty() {
            warn!("Added {:?}. Total: {}", added, nodes.len());
        } else {
            warn!("Unable to add new node.");
        }

        verify_invariant_for_all_nodes(&network, &mut nodes);
        send_and_receive(&mut rng, &mut nodes, elder_size);
    }

    // Simultaneous Add/Drop nodes in the same iteration.
    warn!(
        "Churn [{} nodes, {} sections]: simultaneous adding and dropping nodes",
        nodes.len(),
        count_sections(&nodes)
    );
    let mut count = 0;
    while nodes.len() > target_network_size / 2 && count < 15 {
        count += 1;

        // Only max drop a node per pfx as the node added in this iteration could split a pfx
        // making the 1/3rd calculation in drop_random_nodes incorrect for the split pfx when we poll.
        let max_drop = 1;
        let dropped = drop_random_nodes(&mut rng, &mut nodes, Some(max_drop));
        let added = add_nodes_and_poll(&mut rng, &network, &mut nodes, true);
        warn!("Simultaneously added {:?} and dropped {:?}", added, dropped);

        verify_invariant_for_all_nodes(&network, &mut nodes);

        send_and_receive(&mut rng, &mut nodes, elder_size);
        warn!(
            "Remaining Prefixes: {{{:?}}}",
            current_sections(&nodes).format(", ")
        );
    }

    // Drop nodes to trigger merges.
    warn!(
        "Churn [{} nodes, {} sections]: dropping nodes",
        nodes.len(),
        count_sections(&nodes)
    );
    loop {
        let dropped_nodes = drop_random_nodes(&mut rng, &mut nodes, None);
        if dropped_nodes.is_empty() {
            break;
        }

        warn!("Dropping random nodes. Dropped: {:?}", dropped_nodes);
        poll_and_resend(&mut nodes);
        verify_invariant_for_all_nodes(&network, &mut nodes);
        send_and_receive(&mut rng, &mut nodes, elder_size);
        shuffle_nodes(&mut rng, &mut nodes);
        warn!(
            "Remaining Prefixes: {{{:?}}}",
            current_sections(&nodes).format(", ")
        );
    }

    warn!(
        "Churn [{} nodes, {} sections]: done",
        nodes.len(),
        count_sections(&nodes)
    );
}

#[test]
fn messages_during_churn() {
    let elder_size = 4;
    let safe_section_size = 4;
    let network = Network::new(NetworkParams {
        elder_size,
        safe_section_size,
    });
    let mut rng = network.new_rng();
    let prefixes = vec![2, 2, 2, 3, 3];
    let max_prefixes_len = prefixes.len() * 2;
    let mut nodes = create_connected_nodes_until_split(&network, prefixes);

    for i in 0..50 {
        warn!(
            "Iteration {}. Prefixes: {{{:?}}}",
            i,
            current_sections(&nodes).format(", ")
        );
        let new_indices = random_churn(&mut rng, &network, &mut nodes, max_prefixes_len);

        // Create random data and pick random sending and receiving nodes.
        let content: Vec<_> = rng.gen_iter().take(100).collect();
        let index0 = gen_elder_index(&mut rng, &nodes);
        let index1 = gen_elder_index(&mut rng, &nodes);
        let auth_n0 = Authority::Node(nodes[index0].name());
        let auth_n1 = Authority::Node(nodes[index1].name());
        let auth_g0 = Authority::Section(rng.gen());
        let auth_g1 = Authority::Section(rng.gen());
        let section_name: XorName = rng.gen();
        let auth_s0 = Authority::Section(section_name);
        // this makes sure we have two different sections if there exists more than one
        let auth_s1 = Authority::Section(!section_name);

        let mut expectations = Expectations::default();
        let initial_names = nodes.iter().map(|node| node.name()).collect_vec();

        // Test messages from a node to itself, another node, a group and a section...
        expectations.send_and_expect(&content, auth_n0, auth_n0, &mut nodes, elder_size);
        expectations.send_and_expect(&content, auth_n0, auth_n1, &mut nodes, elder_size);
        expectations.send_and_expect(&content, auth_n0, auth_g0, &mut nodes, elder_size);
        expectations.send_and_expect(&content, auth_n0, auth_s0, &mut nodes, elder_size);
        // ... and from a group to itself, another group, a section and a node...
        expectations.send_and_expect(&content, auth_g0, auth_g0, &mut nodes, elder_size);
        expectations.send_and_expect(&content, auth_g0, auth_g1, &mut nodes, elder_size);
        expectations.send_and_expect(&content, auth_g0, auth_s0, &mut nodes, elder_size);
        expectations.send_and_expect(&content, auth_g0, auth_n0, &mut nodes, elder_size);
        // ... and from a section to itself, another section, a group and a node...
        expectations.send_and_expect(&content, auth_s0, auth_s0, &mut nodes, elder_size);
        expectations.send_and_expect(&content, auth_s0, auth_s1, &mut nodes, elder_size);
        expectations.send_and_expect(&content, auth_s0, auth_g0, &mut nodes, elder_size);
        expectations.send_and_expect(&content, auth_s0, auth_n0, &mut nodes, elder_size);

        poll_and_resend(&mut nodes);
        let new_to_old_map: BTreeMap<XorName, XorName> = nodes
            .iter()
            .zip(initial_names.iter())
            .map(|(node, old_name)| (node.name(), *old_name))
            .filter(|(new_name, old_name)| old_name != new_name)
            .collect();

        let (added_names, failed_indices) = check_added_indices(&mut nodes, new_indices);
        assert!(
            failed_indices.is_empty(),
            "Non-empty set of failed nodes! Failed nodes: {:?}",
            failed_indices
                .into_iter()
                .map(|idx| nodes[idx].name())
                .collect::<Vec<_>>()
        );
        shuffle_nodes(&mut rng, &mut nodes);

        if !added_names.is_empty() {
            warn!("Added nodes: {:?}", added_names);
        }
        expectations.verify(&mut nodes, &new_to_old_map);
        verify_invariant_for_all_nodes(&network, &mut nodes);
    }
}

#[test]
fn remove_unresponsive_node() {
    let elder_size = 8;
    let safe_section_size = 8;
    let network = Network::new(NetworkParams {
        elder_size,
        safe_section_size,
    });

    let mut nodes = create_connected_nodes(&network, safe_section_size);
    poll_and_resend(&mut nodes);
    // Pause a node to act as non-responsive.
    let mut rng = network.new_rng();
    let non_responsive_index = gen_elder_index(&mut rng, &nodes);
    let non_responsive_name = nodes[non_responsive_index].name();
    info!(
        "{:?} chosen as non-responsive.",
        nodes[non_responsive_index].name()
    );
    let mut _non_responsive_node = None;

    // Sending some user events to create a sequence of observations.
    let mut responded = 0;
    for i in 0..UNRESPONSIVE_WINDOW {
        let event: Vec<_> = rng.gen_iter().take(100).collect();
        nodes.iter_mut().for_each(|node| {
            if node.name() == non_responsive_name {
                // `chain_accumulator` gets reset during parsec pruning, which will reset the
                // tracking of unresponsiveness as well. So this test has to assume there is no
                // parsec pruning being carried out.
                if responded < UNRESPONSIVE_WINDOW - UNRESPONSIVE_THRESHOLD - 1
                    && rng.gen_weighted_bool(3)
                {
                    responded += 1;
                } else {
                    return;
                }
            }
            let _ = node
                .inner
                .elder_state_mut()
                .map(|state| state.vote_for_user_event(event.clone()));
        });

        // Required to avoid the case that the non-responsive node doesn't realize its removal,
        // which blocks the polling infinitely.
        if i == UNRESPONSIVE_THRESHOLD - 1 {
            _non_responsive_node = Some(nodes.remove(non_responsive_index));
        }

        poll_and_resend(&mut nodes);
    }

    // Verify the other nodes saw the paused node and removed it.
    for node in nodes.iter_mut().filter(|n| n.inner.is_elder()) {
        expect_any_event!(node, Event::NodeLost(_));
    }
}
