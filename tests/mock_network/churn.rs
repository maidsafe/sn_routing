// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    count_sections, create_connected_nodes, create_connected_nodes_until_split, current_sections,
    gen_elder_index, gen_range, gen_vec, poll_and_resend, verify_invariant_for_all_nodes, TestNode,
};
use itertools::Itertools;
use rand::{seq::SliceRandom, Rng};
use routing::{
    mock::Environment,
    quorum_count,
    rng::MainRng,
    test_consts::{UNRESPONSIVE_THRESHOLD, UNRESPONSIVE_WINDOW},
    Authority, Event, EventStream, FullId, NetworkConfig, NetworkParams, Prefix, XorName, Xorable,
};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    usize,
};

#[test]
fn aggressive_churn() {
    churn(Params {
        message_schedule: MessageSchedule::AfterChurn,
        grow_target_section_num: 5,
        churn_max_iterations: 20,
        ..Default::default()
    });
}

#[test]
fn messages_during_churn() {
    churn(Params {
        initial_prefix_lens: vec![2, 2, 2, 3, 3],
        message_schedule: MessageSchedule::DuringChurn,
        grow_target_section_num: 5,
        churn_probability: 0.8,
        churn_max_section_num: 10,
        churn_max_iterations: 50,
        shrink_drop_probability: 0.0,
        ..Default::default()
    });
}

#[test]
fn remove_unresponsive_node() {
    let elder_size = 8;
    let safe_section_size = 8;
    let env = Environment::new(NetworkParams {
        elder_size,
        safe_section_size,
    });

    let mut nodes = create_connected_nodes(&env, safe_section_size);
    poll_and_resend(&mut nodes);
    // Pause a node to act as non-responsive.
    let mut rng = env.new_rng();
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
        let event = gen_vec(&mut rng, 100);
        nodes.iter_mut().for_each(|node| {
            if node.name() == non_responsive_name {
                // `chain_accumulator` gets reset during parsec pruning, which will reset the
                // tracking of unresponsiveness as well. So this test has to assume there is no
                // parsec pruning being carried out.
                if responded < UNRESPONSIVE_WINDOW - UNRESPONSIVE_THRESHOLD - 1 && rng.gen_bool(0.3)
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

    let still_has_unresponsibe_elder = nodes
        .iter()
        .map(|n| &n.inner)
        .filter(|n| n.elders().any(|id| *id.name() == non_responsive_name))
        .map(|n| format!("{}", n))
        .collect_vec();
    assert_eq!(still_has_unresponsibe_elder, Vec::<String>::new());
}

// Parameters for the churn tests.
//
// The test run in three phases:
// 1. In the grow phase nodes are only added.
// 2. In the churn phase nodes are added and removed
// 3. In the shrink phase nodes are only dropped
//
// Note: probabilities are expressed as a number in the 0..1 interval, e.g. 80% == 0.8.
struct Params {
    // Network params
    network: NetworkParams,
    // The network starts with sections whose prefixes have these lengths. If empty, the network
    // starts with just the root section with `elder_size` nodes.
    initial_prefix_lens: Vec<usize>,
    // When are messages sent during each iteration.
    message_schedule: MessageSchedule,
    // Probability that a node is added to a section during a single iteration of the grow phase.
    // Evaluated per each section.
    grow_add_probability: f64,
    // The grow phase lasts until the number of sections reaches this number.
    grow_target_section_num: usize,
    // Maximum number of iterations for the churn phase.
    churn_max_iterations: usize,
    // Probability that any churn occurs for each iteration of the churn phase. Evaluated once per
    // iteration.
    churn_probability: f64,
    // Probability that a node is added to a section during a single iteration of the churn phases.
    // Evaluated per each section.
    churn_add_probability: f64,
    // Probability that a node is dropped during a single iteration of the churn phase.
    // Evaluated per each node.
    churn_drop_probability: f64,
    // During the churn phase, if the number of sections is more than this number, no more nodes
    // are added, only dropped.
    churn_max_section_num: usize,
    // Probability that a node is dropped during a single iteration of the shrink phase.
    // Evaluated per each node. If zero, the shrink phase is skipped.
    shrink_drop_probability: f64,
}

impl Default for Params {
    fn default() -> Self {
        Self {
            network: NetworkParams {
                elder_size: 4,
                safe_section_size: 4,
            },
            initial_prefix_lens: vec![],
            message_schedule: MessageSchedule::AfterChurn,
            grow_add_probability: 1.0,
            grow_target_section_num: 5,
            churn_max_iterations: 20,
            churn_probability: 1.0,
            churn_add_probability: 0.2,
            churn_drop_probability: 0.1,
            churn_max_section_num: usize::MAX,
            shrink_drop_probability: 0.1,
        }
    }
}

// When do we send messages.
#[derive(Copy, Clone, PartialEq, Eq)]
enum MessageSchedule {
    AfterChurn,
    DuringChurn,
}

fn churn(params: Params) {
    let env = Environment::new(params.network);
    let mut rng = env.new_rng();
    let mut nodes = if params.initial_prefix_lens.is_empty() {
        create_connected_nodes(&env, env.elder_size())
    } else {
        create_connected_nodes_until_split(&env, params.initial_prefix_lens)
    };

    // Grow phase - adding nodes
    //
    warn!(
        "Churn [{} nodes, {} sections]: adding nodes",
        nodes.len(),
        count_sections(&nodes)
    );
    loop {
        if count_sections(&nodes) >= params.grow_target_section_num {
            break;
        }

        let added_indices = add_nodes(&mut rng, &env, &mut nodes, params.grow_add_probability);
        progress_and_verify(
            &mut rng,
            &env,
            &mut nodes,
            params.message_schedule,
            added_indices,
            BTreeSet::new(),
        )
    }

    // Churn phase - simultaneously adding and dropping nodes
    //
    warn!(
        "Churn [{} nodes, {} sections]: simultaneous adding and dropping nodes",
        nodes.len(),
        count_sections(&nodes)
    );
    for i in 0..params.churn_max_iterations {
        warn!("Iteration {}/{}", i, params.churn_max_iterations);

        let (added_indices, dropped_names) = if rng.gen_range(0.0, 1.0) < params.churn_probability {
            random_churn(
                &mut rng,
                &env,
                &mut nodes,
                params.churn_add_probability,
                params.churn_drop_probability,
                params.grow_target_section_num,
                params.churn_max_section_num,
            )
        } else {
            (BTreeSet::new(), BTreeSet::new())
        };

        progress_and_verify(
            &mut rng,
            &env,
            &mut nodes,
            params.message_schedule,
            added_indices,
            dropped_names,
        );

        warn!(
            "Remaining Prefixes: {{{:?}}}",
            current_sections(&nodes).format(", ")
        );
    }

    // Shrink phase - dropping nodes
    //
    if params.shrink_drop_probability > 0.0 {
        warn!(
            "Churn [{} nodes, {} sections]: dropping nodes",
            nodes.len(),
            count_sections(&nodes)
        );
        loop {
            let dropped_names =
                drop_random_nodes(&mut rng, &mut nodes, params.shrink_drop_probability);
            if dropped_names.is_empty() {
                break;
            }

            progress_and_verify(
                &mut rng,
                &env,
                &mut nodes,
                params.message_schedule,
                BTreeSet::new(),
                dropped_names,
            );

            warn!(
                "Remaining Prefixes: {{{:?}}}",
                current_sections(&nodes).format(", ")
            );
        }
    }

    warn!(
        "Churn [{} nodes, {} sections]: done",
        nodes.len(),
        count_sections(&nodes)
    );
}

/// Randomly removes some nodes.
///
/// Limits the number of nodes simultaneously dropped from a section such that the section still
/// remains functional (capable of reaching consensus), also accounting for the fact that any
/// dropped node might trigger relocation of other nodes. This limit is currently possibly too
/// conservative and might change in the future, but it still allows removing at least one node per
/// section.
///
/// Note: it's necessary to call `poll_all` afterwards, as this function doesn't call it itself.
fn drop_random_nodes<R: Rng>(
    rng: &mut R,
    nodes: &mut Vec<TestNode>,
    drop_probability: f64,
) -> BTreeSet<XorName> {
    let mut sections = count_nodes_by_section(nodes);
    let mut dropped_indices = Vec::new();
    let mut dropped_names = BTreeSet::new();

    for (index, node) in nodes.iter().enumerate() {
        if rng.gen_range(0.0, 1.0) >= drop_probability {
            continue;
        }

        let elder_size = unwrap!(node.inner.elder_size());
        let section = unwrap!(sections.get_mut(node.our_prefix()));

        // Don't drop any other node if an elder is already scheduled for drop.
        if section.dropped_elder_count > 0 {
            continue;
        }

        // Don't drop below elder_size nodes.
        if section.all_remaining() <= elder_size {
            continue;
        }

        // If there already are other drops scheduled, make sure we remain with at least one
        // more node above elder_size. This is because one of those other drops might trigger
        // relocation of one of the existing elders and we wouldn't have anyone to replace it with
        // otherwise.
        if section.all_dropped() > 0 && section.all_remaining() <= elder_size + 1 {
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

#[derive(Default)]
struct SectionCounts {
    initial_elder_count: usize,
    initial_other_count: usize,
    dropped_elder_count: usize,
    dropped_other_count: usize,
}

impl SectionCounts {
    fn all_remaining(&self) -> usize {
        self.initial_elder_count + self.initial_other_count
            - self.dropped_other_count
            - self.dropped_elder_count
    }

    fn all_dropped(&self) -> usize {
        self.dropped_elder_count + self.dropped_other_count
    }
}

// Count the number of elders and the number of non-elders for each section in the network.
fn count_nodes_by_section(nodes: &[TestNode]) -> HashMap<Prefix<XorName>, SectionCounts> {
    let mut output: HashMap<_, SectionCounts> = HashMap::new();

    for node in nodes {
        let prefix = *node.our_prefix();
        let counts = output.entry(prefix).or_default();
        if node.inner.is_elder() {
            counts.initial_elder_count += 1;
        } else {
            counts.initial_other_count += 1;
        }
    }

    output
}

/// Sub prefix with smaller member counts.
pub fn sub_perfixes_for_balanced_add(nodes: &[TestNode]) -> BTreeSet<Prefix<XorName>> {
    let mut counts: BTreeMap<Prefix<XorName>, (usize, usize)> = BTreeMap::new();
    for node in nodes {
        let pfx = *node.our_prefix();
        let name = node.name();

        let (bit_0, bit_1) = counts.entry(pfx).or_default();
        if name.bit(pfx.bit_count()) {
            *bit_1 += 1;
        } else {
            *bit_0 += 1;
        }
    }

    counts
        .into_iter()
        .map(|(prefix, (bit_0, bit_1))| {
            let next_bit_with_fewer_members = bit_0 > bit_1;
            prefix.pushed(next_bit_with_fewer_members)
        })
        .collect()
}

/// Adds node per existing prefix with the given probability. Returns new node indices.
fn add_nodes(
    rng: &mut MainRng,
    env: &Environment,
    nodes: &mut Vec<TestNode>,
    add_probability: f64,
) -> BTreeSet<usize> {
    let mut added_nodes = Vec::new();
    let prefixes: BTreeSet<_> = sub_perfixes_for_balanced_add(nodes);

    for prefix in prefixes {
        if rng.gen_range(0.0, 1.0) >= add_probability {
            continue;
        }

        let bootstrap_index = if nodes.len() > unwrap!(nodes[0].inner.elder_size()) {
            gen_elder_index(rng, nodes)
        } else {
            0
        };
        let network_config =
            NetworkConfig::node().with_hard_coded_contact(nodes[bootstrap_index].endpoint());
        let node = TestNode::builder(env)
            .network_config(network_config)
            .full_id(FullId::within_range(rng, &prefix.range_inclusive()))
            .create();
        added_nodes.push(node);
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
/// Returns the names of added nodes.
fn check_added_indices(nodes: &mut [TestNode], new_indices: BTreeSet<usize>) -> BTreeSet<XorName> {
    let mut added = BTreeSet::new();
    let mut failed = Vec::new();

    for index in new_indices {
        let node = &mut nodes[index];

        loop {
            match node.inner.try_next_ev() {
                Err(_) => {
                    failed.push(node.name());
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

    assert!(failed.is_empty(), "Unable to add new nodes: {:?}", failed);

    added
}

// Shuffle nodes excluding the first node
fn shuffle_nodes<R: Rng>(rng: &mut R, nodes: &mut [TestNode]) {
    nodes[1..].shuffle(rng);
}

// Churns the given network randomly. Returns any newly added indices and the
// dropped node names.
fn random_churn(
    rng: &mut MainRng,
    env: &Environment,
    nodes: &mut Vec<TestNode>,
    add_probability: f64,
    drop_probability: f64,
    min_section_num: usize,
    max_section_num: usize,
) -> (BTreeSet<usize>, BTreeSet<XorName>) {
    assert!(min_section_num <= max_section_num);

    let section_num = count_sections(nodes);

    let dropped_names = if section_num > min_section_num {
        drop_random_nodes(rng, nodes, drop_probability)
    } else {
        BTreeSet::new()
    };

    let added_indices = if section_num < max_section_num {
        add_nodes(rng, &env, nodes, add_probability)
    } else {
        BTreeSet::new()
    };

    (added_indices, dropped_names)
}

fn progress_and_verify<R: Rng>(
    rng: &mut R,
    env: &Environment,
    nodes: &mut [TestNode],
    message_schedule: MessageSchedule,
    added_indices: BTreeSet<usize>,
    dropped_names: BTreeSet<XorName>,
) {
    let expectations = match message_schedule {
        MessageSchedule::AfterChurn => {
            poll_after_churn(nodes, added_indices, dropped_names);
            let expectations = setup_expectations(rng, nodes, env.elder_size());
            poll_and_resend(nodes);
            expectations
        }
        MessageSchedule::DuringChurn => {
            let expectations = setup_expectations(rng, nodes, env.elder_size());
            poll_after_churn(nodes, added_indices, dropped_names);
            expectations
        }
    };

    expectations.verify(nodes);
    verify_invariant_for_all_nodes(env, nodes);
    shuffle_nodes(rng, nodes);
}

fn poll_after_churn(
    nodes: &mut [TestNode],
    added_indices: BTreeSet<usize>,
    dropped_names: BTreeSet<XorName>,
) {
    trace!(
        "Adding {{{:?}}}, dropping {:?}",
        added_indices
            .iter()
            .map(|index| nodes[*index].name())
            .format(", "),
        dropped_names
    );

    poll_and_resend(nodes);
    let added_names = check_added_indices(nodes, added_indices);

    warn!("Added {:?}, dropped {:?}", added_names, dropped_names);
}

#[derive(Eq, PartialEq, Hash, Debug)]
struct MessageKey {
    content: Vec<u8>,
    src: Authority<XorName>,
    dst: Authority<XorName>,
}

/// A set of expectations: Which nodes, groups and sections are supposed to receive a message.
struct Expectations {
    /// The message expected to be received.
    messages: HashSet<MessageKey>,
    /// The section or section members of receiving groups or sections, at the time of sending.
    sections: HashMap<Authority<XorName>, HashSet<XorName>>,
    /// Helper to build the map of new names to old names by which we can track even relocated
    /// nodes.
    relocation_map_builder: RelocationMapBuilder,
}

impl Expectations {
    fn new(nodes: &[TestNode]) -> Self {
        Self {
            messages: HashSet::new(),
            sections: HashMap::new(),
            relocation_map_builder: RelocationMapBuilder::new(nodes),
        }
    }

    /// Sends a message using the nodes specified by `src`, and adds the expectation. Panics if not
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
                sent_count >= quorum_count(elder_size),
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
    fn verify(mut self, nodes: &mut [TestNode]) {
        let new_to_old_map = self.relocation_map_builder.build(nodes);

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
        for node in nodes.iter_mut() {
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
                                    "Unexpected message for node {}: {:?} / {:?}",
                                    orig_name,
                                    key,
                                    self.sections
                                );
                            } else {
                                panic!(
                                    "Unexpected message for node {}: {:?} / {:?}",
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
                            "Unexpected message for node {}: {:?}",
                            node.name(),
                            key
                        );
                    }
                }
            }
        }

        for key in self.messages {
            if let Authority::Node(dst_name) = key.dst {
                // Verify that if the message destination is a single node, then that node either
                // received it, or if not it's only because it got dropped, relocated or demoted.
                if let Some(node) = nodes.iter().find(|node| node.name() == dst_name) {
                    assert!(
                        !node.inner.is_elder(),
                        "{} failed to receive message {:?}",
                        node.inner,
                        key
                    );
                }

                continue;
            }

            let (section_size, added, removed) = &section_size_added_removed[&key.dst];

            let count = section_msgs_received.remove(&key).unwrap_or(0);
            assert!(
                count >= quorum_count(*section_size),
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

fn setup_expectations<R: Rng>(
    rng: &mut R,
    nodes: &mut [TestNode],
    elder_size: usize,
) -> Expectations {
    // Create random content and pick random sending and receiving nodes.
    let content = gen_vec(rng, 100);
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

    let mut expectations = Expectations::new(nodes);

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

    expectations
}

// Helper to build a map of new names to old names.
struct RelocationMapBuilder {
    initial_names: Vec<XorName>,
}

impl RelocationMapBuilder {
    fn new(nodes: &[TestNode]) -> Self {
        let initial_names = nodes.iter().map(|node| node.name()).collect();
        Self { initial_names }
    }

    fn build(self, nodes: &[TestNode]) -> BTreeMap<XorName, XorName> {
        nodes
            .iter()
            .zip(self.initial_names)
            .map(|(node, old_name)| (node.name(), old_name))
            .filter(|(new_name, old_name)| old_name != new_name)
            .collect()
    }
}
