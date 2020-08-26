// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::utils::*;
use hex_fmt::HexFmt;
use itertools::Itertools;
use rand::{
    seq::{IteratorRandom, SliceRandom},
    Rng,
};
use routing::{
    event::Event, mock::Environment, quorum_count, rng::MainRng, DstLocation, FullId,
    NetworkParams, Prefix, SrcLocation, TransportConfig,
};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fmt::{self, Display, Formatter},
    usize,
};
use xor_name::XorName;

#[test]
fn aggressive_churn() {
    churn(Params {
        message_schedule: MessageSchedule::AfterChurn,
        churn_max_iterations: 20,
        ..Default::default()
    });
}

#[test]
fn messages_during_churn() {
    churn(Params {
        initial_prefix_lens: vec![2, 2, 2, 3, 3],
        message_schedule: MessageSchedule::DuringChurn,
        grow_target_network_size: 50,
        churn_probability: 0.8,
        churn_max_section_num: 10,
        churn_max_iterations: 50,
        shrink_drop_probability: 0.0,
        ..Default::default()
    });
}

// FIXME: disabled due to parsec removal. Modify to post-parsec era and uncomment.
/*
// FIXME: this test currently fails because of the "cleanup period" at the end of polling which is
// there to give the nodes time to detect lost peers. Because of this period, enough parsec gossip
// messages are exchanged for the parsec pruning to be triggered which interferes with the
// unresponsiveness detection because the unresponsiveness window is currently cleaned on parsec
// prune.
//
// Disabling the test for now because we want to come back to the unresponsiveness detection feature
// to improve it at which point we will likely modify this test anyway, so we might as well fix it
// then.
#[test]
#[ignore]
fn remove_unresponsive_node() {
    let elder_size = 8;
    let recommended_section_size = 8;
    let env = Environment::new(NetworkParams {
        elder_size,
        recommended_section_size,
    });

    let mut nodes = create_connected_nodes(&env, recommended_section_size);
    // Pause a node to act as non-responsive.
    let mut rng = env.new_rng();
    let non_responsive_index = gen_elder_index(&mut rng, &nodes);
    let non_responsive_name = *nodes[non_responsive_index].name();
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
            if *node.name() == non_responsive_name {
                // `event_accumulator` gets reset during parsec pruning, which will reset the
                // tracking of unresponsiveness as well. So this test has to assume there is no
                // parsec pruning being carried out.
                if responded < UNRESPONSIVE_WINDOW - UNRESPONSIVE_THRESHOLD - 1 && rng.gen_bool(0.3)
                {
                    responded += 1;
                } else {
                    return;
                }
            }
            node.inner.vote_for_user_event(event.clone()).unwrap();
        });

        // Required to avoid the case that the non-responsive node doesn't realize its removal,
        // which blocks the polling infinitely.
        if i == UNRESPONSIVE_THRESHOLD - 1 {
            _non_responsive_node = Some(nodes.remove(non_responsive_index));
        }

        let mut consensus_counter = 0;
        poll_until(&env, &mut nodes, |nodes| {
            consensus_reached(nodes, &event, nodes.len(), &mut consensus_counter)
        });
    }

    let still_has_unresponsive_elder = nodes
        .iter()
        .map(|n| &n.inner)
        .filter(|n| {
            n.known_elders()
                .any(|p2p_node| *p2p_node.name() == non_responsive_name)
        })
        .map(|n| n.name())
        .collect_vec();
    assert_eq!(still_has_unresponsive_elder, Vec::<&XorName>::new());
}
*/

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
    // The grow phase lasts until the number of nodes reaches at least this number.
    grow_target_network_size: usize,
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
                recommended_section_size: 5,
            },
            initial_prefix_lens: vec![],
            message_schedule: MessageSchedule::AfterChurn,
            grow_add_probability: 1.0,
            grow_target_network_size: 10,
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
        create_connected_nodes_until_split(&env, &params.initial_prefix_lens)
    };

    // Grow phase - adding nodes
    //
    warn!(
        "Churn [{} nodes, {} sections]: adding {} nodes",
        nodes.len(),
        count_sections(&nodes),
        params.grow_target_network_size.saturating_sub(nodes.len()),
    );
    loop {
        if nodes.len() >= params.grow_target_network_size {
            break;
        }

        let added_indices = add_nodes(&mut rng, &env, &mut nodes, params.grow_add_probability);
        progress_and_verify(
            &mut rng,
            &env,
            &mut nodes,
            params.message_schedule,
            added_indices,
            Default::default(),
        )
    }

    // Churn phase - simultaneously adding and dropping nodes
    //
    let num_sections = count_sections(&nodes);
    warn!(
        "Churn [{} nodes, {} sections]: simultaneous adding and dropping nodes",
        nodes.len(),
        num_sections,
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
                num_sections,
                params.churn_max_section_num,
            )
        } else {
            Default::default()
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
            let dropped_ids =
                drop_random_nodes(&mut rng, &mut nodes, params.shrink_drop_probability);
            if dropped_ids.is_empty() {
                break;
            }

            progress_and_verify(
                &mut rng,
                &env,
                &mut nodes,
                params.message_schedule,
                Default::default(),
                dropped_ids,
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
) -> HashSet<XorName> {
    let mut sections = count_nodes_by_section(nodes);
    let mut dropped_indices = Vec::new();
    let mut dropped_names = HashSet::new();

    for (index, node) in nodes.iter().enumerate() {
        if rng.gen_range(0.0, 1.0) >= drop_probability {
            continue;
        }

        let elder_size = node.inner.elder_size();
        let recommended_section_size = node.inner.recommended_section_size();

        let section = sections.get_mut(node.our_prefix()).unwrap();

        // Drop at most as many nodes as is the minimal number of non-elders in the section.
        // This guarantees we never drop below `elder_size` even in case of split.
        if section.dropped_count >= recommended_section_size - elder_size {
            continue;
        }

        // Don't drop below elder_size nodes.
        if section.initial_count <= elder_size {
            continue;
        }

        section.dropped_count += 1;

        dropped_indices.push(index);
    }

    // Must drop from the end, so the indices are not invalidated.
    dropped_indices.sort();
    for index in dropped_indices.into_iter().rev() {
        assert!(dropped_names.insert(*nodes.remove(index).name()));
    }

    dropped_names
}

#[derive(Default)]
struct SectionCounts {
    initial_count: usize,
    dropped_count: usize,
}

// Count the number of elders and the number of non-elders for each section in the network.
fn count_nodes_by_section(nodes: &[TestNode]) -> HashMap<Prefix, SectionCounts> {
    let mut output: HashMap<_, SectionCounts> = HashMap::new();

    for node in nodes {
        let prefix = *node.our_prefix();
        output.entry(prefix).or_default().initial_count += 1;
    }

    output
}

/// Sub prefix with smaller member counts.
pub fn sub_perfixes_for_balanced_add(nodes: &[TestNode]) -> BTreeSet<Prefix> {
    let mut counts: BTreeMap<Prefix, (usize, usize)> = BTreeMap::new();
    for node in nodes {
        let prefix = *node.our_prefix();
        let name = node.name();

        let (bit_0, bit_1) = counts.entry(prefix).or_default();
        if name.bit(prefix.bit_count() as u8) {
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
) -> HashSet<usize> {
    let mut added_nodes = Vec::new();
    let prefixes: BTreeSet<_> = sub_perfixes_for_balanced_add(nodes);

    for prefix in prefixes {
        if rng.gen_range(0.0, 1.0) >= add_probability {
            continue;
        }

        let bootstrap_index = if nodes.len() > env.elder_size() {
            gen_elder_index(rng, nodes)
        } else {
            0
        };
        let transport_config =
            TransportConfig::node().with_hard_coded_contact(nodes[bootstrap_index].endpoint());
        let node = TestNode::builder(env)
            .transport_config(transport_config)
            .full_id(FullId::within_range(rng, &prefix.range_inclusive()))
            .create();

        trace!("Add node {} to {:?}", node.name(), prefix);
        added_nodes.push(node);
    }

    let mut min_index = 1;
    let mut added_indices = HashSet::new();
    for added_node in added_nodes {
        let index = gen_range(rng, min_index, nodes.len() + 1);
        nodes.insert(index, added_node);
        min_index = index + 1;
        let _ = added_indices.insert(index);
    }

    added_indices
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
) -> (HashSet<usize>, HashSet<XorName>) {
    assert!(min_section_num <= max_section_num);

    let section_num = count_sections(nodes);

    let dropped_names = if section_num > min_section_num {
        drop_random_nodes(rng, nodes, drop_probability)
    } else {
        Default::default()
    };

    let added_indices = if section_num < max_section_num {
        add_nodes(rng, &env, nodes, add_probability)
    } else {
        Default::default()
    };

    (added_indices, dropped_names)
}

fn progress_and_verify(
    rng: &mut MainRng,
    env: &Environment,
    nodes: &mut [TestNode],
    message_schedule: MessageSchedule,
    added_indices: HashSet<usize>,
    dropped_names: HashSet<XorName>,
) {
    let expectations = match message_schedule {
        MessageSchedule::AfterChurn => {
            poll_until_churn_complete(env, nodes, added_indices, dropped_names);
            setup_expectations(rng, nodes, env.elder_size())
        }
        MessageSchedule::DuringChurn => {
            let expectations = setup_expectations(rng, nodes, env.elder_size());
            poll_until_churn_complete(env, nodes, added_indices, dropped_names);
            expectations
        }
    };

    poll_until_expectations_met(env, nodes, expectations);
    verify_invariants_for_nodes(env, nodes);
    shuffle_nodes(rng, nodes);
}

// Poll until all the nodes at `added_indices` join the network and all the nodes from
// `dropped_ids` leave it.
fn poll_until_churn_complete(
    env: &Environment,
    nodes: &mut [TestNode],
    mut added_indices: HashSet<usize>,
    mut dropped_names: HashSet<XorName>,
) {
    trace!(
        "Add {{{}}}, drop {{{}}}",
        added_indices
            .iter()
            .map(|index| nodes[*index].name())
            .format(", "),
        dropped_names.iter().format(", ")
    );

    poll_until(env, nodes, |nodes| {
        added_indices.retain(|&index| !node_joined(nodes, index));
        dropped_names.retain(|name| !node_left(nodes, name));

        added_indices.is_empty() && dropped_names.is_empty()
    })
}

// Poll until all messages from `expectations` are delivered to their intended recipients.
fn poll_until_expectations_met(
    env: &Environment,
    nodes: &mut [TestNode],
    mut expectations: Expectations,
) {
    poll_until(env, nodes, |nodes| expectations.verify(nodes))
}

#[derive(Eq, PartialEq, Hash, Debug)]
struct MessageKey {
    content: Vec<u8>,
    src: SrcLocation,
    dst: DstLocation,
}

impl Display for MessageKey {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "{:10} {:?} -> {:?}",
            HexFmt(&self.content),
            self.src,
            self.dst
        )
    }
}

// A set of message delivery expectations.
struct Expectations {
    // Maps the message to the nodes which are expected to receive it. Each node name is mapped to
    // a flag indicating whether it already received it.
    messages: HashMap<MessageKey, HashMap<XorName, bool>>,
}

impl Expectations {
    fn new() -> Self {
        Self {
            messages: HashMap::new(),
        }
    }

    // Sends a message using the nodes specified by `src`, and adds the expectation. Panics if not
    // enough nodes sent a section message, or if an individual sending node could not be found.
    fn send_and_expect(
        &mut self,
        content: Vec<u8>,
        src: SrcLocation,
        dst: DstLocation,
        nodes: &mut [TestNode],
        elder_size: usize,
    ) {
        let key = MessageKey { content, src, dst };

        let mut sent_count = 0;
        for node in nodes
            .iter_mut()
            .filter(|node| node.inner.is_elder() && node.inner.in_src_location(&key.src))
        {
            trace!("send message {} from {}", key, node.name());

            node.inner
                .send_message(key.src, key.dst, key.content.clone())
                .unwrap();
            sent_count += 1;
        }

        if src.is_section() {
            assert!(
                sent_count >= quorum_count(elder_size),
                "sent_count: {}. elder_size: {}",
                sent_count,
                elder_size,
            );
        } else {
            assert_eq!(sent_count, 1);
        }

        let recipients = nodes
            .iter()
            .filter(|node| is_expected_recipient(node, &dst))
            .map(|node| (*node.name(), false))
            .collect();
        let _ = self.messages.insert(key, recipients);
    }

    // Returns whether all expectations have been met.
    fn verify(&mut self, nodes: &[TestNode]) -> bool {
        for node in nodes {
            if let Some(Event::MessageReceived { content, src, dst }) = node.try_recv_event() {
                self.handle_message_received(node, content, src, dst);
            }
        }

        self.prune_expected_recipients(nodes);

        for (key, recipients) in &self.messages {
            let required = if key.dst.is_section() {
                quorum_count(recipients.len())
            } else {
                recipients.len().min(1)
            };

            let received = recipients.values().filter(|&&r| r).count();

            if received < required {
                trace!(
                    "message {} delivered to only {}/{} of {{{}}}",
                    key,
                    received,
                    required,
                    recipients.keys().format(", ")
                );
                return false;
            }
        }

        true
    }

    fn handle_message_received(
        &mut self,
        node: &TestNode,
        content: Vec<u8>,
        src: SrcLocation,
        dst: DstLocation,
    ) {
        let key = MessageKey { content, src, dst };

        match &dst {
            DstLocation::Node(name) => assert_eq!(
                node.name(),
                name,
                "{}({:b}) unexpected recipient name of message {}",
                node.name(),
                node.our_prefix(),
                key,
            ),
            DstLocation::Section(name) => {
                // Accepting both the current and the parent prefix in case the node went through
                // a split in between the time it received the message and now.
                let matches =
                    node.our_prefix().matches(name) || node.our_prefix().popped().matches(name);
                assert!(
                    matches,
                    "{}({:b}) unexpected recipient prefix of message {}",
                    node.name(),
                    node.our_prefix(),
                    key,
                )
            }
            DstLocation::Direct => panic!("unexpected received direct message {}", key),
        }

        if let Some(recipients) = self.messages.get_mut(&key) {
            if let Some(flag) = recipients.get_mut(node.name()) {
                *flag = true;
            } else {
                trace!("unexpected recipient of {}: {}", key, node.name())
            }
        } else {
            // This is not an error because we can receive messages from previous iterations.
            trace!(
                "unexpected received message {} by {}({:b})",
                key,
                node.name(),
                node.our_prefix()
            )
        }
    }

    // Remove removed or relocated nodes from the map of expected recipients.
    fn prune_expected_recipients(&mut self, nodes: &[TestNode]) {
        for (key, recipients) in &mut self.messages {
            let current: HashSet<_> = nodes
                .iter()
                .filter(|node| is_expected_recipient(node, &key.dst))
                .map(|node| node.name())
                .collect();
            recipients.retain(|name, _| current.contains(name));
        }
    }
}

fn is_expected_recipient(node: &TestNode, dst: &DstLocation) -> bool {
    node.inner.is_elder() && node.inner.in_dst_location(dst)
}

fn setup_expectations(
    rng: &mut MainRng,
    nodes: &mut [TestNode],
    elder_size: usize,
) -> Expectations {
    // Create random content and pick random sending and receiving nodes.
    let content = gen_vec(rng, 100);

    let index0 = gen_elder_index(rng, nodes);
    let index1 = gen_elder_index(rng, nodes);

    let prefix: Prefix = current_sections(nodes).choose(rng).unwrap();
    let section_name = prefix.substituted_in(rng.gen());

    let src_n0 = SrcLocation::Node(*nodes[index0].name());
    let src_s0 = SrcLocation::Section(prefix);

    let dst_n0 = DstLocation::Node(*nodes[index0].name());
    let dst_n1 = DstLocation::Node(*nodes[index1].name());
    let dst_s0 = DstLocation::Section(section_name);
    // this makes sure we have two different sections if there exists more than one
    let dst_s1 = DstLocation::Section(!section_name);

    let mut expectations = Expectations::new();

    // Node to itself
    expectations.send_and_expect(content.clone(), src_n0, dst_n0, nodes, elder_size);
    // Node to another node
    expectations.send_and_expect(content.clone(), src_n0, dst_n1, nodes, elder_size);
    // Node to section
    expectations.send_and_expect(content.clone(), src_n0, dst_s0, nodes, elder_size);
    // Section to itself
    expectations.send_and_expect(content.clone(), src_s0, dst_s0, nodes, elder_size);
    // Section to another section
    expectations.send_and_expect(content.clone(), src_s0, dst_s1, nodes, elder_size);
    // Section to node
    expectations.send_and_expect(content, src_s0, dst_n0, nodes, elder_size);
    expectations
}
