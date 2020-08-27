// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crossbeam_channel as mpmc;
use itertools::Itertools;
use rand::{
    distributions::{Distribution, Standard},
    seq::IteratorRandom,
    Rng,
};
use routing::{
    event::{Connected, Event},
    mock::Environment,
    quorum_count,
    rng::MainRng,
    test_consts, DstLocation, FullId, Node, NodeConfig, PausedState, Prefix, PublicId, SrcLocation,
    TransportConfig, MIN_AGE,
};
use sn_fake_clock::FakeClock;
use std::{
    cmp::Ordering,
    collections::{BTreeSet, HashMap},
    convert::TryInto,
    iter,
    net::SocketAddr,
    time::Duration,
};
use xor_name::XorName;

// The smallest number of elders which allows to reach consensus when one of them goes offline.
pub const MIN_ELDER_SIZE: usize = 4;

// Maximum number of iterations of the `poll_until` function. This is several orders higher than
// the anticipated upper limit for any test, and if hit is likely to indicate an infinite loop.
const POLL_UNTIL_MAX_ITERATIONS: usize = 2000;

// Duration to advance the time after each iteration of poll_until.
const POLL_UNTIL_TIME_STEP: Duration =
    Duration::from_millis(test_consts::RESEND_DELAY.as_millis() as u64 + 1);

// Maximum number of iterations of the `poll_all` function. Hitting this limit does not necessarily
// indicate an error. It just prevents infinite loops in case the time needs to be advanced to make
// progress.
const POLL_ALL_MAX_ITERATIONS: usize = 100;

// Maximum number of nodes that can join the network simultaneously. Trying to add more nodes might
// cause some of them to timeout.
const MAX_SIMULTANEOUS_JOINS: usize = 16;

// -----  Random number generation  -----

pub fn gen_range<T: Rng>(rng: &mut T, low: usize, high: usize) -> usize {
    rng.gen_range(low as u32, high as u32) as usize
}

pub fn gen_elder_index<R: Rng>(rng: &mut R, nodes: &[TestNode]) -> usize {
    loop {
        let index = gen_range(rng, 0, nodes.len());
        if nodes[index].inner.is_elder() {
            break index;
        }
    }
}

// -----  TestNode and builder  -----

pub struct TestNode {
    pub inner: Node,
    user_event_rx: mpmc::Receiver<Event>,
}

impl TestNode {
    pub fn builder(env: &Environment) -> TestNodeBuilder {
        TestNodeBuilder {
            config: NodeConfig::default(),
            env,
        }
    }

    pub fn resume(state: PausedState) -> Self {
        let (inner, user_event_rx) = Node::resume(state);
        Self {
            inner,
            user_event_rx,
        }
    }

    pub fn endpoint(&mut self) -> SocketAddr {
        self.inner.our_connection_info().unwrap()
    }

    pub fn id(&self) -> &PublicId {
        self.inner.id()
    }

    pub fn name(&self) -> &XorName {
        self.inner.name()
    }

    pub fn close_names(&self) -> Vec<XorName> {
        self.inner.close_names(&self.name()).unwrap()
    }

    pub fn our_prefix(&self) -> &Prefix {
        self.inner.our_prefix().unwrap()
    }

    pub fn poll(&mut self) -> bool {
        let mut result = false;

        loop {
            let mut sel = mpmc::Select::new();
            self.inner.register(&mut sel);

            if let Ok(op_index) = sel.try_ready() {
                if self.inner.handle_selected_operation(op_index).is_ok() {
                    result = true;
                }
            } else {
                break;
            }
        }

        result
    }

    pub fn try_recv_event(&self) -> Option<Event> {
        self.user_event_rx.try_recv().ok()
    }
}

pub fn count_sections(nodes: &[TestNode]) -> usize {
    current_sections(nodes).count()
}

pub fn current_sections<'a>(nodes: &'a [TestNode]) -> impl Iterator<Item = Prefix> + 'a {
    nodes
        .iter()
        .filter_map(|n| n.inner.our_prefix())
        .copied()
        .unique()
}

pub struct TestNodeBuilder<'a> {
    config: NodeConfig,
    env: &'a Environment,
}

impl<'a> TestNodeBuilder<'a> {
    pub fn first(mut self) -> Self {
        self.config.first = true;
        self
    }

    pub fn transport_config(mut self, config: TransportConfig) -> Self {
        self.config.transport_config = config;
        self
    }

    pub fn full_id(mut self, full_id: FullId) -> Self {
        self.config.full_id = Some(full_id);
        self
    }

    pub fn create(mut self) -> TestNode {
        self.config.network_params = self.env.network_params();
        self.config.rng = self.env.new_rng();

        let (inner, user_event_rx, _client_rx) = Node::new(self.config);

        TestNode {
            inner,
            user_event_rx,
        }
    }
}

// -----  poll_all, create_connected_...  -----

/// Polls the network until there are no more events to process.
pub fn poll_all(env: &Environment, nodes: &mut [TestNode]) {
    for _ in 0..POLL_ALL_MAX_ITERATIONS {
        env.poll();

        let mut handled = false;

        for node in nodes.iter_mut() {
            handled = node.poll() || handled;
        }

        if !handled {
            return;
        }
    }
}

/// Polls the network until the given predicate returns `true`.
pub fn poll_until<F>(env: &Environment, nodes: &mut [TestNode], mut predicate: F)
where
    F: FnMut(&[TestNode]) -> bool,
{
    for _ in 0..POLL_UNTIL_MAX_ITERATIONS {
        if predicate(nodes) {
            return;
        }

        poll_all(env, nodes);
        advance_time(POLL_UNTIL_TIME_STEP);
    }

    panic!(
        "poll_until has been called {} times.",
        POLL_UNTIL_MAX_ITERATIONS
    );
}

fn advance_time(duration: Duration) {
    FakeClock::advance_time(duration.as_millis().try_into().expect("time step too long"));
}

// Returns whether all nodes from its section recognize the node at the given index as joined.
pub fn node_joined(nodes: &[TestNode], index: usize) -> bool {
    if !nodes[index].inner.is_approved() {
        trace!(
            "Node {} is not yet member according to itself",
            nodes[index].name()
        );
        return false;
    }

    let name = nodes[index].name();

    nodes
        .iter()
        .filter(|node| node.inner.is_elder())
        .filter(|node| {
            node.inner
                .our_prefix()
                .map(|prefix| prefix.matches(&name))
                .unwrap_or(false)
        })
        .all(|node| {
            if node.inner.is_peer_our_member(&name) {
                true
            } else {
                trace!(
                    "Node {} is not yet member according to {}",
                    name,
                    node.name()
                );
                false
            }
        })
}

pub fn all_nodes_joined(nodes: &[TestNode], indices: impl IntoIterator<Item = usize>) -> bool {
    indices.into_iter().all(|index| node_joined(nodes, index))
}

// Returns whether all nodes recognize the node with the given id as left.
pub fn node_left(nodes: &[TestNode], name: &XorName) -> bool {
    nodes
        .iter()
        .filter(|node| node.inner.is_elder())
        .all(|node| {
            // Note: need both checks because even if a node has been consensused as offline, it
            // can still be considered as elder until the new `SectionInfo`.
            if node.inner.is_peer_our_member(name) {
                trace!("Node {} is still member according to {}", name, node.name());
                return false;
            }

            if node.inner.is_peer_our_elder(name) {
                trace!("Node {} is still elder according to {}", name, node.name());
                return false;
            }

            true
        })
}

// Returns whether the section with the given prefix did split.
pub fn section_split(nodes: &[TestNode], prefix: &Prefix) -> bool {
    let sub_prefix0 = prefix.pushed(false);
    let sub_prefix1 = prefix.pushed(true);

    let mut pending = nodes
        .iter()
        .filter(|node| {
            if prefix.matches(node.name())
                && *node.our_prefix() != sub_prefix0
                && *node.our_prefix() != sub_prefix1
            {
                // The node hasn't progressed through the split of its own section yet.
                return true;
            }

            false
        })
        .map(|node| node.name())
        .peekable();

    if pending.peek().is_none() {
        true
    } else {
        debug!("Pending split: {}", pending.format(", "));
        false
    }
}

// Returns whether all elders of section `a` know at least `threshold` online nodes from
// section `b`.
pub fn section_knowledge_is_up_to_date(
    nodes: &[TestNode],
    a: &Prefix,
    b: &Prefix,
    threshold: usize,
) -> bool {
    let names_b: Vec<_> = nodes_with_prefix(nodes, b)
        .map(|node| node.name())
        .collect();

    for node_a in elders_with_prefix(nodes, a) {
        let count = names_b
            .iter()
            .filter(|name_b| node_a.inner.is_peer_elder(name_b))
            .take(threshold)
            .count();

        if count < threshold {
            trace!(
                "Node {}({:b}) knows only {}/{} online nodes from {:?}  {:?} among {:?}",
                node_a.name(),
                node_a.our_prefix(),
                count,
                threshold,
                b,
                names_b
                    .iter()
                    .filter(|name_b| node_a.inner.is_peer_elder(name_b))
                    .collect_vec(),
                names_b,
            );
            return false;
        }
    }

    true
}

pub fn create_connected_nodes(env: &Environment, size: usize) -> Vec<TestNode> {
    let mut nodes = Vec::new();

    // Create the seed node.
    nodes.push(TestNode::builder(env).first().create());
    let _ = nodes[0].poll();
    let endpoint = nodes[0].endpoint();
    info!("Seed node: {}", nodes[0].name());

    // Create other nodes using the seed node endpoint as bootstrap contact.
    for _ in 1..size {
        let config = TransportConfig::node().with_hard_coded_contact(endpoint);
        nodes.push(TestNode::builder(env).transport_config(config).create());
    }

    poll_until(env, &mut nodes, |nodes| {
        all_nodes_joined(nodes, 0..nodes.len())
    });
    poll_until(env, &mut nodes, |nodes| {
        elder_count_reached(nodes, &Prefix::default(), env.elder_size().min(size))
    });
    verify_invariants_for_nodes(&env, &nodes);

    for node in &mut nodes {
        expect_next_event!(node, Event::Connected(Connected::First));

        while let Some(event) = node.try_recv_event() {
            match event {
                Event::EldersChanged { .. }
                | Event::RestartRequired
                | Event::Connected(Connected::Relocate)
                | Event::PromotedToElder
                | Event::PromotedToAdult
                | Event::Demoted
                | Event::MemberJoined { .. }
                | Event::InfantJoined { .. }
                | Event::MemberLeft { .. } => (),
                event => panic!("Got unexpected event: {:?}", event),
            }
        }
    }

    nodes
}

pub fn create_connected_nodes_until_split(
    env: &Environment,
    prefix_lengths: &[usize],
) -> Vec<TestNode> {
    let mut rng = env.new_rng();

    // The prefixes we want to create.
    let final_prefixes = gen_prefixes(&mut rng, prefix_lengths);

    // The sequence of prefixes to split in order to reach `final_prefixes`.
    let mut split_sequence: Vec<_> = final_prefixes
        .iter()
        .flat_map(|prefix| prefix.ancestors())
        .sorted_by(|lhs, rhs| lhs.cmp_breadth_first(rhs))
        .collect();
    split_sequence.dedup();

    let mut nodes = Vec::new();

    for prefix_to_split in split_sequence {
        trigger_split(env, &mut nodes, &prefix_to_split)
    }

    // Gather all the actual prefixes and check they are as expected.
    let actual_prefixes: BTreeSet<_> = current_sections(&nodes).collect();
    assert_eq!(actual_prefixes, final_prefixes.iter().copied().collect());

    let actual_prefix_lengths: Vec<_> = actual_prefixes
        .iter()
        .map(Prefix::bit_count)
        .sorted()
        .collect();
    assert_eq!(&actual_prefix_lengths[..], prefix_lengths);

    trace!("Created testnet comprising {:?}", actual_prefixes);

    nodes
}

// Add connected nodes to the given prefix until adding one extra node into the
// returned sub-prefix would trigger a split.
pub fn add_connected_nodes_until_one_away_from_split(
    env: &Environment,
    nodes: &mut Vec<TestNode>,
    prefix_to_nearly_split: &Prefix,
) -> Prefix {
    let sub_prefix_last_bit = env.new_rng().gen();
    let sub_prefix = prefix_to_nearly_split.pushed(sub_prefix_last_bit);
    let (count0, count1) = if sub_prefix_last_bit {
        (
            env.recommended_section_size(),
            env.recommended_section_size() - 1,
        )
    } else {
        (
            env.recommended_section_size() - 1,
            env.recommended_section_size(),
        )
    };

    add_mature_nodes(env, nodes, prefix_to_nearly_split, count0, count1);

    sub_prefix
}

/// Split the section by adding and/or removing nodes to/from it.
pub fn trigger_split(env: &Environment, nodes: &mut Vec<TestNode>, prefix: &Prefix) {
    info!("trigger_split start: {:?}", prefix);

    // To trigger split, we need the section to contain at least `recommended_section_size` *mature* nodes
    // from each sub-prefix.
    add_mature_nodes(
        env,
        nodes,
        prefix,
        env.recommended_section_size(),
        env.recommended_section_size(),
    );

    // Verify the split actually happened.
    poll_until(env, nodes, |nodes| section_split(nodes, prefix));
    info!("trigger_split done: {:?}", prefix);
}

/// Add/remove nodes to the given section until it has exactly `target_count_0` mature nodes from the
/// 0-ending subprefix and `target_count_1` mature nodes from the 1-ending subprefix.
/// Note: if `target_count_0` and `target_count_1` are both at least `recommended_section_size`, this
/// causes the section to split.
pub fn add_mature_nodes(
    env: &Environment,
    nodes: &mut Vec<TestNode>,
    prefix: &Prefix,
    target_count_0: usize,
    target_count_1: usize,
) {
    let mut rng = env.new_rng();

    let sub_prefix_0 = prefix.pushed(false);
    let sub_prefix_1 = prefix.pushed(true);

    // Add nodes to reach the target size.
    let total_count_0 = nodes_with_prefix(nodes, &sub_prefix_0).count();
    let total_count_1 = nodes_with_prefix(nodes, &sub_prefix_1).count();

    let excess_count_0 = total_count_0.saturating_sub(target_count_0);
    let excess_count_1 = total_count_1.saturating_sub(target_count_1);

    let new_count_0 = target_count_0
        .saturating_sub(total_count_0)
        .saturating_sub(excess_count_1);
    let new_count_1 = target_count_1
        .saturating_sub(total_count_1)
        .saturating_sub(excess_count_0);

    trace!(
        "add_mature_nodes: adding {:?}: {}, {:?}: {}",
        sub_prefix_0,
        new_count_0,
        sub_prefix_0,
        new_count_1
    );
    add_nodes_to_subsections_and_poll(env, nodes, prefix, new_count_0, new_count_1);

    // Is the node at `index` mature (adult or elder)?
    fn is_mature(nodes: &[TestNode], index: usize) -> bool {
        nodes[index].inner.is_elder() || node_age(nodes, nodes[index].name()) > MIN_AGE
    }

    // Churn until we reach the desired number of mature nodes.
    for i in 0.. {
        // Check the number of mature nodes in each subprefix.
        let mature_count_0 = indexed_nodes_with_prefix(nodes, &sub_prefix_0)
            .filter(|(index, _)| is_mature(nodes, *index))
            .count();
        let mature_count_1 = indexed_nodes_with_prefix(nodes, &sub_prefix_1)
            .filter(|(index, _)| is_mature(nodes, *index))
            .count();

        let total_count_0 = nodes_with_prefix(nodes, &sub_prefix_0).count();
        let total_count_1 = nodes_with_prefix(nodes, &sub_prefix_1).count();

        info!(
            "add_mature_nodes (#{}): ({:b}): mature: {}/{} total: {}, ({:b}): mature: {}/{} total: {}",
            i,
            sub_prefix_0,
            mature_count_0,
            target_count_0,
            total_count_0,
            sub_prefix_1,
            mature_count_1,
            target_count_1,
            total_count_1,
        );

        // If there is enough, we are done.
        if mature_count_0 >= target_count_0 && mature_count_1 >= target_count_1 {
            break;
        }

        // Pick prefixes to add and remove nodes to/from.
        let remove_prefix = if mature_count_0 == 0 {
            &sub_prefix_1
        } else if mature_count_1 == 0 {
            &sub_prefix_0
        } else {
            match total_count_0
                .cmp(&total_count_1)
                .then(mature_count_0.cmp(&mature_count_1))
            {
                Ordering::Less => &sub_prefix_1,
                Ordering::Greater => &sub_prefix_0,
                Ordering::Equal => {
                    if rng.gen() {
                        &sub_prefix_0
                    } else {
                        &sub_prefix_1
                    }
                }
            }
        };

        let add_prefix = match total_count_0.cmp(&total_count_1) {
            Ordering::Less => &sub_prefix_0,
            Ordering::Greater => &sub_prefix_1,
            Ordering::Equal => remove_prefix,
        };

        // Pick a random mature node that we will remove later in order to trigger relocation.
        let remove_index = indexed_nodes_with_prefix(nodes, remove_prefix)
            .map(|(index, _)| index)
            .filter(|index| is_mature(nodes, *index))
            .choose(&mut rng)
            .expect("no mature node found");

        // Add a new node to replace the removed one to keep the target section size.
        add_node_to_section(env, nodes, add_prefix);

        // Let the add settle.
        let last_index = nodes.len() - 1;
        poll_until_last_nodes_joined(env, nodes, last_index);
        poll_until_elder_size(env, nodes, prefix);

        // Remove the previously selected mature node. This might trigger one or more relocations.
        trace!(
            "add_mature_nodes (#{}): removing {} (prefix: {:b}, elder: {})",
            i,
            nodes[remove_index].name(),
            remove_prefix,
            nodes[remove_index].inner.is_elder(),
        );
        let remove_name = *nodes.remove(remove_index).name();

        let mut index_cache = create_node_index_cache(nodes);

        // Let the remove settle.
        poll_until(env, nodes, |nodes| node_left(nodes, &remove_name));
        update_neighbours_and_poll(env, nodes, 2);

        // Poll until all triggered relocations complete (if any).
        poll_until_all_relocations_complete(env, nodes, &mut index_cache);
    }
}

/// Poll until all relocations complete, including secondary relocations triggered by previous
/// relocations.
/// `index_cache` is a map from names to indices from the time before the event that caused
pub fn poll_until_all_relocations_complete(
    env: &Environment,
    nodes: &mut [TestNode],
    index_cache: &mut HashMap<XorName, usize>,
) {
    const MAX_ITERATIONS: usize = 100;

    for _ in 0..MAX_ITERATIONS {
        // Detect all relocations voted for by at least quorum of nodes.
        let mut pending = HashMap::<_, Vec<_>>::new();

        for node in nodes.iter_mut() {
            let relocating_nodes =
                iter::from_fn(|| node.try_recv_event()).filter_map(|event| match event {
                    Event::RelocationInitiated { name, .. } => Some(name),
                    _ => None,
                });
            for relocating_node in relocating_nodes {
                pending
                    .entry(relocating_node)
                    .or_default()
                    .push(*node.name());
            }
        }

        let pending: BTreeSet<_> = pending
            .into_iter()
            .filter(|(_, voters)| voters.len() >= quorum_count(env.elder_size()))
            .map(|(name, _)| name)
            .collect();

        if pending.is_empty() {
            return;
        }

        trace!("pending relocations: {:?}", pending);
        poll_until_relocations_complete(env, nodes, &pending, index_cache);
    }

    panic!(
        "poll_until_all_relocations_complete has been called {} times",
        MAX_ITERATIONS
    );
}

// Poll until the given relocations (given as a set of old names of the relocating nodes) all
// complete.
fn poll_until_relocations_complete(
    env: &Environment,
    nodes: &mut [TestNode],
    relocations: &BTreeSet<XorName>,
    index_cache: &mut HashMap<XorName, usize>,
) {
    poll_until(env, nodes, |nodes| {
        for old_name in relocations {
            let index = if let Some(&index) = index_cache.get(old_name) {
                index
            } else {
                // `old_name` is already relocated.
                continue;
            };

            if nodes[index].name() == old_name {
                trace!("pending relocation: {} still has old name", old_name);
                return false;
            }

            let new_name = nodes[index].name();

            if !node_left(nodes, old_name) {
                trace!(
                    "pending relocation: {} (was {}) hasn't yet left the source section",
                    new_name,
                    old_name
                );
                return false;
            }

            if !node_joined(nodes, index) {
                trace!(
                    "pending relocation: {} (was {}) hasn't yet re-joined the network",
                    new_name,
                    old_name,
                );
                return false;
            }

            trace!("relocation complete: {} -> {}", old_name, new_name);

            // Update the index cache
            let _ = index_cache.remove(old_name);
            let _ = index_cache.insert(*new_name, index);
        }

        true
    })
}

// Create map from node name to its index.
fn create_node_index_cache(nodes: &[TestNode]) -> HashMap<XorName, usize> {
    nodes
        .iter()
        .enumerate()
        .map(|(index, node)| (*node.name(), index))
        .collect()
}

// Add `count0` nodes to the sub-prefix of `prefix` ending in 0 and `count1` nodes to the subprefix
// ending in 1. Add the nodes in random order to avoid accidentally relying on them being in any
// particular order. Poll the network until all the new nodes joined.
fn add_nodes_to_subsections_and_poll(
    env: &Environment,
    nodes: &mut Vec<TestNode>,
    prefix: &Prefix,
    count0: usize,
    count1: usize,
) {
    let mut rng = env.new_rng();
    let sub_prefix0 = prefix.pushed(false);
    let sub_prefix1 = prefix.pushed(true);

    let mut remaining0 = count0;
    let mut remaining1 = count1;
    let mut first_index = nodes.len();

    loop {
        let bit = if remaining0 > 0 && remaining1 > 0 {
            rng.gen()
        } else if remaining1 > 0 {
            true
        } else if remaining0 > 0 {
            false
        } else {
            break;
        };

        if bit {
            add_node_to_section(env, nodes, &sub_prefix1);
            remaining1 -= 1;
        } else {
            add_node_to_section(env, nodes, &sub_prefix0);
            remaining0 -= 1;
        }

        let i = count0 + count1 - remaining0 - remaining1;
        if i % MAX_SIMULTANEOUS_JOINS == 0 {
            poll_until_last_nodes_joined(env, nodes, first_index);
            first_index = nodes.len();
        }
    }

    poll_until_last_nodes_joined(env, nodes, first_index);
}

fn poll_until_last_nodes_joined(env: &Environment, nodes: &mut [TestNode], first_index: usize) {
    poll_until(env, nodes, |nodes| {
        all_nodes_joined(nodes, first_index..nodes.len())
    })
}

/*
// Poll until the section with `prefix` has at least 4 elders which is the miminum so that if one
// elder is removed, the consensus on it can still be reached.
fn poll_until_minimal_elder_count(env: &Environment, nodes: &mut [TestNode], prefix: &Prefix) {
    assert!(
        env.elder_size() >= MIN_ELDER_SIZE,
        "elder size must be at least {}, but is only {}",
        MIN_ELDER_SIZE,
        env.elder_size()
    );

    poll_until(env, nodes, |nodes| {
        elder_count_reached(nodes, prefix, MIN_ELDER_SIZE)
    })
}
*/

// Poll until the section with `prefix` has `elder_size` elders.
fn poll_until_elder_size(env: &Environment, nodes: &mut [TestNode], prefix: &Prefix) {
    poll_until(env, nodes, |nodes| {
        let expected_count = env
            .elder_size()
            .min(nodes_with_prefix(nodes, prefix).count());
        elder_count_reached(nodes, prefix, expected_count)
    })
}

// Returns whether the section at `prefix` has at least `expected_count` elders.
fn elder_count_reached(nodes: &[TestNode], prefix: &Prefix, expected_count: usize) -> bool {
    let actual_count = elders_with_prefix(nodes, prefix).count();
    if actual_count < expected_count {
        trace!(
            "there are only {}/{} elders in {:?}",
            actual_count,
            expected_count,
            prefix
        );
        return false;
    }

    for node in elders_with_prefix(nodes, prefix) {
        let actual_count = node.inner.our_elders().count();
        if actual_count < expected_count {
            trace!(
                "node {} knows only {}/{} elders",
                node.name(),
                actual_count,
                expected_count
            );
            return false;
        }
    }

    true
}

// -----  Small misc functions  -----

/// Sorts the given nodes by their distance to `name`.
pub fn sort_nodes_by_distance_to(nodes: &mut [TestNode], name: &XorName) {
    nodes.sort_by(|node0, node1| name.cmp_distance(node0.name(), node1.name()));
}

/// Iterator over all nodes that belong to the given prefix.
pub fn nodes_with_prefix<'a>(
    nodes: &'a [TestNode],
    prefix: &'a Prefix,
) -> impl Iterator<Item = &'a TestNode> {
    nodes.iter().filter(move |node| prefix.matches(node.name()))
}

/// Mutable iterator over all nodes that belong to the given prefix.
pub fn nodes_with_prefix_mut<'a>(
    nodes: &'a mut [TestNode],
    prefix: &'a Prefix,
) -> impl Iterator<Item = &'a mut TestNode> {
    nodes
        .iter_mut()
        .filter(move |node| prefix.matches(node.name()))
}

/// Iterator over all nodes that belong to the given prefix + their indices
pub fn indexed_nodes_with_prefix<'a>(
    nodes: &'a [TestNode],
    prefix: &'a Prefix,
) -> impl Iterator<Item = (usize, &'a TestNode)> {
    nodes
        .iter()
        .enumerate()
        .filter(move |(_, node)| prefix.matches(node.name()))
}

/// Iterator over all elder nodes that belong to the given prefix.
pub fn elders_with_prefix<'a>(
    nodes: &'a [TestNode],
    prefix: &'a Prefix,
) -> impl Iterator<Item = &'a TestNode> {
    nodes_with_prefix(nodes, prefix).filter(|node| node.inner.is_elder())
}

/// Mutable iterator over all elder nodes that belong to the given prefix.
pub fn elders_with_prefix_mut<'a>(
    nodes: &'a mut [TestNode],
    prefix: &'a Prefix,
) -> impl Iterator<Item = &'a mut TestNode> {
    nodes_with_prefix_mut(nodes, prefix).filter(|node| node.inner.is_elder())
}

/// Returns the age of the node with the given name.
pub fn node_age(nodes: &[TestNode], name: &XorName) -> u8 {
    if let Some(counter) = nodes
        .iter()
        .filter_map(|node| node.inner.member_age(name))
        .max()
    {
        counter
    } else {
        panic!("{} is not a member known to any node", name)
    }
}

pub fn verify_invariants_for_node(env: &Environment, node: &TestNode) {
    let our_prefix = node.our_prefix();
    let our_name = node.name();
    let our_section_elders: BTreeSet<_> = node
        .inner
        .our_section()
        .expect("node is not joined")
        .elders
        .keys()
        .copied()
        .collect();

    assert!(
        our_prefix.matches(our_name),
        "{}({:b}) Our prefix doesn't match our name",
        our_name,
        our_prefix,
    );

    if !our_prefix.is_empty() {
        assert!(
            our_section_elders.len() >= env.elder_size(),
            "{}({:b}) Our section is below the minimum size ({}/{})",
            our_name,
            our_prefix,
            our_section_elders.len(),
            env.elder_size(),
        );
    }

    if let Some(name) = our_section_elders
        .iter()
        .find(|name| !our_prefix.matches(name))
    {
        panic!(
            "{}({:b}) A name in our section doesn't match its prefix: {}",
            our_name, our_prefix, name,
        );
    }

    if !node.inner.is_elder() {
        return;
    }

    let neighbour_sections: BTreeSet<_> = node.inner.neighbour_sections().collect();

    if let Some(compatible_prefix) = neighbour_sections
        .iter()
        .map(|info| &info.prefix)
        .find(|prefix| prefix.is_compatible(our_prefix))
    {
        panic!(
            "{}({:b}) Our prefix is compatible with one of the neighbour prefixes: {:?} (neighbour_sections: {:?})",
            our_name,
            our_prefix,
            compatible_prefix,
            neighbour_sections,
        );
    }

    if let Some(info) = neighbour_sections
        .iter()
        .find(|info| info.elders.len() < env.elder_size())
    {
        panic!(
            "{}({:b}) A neighbour section {:?} is below the minimum size ({}/{}) (neighbour_sections: {:?})",
            our_name,
            our_prefix,
            info.prefix,
            info.elders.len(),
            env.elder_size(),
            neighbour_sections,
        );
    }

    for info in &neighbour_sections {
        if let Some(name) = info.elders.keys().find(|name| !info.prefix.matches(name)) {
            panic!(
                "{}({:b}) A name in a section doesn't match its prefix: {:?}, {:?}",
                our_name, our_prefix, name, info.prefix,
            );
        }
    }

    let non_neighbours: Vec<_> = neighbour_sections
        .iter()
        .map(|info| &info.prefix)
        .filter(|prefix| !our_prefix.is_neighbour(prefix))
        .collect();
    if !non_neighbours.is_empty() {
        panic!(
            "{}({:b}) Some of our known sections aren't neighbours of our section: {:?}",
            our_name, our_prefix, non_neighbours,
        );
    }

    let all_neighbours_covered = {
        (0..our_prefix.bit_count()).all(|i| {
            our_prefix
                .with_flipped_bit(i as u8)
                .is_covered_by(neighbour_sections.iter().map(|info| &info.prefix))
        })
    };
    if !all_neighbours_covered {
        panic!(
            "{}({:b}) Some neighbours aren't fully covered by our known sections: {:?}",
            our_name,
            our_prefix,
            iter::once(*our_prefix)
                .chain(neighbour_sections.iter().map(|info| info.prefix))
                .format(", ")
        );
    }
}

pub fn verify_invariants_for_nodes(env: &Environment, nodes: &[TestNode]) {
    for node in nodes {
        verify_invariants_for_node(env, node);
    }
}

// Send an `UserMessage` with `content` from `src` to `dst`.
pub fn send_user_message(nodes: &mut [TestNode], src: Prefix, dst: Prefix, content: Vec<u8>) {
    trace!(
        "send_user_message: {:?} -> {:?}: {:10}",
        src,
        dst,
        hex_fmt::HexFmt(&content),
    );

    let src_location = SrcLocation::Section(src);
    let dst_location = DstLocation::Section(dst.name());

    for node in elders_with_prefix_mut(nodes, &src) {
        node.inner
            .send_message(src_location, dst_location, content.clone())
            .unwrap()
    }
}

// Poll until all sections have up-to-date knowledge of their neighbour sections.
// We consider section A's knowledge of its neighbour section B as up-to-date if every elder from A
// knows at least `threshold` online nodes from B.
pub fn update_neighbours_and_poll(env: &Environment, nodes: &mut [TestNode], threshold: usize) {
    info!("update_neighbours_and_poll start");

    let mut rng = env.new_rng();

    // Max number of times we will try to send messages and wait until the knowledge gets updated.
    let max_sends = 3;
    // Number of iterations until we send new messages.
    let mut send_countdown = 0;

    for _ in 0..POLL_UNTIL_MAX_ITERATIONS {
        let outdated: BTreeSet<_> = neighbours_with_outdated_knowledge(nodes, threshold).collect();
        if outdated.is_empty() {
            info!("update_neighbours_and_poll done");
            return;
        }

        if send_countdown == 0 {
            send_countdown = POLL_UNTIL_MAX_ITERATIONS / max_sends;

            for (a, b) in outdated {
                let content = gen_vec(&mut rng, 32);
                send_user_message(nodes, a, b, content);
                // For the case that section a got churned, but section b not.
                // A user message from a to b contains the latest knowledge of b, which will not
                // incur neighbour update. It has to be a user message from b to a to be sent.
                let content = gen_vec(&mut rng, 32);
                send_user_message(nodes, b, a, content);
            }
        } else {
            send_countdown -= 1;
        }

        poll_all(env, nodes);
        advance_time(POLL_UNTIL_TIME_STEP);
    }

    panic!(
        "update_neighbours_and_poll failed after {} iterations",
        POLL_UNTIL_MAX_ITERATIONS
    );
}

// Returns iterator over pairs of neighbour sections where at least one has outdated knowledge of
// the other. See `section_knowledge_is_up_to_date` for the meaning of `threshold`.
fn neighbours_with_outdated_knowledge<'a>(
    nodes: &'a [TestNode],
    threshold: usize,
) -> impl Iterator<Item = (Prefix, Prefix)> + 'a {
    let prefixes: Vec<_> = current_sections(nodes).collect();
    prefixes
        .into_iter()
        .tuple_combinations()
        .filter(|(a, b)| a.is_neighbour(b))
        .filter(move |(a, b)| {
            !section_knowledge_is_up_to_date(nodes, a, b, threshold)
                || !section_knowledge_is_up_to_date(nodes, b, a, threshold)
        })
}

// Generate a vector of random T of the given length.
pub fn gen_vec<T>(rng: &mut MainRng, size: usize) -> Vec<T>
where
    Standard: Distribution<T>,
{
    rng.sample_iter(&Standard).take(size).collect()
}

// Generate a vector of random bytes of the given length.
pub fn gen_bytes(rng: &mut MainRng, size: usize) -> Vec<u8> {
    gen_vec(rng, size)
}

// Create new node in the given section.
pub fn add_node_to_section(env: &Environment, nodes: &mut Vec<TestNode>, prefix: &Prefix) {
    add_node_to_section_using_bootstrap_node(env, nodes, prefix, 0)
}

// Create new node in the given section, bootstrapping it off the node at the given index.
pub fn add_node_to_section_using_bootstrap_node(
    env: &Environment,
    nodes: &mut Vec<TestNode>,
    prefix: &Prefix,
    bootstrap_node_index: usize,
) {
    let mut rng = env.new_rng();
    let full_id = FullId::within_range(&mut rng, &prefix.range_inclusive());

    let node = if nodes.is_empty() {
        TestNode::builder(env).first().full_id(full_id).create()
    } else {
        let bootstrap_contact = nodes[bootstrap_node_index].endpoint();
        let config = TransportConfig::node().with_hard_coded_contact(bootstrap_contact);
        TestNode::builder(env)
            .transport_config(config)
            .full_id(full_id)
            .create()
    };

    info!("Adding node {} to {:?}", node.name(), prefix);
    nodes.push(node);
}

// Removes one elder node from the given prefix. Returns the name of the removed node.
pub fn remove_elder_from_section(nodes: &mut Vec<TestNode>, prefix: &Prefix) -> XorName {
    let index = indexed_nodes_with_prefix(&nodes, prefix)
        .find(|(_, node)| node.inner.is_elder())
        .map(|(index, _)| index)
        .unwrap();

    info!(
        "Removing node {} from {:?} (was elder: {})",
        nodes[index].name(),
        prefix,
        nodes[index].inner.is_elder(),
    );
    *nodes.remove(index).name()
}

// Generate random prefixes with the given lengths.
fn gen_prefixes(rng: &mut MainRng, prefix_lengths: &[usize]) -> Vec<Prefix> {
    validate_prefix_lenghts(&prefix_lengths);

    let _ = prefix_lengths.iter().fold(0, |previous, &current| {
        assert!(
            previous <= current,
            "Slice {:?} should be sorted.",
            prefix_lengths
        );
        current
    });

    let mut prefixes = vec![Prefix::new(prefix_lengths[0], rng.gen())];
    while prefixes.len() < prefix_lengths.len() {
        let new_prefix = Prefix::new(prefix_lengths[prefixes.len()], rng.gen());
        if prefixes
            .iter()
            .all(|prefix| !prefix.is_compatible(&new_prefix))
        {
            prefixes.push(new_prefix);
        }
    }
    prefixes
}

// Validate the prefixes generated with the given lengths. That is:
// - there are at least two prefixes
// - no prefix is longer than 8 bits
// - the prefixes cover the whole xor-name space
// - the prefixes don't overlap
fn validate_prefix_lenghts(prefix_lengths: &[usize]) {
    assert!(
        prefix_lengths.len() > 1,
        "There should be at least two specified prefix lengths"
    );
    let sum = prefix_lengths.iter().fold(0, |accumulated, &bit_count| {
        assert!(
            bit_count <= 8,
            "The specified prefix lengths {:?} must each be no more than 8",
            prefix_lengths
        );
        accumulated + (1 << (8 - bit_count))
    });

    match sum.cmp(&256) {
        Ordering::Less => {
            panic!(
                "The specified prefix lengths {:?} would not cover the entire address space",
                prefix_lengths
            );
        }
        Ordering::Greater => {
            panic!(
                "The specified prefix lengths {:?} would require overlapping sections",
                prefix_lengths
            );
        }
        Ordering::Equal => (),
    }
}

mod tests {
    use super::*;

    #[test]
    fn validate_prefix_lenghts_valid() {
        validate_prefix_lenghts(&[1, 1]);
        validate_prefix_lenghts(&[1, 2, 3, 4, 5, 6, 7, 8, 8]);
        validate_prefix_lenghts(&[8; 256]);
    }

    #[test]
    #[should_panic(expected = "There should be at least two specified prefix lengths")]
    fn validate_prefix_lenghts_no_split() {
        validate_prefix_lenghts(&[0]);
    }

    #[test]
    #[should_panic(expected = "would require overlapping sections")]
    fn validate_prefix_lenghts_overlapping_sections() {
        validate_prefix_lenghts(&[1, 2, 2, 2]);
    }

    #[test]
    #[should_panic(expected = "would not cover the entire address space")]
    fn validate_prefix_lenghts_missing_sections() {
        validate_prefix_lenghts(&[1, 2]);
    }

    #[test]
    #[should_panic(expected = "must each be no more than 8")]
    fn validate_prefix_lenghts_too_many_sections() {
        validate_prefix_lenghts(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 9]);
    }
}
