// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crossbeam_channel as mpmc;
use fake_clock::FakeClock;
use itertools::Itertools;
use rand::{
    distributions::{Distribution, Standard},
    Rng,
};
use routing::{
    event::{Connected, Event},
    mock::Environment,
    rng::MainRng,
    test_consts, DstLocation, FullId, Node, NodeConfig, PausedState, Prefix, PublicId,
    RelocationOverrides, SrcLocation, TransportConfig,
};
use std::{
    cmp::Ordering, collections::BTreeSet, convert::TryInto, iter, net::SocketAddr, time::Duration,
};
use xor_name::XorName;

// The smallest number of elders which allows to reach consensus when one of them goes offline.
pub const MIN_ELDER_SIZE: usize = 4;

// Maximum number of iterations of the `poll_until` function. This is several orders higher than
// the anticipated upper limit for any test, and if hit is likely to indicate an infinite loop.
const POLL_UNTIL_MAX_ITERATIONS: usize = 2000;

// Duration to advance the time after each iteration of poll_until.
const POLL_UNTIL_TIME_STEP: Duration =
    Duration::from_millis(test_consts::GOSSIP_PERIOD.as_millis() as u64 + 1);

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

// Returns whether consensus on the given user event has been reached by at least the given number
// of nodes.
// `current_count` must point to a variable that is initialized to zero before the polling starts.
pub fn consensus_reached(
    nodes: &[TestNode],
    expected_content: &[u8],
    expected_count: usize,
    current_count: &mut usize,
) -> bool {
    for node in nodes {
        if let Some(Event::Consensus(actual_content)) = node.try_recv_event() {
            if &actual_content[..] == expected_content {
                *current_count += 1;
            }
        }
    }

    *current_count >= expected_count
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
                "Node {}({:b}) knows only {}/{} online nodes from {:?}",
                node_a.name(),
                node_a.our_prefix(),
                count,
                threshold,
                b
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
                | Event::Promoted
                | Event::Demoted
                | Event::MemberJoined { .. }
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

/// Add/remove nodes to the given section until it has exactly `count0` mature nodes from the
/// 0-ending subprefix and `count1` mature nodes from the 1-ending subprefix.
/// Note: if `count0` and `count1` are both at least `recommended_section_size`, this causes the section
/// to split.
pub fn add_mature_nodes(
    env: &Environment,
    nodes: &mut Vec<TestNode>,
    prefix: &Prefix,
    count0: usize,
    count1: usize,
) {
    // Number of churn events to make an infant node become mature.
    let churns_to_mature = 16usize;

    let sub_prefix0 = prefix.pushed(false);
    let sub_prefix1 = prefix.pushed(true);

    // Count the number of nodes per sub-prefix.
    let start_count0 = nodes_with_prefix(nodes, &sub_prefix0).count();
    let start_count1 = nodes_with_prefix(nodes, &sub_prefix1).count();

    info!(
        "Starting with {} initial nodes",
        start_count0 + start_count1
    );

    let mut overrides = RelocationOverrides::new();
    overrides.suppress(*prefix);

    // Add temporary nodes to the section until it has 32 nodes. Purposefully make the section
    // unbalanced to avoid splitting it just yet.
    let temp_sub_prefix = match start_count0.cmp(&start_count1) {
        Ordering::Less => &sub_prefix1,
        Ordering::Greater => &sub_prefix0,
        Ordering::Equal => {
            if env.new_rng().gen() {
                &sub_prefix1
            } else {
                &sub_prefix0
            }
        }
    };

    let temp_count = (2 * churns_to_mature).saturating_sub(start_count0 + start_count1);
    info!("Adding {} temporary nodes", temp_count);
    add_nodes_to_section_and_poll(env, nodes, &temp_sub_prefix, temp_count);

    // Make sure the section has enough elders before proceeding to remove them.
    poll_until_minimal_elder_count(env, nodes, prefix);

    // Remove 16 mature notes so the remaining nodes become all mature.
    info!(
        "Removing the first half ({}) of the temporary nodes",
        churns_to_mature
    );
    remove_elders_from_section_and_poll(env, nodes, prefix, churns_to_mature);

    // Add the final nodes. `count0` into the 0-ending sub-prefix and `count1` into the
    // 1-ending.
    info!("Adding {} final nodes", count0 + count1);
    add_nodes_to_subsections_and_poll(env, nodes, &prefix, count0, count1);

    // Make sure the section has enough elders before proceeding to remove them.
    poll_until_minimal_elder_count(env, nodes, prefix);

    // Remove another 16 matures nodes (which are the remaining temporary nodes) so all the new
    // nodes become mature too.
    info!(
        "Removing the remaining half ({}) of the temporary nodes",
        churns_to_mature
    );
    remove_elders_from_section_and_poll(env, nodes, prefix, churns_to_mature);

    // We should now be left with just the final nodes who are now all mature.
    // Verify it is the case.
    let actual_count0 = nodes_with_prefix(nodes, &sub_prefix0).count();
    let actual_count1 = nodes_with_prefix(nodes, &sub_prefix1).count();
    assert_eq!((actual_count0, actual_count1), (count0, count1));
}

// Add `count` nodes to the section with `prefix` and poll the network until all of them joined.
fn add_nodes_to_section_and_poll(
    env: &Environment,
    nodes: &mut Vec<TestNode>,
    prefix: &Prefix,
    count: usize,
) {
    let mut first_index = nodes.len();

    for i in 0..count {
        add_node_to_section(env, nodes, prefix);

        if (i + 1) % MAX_SIMULTANEOUS_JOINS == 0 {
            poll_until_last_nodes_joined(env, nodes, first_index);
            first_index = nodes.len();
        }
    }

    poll_until_last_nodes_joined(env, nodes, first_index);
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

fn remove_elders_from_section_and_poll(
    env: &Environment,
    nodes: &mut Vec<TestNode>,
    prefix: &Prefix,
    count: usize,
) {
    for _ in 0..count {
        let removed_id = remove_elder_from_section(nodes, prefix);
        poll_until(env, nodes, |nodes| node_left(nodes, &removed_id));
        update_neighbours_and_poll(env, nodes, 2);
    }
}

fn poll_until_last_nodes_joined(env: &Environment, nodes: &mut [TestNode], first_index: usize) {
    poll_until(env, nodes, |nodes| {
        all_nodes_joined(nodes, first_index..nodes.len())
    })
}

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

// Returns whether the section at `prefix` has at least `expected_count` elders.
fn elder_count_reached(nodes: &[TestNode], prefix: &Prefix, expected_count: usize) -> bool {
    let actual_count = elders_with_prefix(nodes, prefix).count();

    if actual_count >= expected_count {
        true
    } else {
        trace!(
            "Section {:?} has only {}/{} elders",
            prefix,
            actual_count,
            expected_count,
        );
        false
    }
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
