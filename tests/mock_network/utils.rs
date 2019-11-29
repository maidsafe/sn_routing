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
use rand::Rng;
use routing::{
    mock::Network, test_consts, Authority, Event, EventStream, FullId, NetworkConfig, Node,
    NodeBuilder, PausedState, Prefix, PublicId, XorName, Xorable,
};
use std::{
    cmp,
    collections::{BTreeMap, BTreeSet},
    iter,
    net::SocketAddr,
    ops::{Deref, DerefMut},
};

// Maximum number of times to try and poll in a loop.  This is several orders higher than the
// anticipated upper limit for any test, and if hit is likely to indicate an infinite loop.
const MAX_POLL_CALLS: usize = 2000;

// ----- Typs -----
type PrefixAndSize = (Prefix<XorName>, usize);

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

/// Wraps a `Vec<TestNode>`s and prints the nodes' routing tables when dropped in a panicking
/// thread.
pub struct Nodes(pub Vec<TestNode>);

impl Deref for Nodes {
    type Target = Vec<TestNode>;

    fn deref(&self) -> &Vec<TestNode> {
        &self.0
    }
}

impl DerefMut for Nodes {
    fn deref_mut(&mut self) -> &mut Vec<TestNode> {
        &mut self.0
    }
}

// -----  TestNode and builder  -----

impl EventStream for TestNode {
    type Item = Event;

    fn next_ev(&mut self) -> Result<Event, mpmc::RecvError> {
        self.inner.next_ev()
    }

    fn try_next_ev(&mut self) -> Result<Event, mpmc::TryRecvError> {
        self.inner.try_next_ev()
    }

    fn poll(&mut self) -> bool {
        self.inner.poll()
    }
}

pub struct TestNode {
    pub inner: Node,
    network: Network,
}

impl TestNode {
    pub fn builder(network: &Network) -> TestNodeBuilder {
        TestNodeBuilder {
            inner: Node::builder(),
            network: network,
        }
    }

    pub fn resume(network: &Network, state: PausedState) -> Self {
        Self {
            inner: Node::resume(state).0,
            network: network.clone(),
        }
    }

    pub fn endpoint(&mut self) -> SocketAddr {
        unwrap!(self.inner.our_connection_info()).peer_addr
    }

    pub fn id(&self) -> PublicId {
        unwrap!(self.inner.id())
    }

    pub fn name(&self) -> XorName {
        *self.id().name()
    }

    pub fn close_names(&self) -> Vec<XorName> {
        unwrap!(self.inner.close_names(&self.name()))
    }

    pub fn our_prefix(&self) -> &Prefix<XorName> {
        unwrap!(self.inner.our_prefix())
    }

    pub fn is_recipient(&self, dst: &Authority<XorName>) -> bool {
        self.inner.in_authority(dst)
    }

    pub fn network(&self) -> &Network {
        &self.network
    }
}

pub fn count_sections(nodes: &[TestNode]) -> usize {
    current_sections(nodes).count()
}

pub fn current_sections<'a>(nodes: &'a [TestNode]) -> impl Iterator<Item = Prefix<XorName>> + 'a {
    nodes.iter().flat_map(|n| n.inner.prefixes()).unique()
}

pub struct TestNodeBuilder<'a> {
    inner: NodeBuilder,
    network: &'a Network,
}

impl<'a> TestNodeBuilder<'a> {
    pub fn first(self) -> Self {
        Self {
            inner: self.inner.first(true),
            ..self
        }
    }

    pub fn network_config(self, config: NetworkConfig) -> Self {
        Self {
            inner: self.inner.network_config(config),
            ..self
        }
    }

    pub fn full_id(self, full_id: FullId) -> Self {
        Self {
            inner: self.inner.full_id(full_id),
            ..self
        }
    }

    pub fn create(self) -> TestNode {
        let (inner, _node_rx) = unwrap!(self
            .inner
            .network_cfg(self.network.network_cfg())
            .rng(self.network.new_rng())
            .create());

        TestNode {
            inner,
            network: self.network.clone(),
        }
    }
}

// -----  poll_all, create_connected_...  -----

/// Process all events. Returns whether there were any events.
pub fn poll_all(nodes: &mut [TestNode]) -> bool {
    assert!(!nodes.is_empty());
    let network = nodes[0].network().clone();
    let mut result = false;
    for _ in 0..MAX_POLL_CALLS {
        network.poll();

        let mut handled_message = false;
        for node in nodes.iter_mut() {
            handled_message = node.poll() || handled_message;
        }

        // check if there were any outgoing messages which could be due to timeouts
        // that were handled via cur iter poll.
        let any_outgoing_messages = network.reset_message_sent();
        if !handled_message && !any_outgoing_messages {
            return result;
        }

        result = true;
    }
    panic!("poll_all has been called {} times.", MAX_POLL_CALLS);
}

/// Polls and processes all events, until there are no unacknowledged messages left.
pub fn poll_and_resend(nodes: &mut [TestNode]) {
    poll_and_resend_with_options(nodes, PollOptions::default())
}

/// Options for polling nodes in the test network.
pub struct PollOptions {
    /// If set, polling continues while this predicate returns true even if all nodes are idle.
    pub continue_predicate: Option<Box<dyn Fn(&[TestNode]) -> bool>>,
    /// If set and all nodes become idle, advances the time by this amount (in seconds) and polls
    /// again one more time.
    pub extra_advance: Option<u64>,
    /// If true and all nodes become idle, advances the time by the amount it takes for joining
    /// nodes to timeout and polls again one more time.
    pub fire_join_timeout: bool,
}

impl Default for PollOptions {
    fn default() -> Self {
        Self {
            continue_predicate: None,
            extra_advance: None,
            fire_join_timeout: true,
        }
    }
}

impl PollOptions {
    pub fn continue_if<F>(self, pred: F) -> Self
    where
        F: Fn(&[TestNode]) -> bool + 'static,
    {
        Self {
            continue_predicate: Some(Box::new(pred)),
            ..self
        }
    }

    pub fn fire_join_timeout(self, fire_join_timeout: bool) -> Self {
        Self {
            fire_join_timeout,
            ..self
        }
    }
}

/// Polls and processes all events, until there are no unacknowledged messages left.
pub fn poll_and_resend_with_options(nodes: &mut [TestNode], mut options: PollOptions) {
    let node_busy = |node: &TestNode| {
        if node.inner.has_unpolled_observations() {
            trace!("{} busy!", node.inner);
            true
        } else {
            false
        }
    };
    for _ in 0..MAX_POLL_CALLS {
        if poll_all(nodes) || nodes.iter().any(node_busy) {
            // Advance time for next route/gossip iter.
            FakeClock::advance_time(1001);
            continue;
        }

        if let Some(continue_predicate) = options.continue_predicate.as_ref() {
            if continue_predicate(nodes) {
                continue;
            }
        }

        if let Some(step) = options.extra_advance.take() {
            FakeClock::advance_time(step * 1000 + 1);
            continue;
        }

        if options.fire_join_timeout {
            // When all routes are polled, advance time to purge any pending re-connecting peers.
            FakeClock::advance_time(
                test_consts::BOOTSTRAP_TIMEOUT
                    .max(test_consts::JOIN_TIMEOUT)
                    .as_secs()
                    * 1000
                    + 1,
            );
            options.fire_join_timeout = false;
            continue;
        }

        return;
    }

    for node in nodes.iter().filter(|node| node_busy(node)) {
        let unpolled_string = node.inner.unpolled_observations_string();
        error!("Still busy: {}: {}", node.inner, unpolled_string);
    }

    if let Some(first_node_busy) = nodes.iter().find(|node| node_busy(node)) {
        let unpolled_string = first_node_busy.inner.unpolled_observations_string();
        panic!(
            "poll_and_resend has been called {} times. first busy: {} : {}",
            MAX_POLL_CALLS, first_node_busy.inner, unpolled_string
        );
    }

    panic!(
        "poll_and_resend has been called {} times. No busy nodes",
        MAX_POLL_CALLS
    );
}

/// Checks each of the last `count` members of `nodes` for a `Connected` event, and removes those
/// which don't fire one. Returns the number of removed nodes.
pub fn remove_nodes_which_failed_to_connect(nodes: &mut Vec<TestNode>, count: usize) -> usize {
    let failed_to_join: Vec<_> = nodes
        .iter_mut()
        .enumerate()
        .rev()
        .take(count)
        .filter_map(|(index, ref mut node)| {
            while let Ok(event) = node.try_next_ev() {
                if let Event::Connected = event {
                    return None;
                }
            }
            Some(index)
        })
        .collect();
    let removed_nodes: Vec<_> = failed_to_join
        .iter()
        .map(|index| nodes.remove(*index).name())
        .collect();
    info!("Failed to be Added as Nodes: {:?}", removed_nodes);
    poll_and_resend(nodes);
    failed_to_join.len()
}

/// Options that control adding and removing nodes to the mock network.
#[derive(Default, Copy, Clone)]
pub struct ChurnOptions {
    /// Suppress any relocations that would be caused by adding/removing a node by setting the next
    /// relocation destination of the existing nodes to lie within their current sections.
    pub suppress_relocation: bool,
}

pub fn create_connected_nodes(network: &Network, size: usize) -> Nodes {
    let mut nodes = Vec::new();

    // Create the seed node.
    nodes.push(TestNode::builder(network).first().create());
    let _ = nodes[0].poll();
    let endpoint = nodes[0].endpoint();
    info!("Seed node: {}", nodes[0].inner);

    // Create other nodes using the seed node endpoint as bootstrap contact.
    for _ in 1..size {
        let config = NetworkConfig::node().with_hard_coded_contact(endpoint);
        nodes.push(TestNode::builder(network).network_config(config).create());

        poll_and_resend(&mut nodes);
        verify_invariant_for_all_nodes(&network, &mut nodes);
    }

    let n = cmp::min(nodes.len(), network.elder_size()) - 1;

    for node in &mut nodes {
        expect_next_event!(node, Event::Connected);

        let mut node_added_count = 0;

        while let Ok(event) = node.try_next_ev() {
            match event {
                Event::NodeAdded(..) => node_added_count += 1,
                Event::NodeLost(..)
                | Event::SectionSplit(..)
                | Event::RestartRequired
                | Event::ClientEvent(..)
                | Event::TimerTicked => (),
                event => panic!("Got unexpected event: {:?}", event),
            }
        }

        assert!(
            node_added_count >= n || !node.inner.is_elder(),
            "{} - Got only {} NodeAdded events, expected at least {}.",
            node.inner,
            node_added_count,
            n
        );
    }

    Nodes(nodes)
}

pub fn create_connected_nodes_until_split(network: &Network, prefix_lengths: Vec<usize>) -> Nodes {
    create_connected_nodes_until_split_with_options(
        network,
        prefix_lengths,
        ChurnOptions::default(),
    )
}

pub fn create_connected_nodes_until_split_with_options(
    network: &Network,
    prefix_lengths: Vec<usize>,
    options: ChurnOptions,
) -> Nodes {
    // Start first node.
    let mut nodes = vec![TestNode::builder(network).first().create()];
    let _ = nodes[0].poll();
    expect_next_event!(nodes[0], Event::Connected);

    add_connected_nodes_until_split(network, &mut nodes, prefix_lengths, options);
    Nodes(nodes)
}

// This adds new nodes (all with `use_cache` set to `true`) until the specified disjoint sections
// have formed.
//
// `prefix_lengths` is an array representing the required `bit_count`s of the section prefixes.  For
// example passing [1, 2, 3, 3] could yield a network comprising sections [0, 100, 101, 11], or
// passing [2, 2, 3, 3, 3, 3] could yield [000, 001, 01, 100, 101, 11], while passing [1, 1] will
// always yield sections [0, 1].
//
// The array is sanity checked (e.g. it would be an error to pass [1, 1, 1]), must comprise at
// least two elements, and every element must be no more than `8`.
pub fn add_connected_nodes_until_split(
    network: &Network,
    nodes: &mut Vec<TestNode>,
    mut prefix_lengths: Vec<usize>,
    options: ChurnOptions,
) {
    // Get sorted list of prefixes to suit requested lengths.
    sanity_check(&prefix_lengths);
    prefix_lengths.sort();
    let mut rng = network.new_rng();
    let prefixes = prefixes(&prefix_lengths, &mut rng);

    // Cleanup the previous event queue
    clear_all_event_queues(nodes, |_| {});

    // Start enough new nodes under each target prefix to trigger a split eventually.
    let min_split_size = unwrap!(nodes[0].inner.min_split_size());
    let prefixes_new_count = prefixes
        .iter()
        .map(|prefix| (*prefix, min_split_size))
        .collect_vec();
    add_nodes_to_prefixes(network, nodes, &prefixes_new_count, options);

    // If recursive splits are added to Routing (https://maidsafe.atlassian.net/browse/MAID-1861)
    // this next step can be removed.
    // Find and add nodes to sections which still need to split to trigger this.
    loop {
        let mut found_prefix = None;
        for node in nodes.iter() {
            if let Some(prefix_to_split) = node
                .inner
                .prefixes()
                .iter()
                .find(|&prefix| !prefixes.contains(prefix))
            {
                // Assert that this can be split down to a desired prefix.
                let is_valid = |prefix: &Prefix<XorName>| {
                    if prefix.is_compatible(prefix_to_split) {
                        assert!(
                            prefix.bit_count() > prefix_to_split.bit_count(),
                            "prefix_to_split: {:?}, prefix: {:?}",
                            prefix_to_split,
                            prefix
                        );
                        return true;
                    }
                    false
                };
                assert!(prefixes.iter().any(is_valid));
                found_prefix = Some(*prefix_to_split);
                break;
            }
        }
        if let Some(prefix_to_split) = found_prefix {
            add_node_to_section(network, nodes, &prefix_to_split, options);
        } else {
            break;
        }
    }

    // Gather all the actual prefixes and check they are as expected.
    let mut actual_prefixes = BTreeSet::<Prefix<XorName>>::new();
    for node in nodes.iter() {
        actual_prefixes.append(&mut node.inner.prefixes());
    }
    assert_eq!(
        prefixes.iter().cloned().collect::<BTreeSet<_>>(),
        actual_prefixes
    );
    assert_eq!(
        prefix_lengths,
        prefixes.iter().map(Prefix::bit_count).collect::<Vec<_>>()
    );

    clear_all_event_queues(nodes, |event| match event {
        Event::NodeAdded(..)
        | Event::NodeLost(..)
        | Event::TimerTicked
        | Event::ClientEvent(..)
        | Event::SectionSplit(..) => (),
        event => panic!("Got unexpected event: {:?}", event),
    });
    clear_relocation_overrides(nodes);

    trace!("Created testnet comprising {:?}", prefixes);
}

// Add connected nodes to the given prefixes until adding one extra node in any of the
// returned sub-prefixes would trigger a split in the parent prefix.
pub fn add_connected_nodes_until_one_away_from_split(
    network: &Network,
    nodes: &mut Vec<TestNode>,
    prefixes_to_nearly_split: &[Prefix<XorName>],
    options: ChurnOptions,
) -> Vec<Prefix<XorName>> {
    let (prefixes_and_counts, prefixes_to_add_to_split) =
        prefixes_and_count_to_split_with_only_one_extra_node(nodes, prefixes_to_nearly_split);

    add_connected_nodes_until_sized(network, nodes, &prefixes_and_counts, options);
    prefixes_to_add_to_split
}

// Add connected nodes until reaching the requested size for each prefix. No split expected.
fn add_connected_nodes_until_sized(
    network: &Network,
    nodes: &mut Vec<TestNode>,
    prefixes_new_count: &[PrefixAndSize],
    options: ChurnOptions,
) {
    clear_all_event_queues(nodes, |_| {});

    add_nodes_to_prefixes(network, nodes, prefixes_new_count, options);

    clear_all_event_queues(nodes, |_| {});
    clear_relocation_overrides(nodes);

    trace!(
        "Filled prefixes until ready to split {:?}",
        prefixes_new_count
    );
}

// Start the target number of new nodes under each target prefix.
fn add_nodes_to_prefixes(
    network: &Network,
    nodes: &mut Vec<TestNode>,
    prefixes_new_count: &[PrefixAndSize],
    options: ChurnOptions,
) {
    for (prefix, target_count) in prefixes_new_count {
        let num_in_section = nodes
            .iter()
            .filter(|node| prefix.matches(&node.name()))
            .count();
        // To ensure you don't hit this assert, don't have more than `min_split_size()` entries in
        // `nodes` when calling this function.
        assert!(
            num_in_section <= *target_count,
            "The existing nodes' names disallow creation of the requested prefixes. There \
             are {} nodes which all belong in {:?} which exceeds the limit here of {}.",
            num_in_section,
            prefix,
            target_count
        );
        let to_add_count = target_count - num_in_section;
        for _ in 0..to_add_count {
            add_node_to_section(network, nodes, prefix, options);
        }
    }
}

// Clear all event queues applying check_event to them.
fn clear_all_event_queues(nodes: &mut Vec<TestNode>, check_event: impl Fn(Event)) {
    for node in nodes.iter_mut() {
        while let Ok(event) = node.try_next_ev() {
            check_event(event)
        }
    }
}

// Clear all `next_relocation_dst` / `next_relocation_interval` values.
pub fn clear_relocation_overrides(nodes: &mut Vec<TestNode>) {
    for node in nodes.iter_mut() {
        node.inner.set_next_relocation_dst(None);
        node.inner.set_next_relocation_interval(None);
    }
}

// Returns sub-prefixes target size to reach so we would split with one extra node.
// The second returned field contains the sub-prefixes to add the final node to trigger the splits.
fn prefixes_and_count_to_split_with_only_one_extra_node(
    nodes: &[TestNode],
    prefixes: &[Prefix<XorName>],
) -> (Vec<PrefixAndSize>, Vec<Prefix<XorName>>) {
    let prefixes_to_add_to_split = prefixes
        .iter()
        .map(|prefix| prefix_half_with_fewer_nodes(nodes, prefix))
        .collect_vec();

    let min_split_size = unwrap!(nodes[0].inner.min_split_size());

    let mut prefixes_and_counts = Vec::new();
    for small_prefix in &prefixes_to_add_to_split {
        prefixes_and_counts.push((*small_prefix, min_split_size - 1));
        prefixes_and_counts.push((small_prefix.sibling(), min_split_size));
    }

    (prefixes_and_counts, prefixes_to_add_to_split)
}

// Return the sub-prefix with fewer nodes.
fn prefix_half_with_fewer_nodes(nodes: &[TestNode], prefix: &Prefix<XorName>) -> Prefix<XorName> {
    let sub_prefixes = [prefix.pushed(false), prefix.pushed(true)];

    let smaller_prefix = sub_prefixes.iter().min_by_key(|prefix| {
        nodes
            .iter()
            .filter(|node| prefix.matches(&node.name()))
            .count()
    });
    *unwrap!(smaller_prefix)
}

// -----  Small misc functions  -----

/// Sorts the given nodes by their distance to `name`. Note that this will call the `name()`
/// function on them which causes polling, so it calls `poll_all` to make sure that all other
/// events have been processed before sorting.
pub fn sort_nodes_by_distance_to(nodes: &mut [TestNode], name: &XorName) {
    let _ = poll_all(nodes); // Poll
    nodes.sort_by(|node0, node1| name.cmp_distance(&node0.name(), &node1.name()));
}

/// Iterator over all nodes that belong to the given prefix.
pub fn nodes_with_prefix<'a>(
    nodes: &'a [TestNode],
    prefix: &'a Prefix<XorName>,
) -> impl Iterator<Item = &'a TestNode> {
    nodes
        .iter()
        .filter(move |node| prefix.matches(&node.name()))
}

/// Mutable iterator over all nodes that belong to the given prefix.
pub fn nodes_with_prefix_mut<'a>(
    nodes: &'a mut [TestNode],
    prefix: &'a Prefix<XorName>,
) -> impl Iterator<Item = &'a mut TestNode> {
    nodes
        .iter_mut()
        .filter(move |node| prefix.matches(&node.name()))
}

pub fn verify_section_invariants_for_node(node: &TestNode, elder_size: usize) {
    let our_prefix = match node.inner.our_prefix() {
        Some(pfx) => pfx,
        None => {
            return;
        }
    };
    let our_name = node.name();
    let our_section_elders = node.inner.section_elders(our_prefix);

    assert!(
        our_prefix.matches(&our_name),
        "{} Our prefix doesn't match our name: {:?}, {:?}",
        node.inner,
        our_prefix,
        our_name,
    );

    if !our_prefix.is_empty() {
        assert!(
            our_section_elders.len() >= elder_size,
            "{} Our section {:?} is below the minimum size!",
            node.inner,
            our_prefix,
        );
    }

    if let Some(name) = our_section_elders
        .iter()
        .find(|name| !our_prefix.matches(name))
    {
        panic!(
            "{} A name in our section doesn't match its prefix! {:?}, {:?}",
            node.inner, name, our_prefix,
        );
    }

    let neighbour_prefixes = node.inner.neighbour_prefixes();

    if let Some(compatible_prefix) = neighbour_prefixes
        .iter()
        .find(|prefix| prefix.is_compatible(our_prefix))
    {
        panic!(
            "{} Our prefix is compatible with one of the neighbour prefixes:\
             us: {:?} / neighbour: {:?}, neighbour_prefixes: {:?}",
            node.inner, our_prefix, compatible_prefix, neighbour_prefixes,
        );
    }

    if let Some(prefix) = neighbour_prefixes
        .iter()
        .find(|prefix| node.inner.section_elders(prefix).len() < elder_size)
    {
        panic!(
            "{} A section is below the minimum size: size({:?}) = {}; For ({:?}: {:?}), neighbour_prefixes: {:?}",
            node.inner,
            prefix,
            node.inner.section_elders(prefix).len(),
            our_name,
            our_prefix,
            neighbour_prefixes,
        );
    }

    for prefix in &neighbour_prefixes {
        if let Some(name) = node
            .inner
            .section_elders(prefix)
            .iter()
            .find(|name| !prefix.matches(name))
        {
            panic!(
                "{} A name in a section doesn't match its prefix! {:?}, {:?}",
                node.inner, name, prefix,
            );
        }
    }

    let all_are_neighbours = node
        .inner
        .neighbour_prefixes()
        .iter()
        .all(|prefix| our_prefix.is_neighbour(prefix));
    let all_neighbours_covered = {
        (0..our_prefix.bit_count()).all(|i| {
            our_prefix
                .with_flipped_bit(i)
                .is_covered_by(&neighbour_prefixes)
        })
    };
    if !all_are_neighbours {
        panic!(
            "{} Some sections in the chain aren't neighbours of our section: {:?}",
            node.inner,
            iter::once(*our_prefix)
                .chain(neighbour_prefixes)
                .collect::<Vec<_>>()
        );
    }
    if !all_neighbours_covered {
        panic!(
            "{} Some neighbours aren't fully covered by the chain: {:?}",
            node.inner,
            iter::once(*our_prefix)
                .chain(neighbour_prefixes)
                .collect::<Vec<_>>()
        );
    }
}

pub fn verify_section_invariants_for_nodes(nodes: &[TestNode], elder_size: usize) {
    for node in nodes.iter() {
        verify_section_invariants_for_node(node, elder_size);
    }
}

pub fn verify_section_invariants_between_nodes(nodes: &[TestNode]) {
    #[derive(Debug)]
    struct NodeSectionInfo {
        node_name: XorName,
        node_prefix: Prefix<XorName>,
        view_section_version: u64,
        view_section_elders: BTreeSet<XorName>,
    };
    let mut sections: BTreeMap<Prefix<XorName>, NodeSectionInfo> = BTreeMap::new();

    for node in nodes.iter().filter(|node| node.inner.is_elder()) {
        let our_prefix = match node.inner.our_prefix() {
            Some(pfx) => pfx,
            None => continue,
        };
        let our_name = node.name();
        // NOTE: using neighbour_prefixes() here and not neighbour_infos().prefix().
        // Is this a problem?
        for prefix in iter::once(our_prefix).chain(node.inner.neighbour_prefixes().iter()) {
            let our_info = NodeSectionInfo {
                node_name: our_name,
                node_prefix: *our_prefix,
                view_section_version: node.inner.section_elder_info_version(prefix),
                view_section_elders: node.inner.section_elders(prefix),
            };

            if let Some(ref their_info) = sections.get(prefix) {
                assert_eq!(
                    (
                        &our_info.view_section_elders,
                        &our_info.view_section_version
                    ),
                    (
                        &their_info.view_section_elders,
                        &their_info.view_section_version
                    ),
                    "Section with prefix {:?} doesn't agree between nodes {:?} and {:?}\n\
                     {:?},\n{:?}",
                    prefix,
                    our_info.node_name,
                    their_info.node_name,
                    our_info,
                    their_info,
                );
                continue;
            }
            let _ = sections.insert(*prefix, our_info);
        }
    }

    // check that prefixes are disjoint
    for prefix1 in sections.keys() {
        for prefix2 in sections.keys() {
            if prefix1 == prefix2 {
                continue;
            }
            if prefix1.is_compatible(prefix2) {
                panic!(
                    "Section prefixes should be disjoint, but these are not:\n\
                     Section {:?}, according to node {:?}: {:?}\n\
                     Section {:?}, according to node {:?}: {:?}",
                    prefix1,
                    sections[prefix1].node_name,
                    sections[prefix1].node_prefix,
                    prefix2,
                    sections[prefix2].node_name,
                    sections[prefix2].node_prefix,
                );
            }
        }
    }

    // check that each section contains names agreeing with its prefix
    for (prefix, ref info) in &sections {
        for name in &info.view_section_elders {
            if !prefix.matches(name) {
                panic!(
                    "Section members should match the prefix, but {:?} \
                     does not match {:?}",
                    name, prefix
                );
            }
        }
    }

    // check that sections cover the whole namespace
    assert!(Prefix::default().is_covered_by(sections.keys()));
}

pub fn verify_invariant_for_all_nodes(network: &Network, nodes: &mut [TestNode]) {
    let elder_size = network.elder_size();
    verify_section_invariants_for_nodes(nodes, elder_size);
    verify_section_invariants_between_nodes(nodes);

    let mut all_missing_peers = BTreeSet::<PublicId>::new();
    for node in nodes.iter_mut().filter(|node| node.inner.is_elder()) {
        // Confirm elders from chain are connected according to PeerMap
        let our_id = unwrap!(node.inner.id());
        let missing_peers = node
            .inner
            .elder_nodes()
            .filter(|p2p_node| p2p_node.public_id() != &our_id)
            .filter(|p2p_node| !node.inner.is_connected(p2p_node.peer_addr()))
            .map(|p2p_node| p2p_node.public_id())
            .cloned()
            .collect_vec();
        if !missing_peers.is_empty() {
            error!(
                "verify_invariant_for_all_nodes: node {}: missing: {:?}",
                our_id, &missing_peers
            );
            all_missing_peers.extend(missing_peers);
        }
    }

    assert!(
        all_missing_peers.is_empty(),
        "verify_invariant_for_all_nodes - all_missing_peers: {:?}",
        all_missing_peers
    );
}

// Generate a vector of random bytes of the given length.
pub fn gen_bytes<R: Rng>(rng: &mut R, size: usize) -> Vec<u8> {
    rng.gen_iter().take(size).collect()
}

fn sanity_check(prefix_lengths: &[usize]) {
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
    if sum < 256 {
        panic!(
            "The specified prefix lengths {:?} would not cover the entire address space",
            prefix_lengths
        );
    } else if sum > 256 {
        panic!(
            "The specified prefix lengths {:?} would require overlapping sections",
            prefix_lengths
        );
    }
}

fn prefixes<T: Rng>(prefix_lengths: &[usize], rng: &mut T) -> Vec<Prefix<XorName>> {
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

fn add_node_to_section(
    network: &Network,
    nodes: &mut Vec<TestNode>,
    prefix: &Prefix<XorName>,
    options: ChurnOptions,
) {
    let mut rng = network.new_rng();
    let config = NetworkConfig::node().with_hard_coded_contact(nodes[0].endpoint());
    let full_id = FullId::within_range(&mut rng, &prefix.range_inclusive());
    nodes.push(
        TestNode::builder(network)
            .network_config(config)
            .full_id(full_id)
            .create(),
    );

    if options.suppress_relocation {
        // Send all relocations to the same section, effectively disabling them.
        let dst = prefix.name();
        for node in nodes_with_prefix_mut(nodes, prefix) {
            node.inner.set_next_relocation_dst(Some(dst));
        }
    }

    // Poll until the new node transitions to the `Elder` state.
    let elder_size = network.elder_size();
    poll_and_resend_with_options(
        nodes,
        PollOptions::default()
            .continue_if(move |nodes| {
                nodes.len() >= elder_size
                    && nodes.iter().filter(|node| node.inner.is_elder()).count() < elder_size
            })
            .fire_join_timeout(false),
    );
    expect_any_event!(unwrap!(nodes.last_mut()), Event::Connected);
    assert!(
        prefix.matches(&nodes[nodes.len() - 1].name()),
        "Prefix {:?} doesn't match the name {}!",
        prefix,
        nodes[nodes.len() - 1].name()
    );
}

mod tests {
    use super::sanity_check;

    #[test]
    fn sanity_check_valid() {
        sanity_check(&[1, 1]);
        sanity_check(&[1, 2, 3, 4, 5, 6, 7, 8, 8]);
        sanity_check(&[8; 256]);
    }

    #[test]
    #[should_panic(expected = "There should be at least two specified prefix lengths")]
    fn sanity_check_no_split() {
        sanity_check(&[0]);
    }

    #[test]
    #[should_panic(expected = "would require overlapping sections")]
    fn sanity_check_overlapping_sections() {
        sanity_check(&[1, 2, 2, 2]);
    }

    #[test]
    #[should_panic(expected = "would not cover the entire address space")]
    fn sanity_check_missing_sections() {
        sanity_check(&[1, 2]);
    }

    #[test]
    #[should_panic(expected = "must each be no more than 8")]
    fn sanity_check_too_many_sections() {
        sanity_check(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 9]);
    }
}
