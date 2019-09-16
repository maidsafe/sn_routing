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
    mock::Network, test_consts::CONNECTING_PEER_TIMEOUT_SECS, verify_chain_invariant, Authority,
    Chain, Config, DevConfig, Event, EventStream, FullId,
    NetworkConfig, Node, Prefix, PublicId, Request, Response, XorName,
    XorTargetInterval, Xorable,
};
use std::{
    cell::RefCell,
    cmp,
    collections::{BTreeSet, HashMap},
    iter,
    net::SocketAddr,
    ops::{Deref, DerefMut},
    time::Duration,
};

// Poll one event per node. Otherwise, all events in a single node are polled before moving on.
const BALANCED_POLLING: bool = true;

// Maximum number of times to try and poll in a loop.  This is several orders higher than the
// anticipated upper limit for any test, and if hit is likely to indicate an infinite loop.
const MAX_POLL_CALLS: usize = 1000;

// Duration clients expect a response by.
const CLIENT_MSG_EXPIRY_DUR_SECS: u64 = 90;

// ----- Typs -----
type PrefixAndSize = (Prefix<XorName>, usize);

/// test dummy data
pub struct ImmutableData  {
    pub content : Vec<u8>,
}
impl ImmutableData {
pub fn new<R: Rng>(rng: &mut R, size: usize) -> ImmutableData {
    let content = rng.gen_iter().take(size).collect();
        ImmutableData {
            content: content,
        }
    }
    pub fn name(&self) -> Vec<u8> {
        self.content()
    }
}


// -----  Random number generation  -----

pub fn gen_range<T: Rng>(rng: &mut T, low: usize, high: usize) -> usize {
    rng.gen_range(low as u32, high as u32) as usize
}

/// Generate a random value in the range, excluding the `exclude` value, if not `None`.
pub fn gen_range_except<T: Rng>(
    rng: &mut T,
    low: usize,
    high: usize,
    exclude: &BTreeSet<usize>,
) -> usize {
    let mut x = gen_range(rng, low, high - exclude.len());
    for e in exclude {
        if x >= *e {
            x += 1;
        }
    }
    x
}

fn create_config(network: &Network) -> Config {
    Config {
        dev: Some(DevConfig {
            min_section_size: Some(network.min_section_size()),
            ..DevConfig::default()
        }),
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
    endpoint: SocketAddr,
}

impl TestNode {
    pub fn builder(network: &Network) -> TestNodeBuilder {
        TestNodeBuilder {
            network: network,
            first_node: false,
            network_config: None,
            endpoint: None,
        }
    }

    pub fn new(
        network: &Network,
        first_node: bool,
        network_config: Option<NetworkConfig>,
        endpoint: Option<SocketAddr>,
    ) -> Self {
        let endpoint = endpoint.unwrap_or_else(|| network.gen_addr());
        network.set_next_addr(endpoint);

        let config = create_config(network);
        let builder = Node::builder()
            .first(first_node)
            .config(config);
        let builder = if let Some(network_config) = network_config {
            builder.network_config(network_config)
        } else {
            builder
        };
        let node = unwrap!(builder.create());

        TestNode {
            inner: node,
            network: network.clone(),
            endpoint,
        }
    }

    pub fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }

    pub fn id(&self) -> PublicId {
        unwrap!(self.inner.id())
    }

    pub fn name(&self) -> XorName {
        *self.id().name()
    }

    pub fn close_names(&self) -> Vec<XorName> {
        unwrap!(unwrap!(self.inner.chain()).close_names(&self.name()))
    }

    pub fn our_prefix(&self) -> &Prefix<XorName> {
        self.chain().our_prefix()
    }

    pub fn chain(&self) -> &Chain {
        unwrap!(self.inner.chain(), "no chain for {}", self.inner)
    }

    pub fn is_recipient(&self, dst: &Authority<XorName>) -> bool {
        self.inner.in_authority(dst)
    }

    pub fn network(&self) -> &Network {
        &self.network
    }
}

pub fn count_sections(nodes: &[TestNode]) -> usize {
    nodes
        .iter()
        .filter_map(|n| n.inner.chain())
        .flat_map(Chain::prefixes)
        .unique()
        .count()
}

pub fn current_sections(nodes: &[TestNode]) -> BTreeSet<Prefix<XorName>> {
    nodes
        .iter()
        .filter_map(|n| n.inner.chain())
        .flat_map(Chain::prefixes)
        .collect()
}

pub struct TestNodeBuilder<'a> {
    network: &'a Network,
    first_node: bool,
    network_config: Option<NetworkConfig>,
    endpoint: Option<SocketAddr>,
}

impl<'a> TestNodeBuilder<'a> {
    pub fn first(mut self) -> Self {
        self.first_node = true;
        self
    }

    pub fn network_config(mut self, config: NetworkConfig) -> Self {
        self.network_config = Some(config);
        self
    }

    pub fn endpoint(mut self, endpoint: SocketAddr) -> Self {
        self.endpoint = Some(endpoint);
        self
    }

    pub fn create(self) -> TestNode {
        TestNode::new(
            self.network,
            self.first_node,
            self.network_config,
            self.endpoint,
            self.cache,
        )
    }
}

// -----  TestClient  -----

pub struct TestClient {
    pub inner: Client,
    pub full_id: FullId,
}

impl TestClient {
    pub fn new(
        network: &Network,
        network_config: Option<NetworkConfig>,
        endpoint: Option<SocketAddr>,
    ) -> Self {
        let full_id = FullId::new();
        Self::new_with_full_id(network, network_config, endpoint, full_id)
    }

    pub fn new_with_full_id(
        network: &Network,
        network_config: Option<NetworkConfig>,
        endpoint: Option<SocketAddr>,
        full_id: FullId,
    ) -> Self {
        let duration = Duration::from_secs(CLIENT_MSG_EXPIRY_DUR_SECS);
        Self::new_impl(network, network_config, endpoint, full_id, duration)
    }

    // fn new_impl(
    //     network: &Network,
    //     network_config: Option<NetworkConfig>,
    //     endpoint: Option<SocketAddr>,
    //     full_id: FullId,
    //     duration: Duration,
    // ) -> Self {
    //     let endpoint = endpoint.unwrap_or_else(|| network.gen_addr());
    //     network.set_next_addr(endpoint);
    //
    //     let client = unwrap!(Client::new(
    //         Some(full_id.clone()),
    //         network_config,
    //         create_config(network),
    //         duration,
    //     ));
    //
    //     TestClient {
    //         inner: client,
    //         full_id: full_id,
    //     }
    // }
    //
    pub fn name(&self) -> XorName {
        *unwrap!(self.inner.id()).name()
    }
}


// -----  poll_all, create_connected_...  -----

/// Process all events. Returns whether there were any events.
pub fn poll_all(nodes: &mut [TestNode], clients: &mut [TestClient]) -> bool {
    let dummy = |_nodes: &[TestNode]| false;
    poll_all_until(nodes, clients, &dummy)
}

/// Process all events. Returns whether there were any events.
/// should_stop: can be used for an early return from poll_all
pub fn poll_all_until(
    nodes: &mut [TestNode],
    clients: &mut [TestClient],
    should_stop: &dyn Fn(&[TestNode]) -> bool,
) -> bool {
    assert!(!nodes.is_empty());
    let network = nodes[0].network().clone();
    let mut result = false;
    for _ in 0..MAX_POLL_CALLS {
        if should_stop(nodes) {
            return result;
        }

        let mut handled_message = false;
        network.poll();
        if BALANCED_POLLING {
            // handle all current messages for each node in turn, then repeat (via outer loop):
            nodes
                .iter_mut()
                .for_each(|node| handled_message = node.poll() || handled_message);
        } else {
            handled_message = nodes.iter_mut().any(TestNode::poll);
        }
        handled_message = clients.iter_mut().any(|c| c.inner.poll()) || handled_message;

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
pub fn poll_and_resend(nodes: &mut [TestNode], clients: &mut [TestClient]) {
    let dummy = |_nodes: &[TestNode]| false;
    poll_and_resend_until(nodes, clients, &dummy, None)
}

/// Polls and processes all events, until there are no unacknowledged messages left.
/// should_stop: can be used for an early return from poll_and_resend
/// extra_advance: this is so far only used for the ignoring candidate_info test.
pub fn poll_and_resend_until(
    nodes: &mut [TestNode],
    clients: &mut [TestClient],
    should_stop: &dyn Fn(&[TestNode]) -> bool,
    mut extra_advance: Option<u64>,
) {
    let mut fired_connecting_peer_timeout = false;
    for _ in 0..MAX_POLL_CALLS {
        if should_stop(nodes) {
            return;
        }

        let node_busy = |node: &TestNode| node.inner.has_unpolled_observations();
        if poll_all_until(nodes, clients, should_stop) || nodes.iter().any(node_busy) {
            // Advance time for next route/gossip iter.
            FakeClock::advance_time(1001);
        } else if let Some(step) = extra_advance {
            FakeClock::advance_time(step * 1000 + 1);
            extra_advance = None;
        } else if !fired_connecting_peer_timeout {
            // When all routes are polled, advance time to purge any pending re-connecting peers.
            FakeClock::advance_time(CONNECTING_PEER_TIMEOUT_SECS * 1000 + 1);
            fired_connecting_peer_timeout = true;
        } else {
            return;
        }
    }
    panic!("poll_and_resend has been called {} times.", MAX_POLL_CALLS);
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
    for index in &failed_to_join {
        let _ = nodes.remove(*index);
    }
    poll_and_resend(nodes, &mut []);
    failed_to_join.len()
}

pub fn create_connected_nodes(network: &Network, size: usize) -> Nodes {
    create_connected_nodes_with_cache(network, size, false)
}

pub fn create_connected_nodes_with_cache(network: &Network, size: usize, use_cache: bool) -> Nodes {
    let mut nodes = Vec::new();

    // Create the seed node.
    let endpoint = network.gen_addr();
    nodes.push(
        TestNode::builder(network)
            .first()
            .endpoint(endpoint)
            .cache(use_cache)
            .create(),
    );
    let _ = nodes[0].poll();
    info!("Seed node: {}", nodes[0].inner);

    // Create other nodes using the seed node endpoint as bootstrap contact.
    for _ in 1..size {
        let config = NetworkConfig::node().with_hard_coded_contact(endpoint);
        nodes.push(
            TestNode::builder(network)
                .network_config(config)
                .cache(use_cache)
                .create(),
        );

        poll_and_resend(&mut nodes, &mut []);
        verify_invariant_for_all_nodes(&network, &mut nodes);
    }

    let n = cmp::min(nodes.len(), network.min_section_size()) - 1;

    for node in &mut nodes {
        expect_next_event!(node, Event::Connected);

        let mut node_added_count = 0;

        while let Ok(event) = node.try_next_ev() {
            match event {
                Event::NodeAdded(..) => node_added_count += 1,
                Event::NodeLost(..)
                | Event::SectionSplit(..)
                | Event::RestartRequired
                | Event::TimerTicked => (),
                event => panic!("Got unexpected event: {:?}", event),
            }
        }

        assert!(
            node_added_count >= n,
            "Got only {} NodeAdded events.",
            node_added_count
        );
    }

    Nodes(nodes)
}

pub fn create_connected_nodes_until_split(
    network: &Network,
    prefix_lengths: Vec<usize>,
    use_cache: bool,
) -> Nodes {
    // Start first node.
    let mut nodes = vec![TestNode::builder(network).first().cache(use_cache).create()];
    let _ = nodes[0].poll();
    expect_next_event!(nodes[0], Event::Connected);

    add_connected_nodes_until_split(network, &mut nodes, prefix_lengths, use_cache);
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
    use_cache: bool,
) {
    // Get sorted list of prefixes to suit requested lengths.
    sanity_check(&prefix_lengths);
    prefix_lengths.sort();
    let mut rng = network.new_rng();
    let prefixes = prefixes(&prefix_lengths, &mut rng);

    // Cleanup the previous event queue
    clear_all_event_queues(nodes, |_| {});

    // Start enough new nodes under each target prefix to trigger a split eventually.
    let min_split_size = nodes[0].chain().min_split_size();
    let prefixes_new_count = prefixes
        .iter()
        .map(|prefix| (*prefix, min_split_size))
        .collect_vec();
    add_nodes_to_prefixes(network, nodes, &prefixes_new_count, use_cache);

    // If recursive splits are added to Routing (https://maidsafe.atlassian.net/browse/MAID-1861)
    // this next step can be removed.
    // Find and add nodes to sections which still need to split to trigger this.
    loop {
        let mut found_prefix = None;
        for node in nodes.iter() {
            if let Some(prefix_to_split) = unwrap!(node.inner.chain())
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
            add_node_to_section(network, nodes, &prefix_to_split, &mut rng, use_cache);
        } else {
            break;
        }
    }

    // Gather all the actual prefixes and check they are as expected.
    let mut actual_prefixes = BTreeSet::<Prefix<XorName>>::new();
    for node in nodes.iter() {
        actual_prefixes.append(&mut unwrap!(node.inner.chain()).prefixes());
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
    use_cache: bool,
) -> Vec<Prefix<XorName>> {
    let (prefixes_and_counts, prefixes_to_add_to_split) =
        prefixes_and_count_to_split_with_only_one_extra_node(nodes, prefixes_to_nearly_split);

    add_connected_nodes_until_sized(network, nodes, &prefixes_and_counts, use_cache);
    prefixes_to_add_to_split
}

// Add connected nodes until reaching the requested size for each prefix. No split expected.
fn add_connected_nodes_until_sized(
    network: &Network,
    nodes: &mut Vec<TestNode>,
    prefixes_new_count: &[PrefixAndSize],
    use_cache: bool,
) {
    clear_all_event_queues(nodes, |_| {});

    add_nodes_to_prefixes(network, nodes, prefixes_new_count, use_cache);

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
    use_cache: bool,
) {
    let mut rng = network.new_rng();

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
            add_node_to_section(network, nodes, prefix, &mut rng, use_cache);
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

    let min_split_size = nodes[0].chain().min_split_size();

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

// Create `size` clients, all of whom are connected to `nodes[0]`.
pub fn create_connected_clients(
    network: &Network,
    nodes: &mut [TestNode],
    size: usize,
) -> Vec<TestClient> {
    let contact = nodes[0].endpoint();
    let mut clients = Vec::with_capacity(size);

    for _ in 0..size {
        let config = NetworkConfig::client().with_hard_coded_contact(contact);
        let client = TestClient::new(network, Some(config), None);
        clients.push(client);

        let _ = poll_all(nodes, &mut clients);
        expect_next_event!(unwrap!(clients.last_mut()), Event::Connected);
    }

    clients
}

// -----  Small misc functions  -----

/// Sorts the given nodes by their distance to `name`. Note that this will call the `name()`
/// function on them which causes polling, so it calls `poll_all` to make sure that all other
/// events have been processed before sorting.
pub fn sort_nodes_by_distance_to(nodes: &mut [TestNode], name: &XorName) {
    let _ = poll_all(nodes, &mut []); // Poll
    nodes.sort_by(|node0, node1| name.cmp_distance(&node0.name(), &node1.name()));
}

pub fn verify_invariant_for_all_nodes(network: &Network, nodes: &mut [TestNode]) {
    let min_section_size = network.min_section_size();
    verify_chain_invariant(nodes.iter().map(TestNode::chain), min_section_size);

    let mut all_missing_peers = BTreeSet::<PublicId>::new();
    for node in nodes.iter_mut() {
        // Confirm valid peers from chain are connected according to PeerMgr
        let mut peers = node.chain().valid_peers();
        let our_id = node.chain().our_id();
        let _ = peers.remove(&our_id);
        let missing_peers = peers
            .iter()
            .filter(|pub_id| !node.inner.is_node_peer(pub_id))
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

// Generate random immutable data with the given payload length.
pub fn gen_immutable_data<R: Rng>(rng: &mut R, size: usize) -> ImmutableData {
    ImmutableData::new(rng, size)
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

fn add_node_to_section<T: Rng>(
    network: &Network,
    nodes: &mut Vec<TestNode>,
    prefix: &Prefix<XorName>,
    rng: &mut T,
    use_cache: bool,
) {
    let relocation_name = prefix.substituted_in(rng.gen());
    nodes.iter_mut().for_each(|node| {
        node.inner.set_next_relocation_dst(Some(relocation_name));
        node.inner
            .set_next_relocation_interval(Some(XorTargetInterval::new(prefix.range_inclusive())));
    });

    let config = NetworkConfig::node().with_hard_coded_contacts(iter::once(nodes[0].endpoint()));
    nodes.push(
        TestNode::builder(network)
            .network_config(config)
            .cache(use_cache)
            .create(),
    );
    poll_and_resend(nodes, &mut []);
    expect_any_event!(unwrap!(nodes.last_mut()), Event::Connected);
    assert!(prefix.matches(&nodes[nodes.len() - 1].name()));
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
