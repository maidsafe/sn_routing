// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use fake_clock::FakeClock;
use itertools::Itertools;
use rand::Rng;
use routing::mock_crust::{self, Endpoint, Network, ServiceHandle};
use routing::test_consts::CONNECTING_PEER_TIMEOUT_SECS;
use routing::{verify_chain_invariant, Chain};
use routing::{
    Authority, BootstrapConfig, Cache, Client, Config, DevConfig, Event, EventStream, FullId,
    ImmutableData, Node, NullCache, Prefix, PublicId, Request, Response, XorName, Xorable,
};
use std::cell::RefCell;
use std::cmp;
use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::ops::{Deref, DerefMut};
use std::sync::mpsc::{RecvError, TryRecvError};
use std::time::Duration;

// Poll one event per node. Otherwise, all events in a single node are polled before moving on.
const BALANCED_POLLING: bool = true;

// Maximum number of times to try and poll in a loop.  This is several orders higher than the
// anticipated upper limit for any test, and if hit is likely to indicate an infinite loop.
const MAX_POLL_CALLS: usize = 1000;

// Duration clients expect a response by.
const CLIENT_MSG_EXPIRY_DUR_SECS: u64 = 90;

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

fn create_config(network: &Network<PublicId>) -> Config {
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

    fn next_ev(&mut self) -> Result<Event, RecvError> {
        self.inner.next_ev()
    }

    fn try_next_ev(&mut self) -> Result<Event, TryRecvError> {
        self.inner.try_next_ev()
    }

    fn poll(&mut self) -> bool {
        self.inner.poll()
    }
}

pub struct TestNode {
    pub handle: ServiceHandle<PublicId>,
    pub inner: Node,
}

impl TestNode {
    pub fn builder(network: &Network<PublicId>) -> TestNodeBuilder {
        TestNodeBuilder {
            network: network,
            first_node: false,
            bootstrap_config: None,
            endpoint: None,
            cache: Box::new(NullCache),
        }
    }

    pub fn new(
        network: &Network<PublicId>,
        first_node: bool,
        bootstrap_config: Option<BootstrapConfig>,
        endpoint: Option<Endpoint>,
        cache: Box<Cache>,
    ) -> Self {
        let handle = network.new_service_handle(bootstrap_config, endpoint);
        let config = create_config(network);
        let node = mock_crust::make_current(&handle, || {
            unwrap!(Node::builder()
                .cache(cache)
                .first(first_node)
                .config(config)
                .create())
        });

        TestNode {
            handle: handle,
            inner: node,
        }
    }

    pub fn id(&self) -> PublicId {
        unwrap!(self.inner.id())
    }

    pub fn name(&self) -> XorName {
        *self.id().name()
    }

    pub fn close_names(&self) -> BTreeSet<XorName> {
        unwrap!(unwrap!(self.inner.chain()).close_names(&self.name()))
    }

    pub fn our_prefix(&self) -> &Prefix<XorName> {
        self.chain().our_prefix()
    }

    pub fn chain(&self) -> &Chain {
        unwrap!(self.inner.chain())
    }

    pub fn is_recipient(&self, dst: &Authority<XorName>) -> bool {
        self.inner.in_authority(dst)
    }
}

pub fn count_sections(nodes: &[TestNode]) -> usize {
    nodes
        .iter()
        .filter_map(|n| n.inner.chain().ok())
        .flat_map(|chain| chain.prefixes())
        .unique()
        .count()
}

pub fn current_sections(nodes: &[TestNode]) -> BTreeSet<Prefix<XorName>> {
    nodes
        .iter()
        .filter_map(|n| n.inner.chain().ok())
        .flat_map(|chain| chain.prefixes())
        .collect()
}

pub struct TestNodeBuilder<'a> {
    network: &'a Network<PublicId>,
    first_node: bool,
    bootstrap_config: Option<BootstrapConfig>,
    endpoint: Option<Endpoint>,
    cache: Box<Cache>,
}

impl<'a> TestNodeBuilder<'a> {
    pub fn first(mut self) -> Self {
        self.first_node = true;
        self
    }

    pub fn bootstrap_config(mut self, bootstrap_config: BootstrapConfig) -> Self {
        self.bootstrap_config = Some(bootstrap_config);
        self
    }

    pub fn endpoint(mut self, endpoint: Endpoint) -> Self {
        self.endpoint = Some(endpoint);
        self
    }

    pub fn cache(mut self, use_cache: bool) -> Self {
        self.cache = if use_cache {
            Box::new(TestCache::new())
        } else {
            Box::new(NullCache)
        };

        self
    }

    pub fn create(self) -> TestNode {
        TestNode::new(
            self.network,
            self.first_node,
            self.bootstrap_config,
            self.endpoint,
            self.cache,
        )
    }
}

// -----  TestClient  -----

pub struct TestClient {
    pub handle: ServiceHandle<PublicId>,
    pub inner: Client,
    pub full_id: FullId,
}

impl TestClient {
    pub fn new(
        network: &Network<PublicId>,
        bootstrap_config: Option<BootstrapConfig>,
        endpoint: Option<Endpoint>,
    ) -> Self {
        let full_id = FullId::new();
        Self::new_with_full_id(network, bootstrap_config, endpoint, full_id)
    }

    pub fn new_with_full_id(
        network: &Network<PublicId>,
        bootstrap_config: Option<BootstrapConfig>,
        endpoint: Option<Endpoint>,
        full_id: FullId,
    ) -> Self {
        let duration = Duration::from_secs(CLIENT_MSG_EXPIRY_DUR_SECS);
        Self::new_impl(network, bootstrap_config, endpoint, full_id, duration)
    }

    pub fn new_with_expire_duration(
        network: &Network<PublicId>,
        bootstrap_config: Option<BootstrapConfig>,
        endpoint: Option<Endpoint>,
        duration: Duration,
    ) -> Self {
        let full_id = FullId::new();
        Self::new_impl(network, bootstrap_config, endpoint, full_id, duration)
    }

    fn new_impl(
        network: &Network<PublicId>,
        bootstrap_config: Option<BootstrapConfig>,
        endpoint: Option<Endpoint>,
        full_id: FullId,
        duration: Duration,
    ) -> Self {
        let handle = network.new_service_handle(bootstrap_config.clone(), endpoint);
        let client = mock_crust::make_current(&handle, || {
            unwrap!(Client::new(
                Some(full_id.clone()),
                bootstrap_config,
                create_config(network),
                duration,
            ))
        });

        TestClient {
            handle: handle,
            inner: client,
            full_id: full_id,
        }
    }

    pub fn name(&self) -> XorName {
        *unwrap!(self.inner.id()).name()
    }

    pub fn ip(&self) -> IpAddr {
        mock_crust::to_socket_addr(&self.handle.endpoint()).ip()
    }
}

// -----  TestCache  -----

#[derive(Default)]
pub struct TestCache(RefCell<HashMap<XorName, ImmutableData>>);

impl TestCache {
    pub fn new() -> Self {
        TestCache(RefCell::new(HashMap::new()))
    }
}

impl Cache for TestCache {
    fn get(&self, request: &Request) -> Option<Response> {
        if let Request::GetIData { ref name, msg_id } = *request {
            self.0.borrow().get(name).map(|data| Response::GetIData {
                res: Ok(data.clone()),
                msg_id: msg_id,
            })
        } else {
            None
        }
    }

    fn put(&self, response: Response) {
        if let Response::GetIData { res: Ok(data), .. } = response {
            let _ = self.0.borrow_mut().insert(*data.name(), data);
        }
    }
}

// -----  poll_all, create_connected_...  -----

/// Process all events. Returns whether there were any events.
pub fn poll_all(nodes: &mut [TestNode], clients: &mut [TestClient]) -> bool {
    assert!(!nodes.is_empty());
    let mut result = false;
    for _ in 0..MAX_POLL_CALLS {
        let mut handled_message = false;
        nodes[0].handle.deliver_messages();
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
        let any_outgoing_messages = nodes[0].handle.reset_message_sent();
        if !handled_message && !any_outgoing_messages {
            return result;
        }

        result = true;
    }
    panic!("poll_all has been called {} times.", MAX_POLL_CALLS);
}

/// Polls and processes all events, until there are no unacknowledged messages left.
pub fn poll_and_resend(nodes: &mut [TestNode], clients: &mut [TestClient]) {
    let mut fired_connecting_peer_timeout = false;
    for _ in 0..MAX_POLL_CALLS {
        let node_busy = |node: &TestNode| {
            node.inner.has_unconsensused_observations() || node.inner.has_unacked_msg()
        };
        let client_busy = |client: &TestClient| client.inner.has_unacked_msg();
        if poll_all(nodes, clients)
            || nodes.iter().any(node_busy)
            || clients.iter().any(client_busy)
        {
            // Advance time for next route/gossip iter.
            FakeClock::advance_time(1001);
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

pub fn create_connected_nodes(network: &Network<PublicId>, size: usize) -> Nodes {
    create_connected_nodes_with_cache(network, size, false)
}

pub fn create_connected_nodes_with_cache(
    network: &Network<PublicId>,
    size: usize,
    use_cache: bool,
) -> Nodes {
    let mut nodes = Vec::new();

    // Create the seed node.
    nodes.push(
        TestNode::builder(network)
            .first()
            .endpoint(Endpoint(0))
            .cache(use_cache)
            .create(),
    );
    let _ = nodes[0].poll();
    println!("Seed node: {}", nodes[0].inner);

    let bootstrap_config = BootstrapConfig::with_contacts(&[nodes[0].handle.endpoint()]);

    // Create other nodes using the seed node endpoint as bootstrap contact.
    for i in 1..size {
        nodes.push(
            TestNode::builder(network)
                .bootstrap_config(bootstrap_config.clone())
                .endpoint(Endpoint(i))
                .cache(use_cache)
                .create(),
        );

        poll_and_resend(&mut nodes, &mut []);
        verify_invariant_for_all_nodes(&mut nodes);
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
                | Event::Tick => (),
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
    network: &Network<PublicId>,
    prefix_lengths: Vec<usize>,
    use_cache: bool,
) -> Nodes {
    // Start first node.
    let mut nodes = vec![TestNode::builder(network)
        .first()
        .endpoint(Endpoint(0))
        .cache(use_cache)
        .create()];
    let _ = nodes[0].poll();
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
    network: &Network<PublicId>,
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
    for node in nodes.iter_mut() {
        while let Ok(_) = node.try_next_ev() {}
    }

    // Start enough new nodes under each target prefix to trigger a split eventually.
    for prefix in &prefixes {
        let num_in_section = nodes
            .iter()
            .filter(|node| prefix.matches(&node.name()))
            .count();
        // To ensure you don't hit this assert, don't have more than `min_split_size()` entries in
        // `nodes` when calling this function.
        assert!(
            num_in_section <= nodes[0].chain().min_split_size(),
            "The existing nodes' names disallow creation of the requested prefixes. There \
             are {} nodes which all belong in {:?} which exceeds the limit here of {}.",
            num_in_section,
            prefix,
            nodes[0].chain().min_split_size()
        );
        let min_split_size = nodes[0].chain().min_split_size() - num_in_section;
        for _ in 0..min_split_size {
            add_node_to_section(network, nodes, prefix, &mut rng, use_cache);
            if nodes.len() == 2 {
                expect_next_event!(nodes[0], Event::Connected);
            }
        }
    }

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
        prefixes
            .iter()
            .map(|prefix| prefix.bit_count())
            .collect::<Vec<_>>()
    );

    // Clear all event queues and clear the `next_relocation_dst` values.
    for node in nodes.iter_mut() {
        while let Ok(event) = node.try_next_ev() {
            match event {
                Event::NodeAdded(..)
                | Event::NodeLost(..)
                | Event::Tick
                | Event::SectionSplit(..) => (),
                event => panic!("Got unexpected event: {:?}", event),
            }
        }
        node.inner.set_next_relocation_dst(None);
        node.inner.set_next_relocation_interval(None);
    }

    trace!("Created testnet comprising {:?}", prefixes);
}

// Create `size` clients, all of whom are connected to `nodes[0]`.
pub fn create_connected_clients(
    network: &Network<PublicId>,
    nodes: &mut [TestNode],
    size: usize,
) -> Vec<TestClient> {
    let contact = nodes[0].handle.endpoint();
    let mut clients = Vec::with_capacity(size);

    for _ in 0..size {
        let client = TestClient::new(
            network,
            Some(BootstrapConfig::with_contacts(&[contact])),
            None,
        );
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

pub fn verify_invariant_for_all_nodes(nodes: &mut [TestNode]) {
    let min_section_size = nodes[0].handle.0.borrow().network.min_section_size();
    verify_chain_invariant(nodes.iter().map(|n| n.chain()), min_section_size);

    for node in nodes.iter_mut() {
        // Confirm valid peers from chain are connected according to PeerMgr
        for pub_id in node
            .chain()
            .valid_peers(true)
            .iter()
            .filter(|id| **id != node.chain().our_id())
        {
            assert_eq!(true, node.inner.is_routing_peer(pub_id));
        }
    }
}

// Generate a vector of random bytes of the given length.
pub fn gen_bytes<R: Rng>(rng: &mut R, size: usize) -> Vec<u8> {
    rng.gen_iter().take(size).collect()
}

// Generate random immutable data with the given payload length.
pub fn gen_immutable_data<R: Rng>(rng: &mut R, size: usize) -> ImmutableData {
    ImmutableData::new(gen_bytes(rng, size))
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
    network: &Network<PublicId>,
    nodes: &mut Vec<TestNode>,
    prefix: &Prefix<XorName>,
    rng: &mut T,
    use_cache: bool,
) {
    let relocation_name = prefix.substituted_in(rng.gen());
    nodes.iter_mut().for_each(|node| {
        node.inner.set_next_relocation_dst(Some(relocation_name));
        node.inner
            .set_next_relocation_interval(Some((prefix.lower_bound(), prefix.upper_bound())));
    });

    let bootstrap_config = BootstrapConfig::with_contacts(&[nodes[0].handle.endpoint()]);
    let endpoint = Endpoint(nodes.len());
    nodes.push(
        TestNode::builder(network)
            .bootstrap_config(bootstrap_config.clone())
            .endpoint(endpoint)
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
