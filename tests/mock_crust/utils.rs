// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.1.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use itertools::Itertools;
use rand::Rng;
use routing::{Authority, Cache, Client, Data, DataIdentifier, Event, FullId, ImmutableData, Node,
              NullCache, Prefix, Request, Response, RoutingTable, XorName, Xorable,
              verify_network_invariant};
use routing::mock_crust::{self, Config, Endpoint, Network, ServiceHandle};
use std::cell::RefCell;
use std::cmp;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::mpsc;

// Various utilities. Since this is all internal stuff we're a bit lax about the doc.
#[allow(missing_docs)]

// Poll one event per node. Otherwise, all events in a single node are polled before moving on.
const BALANCED_POLLING: bool = true;


// -----  Random number generation  -----

/// Generate a random value in the range, excluding the `exclude` value, if not `None`.
pub fn gen_range_except<T: Rng>(rng: &mut T,
                                low: usize,
                                high: usize,
                                exclude: Option<usize>)
                                -> usize {
    match exclude {
        None => rng.gen_range(low, high),
        Some(exclude) => {
            let mut r = rng.gen_range(low, high - 1);
            if r >= exclude {
                r += 1
            }
            r
        }
    }
}


// -----  TestNode and builder  -----

pub struct TestNode {
    pub handle: ServiceHandle,
    pub inner: Node,
    pub event_rx: mpsc::Receiver<Event>,
}

impl TestNode {
    pub fn builder(network: &Network) -> TestNodeBuilder {
        TestNodeBuilder {
            network: network,
            first_node: false,
            config: None,
            endpoint: None,
            cache: Box::new(NullCache),
        }
    }

    pub fn new(network: &Network,
               first_node: bool,
               config: Option<Config>,
               endpoint: Option<Endpoint>,
               cache: Box<Cache>)
               -> Self {
        let (event_tx, event_rx) = mpsc::channel();
        let handle = network.new_service_handle(config, endpoint);
        let node = mock_crust::make_current(&handle, || {
            unwrap!(Node::builder()
                .cache(cache)
                .first(first_node)
                .create(event_tx, network.min_group_size()))
        });

        TestNode {
            handle: handle,
            inner: node,
            event_rx: event_rx,
        }
    }

    // Poll this node until there are no unprocessed events left.
    pub fn poll(&mut self) -> bool {
        let mut result = false;

        while self.inner.poll() {
            result = true;
        }

        result
    }

    pub fn name(&self) -> XorName {
        unwrap!(self.inner.name())
    }

    pub fn close_group(&self) -> HashSet<XorName> {
        unwrap!(unwrap!(self.inner.routing_table()).close_names(&self.name()))
    }

    pub fn routing_table(&self) -> Option<RoutingTable<XorName>> {
        self.inner.routing_table()
    }

    pub fn is_recipient(&self, dst: &Authority<XorName>) -> bool {
        self.inner.routing_table().map_or(false, |rt| rt.in_authority(dst))
    }
}

pub struct TestNodeBuilder<'a> {
    network: &'a Network,
    first_node: bool,
    config: Option<Config>,
    endpoint: Option<Endpoint>,
    cache: Box<Cache>,
}

impl<'a> TestNodeBuilder<'a> {
    pub fn first(mut self) -> Self {
        self.first_node = true;
        self
    }

    pub fn config(mut self, config: Config) -> Self {
        self.config = Some(config);
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
        TestNode::new(self.network,
                      self.first_node,
                      self.config,
                      self.endpoint,
                      self.cache)
    }
}


// -----  TestClient  -----

pub struct TestClient {
    pub handle: ServiceHandle,
    pub inner: Client,
    pub event_rx: mpsc::Receiver<Event>,
}

impl TestClient {
    pub fn new(network: &Network, config: Option<Config>, endpoint: Option<Endpoint>) -> Self {
        let (event_tx, event_rx) = mpsc::channel();
        let full_id = FullId::new();
        let handle = network.new_service_handle(config, endpoint);
        let client = mock_crust::make_current(&handle, || {
            unwrap!(Client::new(event_tx, Some(full_id), network.min_group_size()))
        });

        TestClient {
            handle: handle,
            inner: client,
            event_rx: event_rx,
        }
    }

    // Poll this node until there are no unprocessed events left.
    pub fn poll(&mut self) -> bool {
        let mut result = false;

        while self.inner.poll() {
            result = true;
        }

        result
    }

    pub fn name(&self) -> XorName {
        unwrap!(self.inner.name())
    }
}

// -----  TestCache  -----

#[derive(Default)]
pub struct TestCache(RefCell<HashMap<DataIdentifier, Data>>);

impl TestCache {
    pub fn new() -> Self {
        TestCache(RefCell::new(HashMap::new()))
    }
}

impl Cache for TestCache {
    fn get(&self, request: &Request) -> Option<Response> {
        if let Request::Get(identifier, message_id) = *request {
            self.0
                .borrow()
                .get(&identifier)
                .map(|data| Response::GetSuccess(data.clone(), message_id))
        } else {
            None
        }
    }

    fn put(&self, response: Response) {
        if let Response::GetSuccess(data, _) = response {
            let _ = self.0.borrow_mut().insert(data.identifier(), data);
        }
    }
}


// -----  poll_all, create_connected_...  -----

/// Process all events. Returns whether there were any events.
pub fn poll_all(nodes: &mut [TestNode], clients: &mut [TestClient]) -> bool {
    let mut result = false;
    loop {
        let mut handled_message = false;
        if BALANCED_POLLING {
            // handle all current messages for each node in turn, then repeat (via outer loop):
            nodes.iter_mut().foreach(|node| handled_message = node.inner.poll() || handled_message);
        } else {
            handled_message = nodes.iter_mut().any(TestNode::poll);
        }
        handled_message = clients.iter_mut().any(TestClient::poll) || handled_message;
        if !handled_message {
            return result;
        }
        result = true;
    }
}

pub fn poll_and_resend(nodes: &mut [TestNode], clients: &mut [TestClient]) {
    loop {
        let mut state_changed = poll_all(nodes, clients);
        for node in nodes.iter_mut() {
            state_changed = state_changed || node.inner.resend_unacknowledged();
        }
        for client in clients.iter_mut() {
            state_changed = state_changed || client.inner.resend_unacknowledged();
        }
        if !state_changed {
            return;
        }
    }
}

pub fn create_connected_nodes(network: &Network, size: usize) -> Vec<TestNode> {
    create_connected_nodes_with_cache(network, size, false)
}

pub fn create_connected_nodes_with_cache(network: &Network,
                                         size: usize,
                                         use_cache: bool)
                                         -> Vec<TestNode> {
    let mut nodes = Vec::new();

    // Create the seed node.
    nodes.push(TestNode::builder(network)
        .first()
        .endpoint(Endpoint(0))
        .cache(use_cache)
        .create());
    nodes[0].poll();

    let config = Config::with_contacts(&[nodes[0].handle.endpoint()]);

    // Create other nodes using the seed node endpoint as bootstrap contact.
    for i in 1..size {
        nodes.push(TestNode::builder(network)
            .config(config.clone())
            .endpoint(Endpoint(i))
            .cache(use_cache)
            .create());
        poll_and_resend(&mut nodes, &mut []);
        verify_invariant_for_all_nodes(&nodes);
    }

    let n = cmp::min(nodes.len(), network.min_group_size()) - 1;

    for node in &nodes {
        expect_next_event!(node, Event::Connected);

        let mut node_added_count = 0;

        while let Ok(event) = node.event_rx.try_recv() {
            match event {
                Event::NodeAdded(..) => node_added_count += 1,
                Event::NodeLost(..) |
                Event::GroupSplit(..) |
                Event::Tick => (),
                event => panic!("Got unexpected event: {:?}", event),
            }
        }

        assert!(node_added_count >= n,
                "Got only {} NodeAdded events.",
                node_added_count);
    }

    nodes
}

// This creates new nodes (all with `use_cache` set to `true`) until the specified disjoint groups
// have formed.
//
// `prefix_lengths` is an array representing the required `bit_count`s of the group prefixes.  For
// example passing [1, 2, 3, 3] could yield a network comprising groups [0, 100, 101, 11], or
// passing [2, 2, 3, 3, 3, 3] could yield [000, 001, 01, 100, 101, 11], while passing [1, 1] will
// always yield groups [0, 1].
//
// The array is sanity checked (e.g. it would be an error to pass [1, 1, 1]), must comprise at
// least two elements, and every element must be no more than `8`.
pub fn create_connected_nodes_with_cache_until_split(network: &Network,
                                                     mut prefix_lengths: Vec<usize>)
                                                     -> Vec<TestNode> {
    // Get sorted list of prefixes to suit requested lengths.
    sanity_check(&prefix_lengths);
    prefix_lengths.sort();
    let mut rng = network.new_rng();
    let prefixes = prefixes(&prefix_lengths, &mut rng);

    // Start first node.
    let mut nodes =
        vec![TestNode::builder(network).first().endpoint(Endpoint(0)).cache(true).create()];
    nodes[0].poll();
    let config = Config::with_contacts(&[nodes[0].handle.endpoint()]);

    // Start enough new nodes under each target prefix to trigger a split eventually.
    let min_split_size = unwrap!(nodes[0].routing_table()).min_split_size();
    for prefix in &prefixes {
        for _ in 0..min_split_size {
            let relocation_name = prefix.substituted_in(rng.gen());
            nodes.iter().foreach(|node| node.inner.set_next_node_name(relocation_name));

            let endpoint = Endpoint(nodes.len());
            nodes.push(TestNode::builder(network)
                .config(config.clone())
                .endpoint(endpoint)
                .cache(true)
                .create());
            poll_and_resend(&mut nodes, &mut []);
            expect_next_event!(nodes[nodes.len() - 1], Event::Connected);
            assert_eq!(relocation_name, nodes[nodes.len() - 1].name());
            if nodes.len() == 2 {
                expect_next_event!(nodes[0], Event::Connected);
            }
        }
    }

    // Gather all the actual prefixes and check they are as expected.
    let mut actual_prefixes = BTreeSet::<Prefix<XorName>>::new();
    for node in &nodes {
        actual_prefixes.append(&mut unwrap!(node.inner.routing_table()).prefixes());
    }
    assert_eq!(prefixes.iter().cloned().collect::<BTreeSet<_>>(),
               actual_prefixes);
    assert_eq!(prefix_lengths,
               prefixes.iter().map(|prefix| prefix.bit_count()).collect_vec());

    // Clear all event queues and clear the `next_node_name` values.
    for node in &nodes {
        while let Ok(event) = node.event_rx.try_recv() {
            match event {
                Event::NodeAdded(..) |
                Event::NodeLost(..) |
                Event::Tick |
                Event::GroupSplit(..) => (),
                event => panic!("Got unexpected event: {:?}", event),
            }
        }
        node.inner.clear_next_node_name();
    }

    trace!("Created testnet comprising {:?}", prefixes);
    nodes
}

// Create `size` clients, all of whom are connected to `nodes[0]`.
pub fn create_connected_clients(network: &Network,
                                nodes: &mut [TestNode],
                                size: usize)
                                -> Vec<TestClient> {
    let contact = nodes[0].handle.endpoint();
    let mut clients = Vec::with_capacity(size);

    for _ in 0..size {
        let client = TestClient::new(network, Some(Config::with_contacts(&[contact])), None);
        clients.push(client);

        let _ = poll_all(nodes, &mut clients);
        expect_next_event!(clients[clients.len() - 1], Event::Connected);
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

pub fn verify_invariant_for_all_nodes(nodes: &[TestNode]) {
    let routing_tables = nodes.iter().map(|n| unwrap!(n.routing_table())).collect_vec();
    verify_network_invariant(routing_tables.iter());
}

// Generate a vector of random bytes of the given length.
pub fn gen_bytes<R: Rng>(rng: &mut R, size: usize) -> Vec<u8> {
    rng.gen_iter().take(size).collect()
}

// Generate random immutable data with the given payload length.
pub fn gen_immutable_data<R: Rng>(rng: &mut R, size: usize) -> Data {
    Data::Immutable(ImmutableData::new(gen_bytes(rng, size)))
}

fn sanity_check(prefix_lengths: &[usize]) {
    assert!(prefix_lengths.len() > 1,
            "There should be at least two specified prefix lengths");
    let sum = prefix_lengths.iter().fold(0, |accumulated, &bit_count| {
        assert!(bit_count <= 8,
                "The specified prefix lengths {:?} must each be no more than 8",
                prefix_lengths);
        accumulated + (1 << (8 - bit_count))
    });
    if sum < 256 {
        panic!("The specified prefix lengths {:?} would not cover the entire address space",
               prefix_lengths);
    } else if sum > 256 {
        panic!("The specified prefix lengths {:?} would require overlapping groups",
               prefix_lengths);
    }
}

fn prefixes<T: Rng>(prefix_lengths: &[usize], rng: &mut T) -> Vec<Prefix<XorName>> {
    let _ = prefix_lengths.iter().fold(0, |previous, &current| {
        assert!(previous <= current,
                "Slice {:?} should be sorted.",
                prefix_lengths);
        current
    });
    let mut prefixes = vec![Prefix::new(prefix_lengths[0], rng.gen())];
    while prefixes.len() < prefix_lengths.len() {
        let new_prefix = Prefix::new(prefix_lengths[prefixes.len()], rng.gen());
        if prefixes.iter().all(|prefix| !prefix.is_compatible(&new_prefix)) {
            prefixes.push(new_prefix);
        }
    }
    prefixes
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
    #[should_panic(expected = "would require overlapping groups")]
    fn sanity_check_overlapping_groups() {
        sanity_check(&[1, 2, 2, 2]);
    }

    #[test]
    #[should_panic(expected = "would not cover the entire address space")]
    fn sanity_check_missing_groups() {
        sanity_check(&[1, 2]);
    }

    #[test]
    #[should_panic(expected = "must each be no more than 8")]
    fn sanity_check_too_many_groups() {
        sanity_check(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 9]);
    }
}
