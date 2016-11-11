// copyright 2016 maidsafe.net limited.
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

extern crate itertools;
#[macro_use]
extern crate log;
extern crate rand;
extern crate routing;
#[macro_use]
extern crate unwrap;

use itertools::Itertools;
use rand::Rng;
use routing::{Authority, Cache, NullCache, Client};
use routing::{Data, DataIdentifier, ImmutableData};
use routing::{Event, FullId};
use routing::{Request, Response};
use routing::mock_crust::{self, Config, Endpoint, Network, ServiceHandle};
use routing::mock_crust::crust::PeerId;
use routing::Node;
use routing::MIN_GROUP_SIZE;
use routing::{Prefix, Xorable};
use routing::{Destination, RoutingTable, verify_network_invariant};
use routing::MessageId;
use routing::XorName;
use std::cell::RefCell;
use std::cmp;
use std::collections::{HashMap, HashSet};
use std::sync::mpsc;

// Poll one event per node. Otherwise, all events in a single node are polled before moving on.
const BALANCED_POLLING: bool = true;

/// Expect that the next event raised by the node matches the given pattern.
/// Panics if no event, or an event that does not match the pattern is raised.
/// (ignores ticks).
macro_rules! expect_next_event {
    ($node:expr, $pattern:pat) => {
        loop {
            match $node.event_rx.try_recv() {
                Ok($pattern) => break,
                Ok(Event::Tick) => (),
                other => panic!("Expected Ok({}) at {}, got {:?}",
                    stringify!($pattern),
                    unwrap!($node.inner.name()),
                    other),
            }
        }
    }
}

/// Expects that any event raised by the node matches the given pattern
/// (with optional pattern guard). Ignores events that do not match the pattern.
/// Panics if the event channel is exhausted before matching event is found.
macro_rules! expect_any_event {
    ($node:expr, $pattern:pat) => {
        expect_any_event!($node, $pattern if true => ())
    };
    ($node:expr, $pattern:pat if $guard:expr) => {
        loop {
            match $node.event_rx.try_recv() {
                Ok($pattern) if $guard => break,
                Ok(_) => (),
                other => panic!("Expected Ok({}) at {}, got {:?}",
                    stringify!($pattern),
                    unwrap!($node.inner.name()),
                    other),
            }
        }
    }
}

/// Expects that the node raised no event, panics otherwise (ignores ticks).
macro_rules! expect_no_event {
    ($node:expr) => {
        match $node.event_rx.try_recv() {
            Ok(Event::Tick) => (),
            Err(mpsc::TryRecvError::Empty) => (),
            other => panic!("Expected no event at {}, got {:?}",
                unwrap!($node.inner.name()),
                other),
        }
    }
}

// Generate a random value in the range, excluding the `exclude` value, if not
// `None`.
fn gen_range_except<T: Rng>(rng: &mut T, low: usize, high: usize, exclude: Option<usize>) -> usize {
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

// Generate two distinct random values in the range, excluding the `exclude` value.
fn gen_two_range_except<T: Rng>(rng: &mut T,
                                low: usize,
                                high: usize,
                                exclude: Option<usize>)
                                -> (usize, usize) {
    let r0 = gen_range_except(rng, low, high, exclude);

    loop {
        let r1 = gen_range_except(rng, low, high, exclude);

        if r0 != r1 {
            return (r0, r1);
        }
    }
}

struct TestNode {
    handle: ServiceHandle,
    inner: Node,
    event_rx: mpsc::Receiver<Event>,
}

impl TestNode {
    fn builder(network: &Network) -> TestNodeBuilder {
        TestNodeBuilder {
            network: network,
            first_node: false,
            config: None,
            endpoint: None,
            cache: Box::new(NullCache),
        }
    }

    fn new(network: &Network,
           first_node: bool,
           config: Option<Config>,
           endpoint: Option<Endpoint>,
           cache: Box<Cache>)
           -> Self {
        let (event_tx, event_rx) = mpsc::channel();
        let handle = network.new_service_handle(config, endpoint);
        let node = mock_crust::make_current(&handle, || {
            unwrap!(Node::builder().cache(cache).first(first_node).create(event_tx))
        });

        TestNode {
            handle: handle,
            inner: node,
            event_rx: event_rx,
        }
    }

    // Poll this node until there are no unprocessed events left.
    fn poll(&mut self) -> bool {
        let mut result = false;

        while self.inner.poll() {
            result = true;
        }

        result
    }

    fn name(&self) -> XorName {
        unwrap!(self.inner.name())
    }

    fn close_group(&self) -> HashSet<XorName> {
        unwrap!(self.inner.close_group(self.name())).unwrap_or_else(HashSet::new)
    }

    fn routing_table(&self) -> RoutingTable<XorName> {
        self.inner.routing_table()
    }
}

struct TestNodeBuilder<'a> {
    network: &'a Network,
    first_node: bool,
    config: Option<Config>,
    endpoint: Option<Endpoint>,
    cache: Box<Cache>,
}

impl<'a> TestNodeBuilder<'a> {
    fn first(mut self) -> Self {
        self.first_node = true;
        self
    }

    fn config(mut self, config: Config) -> Self {
        self.config = Some(config);
        self
    }

    fn endpoint(mut self, endpoint: Endpoint) -> Self {
        self.endpoint = Some(endpoint);
        self
    }

    fn cache(mut self, use_cache: bool) -> Self {
        self.cache = if use_cache {
            Box::new(TestCache::new())
        } else {
            Box::new(NullCache)
        };

        self
    }

    fn create(self) -> TestNode {
        TestNode::new(self.network,
                      self.first_node,
                      self.config,
                      self.endpoint,
                      self.cache)
    }
}

struct TestClient {
    handle: ServiceHandle,
    inner: Client,
    event_rx: mpsc::Receiver<Event>,
}

impl TestClient {
    fn new(network: &Network, config: Option<Config>, endpoint: Option<Endpoint>) -> Self {
        let (event_tx, event_rx) = mpsc::channel();
        let full_id = FullId::new();
        let handle = network.new_service_handle(config, endpoint);
        let client = mock_crust::make_current(&handle,
                                              || unwrap!(Client::new(event_tx, Some(full_id))));

        TestClient {
            handle: handle,
            inner: client,
            event_rx: event_rx,
        }
    }

    // Poll this node until there are no unprocessed events left.
    fn poll(&mut self) -> bool {
        let mut result = false;

        while self.inner.poll() {
            result = true;
        }

        result
    }

    fn name(&self) -> XorName {
        unwrap!(self.inner.name())
    }
}

/// Process all events. Returns whether there were any events.
fn poll_all(nodes: &mut [TestNode], clients: &mut [TestClient]) -> bool {
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

fn create_connected_nodes(network: &Network, size: usize) -> Vec<TestNode> {
    create_connected_nodes_with_cache(network, size, false)
}

fn create_connected_nodes_with_cache(network: &Network,
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
        let _ = poll_all(&mut nodes, &mut []);
        verify_invariant_for_all_nodes(&nodes);
    }

    let n = cmp::min(nodes.len(), MIN_GROUP_SIZE) - 1;

    for node in &nodes {
        expect_next_event!(node, Event::Connected);

        let mut node_added_count = 0;

        while let Ok(event) = node.event_rx.try_recv() {
            match event {
                Event::NodeAdded(..) => node_added_count += 1,
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

fn create_connected_nodes_with_cache_till_split(network: &Network) -> Vec<TestNode> {
    let use_cache = true;
    let mut nodes = create_connected_nodes_with_cache(network, MIN_GROUP_SIZE * 2, use_cache);
    let config = Config::with_contacts(&[nodes[0].handle.endpoint()]);

    'outer: loop {
        let len = nodes.len();
        nodes.push(TestNode::builder(network)
            .config(config.clone())
            .endpoint(Endpoint(len))
            .cache(use_cache)
            .create());
        let _ = poll_all(&mut nodes, &mut []);
        while let Ok(event) = nodes[len].event_rx.try_recv() {
            match event {
                Event::NodeAdded(..) |
                Event::Connected |
                Event::Tick => (),
                Event::GroupSplit(..) => break 'outer,
                event => panic!("Got unexpected event: {:?}", event),
            }
        }
    }

    nodes
}

// Create `size` clients, all of whom are connected to `nodes[0]`.
fn create_connected_clients(network: &Network,
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

// Drop node at index and verify its close group receives NodeLost.
fn drop_node(nodes: &mut Vec<TestNode>, index: usize) {
    let node = nodes.remove(index);
    let name = node.name();
    let close_names = node.close_group();

    drop(node);

    let _ = poll_all(nodes, &mut []);

    for node in nodes.iter().filter(|n| close_names.contains(&n.name())) {
        loop {
            match node.event_rx.try_recv() {
                Ok(Event::NodeLost(lost_name)) if lost_name == name => break,
                Ok(_) => (),
                _ => panic!("Event::NodeLost({:?}) not received", name),
            }
        }
    }
}

// Randomly add or remove some nodes, causing churn.
// If a new node was added, returns the index of this node. Otherwise
// returns `None` (it never adds more than one node).
//
// Note: it's necessary to call `poll_all` afterwards, as this function doesn't
// call it itself.
fn random_churn<R: Rng>(rng: &mut R,
                        network: &Network,
                        nodes: &mut Vec<TestNode>)
                        -> Option<usize> {
    let len = nodes.len();

    if len > MIN_GROUP_SIZE + 2 && rng.gen_weighted_bool(3) {
        let _ = nodes.remove(rng.gen_range(0, len));
        let _ = nodes.remove(rng.gen_range(0, len - 1));
        let _ = nodes.remove(rng.gen_range(0, len - 2));

        None
    } else {
        let proxy = rng.gen_range(0, len);
        let index = rng.gen_range(0, len + 1);
        let config = Config::with_contacts(&[nodes[proxy].handle.endpoint()]);

        nodes.insert(index, TestNode::builder(network).config(config).create());
        Some(index)
    }
}


/// Sorts the given nodes by their distance to `name`. Note that this will call the `name()`
/// function on them which causes polling, so it calls `poll_all` to make sure that all other
/// events have been processed before sorting.
fn sort_nodes_by_distance_to(nodes: &mut [TestNode], name: &XorName) {
    let _ = poll_all(nodes, &mut []); // Poll
    nodes.sort_by(|node0, node1| name.cmp_distance(&node0.name(), &node1.name()));
}

fn verify_invariant_for_all_nodes(nodes: &[TestNode]) {
    let routing_tables = nodes.iter().map(TestNode::routing_table).collect_vec();
    verify_network_invariant(routing_tables.iter());
}

// Generate a vector of random bytes of the given length.
fn gen_bytes<R: Rng>(rng: &mut R, size: usize) -> Vec<u8> {
    rng.gen_iter().take(size).collect()
}

// Generate random immutable data with the given payload length.
fn gen_immutable_data<R: Rng>(rng: &mut R, size: usize) -> Data {
    Data::Immutable(ImmutableData::new(gen_bytes(rng, size)))
}

// Check that the given node received a Get request with the given details.
fn did_receive_get_request(node: &TestNode,
                           expected_src: Authority,
                           expected_dst: Authority,
                           expected_data_id: DataIdentifier,
                           expected_message_id: MessageId)
                           -> bool {
    loop {
        match node.event_rx.try_recv() {
            Ok(Event::Request { request: Request::Get(data_id, message_id), ref src, ref dst })
                if *src == expected_src && *dst == expected_dst && data_id == expected_data_id &&
                   message_id == expected_message_id => return true,
            Ok(_) => (),
            Err(_) => return false,
        }
    }
}

fn did_receive_get_success(node: &TestNode,
                           expected_src: Authority,
                           expected_dst: Authority,
                           expected_data: Data,
                           expected_message_id: MessageId)
                           -> bool {
    loop {
        let expected = |src: &Authority, dst: &Authority, data: &Data, message_id: MessageId| {
            *src == expected_src && *dst == expected_dst && *data == expected_data &&
            message_id == expected_message_id
        };
        match node.event_rx.try_recv() {
            Ok(Event::Response { response: Response::GetSuccess(ref data, message_id),
                                 ref src,
                                 ref dst }) if expected(src, dst, data, message_id) => return true,
            Ok(_) => (),
            Err(_) => return false,
        }
    }
}

fn test_nodes(size: usize) {
    let network = Network::new(None);
    let nodes = create_connected_nodes(&network, size);
    verify_invariant_for_all_nodes(&nodes);
}

fn poll_and_resend(nodes: &mut [TestNode], clients: &mut [TestClient]) {
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

struct TestCache(RefCell<HashMap<DataIdentifier, Data>>);

impl TestCache {
    fn new() -> Self {
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

#[test]
fn disconnect_on_rebootstrap() {
    let network = Network::new(None);
    let mut nodes = create_connected_nodes(&network, 2);
    // Try to bootstrap to another than the first node. With network size 2, this should fail.
    let config = Config::with_contacts(&[nodes[1].handle.endpoint()]);
    nodes.push(TestNode::builder(&network).config(config).endpoint(Endpoint(2)).create());
    let _ = poll_all(&mut nodes, &mut []);
    // When retrying to bootstrap, we should have disconnected from the bootstrap node.
    assert!(!unwrap!(nodes.last()).handle.is_connected(&nodes[1].handle));
    expect_next_event!(unwrap!(nodes.last()), Event::Terminate);
}

#[test]
fn less_than_group_size_nodes() {
    test_nodes(3)
}

#[test]
fn equal_group_size_nodes() {
    test_nodes(MIN_GROUP_SIZE);
}

#[test]
#[ignore]
fn more_than_group_size_nodes() {
    test_nodes(MIN_GROUP_SIZE * 6);
}

#[test]
fn failing_connections_group_of_three() {
    let network = Network::new(None);

    network.block_connection(Endpoint(1), Endpoint(2));
    network.block_connection(Endpoint(2), Endpoint(1));

    network.block_connection(Endpoint(1), Endpoint(3));
    network.block_connection(Endpoint(3), Endpoint(1));

    network.block_connection(Endpoint(2), Endpoint(3));
    network.block_connection(Endpoint(3), Endpoint(2));

    let mut nodes = create_connected_nodes(&network, 5);
    verify_invariant_for_all_nodes(&nodes);
    drop_node(&mut nodes, 0); // Drop the tunnel node. Node 4 should replace it.
    verify_invariant_for_all_nodes(&nodes);
    drop_node(&mut nodes, 1); // Drop a tunnel client. The others should be notified.
    verify_invariant_for_all_nodes(&nodes);
}

#[test]
fn failing_connections_ring() {
    let network = Network::new(None);
    let len = MIN_GROUP_SIZE * 2;
    for i in 0..(len - 1) {
        let ep0 = Endpoint(1 + i);
        let ep1 = Endpoint(1 + (i % len));

        network.block_connection(ep0, ep1);
        network.block_connection(ep1, ep0);
    }
    let nodes = create_connected_nodes(&network, len);
    verify_invariant_for_all_nodes(&nodes);
}

#[test]
fn failing_connections_unidirectional() {
    let network = Network::new(None);
    network.block_connection(Endpoint(1), Endpoint(2));
    network.block_connection(Endpoint(1), Endpoint(3));
    network.block_connection(Endpoint(2), Endpoint(3));

    let nodes = create_connected_nodes(&network, 4);
    verify_invariant_for_all_nodes(&nodes);
}

#[test]
fn client_connects_to_nodes() {
    let network = Network::new(None);
    let mut nodes = create_connected_nodes(&network, MIN_GROUP_SIZE + 1);
    let _ = create_connected_clients(&network, &mut nodes, 1);
}

// #[test]
// #[ignore]
// fn messages_accumulate_with_quorum() {
//     let network = Network::new(None);
//     let mut rng = network.new_rng();
//     let mut nodes = create_connected_nodes(&network, 15);
//
//     let data = gen_immutable_data(&mut rng, 8);
//     let src = Authority::NaeManager(*data.name()); // The data's NaeManager.
//     sort_nodes_by_distance_to(&mut nodes, src.name());
//
//     let send = |node: &mut TestNode, dst: &Authority, message_id: MessageId| {
//         assert!(node.inner
//             .send_get_success(src, *dst, data.clone(), message_id)
//             .is_ok());
//     };
//
//     let dst = Authority::ManagedNode(nodes[0].name()); // The closest node.
//
//     // Send a message from the group `src` to the node `dst`.
//     // Only the `QUORUM_SIZE`-th sender should cause accumulation and a
//     // `Response` event. The event should only occur once.
//     let message_id = MessageId::new();
//     for node in nodes.iter_mut().take(QUORUM_SIZE - 1) {
//         send(node, &dst, message_id);
//     }
//     let _ = poll_all(&mut nodes, &mut []);
//     expect_no_event!(nodes[0]);
//     send(&mut nodes[QUORUM_SIZE - 1], &dst, message_id);
//     let _ = poll_all(&mut nodes, &mut []);
//     expect_next_event!(nodes[0], Event::Response { response: Response::GetSuccess(..), .. });
//     send(&mut nodes[QUORUM_SIZE], &dst, message_id);
//     let _ = poll_all(&mut nodes, &mut []);
//     expect_no_event!(nodes[0]);
//
//     // If there are `QUORUM_SIZE` senders but they all only sent hashes, nothing can accumulate.
//     // Only after `nodes[0]`, which is closest to `src.name()`, has sent the full message, it
//     // accumulates.
//     let message_id = MessageId::new();
//     for node in nodes.iter_mut().skip(1).take(QUORUM_SIZE) {
//         send(node, &dst, message_id);
//     }
//     let _ = poll_all(&mut nodes, &mut []);
//     expect_no_event!(nodes[0]);
//     send(&mut nodes[0], &dst, message_id);
//     let _ = poll_all(&mut nodes, &mut []);
//     expect_next_event!(nodes[0], Event::Response { response: Response::GetSuccess(..), .. });
//     send(&mut nodes[QUORUM_SIZE + 1], &dst, message_id);
//     let _ = poll_all(&mut nodes, &mut []);
//     expect_no_event!(nodes[0]);
//
//     let dst_grp = Authority::NaeManager(*src.name()); // The whole group.
//
//     // Send a message from the group `src` to the group `dst_grp`.
//     // Only the `QUORUM_SIZE`-th sender should cause accumulation and a
//     // `Response` event. The event should only occur once.
//     let message_id = MessageId::new();
//     for node in nodes.iter_mut().take(QUORUM_SIZE - 1) {
//         send(node, &dst_grp, message_id);
//     }
//     let _ = poll_all(&mut nodes, &mut []);
//     for node in &mut nodes {
//         expect_no_event!(node);
//     }
//     send(&mut nodes[QUORUM_SIZE - 1], &dst_grp, message_id);
//     let _ = poll_all(&mut nodes, &mut []);
//     for node in &mut nodes {
//         expect_next_event!(node, Event::Response { response: Response::GetSuccess(..), .. });
//     }
//     send(&mut nodes[QUORUM_SIZE], &dst_grp, message_id);
//     let _ = poll_all(&mut nodes, &mut []);
//     for node in &mut nodes {
//         expect_no_event!(node);
//     }
//
//     // If there are `QUORUM_SIZE` senders but they all only sent hashes, nothing can accumulate.
//     // Only after `nodes[0]`, which is closest to `src.name()`, has sent the full message, it
//     // accumulates.
//     let message_id = MessageId::new();
//     for node in nodes.iter_mut().skip(1).take(QUORUM_SIZE) {
//         send(node, &dst_grp, message_id);
//     }
//     let _ = poll_all(&mut nodes, &mut []);
//     for node in &mut nodes {
//         expect_no_event!(node);
//     }
//     send(&mut nodes[0], &dst_grp, message_id);
//     let _ = poll_all(&mut nodes, &mut []);
//     for node in &mut nodes {
//         expect_next_event!(node, Event::Response { response: Response::GetSuccess(..), .. });
//     }
//     send(&mut nodes[QUORUM_SIZE + 1], &dst_grp, message_id);
//     let _ = poll_all(&mut nodes, &mut []);
//     for node in &mut nodes {
//         expect_no_event!(node);
//     }
// }

#[test]
fn node_drops() {
    let network = Network::new(None);
    let mut nodes = create_connected_nodes(&network, MIN_GROUP_SIZE + 2);
    drop_node(&mut nodes, 0);

    verify_invariant_for_all_nodes(&nodes);
}

#[test]
#[ignore]
fn churn() {
    let network = Network::new(None);

    let mut rng = network.new_rng();
    let mut nodes = create_connected_nodes(&network, 20);

    for i in 0..100 {
        trace!("Iteration {}", i);
        let _ = random_churn(&mut rng, &network, &mut nodes);
        poll_and_resend(&mut nodes, &mut []);

        for node in &mut nodes {
            node.inner.clear_state();
        }

        verify_invariant_for_all_nodes(&nodes);
    }
}

#[test]
fn node_joins_in_front() {
    let network = Network::new(None);
    let mut nodes = create_connected_nodes(&network, 2 * MIN_GROUP_SIZE);
    let config = Config::with_contacts(&[nodes[0].handle.endpoint()]);
    nodes.insert(0, TestNode::builder(&network).config(config).create());

    let _ = poll_all(&mut nodes, &mut []);

    verify_invariant_for_all_nodes(&nodes);
}

#[test]
#[ignore]
fn multiple_joining_nodes() {
    let network_size = 2 * MIN_GROUP_SIZE;
    let network = Network::new(None);
    let mut nodes = create_connected_nodes(&network, network_size);
    let config = Config::with_contacts(&[nodes[0].handle.endpoint()]);

    nodes.insert(0,
                 TestNode::builder(&network).config(config.clone()).create());
    nodes.insert(0,
                 TestNode::builder(&network).config(config.clone()).create());
    nodes.push(TestNode::builder(&network).config(config.clone()).create());

    let _ = poll_all(&mut nodes, &mut []);
    nodes.retain(|node| !node.routing_table().is_empty());
    let _ = poll_all(&mut nodes, &mut []);

    verify_invariant_for_all_nodes(&nodes);
}

#[test]
#[cfg_attr(feature = "clippy", allow(needless_range_loop))]
fn node_restart() {
    let network = Network::new(None);
    let mut rng = network.new_rng();
    let mut nodes = create_connected_nodes(&network, MIN_GROUP_SIZE);

    let config = Config::with_contacts(&[nodes[0].handle.endpoint()]);

    // Drop one node, causing the remaining nodes to end up with too few entries
    // in their routing tables and to request a restart.
    let index = rng.gen_range(1, nodes.len());
    drop_node(&mut nodes, index);

    for node in &nodes[1..] {
        expect_next_event!(node, Event::RestartRequired);
    }

    // Restart the nodes that requested it
    for index in 1..nodes.len() {
        nodes[index] = TestNode::builder(&network).config(config.clone()).create();
        poll_all(&mut nodes[..(index + 1)], &mut []);
    }

    verify_invariant_for_all_nodes(&nodes);
}

#[test]
fn check_close_groups_for_group_size_nodes() {
    let nodes = create_connected_nodes(&Network::new(None), MIN_GROUP_SIZE);
    let close_groups_complete = nodes.iter()
        .all(|n| nodes.iter().all(|m| m.close_group().contains(&n.name())));
    assert!(close_groups_complete);
}

#[test]
fn whitelist() {
    let network = Network::new(None);
    let mut nodes = create_connected_nodes(&network, MIN_GROUP_SIZE);
    let config = Config::with_contacts(&[nodes[0].handle.endpoint()]);
    for node in &mut nodes {
        node.handle.0.borrow_mut().whitelist_peer(PeerId(MIN_GROUP_SIZE));
    }
    // The next node has peer ID `GROUP_SIZE`: It should be able to join.
    nodes.push(TestNode::builder(&network).config(config.clone()).create());
    let _ = poll_all(&mut nodes, &mut []);
    verify_invariant_for_all_nodes(&nodes);
    // The next node has peer ID `GROUP_SIZE + 1`: It is not whitelisted.
    nodes.push(TestNode::builder(&network).config(config.clone()).create());
    let _ = poll_all(&mut nodes, &mut []);
    assert!(!unwrap!(nodes.pop()).inner.is_node());
    // A client should be able to join anyway, regardless of the whitelist.
    let mut clients = vec![TestClient::new(&network, Some(config), None)];
    let _ = poll_all(&mut nodes, &mut clients);
    expect_next_event!(clients[0], Event::Connected);
}

#[test]
fn successful_put_request() {
    let network = Network::new(None);
    let mut rng = network.new_rng();
    let mut nodes = create_connected_nodes(&network, MIN_GROUP_SIZE + 1);
    let mut clients = create_connected_clients(&network, &mut nodes, 1);

    let dst = Authority::ClientManager(clients[0].name());
    let data = gen_immutable_data(&mut rng, 1024);
    let message_id = MessageId::new();

    assert!(clients[0]
        .inner
        .send_put_request(dst, data.clone(), message_id)
        .is_ok());

    let _ = poll_all(&mut nodes, &mut clients);

    let mut request_received_count = 0;
    let client_dst = Destination::Group(clients[0].name());
    for node in nodes.iter().filter(|n| n.routing_table().is_recipient(&client_dst)) {
        loop {
            match node.event_rx.try_recv() {
                Ok(Event::Request { request: Request::Put(ref immutable, ref id), .. }) => {
                    request_received_count += 1;
                    if data == *immutable && message_id == *id {
                        break;
                    }
                }
                Ok(_) => (),
                _ => panic!("Event::Request not received"),
            }
        }
    }

    // TODO: Assert a quorum here.
    assert!(2 * request_received_count > MIN_GROUP_SIZE);
}

#[test]
fn successful_get_request() {
    let network = Network::new(None);
    let mut rng = network.new_rng();
    let mut nodes = create_connected_nodes(&network, MIN_GROUP_SIZE + 1);
    let mut clients = create_connected_clients(&network, &mut nodes, 1);

    let data = gen_immutable_data(&mut rng, 1024);
    let dst = Authority::NaeManager(*data.name());
    let data_request = data.identifier();
    let message_id = MessageId::new();

    assert!(clients[0]
        .inner
        .send_get_request(dst, data_request, message_id)
        .is_ok());

    let _ = poll_all(&mut nodes, &mut clients);

    let mut request_received_count = 0;

    let data_dst = Destination::Group(*data.name());
    for node in nodes.iter().filter(|n| n.routing_table().is_recipient(&data_dst)) {
        loop {
            match node.event_rx.try_recv() {
                Ok(Event::Request { request: Request::Get(ref request, id), src, dst }) => {
                    request_received_count += 1;
                    if data_request == *request && message_id == id {
                        if let Err(err) = node.inner
                            .send_get_success(dst, src, data.clone(), id) {
                            trace!("Failed to send GetSuccess response: {:?}", err);
                        }
                        break;
                    }
                }
                Ok(_) => (),
                _ => panic!("Event::Request not received"),
            }
        }
    }

    // TODO: Assert a quorum here.
    assert!(2 * request_received_count > MIN_GROUP_SIZE);

    let _ = poll_all(&mut nodes, &mut clients);

    let mut response_received_count = 0;

    for client in clients {
        loop {
            match client.event_rx.try_recv() {
                Ok(Event::Response {
                    response: Response::GetSuccess(ref immutable, ref id),
                    ..
                }) => {
                    response_received_count += 1;
                    if data == *immutable && message_id == *id {
                        break;
                    }
                }
                Ok(_) => (),
                _ => panic!("Event::Response not received"),
            }
        }
    }

    assert!(response_received_count == 1);
}

#[test]
fn failed_get_request() {
    let network = Network::new(None);
    let mut rng = network.new_rng();
    let mut nodes = create_connected_nodes(&network, MIN_GROUP_SIZE + 1);
    let mut clients = create_connected_clients(&network, &mut nodes, 1);

    let data = gen_immutable_data(&mut rng, 1024);
    let dst = Authority::NaeManager(*data.name());
    let data_request = data.identifier();
    let message_id = MessageId::new();

    assert!(clients[0]
        .inner
        .send_get_request(dst, data_request, message_id)
        .is_ok());

    let _ = poll_all(&mut nodes, &mut clients);

    let mut request_received_count = 0;

    let data_dst = Destination::Group(*data.name());
    for node in nodes.iter().filter(|n| n.routing_table().is_recipient(&data_dst)) {
        loop {
            match node.event_rx.try_recv() {
                Ok(Event::Request { request: Request::Get(ref data_id, ref id), src, dst }) => {
                    request_received_count += 1;
                    if data_request == *data_id && message_id == *id {
                        if let Err(err) = node.inner
                            .send_get_failure(dst, src, *data_id, vec![], *id) {
                            trace!("Failed to send GetFailure response: {:?}", err);
                        }
                        break;
                    }
                }
                Ok(_) => (),
                _ => panic!("Event::Request not received"),
            }
        }
    }

    // TODO: Assert a quorum here.
    assert!(2 * request_received_count > MIN_GROUP_SIZE);

    let _ = poll_all(&mut nodes, &mut clients);

    let mut response_received_count = 0;

    for client in clients {
        loop {
            match client.event_rx.try_recv() {
                Ok(Event::Response { response: Response::GetFailure { ref id, .. }, .. }) => {
                    response_received_count += 1;
                    if message_id == *id {
                        break;
                    }
                }
                Ok(_) => (),
                _ => panic!("Event::Response not received"),
            }
        }
    }

    assert!(response_received_count == 1);
}

#[test]
fn disconnect_on_get_request() {
    let network = Network::new(None);
    let mut rng = network.new_rng();
    let mut nodes = create_connected_nodes(&network, 2 * MIN_GROUP_SIZE);
    let mut clients = create_connected_clients(&network, &mut nodes, 1);

    let immutable_data = ImmutableData::new(gen_bytes(&mut rng, 1024));
    let data = Data::Immutable(immutable_data.clone());
    let dst = Authority::NaeManager(*data.name());
    let data_request = DataIdentifier::Immutable(*data.name());
    let message_id = MessageId::new();

    assert!(clients[0]
        .inner
        .send_get_request(dst, data_request.clone(), message_id)
        .is_ok());

    let _ = poll_all(&mut nodes, &mut clients);

    let mut request_received_count = 0;

    let data_dst = Destination::Group(*data.name());
    for node in nodes.iter().filter(|n| n.routing_table().is_recipient(&data_dst)) {
        loop {
            match node.event_rx.try_recv() {
                Ok(Event::Request { request: Request::Get(ref request, ref id), src, dst }) => {
                    request_received_count += 1;
                    if data_request == *request && message_id == *id {
                        if let Err(err) = node.inner
                            .send_get_success(dst, src, data.clone(), *id) {
                            trace!("Failed to send GetSuccess response: {:?}", err);
                        }
                        break;
                    }
                }
                Ok(_) => (),
                _ => panic!("Event::Request not received"),
            }
        }
    }

    // TODO: Assert a quorum here.
    assert!(2 * request_received_count > MIN_GROUP_SIZE);

    clients[0].handle.0.borrow_mut().disconnect(&nodes[0].handle.0.borrow().peer_id);
    nodes[0].handle.0.borrow_mut().disconnect(&clients[0].handle.0.borrow().peer_id);

    let _ = poll_all(&mut nodes, &mut clients);

    for client in clients {
        if let Ok(Event::Response { .. }) = client.event_rx.try_recv() {
            panic!("Unexpected Event::Response received");
        }
    }
}

const REQUEST_DURING_CHURN_ITERATIONS: usize = 10;

#[test]
#[ignore]
fn request_during_churn_node_to_self() {
    let network = Network::new(None);
    let mut rng = network.new_rng();

    let mut nodes = create_connected_nodes(&network, 2 * MIN_GROUP_SIZE);

    for _ in 0..REQUEST_DURING_CHURN_ITERATIONS {
        let added_index = random_churn(&mut rng, &network, &mut nodes);
        let index = gen_range_except(&mut rng, 0, nodes.len(), added_index);
        let name = nodes[index].name();

        let src = Authority::ManagedNode(name);
        let dst = Authority::ManagedNode(name);
        let data = gen_immutable_data(&mut rng, 8);
        let data_id = data.identifier();
        let message_id = MessageId::new();

        unwrap!(nodes[index].inner.send_get_request(src, dst, data_id, message_id));

        poll_and_resend(&mut nodes, &mut []);
        assert!(did_receive_get_request(&nodes[index], src, dst, data_id, message_id));
    }
}

#[test]
#[ignore]
fn request_during_churn_node_to_node() {
    let network = Network::new(None);
    let mut rng = network.new_rng();
    let mut nodes = create_connected_nodes(&network, 2 * MIN_GROUP_SIZE);

    for _ in 0..REQUEST_DURING_CHURN_ITERATIONS {
        let added_index = random_churn(&mut rng, &network, &mut nodes);

        let (index0, index1) = gen_two_range_except(&mut rng, 0, nodes.len(), added_index);
        let name0 = nodes[index0].name();
        let name1 = nodes[index1].name();

        let src = Authority::ManagedNode(name0);
        let dst = Authority::ManagedNode(name1);
        let data = gen_immutable_data(&mut rng, 8);
        let data_id = data.identifier();
        let message_id = MessageId::new();

        unwrap!(nodes[index0].inner.send_get_request(src, dst, data_id, message_id));

        poll_and_resend(&mut nodes, &mut []);
        assert!(did_receive_get_request(&nodes[index1], src, dst, data_id, message_id));
    }
}

#[test]
#[ignore]
fn request_during_churn_node_to_group() {
    let network = Network::new(None);
    let mut rng = network.new_rng();
    let mut nodes = create_connected_nodes(&network, 2 * MIN_GROUP_SIZE);

    for _ in 0..REQUEST_DURING_CHURN_ITERATIONS {
        let added_index = random_churn(&mut rng, &network, &mut nodes);

        let index = gen_range_except(&mut rng, 0, nodes.len(), added_index);

        let data = gen_immutable_data(&mut rng, 8);
        let src = Authority::ManagedNode(nodes[index].name());
        let dst = Authority::NaeManager(*data.name());
        let data_id = data.identifier();
        let message_id = MessageId::new();

        unwrap!(nodes[index].inner.send_get_request(src, dst, data_id, message_id));

        poll_and_resend(&mut nodes, &mut []);

        // This puts the members of the dst group to the beginning of the vec.
        sort_nodes_by_distance_to(&mut nodes, dst.name());

        let num_received = nodes.iter()
            .take(MIN_GROUP_SIZE)
            .filter(|node| did_receive_get_request(node, src, dst, data_id, message_id))
            .count();

        // TODO: Assert a quorum here.
        assert!(2 * num_received > MIN_GROUP_SIZE);
    }
}

#[test]
#[ignore]
fn request_during_churn_group_to_self() {
    let network = Network::new(None);
    let mut rng = network.new_rng();
    let mut nodes = create_connected_nodes(&network, 2 * MIN_GROUP_SIZE);

    for _ in 0..REQUEST_DURING_CHURN_ITERATIONS {
        let name = rng.gen();
        let src = Authority::NaeManager(name);
        let dst = Authority::NaeManager(name);
        let data = gen_immutable_data(&mut rng, 8);
        let data_id = data.identifier();
        let message_id = MessageId::new();

        sort_nodes_by_distance_to(&mut nodes, &name);

        for node in &nodes[0..MIN_GROUP_SIZE] {
            unwrap!(node.inner.send_get_request(src, dst, data_id, message_id));
        }

        let _ = random_churn(&mut rng, &network, &mut nodes);

        poll_and_resend(&mut nodes, &mut []);

        let num_received = nodes.iter()
            .take(MIN_GROUP_SIZE)
            .filter(|node| did_receive_get_request(node, src, dst, data_id, message_id))
            .count();

        // TODO: Assert a quorum here.
        assert!(2 * num_received > MIN_GROUP_SIZE);
    }
}

#[test]
#[ignore]
fn request_during_churn_group_to_node() {
    let network = Network::new(None);
    let mut rng = network.new_rng();
    let mut nodes = create_connected_nodes(&network, 2 * MIN_GROUP_SIZE);

    for _ in 0..REQUEST_DURING_CHURN_ITERATIONS {
        let data = gen_immutable_data(&mut rng, 8);
        let src = Authority::NaeManager(*data.name());
        sort_nodes_by_distance_to(&mut nodes, src.name());

        let added_index = random_churn(&mut rng, &network, &mut nodes);

        let index = gen_range_except(&mut rng, 0, nodes.len(), added_index);
        let dst = Authority::ManagedNode(nodes[index].name());
        let message_id = MessageId::new();

        for node in &nodes[0..MIN_GROUP_SIZE] {
            unwrap!(node.inner.send_get_success(src, dst, data.clone(), message_id));
        }

        poll_and_resend(&mut nodes, &mut []);
        assert!(did_receive_get_success(&nodes[index], src, dst, data, message_id));
    }
}

#[test]
#[ignore]
fn request_during_churn_group_to_group() {
    let network = Network::new(None);
    let mut rng = network.new_rng();
    let mut nodes = create_connected_nodes(&network, 2 * MIN_GROUP_SIZE);

    for _ in 0..REQUEST_DURING_CHURN_ITERATIONS {
        let name0 = rng.gen();
        let name1 = rng.gen();
        let src = Authority::NodeManager(name0);
        let dst = Authority::NodeManager(name1);
        let data = gen_immutable_data(&mut rng, 8);
        let data_id = data.identifier();
        let message_id = MessageId::new();
        sort_nodes_by_distance_to(&mut nodes, &name0);
        let _added_index = random_churn(&mut rng, &network, &mut nodes);

        for node in &nodes[0..MIN_GROUP_SIZE] {
            unwrap!(node.inner.send_get_request(src, dst, data_id, message_id));
        }

        poll_and_resend(&mut nodes, &mut []);

        sort_nodes_by_distance_to(&mut nodes, &name1);

        let num_received = nodes.iter()
            .take(MIN_GROUP_SIZE)
            .filter(|node| did_receive_get_request(node, src, dst, data_id, message_id))
            .count();

        // TODO: Assert a quorum here.
        assert!(2 * num_received > MIN_GROUP_SIZE);
    }
}

// Generate random immutable data, but make sure the first node in the given
// node slice (the proxy node) is not in the data's group.
fn gen_immutable_data_not_in_first_node_group<T: Rng>(rng: &mut T, nodes: &[TestNode]) -> Data {
    let first_name = nodes[0].name();
    // We want to make sure the data is inserted into a different group. Since the
    // root prefix uses 0 bits, we will have at least one group starting bit 0 and at
    // least one starting bit 1. If this differs, the groups are guaranteed different.
    let prefix = Prefix::new(1, first_name);

    loop {
        let data = gen_immutable_data(rng, 8);
        if !prefix.matches(data.name()) {
            return data;
        }
    }
}

#[test]
fn response_caching() {
    let network = Network::new(None);

    let mut rng = network.new_rng();
    let mut nodes = create_connected_nodes_with_cache_till_split(&network);
    let mut clients = create_connected_clients(&network, &mut nodes, 1);

    let proxy_node_name = nodes[0].name();

    // We need to make sure the proxy node isn't the one closest to the data,
    // because in that case the full response (as opposed to just a hash of it)
    // would originate from the proxy node and would never be relayed by it, thus
    // it would never be stored in the cache.
    let data = gen_immutable_data_not_in_first_node_group(&mut rng, &nodes);
    let data_id = data.identifier();
    let message_id = MessageId::new();
    let dst = Authority::NaeManager(*data.name());

    // No node has the data cached yet, so this request should reach the nodes
    // in the NAE manager group of the data.
    unwrap!(clients[0].inner.send_get_request(dst, data_id, message_id));

    poll_all(&mut nodes, &mut clients);

    for node in &nodes {
        loop {
            match node.event_rx.try_recv() {
                Ok(Event::Request { request: Request::Get(req_data_id, req_message_id),
                                    src: req_src,
                                    dst: req_dst }) => {
                    if req_data_id == data_id && req_message_id == message_id {
                        unwrap!(node.inner
                            .send_get_success(req_dst, req_src, data.clone(), req_message_id));
                        break;
                    }
                }
                Ok(_) => (),
                Err(_) => break,
            }
        }
    }

    poll_all(&mut nodes, &mut clients);

    expect_any_event!(
        clients[0],
        Event::Response {
            response: Response::GetSuccess(ref res_data, res_message_id),
            src: Authority::NaeManager(ref src_name),
            ..
        } if *res_data == data &&
             res_message_id == message_id &&
             src_name == data.name()
    );

    // Drain remaining events if any.
    while let Ok(_) = clients[0].event_rx.try_recv() {}

    let message_id = MessageId::new();

    // The proxy node should have cached the data, so this request should only
    // hit the proxy node and not be relayed to the other nodes.
    unwrap!(clients[0].inner.send_get_request(dst, data_id, message_id));

    poll_all(&mut nodes, &mut clients);

    // The client should receive ack for the request.
    assert!(!clients[0].inner.has_unacknowledged());

    // The client should receive the response...
    expect_any_event!(
        clients[0],
        Event::Response {
            response: Response::GetSuccess(ref res_data, res_message_id),
            src: Authority::ManagedNode(src_name),
            ..
        } if *res_data == data &&
             res_message_id == message_id &&
             src_name == proxy_node_name
    );

    // ...but only once.
    expect_no_event!(clients[0]);

    // The request should not be relayed to any other node, so no node should
    // raise Event::Request.
    for node in nodes.iter().take(MIN_GROUP_SIZE) {
        expect_no_event!(node);
    }
}
