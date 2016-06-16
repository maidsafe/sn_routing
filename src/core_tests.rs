// copyright 2016 maidsafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use rand::{self, Rng, SeedableRng, XorShiftRng};
use rand::distributions::{IndependentSample, Range};
use std::cmp;
use std::collections::HashSet;
use std::sync::mpsc;
use std::thread;

use authority::Authority;
use client::Client;
use core::{GROUP_SIZE, QUORUM_SIZE};
use data::{Data, DataIdentifier, ImmutableData};
use event::Event;
use id::FullId;
use itertools::Itertools;
use kademlia_routing_table::{RoutingTable, ContactInfo};
use messages::{Request, Response};
use mock_crust::{self, Config, Endpoint, Network, ServiceHandle};
use node::Node;
use types::MessageId;
use xor_name::XorName;

// Poll one event per node. Otherwise, all events in a single node are polled before moving on.
const BALANCED_POLLING: bool = true;

struct Seed(pub [u32; 4]);

impl Seed {
    pub fn new() -> Seed {
        Seed([rand::random(), rand::random(), rand::random(), rand::random()])
    }
}

impl Drop for Seed {
    fn drop(&mut self) {
        if thread::panicking() {
            let msg = format!("rng seed = {:?}", self.0);
            let border = (0..msg.len()).map(|_| "=").collect::<String>();
            println!("\n{}\n{}\n{}\n", border, msg, border);
        }
    }
}

struct TestNode {
    handle: ServiceHandle,
    inner: Node,
    event_rx: mpsc::Receiver<Event>,
}

impl TestNode {
    fn new(network: &Network,
           first_node: bool,
           config: Option<Config>,
           endpoint: Option<Endpoint>)
           -> Self {
        let (event_tx, event_rx) = mpsc::channel();
        let handle = network.new_service_handle(config, endpoint);
        let node = mock_crust::make_current(&handle,
                                            || unwrap_result!(Node::new(event_tx, first_node)));

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
        unwrap_result!(self.inner.name())
    }

    fn close_group(&self) -> Vec<XorName> {
        unwrap_result!(self.inner.close_group(self.name())).unwrap_or_else(Vec::new)
    }

    fn routing_table(&self) -> RoutingTable<XorName> {
        self.inner.routing_table()
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
        let client = mock_crust::make_current(&handle, || {
            unwrap_result!(Client::new(event_tx, Some(full_id)))
        });

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
        unwrap_result!(self.inner.name())
    }
}

/// Expects that the node raised an event matching the given pattern, panics if not.
macro_rules! expect_event {
    ($node:expr, $pattern:pat) => {
        match $node.event_rx.try_recv() {
            Ok($pattern) => (),
            other => panic!("Expected Ok({}), got {:?}", stringify!($pattern), other),
        }
    }
}

/// Expects that the node raised no event, panics otherwise.
macro_rules! expect_no_event {
    ($node:expr) => {
        match $node.event_rx.try_recv() {
            Err(mpsc::TryRecvError::Empty) => (),
            other => panic!("Expected no event, got {:?}", other),
        }
    }
}

/// Process all events. Returns whether there were any events.
fn poll_all(nodes: &mut [TestNode], clients: &mut [TestClient]) -> bool {
    let mut result = false;
    loop {
        let mut n = false;
        if BALANCED_POLLING {
            nodes.iter_mut().foreach(|node| n = n || node.inner.poll());
        } else {
            n = nodes.iter_mut().any(TestNode::poll);
        }
        let c = clients.iter_mut().any(TestClient::poll);
        if !n && !c {
            break;
        } else {
            result = true;
        }
    }
    result
}

fn create_connected_nodes(network: &Network, size: usize) -> Vec<TestNode> {
    let mut nodes = Vec::new();

    // Create the seed node.
    nodes.push(TestNode::new(network, true, None, Some(Endpoint(0))));
    nodes[0].poll();

    let config = Config::with_contacts(&[nodes[0].handle.endpoint()]);

    // Create other nodes using the seed node endpoint as bootstrap contact.
    for i in 1..size {
        nodes.push(TestNode::new(network, false, Some(config.clone()), Some(Endpoint(i))));
        let _ = poll_all(&mut nodes, &mut []);
    }

    let n = cmp::min(nodes.len(), GROUP_SIZE) - 1;

    for node in &nodes {
        expect_event!(node, Event::Connected);
        for _ in 0..n {
            expect_event!(node, Event::NodeAdded(..))
        }
        while let Ok(event) = node.event_rx.try_recv() {
            if let Event::NodeAdded(..) = event {
                continue;
            }
            panic!("Got unexpected event: {:?}", event);
        }
    }

    nodes
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
                Ok(Event::NodeLost(lost_name, _)) if lost_name == name => break,
                Ok(_) => (),
                _ => panic!("Event::NodeLost({:?}) not received", name),
            }
        }
    }
}

// Get names of all entries in the `bucket_index`-th bucket in the routing table.
fn entry_names_in_bucket(table: &RoutingTable<XorName>, bucket_index: usize) -> HashSet<XorName> {
    let our_name = table.our_name();
    let far_name = our_name.with_flipped_bit(bucket_index);

    table.closest_nodes_to(&far_name, GROUP_SIZE, false)
        .into_iter()
        .map(|info| *info.name())
        .filter(|name| our_name.bucket_index(name) == bucket_index)
        .collect()
}

// Get names of all nodes that belong to the `index`-th bucket in the `name`s
// routing table.
fn node_names_in_bucket(routing_tables: &[RoutingTable<XorName>],
                        target: &XorName,
                        bucket_index: usize)
                        -> HashSet<XorName> {
    routing_tables.iter()
        .filter(|routing_table| target.bucket_index(routing_table.our_name()) == bucket_index)
        .map(|routing_table| *routing_table.our_name())
        .collect()
}

// Verify that the kademlia invariant is upheld for the node at `index`.
fn verify_kademlia_invariant_for_node(nodes: &[TestNode], index: usize) {
    let routing_tables = nodes.iter().map(|node| node.routing_table()).collect_vec();
    verify_kademlia_invariant(&routing_tables, index);
}

/// Verify that the kademlia invariant is upheld for the routing table at `index`.
pub fn verify_kademlia_invariant(routing_tables: &[RoutingTable<XorName>], index: usize) {
    let target = routing_tables[index].our_name();
    let mut count = routing_tables.len() - 1;
    let mut bucket_index = 0;

    while count > 0 {
        let entries = entry_names_in_bucket(&routing_tables[index], bucket_index);
        let actual_bucket = node_names_in_bucket(routing_tables, target, bucket_index);
        if entries.len() < GROUP_SIZE {
            assert!(actual_bucket == entries,
                    "Node: {:?}, expected: {:?}. found: {:?}",
                    target,
                    actual_bucket,
                    entries);
        }
        count -= actual_bucket.len();
        bucket_index += 1;
    }
}

// Verify that the kademlia invariant is upheld for all nodes.
fn verify_kademlia_invariant_for_all_nodes(nodes: &[TestNode]) {
    for node_index in 0..nodes.len() {
        verify_kademlia_invariant_for_node(nodes, node_index);
    }
}

fn test_nodes(size: usize) {
    let network = Network::new();
    let nodes = create_connected_nodes(&network, size);
    verify_kademlia_invariant_for_all_nodes(&nodes);
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

#[test]
fn less_than_group_size_nodes() {
    test_nodes(3)
}

#[test]
fn group_size_nodes() {
    test_nodes(GROUP_SIZE);
}

#[test]
fn more_than_group_size_nodes() {
    test_nodes(GROUP_SIZE * 2);
}

#[test]
fn failing_connections_group_of_three() {
    let network = Network::new();

    network.block_connection(Endpoint(1), Endpoint(2));
    network.block_connection(Endpoint(2), Endpoint(1));

    network.block_connection(Endpoint(1), Endpoint(3));
    network.block_connection(Endpoint(3), Endpoint(1));

    network.block_connection(Endpoint(2), Endpoint(3));
    network.block_connection(Endpoint(3), Endpoint(2));

    let mut nodes = create_connected_nodes(&network, 5);
    verify_kademlia_invariant_for_all_nodes(&nodes);
    drop_node(&mut nodes, 0); // Drop the tunnel node. Node 4 should replace it.
    verify_kademlia_invariant_for_all_nodes(&nodes);
    drop_node(&mut nodes, 1); // Drop a tunnel client. The others should be notified.
    verify_kademlia_invariant_for_all_nodes(&nodes);
}

#[test]
fn failing_connections_ring() {
    let network = Network::new();
    let len = GROUP_SIZE * 2;
    for i in 0..(len - 1) {
        let ep0 = Endpoint(1 + i);
        let ep1 = Endpoint(1 + (i % len));

        network.block_connection(ep0, ep1);
        network.block_connection(ep1, ep0);
    }
    let nodes = create_connected_nodes(&network, len);
    verify_kademlia_invariant_for_all_nodes(&nodes);
}

#[test]
fn failing_connections_unidirectional() {
    let network = Network::new();
    network.block_connection(Endpoint(1), Endpoint(2));
    network.block_connection(Endpoint(1), Endpoint(3));
    network.block_connection(Endpoint(2), Endpoint(3));

    let nodes = create_connected_nodes(&network, 4);
    verify_kademlia_invariant_for_all_nodes(&nodes);
}

#[test]
fn client_connects_to_nodes() {
    let network = Network::new();
    let mut nodes = create_connected_nodes(&network, GROUP_SIZE + 1);

    // Create one client that tries to connect to the network.
    let client = TestClient::new(&network,
                                 Some(Config::with_contacts(&[nodes[0].handle.endpoint()])),
                                 None);
    let mut clients = vec![client];

    let _ = poll_all(&mut nodes, &mut clients);

    expect_event!(clients[0], Event::Connected);
}

#[test]
fn messages_accumulate_with_quorum() {
    let seed = Seed::new();
    let mut rng = XorShiftRng::from_seed(seed.0);

    let network = Network::new();
    let mut nodes = create_connected_nodes(&network, 15);

    let data = Data::Immutable(ImmutableData::new(rng.gen_iter().take(8).collect()));
    let src = Authority::NaeManager(data.name()); // The data's NaeManager.
    nodes.sort_by(|node0, node1| src.name().cmp_distance(&node0.name(), &node1.name()));

    let send = |node: &mut TestNode, dst: &Authority, message_id: MessageId| {
        assert!(node.inner
            .send_get_success(src.clone(), dst.clone(), data.clone(), message_id)
            .is_ok());
    };

    let dst = Authority::ManagedNode(nodes[0].name()); // The closest node.

    // Send a message from the group `src` to the node `dst`. Only the `QUORUM_SIZE`-th sender
    // should cause accumulation and a `Response` event. The event should only occur once.
    let message_id = MessageId::new();
    for node in nodes.iter_mut().take(QUORUM_SIZE - 1) {
        send(node, &dst, message_id);
    }
    let _ = poll_all(&mut nodes, &mut []);
    expect_no_event!(nodes[0]);
    send(&mut nodes[QUORUM_SIZE - 1], &dst, message_id);
    let _ = poll_all(&mut nodes, &mut []);
    expect_event!(nodes[0], Event::Response { response: Response::GetSuccess(..), .. });
    send(&mut nodes[QUORUM_SIZE], &dst, message_id);
    let _ = poll_all(&mut nodes, &mut []);
    expect_no_event!(nodes[0]);

    // If there are `QUORUM_SIZE` senders but they all only sent hashes, nothing can accumulate.
    // Only after `nodes[0]`, which is closest to `src.name()`, has sent the full message, it
    // accumulates.
    let message_id = MessageId::new();
    for node in nodes.iter_mut().skip(1).take(QUORUM_SIZE) {
        send(node, &dst, message_id);
    }
    let _ = poll_all(&mut nodes, &mut []);
    expect_no_event!(nodes[0]);
    send(&mut nodes[0], &dst, message_id);
    let _ = poll_all(&mut nodes, &mut []);
    expect_event!(nodes[0], Event::Response { response: Response::GetSuccess(..), .. });
    send(&mut nodes[QUORUM_SIZE + 1], &dst, message_id);
    let _ = poll_all(&mut nodes, &mut []);
    expect_no_event!(nodes[0]);

    let dst_grp = Authority::NaeManager(*src.name()); // The whole group.

    // Send a message from the group `src` to the group `dst_grp`. Only the `QUORUM_SIZE`-th sender
    // should cause accumulation and a `Response` event. The event should only occur once.
    let message_id = MessageId::new();
    for node in nodes.iter_mut().take(QUORUM_SIZE - 1) {
        send(node, &dst_grp, message_id);
    }
    let _ = poll_all(&mut nodes, &mut []);
    for node in &mut nodes {
        expect_no_event!(node);
    }
    send(&mut nodes[QUORUM_SIZE - 1], &dst_grp, message_id);
    let _ = poll_all(&mut nodes, &mut []);
    for node in &mut nodes[..GROUP_SIZE] {
        expect_event!(node, Event::Response { response: Response::GetSuccess(..), .. });
    }
    send(&mut nodes[QUORUM_SIZE], &dst_grp, message_id);
    let _ = poll_all(&mut nodes, &mut []);
    for node in &mut nodes {
        expect_no_event!(node);
    }

    // If there are `QUORUM_SIZE` senders but they all only sent hashes, nothing can accumulate.
    // Only after `nodes[0]`, which is closest to `src.name()`, has sent the full message, it
    // accumulates.
    let message_id = MessageId::new();
    for node in nodes.iter_mut().skip(1).take(QUORUM_SIZE) {
        send(node, &dst_grp, message_id);
    }
    let _ = poll_all(&mut nodes, &mut []);
    for node in &mut nodes {
        expect_no_event!(node);
    }
    send(&mut nodes[0], &dst_grp, message_id);
    let _ = poll_all(&mut nodes, &mut []);
    for node in &mut nodes[..GROUP_SIZE] {
        expect_event!(node, Event::Response { response: Response::GetSuccess(..), .. });
    }
    send(&mut nodes[QUORUM_SIZE + 1], &dst_grp, message_id);
    let _ = poll_all(&mut nodes, &mut []);
    for node in &mut nodes {
        expect_no_event!(node);
    }
}

#[test]
fn node_drops() {
    let network = Network::new();
    let mut nodes = create_connected_nodes(&network, GROUP_SIZE + 2);
    drop_node(&mut nodes, 0);

    verify_kademlia_invariant_for_all_nodes(&nodes);
}

#[test]
fn churn() {
    let network = Network::new();
    let seed = Seed::new();
    let mut rng = XorShiftRng::from_seed(seed.0);

    let mut nodes = create_connected_nodes(&network, 20);

    for i in 0..100 {
        let len = nodes.len();
        if len > GROUP_SIZE + 2 && Range::new(0, 3).ind_sample(&mut rng) == 0 {
            let node0 = nodes.remove(Range::new(0, len).ind_sample(&mut rng)).name();
            let node1 = nodes.remove(Range::new(0, len - 1).ind_sample(&mut rng)).name();
            let node2 = nodes.remove(Range::new(0, len - 2).ind_sample(&mut rng)).name();
            trace!("Iteration {}: Removing {:?}, {:?}, {:?}",
                   i,
                   node0,
                   node1,
                   node2);
        } else {
            let proxy = Range::new(0, len).ind_sample(&mut rng);
            let index = Range::new(0, len + 1).ind_sample(&mut rng);
            let config = Config::with_contacts(&[nodes[proxy].handle.endpoint()]);
            nodes.insert(index,
                         TestNode::new(&network, false, Some(config.clone()), None));
            trace!("Iteration {}: Adding {:?}", i, nodes[index].name());
        }

        poll_and_resend(&mut nodes, &mut []);

        for node in &mut nodes {
            node.inner.clear_state();
        }
        verify_kademlia_invariant_for_all_nodes(&nodes);
    }
}

#[test]
fn node_joins_in_front() {
    let network = Network::new();
    let mut nodes = create_connected_nodes(&network, 2 * GROUP_SIZE);
    let config = Config::with_contacts(&[nodes[0].handle.endpoint()]);
    nodes.insert(0,
                 TestNode::new(&network, false, Some(config.clone()), None));
    let _ = poll_all(&mut nodes, &mut []);

    verify_kademlia_invariant_for_all_nodes(&nodes);
}

#[ignore]
#[test]
fn multiple_joining_nodes() {
    let network_size = 2 * GROUP_SIZE;
    let network = Network::new();
    let mut nodes = create_connected_nodes(&network, network_size);
    let config = Config::with_contacts(&[nodes[0].handle.endpoint()]);
    nodes.insert(0,
                 TestNode::new(&network, false, Some(config.clone()), None));
    nodes.insert(0,
                 TestNode::new(&network, false, Some(config.clone()), None));
    nodes.push(TestNode::new(&network, false, Some(config.clone()), None));
    let _ = poll_all(&mut nodes, &mut []);
    nodes.retain(|node| !node.routing_table().is_empty());
    let _ = poll_all(&mut nodes, &mut []);
    assert!(nodes.len() > network_size); // At least one node should have succeeded.

    verify_kademlia_invariant_for_all_nodes(&nodes);
}

#[test]
fn check_close_groups_for_group_size_nodes() {
    let nodes = create_connected_nodes(&Network::new(), GROUP_SIZE);
    let close_groups_complete = nodes.iter()
        .all(|n| nodes.iter().all(|m| m.close_group().contains(&n.name())));
    assert!(close_groups_complete);
}

#[test]
fn successful_put_request() {
    let network = Network::new();
    let seed = Seed::new();
    let mut rng = XorShiftRng::from_seed(seed.0);
    let mut nodes = create_connected_nodes(&network, GROUP_SIZE + 1);
    let mut clients = vec![TestClient::new(&network,
                                           Some(Config::with_contacts(&[nodes[0]
                                                                            .handle
                                                                            .endpoint()])),
                                           None)];
    let _ = poll_all(&mut nodes, &mut clients);
    expect_event!(clients[0], Event::Connected);

    let dst = Authority::ClientManager(clients[0].name());
    let bytes = rng.gen_iter().take(1024).collect();
    let immutable_data = ImmutableData::new(bytes);
    let data = Data::Immutable(immutable_data);
    let message_id = MessageId::new();

    assert!(clients[0].inner.send_put_request(dst,
                                              data.clone(),
                                              message_id).is_ok());

    let _ = poll_all(&mut nodes, &mut clients);

    let mut request_received_count = 0;
    for node in nodes.iter()
        .filter(|n| n.routing_table().is_close(&clients[0].name(), GROUP_SIZE)) {
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

    assert!(request_received_count >= QUORUM_SIZE);
}

#[test]
fn successful_get_request() {
    let network = Network::new();
    let seed = Seed::new();
    let mut rng = XorShiftRng::from_seed(seed.0);
    let mut nodes = create_connected_nodes(&network, GROUP_SIZE + 1);
    let mut clients = vec![TestClient::new(&network,
                                           Some(Config::with_contacts(&[nodes[0]
                                                                            .handle
                                                                            .endpoint()])),
                                           None)];
    let _ = poll_all(&mut nodes, &mut clients);
    expect_event!(clients[0], Event::Connected);

    let bytes = rng.gen_iter().take(1024).collect();
    let immutable_data = ImmutableData::new(bytes);
    let data = Data::Immutable(immutable_data.clone());
    let dst = Authority::NaeManager(data.name());
    let data_request = DataIdentifier::Immutable(data.name());
    let message_id = MessageId::new();

    assert!(clients[0].inner
                      .send_get_request(dst, data_request.clone(), message_id)
                      .is_ok());

    let _ = poll_all(&mut nodes, &mut clients);

    let mut request_received_count = 0;

    for node in nodes.iter().filter(|n| n.routing_table().is_close(&data.name(), GROUP_SIZE)) {
        loop {
            match node.event_rx.try_recv() {
                Ok(Event::Request { request: Request::Get(ref request, id), ref src, ref dst }) => {
                    request_received_count += 1;
                    if data_request == *request && message_id == id {
                        if let Err(_) = node.inner
                            .send_get_success(dst.clone(), src.clone(), data.clone(), id) {
                            trace!("Failed to send GetSuccess response");
                        }
                        break;
                    }
                }
                Ok(_) => (),
                _ => panic!("Event::Request not received"),
            }
        }
    }

    assert!(request_received_count >= QUORUM_SIZE);

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
    let network = Network::new();
    let seed = Seed::new();
    let mut rng = XorShiftRng::from_seed(seed.0);
    let mut nodes = create_connected_nodes(&network, GROUP_SIZE + 1);
    let mut clients = vec![TestClient::new(&network,
                                           Some(Config::with_contacts(&[nodes[0]
                                                                            .handle
                                                                            .endpoint()])),
                                           None)];
    let _ = poll_all(&mut nodes, &mut clients);
    expect_event!(clients[0], Event::Connected);

    let bytes = rng.gen_iter().take(1024).collect();
    let immutable_data = ImmutableData::new(bytes);
    let data = Data::Immutable(immutable_data.clone());
    let dst = Authority::NaeManager(data.name());
    let data_request = DataIdentifier::Immutable(data.name());
    let message_id = MessageId::new();

    assert!(clients[0].inner
                      .send_get_request(dst, data_request.clone(), message_id)
                      .is_ok());

    let _ = poll_all(&mut nodes, &mut clients);

    let mut request_received_count = 0;

    for node in nodes.iter().filter(|n| n.routing_table().is_close(&data.name(), GROUP_SIZE)) {
        loop {
            match node.event_rx.try_recv() {
                Ok(Event::Request { request: Request::Get(ref data_id, ref id),
                                    ref src,
                                    ref dst }) => {
                    request_received_count += 1;
                    if data_request == *data_id && message_id == *id {
                        if let Err(_) = node.inner
                            .send_get_failure(dst.clone(), src.clone(), *data_id, vec![], *id) {
                            trace!("Failed to send GetFailure response.");
                        }
                        break;
                    }
                }
                Ok(_) => (),
                _ => panic!("Event::Request not received"),
            }
        }
    }

    assert!(request_received_count >= QUORUM_SIZE);

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
    let network = Network::new();
    let seed = Seed::new();
    let mut rng = XorShiftRng::from_seed(seed.0);
    let mut nodes = create_connected_nodes(&network, 2 * GROUP_SIZE);
    let mut clients = vec![TestClient::new(&network,
                                           Some(Config::with_contacts(&[nodes[0]
                                                                            .handle
                                                                            .endpoint()])),
                                           Some(Endpoint(2 * GROUP_SIZE)))];
    let _ = poll_all(&mut nodes, &mut clients);
    expect_event!(clients[0], Event::Connected);

    let bytes = rng.gen_iter().take(1024).collect();
    let immutable_data = ImmutableData::new(bytes);
    let data = Data::Immutable(immutable_data.clone());
    let dst = Authority::NaeManager(data.name());
    let data_request = DataIdentifier::Immutable(data.name());
    let message_id = MessageId::new();

    assert!(clients[0].inner
                      .send_get_request(dst, data_request.clone(), message_id)
                      .is_ok());

    let _ = poll_all(&mut nodes, &mut clients);

    let mut request_received_count = 0;

    for node in nodes.iter().filter(|n| n.routing_table().is_close(&data.name(), GROUP_SIZE)) {
        loop {
            match node.event_rx.try_recv() {
                Ok(Event::Request { request: Request::Get(ref request, ref id),
                                    ref src,
                                    ref dst }) => {
                    request_received_count += 1;
                    if data_request == *request && message_id == *id {
                        if let Err(_) = node.inner
                            .send_get_success(dst.clone(), src.clone(), data.clone(), *id) {
                            trace!("Failed to send GetSuccess response");
                        }
                        break;
                    }
                }
                Ok(_) => (),
                _ => panic!("Event::Request not received"),
            }
        }
    }

    assert!(request_received_count >= QUORUM_SIZE);

    clients[0].handle.0.borrow_mut().disconnect(&nodes[0].handle.0.borrow().peer_id);
    nodes[0].handle.0.borrow_mut().disconnect(&clients[0].handle.0.borrow().peer_id);

    let _ = poll_all(&mut nodes, &mut clients);

    for client in clients {
        if let Ok(Event::Response { .. }) = client.event_rx.try_recv() {
            panic!("Unexpected Event::Response received");
        }
    }
}
