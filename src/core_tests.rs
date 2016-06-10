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

use rand::{self, Rng};
use rand::distributions::{IndependentSample, Range};
use std::cmp;
use std::collections::HashSet;
use std::sync::mpsc;
use xor_name::XorName;

use action::Action;
use authority::Authority;
use core::{Core, Role, RoutingTable, GROUP_SIZE};
use data::{Data, DataIdentifier, ImmutableData};
use error::InterfaceError;
use event::Event;
use id::FullId;
use itertools::Itertools;
use kademlia_routing_table::ContactInfo;
use messages::{Request, Response, UserMessage, CLIENT_GET_PRIORITY, DEFAULT_PRIORITY,
               RELOCATE_PRIORITY};
use mock_crust::{self, Config, Endpoint, Network, ServiceHandle};
use types::{MessageId, RoutingActionSender};

// kademlia_routing_table::QUORUM_SIZE is private and subject to change!
const QUORUM_SIZE: usize = 5;

// Poll one event per node. Otherwise, all events in a single node are polled before moving on.
const BALANCED_POLLING: bool = true;

struct TestNode {
    handle: ServiceHandle,
    core: Core,
    event_rx: mpsc::Receiver<Event>,
    action_tx: RoutingActionSender,
}

impl TestNode {
    fn new(network: &Network,
           role: Role,
           config: Option<Config>,
           endpoint: Option<Endpoint>)
           -> Self {
        let handle = network.new_service_handle(config, endpoint);
        let (event_tx, event_rx) = mpsc::channel();

        let (action_tx, core) = mock_crust::make_current(&handle,
                                                         || Core::new(event_tx, role, None));

        TestNode {
            handle: handle,
            core: core,
            event_rx: event_rx,
            action_tx: action_tx,
        }
    }

    fn poll(&mut self) -> bool {
        let mut result = false;

        while self.core.poll() {
            result = true;
        }

        result
    }

    fn name(&self) -> &XorName {
        self.core.name()
    }

    fn close_group(&self) -> Vec<XorName> {
        self.core.close_group()
    }

    fn routing_table(&self) -> &RoutingTable {
        self.core.routing_table()
    }

    /// Respond to a `Get` request indicating success and sending the requested data.
    pub fn send_get_success(&self,
                            src: Authority,
                            dst: Authority,
                            data: Data,
                            id: MessageId,
                            result_tx: mpsc::Sender<Result<(), InterfaceError>>)
                            -> Result<(), InterfaceError> {
        let user_msg = UserMessage::Response(Response::GetSuccess(data, id));
        let priority = if let Authority::Client { .. } = dst {
            CLIENT_GET_PRIORITY
        } else {
            RELOCATE_PRIORITY
        };
        self.send_action(src, dst, user_msg, priority, result_tx)
    }

    /// Respond to a `Get` request indicating failure.
    pub fn send_get_failure(&self,
                            src: Authority,
                            dst: Authority,
                            data_id: DataIdentifier,
                            external_error_indicator: Vec<u8>,
                            id: MessageId,
                            result_tx: mpsc::Sender<Result<(), InterfaceError>>)
                            -> Result<(), InterfaceError> {
        let user_msg = UserMessage::Response(Response::GetFailure {
            id: id,
            data_id: data_id,
            external_error_indicator: external_error_indicator,
        });
        let priority = if let Authority::Client { .. } = dst {
            CLIENT_GET_PRIORITY
        } else {
            RELOCATE_PRIORITY
        };
        self.send_action(src, dst, user_msg, priority, result_tx)
    }

    fn send_action(&self,
                   src: Authority,
                   dst: Authority,
                   user_msg: UserMessage,
                   priority: u8,
                   result_tx: mpsc::Sender<Result<(), InterfaceError>>)
                   -> Result<(), InterfaceError> {
        try!(self.action_tx.send(Action::NodeSendMessage {
            src: src,
            dst: dst,
            content: user_msg,
            result_tx: result_tx,
            priority: priority,
        }));
        Ok(())
    }
}

struct TestClient {
    handle: ServiceHandle,
    core: Core,
    event_rx: mpsc::Receiver<Event>,
    action_tx: RoutingActionSender,
}

impl TestClient {
    fn new(network: &Network, config: Option<Config>, endpoint: Option<Endpoint>) -> Self {
        let handle = network.new_service_handle(config, endpoint);
        let (event_tx, event_rx) = mpsc::channel();
        let full_id = FullId::new();

        let (action_tx, core) =
            mock_crust::make_current(&handle, || Core::new(event_tx, Role::Client, Some(full_id)));

        TestClient {
            handle: handle,
            core: core,
            event_rx: event_rx,
            action_tx: action_tx,
        }
    }

    fn poll(&mut self) -> bool {
        let mut result = false;

        while self.core.poll() {
            result = true;
        }

        result
    }

    fn name(&self) -> &XorName {
        self.core.name()
    }

    fn send_put_request(&self,
                        dst: Authority,
                        data: Data,
                        message_id: MessageId,
                        result_tx: mpsc::Sender<Result<(), InterfaceError>>)
                        -> Result<(), InterfaceError> {
        self.send_action(Request::Put(data, message_id),
                         dst,
                         DEFAULT_PRIORITY,
                         result_tx)
    }

    fn send_get_request(&mut self,
                        dst: Authority,
                        data_request: DataIdentifier,
                        message_id: MessageId,
                        result_tx: mpsc::Sender<Result<(), InterfaceError>>)
                        -> Result<(), InterfaceError> {
        self.send_action(Request::Get(data_request, message_id),
                         dst,
                         CLIENT_GET_PRIORITY,
                         result_tx)
    }

    fn send_action(&self,
                   content: Request,
                   dst: Authority,
                   priority: u8,
                   result_tx: mpsc::Sender<Result<(), InterfaceError>>)
                   -> Result<(), InterfaceError> {
        let action = Action::ClientSendRequest {
            content: content,
            dst: dst,
            priority: priority,
            result_tx: result_tx,
        };

        try!(self.action_tx.send(action));
        Ok(())
    }
}

/// Expect that the node raised an event matching the given pattern, panics if
/// not.
macro_rules! expect_event {
    ($node:expr, $pattern:pat) => {
        match $node.event_rx.try_recv() {
            Ok($pattern) => (),
            other => panic!("Expected Ok({}), got {:?}", stringify!($pattern), other),
        }
    }
}

/// Process all events. Returns whether there were any events.
fn poll_all(nodes: &mut [TestNode], clients: &mut [TestClient]) -> bool {
    let mut result = false;
    loop {
        let mut n = false;
        if BALANCED_POLLING {
            nodes.iter_mut().foreach(|node| n = n || node.core.poll());
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
    nodes.push(TestNode::new(network, Role::FirstNode, None, Some(Endpoint(0))));
    nodes[0].poll();

    let config = Config::with_contacts(&[nodes[0].handle.endpoint()]);

    // Create other nodes using the seed node endpoint as bootstrap contact.
    for i in 1..size {
        nodes.push(TestNode::new(network, Role::Node, Some(config.clone()), Some(Endpoint(i))));
        let _ = poll_all(&mut nodes, &mut []);
    }

    let n = cmp::min(nodes.len(), GROUP_SIZE) - 1;

    for node in &nodes {
        expect_event!(node, Event::Connected);
        for _ in 0..n {
            expect_event!(node, Event::NodeAdded(..))
        }
    }

    nodes
}

// Drop node at index and verify its close group receives NodeLost.
fn drop_node(nodes: &mut Vec<TestNode>, index: usize) {
    let node = nodes.remove(index);
    let name = *node.name();
    let close_names = node.close_group();

    drop(node);

    let _ = poll_all(nodes, &mut []);

    for node in nodes.iter().filter(|n| close_names.contains(n.name())) {
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
fn entry_names_in_bucket(table: &RoutingTable, bucket_index: usize) -> HashSet<XorName> {
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
fn node_names_in_bucket(nodes: &[TestNode],
                        name: &XorName,
                        bucket_index: usize)
                        -> HashSet<XorName> {
    nodes.iter()
        .filter(|node| name.bucket_index(node.name()) == bucket_index)
        .map(|node| *node.name())
        .collect()
}

// Verify that the kademlia invariant is upheld for the node at `index`.
fn verify_kademlia_invariant_for_node(nodes: &[TestNode], index: usize) {
    let node = &nodes[index];
    let mut count = nodes.len() - 1;
    let mut bucket_index = 0;

    while count > 0 {
        let entries = entry_names_in_bucket(node.routing_table(), bucket_index);
        let actual_bucket = node_names_in_bucket(nodes, node.name(), bucket_index);
        if entries.len() < GROUP_SIZE {
            assert!(actual_bucket == entries,
                    "Node: {:?}, expected: {:?}. found: {:?}",
                    node.name(),
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
    let client = TestNode::new(&network,
                               Role::Client,
                               Some(Config::with_contacts(&[nodes[0].handle.endpoint()])),
                               None);

    nodes.push(client);

    let _ = poll_all(&mut nodes, &mut []);

    expect_event!(nodes.iter().last().unwrap(), Event::Connected);
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
    let mut nodes = create_connected_nodes(&network, 20);

    let mut rng = rand::thread_rng();
    for i in 0..100 {
        let len = nodes.len();
        if len > GROUP_SIZE + 2 && Range::new(0, 3).ind_sample(&mut rng) == 0 {
            let node0 = *nodes.remove(Range::new(0, len).ind_sample(&mut rng)).name();
            let node1 = *nodes.remove(Range::new(0, len - 1).ind_sample(&mut rng)).name();
            let node2 = *nodes.remove(Range::new(0, len - 2).ind_sample(&mut rng)).name();
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
                         TestNode::new(&network, Role::Node, Some(config.clone()), None));
            trace!("Iteration {}: Adding {:?}", i, nodes[index].name());
        }

        loop {
            let mut state_changed = poll_all(&mut nodes, &mut []);
            for node in &mut nodes {
                state_changed = state_changed || node.core.resend_unacknowledged();
            }
            if !state_changed {
                break;
            }
        }

        for node in &mut nodes {
            node.core.clear_state();
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
                 TestNode::new(&network, Role::Node, Some(config.clone()), None));
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
                 TestNode::new(&network, Role::Node, Some(config.clone()), None));
    nodes.insert(0,
                 TestNode::new(&network, Role::Node, Some(config.clone()), None));
    nodes.push(TestNode::new(&network, Role::Node, Some(config.clone()), None));
    let _ = poll_all(&mut nodes, &mut []);
    nodes.retain(|node| !node.core.routing_table().is_empty());
    let _ = poll_all(&mut nodes, &mut []);
    assert!(nodes.len() > network_size); // At least one node should have succeeded.

    verify_kademlia_invariant_for_all_nodes(&nodes);
}

#[test]
fn check_close_groups_for_group_size_nodes() {
    let nodes = create_connected_nodes(&Network::new(), GROUP_SIZE);
    let close_groups_complete = nodes.iter()
        .all(|n| nodes.iter().all(|m| m.name() == n.name() || m.close_group().contains(n.name())));
    assert!(close_groups_complete);
}

#[test]
fn successful_put_request() {
    let network = Network::new();
    let mut nodes = create_connected_nodes(&network, GROUP_SIZE + 1);
    let mut clients = vec![TestClient::new(&network,
                                           Some(Config::with_contacts(&[nodes[0]
                                                                            .handle
                                                                            .endpoint()])),
                                           None)];
    let _ = poll_all(&mut nodes, &mut clients);
    expect_event!(clients[0], Event::Connected);

    let (result_tx, _result_rx) = mpsc::channel();
    let dst = Authority::ClientManager(*clients[0].name());
    let bytes = rand::thread_rng().gen_iter().take(50 * 1024).collect();
    let immutable_data = ImmutableData::new(bytes);
    let data = Data::Immutable(immutable_data);
    let message_id = MessageId::new();

    assert!(clients[0].send_put_request(dst, data.clone(), message_id, result_tx).is_ok());

    let _ = poll_all(&mut nodes, &mut clients);

    let mut request_received_count = 0;
    for node in nodes.iter().filter(|n| n.routing_table().is_close(clients[0].name(), GROUP_SIZE)) {
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
    let mut nodes = create_connected_nodes(&network, GROUP_SIZE + 1);
    let mut clients = vec![TestClient::new(&network,
                                           Some(Config::with_contacts(&[nodes[0]
                                                                            .handle
                                                                            .endpoint()])),
                                           None)];
    let _ = poll_all(&mut nodes, &mut clients);
    expect_event!(clients[0], Event::Connected);

    let (result_tx, _result_rx) = mpsc::channel();
    let bytes = rand::thread_rng().gen_iter().take(30 * 1024).collect();
    let immutable_data = ImmutableData::new(bytes);
    let data = Data::Immutable(immutable_data.clone());
    let dst = Authority::NaeManager(data.name());
    let data_request = DataIdentifier::Immutable(data.name());
    let message_id = MessageId::new();

    assert!(clients[0]
        .send_get_request(dst, data_request.clone(), message_id, result_tx.clone())
        .is_ok());

    let _ = poll_all(&mut nodes, &mut clients);

    let mut request_received_count = 0;

    for node in nodes.iter().filter(|n| n.routing_table().is_close(&data.name(), GROUP_SIZE)) {
        loop {
            match node.event_rx.try_recv() {
                Ok(Event::Request { request: Request::Get(ref request, id), ref src, ref dst }) => {
                    request_received_count += 1;
                    if data_request == *request && message_id == id {
                        if let Err(_) = node.send_get_success(dst.clone(),
                                                              src.clone(),
                                                              data.clone(),
                                                              id,
                                                              result_tx.clone()) {
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
    let mut nodes = create_connected_nodes(&network, GROUP_SIZE + 1);
    let mut clients = vec![TestClient::new(&network,
                                           Some(Config::with_contacts(&[nodes[0]
                                                                            .handle
                                                                            .endpoint()])),
                                           None)];
    let _ = poll_all(&mut nodes, &mut clients);
    expect_event!(clients[0], Event::Connected);

    let (result_tx, _result_rx) = mpsc::channel();
    let bytes = rand::thread_rng().gen_iter().take(1024).collect();
    let immutable_data = ImmutableData::new(bytes);
    let data = Data::Immutable(immutable_data.clone());
    let dst = Authority::NaeManager(data.name());
    let data_request = DataIdentifier::Immutable(data.name());
    let message_id = MessageId::new();

    assert!(clients[0]
        .send_get_request(dst, data_request.clone(), message_id, result_tx.clone())
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
                        if let Err(_) = node.send_get_failure(dst.clone(),
                                                              src.clone(),
                                                              *data_id,
                                                              vec![],
                                                              *id,
                                                              result_tx.clone()) {
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
    let mut nodes = create_connected_nodes(&network, 2 * GROUP_SIZE);
    let mut clients = vec![TestClient::new(&network,
                                           Some(Config::with_contacts(&[nodes[0]
                                                                            .handle
                                                                            .endpoint()])),
                                           Some(Endpoint(2 * GROUP_SIZE)))];
    let _ = poll_all(&mut nodes, &mut clients);
    expect_event!(clients[0], Event::Connected);

    let (result_tx, _result_rx) = mpsc::channel();
    let bytes = rand::thread_rng().gen_iter().take(1024).collect();
    let immutable_data = ImmutableData::new(bytes);
    let data = Data::Immutable(immutable_data.clone());
    let dst = Authority::NaeManager(data.name());
    let data_request = DataIdentifier::Immutable(data.name());
    let message_id = MessageId::new();

    assert!(clients[0]
        .send_get_request(dst, data_request.clone(), message_id, result_tx.clone())
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
                        if let Err(_) = node.send_get_success(dst.clone(),
                                                              src.clone(),
                                                              data.clone(),
                                                              *id,
                                                              result_tx.clone()) {
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
