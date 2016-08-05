// Copyright 2015 MaidSafe.net limited.
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

#![cfg(test)]

use std::cmp;
use std::fmt::{self, Binary, Debug, Formatter};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{ATOMIC_USIZE_INIT, AtomicUsize, Ordering};

use super::contact_info::ContactInfo;
use rand;
use super::result::{AddedNodeDetails, DroppedNodeDetails};
use super::routing_table::{Destination, RoutingTable};
use super::xorable::Xorable;

const GROUP_SIZE: usize = 8;

#[derive(Clone, Eq, PartialEq)]
struct Contact(u64);

impl ContactInfo for Contact {
    type Name = u64;

    fn name(&self) -> &u64 {
        &self.0
    }
}


impl Binary for Contact {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let val = self.0;
        write!(f, "{:b}", val)
    }
}

impl Debug for Contact {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let val = self.0;
        write!(f, "{:b}", val)
    }
}

// Simulated network endpoint. In the real networks, this would be something
// like ip address and port pair.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct Endpoint(usize);

// Simulated connection to an endpoint.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct Connection(Endpoint);

type MessageId = usize;

// This is used to generate unique message ids.
static mut MESSAGE_ID_COUNTER: AtomicUsize = ATOMIC_USIZE_INIT;

#[allow(unsafe_code)]
fn next_message_id() -> MessageId {
    unsafe { MESSAGE_ID_COUNTER.fetch_add(1, Ordering::Relaxed) }
}

#[derive(Clone, Debug)]
struct Message {
    id: MessageId,
    src: Destination<u64>,
    dst: Destination<u64>,
    // Names of all the nodes the message passed through.
    route: Vec<u64>,
    // Which of the `GROUP_SIZE` parallel routes to take.
    route_num: usize,
}

impl Message {
    fn new(src: Destination<u64>, dst: Destination<u64>, route_num: usize) -> Self {
        Message {
            id: next_message_id(),
            src: src,
            dst: dst,
            route: vec![*src.name()],
            route_num: route_num,
        }
    }

    fn hop_name(&self) -> &u64 {
        self.route.last().unwrap()
    }
}

// Records how many times a particular message was received and/or sent by a node.
struct MessageStats(HashMap<MessageId, (usize, usize)>);

impl MessageStats {
    fn new() -> Self {
        MessageStats(HashMap::new())
    }

    fn add_received(&mut self, id: MessageId) -> usize {
        let entry = self.entry_mut(id);
        entry.0 += 1;
        entry.0 - 1
    }

    fn add_sent(&mut self, id: MessageId) -> usize {
        let entry = self.entry_mut(id);
        entry.1 += 1;
        entry.1 - 1
    }

    fn get_received(&self, id: MessageId) -> usize {
        self.entry(id).0
    }

    fn get_sent(&self, id: MessageId) -> usize {
        self.entry(id).1
    }

    fn entry(&self, id: MessageId) -> (usize, usize) {
        self.0.get(&id).cloned().unwrap_or((0, 0))
    }

    fn entry_mut(&mut self, id: MessageId) -> &mut (usize, usize) {
        self.0.entry(id).or_insert((0, 0))
    }
}

// Action performed on the network.
#[allow(variant_size_differences)]
enum Action {
    // Send a message via the connection.
    Send(Connection, Message),

    // Connect the nodes at the given endpoints.
    Connect(Endpoint, Endpoint),

    // Find close group to the given name and connect each member of it to the
    // node at the given endpoint.
    ConnectToCloseGroup(Endpoint, u64),
}

// Simulated node.
// The nodes can only interact with the network indirectly, by returning lists
// of Actions, so we are sure a node doesn't do anything it wouldn't be able
// to do in the real world.
struct Node {
    name: u64,
    endpoint: Endpoint,
    table: RoutingTable<Contact>,
    connections: HashMap<u64, Connection>,
    message_stats: MessageStats,
    inbox: HashMap<MessageId, Message>,
}

impl Debug for Node {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "node {:?}", self.name)
    }
}

impl Node {
    fn new(name: u64, endpoint: Endpoint) -> Self {
        let table = RoutingTable::new(Contact(name.clone()), GROUP_SIZE);

        Node {
            name: name,
            endpoint: endpoint,
            table: table,
            connections: HashMap::new(),
            message_stats: MessageStats::new(),
            inbox: HashMap::new(),
        }
    }

    fn is_connected_to(&self, name: &u64) -> bool {
        self.table.contains(name)
    }

    fn is_close(&self, name: &u64) -> bool {
        self.table.is_close(name, GROUP_SIZE)
    }

    fn send_message(&mut self, mut message: Message, handle: bool) -> Vec<Action> {
        let mut actions = Vec::new();

        let targets = self.table
            .target_nodes(message.dst.clone(), message.hop_name(), message.route_num);

        message.route.push(self.name.clone());

        for target in targets {
            if let Some(&connection) = self.connections.get(target.name()) {
                actions.push(Action::Send(connection, message.clone()));
                let _ = self.message_stats.add_sent(message.id);
            }
        }

        // Handle the message ourselves if we need to.
        if handle && self.table.is_recipient(message.dst.clone()) &&
           self.message_stats.get_received(message.id) == 0 {
            actions.extend(self.on_message(message, false));
        }

        actions
    }

    fn on_message(&mut self, message: Message, relay: bool) -> Vec<Action> {
        let mut actions = Vec::new();

        self.check_direction(&message);

        if self.message_stats.add_received(message.id) > GROUP_SIZE {
            return actions;
        }

        if relay {
            actions.extend(self.send_message(message.clone(), false));
        }

        if self.table.is_recipient(message.dst.clone()) {
            let _ = self.inbox.insert(message.id, message);
        }

        actions
    }

    fn check_direction(&self, message: &Message) {
        if !self.is_swarm(&message.dst, message.hop_name()) {
            if message.dst.name().cmp_distance(message.hop_name(), &self.name) ==
               cmp::Ordering::Less {
                panic!("Direction check failed {:?}", message);
            }
        }
    }

    fn is_swarm(&self, dst: &Destination<u64>, hop_name: &u64) -> bool {
        dst.is_group() &&
        match self.table.other_close_nodes(dst.name(), GROUP_SIZE) {
            None => false,
            Some(close_group) => close_group.into_iter().any(|n| n.name() == hop_name),
        }
    }
}

// Handle to node.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct NodeHandle(Endpoint);

// Simulated network. This struct tries to simulate real-world network consisting
// of many nodes. It should expose only operations that would be possible to
// execute on a real network. For example, nodes cannot access other nodes in
// any other means than sending them messages via this network. So nodes don't
// know public endpoints of other nodes unless they have them in their routing
// tables. Operations on the network (for example sending a message to an endpoint)
// are simulated by returning a list of Actions, which the network then executes.
// This is to make sure nodes are only doing what they would be able to do in
// the real world.
struct Network {
    endpoint_counter: usize,
    nodes: HashMap<NodeHandle, Node>,
    names: HashMap<u64, NodeHandle>,
}

impl Network {
    fn new() -> Self {
        Network {
            endpoint_counter: 0,
            nodes: HashMap::new(),
            names: HashMap::new(),
        }
    }

    // Add a node with randomly generated name to the network. Returns a
    // node handle which can be used to perform operations with the node.
    fn add_node(&mut self) -> NodeHandle {
        let endpoint = Endpoint(self.endpoint_counter);
        self.endpoint_counter += 1;

        let handle = NodeHandle(endpoint);
        let name = rand::random::<u64>();
        let node = Node::new(name.clone(), endpoint);

        let _ = self.nodes.insert(handle, node);
        let _ = self.names.insert(name, handle);

        handle
    }

    fn nodes_count(&self) -> usize {
        self.nodes.len()
    }

    fn get_all_nodes(&self) -> Vec<NodeHandle> {
        self.nodes.keys().cloned().collect()
    }

    fn get_random_node(&self) -> NodeHandle {
        self.get_random_nodes(1)[0]
    }

    fn get_two_random_nodes(&self) -> (NodeHandle, NodeHandle) {
        let nodes = self.get_random_nodes(2);
        (nodes[0], nodes[1])
    }

    // Get all nodes that believe they are close to the given name.
    fn get_nodes_close_to(&self, name: &u64) -> Vec<NodeHandle> {
        self.nodes
            .iter()
            .filter(|&(_, node)| node.is_close(name))
            .map(|(&handle, _)| handle)
            .collect()
    }

    #[allow(unused)]
    fn get_node_by_name(&self, name: &u64) -> NodeHandle {
        self.find_node_by_name(name).unwrap()
    }

    fn find_node_by_name(&self, name: &u64) -> Option<NodeHandle> {
        self.names.get(name).cloned()
    }

    fn get_node_name(&self, handle: NodeHandle) -> u64 {
        self.get_node_ref(handle).name.clone()
    }

    // Bootstrap the node by fully populating its routing table.
    fn bootstrap_node(&mut self, node0: NodeHandle) {
        let mut actions = Vec::new();

        for node1 in self.get_all_nodes() {
            if node0 == node1 {
                continue;
            }

            actions.append(&mut self.connect_if_allowed(node0, node1));
        }

        self.execute(actions);
    }

    // Quickly bootstrap all nodes in the network. This is faster than
    // bootstrapping nodes one by one.
    fn bootstrap_all_nodes(&mut self) {
        let mut actions = Vec::new();
        let nodes = self.get_all_nodes();

        for i in 0..nodes.len() {
            for j in (i + 1)..nodes.len() {
                let node0 = nodes[i];
                let node1 = nodes[j];

                actions.append(&mut self.connect_if_allowed(node0, node1));
            }
        }

        self.execute(actions);
    }

    fn remove_node(&mut self, node0: NodeHandle) {
        let mut actions = Vec::new();
        let name0 = self.get_node_name(node0);

        let _ = self.nodes.remove(&node0);
        let _ = self.names.remove(&name0);

        for node1 in self.get_all_nodes() {
            actions.append(&mut self.disconnect(node1, &name0));
        }

        self.execute(actions)
    }

    fn connect_if_allowed(&mut self, node0: NodeHandle, node1: NodeHandle) -> Vec<Action> {
        let mut actions = Vec::new();

        {
            let node0 = self.get_node_ref(node0);
            let node1 = self.get_node_ref(node1);

            let can_connect = (node0.table.need_to_add(&node1.name) &&
                               node1.table.allow_connection(&node0.name)) ||
                              (node1.table.need_to_add(&node0.name) &&
                               node0.table.allow_connection(&node1.name));

            if !can_connect {
                return actions;
            }
        }

        actions.append(&mut self.connect(node0, node1));
        actions.append(&mut self.connect(node1, node0));
        actions
    }

    // Connect node0 and node1 by adding node1 to node0's routing table.
    // This forms only half of the connection. Full connection is achieved by
    // also calling connect(node1, node0)
    fn connect(&mut self, node0: NodeHandle, node1: NodeHandle) -> Vec<Action> {
        let (node1_name, node1_endpoint) = {
            let node1 = self.get_node_ref(node1);
            (node1.name.clone(), node1.endpoint)
        };

        let node0 = self.get_node_mut_ref(node0);
        let _ = node0.table.add(Contact(node1_name));

        Vec::new()
    }

    // Disconnect the node with `name` from `node0`.
    fn disconnect(&mut self, node0: NodeHandle, name: &u64) -> Vec<Action> {
        let node = self.get_node_mut_ref(node0);
        let _ = node.table.remove(name);
        let _ = node.connections.remove(&name);

        Vec::new()
    }

    // Send a message from the node.
    fn send_message(&mut self, node_handle: NodeHandle, message: Message) {
        let actions = self.get_node_mut_ref(node_handle).send_message(message, true);
        self.execute(actions);
    }

    fn is_node_connected_to(&self, node0: NodeHandle, node1: NodeHandle) -> bool {
        let node0 = self.get_node_ref(node0);
        let node1 = self.get_node_ref(node1);

        node0.is_connected_to(&node1.name)
    }

    fn get_contact_count(&self, node: NodeHandle) -> usize {
        self.get_node_ref(node).table.len()
    }

    // Did the node receive a message with the id?
    fn has_node_message_in_inbox(&self, node: NodeHandle, message_id: MessageId) -> bool {
        self.get_node_ref(node).inbox.contains_key(&message_id)
    }

    #[allow(unused)]
    fn get_message_from_inbox(&self, node: NodeHandle, message_id: MessageId) -> Option<&Message> {
        self.get_node_ref(node).inbox.get(&message_id)
    }

    fn get_message_stats(&self, node: NodeHandle) -> &MessageStats {
        &self.get_node_ref(node).message_stats
    }

    // --------------------------------------------------------------------------
    // The following methods are INTERNAL and should not be called in tests.
    // --------------------------------------------------------------------------

    fn get_random_nodes(&self, count: usize) -> Vec<NodeHandle> {
        let mut rng = rand::thread_rng();
        rand::sample(&mut rng, self.nodes.keys().cloned(), count)
    }

    fn get_node_ref(&self, handle: NodeHandle) -> &Node {
        self.nodes.get(&handle).unwrap()
    }

    fn get_node_mut_ref(&mut self, handle: NodeHandle) -> &mut Node {
        self.nodes.get_mut(&handle).unwrap()
    }

    fn get_node_mut_ref_by_endpoint(&mut self, endpoint: Endpoint) -> &mut Node {
        self.get_node_mut_ref(NodeHandle(endpoint))
    }

    // Execute list of network actions on this network.
    fn execute(&mut self, actions: Vec<Action>) {
        let mut queue = VecDeque::with_capacity(actions.len());

        for action in actions {
            queue.push_back(action);
        }

        while let Some(action) = queue.pop_front() {
            let new_actions = match action {
                Action::Send(connection, message) => {
                    let node = self.get_node_mut_ref_by_endpoint(connection.0);
                    node.on_message(message, true)
                }

                Action::Connect(endpoint0, endpoint1) => {
                    self.connect_if_allowed(NodeHandle(endpoint0), NodeHandle(endpoint1))
                }

                Action::ConnectToCloseGroup(endpoint, name) => {
                    let node0 = NodeHandle(endpoint);
                    self.get_nodes_close_to(&name)
                        .into_iter()
                        .flat_map(|node1| self.connect_if_allowed(node0, node1))
                        .collect()
                }
            };

            for new_action in new_actions {
                queue.push_back(new_action);
            }
        }
    }
}

// Number of test samples per each test.
const SAMPLES: usize = 100;

// Number of nodes in the network before starting the test samples.
const INITIAL_NODE_COUNT: usize = 32;

fn create_network(count: usize) -> Network {
    let mut network = Network::new();

    for _ in 0..count {
        let _ = network.add_node();
    }

    network.bootstrap_all_nodes();
    network
}

fn run_tests<F>(mut test_fun: F)
    where F: FnMut(&mut Network)
{
    use rand::Rng;

    let mut network = create_network(INITIAL_NODE_COUNT);

    // Test with unchanging number of nodes that are already bootstrapped.
    for _ in 0..SAMPLES {
        test_fun(&mut network);
    }

    // Every test sample adds or removes one node.
    for _ in 0..SAMPLES {
        if rand::random::<bool>() || network.nodes_count() == 0 {
            // join
            let node = network.add_node();
            network.bootstrap_node(node);
        } else {
            // leave
            let node = network.get_random_node();
            network.remove_node(node);
        }

        if network.nodes_count() < 2 {
            continue;
        }

        test_fun(&mut network);
    }
}

#[test]
fn number_of_nodes_close_to_any_name_is_equal_to_group_size() {
    use std::cmp;

    run_tests(|network| {
        let name = rand::random();
        let expected_count = cmp::min(network.nodes_count(), GROUP_SIZE);
        assert_eq!(network.get_nodes_close_to(&name).len(), expected_count);
    });
}

#[test]
fn node_is_connected_to_every_node_in_its_close_group() {
    run_tests(|network| {
        let node = network.get_node_name(network.get_random_node());
        let close_group = network.get_nodes_close_to(&node);

        for node0 in &close_group {
            for node1 in &close_group {
                if node0 == node1 {
                    continue;
                }
                assert!(network.is_node_connected_to(*node0, *node1));
                assert!(network.is_node_connected_to(*node1, *node0));
            }
        }
    });
}

#[test]
fn nodes_in_close_group_of_any_name_are_connected_to_each_other() {
    run_tests(|network| {
        let name = rand::random();
        let close_group = network.get_nodes_close_to(&name);

        for node0 in &close_group {
            for node1 in &close_group {
                if node0 == node1 {
                    continue;
                }
                assert!(network.is_node_connected_to(*node0, *node1));
                assert!(network.is_node_connected_to(*node1, *node0));
            }
        }
    });
}

#[test]
fn messages_for_individual_nodes_reach_their_recipients() {
    run_tests(|network| {
        let (node_a, node_b) = network.get_two_random_nodes();
        let node_a_name = network.get_node_name(node_a);
        let node_b_name = network.get_node_name(node_b);
        for route_num in 0..GROUP_SIZE {
            let message = Message::new(Destination::Node(node_a_name),
                                       Destination::Node(node_b_name),
                                       route_num);

            let message_id = message.id;

            network.send_message(node_a, message);
            assert!(network.has_node_message_in_inbox(node_b, message_id));
        }
    });
}

#[test]
fn messages_for_groups_reach_all_members_of_the_recipient_group() {
    run_tests(|network| {
        let sender = network.get_random_node();
        let sender_name = network.get_node_name(sender);

        let group_name = rand::random();
        let group_members = network.get_nodes_close_to(&group_name);

        for route_num in 0..GROUP_SIZE {
            let message = Message::new(Destination::Node(sender_name),
                                       Destination::Group(group_name, GROUP_SIZE),
                                       route_num);

            let message_id = message.id;

            network.send_message(sender, message);

            for node in &group_members {
                assert!(network.has_node_message_in_inbox(*node, message_id));
            }
        }
    });
}

#[test]
fn no_multiple_copies() {
    run_tests(|network| {
        let (node_a, node_b) = network.get_two_random_nodes();
        let node_a_name = network.get_node_name(node_a);
        let node_b_name = network.get_node_name(node_b);

        let message = Message::new(Destination::Node(node_a_name),
                                   Destination::Node(node_b_name),
                                   0);
        let message_id = message.id;

        network.send_message(node_a, message);

        for node in network.get_all_nodes() {
            let sent = network.get_message_stats(node).get_sent(message_id);
            assert!(sent <= 1,
                    "Node {:?} sent {} copies of a message from {:?} to {:?}.",
                    network.get_node_name(node),
                    sent,
                    node_a_name,
                    node_b_name);
        }
    });
}
