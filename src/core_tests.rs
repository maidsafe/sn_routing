// Copyright 2016 MaidSafe.net limited.
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

#![allow(unused)]

use std::cmp;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use action::Action;
use core::Core;
use crust_mock::{self, Config, Device, Endpoint, Network};
use event::Event;
use kademlia_routing_table::GROUP_SIZE;
use maidsafe_utilities::thread::RaiiThreadJoiner;
use maidsafe_utilities::log;
use test_utils::{recv_with_timeout, iter_with_timeout};
use types::RoutingActionSender;

#[cfg(feature = "use-mock-crust")]
const TIMEOUT_MS : u64 = 200;

#[cfg(not(feature = "use-mock-crust"))]
const TIMEOUT_MS : u64 = 2500;

fn timeout() -> Duration {
    Duration::from_millis(TIMEOUT_MS)
}

struct TestNode {
    device: Device,
    action_tx: RoutingActionSender,
    event_rx: mpsc::Receiver<Event>,
    num_connections: usize,
    _core_joiner: RaiiThreadJoiner,
}

impl TestNode {
    fn new(network: &Network,
           client_restriction: bool,
           config: Option<Config>,
           endpoint: Option<Endpoint>)
           -> Self {
        let device = network.new_device(config, endpoint);
        let (event_tx, event_rx) = mpsc::channel();

        let (action_tx, core_joiner) = crust_mock::make_current(&device, || {
            Core::new(event_tx, client_restriction, None).unwrap()
        });

        TestNode {
            device: device,
            action_tx: action_tx,
            event_rx: event_rx,
            num_connections: 0,
            _core_joiner: core_joiner,
        }
    }

    fn wait_for_connections(&mut self, goal: usize) {
        if self.num_connections >= goal {
            return;
        }

        for event in iter_with_timeout(&self.event_rx, timeout()) {
            match event {
                Event::NodeAdded(..) => self.num_connections += 1,
                Event::NodeLost(..) => self.num_connections -= 1,
                _ => (),
            }

            if self.num_connections >= goal {
                break;
            }
        }

        assert!(self.num_connections >= goal,
                "{:?} connected to only {} out of {} required nodes",
                self.device.endpoint(),
                self.num_connections,
                goal);
    }
}

impl Drop for TestNode {
    fn drop(&mut self) {
        let _ = self.action_tx.send(Action::Terminate).unwrap();
    }
}

fn wait_for_nodes_to_connect(nodes: &mut [TestNode]) {
    let goal = cmp::min(GROUP_SIZE, nodes.len()) - 1;

    for node in nodes.iter_mut() {
        node.wait_for_connections(goal);
    }
}

fn create_connected_nodes(network: &Network, size: usize) -> Vec<TestNode> {
    let mut nodes = Vec::new();

    // Create the seed node.
    nodes.push(TestNode::new(network, false, None, None));
    thread::sleep(timeout());

    let config = Config::with_contacts(&[nodes[0].device.endpoint()]);

    // Create other nodes using the seed node endpoint as bootstrap contact.
    for i in 1..size {
        nodes.push(TestNode::new(network, false, Some(config.clone()), None));

        // Wait for the new node to connect to the previous nodes.
        let num = nodes.len() - 1;
        nodes[i].wait_for_connections(num);
    }

    wait_for_nodes_to_connect(&mut nodes);

    nodes
}

#[test]
fn two_nodes() {
    let network = Network::new();
    let _ = create_connected_nodes(&network, 2);
}

#[test]
fn few_nodes() {
    let network = Network::new();
    let _ = create_connected_nodes(&network, 3);
}

#[test]
fn group_size_nodes() {
    let network = Network::new();
    let _ = create_connected_nodes(&network, GROUP_SIZE);
}

#[test]
fn more_than_group_size_nodes() {
    let network = Network::new();
    let _ = create_connected_nodes(&network, 2 * GROUP_SIZE);
}

#[test]
fn client_connects_to_nodes() {
    let network = Network::new();
    let nodes = create_connected_nodes(&network, GROUP_SIZE);

    // Create one client that tries to connect to the network.
    let client = TestNode::new(&network,
                               true,
                               Some(Config::with_contacts(&[nodes[0].device.endpoint()])),
                               None);

    let mut connected = false;

    for event in iter_with_timeout(&client.event_rx, timeout()) {
        if Event::Connected == event {
            connected = true;
            break;
        }
    }

    assert!(connected);
}
