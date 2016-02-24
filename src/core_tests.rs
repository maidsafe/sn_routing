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

use std::cmp;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use action::Action;
use core::Core;
use crust_mock::{self, Config, Device, Endpoint, Network};
use event::Event;
use kademlia_routing_table::GROUP_SIZE;
use maidsafe_utilities::log;
use maidsafe_utilities::thread::RaiiThreadJoiner;
use test_utils;
use types::RoutingActionSender;

struct TestNode {
    device: Device,
    action_tx: RoutingActionSender,
    event_rx: mpsc::Receiver<Event>,
    _joiner: RaiiThreadJoiner,
}

impl TestNode {
    fn new(network: &Network,
           client_restriction: bool,
           config: Option<Config>,
           endpoint: Option<Endpoint>)
           -> Self {
        let device = network.new_device(config, endpoint);
        let (event_tx, event_rx) = mpsc::channel();

        let (action_tx, joiner) = crust_mock::make_current(&device, || {
            Core::new(event_tx, client_restriction, None).unwrap()
        });

        TestNode {
            device: device,
            action_tx: action_tx,
            event_rx: event_rx,
            _joiner: joiner,
        }
    }
}

impl Drop for TestNode {
    fn drop(&mut self) {
        let _ = self.action_tx.send(Action::Terminate).unwrap();
    }
}

fn wait_for_events<F>(node: &TestNode, min: usize, pred: F)
    where F: Fn(Event) -> bool
{
    let mut num = 0;

    for event in test_utils::iter_with_timeout(&node.event_rx, Duration::from_secs(1)) {
        if pred(event) {
            num += 1;
            if num >= min {
                break;
            }
        }
    }

    assert!(num >= min,
            "{:?} expected {} events, received only {}",
            node.device.endpoint(),
            min,
            num);
}

fn wait_for_node_added_events(node: &TestNode, min: usize) {
    wait_for_events(node, min, |event| {
        if let Event::NodeAdded(..) = event {
            true
        } else {
            false
        }
    })
}

fn create_connected_nodes(network: &Network, size: usize) -> Vec<TestNode> {
    let mut nodes = Vec::new();

    // Create the seed node.
    nodes.push(TestNode::new(network, false, None, None));
    thread::sleep(Duration::from_millis(500));

    let config = Config::new_with_contacts(&[nodes[0].device.endpoint()]);

    // Create other nodes using the seed node endpoint as bootstrap contact.
    for _ in 1..size {
        nodes.push(TestNode::new(network, false, Some(config.clone()), None));
    }

    let n = cmp::min(GROUP_SIZE, nodes.len()) - 1;

    for node in nodes.iter() {
        wait_for_node_added_events(&node, n);
    }

    nodes
}

#[test]
fn two_nodes() {
    let network = Network::new();
    let _ = create_connected_nodes(&network, 2);
}

#[test]
fn few_nodes() {
    log::init(true);

    let network = Network::new();
    let _ = create_connected_nodes(&network, 3);
}

#[test]
fn group_size_nodes() {
    let network = Network::new();
    let _ = create_connected_nodes(&network, GROUP_SIZE);
}

#[test]
fn client_connects_to_nodes() {
    log::init(true);

    let network = Network::new();
    let nodes = create_connected_nodes(&network, GROUP_SIZE);

    // Create one client that tries to connect to the network.
    let client = TestNode::new(&network,
                               true,
                               Some(Config::new_with_contacts(&[nodes[0].device.endpoint()])),
                               None);

    wait_for_events(&client, 1, |event| Event::Connected == event);
}
