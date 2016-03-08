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

use core::Core;
use event::Event;
use kademlia_routing_table::GROUP_SIZE;
use maidsafe_utilities::log;
use mock_crust::{self, Config, Endpoint, Network, ServiceHandle};

struct TestNode {
    handle: ServiceHandle,
    core: Core,
    event_rx: mpsc::Receiver<Event>,
}

impl TestNode {
    fn new(network: &Network,
           client_restriction: bool,
           config: Option<Config>,
           endpoint: Option<Endpoint>)
           -> Self {
        let handle = network.new_service_handle(config, endpoint);
        let (event_tx, event_rx) = mpsc::channel();

        let (_, core) = mock_crust::make_current(&handle,
                                                 || Core::new(event_tx, client_restriction, None));

        TestNode {
            handle: handle,
            core: core,
            event_rx: event_rx,
        }
    }

    fn poll(&mut self) -> bool {
        let mut result = false;

        while self.core.poll() {
            result = true;
        }

        result
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

/// Process all events
fn poll_all(nodes: &mut [TestNode]) {
    while nodes.iter_mut().any(TestNode::poll) {}
}

fn create_connected_nodes(network: &Network, size: usize) -> Vec<TestNode> {
    let mut nodes = Vec::new();

    // Create the seed node.
    nodes.push(TestNode::new(network, false, None, Some(Endpoint(0))));
    nodes[0].poll();

    let config = Config::with_contacts(&[nodes[0].handle.endpoint()]);

    // Create other nodes using the seed node endpoint as bootstrap contact.
    for i in 1..size {
        nodes.push(TestNode::new(network, false, Some(config.clone()), Some(Endpoint(i))));
        poll_all(&mut nodes);
    }

    let n = cmp::min(nodes.len(), GROUP_SIZE) - 1;

    for node in nodes.iter() {
        for _ in 0..n {
            expect_event!(node, Event::NodeAdded(..))
        }
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
fn more_than_group_size_nodes() {
    let network = Network::new();
    let _ = create_connected_nodes(&network, GROUP_SIZE + 2);
}

#[test]
fn failing_connections() {
    log::init(true);
    let network = Network::new();
    network.block_connection(Endpoint(1), Endpoint(2));
    network.block_connection(Endpoint(1), Endpoint(3));
    network.block_connection(Endpoint(2), Endpoint(3));
    let _ = create_connected_nodes(&network, 5);
}

#[test]
fn client_connects_to_nodes() {
    let network = Network::new();
    let mut nodes = create_connected_nodes(&network, GROUP_SIZE + 1);

    // Create one client that tries to connect to the network.
    let client = TestNode::new(&network,
                               true,
                               Some(Config::with_contacts(&[nodes[0].handle.endpoint()])),
                               None);

    nodes.push(client);

    poll_all(&mut nodes);

    expect_event!(nodes.iter().last().unwrap(), Event::Connected);
}
