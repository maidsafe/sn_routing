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

use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use action::Action;
use core::Core;
use crust_mock::{Config, Device, Endpoint, Network};
use event::Event;
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
        let (action_tx, joiner) = Core::new(&device, event_tx, client_restriction, None).unwrap();

        TestNode {
            device: device,
            action_tx: action_tx,
            event_rx: event_rx,
            _joiner: joiner,
        }
    }

    // Wait until we receive Event::NodeAdded at least `min` times.
    fn wait_for_node_added_events(&self, min: usize) {
        let mut num = 0;

        for event in test_utils::iter_with_timeout(&self.event_rx, Duration::from_secs(1)) {
            match event {
                Event::NodeAdded(..) => {
                    num += 1;
                    if num >= min {
                        break;
                    }
                }

                _ => (),
            }
        }

        assert!(num >= min, "Expected {} events, received only {}", min, num);
    }
}

impl Drop for TestNode {
    fn drop(&mut self) {
        self.action_tx.send(Action::Terminate);
    }
}

#[test]
fn smoke() {
    log::init(true);

    let network = Network::new();
    let mut nodes = Vec::new();

    // Create the seed node.
    nodes.push(TestNode::new(&network, false, None, None));
    // Let the seed node finish bootstrapping.
    // TODO: would be great if nodes raised a BootstrapFinished event, then we
    // would know precisely how long to wait here.
    thread::sleep(Duration::from_secs(1));

    let config = Config::new_with_contacts(&[nodes[0].device.endpoint()]);

    // Create other nodes using the seed node endpoint as bootstrap contact.
    for _ in 0..8 {
        nodes.push(TestNode::new(&network, false, Some(config.clone()), None));
    }

    // Wait until every node connects to at least one other node
    // TODO: should wait until it connects to all nodes instead?
    for node in nodes.iter() {
        node.wait_for_node_added_events(1);
    }

    // Create one client that tries to connect to the network.
    let client = TestNode::new(&network, true, Some(config.clone()), None);

    let mut connected = false;

    for event in test_utils::iter_with_timeout(&client.event_rx, Duration::from_secs(1)) {
        match event {
            Event::Connected => {
                connected = true;
                break;
            }

            _ => panic!("Unexpected event {:?}", event),
        }
    }

    assert!(connected);
}
