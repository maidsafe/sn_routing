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

use std::sync::mpsc::{self, Sender, Receiver, TryRecvError};
use std::thread;
use std::time::Duration;
use maidsafe_utilities::thread::RaiiThreadJoiner;

use event::Event;
use node::Node;

struct TestNode {
    // id: usize,
    _node: Node,
    _thread_joiner: RaiiThreadJoiner,
}

#[derive(Debug)]
struct TestEvent(usize, Event);

impl TestNode {
    fn new(id: usize, main_sender: Sender<TestEvent>) -> Self {
        let (sender, receiver) = mpsc::channel();

        let thread_handle = thread!(format!("TestNode({})", id), move || {
            for event in receiver.iter() {
                let _ = unwrap_result!(main_sender.send(TestEvent(id, event)));
            }
        });

        TestNode {
            // id: id,
            _node: unwrap_result!(Node::new(sender)),
            _thread_joiner: RaiiThreadJoiner::new(thread_handle),
        }
    }
}

fn create_test_node(id: usize, sender: Sender<TestEvent>) -> TestNode {
    let node = TestNode::new(id, sender);

    // Wait for the node to finish bootstrapping (?).
    // TODO: get rid of this sleep.
    thread::sleep(Duration::from_millis(1000));

    node
}

fn recv_with_timeout<T>(receiver: &Receiver<T>, timeout: Duration) -> Option<T> {
    let interval = Duration::from_millis(100);
    let mut elapsed = Duration::from_millis(0);

    loop {
        match receiver.try_recv() {
            Ok(value) => return Some(value),
            Err(TryRecvError::Disconnected) => break,
            _ => (),
        }

        thread::sleep(interval);
        elapsed = elapsed + interval;

        if elapsed > timeout {
            break;
        }
    }

    None
}

#[test]
fn connect() {
    let (event_sender, event_receiver) = mpsc::channel();

    let nodes_count = 4;
    let timeout = Duration::from_secs(10);

    let mut nodes = Vec::with_capacity(nodes_count);
    let mut connection_counts = Vec::with_capacity(nodes_count);

    for i in 0..nodes_count {
        nodes.push(create_test_node(i, event_sender.clone()));
        connection_counts.push(0);
    }

    // Wait for each node to connect to all the other nodes by counting churns.
    loop {
        match recv_with_timeout(&event_receiver, timeout) {
            Some(TestEvent(id, Event::Churn { .. })) => {
                connection_counts[id] += 1;

                if connection_counts.iter().all(|n| *n >= nodes.len() - 1) {
                    break;
                }
            }

            Some(_) => (),
            None => panic!("Not all nodes connected"),
        }
    }
}
