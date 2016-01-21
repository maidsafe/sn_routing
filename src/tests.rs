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

use maidsafe_utilities::serialisation::serialise;
use maidsafe_utilities::thread::RaiiThreadJoiner;
use rand::{thread_rng, Rng};
use sodiumoxide::crypto;
use sodiumoxide::crypto::hash::sha512;
use std::cmp::Ordering::{Less, Greater};
// use std::iter;
use std::sync::mpsc::{self, Sender, Receiver, TryRecvError};
use std::thread;
use std::time::Duration;
use time;
use itertools::Itertools;
use xor_name;
use xor_name::XorName;
use kademlia_routing_table;

use authority::Authority;
use client::Client;
use data::Data;
use event::Event;
use id::FullId;
use messages::{RequestContent, ResponseContent, RequestMessage, ResponseMessage};
use node::Node;
use plain_data::PlainData;

const GROUP_SIZE: usize = kademlia_routing_table::GROUP_SIZE as usize;

#[derive(Debug)]
struct TestEvent(usize, Event);

struct TestNode {
    node: Node,
    _thread_joiner: RaiiThreadJoiner,
}

impl TestNode {
    fn new(index: usize, main_sender: Sender<TestEvent>) -> Self {
        let (sender, joiner) = spawn_select_thread(index, main_sender);

        let node = unwrap_result!(Node::new(sender));

        // Wait for the node to finish bootstrapping (?).
        // TODO: find a way to get rid of this sleep.
        thread::sleep(Duration::from_secs(1 + index as u64));

        TestNode {
            node: node,
            _thread_joiner: joiner,
        }
    }

    pub fn name(&self) -> XorName {
        unwrap_result!(self.node.name())
    }
}

struct TestClient {
    index: usize,
    full_id: FullId,
    client: Client,
    _thread_joiner: RaiiThreadJoiner,
}

impl TestClient {
    fn new(index: usize, main_sender: Sender<TestEvent>) -> Self {
        let (sender, joiner) = spawn_select_thread(index, main_sender);

        let sign_keys = crypto::sign::gen_keypair();
        let encrypt_keys = crypto::box_::gen_keypair();
        let full_id = FullId::with_keys(encrypt_keys, sign_keys);

        TestClient {
            index: index,
            full_id: full_id.clone(),
            client: unwrap_result!(Client::new(sender, Some(full_id))),
            _thread_joiner: joiner,
        }
    }

    pub fn name(&self) -> &XorName {
        self.full_id.public_id().name()
    }
}

fn spawn_select_thread(index: usize,
                       main_sender: Sender<TestEvent>)
                       -> (Sender<Event>, RaiiThreadJoiner) {
    let (sender, receiver) = mpsc::channel();

    let thread_handle = thread::spawn(move || {
        for event in receiver.iter() {
            let _ = unwrap_result!(main_sender.send(TestEvent(index, event)));
        }
    });

    (sender, RaiiThreadJoiner::new(thread_handle))
}

fn recv_with_timeout<T>(receiver: &Receiver<T>, timeout: Duration) -> T {
    let interval = Duration::from_secs(10);
    let mut elapsed = Duration::from_millis(0);

    loop {
        match receiver.try_recv() {
            Ok(value) => return value,
            Err(TryRecvError::Disconnected) => break,
            _ => (),
        }

        thread::sleep(interval);
        elapsed = elapsed + interval;

        if elapsed > timeout {
            break;
        }
    }

    panic!("Timeout");
}

fn create_nodes(count: usize, event_sender: Sender<TestEvent>) -> Vec<TestNode> {
    let interval = Duration::from_secs(5);
    let mut nodes = vec![];
    for i in 0..count {
        nodes.push(TestNode::new(i, event_sender.clone()));
        thread::sleep(interval);
    }
    nodes
    // (0..count)
    //     .map(|i| TestNode::new(i, event_sender.clone()))
    //     .collect()
}

// fn wait_for_nodes_to_connect(nodes: &[TestNode],
//                              event_receiver: &Receiver<TestEvent>,
//                              timeout: Duration) {
//     let mut connection_counts = iter::repeat(0)
//                                     .take(nodes.len())
//                                     .collect::<Vec<usize>>();

//     // Wait for each node to connect to all the other nodes by counting churns.
//     loop {
//         match recv_with_timeout(event_receiver, timeout) {
//             TestEvent(index, Event::Churn { .. }) => {
//                 connection_counts[index] += 1;

//                 if connection_counts.iter().all(|n| *n >= nodes.len() - 1) {
//                     break;
//                 }
//             }

//             _ => (),
//         }
//     }
// }

fn gen_plain_data() -> Data {
    let key: String = thread_rng().gen_ascii_chars().take(10).collect();
    let value: String = thread_rng().gen_ascii_chars().take(10).collect();
    let name = XorName::new(sha512::hash(key.as_bytes()).0);
    let data = unwrap_result!(serialise(&(key, value)));

    Data::PlainData(PlainData::new(name.clone(), data))
}

fn closest_nodes(node_names: &Vec<XorName>, target: &XorName) -> Vec<XorName> {
    node_names.iter()
              .sorted_by(|a, b| if xor_name::closer_to_target(a, b, target) { Less } else { Greater })
              .into_iter()
              .take(GROUP_SIZE)
              .cloned()
              .collect()
}

// #[test]
// fn connect() {
//     let (event_sender, _event_receiver) = mpsc::channel();
//     let _ = create_nodes(4, event_sender);
//     // wait_for_nodes_to_connect(&nodes, &event_receiver, Duration::from_secs(10));
// }

#[test]
fn request_and_response() {
    let (event_sender, event_receiver) = mpsc::channel();
    let nodes = create_nodes(GROUP_SIZE + 1, event_sender.clone());
    // wait_for_nodes_to_connect(&nodes, &event_receiver, Duration::from_secs(10));

    let client = TestClient::new(nodes.len(), event_sender);
    let mut data = Some(gen_plain_data());

    loop {
        match recv_with_timeout(&event_receiver, Duration::from_secs(10)) {
            TestEvent(index, Event::Connected) if index == client.index => {
                // The client is connected now. Send some request.
                if let Some(data) = data.take() {
                    unwrap_result!(client.client.send_put_request(
                        Authority::ClientManager(*client.name()), data));
                }
            }

            TestEvent(index, Event::Request(message)) => {
                // A node received request from the client. Reply with a success.
                if let RequestContent::Put(_, ref id) = message.content {
                    let encoded = unwrap_result!(serialise(&message));
                    let ref node = nodes[index].node;

                    unwrap_result!(node.send_put_success(message.dst,
                                                         message.src,
                                                         sha512::hash(&encoded),
                                                         id.clone()));
                }
            }

            TestEvent(index,
                      Event::Response(ResponseMessage{
                        content: ResponseContent::PutSuccess(_, _), .. }))
                if index == client.index => {
                // The client received response to its request. We are done.
                break;
            }

            _ => (),
        }
    }
}

#[test]
fn to_group_authorities() {
    let (event_sender, event_receiver) = mpsc::channel();
    let nodes = create_nodes(2 * GROUP_SIZE, event_sender.clone());
    let node_names = nodes.iter().map(|node| node.name()).collect();
    let client = TestClient::new(nodes.len(), event_sender);
    let mut close_group = closest_nodes(&node_names, client.name());
    let mut data = Some(gen_plain_data());
    let interval = time::Duration::seconds(10);
    let start = time::SteadyTime::now();

    loop {
        match recv_with_timeout(&event_receiver, Duration::from_secs(10)) {
            TestEvent(index, Event::Connected) if index == client.index => {
                // The client is connected now. Send some request.
                if let Some(data) = data.take() {
                    unwrap_result!(client.client.send_put_request(Authority::ClientManager(*client.name()), data));
                }
            }
            TestEvent(index, Event::Request(RequestMessage{ content: RequestContent::Put(..), .. })) => {
                // A node received put request from the client. Remove it from close_group if present.
                close_group.retain(|&name| name != nodes[index].name());

                if close_group.is_empty() || start + interval > time::SteadyTime::now() {
                    break;
                }
            }
            _ => (),
        }
    }

    assert!(close_group.is_empty());
}
