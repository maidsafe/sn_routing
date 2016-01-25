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

extern crate itertools;
extern crate routing;
#[macro_use]
extern crate maidsafe_utilities;
extern crate kademlia_routing_table;
extern crate rand;
extern crate sodiumoxide;
extern crate time;
extern crate xor_name;

use sodiumoxide::crypto;
use sodiumoxide::crypto::hash::sha512;
use std::iter;
use std::sync::mpsc::{self, Sender, Receiver, TryRecvError};
use std::thread;
use std::time::Duration;
use std::cmp::Ordering::{Less, Greater};
use itertools::Itertools;

use xor_name::XorName;
use maidsafe_utilities::serialisation::serialise;
use maidsafe_utilities::thread::RaiiThreadJoiner;
use routing::Authority;
use routing::Client;
use routing::Data;
use routing::Event;
use routing::FullId;
use routing::{RequestContent, ResponseContent, RequestMessage, ResponseMessage};
use routing::Node;
use routing::PlainData;

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

        TestNode {
            node: unwrap_result!(Node::new(sender)),
            _thread_joiner: joiner,
        }
    }

    fn name(&self) -> XorName {
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

// Spanws a thread that received events from a node a routes them to the main
// channel.
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
    let interval = timeout;
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

fn wait_for_nodes_to_connect(nodes: &[TestNode],
                             connection_counts: &mut [usize],
                             event_receiver: &Receiver<TestEvent>) {
    // Wait for each node to connect to all the other nodes by counting churns.
    loop {
        match recv_with_timeout(event_receiver, Duration::from_secs(20)) {
            TestEvent(index, Event::Churn { .. }) => {
                connection_counts[index] += 1;

                let k = nodes.len();
                if (0..k).map(|i| connection_counts[i]).all(|n| n >= k - 1) {
                    break;
                }
            }

            _ => (),
        }
    }
}

fn create_connected_nodes(count: usize,
                          event_sender: Sender<TestEvent>,
                          event_receiver: &Receiver<TestEvent>)
                          -> Vec<TestNode> {
    let mut nodes = Vec::with_capacity(count);
    let mut connection_counts = iter::repeat(0).take(count).collect::<Vec<usize>>();

    // Bootstrap node
    nodes.push(TestNode::new(0, event_sender.clone()));

    // HACK: wait until the above node switches to accepting mode. Would be
    // nice to know exactly when it happens instead of having to thread::sleep...
    thread::sleep(Duration::from_secs(2));

    // For each node, wait until it fully connects to the previous nodes before
    // continuing.
    for _ in 1..count {
        let index = nodes.len();
        nodes.push(TestNode::new(index, event_sender.clone()));
        wait_for_nodes_to_connect(&nodes, &mut connection_counts, event_receiver);
    }

    nodes
}

fn gen_plain_data() -> Data {
    let key: String = (0..10).map(|_| rand::random::<u8>() as char).collect();
    let value: String = (0..10).map(|_| rand::random::<u8>() as char).collect();
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

fn core() {
    let (event_sender, event_receiver) = mpsc::channel();
    let mut nodes = create_connected_nodes(GROUP_SIZE + 1, event_sender.clone(), &event_receiver);

    {
        // request and response
        let client = TestClient::new(nodes.len(), event_sender.clone());
        let data = gen_plain_data();

        loop {
            match recv_with_timeout(&event_receiver, Duration::from_secs(20)) {
                TestEvent(index, Event::Connected) if index == client.index => {
                    // The client is connected now. Send some request.
                    unwrap_result!(client.client.send_put_request(
                        Authority::ClientManager(*client.name()), data.clone()));
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
                            content: ResponseContent::PutSuccess(..), .. }))
                    if index == client.index => {
                    // The client received response to its request. We are done.
                    break;
                }

                _ => (),
            }
        }
    }

    {
        // request to group authority
        let node_names = nodes.iter().map(|node| node.name()).collect();
        let client = TestClient::new(nodes.len(), event_sender.clone());
        let data = gen_plain_data();
        let mut close_group = closest_nodes(&node_names, client.name());
        let timeout = time::Duration::seconds(10);
        let start = time::SteadyTime::now();

        loop {
            match recv_with_timeout(&event_receiver, Duration::from_secs(10)) {
                TestEvent(index, Event::Connected) if index == client.index => {
                    unwrap_result!(client.client.send_put_request(
                        Authority::ClientManager(*client.name()), data.clone()));
                }
                TestEvent(index, Event::Request(RequestMessage{ content: RequestContent::Put(..), .. })) => {
                    close_group.retain(|&name| name != nodes[index].name());

                    if close_group.is_empty() || start + timeout > time::SteadyTime::now() {
                        break;
                    }
                }
                _ => (),
            }
        }

        assert!(close_group.is_empty());
    }

    {
        // response from group authority
        let node_names = nodes.iter().map(|node| node.name()).collect();
        let client = TestClient::new(nodes.len(), event_sender.clone());
        let data = gen_plain_data();
        let mut close_group = closest_nodes(&node_names, client.name());
        let timeout = time::Duration::seconds(10);
        let start = time::SteadyTime::now();

        loop {
            match recv_with_timeout(&event_receiver, Duration::from_secs(10)) {
                TestEvent(index, Event::Connected) if index == client.index => {
                    unwrap_result!(client.client.send_put_request(
                        Authority::ClientManager(*client.name()), data.clone()));
                }
                TestEvent(index, Event::Request(RequestMessage{ src: Authority::Client{ .. },
                                                                dst: Authority::ClientManager(name),
                                                                content: RequestContent::Put(data, id) })) => {
                    unwrap_result!(nodes[index].node.send_put_request(
                        Authority::ClientManager(name),
                        Authority::NaeManager(data.name().clone()),
                        data.clone(),
                        id.clone()));
                }
                TestEvent(index, Event::Request(ref msg)) => {
                    if let RequestContent::Put(_, ref id) = msg.content {
                        unwrap_result!(nodes[index].node.send_put_failure(
                            msg.dst.clone(),
                            msg.src.clone(),
                            msg.clone(),
                            vec![],
                            id.clone()));
                    }
                }
                TestEvent(index, Event::Response(
                        ResponseMessage{ content: ResponseContent::PutFailure{ .. }, .. })) => {
                    close_group.retain(|&name| name != nodes[index].name());

                    if close_group.is_empty() || start + timeout > time::SteadyTime::now() {
                        break;
                    }
                }
                _ => (),
            }
        }

        assert!(close_group.is_empty());
    }

    {
        // leaving nodes cause churn
        let mut churns = iter::repeat(false).take(nodes.len() - 1).collect::<Vec<_>>();
        // a node leaves...
        let node = nodes.pop().unwrap();
        let name = node.name();
        drop(node);

        loop {
            match recv_with_timeout(&event_receiver, Duration::from_secs(10)) {
                TestEvent(index, Event::Churn { lost_close_node: Some(lost_name), .. })
                    if index < nodes.len() && lost_name == name => {
                    churns[index] = true;
                    if churns.iter().all(|b| *b) {
                        break;
                    }
                }

                _ => (),
            }
        }
    }

    {
        // joining nodes cause churn
        let nodes_len = nodes.len();
        let mut churns = iter::repeat(false).take(nodes_len + 1).collect::<Vec<_>>();
        // a node joins...
        nodes.push(TestNode::new(nodes_len, event_sender.clone()));

        loop {
            match recv_with_timeout(&event_receiver, Duration::from_secs(10)) {
                TestEvent(index, Event::Churn { lost_close_node: None, .. }) if index < nodes.len() => {
                    churns[index] = true;
                    if churns.iter().all(|b| *b) { break; }
                }

                _ => (),
            }
        }
    }
}

fn main() {
    core();
}
