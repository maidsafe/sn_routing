// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Standalone CI test runner which starts a routing network with each node running in its own
//! thread.

// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(
    bad_style,
    exceeding_bitshifts,
    mutable_transmutes,
    no_mangle_const_items,
    unknown_crate_types,
    warnings
)]
#![deny(
    deprecated,
    improper_ctypes,
    missing_docs,
    non_shorthand_field_patterns,
    overflowing_literals,
    plugin_as_library,
    stable_features,
    unconditional_recursion,
    unknown_lints,
    unsafe_code,
    unused,
    unused_allocation,
    unused_attributes,
    unused_comparisons,
    unused_features,
    unused_parens,
    while_true
)]
#![warn(
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results,
    variant_size_differences
)]
#![allow(
    box_pointers,
    missing_copy_implementations,
    missing_debug_implementations
)]
#![cfg(not(feature = "mock"))]

#[cfg(target_os = "macos")]
extern crate libc;
use maidsafe_utilities;
#[macro_use]
extern crate unwrap;

use itertools::Itertools;
use maidsafe_utilities::thread::{self, Joiner};
use maidsafe_utilities::SeededRng;
use rand::Rng;
use routing::{
    Authority, Client, ClientError, Event, EventStream, FullId, MessageId, MutableData, Node,
    Request, Response, Value, XorName, Xorable, MIN_SECTION_SIZE,
};
use safe_crypto::{gen_encrypt_keypair, gen_sign_keypair};
use std::collections::{BTreeMap, BTreeSet, HashSet};
#[cfg(target_os = "macos")]
use std::io;
use std::iter;
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::time::Duration;

#[derive(Debug)]
enum RecvWithTimeoutError {
    Disconnected,
    Timeout,
}

/// Blocks until something is received on the `Receiver`, or timeout, whichever happens sooner.
fn recv_with_timeout(
    nodes: &mut [TestNode],
    sender: &Sender<TestEvent>,
    receiver: &Receiver<TestEvent>,
    timeout: Duration,
) -> Result<TestEvent, RecvWithTimeoutError> {
    let interval = Duration::from_millis(100);
    let mut elapsed = Duration::from_millis(0);

    loop {
        // Try to step each node's state machine, and proxy any events found onto the channel.
        for (index, node) in nodes.iter_mut().enumerate() {
            while let Ok(ev) = node.node.try_next_ev() {
                unwrap!(sender.send(TestEvent(index, ev)));
            }
        }

        match receiver.try_recv() {
            Ok(value) => return Ok(value),
            Err(TryRecvError::Disconnected) => return Err(RecvWithTimeoutError::Disconnected),
            Err(TryRecvError::Empty) => {
                std::thread::sleep(interval);
                elapsed += interval;

                if elapsed > timeout {
                    return Err(RecvWithTimeoutError::Timeout);
                }
            }
        }
    }
}

#[derive(Debug)]
struct TestEvent(usize, Event);

struct TestNode {
    node: Node,
}

impl TestNode {
    // If `index` is `0`, this will be treated as the first node of the network.
    fn new(index: usize) -> Self {
        TestNode {
            node: unwrap!(Node::builder().first(index == 0).create()),
        }
    }

    fn name(&self) -> XorName {
        *unwrap!(self.node.id()).name()
    }
}

struct TestClient {
    index: usize,
    full_id: FullId,
    client: Client,
    _thread_joiner: Joiner,
}

impl TestClient {
    fn new(index: usize, main_sender: Sender<TestEvent>) -> Self {
        let thread_name = format!("TestClient {} event sender", index);
        let (sender, joiner) = spawn_select_thread(index, main_sender, thread_name);

        let sign_keys = gen_sign_keypair();
        let encrypt_keys = gen_encrypt_keypair();
        let full_id = FullId::with_keys(encrypt_keys, sign_keys);

        TestClient {
            index,
            full_id: full_id.clone(),
            client: unwrap!(Client::new(
                sender,
                Some(full_id),
                None,
                Duration::from_secs(90),
            )),
            _thread_joiner: joiner,
        }
    }

    pub fn name(&self) -> &XorName {
        self.full_id.public_id().name()
    }

    pub fn full_id(&self) -> &FullId {
        &self.full_id
    }
}

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
fn get_open_file_limits() -> io::Result<libc::rlimit> {
    unsafe {
        let mut result = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut result) != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(result)
    }
}

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
fn set_open_file_limits(limits: libc::rlimit) -> io::Result<()> {
    unsafe {
        if libc::setrlimit(libc::RLIMIT_NOFILE, &limits) != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn init() {
    unwrap!(maidsafe_utilities::log::init(true));
    let mut limits = unwrap!(get_open_file_limits());
    if limits.rlim_cur < 1024 {
        limits.rlim_cur = 1024;
        unwrap!(set_open_file_limits(limits));
    }
}

#[cfg(not(target_os = "macos"))]
fn init() {
    unwrap!(maidsafe_utilities::log::init(true));
}

// Spawns a thread that received events from a node a routes them to the main channel.
fn spawn_select_thread(
    index: usize,
    main_sender: Sender<TestEvent>,
    thread_name: String,
) -> (Sender<Event>, Joiner) {
    let (sender, receiver) = mpsc::channel();

    let thread_handle = thread::named(thread_name, move || {
        for event in receiver.iter() {
            unwrap!(main_sender.send(TestEvent(index, event)));
        }
    });

    (sender, thread_handle)
}

fn wait_for_nodes_to_connect(
    nodes: &mut [TestNode],
    connection_counts: &mut [usize],
    event_sender: &Sender<TestEvent>,
    event_receiver: &Receiver<TestEvent>,
) {
    // Wait for each node to connect to all the other nodes by counting churns.
    loop {
        if let Ok(test_event) =
            recv_with_timeout(nodes, event_sender, event_receiver, Duration::from_secs(30))
        {
            if let TestEvent(index, Event::NodeAdded(..)) = test_event {
                connection_counts[index] += 1;

                let k = nodes.len();
                let all_events_received = (0..k)
                    .map(|i| connection_counts[i])
                    .all(|n| n >= k - 1 || n >= MIN_SECTION_SIZE);
                if all_events_received {
                    break;
                }
            }
        } else {
            panic!("Timeout");
        }
    }
}

fn create_connected_nodes(
    count: usize,
    event_sender: &Sender<TestEvent>,
    event_receiver: &Receiver<TestEvent>,
) -> Vec<TestNode> {
    let mut nodes = Vec::with_capacity(count);
    let mut connection_counts = iter::repeat(0).take(count).collect::<Vec<usize>>();

    // Bootstrap node
    nodes.push(TestNode::new(0));

    // HACK: wait until the above node switches to accepting mode. Would be
    // nice to know exactly when it happens instead of having to thread::sleep...
    std::thread::sleep(Duration::from_secs(5));

    // For each node, wait until it fully connects to the previous nodes before
    // continuing.
    for _ in 1..count {
        let index = nodes.len();
        nodes.push(TestNode::new(index));
        wait_for_nodes_to_connect(
            &mut nodes,
            &mut connection_counts,
            event_sender,
            event_receiver,
        );
    }
    nodes
}

fn gen_mutable_data<R: Rng>(full_id: &FullId, rng: &mut R) -> MutableData {
    let tag = 10_000;

    let num_entries = rng.gen_range(1, 10);
    let entries: BTreeMap<_, _> = (0..num_entries)
        .map(|_| {
            let key: Vec<u8> = rng.gen_iter().take(10).collect();
            let content: Vec<u8> = rng.gen_iter().take(10).collect();

            (
                key,
                Value {
                    content,
                    entry_version: 0,
                },
            )
        })
        .collect();

    let owner_pubkey = *full_id.public_id().signing_public_key();
    let mut owners = BTreeSet::new();
    let _ = owners.insert(owner_pubkey);

    MutableData::new(rng.gen(), tag, Default::default(), entries, owners)
        .expect("Cannot create structured data for test")
}

fn closest_nodes(node_names: &[XorName], target: &XorName) -> Vec<XorName> {
    node_names
        .iter()
        .sorted_by(|a, b| target.cmp_distance(a, b))
        .into_iter()
        .take(MIN_SECTION_SIZE)
        .cloned()
        .collect()
}

// TODO: Extract the individual tests into their own functions.
#[allow(clippy::cyclomatic_complexity)]
fn core() {
    let (event_sender, event_receiver) = mpsc::channel();
    let mut nodes = create_connected_nodes(MIN_SECTION_SIZE + 1, &event_sender, &event_receiver);
    let mut rng = SeededRng::new();

    {
        // request and response
        let mut client = TestClient::new(nodes.len(), event_sender.clone());
        let client_key = *client.full_id().public_id().signing_public_key();
        let data = gen_mutable_data(client.full_id(), &mut rng);
        let message_id = MessageId::new();

        loop {
            if let Ok(test_event) = recv_with_timeout(
                &mut nodes,
                &event_sender,
                &event_receiver,
                Duration::from_secs(20),
            ) {
                match test_event {
                    TestEvent(index, Event::Connected) if index == client.index => {
                        // The client is connected now. Send some request.
                        let src = Authority::ClientManager(*client.name());
                        let result =
                            client
                                .client
                                .put_mdata(src, data.clone(), message_id, client_key);
                        assert!(result.is_ok());
                    }

                    TestEvent(index, Event::Request { request, src, dst }) => {
                        // A node received request from the client. Reply with a success.
                        if let Request::PutMData { msg_id, .. } = request {
                            let node = &mut nodes[index].node;
                            unwrap!(node.send_put_mdata_response(dst, src, Ok(()), msg_id));
                        }
                    }

                    TestEvent(
                        index,
                        Event::Response {
                            response:
                                Response::PutMData {
                                    res: Ok(()),
                                    msg_id: res_message_id,
                                },
                            ..
                        },
                    ) if index == client.index => {
                        // The client received response to its request. We are done.
                        assert_eq!(message_id, res_message_id);
                        break;
                    }

                    _ => (),
                }
            } else {
                panic!("Timeout");
            }
        }
    }

    {
        // request to group authority
        let node_names = nodes.iter().map(|node| node.name()).collect_vec();
        let mut client = TestClient::new(nodes.len(), event_sender.clone());
        let client_key = *client.full_id().public_id().signing_public_key();
        let data = gen_mutable_data(client.full_id(), &mut rng);
        let mut close_group = closest_nodes(&node_names, client.name());

        loop {
            if let Ok(test_event) = recv_with_timeout(
                &mut nodes,
                &event_sender,
                &event_receiver,
                Duration::from_secs(20),
            ) {
                match test_event {
                    TestEvent(index, Event::Connected) if index == client.index => {
                        let dst = Authority::ClientManager(*client.name());
                        assert!(client
                            .client
                            .put_mdata(dst, data.clone(), MessageId::new(), client_key)
                            .is_ok());
                    }
                    TestEvent(
                        index,
                        Event::Request {
                            request: Request::PutMData { .. },
                            ..
                        },
                    ) => {
                        close_group.retain(|&name| name != nodes[index].name());

                        if close_group.is_empty() {
                            break;
                        }
                    }
                    _ => (),
                }
            } else {
                panic!("Timeout");
            }
        }

        assert!(close_group.is_empty());
    }

    {
        // response from group authority
        let node_names = nodes.iter().map(|node| node.name()).collect_vec();
        let mut client = TestClient::new(nodes.len(), event_sender.clone());
        let client_key = *client.full_id().public_id().signing_public_key();
        let data = gen_mutable_data(client.full_id(), &mut rng);
        let mut close_group = closest_nodes(&node_names, client.name());

        loop {
            if let Ok(test_event) = recv_with_timeout(
                &mut nodes,
                &event_sender,
                &event_receiver,
                Duration::from_secs(20),
            ) {
                match test_event {
                    TestEvent(index, Event::Connected) if index == client.index => {
                        let dst = Authority::ClientManager(*client.name());
                        assert!(client
                            .client
                            .put_mdata(dst, data.clone(), MessageId::new(), client_key)
                            .is_ok());
                    }
                    TestEvent(
                        index,
                        Event::Request {
                            request:
                                Request::PutMData {
                                    data,
                                    msg_id,
                                    requester,
                                },
                            src: Authority::Client { .. },
                            dst: Authority::ClientManager(name),
                        },
                    ) => {
                        let src = Authority::ClientManager(name);
                        let dst = Authority::NaeManager(*data.name());
                        unwrap!(nodes[index].node.send_put_mdata_request(
                            src,
                            dst,
                            data.clone(),
                            msg_id,
                            requester,
                        ));
                    }
                    TestEvent(index, Event::Request { request, src, dst }) => {
                        if let Request::PutMData { msg_id, .. } = request {
                            unwrap!(nodes[index].node.send_put_mdata_response(
                                dst,
                                src,
                                Err(ClientError::NoSuchData),
                                msg_id,
                            ));
                        }
                    }
                    TestEvent(
                        index,
                        Event::Response {
                            response: Response::PutMData { res: Err(_), .. },
                            ..
                        },
                    ) => {
                        close_group.retain(|&name| name != nodes[index].name());

                        if close_group.is_empty() {
                            break;
                        }
                    }
                    _ => (),
                }
            } else {
                panic!("Timeout");
            }
        }

        assert!(close_group.is_empty());
    }

    {
        // leaving nodes cause churn
        let mut churns = iter::repeat(false)
            .take(nodes.len() - 1)
            .collect::<Vec<_>>();
        // a node leaves...
        let node = unwrap!(nodes.pop(), "No more nodes left.");
        let name = node.name();
        drop(node);

        loop {
            if let Ok(test_event) = recv_with_timeout(
                &mut nodes,
                &event_sender,
                &event_receiver,
                Duration::from_secs(20),
            ) {
                match test_event {
                    TestEvent(index, Event::NodeLost(lost_name))
                        if index < nodes.len() && lost_name == name =>
                    {
                        churns[index] = true;
                        if churns.iter().all(|b| *b) {
                            break;
                        }
                    }

                    _ => (),
                }
            } else {
                panic!("Timeout");
            }
        }
    }

    {
        // joining nodes cause churn
        let nodes_len = nodes.len();
        let mut churns: Vec<_> = iter::repeat(false).take(nodes_len + 1).collect();
        // a node joins...
        nodes.push(TestNode::new(nodes_len));

        loop {
            if let Ok(test_event) = recv_with_timeout(
                &mut nodes,
                &event_sender,
                &event_receiver,
                Duration::from_secs(20),
            ) {
                match test_event {
                    TestEvent(index, Event::NodeAdded(..)) if index < nodes.len() => {
                        churns[index] = true;
                        if churns.iter().all(|b| *b) {
                            break;
                        }
                    }

                    _ => (),
                }
            } else {
                panic!("Timeout");
            }
        }
    }

    {
        // message from quorum - 1 section members
        let mut client = TestClient::new(nodes.len(), event_sender.clone());
        let client_key = *client.full_id().public_id().signing_public_key();
        let data = gen_mutable_data(client.full_id(), &mut rng);

        while let Ok(test_event) = recv_with_timeout(
            &mut nodes,
            &event_sender,
            &event_receiver,
            Duration::from_secs(5),
        ) {
            match test_event {
                TestEvent(index, Event::Connected) if index == client.index => {
                    let dst = Authority::ClientManager(*client.name());
                    assert!(client
                        .client
                        .put_mdata(dst, data.clone(), MessageId::new(), client_key)
                        .is_ok());
                }
                TestEvent(
                    index,
                    Event::Request {
                        request:
                            Request::PutMData {
                                data,
                                msg_id,
                                requester,
                            },
                        src: Authority::Client { .. },
                        dst: Authority::ClientManager(name),
                    },
                ) => {
                    let src = Authority::ClientManager(name);
                    let dst = Authority::NaeManager(*data.name());
                    unwrap!(nodes[index].node.send_put_mdata_request(
                        src,
                        dst,
                        data.clone(),
                        msg_id,
                        requester,
                    ));
                }
                TestEvent(index, Event::Request { request, src, dst }) => {
                    if let Request::PutMData { msg_id, .. } = request {
                        if 2 * (index + 1) < MIN_SECTION_SIZE {
                            unwrap!(nodes[index].node.send_put_mdata_response(
                                dst,
                                src,
                                Err(ClientError::NoSuchData),
                                msg_id,
                            ));
                        }
                    }
                }
                TestEvent(
                    _index,
                    Event::Response {
                        response: Response::PutMData { res: Err(_), .. },
                        ..
                    },
                ) => {
                    // TODO: Once the new quorum definition is implemented, reactivate this.
                    // panic!("Unexpected response.");
                }
                _ => (),
            }
        }
    }

    {
        // message from more than quorum section members
        let mut client = TestClient::new(nodes.len(), event_sender.clone());
        let client_key = *client.full_id().public_id().signing_public_key();
        let data = gen_mutable_data(client.full_id(), &mut rng);
        let mut sent_ids = HashSet::new();
        let mut received_ids = HashSet::new();

        loop {
            if let Ok(test_event) = recv_with_timeout(
                &mut nodes,
                &event_sender,
                &event_receiver,
                Duration::from_secs(5),
            ) {
                match test_event {
                    TestEvent(index, Event::Connected) if index == client.index => {
                        // The client is connected now. Send some request.
                        let src = Authority::ClientManager(*client.name());
                        let message_id = MessageId::new();
                        let result =
                            client
                                .client
                                .put_mdata(src, data.clone(), message_id, client_key);
                        assert!(result.is_ok());
                        let _ = sent_ids.insert(message_id);
                    }
                    TestEvent(index, Event::Request { request, src, dst }) => {
                        // A node received request from the client. Reply with a success.
                        if let Request::PutMData { msg_id, .. } = request {
                            unwrap!(nodes[index].node.send_put_mdata_response(
                                dst,
                                src,
                                Ok(()),
                                msg_id,
                            ));
                        }
                    }
                    TestEvent(
                        index,
                        Event::Response {
                            response:
                                Response::PutMData {
                                    res: Ok(()),
                                    msg_id,
                                },
                            ..
                        },
                    ) if index == client.index => {
                        // TODO: assert!(received_ids.insert(id));
                        let _ = received_ids.insert(msg_id);
                    }
                    _ => (),
                }
            } else {
                assert_eq!(1, received_ids.len());
                assert_eq!(sent_ids, received_ids);
                break;
            }
        }
    }
}

#[test]
fn main() {
    init();
    core();
}
