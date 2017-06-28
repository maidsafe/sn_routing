// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

mod accumulate;
mod cache;
mod churn;
mod drop;
mod merge;
mod requests;
mod tunnel;
mod utils;

pub use self::utils::{Nodes, TestClient, TestNode, add_connected_nodes_until_split,
                      create_connected_clients, create_connected_nodes,
                      create_connected_nodes_until_split, gen_bytes, gen_immutable_data,
                      gen_range, gen_range_except, poll_all, poll_and_resend,
                      remove_nodes_which_failed_to_connect, sort_nodes_by_distance_to,
                      verify_invariant_for_all_nodes};
use fake_clock::FakeClock;
use rand::Rng;
use routing::{Authority, BootstrapConfig, Event, EventStream, MessageId, Prefix, Request,
              XOR_NAME_LEN, XorName};
use routing::mock_crust::{Endpoint, Network};
use routing::rate_limiter_consts::{CAPACITY, CLIENT_GET_CHARGE, RATE};
use routing::test_consts::MAX_CLIENTS_PER_PROXY;
use std::collections::HashMap;
use std::net::IpAddr;

// -----  Miscellaneous tests below  -----

fn test_nodes(percentage_size: usize) {
    let min_section_size = 8;
    let size = min_section_size * percentage_size / 100;
    let network = Network::new(min_section_size, None);
    let mut nodes = create_connected_nodes(&network, size);
    verify_invariant_for_all_nodes(&mut nodes);
}

#[test]
fn disconnect_on_rebootstrap() {
    let min_section_size = 8;
    let network = Network::new(min_section_size, None);
    let mut nodes = create_connected_nodes(&network, 2);
    // Try to bootstrap to another than the first node. With network size 2, this should fail.
    let config = BootstrapConfig::with_contacts(&[nodes[1].handle.endpoint()]);
    nodes.push(TestNode::builder(&network)
                   .config(config)
                   .endpoint(Endpoint(2))
                   .create());
    let _ = poll_all(&mut nodes, &mut []);
    // When retrying to bootstrap, we should have disconnected from the bootstrap node.
    assert!(!unwrap!(nodes.last())
                 .handle
                 .is_connected(&nodes[1].handle));
    expect_next_event!(unwrap!(nodes.last_mut()), Event::Terminate);
}

#[test]
fn less_than_section_size_nodes() {
    test_nodes(38)
}

#[test]
fn equal_section_size_nodes() {
    test_nodes(100);
}

#[test]
fn more_than_section_size_nodes() {
    test_nodes(600);
}

#[test]
fn client_connects_to_nodes() {
    let min_section_size = 8;
    let network = Network::new(min_section_size, None);
    let mut nodes = create_connected_nodes(&network, min_section_size + 1);
    let _ = create_connected_clients(&network, &mut nodes, 1);
}

#[test]
fn node_joins_in_front() {
    let min_section_size = 8;
    let network = Network::new(min_section_size, None);
    let mut nodes = create_connected_nodes(&network, 2 * min_section_size);
    let config = BootstrapConfig::with_contacts(&[nodes[0].handle.endpoint()]);
    nodes.insert(0, TestNode::builder(&network).config(config).create());

    let _ = poll_all(&mut nodes, &mut []);

    verify_invariant_for_all_nodes(&mut nodes);
}

#[test]
fn multiple_joining_nodes() {
    let min_section_size = 8;
    let network = Network::new(min_section_size, None);
    let mut nodes = create_connected_nodes(&network, min_section_size);
    let config = BootstrapConfig::with_contacts(&[nodes[0].handle.endpoint()]);

    while nodes.len() < 40 {
        info!("Size {}", nodes.len());

        // Try adding five nodes at once, possibly to the same section. This makes sure one section
        // can handle this, either by adding the nodes in sequence or by rejecting some.
        let count = 5;
        for _ in 0..count {
            nodes.push(TestNode::builder(&network)
                           .config(config.clone())
                           .create());
        }

        poll_and_resend(&mut nodes, &mut []);
        let _ = remove_nodes_which_failed_to_connect(&mut nodes, count);
        verify_invariant_for_all_nodes(&mut nodes);
    }
}

#[test]
// TODO - The original intent of this test was to ensure two nodes could join two separate sections
//        simultaneously. That can fail if one section has four members which add the new node from
//        the other section to their RTs and four members which don't, while still waiting to
//        approve their own candidate. In that case, their candidate doesn't receive its
//        `NodeApproval` and the invariant check fails. This is true regardless of whether we send
//        a snapshot of the RT taken when sending `CandidateApproval` in the `NodeApproval`, or send
//        a current version of the RT: only the window for failure shifts in these scenarios.
fn simultaneous_joining_nodes() {
    // Create a network with two sections:
    let min_section_size = 8;
    let network = Network::new(min_section_size, None);
    let mut nodes = create_connected_nodes_until_split(&network, vec![1, 1], false);
    let config = BootstrapConfig::with_contacts(&[nodes[0].handle.endpoint()]);

    // Add two nodes simultaneously, to two different sections:
    // We now have two sections, with prefixes 0 and 1. Make one joining node contact each section,
    // and tell each section to allocate a name in its own section when `Relocate` is received.
    // This is to test that the routing table gets updated correctly (previously one new node would
    // miss the new node added to the neighbouring section).
    let (name0, name1) = (XorName([0u8; XOR_NAME_LEN]), XorName([255u8; XOR_NAME_LEN]));
    let prefix0 = Prefix::new(1, name0);

    for node in &mut *nodes {
        if prefix0.matches(&node.name()) {
            node.inner.set_next_relocation_dst(name0);
        } else {
            node.inner.set_next_relocation_dst(name1);
        }
    }

    let node = TestNode::builder(&network)
        .config(config.clone())
        .create();
    let prefix = Prefix::new(1, node.name());
    nodes.push(node);
    loop {
        let node = TestNode::builder(&network)
            .config(config.clone())
            .create();
        if !prefix.matches(&node.name()) {
            nodes.push(node);
            break;
        }
    }

    poll_and_resend(&mut nodes, &mut []);
    assert!(remove_nodes_which_failed_to_connect(&mut nodes, 2) < 2);
    verify_invariant_for_all_nodes(&mut nodes);
}

#[test]
fn check_close_names_for_min_section_size_nodes() {
    let min_section_size = 8;
    let nodes = create_connected_nodes(&Network::new(min_section_size, None), min_section_size);
    let close_sections_complete =
        nodes
            .iter()
            .all(|n| nodes.iter().all(|m| m.close_names().contains(&n.name())));
    assert!(close_sections_complete);
}

#[test]
fn whitelist() {
    let min_section_size = 8;
    let network = Network::new(min_section_size, None);
    let mut nodes = create_connected_nodes(&network, min_section_size);
    let config = BootstrapConfig::with_contacts(&[nodes[0].handle.endpoint()]);

    for node in &mut *nodes {
        node.handle
            .0
            .borrow_mut()
            .whitelist_peer(Endpoint(min_section_size));
    }
    // The next node has endpoint `min_section_size`: It should be able to join.
    nodes.push(TestNode::builder(&network)
                   .config(config.clone())
                   .create());
    let _ = poll_all(&mut nodes, &mut []);
    verify_invariant_for_all_nodes(&mut nodes);
    // The next node has endpoint `min_section_size + 1`: It is not whitelisted.
    nodes.push(TestNode::builder(&network)
                   .config(config.clone())
                   .create());
    let _ = poll_all(&mut nodes, &mut []);
    assert!(!unwrap!(nodes.pop()).inner.is_node());
    // A client should be able to join anyway, regardless of the whitelist.
    let mut clients = vec![TestClient::new(&network, Some(config), None)];
    let _ = poll_all(&mut nodes, &mut clients);
    expect_next_event!(clients[0], Event::Connected);
}

#[test]
/// Connects multiple clients to the same proxy node, expecting clients fail to connect after
/// reaching `MAX_CLIENTS_PER_PROXY`, and succeed again when a connected client drops out.
fn multiple_clients_per_proxy() {
    let min_section_size = 8;
    let network = Network::new(min_section_size, None);
    let mut nodes = create_connected_nodes(&network, min_section_size);
    let mut clients = create_connected_clients(&network, &mut nodes, MAX_CLIENTS_PER_PROXY);

    let config = BootstrapConfig::with_contacts(&[nodes[0].handle.endpoint()]);
    clients.push(TestClient::new(&network, Some(config.clone()), None));
    let _ = poll_all(&mut nodes, &mut clients);
    expect_next_event!(clients[MAX_CLIENTS_PER_PROXY], Event::Terminate);

    let _ = clients.remove(MAX_CLIENTS_PER_PROXY);
    let _ = clients.remove(0);
    let _ = poll_all(&mut nodes, &mut clients);

    clients.push(TestClient::new(&network, Some(config.clone()), None));
    let _ = poll_all(&mut nodes, &mut clients);
    expect_next_event!(clients[MAX_CLIENTS_PER_PROXY - 1], Event::Connected);
}

#[test]
/// Connects multiple clients to the same proxy node and randomly sending get requests.
/// Expect some reguests will be blocked due to the rate limit.
/// Expect the total capacity of the proxy will never be exceeded.
fn rate_limit_proxy() {
    let min_section_size = 8;
    let network = Network::new(min_section_size, None);
    let mut nodes = create_connected_nodes(&network, min_section_size);
    let mut clients = create_connected_clients(&network, &mut nodes, MAX_CLIENTS_PER_PROXY);

    let mut rng = network.new_rng();
    let data_id: XorName = rng.gen();
    let dst = Authority::NaeManager(data_id);
    let mut total_usage: u64 = 0;
    let wait_millis = 2 * CLIENT_GET_CHARGE * 1000 / RATE as u64;
    let leaky_rate = 2 * CLIENT_GET_CHARGE;
    let per_client_cap = CAPACITY / MAX_CLIENTS_PER_PROXY as u64;
    for i in 0..10 {
        trace!("iteration {:?}", i);
        let mut clients_sent = HashMap::new();
        for (j, client) in clients.iter_mut().enumerate() {
            if rng.gen_weighted_bool(2) {
                let msg_id = MessageId::new();
                unwrap!(client.inner.get_idata(dst, data_id, msg_id));
                let _ =
                    clients_sent.insert(msg_id,
                                        IpAddr::from([0, 0, 0, (j + min_section_size) as u8]));
            }
        }
        trace!("clients_sent: {:?}", clients_sent);
        let _ = poll_all(&mut nodes, &mut clients);

        let mut request_received: HashMap<MessageId, usize> = HashMap::new();
        for node in nodes.iter_mut().filter(|n| n.is_recipient(&dst)) {
            while let Ok(event) = node.try_next_ev() {
                if let Event::Request {
                           request: Request::GetIData { msg_id: req_message_id, .. }, ..
                       } = event {
                    let entry = request_received
                        .entry(req_message_id)
                        .or_insert_with(|| 0);
                    *entry += 1;
                }
            }
        }
        trace!("request_received: {:?}", request_received);

        for (msg_id, count) in &request_received {
            assert_eq!(*count, min_section_size);
            let _ = unwrap!(clients_sent.remove(msg_id));
            total_usage += CLIENT_GET_CHARGE;
        }
        assert!(total_usage <= CAPACITY);


        let clients_usage = nodes[0].inner.get_clients_usage();
        assert_eq!(clients_usage.iter()
                             .filter(|&(_, usage)| *usage > per_client_cap)
                             .count(),
                   0);
        for ip in clients_sent.values() {
            assert!(unwrap!(clients_usage.get(ip)) + CLIENT_GET_CHARGE > per_client_cap);
        }

        FakeClock::advance_time(wait_millis);
        total_usage -= leaky_rate;
    }
}

#[test]
/// Connect a client to the network then send an invalid message.
/// Expect the client will be banned (disconnected);
fn ban_malicious_client() {
    let min_section_size = 8;
    let network = Network::new(min_section_size, None);
    let mut nodes = create_connected_nodes(&network, min_section_size);
    let mut clients = create_connected_clients(&network, &mut nodes, 1);




    let mut rng = network.new_rng();
    let data_name: XorName = rng.gen();
    let group_auth = Authority::NaeManager(data_name);
    let client_auth = Authority::Client {
        client_id: *clients[0].full_id.public_id(),
        proxy_node_name: nodes[0].name(),
    };
    let msg_id = MessageId::new();

    // Send a get request from NM to client, which makes client sends an ACK to proxy.
    // This ACK will be in the priority of `RELOCATE_PRIORITY`, which makes proxy ban the client.
    for node in nodes.iter_mut() {
        unwrap!(node.inner.send_get_idata_request(group_auth, client_auth, data_name, msg_id));
    }
    let _ = poll_all(&mut nodes, &mut clients);

    let mut terminated = false;
    while let Ok(event) = clients[0].inner.try_next_ev() {
        match event {
            Event::Request { request: Request::GetIData { .. }, .. } => {}
            Event::Terminate => terminated = true,
            _ => panic!("unexpected event {:?}", event),
        }
    }
    assert!(terminated);
}
