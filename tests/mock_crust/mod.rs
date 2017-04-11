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

#[macro_export]
macro_rules! log_init {
    () => {
        use ::std::env::var;
        use ::mock_crust::LOGGER;
        match var("RUST_LOG") {
            Ok(ref val) if val != "disabled" => LOGGER.with(|_| {}),
            _ => ()
        }
    }
}

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
use routing::{Event, EventStream, Prefix, XOR_NAME_LEN, XorName};
use routing::mock_crust::{Config, Endpoint, Network};
use routing::mock_crust::crust::PeerId;

thread_local! {
    static LOGGER: () = unwrap!(::maidsafe_utilities::log::init(false));
}

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
    let config = Config::with_contacts(&[nodes[1].handle.endpoint()]);
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
    log_init!();
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
    let config = Config::with_contacts(&[nodes[0].handle.endpoint()]);
    nodes.insert(0, TestNode::builder(&network).config(config).create());

    let _ = poll_all(&mut nodes, &mut []);

    verify_invariant_for_all_nodes(&mut nodes);
}

#[test]
fn multiple_joining_nodes() {
    let min_section_size = 8;
    let network = Network::new(min_section_size, None);
    let mut nodes = create_connected_nodes(&network, min_section_size);
    let config = Config::with_contacts(&[nodes[0].handle.endpoint()]);

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
    let config = Config::with_contacts(&[nodes[0].handle.endpoint()]);

    // Add two nodes simultaneously, to two different sections:
    // We now have two sections, with prefixes 0 and 1. Make one joining node contact each section,
    // and tell each section to allocate a name in its own section when `GetNodeName` is received.
    // This is to test that the routing table gets updated correctly (previously one new node would
    // miss the new node added to the neighbouring section).
    let (name0, name1) = (XorName([0u8; XOR_NAME_LEN]), XorName([255u8; XOR_NAME_LEN]));
    let prefix0 = Prefix::new(1, name0);

    for node in &mut *nodes {
        if prefix0.matches(&node.name()) {
            node.inner.set_next_reloc_section(name0);
        } else {
            node.inner.set_next_reloc_section(name1);
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
    let config = Config::with_contacts(&[nodes[0].handle.endpoint()]);

    for node in &mut *nodes {
        node.handle
            .0
            .borrow_mut()
            .whitelist_peer(PeerId(min_section_size));
    }
    // The next node has peer ID `min_section_size`: It should be able to join.
    nodes.push(TestNode::builder(&network)
                   .config(config.clone())
                   .create());
    let _ = poll_all(&mut nodes, &mut []);
    verify_invariant_for_all_nodes(&mut nodes);
    // The next node has peer ID `min_section_size + 1`: It is not whitelisted.
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
