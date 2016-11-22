// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.1.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use itertools::Itertools;
use rand::Rng;
use routing::{Authority, Data, DataIdentifier, Event, MIN_GROUP_SIZE, MessageId, QUORUM, Request,
              Response};
use routing::mock_crust::{Config, Network};
use super::{TestNode, create_connected_nodes, gen_immutable_data, gen_range_except,
            poll_and_resend, sort_nodes_by_distance_to, verify_invariant_for_all_nodes};

// Randomly add or remove some nodes, causing churn.
// If a new node was added, returns the index of this node. Otherwise
// returns `None` (it never adds more than one node).
//
// Note: it's necessary to call `poll_all` afterwards, as this function doesn't
// call it itself.
fn random_churn<R: Rng>(rng: &mut R,
                        network: &Network,
                        nodes: &mut Vec<TestNode>)
                        -> Option<usize> {
    let len = nodes.len();

    if len > MIN_GROUP_SIZE + 2 && rng.gen_weighted_bool(3) {
        let _ = nodes.remove(rng.gen_range(0, len));
        let _ = nodes.remove(rng.gen_range(0, len - 1));
        let _ = nodes.remove(rng.gen_range(0, len - 2));

        None
    } else {
        let proxy = rng.gen_range(0, len);
        let index = rng.gen_range(0, len + 1);
        let config = Config::with_contacts(&[nodes[proxy].handle.endpoint()]);

        nodes.insert(index, TestNode::builder(network).config(config).create());
        Some(index)
    }
}


// Check that the given node received a Get request with the given details.
fn did_receive_get_request(node: &TestNode,
                           expected_src: Authority,
                           expected_dst: Authority,
                           expected_data_id: DataIdentifier,
                           expected_message_id: MessageId)
                           -> bool {
    loop {
        match node.event_rx.try_recv() {
            Ok(Event::Request { request: Request::Get(data_id, message_id), ref src, ref dst })
                if *src == expected_src && *dst == expected_dst && data_id == expected_data_id &&
                   message_id == expected_message_id => return true,
            Ok(_) => (),
            Err(_) => return false,
        }
    }
}

fn did_receive_get_success(node: &TestNode,
                           expected_src: Authority,
                           expected_dst: Authority,
                           expected_data: Data,
                           expected_message_id: MessageId)
                           -> bool {
    loop {
        let expected = |src: &Authority, dst: &Authority, data: &Data, message_id: MessageId| {
            *src == expected_src && *dst == expected_dst && *data == expected_data &&
            message_id == expected_message_id
        };
        match node.event_rx.try_recv() {
            Ok(Event::Response { response: Response::GetSuccess(ref data, message_id),
                                 ref src,
                                 ref dst }) if expected(src, dst, data, message_id) => return true,
            Ok(_) => (),
            Err(_) => return false,
        }
    }
}

fn target_group(nodes: &[TestNode], target: Authority) -> Vec<&TestNode> {
    nodes.iter()
        .filter(|n| n.routing_table().is_recipient(&target.to_destination()))
        .collect_vec()
}


fn send_requests(group: Vec<&TestNode>,
                 src: Authority,
                 dst: Authority,
                 data_id: DataIdentifier,
                 message_id: MessageId) {
    for node in &group {
        let _ = node.inner.send_get_request(src, dst, data_id, message_id);
    }
}

fn count_received(group: Vec<&TestNode>,
                  src: Authority,
                  dst: Authority,
                  data_id: DataIdentifier,
                  message_id: MessageId)
                  -> usize {
    group.iter()
        .filter(|node| did_receive_get_request(node, src, dst, data_id, message_id))
        .count()
}

fn quorum(group_len: usize) -> usize {
    (group_len * QUORUM - 1) / 100 + 1
}

const CHURN_ITERATIONS: usize = 100;

#[test]
fn churn() {
    let network = Network::new(None);

    let mut rng = network.new_rng();
    let mut nodes = create_connected_nodes(&network, 20);

    for i in 0..CHURN_ITERATIONS {
        trace!("Iteration {}", i);
        let added_index = random_churn(&mut rng, &network, &mut nodes);

        // Create random data and pick random sending and receiving nodes.
        let data_id = gen_immutable_data(&mut rng, 8).identifier();
        let index0 = gen_range_except(&mut rng, 0, nodes.len(), added_index);
        let index1 = gen_range_except(&mut rng, 0, nodes.len(), added_index);
        let auth0 = Authority::ManagedNode(nodes[index0].name());
        let auth1 = Authority::ManagedNode(nodes[index1].name());
        let authd = Authority::NaeManager(*data_id.name());
        let msg_id_00 = MessageId::new();
        let msg_id_01 = MessageId::new();
        let msg_id_0d = MessageId::new();

        let quorum_before = quorum(nodes.iter()
            .enumerate()
            .filter(|&(i, n)| {
                Some(i) != added_index && n.routing_table().is_recipient(&authd.to_destination())
            })
            .count());

        unwrap!(nodes[index0].inner.send_get_request(auth0, auth0, data_id, msg_id_00));
        unwrap!(nodes[index0].inner.send_get_request(auth0, auth1, data_id, msg_id_01));
        unwrap!(nodes[index0].inner.send_get_request(auth0, authd, data_id, msg_id_0d));

        poll_and_resend(&mut nodes, &mut []);

        // TODO: These empty the nodes' event queues. When we add groups as destinations to this
        //       test, we'll need to accept the events in any order.
        assert!(did_receive_get_request(&nodes[index0], auth0, auth0, data_id, msg_id_00));
        assert!(did_receive_get_request(&nodes[index1], auth0, auth1, data_id, msg_id_01));

        {
            let receiving_group = target_group(&nodes, authd);
            let quorum_after = quorum(receiving_group.len());
            let num_received = count_received(receiving_group, auth0, authd, data_id, msg_id_0d);

            assert!(num_received >= quorum_before || num_received >= quorum_after,
                    "Received: {}, quorum_before: {}, quorum_after: {}",
                    num_received,
                    quorum_before,
                    quorum_after);
        }

        verify_invariant_for_all_nodes(&nodes);

        // Every few iterations, clear the nodes' caches, simulating a longer time between events.
        if rng.gen_weighted_bool(5) {
            for node in &mut nodes {
                node.inner.clear_state();
            }
        }
    }
}

const REQUEST_DURING_CHURN_ITERATIONS: usize = 10;

#[test]
#[ignore]
fn request_during_churn_group_to_self() {
    let network = Network::new(None);
    let mut rng = network.new_rng();
    let mut nodes = create_connected_nodes(&network, 2 * MIN_GROUP_SIZE);

    for _ in 0..REQUEST_DURING_CHURN_ITERATIONS {
        let name = rng.gen();
        let src = Authority::NaeManager(name);
        let dst = Authority::NaeManager(name);
        let data = gen_immutable_data(&mut rng, 8);
        let data_id = data.identifier();
        let message_id = MessageId::new();

        send_requests(target_group(&nodes, src), src, dst, data_id, message_id);
        let quorum_before = quorum(target_group(&nodes, dst).len());

        let _ = random_churn(&mut rng, &network, &mut nodes);
        poll_and_resend(&mut nodes, &mut []);

        let receiving_group = target_group(&nodes, dst);
        let quorum_after = quorum(receiving_group.len());
        let num_received = count_received(receiving_group, src, dst, data_id, message_id);

        assert!(num_received >= quorum_before || num_received >= quorum_after,
                "Received: {}, quorum_before: {}, quorum_after: {}",
                num_received,
                quorum_before,
                quorum_after);
    }
}

#[test]
#[ignore]
fn request_during_churn_group_to_node() {
    let network = Network::new(None);
    let mut rng = network.new_rng();
    let mut nodes = create_connected_nodes(&network, 2 * MIN_GROUP_SIZE);

    for _ in 0..REQUEST_DURING_CHURN_ITERATIONS {
        let added_index = random_churn(&mut rng, &network, &mut nodes);

        let message_id = MessageId::new();
        let data = gen_immutable_data(&mut rng, 8);
        let src = Authority::NaeManager(*data.name());

        sort_nodes_by_distance_to(&mut nodes, src.name());

        let except_index = added_index.unwrap_or(nodes.len());
        let group_len = nodes.iter()
            .enumerate()
            .filter(|&(i, n)| {
                i != except_index && n.routing_table().is_recipient(&src.to_destination())
            })
            .count();

        let index = rng.gen_range(0, group_len);
        let dst = Authority::ManagedNode(nodes[index].name());
        for node in &nodes[0..group_len] {
            unwrap!(node.inner.send_get_success(src, dst, data.clone(), message_id));
        }

        poll_and_resend(&mut nodes, &mut []);

        assert!(did_receive_get_success(&nodes[index], src, dst, data, message_id));
    }
}

#[test]
#[ignore]
fn request_during_churn_group_to_group() {
    let network = Network::new(None);
    let mut rng = network.new_rng();
    let mut nodes = create_connected_nodes(&network, 2 * MIN_GROUP_SIZE);

    for _ in 0..REQUEST_DURING_CHURN_ITERATIONS {
        let name0 = rng.gen();
        let name1 = rng.gen();
        let src = Authority::NodeManager(name0);
        let dst = Authority::NodeManager(name1);
        let data = gen_immutable_data(&mut rng, 8);
        let data_id = data.identifier();
        let message_id = MessageId::new();

        send_requests(target_group(&nodes, src), src, dst, data_id, message_id);
        let quorum_before = quorum(target_group(&nodes, dst).len());

        let _ = random_churn(&mut rng, &network, &mut nodes);
        poll_and_resend(&mut nodes, &mut []);

        let receiving_group = target_group(&nodes, dst);
        let quorum_after = quorum(receiving_group.len());
        let num_received = count_received(receiving_group, src, dst, data_id, message_id);

        assert!(num_received >= quorum_before || num_received >= quorum_after,
                "Received: {}, quorum_before: {}, quorum_after: {}",
                num_received,
                quorum_before,
                quorum_after);
    }
}
