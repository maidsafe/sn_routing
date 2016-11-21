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
            gen_two_range_except, poll_and_resend, sort_nodes_by_distance_to,
            verify_invariant_for_all_nodes};

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

fn quorum_calculate(nodes: &[TestNode],
                    request_info: (Authority, Authority, DataIdentifier, MessageId),
                    target: Authority,
                    send_get: bool,
                    check_received: bool)
                    -> (usize, usize) {
    let group = nodes.iter()
        .filter(|n| n.routing_table().is_recipient(&target.to_destination()))
        .collect_vec();
    let quorum = (group.len() * QUORUM - 1) / 100 + 1;

    if send_get {
        for node in &group {
            let _ = node.inner.send_get_request(request_info.0,
                                                request_info.1,
                                                request_info.2,
                                                request_info.3);
        }
    }

    let num_received = if check_received { 
        group.iter()
             .filter(|node| did_receive_get_request(node,
                                                    request_info.0,
                                                    request_info.1,
                                                    request_info.2,
                                                    request_info.3))
             .count()
    } else {
        0
    };
    (quorum, num_received)
}

#[test]
#[ignore]
fn churn() {
    let network = Network::new(None);

    let mut rng = network.new_rng();
    let mut nodes = create_connected_nodes(&network, 20);

    for i in 0..100 {
        trace!("Iteration {}", i);
        let _ = random_churn(&mut rng, &network, &mut nodes);
        poll_and_resend(&mut nodes, &mut []);

        for node in &mut nodes {
            node.inner.clear_state();
        }

        verify_invariant_for_all_nodes(&nodes);
    }
}

const REQUEST_DURING_CHURN_ITERATIONS: usize = 10;

#[test]
fn request_during_churn_node_to_self() {
    let network = Network::new(None);
    let mut rng = network.new_rng();

    let mut nodes = create_connected_nodes(&network, 2 * MIN_GROUP_SIZE);

    for _ in 0..REQUEST_DURING_CHURN_ITERATIONS {
        let added_index = random_churn(&mut rng, &network, &mut nodes);
        let index = gen_range_except(&mut rng, 0, nodes.len(), added_index);
        let name = nodes[index].name();

        let src = Authority::ManagedNode(name);
        let dst = Authority::ManagedNode(name);
        let data = gen_immutable_data(&mut rng, 8);
        let data_id = data.identifier();
        let message_id = MessageId::new();

        unwrap!(nodes[index].inner.send_get_request(src, dst, data_id, message_id));

        poll_and_resend(&mut nodes, &mut []);
        assert!(did_receive_get_request(&nodes[index], src, dst, data_id, message_id));
    }
}

#[test]
fn request_during_churn_node_to_node() {
    let network = Network::new(None);
    let mut rng = network.new_rng();
    let mut nodes = create_connected_nodes(&network, 2 * MIN_GROUP_SIZE);

    for _ in 0..REQUEST_DURING_CHURN_ITERATIONS {
        let added_index = random_churn(&mut rng, &network, &mut nodes);

        let (index0, index1) = gen_two_range_except(&mut rng, 0, nodes.len(), added_index);
        let name0 = nodes[index0].name();
        let name1 = nodes[index1].name();

        let src = Authority::ManagedNode(name0);
        let dst = Authority::ManagedNode(name1);
        let data = gen_immutable_data(&mut rng, 8);
        let data_id = data.identifier();
        let message_id = MessageId::new();

        unwrap!(nodes[index0].inner.send_get_request(src, dst, data_id, message_id));

        poll_and_resend(&mut nodes, &mut []);
        assert!(did_receive_get_request(&nodes[index1], src, dst, data_id, message_id));
    }
}

#[test]
#[ignore]
fn request_during_churn_node_to_group() {
    let network = Network::new(None);
    let mut rng = network.new_rng();
    let mut nodes = create_connected_nodes(&network, 2 * MIN_GROUP_SIZE);

    for _ in 0..REQUEST_DURING_CHURN_ITERATIONS {
        let added_index = random_churn(&mut rng, &network, &mut nodes);

        let index = gen_range_except(&mut rng, 0, nodes.len(), added_index);

        let data = gen_immutable_data(&mut rng, 8);
        let src = Authority::ManagedNode(nodes[index].name());
        let dst = Authority::NaeManager(*data.name());
        let data_id = data.identifier();
        let message_id = MessageId::new();

        unwrap!(nodes[index].inner.send_get_request(src, dst, data_id, message_id));

        poll_and_resend(&mut nodes, &mut []);

        let (quorum, num_received) =
            quorum_calculate(&nodes, (src, dst, data_id, message_id), dst, false, true);

        assert!(num_received >= quorum,
                "Received: {}, quorum: {}",
                num_received,
                quorum);
    }
}

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

        let (quorum_before, _) =
            quorum_calculate(&nodes, (src, dst, data_id, message_id), src, true, false);

        let _ = random_churn(&mut rng, &network, &mut nodes);

        poll_and_resend(&mut nodes, &mut []);

        let (quorum_after, num_received) =
            quorum_calculate(&nodes, (src, dst, data_id, message_id), dst, false, true);

        assert!(num_received >= quorum_before || num_received >= quorum_after,
                "Received: {}, quorum_before: {}, quorum_after: {}",
                num_received,
                quorum_before,
                quorum_after);
    }
}

#[test]
fn request_during_churn_group_to_node() {
    let network = Network::new(None);
    let mut rng = network.new_rng();
    let mut nodes = create_connected_nodes(&network, 2 * MIN_GROUP_SIZE);

    for _ in 0..REQUEST_DURING_CHURN_ITERATIONS {
        let message_id = MessageId::new();
        let data = gen_immutable_data(&mut rng, 8);
        let src = Authority::NaeManager(*data.name());

        sort_nodes_by_distance_to(&mut nodes, src.name());

        let group_len = nodes.iter()
            .filter(|n| n.routing_table().is_recipient(&src.to_destination()))
            .count();

        let index = rng.gen_range(0, group_len);
        let dst = Authority::ManagedNode(nodes[index].name());
        for node in &nodes[0..group_len] {
            unwrap!(node.inner.send_get_success(src, dst, data.clone(), message_id));
        }

        let proxy = rng.gen_range(0, nodes.len());
        let config = Config::with_contacts(&[nodes[proxy].handle.endpoint()]);
        nodes.push(TestNode::builder(&network).config(config).create());
        poll_and_resend(&mut nodes, &mut []);

        assert!(did_receive_get_success(&nodes[index], src, dst, data, message_id));
    }
}

#[test]
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

        let (quorum_before, _) =
            quorum_calculate(&nodes, (src, dst, data_id, message_id), src, true, false);

        let _added_index = random_churn(&mut rng, &network, &mut nodes);
        poll_and_resend(&mut nodes, &mut []);

        let (quorum_after, num_received) =
            quorum_calculate(&nodes, (src, dst, data_id, message_id), dst, false, true);

        assert!(num_received >= quorum_before || num_received >= quorum_after,
                "Received: {}, quorum_before: {}, quorum_after: {}",
                num_received,
                quorum_before,
                quorum_after);
    }
}
