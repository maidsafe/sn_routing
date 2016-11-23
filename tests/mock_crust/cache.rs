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

// TODO: uncomment and fix

/*

use rand::Rng;
use routing::{Authority, Data, Event, MIN_GROUP_SIZE, MessageId, Prefix, Request, Response};
use routing::mock_crust::Network;
use super::{TestNode, create_connected_clients, create_connected_nodes_with_cache_till_split,
            gen_immutable_data, poll_all};
use std::sync::mpsc;

// Generate random immutable data, but make sure the first node in the given
// node slice (the proxy node) is not in the data's group.
fn gen_immutable_data_not_in_first_node_group<T: Rng>(rng: &mut T, nodes: &[TestNode]) -> Data {
    let first_name = nodes[0].name();
    // We want to make sure the data is inserted into a different group. Since the
    // root prefix uses 0 bits, we will have at least one group starting bit 0 and at
    // least one starting bit 1. If this differs, the groups are guaranteed different.
    let prefix = Prefix::new(1, first_name);

    loop {
        let data = gen_immutable_data(rng, 8);
        if !prefix.matches(data.name()) {
            return data;
        }
    }
}

#[test]
fn response_caching() {
    let network = Network::new(None);

    let mut rng = network.new_rng();
    let mut nodes = create_connected_nodes_with_cache_till_split(&network);
    let mut clients = create_connected_clients(&network, &mut nodes, 1);

    let proxy_node_name = nodes[0].name();

    // We need to make sure the proxy node isn't the one closest to the data,
    // because in that case the full response (as opposed to just a hash of it)
    // would originate from the proxy node and would never be relayed by it, thus
    // it would never be stored in the cache.
    let data = gen_immutable_data_not_in_first_node_group(&mut rng, &nodes);
    let data_name = *data.name();
    let msg_id = MessageId::new();
    let dst = Authority::NaeManager(data_name);

    // No node has the data cached yet, so this request should reach the nodes
    // in the NAE manager group of the data.
    unwrap!(clients[0].inner.get_idata(dst, data_name, msg_id));

    poll_all(&mut nodes, &mut clients);

    for node in &nodes {
        loop {
            match node.event_rx.try_recv() {
                Ok(Event::Request { request: Request::GetIData { name: req_data_name,
                                                        msg_id: req_msg_id },
                                    src: req_src,
                                    dst: req_dst }) => {
                    if req_data_name == data_name && req_msg_id == msg_id {
                        unwrap!(node.inner
                            .send_get_success(req_dst, req_src, data.clone(), req_msg_id));
                        break;
                    }
                }
                Ok(_) => (),
                Err(_) => break,
            }
        }
    }

    poll_all(&mut nodes, &mut clients);

    expect_any_event!(
        clients[0],
        Event::Response {
            response: Response::GetIData {
                res: Ok(res_data),
                msg_id: res_msg_id
            },
            src: Authority::NaeManager(ref src_name),
            ..
        } if res_data == data &&
             res_msg_id == msg_id &&
             src_name == data.name()
    );

    // Drain remaining events if any.
    while let Ok(_) = clients[0].event_rx.try_recv() {}

    let msg_id = MessageId::new();

    // The proxy node should have cached the data, so this request should only
    // hit the proxy node and not be relayed to the other nodes.
    unwrap!(clients[0].inner.get_idata(dst, data_name, msg_id));

    poll_all(&mut nodes, &mut clients);

    // The client should receive ack for the request.
    assert!(!clients[0].inner.has_unacknowledged());

    // The client should receive the response...
    expect_any_event!(
        clients[0],
        Event::Response {
            response: Response::GetIData {
                res: Ok(res_data),
                msg_id: res_msg_id
            },
            src: Authority::ManagedNode(src_name),
            ..
        } if res_data == data &&
             res_msg_id == msg_id &&
             src_name == proxy_node_name
    );

    // ...but only once.
    expect_no_event!(clients[0]);

    // The request should not be relayed to any other node, so no node should
    // raise Event::Request.
    for node in nodes.iter().take(MIN_GROUP_SIZE) {
        expect_no_event!(node);
    }
}

*/
