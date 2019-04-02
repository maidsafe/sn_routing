// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    create_connected_clients, create_connected_nodes_until_split, gen_immutable_data, poll_all,
    TestNode,
};
use fake_clock::FakeClock;
use rand::Rng;
use routing::{
    mock::Network, Authority, Event, EventStream, ImmutableData, MessageId, Prefix, Request,
    Response,
};

// Generate random immutable data, but make sure the first node in the given
// node slice (the proxy node) is not in the data's section.
fn gen_immutable_data_not_in_first_node_section<T: Rng>(
    rng: &mut T,
    nodes: &[TestNode],
) -> ImmutableData {
    let first_name = nodes[0].name();
    // We want to make sure the data is inserted into a different section. Since the
    // root prefix uses 0 bits, we will have at least one section starting bit 0 and at
    // least one starting bit 1. If this differs, the sections are guaranteed different.
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
    let min_section_size = 8;
    let network = Network::new(min_section_size, None);

    let mut rng = network.new_rng();
    let mut nodes = create_connected_nodes_until_split(&network, vec![1, 1], true);
    let mut clients = create_connected_clients(&network, &mut nodes, 1);

    let proxy_node_name = nodes[0].name();

    // We need to make sure the proxy node isn't the one closest to the data,
    // because in that case the full response (as opposed to just a hash of it)
    // would originate from the proxy node and would never be relayed by it, thus
    // it would never be stored in the cache.
    let data = gen_immutable_data_not_in_first_node_section(&mut rng, &nodes);
    let data_id = *data.name();
    let message_id = MessageId::new();
    let dst = Authority::NaeManager(data_id);

    // No node has the data cached yet, so this request should reach the nodes
    // in the NAE manager section of the data.
    unwrap!(clients[0].inner.get_idata(dst, data_id, message_id));

    let _ = poll_all(&mut nodes, &mut clients);

    for node in &mut *nodes {
        loop {
            match node.try_next_ev() {
                Ok(Event::RequestReceived {
                    request:
                        Request::GetIData {
                            name: req_data_id,
                            msg_id: req_message_id,
                        },
                    src: req_src,
                    dst: req_dst,
                }) => {
                    if req_data_id == data_id && req_message_id == message_id {
                        unwrap!(node.inner.send_get_idata_response(
                            req_dst,
                            req_src,
                            Ok(data.clone()),
                            req_message_id,
                        ));
                        break;
                    }
                }
                Ok(_) => (),
                Err(_) => break,
            }
        }
    }

    let _ = poll_all(&mut nodes, &mut clients);

    expect_any_event!(
        clients[0],
        Event::ResponseReceived {
            response: Response::GetIData { res: Ok(ref res_data), msg_id: res_message_id },
            src: Authority::NaeManager(ref src_name),
            ..
        } if *res_data == data &&
             res_message_id == message_id &&
             src_name == data.name()
    );

    // Drain remaining events if any, and advance the fake clock by a second (TODO: check if still
    // necessary, waiting here was needed because of the rate limiter)
    while let Ok(_) = clients[0].inner.try_next_ev() {}
    let wait_millis = 1000;
    FakeClock::advance_time(wait_millis);

    let message_id = MessageId::new();

    // The proxy node should have cached the data, so this request should only
    // hit the proxy node and not be relayed to the other nodes.
    unwrap!(clients[0].inner.get_idata(dst, data_id, message_id));

    let _ = poll_all(&mut nodes, &mut clients);

    // The client should receive the response...
    expect_any_event!(
        clients[0],
        Event::ResponseReceived {
            response: Response::GetIData { res: Ok(ref res_data), msg_id: res_message_id },
            src: Authority::ManagedNode(src_name),
            ..
        } if *res_data == data &&
             res_message_id == message_id &&
             src_name == proxy_node_name
    );

    // ...but only once.
    expect_no_event!(clients[0]);

    // The request should not be relayed to any other node, so no node should
    // raise Event::RequestReceived.
    for node in nodes.iter_mut().take(min_section_size) {
        expect_no_event!(node);
    }
}
