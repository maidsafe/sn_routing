// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{create_connected_nodes, gen_elder_index, gen_vec, poll_until, TestNode};
use rand::Rng;
use routing::{
    event::Event, mock::Environment, quorum_count, DstLocation, NetworkParams, SrcLocation,
};
use std::collections::HashMap;

#[test]
fn send() {
    let elder_size = 8;
    let safe_section_size = 8;
    let quorum = quorum_count(elder_size);
    let env = Environment::new(NetworkParams {
        elder_size,
        safe_section_size,
    });
    let mut rng = env.new_rng();
    let mut nodes = create_connected_nodes(&env, elder_size + 1);

    let sender_index = gen_elder_index(&mut rng, &nodes);
    let src = SrcLocation::Node(*nodes[sender_index].name());
    let dst = DstLocation::Section(rng.gen());
    let content = gen_vec(&mut rng, 1024);
    assert!(nodes[sender_index]
        .inner
        .send_message(src, dst, content.clone())
        .is_ok());

    let mut expected_recipients: HashMap<_, _> = expected_recipients(&nodes, &dst)
        .map(|index| (index, false))
        .collect();
    assert!(expected_recipients.len() >= quorum);

    // Poll until every node that is expected to receive the message actually receives it.
    poll_until(&env, &mut nodes, |nodes| {
        for (index, node) in nodes.iter().enumerate() {
            if let Some(received) = expected_recipients.get_mut(&index) {
                *received = *received || message_received(node, &content);
            }
        }

        expected_recipients.values().all(|&received| received)
    });
}

#[test]
fn send_and_receive() {
    let elder_size = 8;
    let safe_section_size = 8;
    let quorum = quorum_count(elder_size);
    let env = Environment::new(NetworkParams {
        elder_size,
        safe_section_size,
    });
    let mut rng = env.new_rng();
    let mut nodes = create_connected_nodes(&env, elder_size + 1);

    let sender_index = gen_elder_index(&mut rng, &nodes);
    let req_src = SrcLocation::Node(*nodes[sender_index].name());
    let req_dst = DstLocation::Section(rng.gen());
    let req_content = gen_vec(&mut rng, 10);
    let res_content = gen_vec(&mut rng, 11);

    assert!(nodes[sender_index]
        .inner
        .send_message(req_src, req_dst, req_content.clone())
        .is_ok());

    // For all expected recipients, poll until it receives the request message and sends
    // the response
    let expected_req_recipients: Vec<_> = expected_recipients(&nodes, &req_dst).collect();
    assert!(expected_req_recipients.len() >= quorum);

    for index in expected_req_recipients {
        // Poll until the node received the request...
        poll_until(&env, &mut nodes, |nodes| {
            message_received(&nodes[index], &req_content)
        });

        // ...then send the response back.
        let res_src = SrcLocation::Section(*nodes[index].our_prefix());
        let res_dst = DstLocation::Node(*nodes[sender_index].name());

        if let Err(err) = nodes[index]
            .inner
            .send_message(res_src, res_dst, res_content.clone())
        {
            trace!("Failed to send message: {:?}", err);
        }
    }

    // Poll until the response is received by the sender of the request.
    poll_until(&env, &mut nodes, |nodes| {
        message_received(&nodes[sender_index], &res_content)
    })
}

// Returns the indices of the nodes that are expected to receive a message with the given
// destination.
fn expected_recipients<'a>(
    nodes: &'a [TestNode],
    dst: &'a DstLocation,
) -> impl Iterator<Item = usize> + 'a {
    nodes
        .iter()
        .enumerate()
        .filter(move |(_, node)| node.inner.is_elder() && node.inner.in_dst_location(dst))
        .map(|(index, _)| index)
}

// Returns whether the given node received a message with the given content since the last time
// this function was called, or since the beginning of the polling if this is the first call.
fn message_received(node: &TestNode, expected_content: &[u8]) -> bool {
    while let Some(event) = node.try_recv_event() {
        if let Event::MessageReceived { content, .. } = event {
            if content == expected_content {
                return true;
            }
        }

        // Ignore any other events
    }

    false
}
