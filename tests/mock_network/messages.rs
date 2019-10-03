// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{create_connected_nodes, poll_all};
use rand::Rng;
use routing::{mock::Network, Authority, Event, EventStream, QUORUM_DENOMINATOR, QUORUM_NUMERATOR};

#[test]
fn send() {
    let min_section_size = 8;
    let quorum = 1 + (min_section_size * QUORUM_NUMERATOR) / QUORUM_DENOMINATOR;
    let network = Network::new(min_section_size, None);
    let mut rng = network.new_rng();
    let mut nodes = create_connected_nodes(&network, min_section_size + 1);

    let sender_index = rng.gen_range(0, nodes.len());
    let src = Authority::Node(nodes[sender_index].name());
    let dst = Authority::NaeManager(rng.gen());
    let content: Vec<_> = rng.gen_iter().take(1024).collect();
    assert!(nodes[sender_index]
        .inner
        .send_message(src, dst, content.clone())
        .is_ok());

    let _ = poll_all(&mut nodes);

    let mut message_received_count = 0;
    for node in nodes.iter_mut().filter(|n| n.is_recipient(&dst)) {
        loop {
            match node.try_next_ev() {
                Ok(Event::MessageReceived {
                    content: ref req_content,
                    ..
                }) => {
                    message_received_count += 1;
                    if content == *req_content {
                        break;
                    }
                }
                Ok(_) => (),
                _ => panic!("Event::MessageReceived not received"),
            }
        }
    }

    assert!(message_received_count >= quorum);
}

#[test]
fn send_and_receive() {
    let min_section_size = 8;
    let quorum = 1 + (min_section_size * QUORUM_NUMERATOR) / QUORUM_DENOMINATOR;
    let network = Network::new(min_section_size, None);
    let mut rng = network.new_rng();
    let mut nodes = create_connected_nodes(&network, min_section_size + 1);

    let sender_index = rng.gen_range(0, nodes.len());
    let src = Authority::Node(nodes[sender_index].name());
    let dst = Authority::NaeManager(rng.gen());

    let req_content: Vec<_> = rng.gen_iter().take(10).collect();
    let res_content: Vec<_> = rng.gen_iter().take(11).collect();

    assert!(nodes[sender_index]
        .inner
        .send_message(src, dst, req_content.clone())
        .is_ok());

    let _ = poll_all(&mut nodes);

    let mut request_received_count = 0;

    for node in nodes.iter_mut().filter(|n| n.is_recipient(&dst)) {
        loop {
            match node.try_next_ev() {
                Ok(Event::MessageReceived { content, src, dst }) => {
                    request_received_count += 1;
                    if req_content == content {
                        if let Err(err) = node.inner.send_message(dst, src, res_content.clone()) {
                            trace!("Failed to send message: {:?}", err);
                        }
                        break;
                    }
                }
                Ok(_) => (),
                _ => panic!("Event::MessageReceived not received"),
            }
        }
    }

    assert!(request_received_count >= quorum);

    let _ = poll_all(&mut nodes);

    let mut response_received_count = 0;

    loop {
        match nodes[sender_index].inner.try_next_ev() {
            Ok(Event::MessageReceived { content, .. }) => {
                response_received_count += 1;
                if res_content == content {
                    break;
                }
            }
            Ok(_) => (),
            _ => panic!("Event::MessageReceived not received"),
        }
    }

    assert_eq!(response_received_count, 1);
}
