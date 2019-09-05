// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{create_connected_nodes, poll_all};
use rand::Rng;
use routing::{
    mock::Network, Authority, Event, EventStream, MessageId, Request, Response, QUORUM_DENOMINATOR,
    QUORUM_NUMERATOR,
};

#[test]
fn send() {
    let min_section_size = 8;
    let quorum = 1 + (min_section_size * QUORUM_NUMERATOR) / QUORUM_DENOMINATOR;
    let network = Network::new(min_section_size, None);
    let mut rng = network.new_rng();
    let mut nodes = create_connected_nodes(&network, min_section_size + 1);

    let sender_index = rng.gen_range(0, nodes.len());
    let src = Authority::ManagedNode(nodes[sender_index].name());
    let dst = Authority::NaeManager(rng.gen());

    let content: Vec<_> = rng.gen_iter().take(1024).collect();
    let msg_id = MessageId::new();

    assert!(nodes[sender_index]
        .inner
        .send_request(
            src,
            dst,
            Request {
                content: content.clone(),
                msg_id
            }
        )
        .is_ok());

    let _ = poll_all(&mut nodes);

    let mut request_received_count = 0;
    for node in nodes.iter_mut().filter(|n| n.is_recipient(&dst)) {
        loop {
            match node.try_next_ev() {
                Ok(Event::RequestReceived {
                    request:
                        Request {
                            content: ref req_content,
                            msg_id: ref req_msg_id,
                        },
                    ..
                }) => {
                    request_received_count += 1;
                    if content == *req_content && msg_id == *req_msg_id {
                        break;
                    }
                }
                Ok(_) => (),
                _ => panic!("Event::RequestReceived not received"),
            }
        }
    }

    assert!(request_received_count >= quorum);
}

#[test]
fn send_and_receive() {
    let min_section_size = 8;
    let quorum = 1 + (min_section_size * QUORUM_NUMERATOR) / QUORUM_DENOMINATOR;
    let network = Network::new(min_section_size, None);
    let mut rng = network.new_rng();
    let mut nodes = create_connected_nodes(&network, min_section_size + 1);

    let sender_index = rng.gen_range(0, nodes.len());
    let src = Authority::ManagedNode(nodes[sender_index].name());
    let dst = Authority::NaeManager(rng.gen());

    let req_content: Vec<_> = rng.gen_iter().take(10).collect();
    let res_content: Vec<_> = rng.gen_iter().take(11).collect();

    let msg_id = MessageId::new();

    assert!(nodes[sender_index]
        .inner
        .send_request(
            src,
            dst,
            Request {
                content: req_content.clone(),
                msg_id
            }
        )
        .is_ok());

    let _ = poll_all(&mut nodes);

    let mut request_received_count = 0;

    for node in nodes.iter_mut().filter(|n| n.is_recipient(&dst)) {
        loop {
            match node.try_next_ev() {
                Ok(Event::RequestReceived {
                    request:
                        Request {
                            content,
                            msg_id: req_msg_id,
                        },
                    src,
                    dst,
                }) => {
                    request_received_count += 1;
                    if req_content == content && msg_id == req_msg_id {
                        if let Err(err) = node.inner.send_response(
                            dst,
                            src,
                            Response {
                                content: res_content.clone(),
                                msg_id: req_msg_id,
                            },
                        ) {
                            trace!("Failed to send GetIData success response: {:?}", err);
                        }
                        break;
                    }
                }
                Ok(_) => (),
                _ => panic!("Event::RequestReceived not received"),
            }
        }
    }

    assert!(request_received_count >= quorum);

    let _ = poll_all(&mut nodes);

    let mut response_received_count = 0;

    loop {
        match nodes[sender_index].inner.try_next_ev() {
            Ok(Event::ResponseReceived {
                response:
                    Response {
                        content,
                        msg_id: res_msg_id,
                    },
                ..
            }) => {
                response_received_count += 1;
                if res_content == content && msg_id == res_msg_id {
                    break;
                }
            }
            Ok(_) => (),
            _ => panic!("Event::ResponseReceived not received"),
        }
    }

    assert_eq!(response_received_count, 1);
}
