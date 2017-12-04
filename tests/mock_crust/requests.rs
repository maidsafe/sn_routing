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

use super::{create_connected_clients, create_connected_nodes, gen_bytes, gen_immutable_data,
            poll_all};
use routing::{Authority, ClientError, Event, EventStream, ImmutableData, MessageId, Request,
              Response};
use routing::mock_crust::Network;

#[test]
fn successful_put_request() {
    let min_section_size = 8;
    let network = Network::new(min_section_size, None);
    let mut rng = network.new_rng();
    let mut nodes = create_connected_nodes(&network, min_section_size + 1);
    let mut clients = create_connected_clients(&network, &mut nodes, 1);

    let dst = Authority::ClientManager(clients[0].name());
    let data = gen_immutable_data(&mut rng, 1024);
    let message_id = MessageId::new();

    assert!(
        clients[0]
            .inner
            .put_idata(dst, data.clone(), message_id)
            .is_ok()
    );

    let _ = poll_all(&mut nodes, &mut clients);

    let mut request_received_count = 0;
    for node in nodes.iter_mut().filter(|n| n.is_recipient(&dst)) {
        loop {
            match node.try_next_ev() {
                Ok(Event::Request {
                       request: Request::PutIData {
                           data: ref req_data,
                           msg_id: ref req_message_id,
                       },
                       ..
                   }) => {
                    request_received_count += 1;
                    if data == *req_data && message_id == *req_message_id {
                        break;
                    }
                }
                Ok(_) => (),
                _ => panic!("Event::Request not received"),
            }
        }
    }

    // TODO: Assert a quorum here.
    assert!(2 * request_received_count > min_section_size);
}

#[test]
fn successful_get_request() {
    let min_section_size = 8;
    let network = Network::new(min_section_size, None);
    let mut rng = network.new_rng();
    let mut nodes = create_connected_nodes(&network, min_section_size + 1);
    let mut clients = create_connected_clients(&network, &mut nodes, 1);

    let data = gen_immutable_data(&mut rng, 1024);
    let dst = Authority::NaeManager(*data.name());
    let message_id = MessageId::new();

    assert!(
        clients[0]
            .inner
            .get_idata(dst, *data.name(), message_id)
            .is_ok()
    );

    let _ = poll_all(&mut nodes, &mut clients);

    let mut request_received_count = 0;

    for node in nodes.iter_mut().filter(|n| n.is_recipient(&dst)) {
        loop {
            match node.try_next_ev() {
                Ok(Event::Request {
                       request: Request::GetIData {
                           name: ref req_name,
                           msg_id: req_message_id,
                       },
                       src,
                       dst,
                   }) => {
                    request_received_count += 1;
                    if data.name() == req_name && message_id == req_message_id {
                        if let Err(err) = node.inner.send_get_idata_response(
                            dst,
                            src,
                            Ok(data.clone()),
                            req_message_id,
                        )
                        {
                            trace!("Failed to send GetIData success response: {:?}", err);
                        }
                        break;
                    }
                }
                Ok(_) => (),
                _ => panic!("Event::Request not received"),
            }
        }
    }

    // TODO: Assert a quorum here.
    assert!(2 * request_received_count > min_section_size);

    let _ = poll_all(&mut nodes, &mut clients);

    let mut response_received_count = 0;

    for client in &mut clients {
        loop {
            match client.inner.try_next_ev() {
                Ok(Event::Response {
                       response: Response::GetIData {
                           res: Ok(ref res_data),
                           msg_id: ref res_message_id,
                       },
                       ..
                   }) => {
                    response_received_count += 1;
                    if data == *res_data && message_id == *res_message_id {
                        break;
                    }
                }
                Ok(_) => (),
                _ => panic!("Event::Response not received"),
            }
        }
    }

    assert_eq!(response_received_count, 1);
}

#[test]
fn failed_get_request() {
    let min_section_size = 8;
    let network = Network::new(min_section_size, None);
    let mut rng = network.new_rng();
    let mut nodes = create_connected_nodes(&network, min_section_size + 1);
    let mut clients = create_connected_clients(&network, &mut nodes, 1);

    let data = gen_immutable_data(&mut rng, 1024);
    let dst = Authority::NaeManager(*data.name());
    let message_id = MessageId::new();

    assert!(
        clients[0]
            .inner
            .get_idata(dst, *data.name(), message_id)
            .is_ok()
    );

    let _ = poll_all(&mut nodes, &mut clients);

    let mut request_received_count = 0;

    for node in nodes.iter_mut().filter(|n| n.is_recipient(&dst)) {
        loop {
            match node.try_next_ev() {
                Ok(Event::Request {
                       request: Request::GetIData {
                           name: ref req_name,
                           msg_id: ref req_message_id,
                       },
                       src,
                       dst,
                   }) => {
                    request_received_count += 1;
                    if data.name() == req_name && message_id == *req_message_id {
                        if let Err(err) = node.inner.send_get_idata_response(
                            dst,
                            src,
                            Err(ClientError::NoSuchData),
                            *req_message_id,
                        )
                        {
                            trace!("Failed to send GetIData failure response: {:?}", err);
                        }
                        break;
                    }
                }
                Ok(_) => (),
                _ => panic!("Event::Request not received"),
            }
        }
    }

    // TODO: Assert a quorum here.
    assert!(2 * request_received_count > min_section_size);

    let _ = poll_all(&mut nodes, &mut clients);

    let mut response_received_count = 0;

    for client in &mut clients {
        loop {
            match client.inner.try_next_ev() {
                Ok(Event::Response {
                       response: Response::GetIData {
                           res: Err(_),
                           msg_id: ref res_message_id,
                       },
                       ..
                   }) => {
                    response_received_count += 1;
                    if message_id == *res_message_id {
                        break;
                    }
                }
                Ok(_) => (),
                _ => panic!("Event::Response not received"),
            }
        }
    }

    assert_eq!(response_received_count, 1);
}

#[test]
fn disconnect_on_get_request() {
    let min_section_size = 8;
    let network = Network::new(min_section_size, None);
    let mut rng = network.new_rng();
    let mut nodes = create_connected_nodes(&network, 2 * min_section_size);
    let mut clients = create_connected_clients(&network, &mut nodes, 1);

    let data = ImmutableData::new(gen_bytes(&mut rng, 1024));
    let dst = Authority::NaeManager(*data.name());
    let message_id = MessageId::new();

    assert!(
        clients[0]
            .inner
            .get_idata(dst, *data.name(), message_id)
            .is_ok()
    );

    let _ = poll_all(&mut nodes, &mut clients);

    let mut request_received_count = 0;

    for node in nodes.iter_mut().filter(|n| n.is_recipient(&dst)) {
        loop {
            match node.try_next_ev() {
                Ok(Event::Request {
                       request: Request::GetIData {
                           name: ref req_name,
                           msg_id: ref req_message_id,
                       },
                       src,
                       dst,
                   }) => {
                    request_received_count += 1;
                    if data.name() == req_name && message_id == *req_message_id {
                        if let Err(err) = node.inner.send_get_idata_response(
                            dst,
                            src,
                            Ok(data.clone()),
                            *req_message_id,
                        )
                        {
                            trace!("Failed to send GetIData success response: {:?}", err);
                        }
                        break;
                    }
                }
                Ok(_) => (),
                _ => panic!("Event::Request not received"),
            }
        }
    }

    // TODO: Assert a quorum here.
    assert!(2 * request_received_count > min_section_size);

    clients[0].handle.0.borrow_mut().disconnect(&unwrap!(
        nodes[0]
            .handle
            .0
            .borrow()
            .uid
    ));
    nodes[0].handle.0.borrow_mut().disconnect(&unwrap!(
        clients[0]
            .handle
            .0
            .borrow()
            .uid
    ));

    let _ = poll_all(&mut nodes, &mut clients);

    for client in &mut clients {
        if let Ok(Event::Response { .. }) = client.inner.try_next_ev() {
            panic!("Unexpected Event::Response received");
        }
    }
}
