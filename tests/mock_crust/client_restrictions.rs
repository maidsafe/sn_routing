// Copyright 2017 MaidSafe.net limited.
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

use super::{MIN_SECTION_SIZE, TestClient, TestNode, create_connected_clients,
            create_connected_nodes, poll_all, poll_and_resend};
use rand::Rng;
use routing::{Authority, BootstrapConfig, Event, EventStream, FullId, ImmutableData,
              MAX_IMMUTABLE_DATA_SIZE_IN_BYTES, MessageId, Request};
use routing::mock_crust::Network;
use routing::rate_limiter_consts::MAX_PARTS;

/// Connect a client to the network then send an invalid message.
/// Expect the client will be disconnected and banned;
#[test]
fn ban_malicious_client() {
    let network = Network::new(MIN_SECTION_SIZE, None);
    let mut nodes = create_connected_nodes(&network, MIN_SECTION_SIZE);
    let mut clients = create_connected_clients(&network, &mut nodes, 1);
    let mut rng = network.new_rng();

    // Send a `Refresh` request from the client; should cause it to get banned.
    let _ = clients[0].inner.send_request(
        Authority::NaeManager(rng.gen()),
        Request::Refresh(vec![], MessageId::new()),
        2,
    );
    let _ = poll_all(&mut nodes, &mut clients);
    expect_next_event!(unwrap!(clients.last_mut()), Event::Terminate);
    let banned_client_ips = nodes[0].inner.get_banned_client_ips();
    assert_eq!(banned_client_ips.len(), 1);
    let ip_addr = clients[0].ip();
    assert_eq!(unwrap!(banned_client_ips.into_iter().next()), ip_addr);

    let _ = clients.remove(0);
    let _ = poll_all(&mut nodes, &mut clients);

    // Connect a new client with the same ip address shall get rejected.
    let endpoint = network.gen_endpoint_with_ip(&ip_addr);
    let contact = nodes[0].handle.endpoint();
    let client = TestClient::new(
        &network,
        Some(BootstrapConfig::with_contacts(&[contact])),
        Some(endpoint),
    );
    clients.push(client);
    let _ = poll_all(&mut nodes, &mut clients);
    expect_next_event!(unwrap!(clients.last_mut()), Event::Terminate);
}

/// Connects two clients to the network using the same ip address and via the same proxy.
/// Expect only one client got connected.
#[test]
fn only_one_client_per_ip() {
    let network = Network::new(MIN_SECTION_SIZE, None);
    let mut nodes = create_connected_nodes(&network, MIN_SECTION_SIZE);
    let mut clients = create_connected_clients(&network, &mut nodes, 1);

    // Connect a new client with the same ip address shall get rejected.
    let endpoint = network.gen_endpoint_with_ip(&clients[0].ip());
    let contact = nodes[0].handle.endpoint();
    let client = TestClient::new(
        &network,
        Some(BootstrapConfig::with_contacts(&[contact])),
        Some(endpoint),
    );
    clients.push(client);
    let _ = poll_all(&mut nodes, &mut clients);
    expect_next_event!(unwrap!(clients.last_mut()), Event::Terminate);
}

/// Reconnect a client (disconnected as network not having enough nodes) with the same id.
#[test]
fn reconnect_disconnected_client() {
    let network = Network::new(MIN_SECTION_SIZE, None);
    let mut nodes = create_connected_nodes(&network, MIN_SECTION_SIZE - 1);

    let config = Some(BootstrapConfig::with_contacts(
        &[nodes[1].handle.endpoint()],
    ));
    let full_id = FullId::new();

    // Client will get rejected as network not having enough nodes.
    let mut clients =
        vec![
            TestClient::new_with_full_id(&network, config.clone(), None, full_id.clone()),
        ];
    let _ = poll_all(&mut nodes, &mut clients);
    expect_next_event!(unwrap!(clients.last_mut()), Event::Terminate);

    let _ = clients.remove(0);
    let bootstrap_config = BootstrapConfig::with_contacts(&[nodes[0].handle.endpoint()]);
    nodes.push(
        TestNode::builder(&network)
            .bootstrap_config(bootstrap_config)
            .create(),
    );
    let _ = poll_all(&mut nodes, &mut clients);

    // Reconnecting the client (with same id) shall succeed.
    clients.push(TestClient::new_with_full_id(
        &network,
        config,
        None,
        full_id,
    ));
    let _ = poll_all(&mut nodes, &mut clients);
    expect_next_event!(unwrap!(clients.last_mut()), Event::Connected);
}


/// Confirming the number of user message parts being sent in case of exceeding limit.
#[test]
fn resending_parts_on_exceeding_limit() {
    let network = Network::new(MIN_SECTION_SIZE, None);
    let mut rng = network.new_rng();
    let mut nodes = create_connected_nodes(&network, MIN_SECTION_SIZE);
    let mut clients = create_connected_clients(&network, &mut nodes, 1);

    let mut datas = vec![
        ImmutableData::new(
            rng.gen_iter()
                .take((MAX_IMMUTABLE_DATA_SIZE_IN_BYTES / 2) as usize)
                .collect()
        ),
    ];
    datas.push(ImmutableData::new(
        rng.gen_iter()
            .take(MAX_IMMUTABLE_DATA_SIZE_IN_BYTES as usize)
            .collect(),
    ));

    for data in datas {
        let msg_id = MessageId::new();
        let dst = Authority::NaeManager(*data.name());
        unwrap!(clients[0].inner.put_idata(dst, data, msg_id));
    }
    let _ = poll_and_resend(&mut nodes, &mut clients);

    // `MAX_PARTS / 2` parts will be resent from client.
    let client_expected_sent_parts = (2 * MAX_PARTS) as u64;
    assert_eq!(
        clients[0].inner.get_user_msg_parts_count(),
        client_expected_sent_parts
    );

    // Node shall not receive any duplicated parts.
    let node_expected_sent_parts = (MAX_PARTS + MAX_PARTS / 2) as u64;
    for node in nodes.iter() {
        assert_eq!(
            node.inner.get_user_msg_parts_count(),
            node_expected_sent_parts
        );
    }
}
