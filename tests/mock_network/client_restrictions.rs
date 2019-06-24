// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{create_connected_nodes, poll_and_resend, TestClient, TestNode, MIN_SECTION_SIZE};
use routing::{mock::Network, Event, EventStream, FullId, NetworkConfig};

/// Reconnect a client (disconnected as network not having enough nodes) with the same id.
#[test]
// TODO (quic-p2p): This test requires bootstrap blacklist which isn't implemented in quic-p2p.
#[ignore]
fn reconnect_disconnected_client() {
    let network = Network::new(MIN_SECTION_SIZE, None);
    let mut nodes = create_connected_nodes(&network, MIN_SECTION_SIZE - 1);

    let config = NetworkConfig::client().with_hard_coded_contact(nodes[1].endpoint());
    let full_id = FullId::new();

    // Client will get rejected as network not having enough nodes.
    let mut clients = vec![TestClient::new_with_full_id(
        &network,
        Some(config),
        None,
        full_id.clone(),
    )];
    poll_and_resend(&mut nodes, &mut clients);
    expect_next_event!(unwrap!(clients.last_mut()), Event::Terminated);

    let _ = clients.remove(0);
    let config = NetworkConfig::node().with_hard_coded_contact(nodes[0].endpoint());
    nodes.push(TestNode::builder(&network).network_config(config).create());
    poll_and_resend(&mut nodes, &mut clients);

    // Reconnecting the client (with same id) shall succeed.
    let config = NetworkConfig::client().with_hard_coded_contact(nodes[1].endpoint());
    clients.push(TestClient::new_with_full_id(
        &network,
        Some(config),
        None,
        full_id,
    ));
    poll_and_resend(&mut nodes, &mut clients);
    expect_next_event!(unwrap!(clients.last_mut()), Event::Connected);
}
