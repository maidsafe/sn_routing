// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{create_connected_nodes, gen_bytes, poll_all, sort_nodes_by_distance_to, TestNode};
use rand::Rng;
use routing::{
    mock::Network, Authority, Event, EventStream, NetworkParams, XorName, THRESHOLD_DENOMINATOR,
    THRESHOLD_NUMERATOR,
};

#[test]
fn messages_accumulate_with_quorum() {
    let section_size = 15;
    let network = Network::new(
        NetworkParams {
            elder_size: 8,
            safe_section_size: 8,
        },
        None,
    );
    let mut rng = network.new_rng();
    let mut nodes = create_connected_nodes(&network, section_size);

    let src = Authority::Section(rng.gen());
    sort_nodes_by_distance_to(&mut nodes, &src.name());

    let send = |node: &mut TestNode, dst: &Authority<XorName>, content: Vec<u8>| {
        assert!(node.inner.send_message(src, *dst, content).is_ok());
    };

    let dst = Authority::Node(nodes[0].name()); // The closest node.
    let content = gen_bytes(&mut rng, 8);

    // The smallest number such that `quorum * QUORUM_DENOMINATOR > section_size * QUORUM_NUMERATOR`:
    let quorum = 1 + section_size * THRESHOLD_NUMERATOR / THRESHOLD_DENOMINATOR;

    // Send a message from the section `src` to the node `dst`.
    // Only the `quorum`-th sender should cause accumulation and a
    // `MessageReceived` event. The event should only occur once.
    for node in nodes.iter_mut().take(quorum - 1) {
        send(node, &dst, content.clone());
    }
    let _ = poll_all(&mut nodes);
    expect_no_event!(nodes[0]);
    send(&mut nodes[quorum - 1], &dst, content.clone());
    let _ = poll_all(&mut nodes);
    expect_next_event!(nodes[0], Event::MessageReceived { .. });
    send(&mut nodes[quorum], &dst, content);
    let _ = poll_all(&mut nodes);
    expect_no_event!(nodes[0]);

    let dst_grp = Authority::Section(src.name()); // The whole section.
    let content = gen_bytes(&mut rng, 9);

    // Send a message from the section `src` to the section `dst_grp`. Only the `quorum`-th sender
    // should cause accumulation and a `MessageReceived` event. The event should only occur once.
    for node in nodes.iter_mut().take(quorum - 1) {
        send(node, &dst_grp, content.clone());
    }
    let _ = poll_all(&mut nodes);
    for node in &mut *nodes {
        expect_no_event!(node);
    }
    send(&mut nodes[quorum - 1], &dst_grp, content.clone());
    let _ = poll_all(&mut nodes);
    for node in &mut *nodes {
        expect_next_event!(node, Event::MessageReceived { .. });
    }
    send(&mut nodes[quorum], &dst_grp, content);
    let _ = poll_all(&mut nodes);
    for node in &mut *nodes {
        expect_no_event!(node);
    }
}
