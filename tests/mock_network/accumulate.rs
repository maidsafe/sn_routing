// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{create_connected_nodes, gen_bytes, poll_all, sort_nodes_by_distance_to, TestNode};
use rand::Rng;
use routing::{mock::Environment, Authority, Event, EventStream, NetworkParams, XorName};

#[test]
fn messages_accumulate_with_quorum() {
    let section_size = 15;
    let elder_size = 8;
    let env = Environment::new(NetworkParams {
        elder_size,
        safe_section_size: elder_size,
    });
    let mut rng = env.new_rng();
    let mut nodes = create_connected_nodes(&env, section_size);

    let src = Authority::Section(rng.gen());
    sort_nodes_by_distance_to(&mut nodes, &src.name());

    let send = |node: &mut TestNode, dst: &Authority<XorName>, content: Vec<u8>| {
        assert!(node.inner.send_message(src, *dst, content).is_ok());
    };

    // Fine to unwrap - we should have at least one elder, if not, it's a bug
    let closest_elder_index = nodes
        .iter()
        .enumerate()
        .filter(|(_, n)| n.inner.is_elder())
        .map(|(i, _)| i)
        .next()
        .unwrap();

    let dst = Authority::Node(nodes[closest_elder_index].name()); // The closest node.
    let content = gen_bytes(&mut rng, 8);

    // The BLS scheme will require more than `participants / 3`
    // shares in order to construct a full key or signature.
    // The smallest number such that `quorum > threshold`:
    let threshold = elder_size.saturating_sub(1) / 3;
    let quorum = 1 + threshold;

    // Send a message from the section `src` to the node `dst`.
    // Only the `quorum`-th sender should cause accumulation and a
    // `MessageReceived` event. The event should only occur once.
    for node in nodes
        .iter_mut()
        .filter(|node| node.inner.is_elder())
        .take(quorum - 1)
    {
        send(node, &dst, content.clone());
    }
    let _ = poll_all(&mut nodes);
    expect_no_event!(nodes[closest_elder_index]);
    for node in nodes
        .iter_mut()
        .rev()
        .filter(|node| node.inner.is_elder())
        .take(1)
    {
        send(node, &dst, content.clone());
    }
    let _ = poll_all(&mut nodes);
    expect_next_event!(nodes[closest_elder_index], Event::MessageReceived { .. });
    for node in nodes
        .iter_mut()
        .rev()
        .filter(|node| node.inner.is_elder())
        .skip(1)
        .take(1)
    {
        send(node, &dst, content.clone());
    }
    let _ = poll_all(&mut nodes);
    expect_no_event!(nodes[closest_elder_index]);

    let dst_grp = Authority::Section(src.name()); // The whole section.
    let content = gen_bytes(&mut rng, 9);

    // Send a message from the section `src` to the section `dst_grp`. Only the `quorum`-th sender
    // should cause accumulation and a `MessageReceived` event. The event should only occur once.
    for node in nodes
        .iter_mut()
        .filter(|node| node.inner.is_elder())
        .take(quorum - 1)
    {
        send(node, &dst_grp, content.clone());
    }
    let _ = poll_all(&mut nodes);
    for node in &mut *nodes {
        expect_no_event!(node);
    }
    for node in nodes
        .iter_mut()
        .rev()
        .filter(|node| node.inner.is_elder())
        .take(1)
    {
        send(node, &dst_grp, content.clone());
    }
    let _ = poll_all(&mut nodes);
    for node in nodes.iter_mut().filter(|node| node.inner.is_elder()) {
        expect_next_event!(node, Event::MessageReceived { .. });
    }
    for node in nodes
        .iter_mut()
        .rev()
        .filter(|node| node.inner.is_elder())
        .skip(1)
        .take(1)
    {
        send(node, &dst_grp, content.clone());
    }
    let _ = poll_all(&mut nodes);
    for node in &mut *nodes {
        expect_no_event!(node);
    }
}
