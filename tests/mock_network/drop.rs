// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    create_connected_nodes, poll_all, verify_dropped_nodes, verify_invariant_for_all_nodes,
    TestNode,
};
use routing::{mock::Network, NetworkParams, PublicId};
use std::{collections::BTreeSet, iter};

// Drop node at index and verify its still recognise as elder by other section members.
fn drop_node(nodes: &mut Vec<TestNode>, index: usize) -> BTreeSet<PublicId> {
    let node = nodes.remove(index);
    let id = node.id();
    let close_names = node.close_names();

    drop(node);

    // Using poll_all instead of poll_and_resend here to only let the other nodes realise the node
    // got disconnected, but not make more progress. We expect the node to remain elder until
    // detected as unresponsive.
    let _ = poll_all(nodes);

    for node in nodes.iter_mut().filter(|n| close_names.contains(&n.name())) {
        assert!(node.inner.is_peer_our_member(&id));
    }
    iter::once(id).collect()
}

#[test]
fn node_drops() {
    let elder_size = 8;
    let safe_section_size = 8;
    let network = Network::new(NetworkParams {
        elder_size,
        safe_section_size,
    });
    let mut nodes = create_connected_nodes(&network, elder_size + 2);

    let dropped_node = drop_node(&mut nodes, 0);

    let mut rng = network.new_rng();
    // Ensure the dropped node will be detected and removed later on with more user data exchanged.
    verify_dropped_nodes(&mut rng, &mut nodes, &dropped_node);

    verify_invariant_for_all_nodes(&network, &mut nodes);
}
