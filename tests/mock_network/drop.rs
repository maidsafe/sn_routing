// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    create_connected_nodes, poll_all, poll_and_resend, verify_invariants_for_nodes, TestNode,
};
use routing::{mock::Environment, NetworkParams};

// Drop node at index and verify its own section detected it.
fn drop_node(env: &Environment, nodes: &mut Vec<TestNode>, index: usize) {
    let _ = nodes.remove(index);

    // Using poll_all instead of poll_and_resend here to only let the other nodes realise the node
    // got disconnected, but not make more progress.
    let _ = poll_all(env, nodes);
}

#[test]
fn node_drops() {
    let elder_size = 8;
    let safe_section_size = 8;
    let env = Environment::new(NetworkParams {
        elder_size,
        safe_section_size,
    });
    let mut nodes = create_connected_nodes(&env, elder_size + 2);
    drop_node(&env, &mut nodes, 0);

    // Trigger poll_and_resend to allow remaining nodes to gossip and
    // update their chain accordingly.
    poll_and_resend(&mut nodes);
    verify_invariants_for_nodes(&env, &nodes);
}
