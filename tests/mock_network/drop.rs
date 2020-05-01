// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    create_connected_nodes, node_left, poll_until, verify_invariants_for_nodes, LOWERED_ELDER_SIZE,
};
use rand::Rng;
use routing::{mock::Environment, NetworkParams};

#[test]
fn node_drops() {
    let env = Environment::new(NetworkParams {
        elder_size: LOWERED_ELDER_SIZE,
        safe_section_size: LOWERED_ELDER_SIZE + 1,
    });
    let mut rng = env.new_rng();
    let mut nodes = create_connected_nodes(&env, LOWERED_ELDER_SIZE + 2);

    let index = rng.gen_range(0, nodes.len());
    let dropped_name = *nodes.remove(index).name();

    poll_until(&env, &mut nodes, |nodes| node_left(nodes, &dropped_name));
    verify_invariants_for_nodes(&env, &nodes);
}
