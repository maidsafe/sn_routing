// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use super::test_client::TestClient;
use super::test_node::TestNode;

/// Empty event queue of nodes provided
pub fn nodes(nodes: &mut [TestNode]) {
    loop {
        let mut next = false;

        for node in nodes.iter_mut() {
            if node.poll() > 0 {
                next = true;
                break;
            }
        }

        if !next {
            break;
        }
    }
}

/// Resends all unacknowledged messages on all nodes.
pub fn resend_unacknowledged(nodes: &[TestNode], client: &TestClient) {
    for node in nodes {
        node.resend_unacknowledged()
    }
    client.resend_unacknowledged();
}

/// Empty event queue of nodes and clients provided
pub fn nodes_and_client(nodes: &mut [TestNode], client: &mut TestClient) -> usize {
    let mut count: usize = 0;
    loop {
        let prev_count = count;

        for node in nodes.iter_mut() {
            count += node.poll();
        }

        count += client.poll();

        if prev_count == count {
            break;
        }
    }
    count
}

/// Empty event queue of nodes and clients and resend unacknowledged messages.
pub fn poll_and_resend_unacknowledged(nodes: &mut [TestNode], client: &mut TestClient) -> usize {
    let count = nodes_and_client(nodes, client);
    resend_unacknowledged(nodes, client);
    count + nodes_and_client(nodes, client)
}
