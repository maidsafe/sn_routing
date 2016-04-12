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

use routing::mock_crust::{self, Endpoint, Network, ServiceHandle};
use safe_vault::{Config, Vault};
use xor_name::XorName;

use super::poll;

pub struct TestNode {
    handle: ServiceHandle,
    vault: Vault,
}

impl TestNode {
    pub fn new(network: &Network,
               crust_config: Option<mock_crust::Config>,
               config: Option<Config>)
               -> Self {
        let handle = network.new_service_handle(crust_config, None);
        let vault = mock_crust::make_current(&handle, || unwrap_result!(Vault::new(config)));

        TestNode {
            handle: handle,
            vault: vault,
        }
    }

    pub fn poll(&mut self) -> bool {
        let mut result = false;

        while self.vault.poll() {
            result = true;
        }

        result
    }

    pub fn endpoint(&self) -> Endpoint {
        self.handle.endpoint()
    }

    pub fn get_stored_names(&self) -> Vec<XorName> {
        self.vault.get_stored_names()
    }
}

pub fn create_nodes(network: &Network, size: usize, config: Option<Config>) -> Vec<TestNode> {
    let mut nodes = Vec::new();

    // Create the seed node.
    nodes.push(TestNode::new(network, None, config.clone()));
    while nodes[0].poll() {}

    let crust_config = mock_crust::Config::with_contacts(&[nodes[0].endpoint()]);

    // Create other nodes using the seed node endpoint as bootstrap contact.
    for _ in 1..size {
        nodes.push(TestNode::new(network, Some(crust_config.clone()), config.clone()));
        poll::nodes(&mut nodes);
    }

    nodes
}

pub fn _add_nodes(network: &Network, mut nodes: &mut Vec<TestNode>, size: usize) {
    let mut config = None;

    if !nodes.is_empty() {
        config = Some(mock_crust::Config::with_contacts(&[nodes[0].endpoint()]));
    }

    for _ in 0..size {
        nodes.push(TestNode::new(network, config.clone(), None));
        poll::nodes(&mut nodes);
    }
}

pub fn _add_node(network: &Network, nodes: &mut Vec<TestNode>) {
    let config = mock_crust::Config::with_contacts(&[nodes[0].endpoint()]);
    nodes.push(TestNode::new(network, Some(config.clone()), None));
    poll::nodes(nodes);
}

pub fn _drop_node(nodes: &mut Vec<TestNode>, index: usize) {
    let node = nodes.remove(index);
    drop(node);
    _poll_all(nodes);
}

/// Process all events
fn _poll_all(nodes: &mut [TestNode]) {
    while nodes.iter_mut().any(TestNode::poll) {}
}
