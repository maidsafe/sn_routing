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

// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md

use kademlia_routing_table::GROUP_SIZE;
use rand::{random, thread_rng};
use rand::distributions::{IndependentSample, Range};
use routing::{Data, ImmutableData};
use routing::mock_crust::{self, Network};
use safe_network_common::client_errors::MutationError;
use safe_vault::mock_crust_detail::{self, poll, test_node};
use safe_vault::mock_crust_detail::test_client::TestClient;
use safe_vault::test_utils;

const TEST_NET_SIZE: usize = 20;

#[test]
fn handle_put_without_account() {
    let network = Network::new();
    let node_count = TEST_NET_SIZE;
    let mut nodes = test_node::create_nodes(&network, node_count, None);
    let config = mock_crust::Config::with_contacts(&[nodes[0].endpoint()]);
    let mut client = TestClient::new(&network, Some(config));

    client.ensure_connected(&mut nodes);

    let immutable_data = ImmutableData::new(test_utils::generate_random_vec_u8(1024));
    client.put(Data::Immutable(immutable_data));
    let _ = poll::nodes_and_client(&mut nodes, &mut client);
    let count = nodes.iter()
        .filter(|node| node.get_maid_manager_put_count(client.name()).is_some())
        .count();
    assert!(0 == count,
            "put_count {} found with {} nodes",
            count,
            node_count);
}

#[test]
fn handle_put_with_account() {
    let network = Network::new();
    let node_count = TEST_NET_SIZE;
    let mut nodes = test_node::create_nodes(&network, node_count, None);
    let config = mock_crust::Config::with_contacts(&[nodes[0].endpoint()]);
    let mut client = TestClient::new(&network, Some(config));

    client.ensure_connected(&mut nodes);
    client.create_account(&mut nodes);

    let immutable_data = ImmutableData::new(test_utils::generate_random_vec_u8(1024));
    client.put(Data::Immutable(immutable_data.clone()));
    let _ = poll::nodes_and_client(&mut nodes, &mut client);
    let count = nodes.iter()
        .filter(|node| node.get_maid_manager_put_count(client.name()).is_some())
        .count();
    assert!(GROUP_SIZE == count,
            "client account {} found on {} nodes",
            count,
            node_count);
    let mut stored_immutable = Vec::new();
    stored_immutable.push(Data::Immutable(immutable_data));
    mock_crust_detail::check_data(stored_immutable, &nodes);
}

#[test]
#[should_panic] // TODO Look at using std::panic::catch_unwind (1.9)
fn invalid_put_for_previously_created_account() {
    let network = Network::new();
    let node_count = TEST_NET_SIZE;
    let mut nodes = test_node::create_nodes(&network, node_count, None);
    let config = mock_crust::Config::with_contacts(&[nodes[0].endpoint()]);
    let mut client = TestClient::new(&network, Some(config));

    client.ensure_connected(&mut nodes);
    client.create_account(&mut nodes);
    client.create_account(&mut nodes);
}

#[test]
fn storing_till_client_account_full() {
    // This needs to be kept in sync with maid_manager.rs
    // Ideally, a setter is preferred, so that this test can be completed quicker.
    const DEFAULT_ACCOUNT_SIZE: u64 = 100;
    let network = Network::new();
    let node_count = 15;
    let mut nodes = test_node::create_nodes(&network, node_count, None);
    let config = mock_crust::Config::with_contacts(&[nodes[0].endpoint()]);
    let mut client = TestClient::new(&network, Some(config));

    client.ensure_connected(&mut nodes);
    client.create_account(&mut nodes);
    let full_id = client.full_id().clone();

    for i in 0..(DEFAULT_ACCOUNT_SIZE + 5) {
        let data = if i % 2 == 0 {
            Data::Structured(test_utils::random_structured_data(100000, &full_id))
        } else {
            Data::Immutable(ImmutableData::new(test_utils::generate_random_vec_u8(10)))
        };
        let result = client.put_and_verify(data.clone(), &mut nodes);
        if i < DEFAULT_ACCOUNT_SIZE - 1 {
            assert_eq!(result, Ok(()));
        } else {
            assert_eq!(result, Err(Some(MutationError::LowBalance)));
        }
    }
}

#[test]
fn maid_manager_account_updates_with_churn() {
    let network = Network::new();
    let node_count = 15;
    let mut nodes = test_node::create_nodes(&network, node_count, None);
    let config = mock_crust::Config::with_contacts(&[nodes[0].endpoint()]);
    let mut client = TestClient::new(&network, Some(config));

    client.ensure_connected(&mut nodes);
    client.create_account(&mut nodes);

    let mut rng = thread_rng();

    let mut put_count = 1; // Login packet.
    let full_id = client.full_id().clone();

    for i in 0..10 {
        for data in (0..4)
            .map(|_| Data::Structured(test_utils::random_structured_data(100000, &full_id))) {
            client.put(data.clone());
            put_count += 1;
        }
        trace!("Churning on {} nodes, iteration {}", nodes.len(), i);
        if nodes.len() <= GROUP_SIZE + 2 || random() {
            let index = Range::new(1, nodes.len()).ind_sample(&mut rng);
            trace!("Adding node with bootstrap node {}.", index);
            test_node::add_node(&network, &mut nodes, index);
        } else {
            let number = Range::new(1, 4).ind_sample(&mut rng);
            trace!("Removing {} node(s).", number);
            for _ in 0..number {
                let node_index = Range::new(1, nodes.len()).ind_sample(&mut rng);
                test_node::drop_node(&mut nodes, node_index);
            }
        }
        let _ = poll::nodes_and_client(&mut nodes, &mut client);
        let count = nodes.iter()
            .filter(|node| {
                match node.get_maid_manager_put_count(client.name()) {
                    None => false,
                    Some(count) => count == put_count,
                }
            })
            .count();
        assert!(GROUP_SIZE - 3 <= count,
                "put_count {} only found with {} nodes",
                put_count,
                count);
    }
}
