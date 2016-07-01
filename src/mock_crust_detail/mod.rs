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

/// Poll events
pub mod poll;
/// Test client node
pub mod test_client;
/// Test full node
pub mod test_node;

use kademlia_routing_table::RoutingTable;
use itertools::Itertools;
use mock_crust_detail::test_node::TestNode;
use personas::data_manager::IdAndVersion;
use routing::{self, GROUP_SIZE, Data, XorName};
use std::collections::{HashMap, HashSet};

/// Checks that none of the given nodes has any copy of the given data left.
pub fn check_deleted_data(deleted_data: &[Data], nodes: &[TestNode]) {
    let deleted_data_ids: HashSet<_> = deleted_data.iter()
        .map(Data::identifier)
        .collect();
    let mut data_count = HashMap::new();
    nodes.iter()
        .flat_map(TestNode::get_stored_names)
        .foreach(|data_idv| {
            if deleted_data_ids.contains(&data_idv.0) {
                *data_count.entry(data_idv).or_insert(0) += 1;
            }
        });
    for (data_id, count) in data_count {
        assert!(count < 5,
                "Found deleted data: {:?}. count: {}",
                data_id,
                count);
    }
}

/// Checks that the given `nodes` store the expected number of copies of the given data.
pub fn check_data(all_data: Vec<Data>, nodes: &[TestNode]) {
    let mut data_holders_map: HashMap<IdAndVersion, Vec<XorName>> = HashMap::new();
    for node in nodes {
        for data_idv in node.get_stored_names() {
            data_holders_map.entry(data_idv).or_insert_with(Vec::new).push(node.name());
        }
    }

    for data in all_data {
        let (data_id, data_version) = match data {
            Data::Immutable(data) => (data.identifier(), 0),
            Data::Structured(data) => (data.identifier(), data.get_version()),
            _ => unreachable!(),
        };
        let data_holders = data_holders_map.get(&(data_id, data_version))
            .cloned()
            .unwrap_or_else(Vec::new)
            .into_iter()
            .sorted_by(|left, right| data_id.name().cmp_distance(left, right));

        let mut expected_data_holders = nodes.iter()
            .map(TestNode::name)
            .sorted_by(|left, right| data_id.name().cmp_distance(left, right));

        expected_data_holders.truncate(GROUP_SIZE);

        assert!(expected_data_holders == data_holders,
                "Data: {:?}. expected = {:?}, actual = {:?}",
                data_id,
                expected_data_holders,
                data_holders);
    }
}

/// Verify that the kademlia invariant is upheld for all nodes.
pub fn verify_kademlia_invariant_for_all_nodes(nodes: &[TestNode]) {
    let routing_tables: Vec<RoutingTable<XorName>> =
        nodes.iter().map(TestNode::routing_table).collect();
    for node_index in 0..nodes.len() {
        routing::verify_kademlia_invariant(&routing_tables, node_index);
    }
}
