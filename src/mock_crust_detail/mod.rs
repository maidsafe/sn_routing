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

#![cfg(any(test, feature = "use-mock-crust"))]

/// Poll events
pub mod poll;
/// Test client node
pub mod test_client;
/// Test full node
pub mod test_node;

use itertools::Itertools;
use routing::{Data, DataIdentifier};
use std::collections::{HashMap, HashSet};
use mock_crust_detail::test_node::TestNode;

/// Checks that none of the given nodes has any copy of the given data left.
pub fn check_deleted_data(deleted_data: &[Data], nodes: &[TestNode]) {
    let deleted_data_ids: HashSet<_> = deleted_data.iter()
        .map(Data::identifier)
        .collect();
    let mut data_count = HashMap::new();
    nodes.iter()
        .flat_map(TestNode::get_stored_names)
        .foreach(|data_id| {
            if deleted_data_ids.contains(&data_id) {
                *data_count.entry(data_id).or_insert(0) += 1;
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
    let mut data_count: HashMap<DataIdentifier, usize> = HashMap::new();
    for data_id in nodes.iter().flat_map(TestNode::get_stored_names) {
        *data_count.entry(data_id).or_insert(0) += 1;
    }

    for data in all_data {
        match data {
            Data::Immutable(data) => {
                let count = *data_count.get(&data.identifier()).unwrap_or(&0);
                assert!(5 <= count,
                        "Only {} copies of immutable data {:?}.",
                        count,
                        data.identifier());
            }
            Data::Structured(data) => {
                let count = *data_count.get(&data.identifier()).unwrap_or(&0);
                assert!(5 <= count,
                        "Only {} copies of structured data {:?}.",
                        count,
                        data.identifier());
            }
            _ => unreachable!(),
        }
    }
}
