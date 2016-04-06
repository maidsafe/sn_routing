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

#![allow(unused)]

mod poll;
mod test_client;
mod test_node;
use std::time::Duration;
use std::thread;
use rand::{random, thread_rng};
use rand::distributions::{IndependentSample, Range};
use routing::{Data, DataRequest, ImmutableData, ImmutableDataType, normal_to_backup, normal_to_sacrificial,
              StructuredData};
use routing::mock_crust::{Config, Network};
use sodiumoxide::crypto::sign;
use xor_name::XorName;
use utils;

use self::test_client::TestClient;

fn random_structured_data(type_tag: u64) -> StructuredData {
    let keys = sign::gen_keypair();

    unwrap_result!(StructuredData::new(type_tag,
                                       random::<XorName>(),
                                       0,
                                       utils::generate_random_vec_u8(10),
                                       vec![keys.0],
                                       vec![],
                                       Some(&keys.1)))
}

fn check_data(all_immutable_data: Vec<Data>, all_structured_data: Vec<Data>, mut all_stored_names: Vec<XorName>) {
    all_stored_names.sort();

    let mut all_immutable_data_names =
        all_immutable_data.iter()
                          .cloned()
                          .map(|data| data.name().clone())
                          .collect::<Vec<XorName>>();

    all_immutable_data_names.sort();

    let mut normal_names = all_stored_names.clone();

    normal_names.retain(|&stored_name|
        all_immutable_data_names.iter()
                                .find(|&&name| name == stored_name)
                                .is_some());

    assert_eq!(2 * all_immutable_data.len(), normal_names.len());

    normal_names.dedup();

    assert_eq!(all_immutable_data_names.iter()
                                       .zip(normal_names)
                                       .filter(|&(data_name, normal_name)| *data_name == normal_name)
                                       .count(), all_immutable_data.len());

    let mut backup_names = all_stored_names.clone();

    backup_names.retain(|&stored_name|
        all_immutable_data_names.iter()
                                .find(|&&name| normal_to_backup(&name) == stored_name)
                                .is_some());

    assert_eq!(2 * all_immutable_data.len(), backup_names.len());

    let mut all_backup_names =
        all_immutable_data.iter()
                          .cloned()
                          .map(|data| normal_to_backup(&data.name()))
                          .collect::<Vec<XorName>>();

    all_backup_names.sort();
    backup_names.sort();
    backup_names.dedup();

    assert_eq!(all_backup_names.iter()
                               .zip(backup_names)
                               .filter(|&(data_name, backup_name)| *data_name == backup_name)
                               .count(), all_immutable_data.len());

    let mut sacrificial_names = all_stored_names.clone();

    sacrificial_names.retain(|&stored_name|
        all_immutable_data_names.iter()
                                .find(|&&name| normal_to_sacrificial(&name) == stored_name)
                                .is_some());

    assert_eq!(2 * all_immutable_data.len(), sacrificial_names.len());

    let mut all_sacrificial_names =
        all_immutable_data.iter()
                          .cloned()
                          .map(|data| normal_to_sacrificial(&data.name()))
                          .collect::<Vec<XorName>>();

    all_sacrificial_names.sort();
    sacrificial_names.sort();
    sacrificial_names.dedup();

    assert_eq!(all_sacrificial_names.iter()
                                    .zip(sacrificial_names)
                                    .filter(|&(data_name, sacrificial_name)| *data_name == sacrificial_name)
                                    .count(), all_immutable_data.len());

    let mut all_structured_data_names =
        all_structured_data.iter()
                           .cloned()
                           .map(|data| data.name().clone())
                           .collect::<Vec<XorName>>();

    all_structured_data_names.sort();

    let mut structured_names = all_stored_names.clone();

    structured_names.retain(|&stored_name|
        all_structured_data_names.iter()
                                 .find(|&&name| name == stored_name)
                                 .is_some());

    assert_eq!(8 * all_structured_data.len(), structured_names.len());

    structured_names.sort();
    structured_names.dedup();

    assert_eq!(all_structured_data_names.iter()
                                        .zip(structured_names)
                                        .filter(|&(data_name, structured_name)| *data_name == structured_name)
                                        .count(), all_structured_data.len());
}

#[test]
fn plain_data_put_and_get() {
    let network = Network::new();
    let mut nodes = test_node::create_nodes(&network, 8);
    let config = Config::with_contacts(&[nodes[0].endpoint()]);

    let mut client = TestClient::new(&network, Some(config));
    client.ensure_connected(&mut nodes);
    client.create_account(&mut nodes);

    let content = utils::generate_random_vec_u8(1024);
    let orig_data = ImmutableData::new(ImmutableDataType::Normal, content);

    client.put(Data::Immutable(orig_data.clone()), &mut nodes);

    match client.get(DataRequest::Immutable(orig_data.name(), ImmutableDataType::Normal), &mut nodes) {
        Data::Immutable(data) => {
            assert_eq!(data.name(), orig_data.name());
            assert!(data.value() == orig_data.value());
        },

        data => panic!("Got unexpected data: {:?}", data),
    }
}

#[test]
fn test1() {
    let network = Network::new();
    let node_count = 2 * 8;
    let mut nodes = test_node::create_nodes(&network, node_count);
    let config = Config::with_contacts(&[nodes[0].endpoint()]);
    let mut client = TestClient::new(&network, Some(config));

    client.ensure_connected(&mut nodes);
    client.create_account(&mut nodes);

    let mut all_data = Vec::new();
    let mut all_immutable_data = Vec::new();
    let mut all_structured_data = Vec::new();
    let mut rng = thread_rng();
    let immutable_range = Range::new(128, 1024);
    let structured_range = Range::new(1, 10000);
    let put_range = Range::new(50, 100);
    let put_requests = 1; // put_range.ind_sample(&mut rng);

    for _ in 0..put_requests {
        // if random::<usize>() % 2 == 0 {
            let content = utils::generate_random_vec_u8(immutable_range.ind_sample(&mut rng));
            let immutable_data = ImmutableData::new(ImmutableDataType::Normal, content);
            all_data.push(Data::Immutable(immutable_data));
        // } else {
        //     let structured_data = random_structured_data(structured_range.ind_sample(&mut rng));
        //     all_data.push(Data::Structured(structured_data));
        // }
    }

    for data in &all_data {
        client.put(data.clone(), &mut nodes);
    }

    for data in &all_data {
        match *data {
            Data::Immutable(ref sent_immutable_data) => {
                match client.get(DataRequest::Immutable(data.name(), ImmutableDataType::Normal), &mut nodes) {
                    Data::Immutable(recovered_immutable_data) => {
                        assert_eq!(recovered_immutable_data.name(), sent_immutable_data.name());
                        assert!(recovered_immutable_data.value() == sent_immutable_data.value());
                    },
                    unexpected_data => panic!("Got unexpected data: {:?}", unexpected_data),
                }
                all_immutable_data.push(data.clone());
            },
            Data::Structured(ref sent_structured_data) => {
                match client.get(DataRequest::Structured(sent_structured_data.get_identifier().clone(),
                                                         sent_structured_data.get_type_tag()),
                                                         &mut nodes) {
                    Data::Structured(recovered_structured_data) => {
                        assert_eq!(recovered_structured_data.name(), sent_structured_data.name());
                    },
                    unexpected_data => panic!("Got unexpected data: {:?}", unexpected_data),
                }
                all_structured_data.push(data.clone());
            },
            _ => unreachable!(),
        }
    }

    poll::nodes_and_client(&mut nodes, &mut client);

    let mut all_stored_names = Vec::new();

    for node in &nodes {
        all_stored_names.append(&mut node.get_stored_names());
    }

    check_data(all_immutable_data.clone(), all_structured_data.clone(), all_stored_names.clone());

    for _ in 0..10 {
        for _ in 0..3 {
            let node_range = Range::new(1, nodes.len());
            let node_index = node_range.ind_sample(&mut rng);
            let node = nodes.remove(node_index);

            drop(node);

            // thread::sleep(Duration::from_secs(5));
            // poll::nodes(&mut nodes);
        }
        thread::sleep(Duration::from_secs(5));
        poll::nodes_and_client(&mut nodes, &mut client);
        all_stored_names.clear();

        for node in &nodes {
            all_stored_names.append(&mut node.get_stored_names());
        }

        check_data(all_immutable_data.clone(), all_structured_data.clone(), all_stored_names.clone());

        test_node::add_nodes(&network, &mut nodes, 3);
        thread::sleep(Duration::from_secs(5));
        poll::nodes_and_client(&mut nodes, &mut client);
        all_stored_names.clear();

        for node in &nodes {
            all_stored_names.append(&mut node.get_stored_names());
        }

        check_data(all_immutable_data.clone(), all_structured_data.clone(), all_stored_names.clone());
    }
}
