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
#![forbid(bad_style, exceeding_bitshifts, mutable_transmutes, no_mangle_const_items,
          unknown_crate_types, warnings)]
#![deny(deprecated, drop_with_repr_extern, improper_ctypes, missing_docs,
        non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
        private_no_mangle_fns, private_no_mangle_statics, stable_features, unconditional_recursion,
        unknown_lints, unsafe_code, unused, unused_allocation, unused_attributes,
        unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results)]
#![allow(box_pointers, fat_ptr_transmutes, missing_copy_implementations,
         missing_debug_implementations, variant_size_differences)]

#![cfg(feature = "use-mock-crust")]
#![cfg(test)]

extern crate itertools;
extern crate kademlia_routing_table;
#[macro_use]
extern crate log;
#[macro_use]
extern crate maidsafe_utilities;
extern crate rand;
extern crate routing;
extern crate safe_network_common;
extern crate safe_vault;
extern crate sodiumoxide;
extern crate xor_name;

mod mock_crust_detail;

mod test {
    use itertools::Itertools;
    use kademlia_routing_table::GROUP_SIZE;
    use mock_crust_detail::{self, poll, test_node};
    use mock_crust_detail::test_node::TestNode;
    use mock_crust_detail::test_client::TestClient;
    use rand::{random, thread_rng};
    use rand::distributions::{IndependentSample, Range};
    use routing::{Data, DataIdentifier, ImmutableData, StructuredData};
    use routing::mock_crust::{self, Network};
    use safe_vault::Config;
    use sodiumoxide::crypto::sign;
    use std::cmp;
    use std::collections::HashMap;
    use xor_name::XorName;

    fn random_structured_data(type_tag: u64, key: sign::SecretKey) -> StructuredData {
        let keys = sign::gen_keypair();

        unwrap_result!(StructuredData::new(type_tag,
                                           random::<XorName>(),
                                           0,
                                           mock_crust_detail::generate_random_vec_u8(10),
                                           vec![keys.0],
                                           vec![],
                                           Some(&key)))
    }

    /// Checks that the given `nodes` store the expected number of copies of the given data.
    fn check_data(all_data: Vec<Data>, nodes: &[TestNode]) {
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

    #[test]
    fn maid_manager_churn() {
        let _ = ::maidsafe_utilities::log::init(false);
        let network = Network::new();
        let node_count = 15;
        let mut nodes = test_node::create_nodes(&network, node_count, None);
        let config = mock_crust::Config::with_contacts(&[nodes[0].endpoint()]);
        let mut client = TestClient::new(&network, Some(config));

        client.ensure_connected(&mut nodes);
        client.create_account(&mut nodes);

        let mut rng = thread_rng();

        let mut put_count = 1; // Login packet.
        let client_key = client.signing_private_key().clone();

        for i in 0..10 {
            for data in (0..4).map(|_| {
                Data::Structured(random_structured_data(100000, client_key.clone()))
            }) {
                client.put(data.clone());
                put_count += 1;
            }
            trace!("Churn {}", i);
            if nodes.len() <= GROUP_SIZE + 2 || random() {
                trace!("Adding node.");
                test_node::add_node(&network, &mut nodes);
            } else {
                let number = Range::new(1, 4).ind_sample(&mut rng);
                trace!("Removing {} node(s).", number);
                for _ in 0..number {
                    let node_index = Range::new(1, nodes.len()).ind_sample(&mut rng);
                    test_node::drop_node(&mut nodes, node_index);
                }
            }
            poll::nodes_and_client(&mut nodes, &mut client);
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

    #[test]
    fn immutable_data_churn() {
        let _ = ::maidsafe_utilities::log::init(false);
        let network = Network::new();
        let node_count = 15;
        let mut nodes = test_node::create_nodes(&network, node_count, None);
        let config = mock_crust::Config::with_contacts(&[nodes[0].endpoint()]);
        let mut client = TestClient::new(&network, Some(config));
        const DATA_COUNT: usize = 5;
        const DATA_PER_ITER: usize = 2;

        client.ensure_connected(&mut nodes);
        client.create_account(&mut nodes);

        let mut all_data = vec![];
        let mut rng = thread_rng();

        for i in 0..10 {
            for _ in 0..(cmp::min(DATA_PER_ITER, DATA_COUNT - all_data.len())) {
                let data =
                    Data::Immutable(ImmutableData::new(mock_crust_detail::generate_random_vec_u8(10)));
                trace!("Putting data {:?}.", data.name());
                client.put(data.clone());
                all_data.push(data);
            }
            trace!("Churn {}", i);
            if nodes.len() <= GROUP_SIZE + 2 || random() {
                trace!("Adding node.");
                test_node::add_node(&network, &mut nodes);
            } else {
                let number = Range::new(3, 4).ind_sample(&mut rng);
                trace!("Removing {} node(s).", number);
                for _ in 0..number {
                    let node_range = Range::new(1, nodes.len());
                    let node_index = node_range.ind_sample(&mut rng);
                    test_node::drop_node(&mut nodes, node_index);
                }
            }
            poll::nodes_and_client(&mut nodes, &mut client);

            check_data(all_data.clone(), &nodes);
        }

        for data in &all_data {
            match *data {
                Data::Immutable(ref sent_data) => {
                    match client.get(sent_data.identifier(), &mut nodes) {
                        Data::Immutable(recovered_data) => {
                            assert_eq!(recovered_data, *sent_data);
                        }
                        unexpected_data => panic!("Got unexpected data: {:?}", unexpected_data),
                    }
                }
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn structured_data_churn() {
        let _ = ::maidsafe_utilities::log::init(false);
        let network = Network::new();
        let node_count = 15;
        let mut nodes = test_node::create_nodes(&network, node_count, None);
        let config = mock_crust::Config::with_contacts(&[nodes[0].endpoint()]);
        let mut client = TestClient::new(&network, Some(config));

        client.ensure_connected(&mut nodes);
        client.create_account(&mut nodes);

        let mut all_data = vec![];
        let mut rng = thread_rng();

        for i in 0..10 {
            for _ in 0..4 {
                if all_data.is_empty() || random() {
                    let data =
                        Data::Structured(random_structured_data(100000,
                                                                client.signing_private_key()
                                                                      .clone()));
                    trace!("Putting data {:?}.", data.name());
                    client.put(data.clone());
                    all_data.push(data);
                } else {
                    let j = Range::new(0, all_data.len()).ind_sample(&mut rng);
                    let data = Data::Structured(if let Data::Structured(sd) = all_data[j]
                                                                                  .clone() {
                        unwrap_result!(StructuredData::new(sd.get_type_tag(),
                                                           *sd.get_identifier(),
                                                           sd.get_version() + 1,
                                                           mock_crust_detail::generate_random_vec_u8(10),
                                                           sd.get_owner_keys().clone(),
                                                           vec![],
                                                           Some(client.signing_private_key())))
                    } else {
                        panic!("Non-structured data found.");
                    });
                    trace!("Posting data {:?}.", data.name());
                    all_data[j] = data.clone();
                    client.post(data);
                }
            }
            trace!("Churn {}", i);
            if nodes.len() <= GROUP_SIZE + 2 || random() {
                trace!("Adding node.");
                test_node::add_node(&network, &mut nodes);
            } else {
                let number = Range::new(3, 4).ind_sample(&mut rng);
                trace!("Removing {} node(s).", number);
                for _ in 0..number {
                    let node_range = Range::new(1, nodes.len());
                    let node_index = node_range.ind_sample(&mut rng);
                    test_node::drop_node(&mut nodes, node_index);
                }
            }
            poll::nodes_and_client(&mut nodes, &mut client);

            check_data(all_data.clone(), &nodes);

            for data in &all_data {
                match *data {
                    Data::Structured(ref sent_structured_data) => {
                        match client.get(sent_structured_data.identifier(), &mut nodes) {
                            Data::Structured(recovered_structured_data) => {
                                assert_eq!(recovered_structured_data.name(),
                                           sent_structured_data.name());
                            }
                            unexpected_data => panic!("Got unexpected data: {:?}", unexpected_data),
                        }
                    }
                    _ => unreachable!(),
                }
            }
        }
    }

    #[ignore]
    #[test]
    fn data_confirmation() {
        let network = Network::new();
        let node_count = 24;
        let mut nodes = test_node::create_nodes(&network, node_count, None);
        let config = mock_crust::Config::with_contacts(&[nodes[0].endpoint()]);
        let mut client = TestClient::new(&network, Some(config));

        client.ensure_connected(&mut nodes);
        client.create_account(&mut nodes);

        let mut all_data = Vec::new();
        let mut all_immutable_data = Vec::new();
        let mut all_structured_data = Vec::new();
        let mut rng = thread_rng();
        let immutable_range = Range::new(128, 1024);
        let structured_range = Range::new(1, 10000);
        let put_range = Range::new(5, 10);
        let put_requests = put_range.ind_sample(&mut rng);

        for _ in 0..put_requests {
            if random::<bool>() {
                let content =
                    mock_crust_detail::generate_random_vec_u8(immutable_range.ind_sample(&mut rng));
                let immutable_data = ImmutableData::new(content);
                all_data.push(Data::Immutable(immutable_data));
            } else {
                let structured_data = random_structured_data(structured_range.ind_sample(&mut rng),
                                                             client.signing_private_key().clone());
                all_data.push(Data::Structured(structured_data));
            }
        }

        for data in &all_data {
            unwrap_result!(client.put_and_verify(data.clone(), &mut nodes));
        }

        for data in &all_data {
            match *data {
                Data::Immutable(ref sent_immutable_data) => {
                    match client.get(DataIdentifier::Immutable(data.name()), &mut nodes) {
                        Data::Immutable(recovered_immutable_data) => {
                            assert_eq!(recovered_immutable_data.name(), sent_immutable_data.name());
                            assert!(recovered_immutable_data.value() ==
                                    sent_immutable_data.value());
                        }
                        unexpected_data => panic!("Got unexpected data: {:?}", unexpected_data),
                    }
                    all_immutable_data.push(data.clone());
                }
                Data::Structured(ref sent_structured_data) => {
                    match client.get(DataIdentifier::Structured(sent_structured_data.get_identifier()
                                                                                 .clone(),
                                                             sent_structured_data.get_type_tag()),
                                     &mut nodes) {
                        Data::Structured(recovered_structured_data) => {
                            assert_eq!(recovered_structured_data.name(),
                                       sent_structured_data.name());
                        }
                        unexpected_data => panic!("Got unexpected data: {:?}", unexpected_data),
                    }
                    all_structured_data.push(data.clone());
                }
                _ => unreachable!(),
            }
        }

        poll::nodes_and_client(&mut nodes, &mut client);

        check_data(all_immutable_data.iter()
                                     .chain(all_structured_data.iter())
                                     .cloned()
                                     .collect_vec(),
                   &nodes);

        // for _ in 0..10 {
        //    for _ in 0..3 {
        //        let node_range = Range::new(1, nodes.len());
        //        let node_index = node_range.ind_sample(&mut rng);

        //        test_node::drop_node(&mut nodes, node_index);
        //    }

        //    poll::nodes_and_client(&mut nodes, &mut client);
        //    all_stored_names.clear();

        //    for node in &nodes {
        //        all_stored_names.append(&mut node.get_stored_names());
        //    }

        //    check_data(all_immutable_data.clone(),
        //               all_structured_data.clone(),
        //               all_stored_names.clone());

        //    test_node::add_nodes(&network, &mut nodes, 3);
        //    poll::nodes_and_client(&mut nodes, &mut client);
        //    all_stored_names.clear();

        //    for node in &nodes {
        //        all_stored_names.append(&mut node.get_stored_names());
        //    }

        //    check_data(all_immutable_data.clone(),
        //               all_structured_data.clone(),
        //               all_stored_names.clone());
        // }
    }

    // TODO: This is still flaky and occasionally fails with `Err(Empty)` in
    // `TestClient::put_and_verify`.
    #[ignore]
    #[test]
    fn fill_network() {
        let network = Network::new();
        let config = Config {
            wallet_address: None,
            max_capacity: Some(7000),
        };
        let mut nodes = test_node::create_nodes(&network, 24, Some(config));
        let crust_config = mock_crust::Config::with_contacts(&[nodes[0].endpoint()]);
        let mut client = TestClient::new(&network, Some(crust_config));

        client.ensure_connected(&mut nodes);
        client.create_account(&mut nodes);

        let mut content = vec![0u8; 1024];
        let mut index = 0;
        loop {
            content[index] ^= 1u8;
            let immutable_data = ImmutableData::new(content.clone());
            match client.put_and_verify(Data::Immutable(immutable_data), &mut nodes) {
                Ok(()) => trace!("\nStored chunk {}\n=================\n", index),
                Err(response) => {
                    trace!("\nFailed storing chunk {}\n=================\n{:?}\n",
                           index,
                           response);
                    break;
                }
            }
            index += 1;
        }
    }

    #[ignore]
    #[test]
    fn put_get_when_churn() {
        let network = Network::new();
        let mut nodes = test_node::create_nodes(&network, 24, None);
        let crust_config = mock_crust::Config::with_contacts(&[nodes[0].endpoint()]);
        let mut client = TestClient::new(&network, Some(crust_config));

        client.ensure_connected(&mut nodes);
        client.create_account(&mut nodes);

        let mut all_immutable_data = Vec::new();
        let mut rng = thread_rng();
        let range = Range::new(128, 1024);
        let put_requests = 5;

        for _ in 0..put_requests {
            let content = mock_crust_detail::generate_random_vec_u8(range.ind_sample(&mut rng));
            let immutable_data = ImmutableData::new(content);
            all_immutable_data.push(immutable_data);
        }

        // let node_index_range = Range::new(1, nodes.len() - 1);
        // Churn every 10 put_requests, thats 10 churn in total
        for i in 0..all_immutable_data.len() {
            unwrap_result!(client.put_and_verify(Data::Immutable(all_immutable_data[i].clone()),
                                                 &mut nodes));
            // TODO: Re-enable churn.
            // if i % 10 == 0 {
            //    if i % 20 == 0 {
            //        test_node::drop_node(&mut nodes, node_index_range.ind_sample(&mut rng));
            //    } else {
            //        test_node::add_node(&network, &mut nodes);
            //    }
            // }
        }
        poll::nodes_and_client(&mut nodes, &mut client);
        // Churn every 10 put_requests, thats 10 churn in total
        for i in 0..all_immutable_data.len() {
            match client.get(DataIdentifier::Immutable(all_immutable_data[i].name()),
                             &mut nodes) {
                Data::Immutable(immutable_data) => {
                    assert_eq!(immutable_data.name(), all_immutable_data[i].name());
                    assert!(immutable_data.value() == all_immutable_data[i].value());
                }
                data => panic!("Got unexpected data: {:?}", data),
            }
            // TODO: Re-enable churn.
            // if i % 10 == 0 {
            //    if i % 20 == 0 {
            //        test_node::drop_node(&mut nodes, node_index_range.ind_sample(&mut rng));
            //    } else {
            //        test_node::add_node(&network, &mut nodes);
            //    }
            // }
        }
        poll::nodes_and_client(&mut nodes, &mut client);

        let all_data = all_immutable_data.iter()
                                         .cloned()
                                         .map(|immutable_data| Data::Immutable(immutable_data))
                                         .collect::<Vec<Data>>();
        check_data(all_data, &nodes);
    }
}
