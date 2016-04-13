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
#[macro_use]
extern crate maidsafe_utilities;
#[macro_use]
extern crate log;
extern crate rand;
extern crate routing;
extern crate safe_network_common;
extern crate sodiumoxide;
extern crate xor_name;
extern crate safe_vault;

mod mock_crust_detail;

mod test {
    use maidsafe_utilities::log;
    use mock_crust_detail::{self, poll, test_node};
    use mock_crust_detail::test_client::TestClient;
    use rand::{random, thread_rng};
    use rand::distributions::{IndependentSample, Range};
    use routing::{self, Data, DataRequest, ImmutableData, ImmutableDataType, StructuredData};
    use routing::mock_crust::{self, Network};
    use safe_vault::Config;
    use sodiumoxide::crypto::sign;
    use xor_name::XorName;

    fn random_structured_data(type_tag: u64) -> StructuredData {
        let keys = sign::gen_keypair();

        unwrap_result!(StructuredData::new(type_tag,
                                           random::<XorName>(),
                                           0,
                                           mock_crust_detail::generate_random_vec_u8(10),
                                           vec![keys.0],
                                           vec![],
                                           Some(&keys.1)))
    }

    fn check_data(all_immutable_data: Vec<Data>,
                  all_structured_data: Vec<Data>,
                  mut all_stored_names: Vec<XorName>) {
        all_stored_names.sort();

        let mut all_immutable_data_names = all_immutable_data.iter()
                                                             .cloned()
                                                             .map(|data| data.name().clone())
                                                             .collect::<Vec<XorName>>();

        all_immutable_data_names.sort();

        let mut normal_names = all_stored_names.clone();

        normal_names.retain(|&stored_name| {
            all_immutable_data_names.iter()
                                    .find(|&&name| name == stored_name)
                                    .is_some()
        });

        assert_eq!(2 * all_immutable_data.len(), normal_names.len());

        normal_names.dedup();

        assert_eq!(all_immutable_data_names.iter()
                                           .zip(normal_names)
                                           .filter(|&(data_name, normal_name)| {
                                               *data_name == normal_name
                                           })
                                           .count(),
                   all_immutable_data.len());

        let mut backup_names = all_stored_names.clone();

        backup_names.retain(|&stored_name| {
            all_immutable_data_names.iter()
                                    .find(|&&name| routing::normal_to_backup(&name) == stored_name)
                                    .is_some()
        });

        assert_eq!(2 * all_immutable_data.len(), backup_names.len());

        let mut all_backup_names = all_immutable_data.iter()
                                                     .cloned()
                                                     .map(|data| {
                                                         routing::normal_to_backup(&data.name())
                                                     })
                                                     .collect::<Vec<XorName>>();

        all_backup_names.sort();
        backup_names.sort();
        backup_names.dedup();

        assert_eq!(all_backup_names.iter()
                                   .zip(backup_names)
                                   .filter(|&(data_name, backup_name)| *data_name == backup_name)
                                   .count(),
                   all_immutable_data.len());

        let mut sacrificial_names = all_stored_names.clone();

        sacrificial_names.retain(|&stored_name| {
            all_immutable_data_names.iter()
                                    .find(|&&name| {
                                        routing::normal_to_sacrificial(&name) == stored_name
                                    })
                                    .is_some()
        });

        assert_eq!(2 * all_immutable_data.len(), sacrificial_names.len());

        let mut all_sacrificial_names =
            all_immutable_data.iter()
                              .cloned()
                              .map(|data| routing::normal_to_sacrificial(&data.name()))
                              .collect::<Vec<XorName>>();

        all_sacrificial_names.sort();
        sacrificial_names.sort();
        sacrificial_names.dedup();

        assert_eq!(all_sacrificial_names.iter()
                                        .zip(sacrificial_names)
                                        .filter(|&(data_name, sacrificial_name)| {
                                            *data_name == sacrificial_name
                                        })
                                        .count(),
                   all_immutable_data.len());

        let mut all_structured_data_names = all_structured_data.iter()
                                                               .cloned()
                                                               .map(|data| data.name().clone())
                                                               .collect::<Vec<XorName>>();

        all_structured_data_names.sort();

        let mut structured_names = all_stored_names.clone();

        structured_names.retain(|&stored_name| {
            all_structured_data_names.iter()
                                     .find(|&&name| name == stored_name)
                                     .is_some()
        });

        assert_eq!(8 * all_structured_data.len(), structured_names.len());

        structured_names.sort();
        structured_names.dedup();

        assert_eq!(all_structured_data_names.iter()
                                            .zip(structured_names)
                                            .filter(|&(data_name, structured_name)| {
                                                *data_name == structured_name
                                            })
                                            .count(),
                   all_structured_data.len());
    }

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
                let immutable_data = ImmutableData::new(ImmutableDataType::Normal, content);
                all_data.push(Data::Immutable(immutable_data));
            } else {
                let structured_data = random_structured_data(structured_range.ind_sample(&mut rng));
                all_data.push(Data::Structured(structured_data));
            }
        }

        for data in &all_data {
            unwrap_result!(client.put(data.clone(), &mut nodes));
        }

        for data in &all_data {
            match *data {
                Data::Immutable(ref sent_immutable_data) => {
                    match client.get(DataRequest::Immutable(data.name(),
                                                            ImmutableDataType::Normal),
                                     &mut nodes) {
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
                    match client.get(DataRequest::Structured(sent_structured_data.get_identifier()
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

        let mut all_stored_names = Vec::new();

        for node in &nodes {
            all_stored_names.append(&mut node.get_stored_names());
        }

        check_data(all_immutable_data.clone(),
                   all_structured_data.clone(),
                   all_stored_names.clone());

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

    #[test]
    fn fill_network() {
        let _ = log::init(false);
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
            let immutable_data = ImmutableData::new(ImmutableDataType::Normal, content.clone());
            match client.put(Data::Immutable(immutable_data), &mut nodes) {
                Ok(()) => {
                    trace!("\nStored chunk {}\n=================\n", index)
                }
                Err(response) => {
                    trace!("\nFailed storing chunk {}\n=================\n{:?}\n", index, response);
                    break;
                }
            }
            index += 1;
        }
    }

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
            let immutable_data = ImmutableData::new(ImmutableDataType::Normal, content);
            all_immutable_data.push(immutable_data);
        }

        // let node_index_range = Range::new(1, nodes.len() - 1);
        // Churn every 10 put_requests, thats 10 churn in total
        for i in 0..all_immutable_data.len() {
            unwrap_result!(client.put(Data::Immutable(all_immutable_data[i].clone()), &mut nodes));
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
            match client.get(DataRequest::Immutable(all_immutable_data[i].name(),
                                                    ImmutableDataType::Normal),
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

        let mut all_immutable_data_names = all_immutable_data.iter()
                                                             .cloned()
                                                             .map(|immutable_data| {
                                                                 immutable_data.name().clone()
                                                             })
                                                             .collect::<Vec<XorName>>();

        all_immutable_data_names.sort();

        let mut all_stored_names = Vec::new();

        for node in &nodes {
            all_stored_names.append(&mut node.get_stored_names());
        }

        all_stored_names.sort();

        all_stored_names.retain(|&stored_name| {
            all_immutable_data_names.iter()
                                    .find(|&&immutable_data_name| {
                                        immutable_data_name == stored_name
                                    })
                                    .is_some()
        });

        assert!(all_stored_names.len() >= 2 * put_requests);

        all_stored_names.dedup();

        assert_eq!(all_immutable_data_names.iter()
                                           .zip(all_stored_names)
                                           .filter(|&(data_name, stored_name)| {
                                               *data_name == stored_name
                                           })
                                           .count(),
                   put_requests);
    }
}
