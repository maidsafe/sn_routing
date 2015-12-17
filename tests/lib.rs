// Copyright 2015 MaidSafe.net limited.
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
        unused_qualifications, unused_results, variant_size_differences)]
#![allow(box_pointers, fat_ptr_transmutes, missing_copy_implementations,
         missing_debug_implementations)]

#[cfg(not(feature = "use-mock-routing"))]
extern crate sodiumoxide;
#[cfg(not(feature = "use-mock-routing"))]
extern crate routing;

#[cfg(not(feature = "use-mock-routing"))]
fn start_vaults(num_of_nodes: u32) -> Vec<::std::process::Child> {
    use std::error::Error;
    let mut processes = Vec::new();
    let executable_path = match std::env::current_exe() {
        Ok(mut exe_path) => {
            exe_path.pop();
            std::path::Path::new("./target")
                .join(exe_path.iter().last().unwrap())
                .join("safe_vault")
        }
        Err(e) => panic!("Failed to get current integration test path: {}", e),
    };
    println!("Expecting vault executable at the path of {}",
             executable_path.to_path_buf().display());

    for i in 0..num_of_nodes {
        println!("---------- starting node {} --------------", i);
        processes.push(match ::std::process::Command::new(executable_path.to_path_buf())
                                 .stderr(::std::process::Stdio::piped())
                                 .spawn() {
            Err(why) => panic!("couldn't spawn safe_vault: {}", why.description()),
            Ok(process) => process,
        });
        let duration = ::std::time::Duration::from_millis(1000 + i as u64 * 1500);
        ::std::thread::sleep(duration);
    }
    let duration = ::std::time::Duration::from_millis(num_of_nodes as u64 * 1000);
    ::std::thread::sleep(duration);
    processes
}

#[cfg(not(feature = "use-mock-routing"))]
fn start_client() -> (::routing::routing_client::RoutingClient,
                      ::std::sync::mpsc::Receiver<(::routing::data::Data)>, XorName) {
    let (sender, receiver) = ::std::sync::mpsc::channel();
    let (client_sender, client_receiver) = ::std::sync::mpsc::channel();
    let client_receiving = |receiver: ::std::sync::mpsc::Receiver<(::routing::event::Event)>,
                            client_sender: ::std::sync::mpsc::Sender<(::routing::data::Data)>| {
        let _ = ::std::thread::spawn(move || {
            while let Ok(event) = receiver.recv() {
                match event {
                    ::routing::event::Event::Request{
                        request, our_authority, from_authority, response_token
                    } => println!("client as {:?} received request: {:?} from {:?} having token \
                                  {:?}",
                                  our_authority, request, from_authority, response_token == None),
                    ::routing::event::Event::Response{
                        response, our_authority, from_authority
                    } => {
                        println!("client as {:?} received response: {:?} from {:?}",
                                 our_authority, response, from_authority);
                        match response {
                            ::routing::ExternalResponse::Get(data, _, _) => {
                                let _ = client_sender.clone().send(data);
                            },
                            _ => panic!("not expected!")
                        }
                    },
                    ::routing::event::Event::Refresh(_type_tag, _group_name, _accounts) =>
                        println!("client received a refresh"),
                    ::routing::event::Event::Churn(_close_group, _churn_node) =>
                        println!("client received a churn"),
                    ::routing::event::Event::DoRefresh(_type_tag, _our_authority, _churn_node) =>
                        println!("client received a do-refresh"),
                    ::routing::event::Event::Connected => println!("client connected"),
                    ::routing::event::Event::Disconnected => println!("client disconnected"),
                    ::routing::event::Event::FailedRequest{
                        request, our_authority, location, interface_error
                    } => println!("client as {:?} received request: {:?} targeting {:?} having \
                                  error {:?}", our_authority, request, location, interface_error),
                    ::routing::event::Event::FailedResponse{
                        response, our_authority, location, interface_error
                    } => println!("client as {:?} received response: {:?} targeting {:?} having \
                                  error {:?}", our_authority, response, location, interface_error),
                    ::routing::event::Event::Bootstrapped =>
                        println!("client routing Bootstrapped"),
                    ::routing::event::Event::Terminated => {
                        println!("client routing listening terminated");
                        break;
                    },
                };
            }
        });
    };
    let _ = client_receiving(receiver, client_sender);
    let id = ::routing::id::Id::new();
    let client_name = id.name();
    let client_routing = ::routing::routing_client::RoutingClient::new(sender, Some(id));
    let duration = ::std::time::Duration::from_millis(1000);
    ::std::thread::sleep(duration);
    (client_routing, client_receiver, client_name)
}

// The following tests require the executable safe_vault to be presented
// And the tests must be executed as "RUST_LOG=info RUST_TEST_THREADS=1 cargo test"

#[cfg(not(feature = "use-mock-routing"))]
#[test]
fn executable_connection_test() {
    use std::io::Read;
    let num_of_nodes = 8;
    let mut processes = start_vaults(num_of_nodes);
    let mut test_failed = false;
    while let Some(mut process) = processes.pop() {
        let _ = process.kill();
        let result: Vec<u8> = process.stderr.unwrap().bytes().map(|x| x.unwrap()).collect();
        let s = String::from_utf8(result).unwrap();
        println!("\n\n     +++++++++++++++++++++++++++++++++++++++\n {} \n\n", s);
        let v: Vec<&str> = s.split("added connected node").collect();
        let marked_connections = v.len() - 1;
        println!("\t  safe_vault {} has {} connected connections.",
                 processes.len(), marked_connections);
        if num_of_nodes as usize != marked_connections + 1 {
            test_failed = true;
        }
    }
    assert_eq!(test_failed, false);
}

#[cfg(not(feature = "use-mock-routing"))]
#[test]
fn executable_immutable_data_churn_test() {
    use std::io::Read;
    let mut processes = start_vaults(4);
    let (mut client_routing, client_receiver, client_name) = start_client();

    let value = ::routing::types::generate_random_vec_u8(1024);
    let im_data = ::routing::immutable_data::ImmutableData::new(
        ::routing::immutable_data::ImmutableDataType::Normal, value);
    client_routing.put_request(::routing::Authority::ClientManager(client_name),
                               ::routing::data::Data::ImmutableData(im_data.clone()));
    let duration = ::std::time::Duration::from_millis(5000);
    ::std::thread::sleep(duration);

    let mut new_vault_process = start_vaults(1);

    client_routing.get_request(::routing::Authority::NaeManager(im_data.name()),
                               ::routing::data::DataRequest::ImmutableData(im_data.name(),
            ::routing::immutable_data::ImmutableDataType::Normal));
    while let Ok(data) = client_receiver.recv() {
        assert_eq!(data, ::routing::data::Data::ImmutableData(im_data.clone()));
        break;
    }

    if let Some(mut process) = new_vault_process.pop() {
        let _ = process.kill();
        let result: Vec<u8> = process.stderr.unwrap().bytes().map(|x| x.unwrap()).collect();
        let s = String::from_utf8(result).unwrap();
        let mm_v: Vec<&str> = s.split("MaidManager updated account").collect();
        assert_eq!(2, mm_v.len());
        let dm_v: Vec<&str> = s.split("DataManager updated account").collect();
        assert_eq!(2, dm_v.len());
        let pm_v: Vec<&str> = s.split("DataManager updated account").collect();
        assert_eq!(2, pm_v.len());
        println!("\n\n     +++++++++++++++++++++++++++++++++++++++\n {} \n\n", s);
    };
    while let Some(mut process) = processes.pop() {
        let _ = process.kill();
        let result: Vec<u8> = process.stderr.unwrap().bytes().map(|x| x.unwrap()).collect();
        let s = String::from_utf8(result).unwrap();
        println!("\n\n     +++++++++++++++++++++++++++++++++++++++\n {} \n\n", s);
    }
}

#[cfg(not(feature = "use-mock-routing"))]
#[test]
fn executable_structured_data_churn_test() {
    use std::io::Read;
    let mut processes = start_vaults(4);
    let (mut client_routing, client_receiver, client_name) = start_client();

    let name = XorName(::routing::types::slice_as_u8_64_array(
        &*::routing::types::generate_random_vec_u8(64)));
    let value = ::routing::types::generate_random_vec_u8(1024);
    let sign_keys = ::sodiumoxide::crypto::sign::gen_keypair();
    let sd = ::routing::structured_data::StructuredData::new(0,
                                                             name,
                                                             0,
                                                             value.clone(),
                                                             vec![sign_keys.0],
                                                             vec![],
                                                             Some(&sign_keys.1))
                 .ok()
                 .unwrap();
    client_routing.put_request(::routing::Authority::ClientManager(client_name),
                               ::routing::data::Data::StructuredData(sd.clone()));
    let duration = ::std::time::Duration::from_millis(5000);
    ::std::thread::sleep(duration);

    let mut new_vault_process = start_vaults(1);

    client_routing.get_request(::routing::Authority::NaeManager(sd.name()),
                               ::routing::data::DataRequest::StructuredData(sd.name(), 0));
    while let Ok(data) = client_receiver.recv() {
        assert_eq!(data, ::routing::data::Data::StructuredData(sd.clone()));
        break;
    }

    if let Some(mut process) = new_vault_process.pop() {
        let _ = process.kill();
        let result: Vec<u8> = process.stderr.unwrap().bytes().map(|x| x.unwrap()).collect();
        let s = String::from_utf8(result).unwrap();
        let sd_v: Vec<&str> = s.split("SdManager transferred structured_data").collect();
        assert_eq!(2, sd_v.len());
        println!("\n\n     +++++++++++++++++++++++++++++++++++++++\n {} \n\n", s);
    };
    while let Some(mut process) = processes.pop() {
        let _ = process.kill();
        let result: Vec<u8> = process.stderr.unwrap().bytes().map(|x| x.unwrap()).collect();
        let s = String::from_utf8(result).unwrap();
        println!("\n\n     +++++++++++++++++++++++++++++++++++++++\n {} \n\n", s);
    }
}
