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
// relating to use of the SAFE Network Software.                                                              */

#![forbid(bad_style, warnings)]
#![deny(deprecated, improper_ctypes, non_shorthand_field_patterns,
        overflowing_literals, plugin_as_library, private_no_mangle_fns, private_no_mangle_statics,
        raw_pointer_derive, stable_features, unconditional_recursion, unknown_lints, unsafe_code,
        unused, unused_allocation, unused_attributes, unused_comparisons,
        unused_features, unused_parens, while_true)]

#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
        unused_qualifications, variant_size_differences)]
#![feature(negate_unsigned)]

extern crate routing;

use std::io::BufRead;
use std::thread;
use std::process::Stdio;
use std::process::Command;
use std::error::Error;
use std::io::Read;

use routing::event::Event;

// The following tests require the executable safe_vault to be presented
// And the tests must be executed as "RUST_LOG=info RUST_TEST_THREADS=1 cargo test"

#[test]
fn executable_connection_test() {
    let mut processes = Vec::new();
    let num_of_nodes = 8;
    let executable_path = match std::env::current_exe() {
        Ok(mut exe_path) => {
            exe_path.pop();
            std::path::Path::new("./target").join(exe_path.iter().last().unwrap()).join("safe_vault")
        }
        Err(e) => panic!("Failed to get current integration test path: {}", e),
    };
    println!("Expecting vault executable at the path of {}", executable_path.to_path_buf().display());

    for i in 0..num_of_nodes {
        println!("---------- starting node {} --------------", i);
        processes.push(match Command::new(executable_path.to_path_buf()).stderr(Stdio::piped()).spawn() {
                    Err(why) => panic!("couldn't spawn safe_vault: {}", why.description()),
                    Ok(process) => process,
                });
        thread::sleep_ms(1000 + i * 1500);
    }
    thread::sleep_ms(15000);
    let mut test_failed = false;
    while let Some(mut process) = processes.pop() {
        let _ = process.kill();
        let result : Vec<u8> = process.stderr.unwrap().bytes().map(|x| x.unwrap()).collect();
        let s = String::from_utf8(result).unwrap();
        println!("\n\n     +++++++++++++++++++++++++++++++++++++++\n {} \n\n", s);
        let v: Vec<&str> = s.split("added connected node").collect();
        let marked_connections = v.len() - 1;
        println!("\t  safe_vault {} has {} connected connections.", processes.len(), marked_connections);
        if num_of_nodes as usize != marked_connections + 1 {
          test_failed = true;
        }
    }
    assert_eq!(test_failed, false);
}

#[test]
fn executable_churn_test() {
    let mut processes = Vec::new();
    let num_of_nodes = 4;
    let executable_path = match std::env::current_exe() {
        Ok(mut exe_path) => {
            exe_path.pop();
            std::path::Path::new("./target").join(exe_path.iter().last().unwrap()).join("safe_vault")
        }
        Err(e) => panic!("Failed to get current integration test path: {}", e),
    };
    println!("Expecting vault executable at the path of {}", executable_path.to_path_buf().display());
    
    for i in 0..num_of_nodes {
        println!("---------- starting node {} --------------", i);
        processes.push(match Command::new(executable_path.to_path_buf()).stderr(Stdio::piped()).spawn() {
                    Err(why) => panic!("couldn't spawn safe_vault: {}", why.description()),
                    Ok(process) => process,
                });
        thread::sleep_ms(1000 + i * 1500);
    }
    thread::sleep_ms(5000);

    let (sender, receiver) = ::std::sync::mpsc::channel();
    let (client_sender, /*client_receiver*/ _) = ::std::sync::mpsc::channel();
    let client_receiving = |receiver: ::std::sync::mpsc::Receiver<(Event)>,
                            client_sender: ::std::sync::mpsc::Sender<(::routing::data::Data)>| {
        let _ = ::std::thread::spawn(move || {
            while let Ok(event) = receiver.recv() {
                match event {
                    Event::Request{ request, our_authority, from_authority, response_token } =>
                        println!("client as {:?} received request: {:?} from {:?} having token {:?}",
                                 our_authority, request, from_authority, response_token == None),
                    Event::Response{ response, our_authority, from_authority } => {
                        println!("client as {:?} received response: {:?} from {:?}",
                                 our_authority, response, from_authority);
                        match response {
                            ::routing::ExternalResponse::Get(data, _, _) => {
                                let _ = client_sender.clone().send(data);
                            },
                            _ => panic!("not expected!")
                        }
                    },
                    Event::Refresh(_type_tag, _group_name, _accounts) =>
                        println!("client received a refresh"),
                    Event::Churn(_close_group) => println!("client received a churn"),
                    Event::Connected => println!("client connected"),
                    Event::Disconnected => println!("client disconnected"),
                    Event::FailedRequest{ request, our_authority, location, interface_error } =>
                        println!("client as {:?} received request: {:?} targeting {:?} having error {:?}",
                                 our_authority, request, location, interface_error),
                    Event::FailedResponse{ response, our_authority, location, interface_error } =>
                        println!("client as {:?} received response: {:?} targeting {:?} having error {:?}",
                                 our_authority, response, location, interface_error),
                    Event::Bootstrapped => println!("client routing Bootstrapped"),
                    Event::Terminated => {
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
    ::std::thread::sleep_ms(1000);

    let value = ::routing::types::generate_random_vec_u8(1024);
    let im_data = ::routing::immutable_data::ImmutableData::new(
        ::routing::immutable_data::ImmutableDataType::Normal, value);
    client_routing.put_request(::routing::authority::Authority::ClientManager(client_name),
                               ::routing::data::Data::ImmutableData(im_data.clone()));
    ::std::thread::sleep_ms(5000);

    let mut new_vault_process = match Command::new(executable_path.to_path_buf()).stderr(Stdio::piped()).spawn() {
        Err(why) => panic!("couldn't spawn safe_vault: {}", why.description()),
        Ok(process) => process,
    };
    ::std::thread::sleep_ms(5000);
    let _ = new_vault_process.kill();
    let result : Vec<u8> = new_vault_process.stderr.unwrap().bytes().map(|x| x.unwrap()).collect();
    let s = String::from_utf8(result).unwrap();
    println!("\n\n     +++++++++++++++++++++++++++++++++++++++\n {} \n\n", s);

    while let Some(mut process) = processes.pop() {
        let _ = process.kill();
        let result : Vec<u8> = process.stderr.unwrap().bytes().map(|x| x.unwrap()).collect();
        let s = String::from_utf8(result).unwrap();
        println!("\n\n     +++++++++++++++++++++++++++++++++++++++\n {} \n\n", s);
    }
}
