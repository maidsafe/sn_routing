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
        unsigned_negation, unused, unused_allocation, unused_attributes, unused_comparisons,
        unused_features, unused_parens, while_true)]

#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
        unused_qualifications, variant_size_differences)]

// use std::io::BufRead;
// use std::thread;
// use std::process::Stdio;
// use std::process::Command;
// use std::error::Error;
// use std::io::Read;

#[test]
// This test requires the executable maidsafe_vault is presented at the same place of the test get executed
// also it depends a printout in routing lib. if such printout is changed / muted, this test needs to be updated
fn executable_test() {
    // let mut processes = Vec::new();
    // let num_of_nodes = 8;
    // let executable_path = match std::env::current_exe() {
    //     Ok(mut exe_path) => {
    //         exe_path.pop();
    //         std::path::Path::new("./target").join(exe_path.iter().last().unwrap()).join("maidsafe_vault")
    //     }
    //     Err(e) => panic!("Failed to get current integration test path: {}", e),
    // };
    // println!("Expecting vault executable at the path of {}", executable_path.to_path_buf().display());
    // // the first vault must be run in zero_membrane mode
    // println!("---------- starting node 0 --------------");
    // processes.push(match Command::new(executable_path.to_path_buf()).arg("-f").stdout(Stdio::piped()).spawn() {
    //             Err(why) => panic!("couldn't spawn maidsafe_vault: {}", why.description()),
    //             Ok(process) => process,
    //         });
    // thread::sleep_ms(1000);

    // for i in 1..num_of_nodes {
    //     println!("---------- starting node {} --------------", i);
    //     processes.push(match Command::new(executable_path.to_path_buf()).stdout(Stdio::piped()).spawn() {
    //                 Err(why) => panic!("couldn't spawn maidsafe_vault: {}", why.description()),
    //                 Ok(process) => process,
    //             });
    //     thread::sleep_ms(1000 + i * 1500);
    // }
    // thread::sleep_ms(15000);
    // let mut test_failed = false;
    // while let Some(mut process) = processes.pop() {
    //     let _ = process.kill();
    //     let result : Vec<u8> = process.stdout.unwrap().bytes().map(|x| x.unwrap()).collect();
    //     let s = String::from_utf8(result).unwrap();
    //     println!("\n\n     +++++++++++++++++++++++++++++++++++++++\n {} \n\n", s);
    //     let v: Vec<&str> = s.split("added connected node").collect();
    //     let marked_connections = v.len() - 1;
    //     println!("\t  maidsafe_vault {} has {} connected connections.", processes.len(), marked_connections);
    //     if num_of_nodes as usize != marked_connections + 1 {
    //     	test_failed = true;
    //     }
    // }
    // assert_eq!(test_failed, false);
}
