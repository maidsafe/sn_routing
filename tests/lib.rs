// Copyright 2015 MaidSafe.net limited.
//
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

#[macro_use]
extern crate log;
#[macro_use]
extern crate maidsafe_utilities;
extern crate routing;
extern crate sodiumoxide;
extern crate xor_name;

use std::error::Error;
use std::process::{Child, Command, ExitStatus};

fn start_nodes(number_of_nodes: u32) -> Vec<Child> {
    ::maidsafe_utilities::log::init(false);
    let mut processes = Vec::new();
    let exe_path = match std::env::current_exe() {
        Ok(mut exe_path) => {
            exe_path.pop();
            std::path::Path::new("./target")
                .join(unwrap_option!(exe_path.iter().last(), ""))
                .join("node")
        }
        Err(e) => panic!("Failed to get current integration test path: {}", e),
    };

    debug!("Expecting node executable at path {}", exe_path.to_path_buf().display());

    for i in 0..number_of_nodes {
        processes.push(match Command::new(exe_path.to_path_buf())
                                 .stderr(::std::process::Stdio::piped())
                                 .spawn() {
            Err(e) => panic!("Failed to spawn process: {}", e.description()),
            Ok(process) => {
                trace!("Starting Node {:05}", process.id());
                process
            }
        });
        let interval = ::std::time::Duration::from_millis(1000 + i as u64 * 1000);
        ::std::thread::sleep(interval);
    }

    let interval = ::std::time::Duration::from_millis(number_of_nodes as u64 * 1000);
    ::std::thread::sleep(interval);
    processes
}

fn stop_nodes(processes: &mut Vec<Child>) {
    while let Some(mut process) = processes.pop() {
        trace!("Stopping Node {:05}", process.id());
        let _ = process.kill();
    }
}

fn calculate_key_name(key: &::std::string::String) -> ::xor_name::XorName {
    ::xor_name::XorName::new(::sodiumoxide::crypto::hash::sha512::hash(key.as_bytes()).0)
}

fn local_network(nodes: usize, requests: usize) -> ExitStatus {
    let exe_path = match std::env::current_exe() {
        Ok(mut exe_path) => {
            exe_path.pop();
            std::path::Path::new("./target")
                .join(unwrap_option!(exe_path.iter().last(), ""))
                .join("local_network")
        }
        Err(e) => panic!("Failed to get current integration test path: {}", e),
    };

    Command::new(exe_path.to_path_buf())
        .arg(nodes.to_string())
        .arg(requests.to_string())
        .status()
        .unwrap_or_else(|e| { panic!("Failed to execute process: {}", e) })
}

#[cfg(test)]
mod test {
    use routing::{PlainData, Data, DataRequest};

    #[test]
    #[ignore]
    fn start_stop_nodes() {
        let mut nodes = super::start_nodes(3u32);
        super::stop_nodes(&mut nodes);
    }

    #[test]
    #[ignore]
    fn client_put_get() {
        let mut nodes = super::start_nodes(3u32);
        trace!("Starting Client");
        let mut client = ::routing::test_utils::client::Client::new();
        let interval = ::std::time::Duration::from_millis(2000);
        ::std::thread::sleep(interval);

        let key = ::std::string::String::from("key");
        let value = ::std::string::String::from("value");
        let name = super::calculate_key_name(&key.clone());
        let data = unwrap_result!(::maidsafe_utilities::serialisation::serialise(&(key, value)));
        let data = Data::PlainData(PlainData::new(name.clone(), data));

        trace!("Putting data {:?}", data);
        client.put(data.clone());

        let interval = ::std::time::Duration::from_millis(5000);
        ::std::thread::sleep(interval);

        let recovered_data = match client.get(DataRequest::PlainData(name)) {
            Some(data) => data,
            None => panic!("Failed to recover stored data: {}.", name),
        };

        trace!("Recovered data {:?}", recovered_data);
        super::stop_nodes(&mut nodes);
        assert_eq!(recovered_data, data);
    }

    #[test]
    fn local_network() {
        assert!(super::local_network(6, 3).success());
    }
}
