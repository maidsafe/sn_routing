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

//! Run a local network with 'nodes' nodes sending 'requests' requests.

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
extern crate rand;
extern crate rustc_serialize;
extern crate docopt;
extern crate sodiumoxide;
extern crate routing;
extern crate xor_name;

mod utils;

use rand::random;
use std::string::String;
use std::error::Error;
use std::process::{Child, Command, Stdio};
use docopt::Docopt;
use sodiumoxide::crypto::hash;
use maidsafe_utilities::serialisation::serialise;
use utils::client::Client;
use routing::{Data, DataRequest, PlainData};
use xor_name::XorName;


fn start_nodes(nodes: usize, churn_nodes: usize) -> Vec<Child> {
    maidsafe_utilities::log::init(false);
    let mut processes = Vec::new();
    let (node_exe_path, churn_node_exe_path) = match std::env::current_exe() {
        Ok(exe_path) => {
            let parent = unwrap_option!(exe_path.parent(), "").clone();
            (parent.join("node"), parent.join("churn_node"))
        }
        Err(e) => panic!("Failed to get current integration test path: {}", e),
    };

    for i in 0..nodes {
        processes.push(match Command::new(node_exe_path.to_path_buf())
                                 .stderr(Stdio::piped())
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

    for i in 0..churn_nodes {
        processes.push(match Command::new(churn_node_exe_path.to_path_buf())
                                 .stderr(Stdio::piped())
                                 .spawn() {
            Err(e) => panic!("Failed to spawn process: {}", e.description()),
            Ok(process) => {
                trace!("Starting ChurnNode {:05}", process.id());
                process
            }
        });
        let interval = ::std::time::Duration::from_millis(2000 + i as u64 * 1000);
        ::std::thread::sleep(interval);
    }

    let interval = ::std::time::Duration::from_millis((nodes + churn_nodes) as u64 * 1000);
    ::std::thread::sleep(interval);
    processes
}

fn stop_nodes(processes: &mut Vec<Child>) {
    while let Some(mut process) = processes.pop() {
        trace!("Stopping process {:05}", process.id());
        let _ = process.kill();
    }
}

// ==========================   Program Options   =================================
static USAGE: &'static str = "
Usage:
  local_network [options] <nodes> <requests>

Options:
  \
                              -h, --help   Display this help message.

  Run 'nodes' nodes \
                              sending 'requests' requests.
";

#[derive(PartialEq, Eq, Debug, Clone, RustcDecodable)]
struct Args {
    arg_nodes: Option<usize>,
    arg_requests: Option<usize>,
    flag_help: bool,
}

fn main() {
    maidsafe_utilities::log::init(false);
    let args: Args = Docopt::new(USAGE)
                         .and_then(|docopt| docopt.decode())
                         .unwrap_or_else(|error| error.exit());
    // Default number of nodes to run is 10, 20% stable, 80% churn.
    let mut nodes: usize = 2;
    let mut churn_nodes: usize = 8;
    // Default number of put requests to send is 100, extend to post, delete requests later.
    let mut requests: usize = 100;

    match args.arg_nodes {
        Some(number) => {
            churn_nodes = (number as f32 * 0.8).floor() as usize;
            nodes = number - churn_nodes;
        }
        None => {}
    }
    match args.arg_requests {
        Some(number) => {
            requests = number;
        }
        None => {}
    }

    let mut processes = start_nodes(nodes, churn_nodes);
    trace!("Starting Client");
    let mut client = Client::new();

    let interval = ::std::time::Duration::from_millis(10000);
    ::std::thread::sleep(interval);

    trace!("Putting data");
    let mut stored_data = Vec::with_capacity(requests);
    for _ in 0..requests {
        let key: String = (0..10).map(|_| random::<u8>() as char).collect();
        let value: String = (0..10).map(|_| random::<u8>() as char).collect();
        let name = XorName::new(hash::sha512::hash(key.as_bytes()).0);
        let data = unwrap_result!(serialise(&(key, value)));
        let data = Data::PlainData(PlainData::new(name.clone(), data));

        client.put(data.clone());
        stored_data.push(data);
    }

    let interval = ::std::time::Duration::from_millis(5000);
    ::std::thread::sleep(interval);

    trace!("Getting data");
    for i in 0..requests {
        let data = match client.get(DataRequest::PlainData(stored_data[i].name())) {
            Some(data) => data,
            None => panic!("Failed to recover stored data: {}.", stored_data[i].name()),
        };
        assert_eq!(data, stored_data[i]);
    }

    stop_nodes(&mut processes);
}
