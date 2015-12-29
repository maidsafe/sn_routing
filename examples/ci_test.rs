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
extern crate lru_time_cache;
extern crate time;

mod utils;
mod simulate_churn;

use rand::random;
use std::string::String;
use std::error::Error;
use std::io;
use std::env;
use std::thread;
use std::time::Duration;
use std::process::{Child, Command};
use docopt::Docopt;
use sodiumoxide::crypto::hash;
use maidsafe_utilities::serialisation::serialise;
use utils::example_client::ExampleClient;
use routing::{Data, DataRequest, PlainData};
use xor_name::XorName;
use std::sync::Arc;
use std::sync::atomic::{Ordering, AtomicBool};

const GROUP_SIZE: usize = 8;
const DEFAULT_REQUESTS: usize = 30;
const DEFAULT_NODE_COUNT: usize = 20;

/// RAII wrapper for child processes
pub struct NodeProcess(Child);
impl Drop for NodeProcess {
    fn drop(&mut self) {
        match self.0.kill() {
            Ok(()) => trace!("Killed Node with Process ID #{}", self.0.id()),
            Err(err) => {
                error!("Error killing Node with Process ID #{} - {:?}",
                       self.0.id(),
                       err)
            }
        }
    }
}

fn start_nodes(count: usize) -> Result<Vec<NodeProcess>, io::Error> {
    println!("--------- Starting #{} nodes -----------", count);

    let mut nodes = Vec::with_capacity(count);
    let current_exe_path = unwrap_result!(env::current_exe());

    let mut arg;
    for i in 0..count {
        arg = match i {
            0 => "-nd".to_owned(),
            _ => "-n".to_owned(),
        };

        nodes.push(NodeProcess(try!(Command::new(current_exe_path.clone()).arg(arg).spawn())));
        trace!("Started Node #{} with Process ID #{}", i, nodes[0].0.id());
        // Let Routing properly stabilise and populate its routing-table
        thread::sleep(Duration::from_secs(1 + i as u64));
    }

    Ok(nodes)
}

// ==========================   Program Options   =================================
#[cfg_attr(rustfmt, rustfmt_skip)]
static USAGE: &'static str = "
Usage:
  local_network [(<nodes> <requests>) | ([-nhd] | [-ch])]

Options:
  -n, --node                    Run individual CI node.
  -c, --client                  Run individual CI client.
  -d, --delete-bootstrap-cache  Delete existing bootstrap-cache.
  -h, --help                    Display this help message.
";

#[derive(PartialEq, Eq, Debug, Clone, RustcDecodable)]
struct Args {
    arg_nodes: Option<usize>,
    arg_requests: Option<usize>,
    flag_node: Option<bool>,
    flag_delete_bootstrap_cache: Option<bool>,
    flag_client: Option<bool>,
    flag_help: Option<bool>,
}

fn main() {
    maidsafe_utilities::log::init(true);

    let args: Args = Docopt::new(USAGE)
                         .and_then(|docopt| docopt.decode())
                         .unwrap_or_else(|e| e.exit());

    println!("{:?}", args);

    let run_network_test = !(args.flag_node.is_some() ||
                             args.flag_delete_bootstrap_cache.is_some() ||
                             args.flag_client.is_some());

    if run_network_test {
        let node_count = match args.arg_nodes {
            Some(number) => {
                if number <= GROUP_SIZE {
                    panic!("The number of nodes should be > Group-Size. {{Group-Size = #{}}}",
                           GROUP_SIZE);
                }

                number
            }
            None => DEFAULT_NODE_COUNT,
        };

        let requests = args.arg_requests.unwrap_or(DEFAULT_REQUESTS);

        let nodes = unwrap_result!(start_nodes(node_count));

        let stop_flg = Arc::new(AtomicBool::new(false));
        let _raii_joiner = simulate_churn::simulate_churn(nodes, node_count, stop_flg.clone());

        // TODO (Spandan) Done till above
        // /////////////////////////////////

        trace!("Starting Client");
        let mut example_client = ExampleClient::new();

        let interval = ::std::time::Duration::from_millis(10000);
        thread::sleep(interval);

        trace!("Putting data");
        let mut stored_data = Vec::with_capacity(requests);
        for i in 0..requests {
            let key: String = (0..10).map(|_| random::<u8>() as char).collect();
            let value: String = (0..10).map(|_| random::<u8>() as char).collect();
            let name = XorName::new(hash::sha512::hash(key.as_bytes()).0);
            let data = unwrap_result!(serialise(&(key, value)));
            let data = Data::PlainData(PlainData::new(name.clone(), data));

            example_client.put(data.clone());
            println!("Putting Data: count #{}", i);
            ::std::thread::sleep(::std::time::Duration::from_secs(5));
            stored_data.push(data);
        }

        trace!("Getting data");
        for i in 0..requests {
            trace!("Get attempt #{}", i);
            let data = match example_client.get(DataRequest::PlainData(stored_data[i].name())) {
                Some(data) => data,
                None => panic!("Failed to recover stored data: {}.", stored_data[i].name()),
            };
            assert_eq!(data, stored_data[i]);
        }

        stop_flg.store(true, Ordering::SeqCst);
    } else if let Some(true) = args.flag_node {
        trace!("--------- Running Individual Node ----------");
        utils::example_node::ExampleNode::new().run();
    } else if let Some(true) = args.flag_client {
        trace!("--------- Running Individual Client ----------");
        // TODO
        let _ = ExampleClient::new();
    }
}

// /// //////////////////////////////////////
// /// 0) spawn N > close_group number of nodes
// /// 1) do not churn till this
// /// 2) after this run a random churn event which either kills a node or adds a node
// ///    a) the killing of the node is to be ignored if number of nodes has come down to close_group
// ///       size (same as 0 and 1)
// ///    b) bootstrap node should never get killed
// ///    c) the adding of the node is to be ignored if number of nodes has gone up to N
