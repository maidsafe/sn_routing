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
extern crate env_logger;
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

use log::LogRecord;

use std::fs::{File, OpenOptions};
use std::time::Duration;
use std::{io, env, thread};
use std::io::Write;
use std::sync::{Arc, Mutex, Condvar};
use std::process::{Child, Command};

use docopt::Docopt;
use xor_name::XorName;
use sodiumoxide::crypto::hash;
use utils::{ExampleNode, ExampleClient};
use routing::{Data, DataRequest, PlainData};

use maidsafe_utilities::serialisation::serialise;
use maidsafe_utilities::thread::RaiiThreadJoiner;

use rand::{thread_rng, random, ThreadRng};
use rand::distributions::{IndependentSample, Range};

// use log::LogLevelFilter;
// use log4rs::init_config;
// use log4rs::appender::FileAppender;
// use log4rs::pattern::PatternLayout;
// use log4rs::config::{Config, Logger, Root, Appender};

const GROUP_SIZE: usize = 8;
// TODO This is a current limitation but once responses are coded this can ideally be close to 0
const CHURN_MIN_WAIT_SEC: u64 = 2;
const CHURN_MAX_WAIT_SEC: u64 = 20;
const DEFAULT_REQUESTS: usize = 30;
const DEFAULT_NODE_COUNT: usize = 20;

// const LOG_PATTERN: &'static str = "%l [%T] %f:%L - %m";

struct NodeProcess(Child);
impl Drop for NodeProcess {
    fn drop(&mut self) {
        match self.0.kill() {
            Ok(()) => println!("Killed Node with Process ID #{}", self.0.id()),
            Err(err) => {
                println!("Error killing Node with Process ID #{} - {:?}",
                         self.0.id(),
                         err)
            }
        }
    }
}

fn start_nodes(count: usize) -> Result<Vec<NodeProcess>, io::Error> {
    println!("--------- Starting {} nodes -----------", count);

    let mut nodes = Vec::with_capacity(count);
    let current_exe_path = unwrap_result!(env::current_exe());

    for i in 0..count {
        let mut args = vec![format!("--node=Node_{}.log", i + 1)];
        if i == 0 {
            args.push("-d".to_owned());
        }

        nodes.push(NodeProcess(try!(Command::new(current_exe_path.clone())
                                        .args(&args)
                                        .spawn())));

        println!("Started Node #{} with Process ID {}",
                 i + 1,
                 nodes[i].0.id());
        // Let Routing properly stabilise and populate its routing-table
        thread::sleep(Duration::from_secs(3 + i as u64));
    }

    println!("Waiting 10 seconds to let the network stabilise");
    thread::sleep(Duration::from_secs(10));

    Ok(nodes)
}

fn simulate_churn(mut nodes: Vec<NodeProcess>,
                  network_size: usize,
                  stop_flg: Arc<(Mutex<bool>, Condvar)>)
                  -> RaiiThreadJoiner {
    let joiner = thread!("ChurnSimulationThread", move || {
        let mut rng = thread_rng();
        let wait_range = Range::new(CHURN_MIN_WAIT_SEC, CHURN_MAX_WAIT_SEC);

        let mut log_file_number = nodes.len() + 1;
        loop {
            {
                let &(ref lock, ref cvar) = &*stop_flg;

                let mut stop_condition = unwrap_result!(lock.lock());
                let mut wait_timed_out = false;
                let wait_for = wait_range.ind_sample(&mut rng);

                while !*stop_condition && !wait_timed_out {
                    let wake_up_result = unwrap_result!(cvar.wait_timeout(stop_condition,
                                                         Duration::from_secs(wait_for)));
                    stop_condition = wake_up_result.0;
                    wait_timed_out = wake_up_result.1.timed_out();
                }

                if *stop_condition {
                    break;
                }
            }

            if let Err(err) = simulate_churn_impl(&mut nodes,
                                                  &mut rng,
                                                  &mut log_file_number,
                                                  network_size) {
                println!("{:?}", err);
                break;
            }
        }
    });

    RaiiThreadJoiner::new(joiner)
}

fn simulate_churn_impl(nodes: &mut Vec<NodeProcess>,
                       rng: &mut ThreadRng,
                       log_file_number: &mut usize,
                       network_size: usize)
                       -> Result<(), io::Error> {
    println!("About to churn on #{} active nodes...", nodes.len());

    let kill_node = match nodes.len() {
        size if size == GROUP_SIZE => false,
        size if size == network_size => true,
        _ => random(),
    };

    if kill_node {
        // Never kill the bootstrap (0th) node
        let kill_at_index = Range::new(1, nodes.len()).ind_sample(rng);
        println!("Killing Node #{}", kill_at_index + 1);
        let _ = nodes.remove(kill_at_index);
    } else {
        let arg = format!("--node=Node_{}.log", log_file_number);
        *log_file_number += 1;

        nodes.push(NodeProcess(try!(Command::new(try!(env::current_exe()))
                                        .arg(arg)
                                        .spawn())));
        println!("Started Node #{} with Process ID #{}",
                 nodes.len(),
                 nodes[nodes.len() - 1].0.id());
    }

    Ok(())
}

// ==========================   Program Options   =================================
#[cfg_attr(rustfmt, rustfmt_skip)]
static USAGE: &'static str = "
Usage:
  local_network [(<nodes> <requests>) | (--node=<log_file> | --node=<log_file> -d | -h)]

Options:
  --node=<log_file>             Run individual CI node.
  -d, --delete-bootstrap-cache  Delete existing bootstrap-cache.
  -h, --help                    Display this help message.
";
// ================================================================================

#[derive(PartialEq, Eq, Debug, Clone, RustcDecodable)]
struct Args {
    arg_nodes: Option<usize>,
    arg_requests: Option<usize>,
    flag_node: Option<String>,
    flag_delete_bootstrap_cache: Option<bool>,
    flag_help: Option<bool>,
}

fn init(file_name: String) {
    let mut log_path = unwrap_result!(env::current_exe());
    log_path.set_file_name(file_name.clone());

    // Truncate the file if existent
    let _ = unwrap_result!(File::create(log_path.clone()));

    let format = move |record: &LogRecord| {
        let log_message = format!("[{}:{}] {}\n",
            record.location().file(),
            record.location().line(),
            record.args());
        let mut logfile = unwrap_result!(OpenOptions::new().write(true).append(true).open(file_name.clone()));
        unwrap_result!(logfile.write_all(&log_message.clone().into_bytes()[..]));
        log_message
    };

    let mut builder = ::env_logger::LogBuilder::new();
    let _ = builder.format(format);

    if let Ok(rust_log) = ::std::env::var("RUST_LOG") {
        let _ = builder.parse(&rust_log);
    }

    builder.init().unwrap_or_else(|error| println!("Error initialising logger: {}", error));
}

// fn init_logging(file_name: String) {
//     let mut log_path = unwrap_result!(env::current_exe());
//     log_path.set_file_name(file_name);

//     // Truncate the file if existent
//     let _ = unwrap_result!(File::create(log_path.clone()));

//     let appender = Appender::builder("file".to_owned(),
//                                      Box::new(unwrap_result!(FileAppender::builder(log_path)
//                      .pattern(unwrap_result!(PatternLayout::new(LOG_PATTERN)))
//                      .build())))
//                        .build();

//     let logger = Logger::builder("ci_test::utils::example_node".to_owned(),
//                                  LogLevelFilter::Trace)
//                      .build();

//     let root = Root::builder(LogLevelFilter::Error)
//                    .appender("file".to_owned())
//                    .build();

//     let config = unwrap_result!(Config::builder(root)
//                                      .appender(appender)
//                                      .logger(logger)
//                                      .build());

//     unwrap_result!(init_config(config));
// }

fn main() {
    let args: Args = Docopt::new(USAGE)
                         .and_then(|docopt| docopt.decode())
                         .unwrap_or_else(|e| e.exit());

    let run_network_test = !(args.flag_node.is_some() ||
                             args.flag_delete_bootstrap_cache.is_some());

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

        let stop_flg = Arc::new((Mutex::new(false), Condvar::new()));
        let _raii_joiner = simulate_churn(nodes, node_count, stop_flg.clone());

        println!("--------- Starting Client -----------");
        let mut example_client = ExampleClient::new();

        println!("--------- Putting Data -----------");
        let mut stored_data = Vec::with_capacity(requests);
        for i in 0..requests {
            let key: String = (0..10).map(|_| random::<u8>() as char).collect();
            let value: String = (0..10).map(|_| random::<u8>() as char).collect();
            let name = XorName::new(hash::sha512::hash(key.as_bytes()).0);
            let data = unwrap_result!(serialise(&(key, value)));
            let data = Data::PlainData(PlainData::new(name.clone(), data));

            println!("Putting Data: count #{} - Data {:?}", i + 1, name);
            example_client.put(data.clone());
            stored_data.push(data);
        }

        println!("--------- Getting Data -----------");
        for i in 0..requests {
            println!("Get attempt #{} - Data {:?}", i + 1, stored_data[i].name());
            let data = match example_client.get(DataRequest::PlainData(stored_data[i].name())) {
                Some(data) => data,
                None => {
                    println!("Failed to recover stored data: {}.", stored_data[i].name());
                    break;
                }
            };
            assert_eq!(data, stored_data[i]);
        }

        // Graceful exit
        {
            let &(ref lock, ref cvar) = &*stop_flg;
            *unwrap_result!(lock.lock()) = true;
            cvar.notify_one();
        }
    } else if let Some(log_file) = args.flag_node {
        init(log_file);

        if let Some(true) = args.flag_delete_bootstrap_cache {
            // TODO Remove bootstrap cache file
        }

        ExampleNode::new().run();
    }
}
