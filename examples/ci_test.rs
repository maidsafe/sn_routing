// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
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
#![forbid(exceeding_bitshifts, mutable_transmutes, no_mangle_const_items,
          unknown_crate_types, warnings)]
#![deny(bad_style, deprecated, improper_ctypes, missing_docs,
        non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
        private_no_mangle_fns, private_no_mangle_statics, stable_features, unconditional_recursion,
        unknown_lints, unsafe_code, unused, unused_allocation, unused_attributes,
        unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results)]
#![allow(box_pointers, missing_copy_implementations,
         missing_debug_implementations, variant_size_differences, non_camel_case_types)]

#![cfg_attr(feature = "use-mock-crust", allow(unused_extern_crates, unused_imports))]

#[macro_use]
extern crate log;
extern crate maidsafe_utilities;
extern crate rand;
extern crate docopt;
extern crate rust_sodium;
extern crate routing;
extern crate lru_time_cache;
extern crate term;
#[macro_use]
extern crate unwrap;
#[macro_use]
extern crate serde_derive;

mod utils;

#[cfg(feature = "use-mock-crust")]
fn main() {
    println!("This example should be built without `--features=use-mock-crust`.");
    // Return Linux sysexit code for "configuration error"
    ::std::process::exit(78);
}

#[cfg(not(feature = "use-mock-crust"))]
mod unnamed {
    use docopt::Docopt;
    use maidsafe_utilities::SeededRng;
    use maidsafe_utilities::log;
    use maidsafe_utilities::thread::Joiner;
    use maidsafe_utilities::thread::named as thread_named;
    use rand::{Rng, ThreadRng, random, thread_rng};
    use rand::distributions::{IndependentSample, Range};
    use routing::{MIN_SECTION_SIZE, MutableData, Value};
    use rust_sodium::crypto::sign;
    use std::{env, io, thread};
    use std::collections::BTreeMap;
    use std::io::Write;
    use std::iter;
    use std::panic;
    use std::process::{Child, Command, Stdio};
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::Duration;
    use term::{self, color};
    use utils::{ExampleClient, ExampleNode};

    const CHURN_MIN_WAIT_SEC: u64 = 20;
    const CHURN_MAX_WAIT_SEC: u64 = 30;
    const CHURN_TIME_SEC: u64 = 20;
    const DEFAULT_REQUESTS: usize = 30;
    const DEFAULT_NODE_COUNT: usize = 20;
    /// The number of churn-get cycles.
    const DEFAULT_BATCHES: usize = 1;

    struct NodeProcess(Child, usize);

    impl Drop for NodeProcess {
        fn drop(&mut self) {
            match self.0.kill() {
                Ok(()) => println!("Killed Node with Process ID #{}", self.0.id()),
                Err(err) => {
                    println!(
                        "Error killing Node with Process ID #{} - {:?}",
                        self.0.id(),
                        err
                    )
                }
            }
        }
    }

    fn start_nodes(count: usize) -> Vec<NodeProcess> {
        println!("--------- Starting {} nodes -----------", count);

        let current_exe_path = unwrap!(env::current_exe());
        let mut log_path = current_exe_path.clone();

        let nodes: Vec<_> = (0..count)
            .map(|i| {
                log_path.set_file_name(&format!("Node{:02}.log", i));
                let mut args = vec![format!("--output={}", log_path.display())];
                if i == 0 {
                    args.push("-d".to_owned());
                    args.push("-f".to_owned());
                }

                let cmd = Command::new(current_exe_path.clone())
                    .args(&args)
                    .stdout(Stdio::piped())
                    .stderr(Stdio::inherit())
                    .spawn();
                let node = NodeProcess(unwrap!(cmd), i);

                println!("Started Node #{} with Process ID {}", i, node.0.id());
                thread::sleep(Duration::from_secs(5));
                node
            })
            .collect();
        thread::sleep(Duration::from_secs(10));
        nodes
    }

    fn simulate_churn(
        mut nodes: Vec<NodeProcess>,
        network_size: usize,
        stop_flag: Arc<(Mutex<bool>, Condvar)>,
    ) -> Joiner {
        thread_named("ChurnSimulationThread", move || {
            let mut rng = thread_rng();
            let wait_range = Range::new(CHURN_MIN_WAIT_SEC, CHURN_MAX_WAIT_SEC);

            let mut node_count = nodes.len();

            loop {
                {
                    let &(ref lock, ref condvar) = &*stop_flag;

                    let mut stop_condition = unwrap!(lock.lock());
                    let mut wait_timed_out = false;
                    let wait_for = wait_range.ind_sample(&mut rng);

                    while !*stop_condition && !wait_timed_out {
                        let wake_up_result = unwrap!(condvar.wait_timeout(
                            stop_condition,
                            Duration::from_secs(wait_for),
                        ));
                        stop_condition = wake_up_result.0;
                        wait_timed_out = wake_up_result.1.timed_out();
                    }

                    if *stop_condition {
                        break;
                    }
                }

                if let Err(err) = simulate_churn_impl(
                    &mut nodes,
                    &mut rng,
                    network_size,
                    &mut node_count,
                )
                {
                    println!("{:?}", err);
                    break;
                }
            }
        })
    }

    fn simulate_churn_impl(
        nodes: &mut Vec<NodeProcess>,
        rng: &mut ThreadRng,
        network_size: usize,
        node_count: &mut usize,
    ) -> Result<(), io::Error> {
        print!("Churning on {} active nodes. ", nodes.len());
        io::stdout().flush().expect("Could not flush stdout");

        let kill_node = match nodes.len() {
            size if size == MIN_SECTION_SIZE => false,
            size if size == network_size => true,
            _ => random(),
        };

        let current_exe_path = unwrap!(env::current_exe());
        let mut log_path = current_exe_path.clone();

        if kill_node {
            // Never kill the bootstrap (0th) node
            let kill_at_index = Range::new(1, nodes.len()).ind_sample(rng);
            let node = nodes.remove(kill_at_index);
            print!("Killing Node #{}: ", node.1);
            io::stdout().flush().expect("Could not flush stdout");
        } else {
            *node_count += 1;
            log_path.set_file_name(&format!("Node{:02}.log", node_count));
            let arg = format!("--output={}", log_path.display());

            nodes.push(NodeProcess(
                Command::new(current_exe_path.clone())
                    .arg(arg)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()?,
                *node_count,
            ));
            println!(
                "Started Node #{} with Process ID #{}",
                node_count,
                nodes[nodes.len() - 1].0.id()
            );
        }

        Ok(())
    }

    fn print_color(text: &str, color: color::Color) {
        let mut term = term::stdout().expect("Could not open stdout.");
        term.fg(color).expect("Failed to set color");
        print!("{}", text);
        term.reset().expect("Failed to restore stdout attributes.");
        io::stdout().flush().expect("Could not flush stdout");
    }

    fn store_and_verify(requests: usize, batches: usize) {
        let mut test_success = true;
        println!("--------- Starting Client -----------");
        let mut example_client = ExampleClient::new();

        println!("--------- Putting Data -----------");
        let mut stored_data = Vec::with_capacity(requests);
        let mut rng = SeededRng::new();
        for i in 0..requests {
            let data = gen_mutable_data(&mut rng, *example_client.signing_public_key());

            print!("Putting Data: count #{} - Data {:?} - ", i, data.name());
            io::stdout().flush().expect("Could not flush stdout");

            if example_client.put_mdata(data.clone()).is_ok() {
                print_color("OK", color::GREEN);
                print!(" - getting - ");
                io::stdout().flush().expect("Could not flush stdout");

                stored_data.push(data.clone());

                let shell_res = example_client.get_mdata_shell(*data.name(), data.tag());
                let entries_res = example_client.list_mdata_entries(*data.name(), data.tag());

                if let (Ok(shell), Ok(entries)) = (shell_res, entries_res) {
                    assert_eq!(shell, data.shell());
                    assert_eq!(entries, *data.entries());
                    print_color("OK\n", color::GREEN);
                } else {
                    test_success = false;
                    print_color("FAIL\n", color::RED);
                    break;
                };
            } else {
                test_success = false;
                print_color("FAIL\n", color::RED);
                break;
            }
        }

        for batch in 0..batches {
            println!("--------- Churning {} seconds -----------", CHURN_TIME_SEC);
            thread::sleep(Duration::from_secs(CHURN_TIME_SEC));

            println!("--------- Getting Data - batch {} -----------", batch);
            for (i, data) in stored_data.iter().enumerate().take(requests) {
                print!("Get attempt #{} - {} - ", i, data.name());
                io::stdout().flush().expect("Could not flush stdout");

                let res_shell = example_client.get_mdata_shell(*data.name(), data.tag());
                let res_entries = example_client.list_mdata_entries(*data.name(), data.tag());

                if let (Ok(shell), Ok(entries)) = (res_shell, res_entries) {
                    assert_eq!(shell, data.shell());
                    assert_eq!(entries, *data.entries());
                    print_color("OK\n", color::GREEN);
                } else {
                    test_success = false;
                    print_color("FAIL\n", color::RED);
                    break;
                };
            }
        }

        assert!(test_success, "Failed to store and verify data.");
    }

    fn gen_mutable_data<R: Rng>(rng: &mut R, owner: sign::PublicKey) -> MutableData {
        let name = rng.gen();
        let tag = rng.gen_range(10_000, 20_000);

        let num_entries = rng.gen_range(0, 10);
        let mut entries = BTreeMap::new();

        for _ in 0..num_entries {
            let key = rng.gen_iter().take(5).collect();
            let content = rng.gen_iter().take(10).collect();
            let _ = entries.insert(
                key,
                Value {
                    content: content,
                    entry_version: 0,
                },
            );
        }

        let owners = iter::once(owner).collect();

        unwrap!(MutableData::new(
            name,
            tag,
            Default::default(),
            entries,
            owners,
        ))
    }

    // ==========================   Program Options   =================================
    #[cfg_attr(rustfmt, rustfmt_skip)]
    static USAGE: &'static str = "
Usage:
  ci_test -h
  ci_test [--output=<log_file>] [-c [<requests> [<batches>]]] [-f] [-d]
  ci_test [<nodes> <requests> [<batches>]]

Options:
  -o, --output=<log_file>       Run individual CI node.
  -c, --client                  Run as an individual client.
  -d, --delete-bootstrap-cache  Delete existing bootstrap-cache.
  -h, --help                    Display this help message.
  -f, --first                   This is the first node of a new network.
";
    // ================================================================================

    #[derive(PartialEq, Eq, Debug, Deserialize, Clone)]
    struct Args {
        arg_batches: Option<usize>,
        arg_nodes: Option<usize>,
        arg_requests: Option<usize>,
        flag_first: Option<bool>,
        flag_output: Option<String>,
        flag_client: Option<bool>,
        flag_delete_bootstrap_cache: Option<bool>,
        flag_help: Option<bool>,
    }

    #[cfg_attr(feature = "cargo-clippy", allow(mutex_atomic))]
    pub fn run_main() {
        let args: Args = Docopt::new(USAGE)
            .and_then(|docopt| docopt.deserialize())
            .unwrap_or_else(|error| error.exit());

        let run_network_test = !(args.flag_output.is_some() ||
                                     args.flag_delete_bootstrap_cache.is_some());
        let requests = args.arg_requests.unwrap_or(DEFAULT_REQUESTS);
        let batches = args.arg_batches.unwrap_or(DEFAULT_BATCHES);
        let first = args.flag_first.unwrap_or(false);

        if run_network_test {
            unwrap!(log::init(false));
            let node_count = match args.arg_nodes {
                Some(number) => {
                    if number <= MIN_SECTION_SIZE {
                        panic!("The number of nodes should be > {}.", MIN_SECTION_SIZE);
                    }

                    number
                }
                None => DEFAULT_NODE_COUNT,
            };

            let nodes = start_nodes(node_count);

            let stop_flag = Arc::new((Mutex::new(false), Condvar::new()));
            let _raii_joiner = simulate_churn(nodes, node_count, Arc::clone(&stop_flag));

            let test_result = panic::catch_unwind(|| { store_and_verify(requests, batches); });

            // Graceful exit
            {
                let &(ref lock, ref condvar) = &*stop_flag;
                *unwrap!(lock.lock()) = true;
                condvar.notify_one();
            }
            assert!(test_result.is_ok());
        } else {
            if let Some(log_file) = args.flag_output {
                unwrap!(log::init_to_file(false, log_file, true));
            } else {
                unwrap!(log::init(false));
            }

            if let Some(true) = args.flag_delete_bootstrap_cache {
                // TODO Remove bootstrap cache file
            }

            if Some(true) == args.flag_client {
                store_and_verify(requests, batches);
            } else {
                ExampleNode::new(first).run();
            }
        }
    }
}

#[cfg(not(feature = "use-mock-crust"))]
fn main() {
    unnamed::run_main()
}
