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

use super::{GROUP_SIZE, NodeProcess};
use rand::{thread_rng, random, ThreadRng};
use rand::distributions::Range;
use std::sync::{Arc, Mutex, Condvar};
use maidsafe_utilities::thread::RaiiThreadJoiner;
use std::io;
use std::env;
use std::time::Duration;
use std::process::{Command, Stdio};
use rand::distributions::IndependentSample;
use std::fs::File;
use std::os::unix::io::FromRawFd;
use std::os::unix::io::IntoRawFd;

const CHURN_MIN_WAIT_SEC: u64 = 25;
const CHURN_MAX_WAIT_SEC: u64 = 30;

pub fn simulate_churn(mut nodes: Vec<NodeProcess>,
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

#[allow(unsafe_code)]
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
        let mut path_to_log = try!(env::current_exe());
        path_to_log.set_file_name(format!("Node_{}.log", log_file_number));
        *log_file_number += 1;

        let log_file = try!(File::create(path_to_log));
        let raw_fd = log_file.into_raw_fd();
        unsafe {
            nodes.push(NodeProcess(try!(Command::new(try!(env::current_exe()))
                                            .arg("-n")
                                            .stdout(Stdio::from_raw_fd(raw_fd))
                                            .stderr(Stdio::from_raw_fd(raw_fd))
                                            .spawn())));
        }
        println!("Started Node #{} with Process ID #{}",
                 nodes.len(),
                 nodes[nodes.len() - 1].0.id());
    }

    Ok(())
}
