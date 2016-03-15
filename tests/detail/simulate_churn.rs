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

use std::io;
use std::sync::{Arc, Mutex, Condvar};
use std::time::Duration;

use kademlia_routing_table::GROUP_SIZE;
use maidsafe_utilities::thread::RaiiThreadJoiner;
use rand::{thread_rng, random, ThreadRng};
use rand::distributions::{IndependentSample, Range};
use super::VaultProcess;

pub fn simulate_churn(mut processes: Vec<VaultProcess>,
                      stop_flag: Arc<(Mutex<bool>, Condvar)>,
                      vault_count: u32,
                      min_wait: u64,
                      max_wait: u64)
                      -> RaiiThreadJoiner {
    RaiiThreadJoiner::new(thread!("churn", move || {
        let mut rng = thread_rng();
        let wait_range = Range::new(min_wait, max_wait);

        let mut vault_index = processes.len() as u32 - 1;
        loop {
            {
                let &(ref lock, ref cond_var) = &*stop_flag;

                let mut stop_condition = unwrap_result!(lock.lock());
                let mut wait_timed_out = false;
                let wait_for = wait_range.ind_sample(&mut rng);

                while !*stop_condition && !wait_timed_out {
                    let wake_up_result = unwrap_result!(cond_var.wait_timeout(stop_condition,
                                                         Duration::from_secs(wait_for)));
                    stop_condition = wake_up_result.0;
                    wait_timed_out = wake_up_result.1.timed_out();
                }

                if *stop_condition {
                    break;
                }
            }

            if let Err(err) = simulate_churn_impl(&mut processes,
                                                  &mut rng,
                                                  vault_count,
                                                  &mut vault_index) {
                error!("{:?}", err);
                break;
            }
        }
    }))
}

fn simulate_churn_impl(processes: &mut Vec<VaultProcess>,
                       rng: &mut ThreadRng,
                       vault_count: u32,
                       vault_index: &mut u32)
                       -> Result<(), io::Error> {
    info!("About to churn");

    let kill_node = match processes.len() {
        size if size == GROUP_SIZE => false,
        size if size == vault_count as usize => true,
        _ => random(),
    };

    if kill_node {
        // Never kill the bootstrap (0th) node
        let kill_at_index = Range::new(1, processes.len()).ind_sample(rng);
        info!("Killing {:?}",
              unwrap_option!(processes.get(kill_at_index), ""));
        let _ = processes.remove(kill_at_index);
    } else {
        *vault_index += 1;
        processes.push(VaultProcess::new(*vault_index));
    }

    Ok(())
}
