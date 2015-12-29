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
use std::sync::Arc;
use std::sync::atomic::{Ordering, AtomicBool};
use maidsafe_utilities::thread::RaiiThreadJoiner;
use std::thread::sleep;
use std::io;
use std::env;
use std::time::Duration;
use std::process::Command;
use rand::distributions::IndependentSample;

const CHURN_MIN_WAIT_SEC: u64 = 10;
const CHURN_MAX_WAIT_SEC: u64 = 30;

pub fn simulate_churn(mut nodes: Vec<NodeProcess>,
                      network_size: usize,
                      stop_flg: Arc<AtomicBool>)
                      -> RaiiThreadJoiner {
    let joiner = thread!("ChurnSimulationThread", move || {
        let mut rng = thread_rng();
        let wait_range = Range::new(CHURN_MIN_WAIT_SEC, CHURN_MAX_WAIT_SEC);

        while !stop_flg.load(Ordering::SeqCst) {
            let wait_for = wait_range.ind_sample(&mut rng);
            sleep(Duration::from_secs(wait_for));
            if let Err(err) = simulate_churn_impl(&mut nodes, &mut rng, network_size) {
                error!("{:?}", err);
                break;
            }
        }
    });

    RaiiThreadJoiner::new(joiner)
}

fn simulate_churn_impl(nodes: &mut Vec<NodeProcess>,
                       rng: &mut ThreadRng,
                       network_size: usize)
                       -> Result<(), io::Error> {
    let kill_node = match nodes.len() {
        size if size == GROUP_SIZE => false,
        size if size == network_size => true,
        _ => random(),
    };

    if kill_node {
        // Never kill the bootstrap (0th) node
        let kill_at_index = Range::new(1, nodes.len()).ind_sample(rng);
        let _ = nodes.remove(kill_at_index);
    } else {
        nodes.push(NodeProcess(try!(Command::new(try!(env::current_exe()))
                                        .arg("-n")
                                        .spawn())));
        trace!("Started Node #{} with Process ID #{}",
               nodes.len() - 1,
               nodes[0].0.id());
    }

    Ok(())
}
