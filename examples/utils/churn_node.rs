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

//! Runs a test routing node that generates churn.

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

extern crate log;
extern crate rand;
extern crate time;
extern crate routing;
extern crate maidsafe_utilities;

use std::thread;
use self::rand::distributions::IndependentSample;
use self::time::SteadyTime;
use utils::example_node::ExampleNode;
use self::routing::Event;

/// ChurnNode
#[allow(unused)]
pub struct ChurnNode;

impl ChurnNode {
    /// Run a routing node that generates churn.
    #[allow(unused)]
    pub fn run() {
        let mut rng = rand::thread_rng();
        let mut time = SteadyTime::now();
        let minutes = rand::distributions::Range::new(2, 5);
        let mut duration = time::Duration::minutes(minutes.ind_sample(&mut rng));
        let sample = rand::distributions::Range::new(0, 5);
        let mut node = ExampleNode::new();
        let mut sender = node.get_sender();

        trace!("Running node for {:?}", duration);
        let _ = thread::spawn(move || node.run());
        let mut running = true;

        trace!("Entering loop.");
        loop {
            if running {
                trace!("ExampleNode online.");
                if time + duration < SteadyTime::now() {
                    trace!("Reached run time.");
                    let state = sample.ind_sample(&mut rng);
                    if state == 0 {
                        let _ = sender.send(Event::Terminated);
                        running = false;
                        duration = time::Duration::minutes(minutes.ind_sample(&mut rng));
                        trace!("Stopping node for {:?}", duration);
                    }
                    time = SteadyTime::now();
                }
            } else {
                trace!("ExampleNode offline.");
                if time + duration < SteadyTime::now() {
                    trace!("Reached stop time.");
                    node = ExampleNode::new();
                    sender = node.get_sender();
                    let _ = thread::spawn(move || node.run());
                    running = true;
                    duration = time::Duration::minutes(minutes.ind_sample(&mut rng));
                    time = SteadyTime::now();
                    trace!("Running node for {:?}", duration);
                }
            }

            let interval = ::std::time::Duration::from_millis(10000);
            thread::sleep(interval);
        }
    }
}
