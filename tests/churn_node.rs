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

#[macro_use]
extern crate log;
#[macro_use]
extern crate maidsafe_utilities;
extern crate rand;
extern crate time;
extern crate routing;

use routing::Event;

#[allow(missing_docs)]
pub fn main () {
    use rand::distributions::IndependentSample;

    ::maidsafe_utilities::log::init(true);

    let mut time = ::time::SteadyTime::now();
    let runtime = ::time::Duration::minutes(5);
    let stoptime = ::time::Duration::minutes(2);
    let mut rng = ::rand::thread_rng();
    let range = ::rand::distributions::Range::new(0, 20);
    let mut node = ::routing::test_utils::node::Node::new();
    let mut sender = node.get_sender();

    debug!("Running node.");
    let _ = thread!("Initial churn node", move || node.run());
    let mut running = true;

    debug!("Entering loop.");
    loop {
        if running {
            debug!("Node online.");
            if time + runtime < ::time::SteadyTime::now() {
                debug!("Reached run time.");
                let sample = range.ind_sample(&mut rng);
                if sample == 0 {
                    debug!("Stopping node.");
                    let _ = sender.send(Event::Terminated);
                    running = false;
                }
                time = ::time::SteadyTime::now();
            }
        } else {
            debug!("Node offline.");
            if time + stoptime < ::time::SteadyTime::now() {
                debug!("Reached stop time.");
                node = ::routing::test_utils::node::Node::new();
                sender = node.get_sender();
                debug!("Running node.");
                let _ = thread!("Later churn node", move || node.run());
                running = true;
                time = ::time::SteadyTime::now();
            }
        }

        let interval = ::std::time::Duration::from_millis(10000);
        ::std::thread::sleep(interval);
    }
}
