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

//! Standalone CI test runner which starts a vault network with each vault as a separate process.

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

#![cfg_attr(feature="clippy", feature(plugin))]
#![cfg_attr(feature="clippy", plugin(clippy))]
#![cfg_attr(feature="clippy", deny(clippy, clippy_pedantic))]

// To avoid multiple cfg statements before each import.
#![cfg_attr(feature="use-mock-routing", allow(unused, unused_extern_crates))]

extern crate kademlia_routing_table;
#[macro_use]
extern crate log;
#[macro_use]
extern crate maidsafe_utilities;
extern crate mpid_messaging;
extern crate rand;
extern crate routing;
extern crate rustc_serialize;
extern crate sodiumoxide;
extern crate xor_name;

#[cfg(not(feature = "use-mock-routing"))]
mod detail;

const VAULT_COUNT: u32 = 10;
// TODO This is a current limitation but once responses are coded this can ideally be close to 0
const CHURN_MIN_WAIT_SEC: u64 = 10;
const CHURN_MAX_WAIT_SEC: u64 = 20;
// The number of requests to send during the churn phase of the tests.  This will result in
// `REQUEST_COUNT` Puts for ImmutableData, then `REQUEST_COUNT` Gets, then similarly for
// StructuredData and MPID messages.
const REQUEST_COUNT: u32 = 30;

use std::process;
use std::sync::{Arc, Mutex, Condvar};
#[cfg(not(feature = "use-mock-routing"))]
use detail::*;

#[cfg(not(feature = "use-mock-routing"))]
fn main() {
    let mut failed = false;
    {
        maidsafe_utilities::log::init(true);
        let vault_count = VAULT_COUNT;
        let min_wait = CHURN_MIN_WAIT_SEC;
        let max_wait = CHURN_MAX_WAIT_SEC;
        let request_count = REQUEST_COUNT;
        let processes = setup_network(vault_count);

        let mut is_err = thread!("ImmutableData test", move || immutable_data_test())
                             .join()
                             .is_err();
        failed = failed || is_err;
        is_err = thread!("StructuredData test", move || structured_data_test()).join().is_err();
        failed = failed || is_err;
        is_err = thread!("Messaging test", move || messaging_test()).join().is_err();
        failed = failed || is_err;

        let stop_flag = Arc::new((Mutex::new(false), Condvar::new()));
        let _joiner = simulate_churn(processes,
                                     stop_flag.clone(),
                                     vault_count,
                                     min_wait,
                                     max_wait);
        is_err = thread!("ImmutableData churn test",
                         move || immutable_data_churn_test(request_count))
                     .join()
                     .is_err();
        failed = failed || is_err;
        is_err = thread!("StructuredData churn test",
                         move || structured_data_churn_test(request_count))
                     .join()
                     .is_err();
        failed = failed || is_err;
        is_err = thread!("Messaging churn test",
                         move || messaging_churn_test(request_count))
                     .join()
                     .is_err();
        failed = failed || is_err;

        // Stop churn thread
        let &(ref lock, ref cond_var) = &*stop_flag;
        *unwrap_result!(lock.lock()) = true;
        cond_var.notify_one();
    }
    if failed {
        println!("OVERALL FAILED\n");
        process::exit(101);
    } else {
        println!("OVERALL PASSED\n");
    }
}

#[cfg(feature = "use-mock-routing")]
fn main() {}
