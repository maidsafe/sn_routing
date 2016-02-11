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
#![allow(unused_extern_crates)]

#[macro_use]
extern crate log;
#[macro_use]
extern crate maidsafe_utilities;
extern crate rand;
extern crate routing;
extern crate sodiumoxide;
extern crate xor_name;
extern crate mpid_messaging;

#[cfg(not(feature = "use-mock-routing"))]
mod detail;
#[cfg(not(feature = "use-mock-routing"))]
use xor_name::XorName;
#[cfg(not(feature = "use-mock-routing"))]
use routing::StructuredData;
#[cfg(not(feature = "use-mock-routing"))]
use routing::Data;

#[cfg(not(feature = "use-mock-routing"))]
fn main() {
    use detail::*;
    maidsafe_utilities::log::init(false);
    let vault_count = 10;
    let processes = setup_network(vault_count);
    let mut client = Client::new();

    let sd = unwrap_result!(StructuredData::new(0, rand::random::<XorName>(), 0, vec![], vec![], vec![], None));
    let _ = client.put(Data::StructuredData(sd));

    immutable_data_churn_test(&mut client);
    structured_data_churn_test(&mut client);

    messaging_test();

    for mut process in processes {
        let _ = process.kill();
    }
}

#[cfg(feature = "use-mock-routing")]
fn main() {}
