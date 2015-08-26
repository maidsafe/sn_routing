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

//! SAFE Vault provides the interface to SAFE routing.
//! The resulting executable is the Vault node for the SAFE network.

#![doc(html_logo_url = "http://maidsafe.net/img/Resources/branding/maidsafe_logo.fab2.png",
       html_favicon_url = "http://maidsafe.net/img/favicon.ico",
       html_root_url = "http://maidsafe.github.io/safe_vault")]
#![forbid(bad_style, warnings)]
#![deny(deprecated, drop_with_repr_extern, improper_ctypes, missing_docs,
        non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
        private_no_mangle_fns, private_no_mangle_statics, raw_pointer_derive, stable_features,
        unconditional_recursion, unknown_lints, unsafe_code, unused, unused_allocation,
        unused_attributes, unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results, variant_size_differences)]

#[macro_use]
extern crate log;
extern crate env_logger;

// Non-MaidSafe crates
extern crate cbor;
extern crate rustc_serialize;
extern crate sodiumoxide;
extern crate tempdir;
extern crate time;
#[cfg(test)]
extern crate rand;

// MaidSafe crates
extern crate lru_time_cache;
extern crate routing;

mod data_manager;
mod maid_manager;
mod pmid_manager;
mod sd_manager;
mod chunk_store;
mod pmid_node;
mod transfer_parser;
mod vault;
mod utils;
mod routing_types;
mod macros;

#[cfg(feature = "use-mock-routing")]
mod non_networking_test_framework;

/// Runs a SAFE Network vault
pub fn main () {
    match env_logger::init() {
        Ok(()) => {},
        Err(e) => println!("Error initialising logger; continuing without: {:?}", e)
    }

    ::vault::Vault::run();
}
