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

#![doc(html_logo_url = "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
       html_favicon_url = "http://maidsafe.net/img/favicon.ico",
       html_root_url = "http://maidsafe.github.io/safe_vault")]

#![forbid(
    bad_style,              // Includes:
                            // - non_camel_case_types:   types, variants, traits and type parameters
                            //                           should have camel case names,
                            // - non_snake_case:         methods, functions, lifetime parameters and
                            //                           modules should have snake case names
                            // - non_upper_case_globals: static constants should have uppercase
                            //                           identifiers
    exceeding_bitshifts,    // shift exceeds the type's number of bits
    mutable_transmutes,     // mutating transmuted &mut T from &T may cause undefined behavior
    no_mangle_const_items,  // const items will not have their symbols exported
    unknown_crate_types,    // unknown crate type found in #[crate_type] directive
    warnings                // mass-change the level for lints which produce warnings
    )]

#![deny(
    deprecated,                    // detects use of #[deprecated] items
    drop_with_repr_extern,         // use of #[repr(C)] on a type that implements Drop
    improper_ctypes,               // proper use of libc types in foreign modules
    missing_docs,                  // detects missing documentation for public members
    non_shorthand_field_patterns,  // using `Struct { x: x }` instead of `Struct { x }`
    overflowing_literals,          // literal out of range for its type
    plugin_as_library,             // compiler plugin used as ordinary library in non-plugin crate
    private_no_mangle_fns,         // functions marked #[no_mangle] should be exported
    private_no_mangle_statics,     // statics marked #[no_mangle] should be exported
    raw_pointer_derive,            // uses of #[derive] with raw pointers are rarely correct
    stable_features,               // stable features found in #[feature] directive
    unconditional_recursion,       // functions that cannot return without calling themselves
    unknown_lints,                 // unrecognized lint attribute
    unsafe_code,                   // usage of `unsafe` code
    unused,                        // Includes:
                                   // - unused_imports:     imports that are never used
                                   // - unused_variables:   detect variables which are not used in
                                   //                       any way
                                   // - unused_assignments: detect assignments that will never be
                                   //                       read
                                   // - dead_code:          detect unused, unexported items
                                   // - unused_mut:         detect mut variables which don't need to
                                   //                       be mutable
                                   // - unreachable_code:   detects unreachable code paths
                                   // - unused_must_use:    unused result of a type flagged as
                                   //                       #[must_use]
                                   // - unused_unsafe:      unnecessary use of an `unsafe` block
                                   // - path_statements: path statements with no effect
    unused_allocation,             // detects unnecessary allocations that can be eliminated
    unused_attributes,             // detects attributes that were not used by the compiler
    unused_comparisons,            // comparisons made useless by limits of the types involved
    unused_features,               // unused or unknown features found in crate-level #[feature]
                                   // directives
    unused_parens,                 // `if`, `match`, `while` and `return` do not need parentheses
    while_true                     // suggest using `loop { }` instead of `while true { }`
    )]

#![warn(
    trivial_casts,            // detects trivial casts which could be removed
    trivial_numeric_casts,    // detects trivial casts of numeric types which could be removed
    unused_extern_crates,     // extern crates that are never used
    unused_import_braces,     // unnecessary braces around an imported item
    unused_qualifications,    // detects unnecessarily qualified names
    unused_results,           // unused result of an expression in a statement
    variant_size_differences  // detects enums with widely varying variant sizes
    )]

#![allow(
    box_pointers,                  // use of owned (Box type) heap memory
    fat_ptr_transmutes,            // detects transmutes of fat pointers
    missing_copy_implementations,  // detects potentially-forgotten implementations of `Copy`
    missing_debug_implementations  // detects missing implementations of fmt::Debug
    )]

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

mod chunk_store;
mod data_manager;
mod macros;
mod maid_manager;
mod pmid_manager;
mod pmid_node;
mod sd_manager;
mod transfer_parser;
mod types;
mod utils;
mod vault;

#[cfg(feature = "use-mock-routing")]
mod non_networking_test_framework;

/// Runs a SAFE Network vault
pub fn main() {
    match env_logger::init() {
        Ok(()) => {}
        Err(e) => println!("Error initialising logger; continuing without: {:?}", e),
    }
    ::vault::Vault::run();
}
