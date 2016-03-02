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

#![doc(html_logo_url =
           "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
       html_favicon_url = "http://maidsafe.net/img/favicon.ico",
       html_root_url = "http://maidsafe.github.io/safe_vault")]

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

#[macro_use]
extern crate log;
#[macro_use]
extern crate maidsafe_utilities;
extern crate chunk_store;
extern crate config_file_handler;
extern crate ctrlc;
extern crate docopt;
#[cfg(all(test, feature = "use-mock-routing"))]
extern crate kademlia_routing_table;
extern crate lru_time_cache;
extern crate mpid_messaging;
#[cfg(all(test, feature = "use-mock-routing"))]
extern crate rand;
extern crate routing;
extern crate rustc_serialize;
extern crate sodiumoxide;
extern crate time;
extern crate xor_name;

mod default_chunk_store;
mod error;
mod mock_routing;
mod personas;
mod types;
mod utils;
mod vault;

use std::ffi::OsString;
use std::process;
use docopt::Docopt;

#[cfg_attr(rustfmt, rustfmt_skip)]
static USAGE: &'static str = "
Usage:
  safe_vault [options]

Options:
  -o <file>, --output=<file>    Direct log output to stderr _and_ <file>.  If
                                <file> does not exist it will be created,
                                otherwise it will be truncated.
  -V, --version                 Display version info and exit.
  -h, --help                    Display this help message and exit.
";

#[derive(PartialEq, Eq, Debug, Clone, RustcDecodable)]
struct Args {
    flag_output: Option<String>,
    flag_version: bool,
    flag_help: bool,
}

/// Runs a SAFE Network vault.
pub fn main() {
    let args: Args = Docopt::new(USAGE)
                         .and_then(|docopt| docopt.decode())
                         .unwrap_or_else(|error| error.exit());

    let name = config_file_handler::exe_file_stem().unwrap_or(OsString::new());
    let name_and_version = format!("{} v{}", name.to_string_lossy(), env!("CARGO_PKG_VERSION"));
    if args.flag_version {
        println!("{}", name_and_version);
        process::exit(0);
    }

    if let Some(log_file) = args.flag_output {
        unwrap_result!(maidsafe_utilities::log::init_to_file(false, log_file));
    } else {
        maidsafe_utilities::log::init(false);
    }

    let message = String::from("Running ") + &name_and_version;
    let underline = String::from_utf8(vec!['=' as u8; message.len()]).unwrap();
    info!("\n\n{}\n{}", message, underline);

    vault::Vault::run();
}
