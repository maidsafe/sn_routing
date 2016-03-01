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

extern crate docopt;
extern crate env_logger;
#[macro_use]
extern crate log;
#[macro_use]
extern crate maidsafe_utilities;
extern crate mpid_messaging;
extern crate chunk_store;
extern crate config_file_handler;
extern crate ctrlc;
#[cfg(all(test, feature = "use-mock-routing"))]
extern crate kademlia_routing_table;
extern crate lru_time_cache;
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

use docopt::Docopt;
use log::LogRecord;
use std::fs::OpenOptions;
use std::env;
use std::io::Write;

// ==========================   Program Options   =================================
#[cfg_attr(rustfmt, rustfmt_skip)]
static USAGE: &'static str = "
Usage:
  safe_vault (--node=<log_file>)
Options:
  --node=<log_file>      Logging to the file.
";
// ================================================================================

#[derive(PartialEq, Eq, Debug, Clone, RustcDecodable)]
struct Args {
    flag_node: Option<String>,
}

fn init(file_name: String) {
    let mut log_path = unwrap_result!(env::current_exe());
    log_path.set_file_name(file_name.clone());

    let format = move |record: &LogRecord| {
        let log_message = format!("[{}:{}] {}\n",
                                  record.location().file(),
                                  record.location().line(),
                                  record.args());
        let mut logfile = unwrap_result!(OpenOptions::new()
                                             .write(true)
                                             .create(true)
                                             .append(true)
                                             .open(log_path.clone()));
        unwrap_result!(logfile.write_all(&log_message.clone().into_bytes()[..]));
        log_message
    };

    let mut builder = ::env_logger::LogBuilder::new();
    let _ = builder.format(format);

    if let Ok(rust_log) = ::std::env::var("RUST_LOG") {
        let _ = builder.parse(&rust_log);
    }

    builder.init().unwrap_or_else(|error| println!("Error initialising logger: {}", error));
}

/// Runs a SAFE Network vault.
pub fn main() {
    utils::handle_version();
    let args: Args = Docopt::new(USAGE)
                         .and_then(|docopt| docopt.decode())
                         .unwrap_or_else(|e| e.exit());
    if let Some(log_file) = args.flag_node {
        init(log_file);
    } else {
        maidsafe_utilities::log::init(false);
    }

    vault::Vault::run();
}
