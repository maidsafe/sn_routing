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

//! SAFE Vault provides the interface to SAFE routing.  The resulting executable is the Vault node
//! for the SAFE network.

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
#![cfg_attr(feature="clippy", allow(use_debug))]

#[macro_use]
extern crate log;
#[macro_use]
extern crate maidsafe_utilities;
extern crate config_file_handler;
extern crate docopt;
extern crate rustc_serialize;
extern crate safe_vault;

use std::ffi::OsString;
use std::fs;
use docopt::Docopt;
use safe_vault::Vault;

#[cfg_attr(rustfmt, rustfmt_skip)]
static USAGE: &'static str = "
Usage:
  safe_vault [options]

Options:
  -f, --first     Run as the first Vault of a new network.
  -V, --version   Display version info and exit.
  -h, --help      Display this help message and exit.
";

#[derive(PartialEq, Eq, Debug, Clone, RustcDecodable)]
struct Args {
    flag_first: bool,
    flag_version: bool,
    flag_help: bool,
}

/// Runs a SAFE Network vault.
#[cfg_attr(feature="clippy", allow(print_stdout))]
pub fn main() {
    // TODO - remove the following line once maidsafe_utilities is updated to use log4rs v4.
    let _ = fs::remove_file("Node.log");

    let args: Args = Docopt::new(USAGE)
        .and_then(|docopt| docopt.decode())
        .unwrap_or_else(|error| error.exit());

    let name = config_file_handler::exe_file_stem().unwrap_or_else(|_| OsString::new());
    let name_and_version = format!("{} v{}", name.to_string_lossy(), env!("CARGO_PKG_VERSION"));
    if args.flag_version {
        println!("{}", name_and_version);
        return;
    }

    let _ = maidsafe_utilities::log::init(false);

    let mut message = String::from("Running ");
    message.push_str(&name_and_version);
    let underline = unwrap_result!(String::from_utf8(vec!['=' as u8; message.len()]));
    info!("\n\n{}\n{}", message, underline);

    loop {
        let mut vault = match Vault::new(args.flag_first, true) {
            Ok(vault) => vault,
            Err(e) => {
                println!("Cannot start vault due to error : {:?}", e);
                return;
            }
        };
        if let Ok(true) = vault.run() {
            break;
        }
    }
}
