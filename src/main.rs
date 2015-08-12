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
// relating to use of the SAFE Network Software.                                                              */

#![crate_name = "safe_vault"]
#![crate_type = "bin"]
#![doc(html_logo_url = "http://maidsafe.net/img/Resources/branding/maidsafe_logo.fab2.png",
       html_favicon_url = "http://maidsafe.net/img/favicon.ico",
              html_root_url = "http://dirvine.github.io/dirvine/safe_vault/")]
#![forbid(bad_style, warnings)]
#![deny(deprecated, improper_ctypes, missing_docs, non_shorthand_field_patterns,
        overflowing_literals, plugin_as_library, private_no_mangle_fns, private_no_mangle_statics,
        raw_pointer_derive, stable_features, unconditional_recursion, unknown_lints, unsafe_code,
        unsigned_negation, unused, unused_allocation, unused_attributes, unused_comparisons,
        unused_features, unused_parens, while_true)]

#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
        unused_qualifications)]

//! Safe Vault provides the interface to SAFE routing.
//!
//! The resulting executable is the Vault node for the SAFE network.
//! Refer to https://github.com/maidsafe/safe_vault
#![feature(convert, core)]
//! Refer to https://github.com/maidsafe/safe_vault
#![feature(core)]

#![allow(unused)]

extern crate core;
extern crate rustc_serialize;
extern crate cbor;
extern crate crust;
extern crate time;
extern crate lru_time_cache;

extern crate maidsafe_sodiumoxide as sodiumoxide;

extern crate rand;

use std::thread;
use std::thread::spawn;

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

mod non_networking_test_framework;

use vault::{VaultFacade, ResponseNotifier};
use routing_types::{MethodCall, POLL_DURATION_IN_MILLISEC, RoutingMessage};
use non_networking_test_framework::RoutingVaultMock;

type RoutingVault = ::std::sync::Arc<::std::sync::Mutex<RoutingVaultMock>>;
fn get_new_routing_vault() -> (RoutingVault, ::std::sync::mpsc::Receiver<RoutingMessage>) {
    let (routing_mock, receiver) = RoutingVaultMock::new();
    (::std::sync::Arc::new(::std::sync::Mutex::new(routing_mock)), receiver)
}

/// Placeholder doc test
pub fn always_true() -> bool { true }

/// The Vault structure to hold the logical interface to provide behavioural logic to routing.
pub struct Vault {
    routing            : RoutingVault,
    vault_facade       : ::std::sync::Arc<::std::sync::Mutex<VaultFacade>>,
    join_handles       : Vec<::std::thread::JoinHandle<()>>,    
    response_notifier  : ResponseNotifier,
    routing_stop_flag  : ::std::sync::Arc<::std::sync::Mutex<bool>>,
}


impl Vault {
    fn new() -> Vault {
        let notifier = ::std::sync::Arc::new((::std::sync::Mutex::new(Ok(vec![MethodCall::Terminate])),
                                              ::std::sync::Condvar::new()));
        let (routing_vault, receiver) = get_new_routing_vault();
        let (vault_facade, receiver_joiner) = VaultFacade::new(notifier.clone(), receiver);
        let cloned_routing_vault = routing_vault.clone();
        let routing_stop_flag = ::std::sync::Arc::new(::std::sync::Mutex::new(false));
        let routing_stop_flag_clone = routing_stop_flag.clone();

        let routing_joiner = ::std::thread::spawn(move || {
            let _ = cloned_routing_vault.lock().unwrap().bootstrap(None, None);
            while !*routing_stop_flag_clone.lock().unwrap() {
                ::std::thread::sleep_ms(POLL_DURATION_IN_MILLISEC);
                cloned_routing_vault.lock().unwrap().run();
            }
            cloned_routing_vault.lock().unwrap().close();
        });

        Vault {
            routing            : routing_vault,
            vault_facade       : vault_facade,
            join_handles       : vec![routing_joiner, receiver_joiner],
            response_notifier  : notifier,
            routing_stop_flag  : routing_stop_flag,
        }
    }
}

/// Main entry for start up a vault node
pub fn main () {
    // routing changed to eliminate the difference of the first and later on nodes on network
    // the routing_node.run() replaces the previous run_zero_membrance() and bootstrap() function
    let mut vault = Vault::new();
    // match vault.routing_node.run() {
    //     Err(err) => panic!("Could not connect to the network with error : {:?}", err),
    //     _ => {}
    // }
    let thread_guard = spawn(move || {
        loop {
            thread::sleep_ms(10000);
        }
    });
    let _ = thread_guard.join();
}

#[cfg(test)]
mod test {
    use super::*;
    use std::thread;
    use std::thread::spawn;

    #[test]
    fn lib_test() {
        let run_vault = |mut vault: Vault| {
            spawn(move || {
                match vault.routing_node.run() {
                    Err(err) => panic!("Could not connect to the network with error : {:?}", err),
                    _ => {}
                }
                let thread_guard = spawn(move || {
                    loop {
                        thread::sleep_ms(1);
                    }
                });
                let _ = thread_guard.join();
            })
        };
        // The performance of get RoutingTable fully populated among certain amount of nodes is machine dependent
        // The stable duration needs to be increased dramatically along with the increase of the total node numbers.
        // for example, you may need i * 1500 when increase total nodes from 8 to 9
        // The first node must be run in membrane mode
        for i in 0..8 {
            let _ = run_vault(Vault::new());
            thread::sleep_ms(1000 + i * 1000);
        }
        thread::sleep_ms(10000);
    }

}
