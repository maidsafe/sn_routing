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

//! Safe Vault provides the interface to SAFE routing.
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

// Non-MaidSafe crates
extern crate cbor;
extern crate rand;
extern crate rustc_serialize;
extern crate sodiumoxide;
extern crate tempdir;
extern crate time;

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

#[cfg(not(feature = "use-actual-routing"))]
mod non_networking_test_framework;
#[cfg(not(feature = "use-actual-routing"))]
type Routing = ::std::sync::Arc<::std::sync::Mutex<non_networking_test_framework::MockRouting>>;
#[cfg(not(feature = "use-actual-routing"))]
fn get_new_routing(event_sender: ::std::sync::mpsc::Sender<(::routing::event::Event)>) -> Routing {
    let mock_routing = non_networking_test_framework::MockRouting::new(event_sender);
    ::std::sync::Arc::new(::std::sync::Mutex::new(mock_routing))
}

#[cfg(feature = "use-actual-routing")]
type Routing = ::std::sync::Arc<::std::sync::Mutex<::routing::routing::Routing>>;
#[cfg(feature = "use-actual-routing")]
fn get_new_routing(event_sender: ::std::sync::mpsc::Sender<(::routing::event::Event)>) -> Routing {
    ::std::sync::Arc::new(::std::sync::Mutex::new(::routing::routing::Routing::new(event_sender)))
}



use vault::{VaultFacade, ResponseNotifier};
use routing_types::{MethodCall, POLL_DURATION_IN_MILLISEC};

/// The Vault structure to hold the logical interface to provide behavioural logic to routing.
pub struct Vault {
    routing: Routing,
    #[allow(dead_code)]
    vault_facade: ::std::sync::Arc<::std::sync::Mutex<VaultFacade>>,
    #[allow(dead_code)]
    join_handles: Vec<::std::thread::JoinHandle<()>>,
    response_notifier: ResponseNotifier,
    #[allow(dead_code)]
    routing_stop_flag: ::std::sync::Arc<::std::sync::Mutex<bool>>,
}


impl Vault {
    /// starts-up a vault with initialized routing and personas
    fn new() -> Vault {
        let notifier = ::std::sync::Arc::new((::std::sync::Mutex::new(Ok(vec![MethodCall::Terminate])),
                                              ::std::sync::Condvar::new()));
        let (sender, receiver) = ::std::sync::mpsc::channel();
        let routing = get_new_routing(sender);
        let (vault_facade, receiver_joiner) = VaultFacade::mutex_new(notifier.clone(), receiver);
        let cloned_routing = routing.clone();
        let routing_stop_flag = ::std::sync::Arc::new(::std::sync::Mutex::new(false));
        let routing_stop_flag_clone = routing_stop_flag.clone();

        let routing_joiner = ::std::thread::spawn(move || {
            let _ = cloned_routing.lock().unwrap().bootstrap();
            while !*routing_stop_flag_clone.lock().unwrap() {
                ::std::thread::sleep_ms(POLL_DURATION_IN_MILLISEC);
                cloned_routing.lock().unwrap().run();
            }
            cloned_routing.lock().unwrap().close();
        });

        Vault {
            routing : routing,
            vault_facade : vault_facade,
            join_handles : vec![routing_joiner, receiver_joiner],
            response_notifier : notifier,
            routing_stop_flag : routing_stop_flag,
        }
    }

    /// vault listening messages from routing
    pub fn run(&mut self) {
        let (ref lock, ref condition_var) = *self.response_notifier;
        let mut mutex_guard : _;
        let valid_condition = Ok(vec![MethodCall::ShutDown]);
        mutex_guard = lock.lock().unwrap();
        while *mutex_guard != valid_condition {
            mutex_guard = condition_var.wait(mutex_guard).unwrap();
            match mutex_guard.clone() {
                Ok(actions) => {
                    for i in 0..actions.len() {
                        match actions[i].clone() {
                            MethodCall::Get { name, data_request } => {
                                let _ = self.routing.lock().unwrap().get(name, data_request);
                            },
                            MethodCall::Put { destination, content } => {
                                let _ = self.routing.lock().unwrap().put(destination, content);
                             },
                            MethodCall::Reply { data } => {
                                let _ = self.routing.lock().unwrap().get_response(data);
                            },
                            _ => {}
                        }
                    }
                },
                Err(_) => {}
            }
        }
    }
}

/// Main entry for start up a vault node
pub fn main () {
    // routing changed to eliminate the difference of the first and later on nodes on network
    // the routing_node.run() replaces the previous run_zero_membrance() and bootstrap() function
    let mut vault = Vault::new();
    // a blocking call to vault's run method
    vault.run();
}

#[cfg(test)]
mod test {
    use super::*;
    use std::thread;
    use std::thread::spawn;
    use sodiumoxide::crypto;

    use routing_types::*;

    #[test]
    fn lib_test() {
        let run_vault = |mut vault: Vault| {
            let _ = spawn(move || {
                vault.run();
            });
        };
        let vault = Vault::new();
        let routing_mutex_clone = vault.routing.clone();
        let _ = run_vault(vault);
        let client_name = NameType(vector_as_u8_64_array(generate_random_vec_u8(64)));
        let sign_keys =  crypto::sign::gen_keypair();
        let value = generate_random_vec_u8(1024);
        let im_data = ImmutableData::new(ImmutableDataType::Normal, value);
        routing_mutex_clone.lock().unwrap().client_put(client_name, sign_keys.0,
                                                       Data::ImmutableData(im_data.clone()));
        assert_eq!(routing_mutex_clone.lock().unwrap().has_chunk(im_data.name()), false);
        thread::sleep_ms(5000);
        assert_eq!(routing_mutex_clone.lock().unwrap().has_chunk(im_data.name()), true);

        let receiver = routing_mutex_clone.lock().unwrap().client_get(im_data.name());
        for it in receiver.iter() {
            assert_eq!(it, Data::ImmutableData(im_data));
            break;
        }
    }

}
