// Copyright 2015 MaidSafe.net limited
// This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
// By contributing code to the MaidSafe Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
// directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
// available at: http://www.maidsafe.net/licenses
// Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
// OF ANY KIND, either express or implied.
// See the Licences for the specific language governing permissions and limitations relating to
// use of the MaidSafe
// Software.

#![crate_name = "maidsafe_vault"]
#![crate_type = "lib"]
#![doc(html_logo_url = "http://maidsafe.net/img/Resources/branding/maidsafe_logo.fab2.png",
       html_favicon_url = "http://maidsafe.net/img/favicon.ico",
       html_root_url = "http://dirvine.github.io/dirvine/maidsafe_vault/")]
//! MaidSafe Vault is the application for a vault on the SAFE network.
//!
//! MaidSafe Vault provides the interface for
//! the behavioural logic of the SAFE network. The Vault crate currently provides following
//! managers for the group authorities determined by SAFE routing: (maid_manager
//! The MAID manager (MaidSafe Anonymous ID) allows the client to create an account
//! and put data to the network.

extern crate sodiumoxide;
extern crate rustc_serialize;
extern crate cbor;
extern crate time;
extern crate routing;
extern crate maidsafe_types;
extern crate rand;
extern crate lru_time_cache;

mod data_manager;
mod maid_manager;
mod pmid_manager;
mod version_handler;
mod chunk_store;
mod pmid_node;
///
pub mod vault;

use vault::VaultFacade;
// use routing::types::DhtId;
// use routing::routing_node::RoutingNode;

/// Placeholder doc test
pub fn always_true() -> bool { true }

/// Main Vault structure to start RoutingNode and link logical interface
pub struct Vault {
  my_facade : VaultFacade
}

impl Vault {

  /// Initialise a new Vault
  pub fn new() -> Vault {
    Vault { my_facade: VaultFacade::new() }
  }

  /// Start the RoutingNode and the Vault event loop
  pub fn start_vault(&self) {
    // let my_routing = RoutingNode::new(DhtId::generate_random(), &self.my_facade);
    loop {
      always_true();
    }
  }
}

fn main () {
    
let vault = Vault::new();
vault.start_vault();
    
}



#[test]
fn it_works() {
 assert_eq!(always_true(), true);
}
