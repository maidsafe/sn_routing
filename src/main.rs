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

#![crate_name = "maidsafe_vault"]
#![crate_type = "bin"]
#![doc(html_logo_url = "http://maidsafe.net/img/Resources/branding/maidsafe_logo.fab2.png",
       html_favicon_url = "http://maidsafe.net/img/favicon.ico",
              html_root_url = "http://dirvine.github.io/dirvine/maidsafe_vault/")]

#![deny(missing_docs)]
//! MaidSafe Vault provides the interface to SAFE routing.
//!
//! The resulting executable is the Vault node for the SAFE network.
//! Refer to https://github.com/dirvine/maidsafe_vault
#![feature(std_misc)]

extern crate sodiumoxide;
extern crate rustc_serialize;
extern crate cbor;
extern crate time;
extern crate routing;
extern crate maidsafe_types;
extern crate rand;

mod data_manager;
mod maid_manager;
mod pmid_manager;
mod version_handler;
mod chunk_store;
mod pmid_node;
mod vault;
mod utils;

use vault::VaultFacade;

/// Placeholder doc test
pub fn always_true() -> bool { true }

/// The Vault structure to hold the logical interface to provide behavioural logic to routing.
pub struct Vault {
  routing_node: routing::routing_node::RoutingNode<VaultFacade>,
}

impl Vault {
  fn new() -> Vault {
    Vault {
      routing_node: routing::routing_node::RoutingNode::new(VaultFacade::new()),
    }
  }
}

fn main () {
  let mut vault = Vault::new();
  vault.routing_node.run();
}

#[test]
fn it_works() {
  assert_eq!(always_true(), true);
}
