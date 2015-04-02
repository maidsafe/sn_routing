#![crate_name = "maidsafe_vault"]
#![crate_type = "lib"]
#![doc(html_logo_url = "http://maidsafe.net/img/Resources/branding/maidsafe_logo.fab2.png",
       html_favicon_url = "http://maidsafe.net/img/favicon.ico",
              html_root_url = "http://dirvine.github.io/dirvine/maidsafe_vault/")]
//! Placeholder

#![feature(convert)]
extern crate sodiumoxide;
extern crate rustc_serialize;
extern crate cbor;
extern crate time;
extern crate routing;
extern crate rand;

pub mod chunk_store;
pub mod pmid_manager;
pub mod pmid_node;
pub mod vault;

use vault::VaultFacade;

/// Placeholder doc test
pub fn always_true() -> bool { true }

pub struct Vault {
  my_facade : VaultFacade
}

impl Vault {
  pub fn new() -> Vault {
    Vault { my_facade: VaultFacade::new() }
  }

  pub fn start_vault(&self) {
    let my_routing = routing::RoutingNode::new(&self.my_facade);
    loop {
      always_true();
    }
  }
}

#[test]
fn it_works() {
 assert_eq!(always_true(), true);
}
