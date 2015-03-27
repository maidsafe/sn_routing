#![crate_name = "maidsafe_vault"]
#![crate_type = "lib"]
#![doc(html_logo_url = "http://maidsafe.net/img/Resources/branding/maidsafe_logo.fab2.png",
       html_favicon_url = "http://maidsafe.net/img/favicon.ico",
              html_root_url = "http://dirvine.github.io/dirvine/maidsafe_vault/")]
//! Placeholder

#![feature(convert)]
extern crate self_encryption;
extern crate sodiumoxide;
extern crate lru_cache;
extern crate rustc_serialize;
extern crate cbor;
extern crate time;
extern crate bchannel;

use std::net::{TcpStream};
use sodiumoxide::crypto;
use std::sync::mpsc;
use std::sync::mpsc::{Sender, Receiver};
use std::default::Default;

pub mod chunk_store;
pub mod pmid_manager;
pub mod pmid_node;
pub mod vault;

#[path="data_manager/data_manager.rs"]
mod data_manager;

/// Placeholder doc test
pub fn always_true() -> bool { true }

#[test]
fn it_works() {
 assert_eq!(always_true(), true);
}
