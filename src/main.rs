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
#![forbid(bad_style, warnings)]
#![deny(missing_docs)]
//! MaidSafe Vault provides the interface to SAFE routing.
//!
//! The resulting executable is the Vault node for the SAFE network.
//! Refer to https://github.com/dirvine/maidsafe_vault
#![feature(convert, core, std_misc)]

extern crate core;
extern crate crust;
extern crate docopt;
extern crate sodiumoxide;
extern crate rustc_serialize;
extern crate cbor;
extern crate time;
extern crate lru_time_cache;
extern crate routing;
extern crate maidsafe_types;
extern crate rand;

use core::iter::FromIterator;
use std::net::SocketAddr;
use std::str::FromStr;
use std::thread;
use std::thread::spawn;

use docopt::Docopt;
use rustc_serialize::{Decodable, Decoder};

mod data_manager;
mod maid_manager;
mod pmid_manager;
mod version_handler;
mod chunk_store;
mod pmid_node;
mod vault;
mod utils;

use crust::Endpoint;
use vault::{ VaultFacade, VaultGenerator };

/// Placeholder doc test
pub fn always_true() -> bool { true }

/// The Vault structure to hold the logical interface to provide behavioural logic to routing.
pub struct Vault {
  routing_node: routing::routing_node::RoutingNode<VaultFacade, VaultGenerator>,
}

impl Vault {
  fn new() -> Vault {
    Vault {
      routing_node: routing::routing_node::RoutingNode::<VaultFacade, VaultGenerator>::new(VaultGenerator),
    }
  }
}

// ==========================   Program Options   =================================
static USAGE: &'static str = "
Usage:
  maidsafe_vault (--first | --node [<peer>...])
  maidsafe_vault --help

Options:
  -f, --first  Node runs as the first vault in the network.
  -n, --node   Node runs as a non-first vault in the network.
  -h, --help   Display this help message.

  Running without '--first' requires an existing network to connect to.  If this
  is the first vault of a new network, the only arg passed should be '--first'.

  The optional <peer>... arg(s) are a list of peer endpoints (other running vaults).
  If these are supplied, the node will try to connect to one of these in order to
  join the network.  If no endpoints are supplied, the node will try to connect to
  an existing network using Crust's discovery protocol.
";

#[derive(RustcDecodable, Debug)]
struct Args {
    arg_peer: Vec<PeerEndpoint>,
    flag_node: bool,
    flag_first: bool,
    flag_help: bool,
}

#[derive(Debug)]
enum PeerEndpoint {
    Tcp(SocketAddr),
}

impl Decodable for PeerEndpoint {
    fn decode<D: Decoder>(decoder: &mut D)->Result<PeerEndpoint, D::Error> {
        let str = try!(decoder.read_str());
        let address = match SocketAddr::from_str(&str) {
            Ok(addr) => addr,
            Err(_) => {
                return Err(decoder.error(format!(
                    "Could not decode {} as valid IPv4 or IPv6 address.", str).as_str()));
            },
        };
        Ok(PeerEndpoint::Tcp(address))
    }
}

/// Main entry for start up a vault node
pub fn main () {
    let args: Args = Docopt::new(USAGE)
                            .and_then(|docopt| docopt.decode())
                            .unwrap_or_else(|error| error.exit());
    // Convert peer endpoints to usable bootstrap list.
    let bootstrap_peers = if args.arg_peer.is_empty() {
        None
    } else {
        Some(Vec::<Endpoint>::from_iter(args.arg_peer.iter().map(|endpoint| {
            Endpoint::Tcp(match *endpoint { PeerEndpoint::Tcp(address) => address, })
        })))
    };

    let mut vault = Vault::new();
    if args.flag_first {
        vault.routing_node.run_zero_membrane();
    } else {
        let _ = vault.routing_node.bootstrap(bootstrap_peers, None);
    }

    let thread_guard = spawn(move || {
        loop {
            thread::sleep_ms(1);
        }
    });
    let _ = thread_guard.join();
}

#[cfg(test)]
mod test {
    use super::*;
    use std::io::BufRead;
    use std::thread;
    use std::thread::spawn;
    use std::process::Stdio;
    use std::process::Command;
    use std::error::Error;
    use std::io::Read;

    #[test]
    fn lib_test() {
        let run_vault = |mut vault: Vault| {
            spawn(move || {
                let _ = vault.routing_node.bootstrap(None, None);
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
        let _ = spawn(move || {
                let mut vault = Vault::new();
                let _ = vault.routing_node.run_zero_membrane();
                let thread_guard = spawn(move || {
                    loop {
                        thread::sleep_ms(1);
                    }
                });
                let _ = thread_guard.join();
            });
        thread::sleep_ms(1000);
        for i in 1..8 {
            let _ = run_vault(Vault::new());
            thread::sleep_ms(1000 + i * 1000);
        }
        thread::sleep_ms(10000);
    }

    #[test]
    // This test requires the executable maidsafe_vault is presented at the same place of the test get executed
    // also it depends a printout in routing lib. if such printout is changed / muted, this test needs to be updated
    fn executable_test() {
        let mut processes = Vec::new();
        let num_of_nodes = 8;
        // the first vault must be run in zero_membrane mode
        println!("---------- starting node 0 --------------");
        processes.push(match Command::new("./target/debug/maidsafe_vault").arg("-f").stdout(Stdio::piped()).spawn() {
                    Err(why) => panic!("couldn't spawn maidsafe_vault: {}", why.description()),
                    Ok(process) => process,
                });
        thread::sleep_ms(1000);

        for i in 1..num_of_nodes {
            println!("---------- starting node {} --------------", i);
            processes.push(match Command::new("./target/debug/maidsafe_vault").arg("-n").stdout(Stdio::piped()).spawn() {
                        Err(why) => panic!("couldn't spawn maidsafe_vault: {}", why.description()),
                        Ok(process) => process,
                    });
            thread::sleep_ms(1000 + i * 1000);
        }
        thread::sleep_ms(10000);
        while let Some(mut process) = processes.pop() {
            let _ = process.kill();
            let result : Vec<u8> = process.stdout.unwrap().bytes().map(|x| x.unwrap()).collect();
            let s = String::from_utf8(result).unwrap();
            let v: Vec<&str> = s.split("added connected node").collect();
            let marked_connections = v.len() - 1;
            println!("\t  maidsafe_vault {} has {} connected connections.", processes.len(), marked_connections);
            assert_eq!(num_of_nodes as usize, marked_connections + 1);
        }
    }
}
