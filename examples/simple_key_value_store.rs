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

//! usage example (using default methods of connecting to the network):
//!      starting a passive node:       simple_key_value_store --node
//!      starting an interactive node:  simple_key_value_store

#![forbid(bad_style, warnings)]
#![deny(deprecated, drop_with_repr_extern, improper_ctypes, missing_docs,
        non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
        private_no_mangle_fns, private_no_mangle_statics, raw_pointer_derive, stable_features,
        unconditional_recursion, unknown_lints, unsafe_code, unsigned_negation, unused,
        unused_allocation, unused_attributes, unused_comparisons, unused_features, unused_parens,
        while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results, variant_size_differences)]
#![feature(convert, core)]

extern crate env_logger;

extern crate cbor;
extern crate core;
extern crate docopt;
extern crate rustc_serialize;
extern crate maidsafe_sodiumoxide as sodiumoxide;

extern crate crust;
extern crate routing;

use core::iter::FromIterator;
use std::io;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::thread::spawn;
use std::collections::BTreeMap;

use cbor::CborError;
use docopt::Docopt;
use rustc_serialize::{Decodable, Decoder};
use sodiumoxide::crypto;

use crust::Endpoint;
use routing::node_interface::{CreatePersonas, Interface, MethodCall};
use routing::routing_client::RoutingClient;
use routing::routing_node::RoutingNode;
use routing::sendable::Sendable;
use routing::types;
use routing::id::Id;
use routing::authority::Authority;
use routing::NameType;
use routing::error::{ResponseError, InterfaceError};
use routing::data::{Data, DataRequest};
use routing::plain_data::PlainData;
use routing::utils::{encode, decode, public_key_to_client_name};

// ==========================   Program Options   =================================
static USAGE: &'static str = "
Usage:
  simple_key_value_store [<peer>...]
  simple_key_value_store (--node [<peer>...])
  simple_key_value_store --help

Options:
  -n, --node   Run as a non-interactive routing node in the network.
  -h, --help   Display this help message.

  Running without the --node option will start an interactive node.
  Such a node can be used to send requests such as 'put' and
  'get' to the network.

  A passive node is one that simply reacts on received requests. Such nodes are
  the workers; they route messages and store and provide data.

  The optional <peer>... arg(s) are a list of peer endpoints (other running
  instances of this example).  If these are supplied, the node will try to
  connect to one of these in order to join the network.  If no endpoints are
  supplied, the node will try to connect to an existing network using Crust's
  discovery protocol.
";

#[derive(RustcDecodable, Debug)]
struct Args {
    arg_peer: Vec<PeerEndpoint>,
    flag_node: bool,
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

// We'll use docopt to help parse the ongoing CLI commands entered by the user.
static CLI_USAGE: &'static str = "
Usage:
  cli put <key> <value>
  cli get <key>
  cli stop
";

#[derive(RustcDecodable, Debug)]
struct CliArgs {
    cmd_put: bool,
    cmd_get: bool,
    cmd_stop: bool,
    arg_key: Option<String>,
    arg_value: String,
}

// ==========================   Implement traits   =================================

struct TestClient {
    pub key_reverse_lookup : BTreeMap<NameType, String>
}

impl TestClient {
    pub fn new() -> TestClient {
        TestClient {
            key_reverse_lookup: BTreeMap::new()
        }
    }
}

impl routing::client_interface::Interface for TestClient {
    fn handle_get_response(&mut self, data_location : NameType, data : Data) {
        println!("Testing client received get_response from {:?} with testdata {:?}",
                    data_location, data);
        match data {
            Data::PlainData(plain_data) => {
                match decode_key_value(plain_data.value()) {
                    Ok((key, value)) => {
                        println!("Client received {} under key {} from {}",
                            value, key, data_location);
                    },
                    Err(_) => {
                        println!("Client received get response from {} but failed to decode",
                            data_location);
                    }
                }
            },
            _ => {
                println!("Client received get response from {} but it is not PlainData.",
                    data_location);}
        }
    }

    fn handle_put_response(&mut self, response_error: ResponseError, _request_data: Data) {
        match response_error {
            ResponseError::NoData =>
                println!("Testing client received put_response with error NoData"),
            ResponseError::InvalidRequest =>
                println!("Testing client received put_response with error InvalidRequest"),
            ResponseError::FailedToStoreData(data) =>
                println!("Testing client received put_response with error FailedToStoreData for {}", data.name()),
        }
    }

    fn handle_post_response(&mut self, _response_error: ResponseError, _request_data: Data) {
         unimplemented!();
    }

    fn handle_delete_response(&mut self, _response_error: ResponseError, _request_data: Data) {
        unimplemented!();
    }
}

struct TestNode {
  db: BTreeMap<NameType, PlainData>
}

impl TestNode {
    pub fn new() -> TestNode {
        TestNode {
            db : BTreeMap::new()
        }
    }
}

impl Interface for TestNode {
    fn handle_get(&mut self,
                  data_request: DataRequest, our_authority: Authority,
                  _from_authority: Authority, _from_address: types::SourceAddress)
                   -> Result<Vec<MethodCall>, InterfaceError> {
        match data_request {
              DataRequest::PlainData => {
                  match our_authority {
                      Authority::NaeManager(group_name) => {
                          match self.db.get(&group_name) {
                              Some(plain_data) => {
                                  println!("node replied to get request for chunk {}",
                                      group_name);
                                  return Ok(vec![MethodCall::Reply {
                                      data : Data::PlainData(plain_data.clone()) }]);
                              },
                              None => {
                                  println!("node didn't have chunk {}",
                                      group_name);
                              }
                          }
                      },
                      _ => {}
                  };
              },
              _ => {}
        };
        Err(InterfaceError::Response(ResponseError::NoData))
    }

    fn handle_put(&mut self, our_authority: Authority, _from_authority: Authority,
                _from_address: types::SourceAddress, _dest_address: types::DestinationAddress,
                data: Data) -> Result<Vec<MethodCall>, InterfaceError> {
        match data {
            Data::PlainData(plain_data) => {
                match our_authority {
                    Authority::ClientManager(client_name) => {
                        println!("ClientManager of {:?} forwarding data to DataManager around {:?}",
                            client_name, plain_data.name());
                        return Ok(vec![MethodCall::Put {
                            destination: plain_data.name(),
                            content: Data::PlainData(plain_data) }]);
                    },
                    Authority::NaeManager(group_name) => {
                        assert_eq!(group_name, plain_data.name());
                        let _ = self.db.entry(plain_data.name())
                            .or_insert(plain_data);
                    },
                    _ => {}
                }
            },
            _ => {}
        };
        return Ok(vec![]);
    }

    fn handle_post(&mut self, _our_authority: Authority, _from_authority: Authority,
        _from_address: types::SourceAddress, _dest_address: types::DestinationAddress,
        _data: Data) -> Result<Vec<MethodCall>, InterfaceError> {
        Err(InterfaceError::Abort)
    }

    fn handle_refresh(&mut self, _type_tag: u64, _from_group: NameType, _payloads: Vec<Vec<u8>>) {
        unimplemented!()
    }

    fn handle_get_response(&mut self, from_address: NameType, response: Data) -> Vec<MethodCall> {
        println!("testing node received get_response from {} with data {:?}", from_address, response);
        vec![]
    }

    fn handle_put_response(&mut self, _from_authority : Authority, _from_address: types::SourceAddress,
                                      response: ResponseError) -> Vec<MethodCall> {
        println!("testing node received error put_response {}", response);
        vec![]
    }

    fn handle_post_response(&mut self, _from_authority: Authority,
        _from_address: types::SourceAddress, _response: ResponseError)
        -> Vec<MethodCall> {
        unimplemented!();
    }

    fn handle_churn(&mut self, close_group: Vec<NameType>) -> Vec<MethodCall> {
        for name in close_group {
          println!("RT: {:?}", name);
        }
        vec![]
    }

    fn handle_cache_get(&mut self, _data_request: DataRequest, _data_location: NameType,
                                   _from_address: NameType) -> Result<MethodCall, InterfaceError> {
        // FIXME(ben): 17/7/2015 implement a proper caching mechanism;
        // separate from the key-value store
        Err(InterfaceError::Abort)
    }

    fn handle_cache_put(&mut self, _from_authority: Authority, _from_address: NameType,
                        _data: Data) -> Result<MethodCall, InterfaceError> {
        // FIXME(ben): 17/7/2015 implement a proper caching mechanism;
        // separate from the key-value store
        Err(InterfaceError::Abort)
    }
}

struct TestNodeGenerator;

impl CreatePersonas<TestNode> for TestNodeGenerator {
    fn create_personas(&mut self) -> TestNode {
        TestNode::new()
    }
}

fn calculate_key_name(key: &String) -> NameType {
    NameType::new(crypto::hash::sha512::hash(key.as_bytes()).0)
}

#[allow(dead_code)]
fn encode_key_value(key : String, value : String) -> Result<Vec<u8>, CborError> {
    encode(&(key, value))
}

#[allow(dead_code)]
fn decode_key_value(data : &Vec<u8>) -> Result<(String, String), CborError> {
    decode(data)
}

fn run_passive_node(_bootstrap_peers: Option<Vec<Endpoint>>) {
    let mut test_node = RoutingNode::<TestNode, TestNodeGenerator>::new(TestNodeGenerator);
    let _ = test_node.run();
    let ref mut command = String::new();
    loop {
        command.clear();
        println!("Enter command (stop)>");
        let _ = io::stdin().read_line(command);
        let x: &[_] = &['\r', '\n'];
        match command.trim_right_matches(x) {
            "stop" => break,
            _ => println!("Invalid command.")
        }
    }
}

fn run_interactive_node(_bootstrap_peers: Option<Vec<Endpoint>>) {
    let our_id = Id::new();
    let our_client_name : NameType = public_key_to_client_name(&our_id.signing_public_key());
    let test_client = RoutingClient::new(Arc::new(Mutex::new(TestClient::new())), our_id);
    let mutate_client = Arc::new(Mutex::new(test_client));
    let copied_client = mutate_client.clone();
    let _ = spawn(move || {
        let _ = copied_client.lock().unwrap().bootstrap();
        thread::sleep_ms(100);
        loop {
            thread::sleep_ms(10);
            copied_client.lock().unwrap().poll_one();
        }
    });
    let ref mut command = String::new();
    let docopt: Docopt = Docopt::new(CLI_USAGE).unwrap_or_else(|error| error.exit());
    let mut stdin = io::stdin();
    loop {
        command.clear();
        println!("Enter command (stop | put <key> <value> | get <key>)>");
        let _ = stdin.read_line(command);
        let x: &[_] = &['\r', '\n'];
        let mut raw_args: Vec<&str> = command.trim_right_matches(x).split(' ').collect();
        raw_args.insert(0, "cli");
        let args: CliArgs = match docopt.clone().argv(raw_args.into_iter()).decode() {
            Ok(args) => args,
            Err(error) => {
                match error {
                    docopt::Error::Decode(what) => println!("{}", what),
                    _ => println!("Invalid command."),
                };
                continue
            },
        };

        if args.cmd_put {
            // docopt should ensure arg_key and arg_value are valid
            assert!(args.arg_key.is_some() && !args.arg_value.is_empty());
            match args.arg_key {
                Some(key) => {
                    let key_name : NameType = calculate_key_name(&key);
                    println!("Putting value \"{}\" to network under key \"{}\" at location {}.",
                        args.arg_value, key, key_name);
                    match encode_key_value(key, args.arg_value) {
                        Ok(serialised_key_value) => {
                            let data = PlainData::new(key_name, serialised_key_value);
                            let _ = mutate_client.lock().unwrap()
                                .put(our_client_name, Data::PlainData(data));
                        },
                        Err(_) => { println!("Failed to encode key and value."); }
                    }
                },
                None => ()
            }
        } else if args.cmd_get {
            // docopt should ensure arg_key is valid
            assert!(args.arg_key.is_some());
            match args.arg_key {
                Some(key) => {
                    let key_name : NameType = calculate_key_name(&key);
                    println!("Getting value for key \"{}\" from network at location {}.",
                        key, key_name);
                    let _ = mutate_client.lock().unwrap().get(key_name, DataRequest::PlainData);
                },
                None => ()
            }
        } else if args.cmd_stop {
            break;
        }
    }
}

fn main() {
    match env_logger::init() {
        Ok(()) => {},
        Err(e) => println!("Error initialising logger; continuing without: {:?}", e)
    }

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

    if args.flag_node {
        run_passive_node(bootstrap_peers);
    } else {
        run_interactive_node(bootstrap_peers);
    }
}
