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

//#![forbid(bad_style, warnings)]
//#![deny(deprecated, drop_with_repr_extern, improper_ctypes, missing_docs,
//        non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
//        private_no_mangle_fns, private_no_mangle_statics, raw_pointer_derive, stable_features,
//        unconditional_recursion, unknown_lints, unsafe_code, unused,
//        unused_allocation, unused_attributes, unused_comparisons, unused_features, unused_parens,
//        while_true)]
//#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
//        unused_qualifications, unused_results, variant_size_differences)]
//#![feature(convert, core)]

#[macro_use]
extern crate log;
extern crate env_logger;

extern crate cbor;
extern crate docopt;
extern crate rustc_serialize;
extern crate sodiumoxide;

extern crate crust;
extern crate routing;

use std::io;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::thread;
use std::thread::spawn;
use std::collections::BTreeMap;
use std::io::Write;

use docopt::Docopt;
use rustc_serialize::{Decodable, Decoder};
use sodiumoxide::crypto;

use crust::Endpoint;
use routing::routing::Routing;
use routing::authority::Authority;
use routing::NameType;
use routing::error::RoutingError;
use routing::event::Event;
use routing::data::{Data, DataRequest};
use routing::plain_data::PlainData;
use routing::utils::{encode, public_key_to_client_name};
use routing::{ExternalRequest, SignedToken};

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

impl PeerEndpoint {
    fn to_crust_endpoint(self) -> Endpoint {
        Endpoint::Tcp(match self { PeerEndpoint::Tcp(address) => address })
    }
}

impl Decodable for PeerEndpoint {
    fn decode<D: Decoder>(decoder: &mut D)->Result<PeerEndpoint, D::Error> {
        let str = try!(decoder.read_str());
        let address = match SocketAddr::from_str(&str) {
            Ok(addr) => addr,
            Err(_) => {
                return Err(decoder.error(&format!(
                    "Could not decode {} as valid IPv4 or IPv6 address.", str)[..]));
            },
        };
        Ok(PeerEndpoint::Tcp(address))
    }
}

////////////////////////////////////////////////////////////////////////////////
struct Node {
    routing  : Routing,
    receiver : Receiver<Event>,
    db       : BTreeMap<NameType, PlainData>,
}

impl Node {
    fn new(_bootstrap_peers: Vec<Endpoint>) -> Result<Node, RoutingError> {
        let (sender, receiver) = mpsc::channel::<Event>();
        let routing = try!(Routing::new(sender));

        Ok(Node {
            routing  : routing,
            receiver : receiver,
            db       : BTreeMap::new(),
        })
    }

    fn run(&mut self) {
        loop {
            let event = match self.receiver.recv() {
                Ok(event) => event,
                Err(_)  => {
                    println!("Node: Routing closed the event channel");
                    return;
                }
            };

            println!("Node: Receied event {:?}", event);

            match event {
                Event::Request{request,
                               our_authority,
                               from_authority,
                               response_token} => {
                    self.handle_request(request,
                                        our_authority,
                                        from_authority,
                                        response_token);
                },
                _ => {}
            }
        }
    }

    fn handle_request(&mut self, request        : ExternalRequest,
                                 our_authority  : Authority,
                                 from_authority : Authority,
                                 response_token : SignedToken) {
        match request {
            ExternalRequest::Get(data_request) => {
                self.handle_get_request(data_request,
                                        our_authority,
                                        from_authority,
                                        response_token);
            },
            ExternalRequest::Put(data) => {
                self.handle_put_request(data,
                                        our_authority,
                                        from_authority,
                                        response_token);
            },
            ExternalRequest::Post(_) => {
                println!("Node: Post is not implemented, ignoring.");
            },
            ExternalRequest::Delete(_) => {
                println!("Node: Delete is not implemented, ignoring.");
            },
        }
    }

    fn handle_get_request(&mut self, data_request   : DataRequest,
                                     _our_authority  : Authority,
                                     from_authority : Authority,
                                     response_token : SignedToken) {
        let name = match data_request {
            DataRequest::PlainData(name) => name,
            _ => { println!("Node: Only serving plain data in this example"); return; }
        };

        let data = match self.db.get(&name) {
            Some(data) => data.clone(),
            None => return,
        };

        self.routing.get_response(from_authority, Data::PlainData(data), response_token);
    }

    fn handle_put_request(&mut self, data           : Data,
                                     our_authority  : Authority,
                                     _from_authority : Authority,
                                     _response_token : SignedToken) {
        let plain_data = match data {
            Data::PlainData(plain_data) => plain_data,
            _ => { println!("Node: Only storing plain data in this example"); return; }
        };

        match our_authority {
            Authority::ClientManager(_) => {
                self.routing.put_request(Authority::NaeManager(plain_data.name()),
                                         Data::PlainData(plain_data));
            },
            Authority::NaeManager(_) => {
                self.db.insert(plain_data.name(), plain_data);
            },
            _ => {
                println!("Node: Unexpected our_authority ({:?})", our_authority);
                assert!(false);
            }
        }

    }
}

////////////////////////////////////////////////////////////////////////////////
#[derive(PartialEq, Eq, Debug, Clone)]
enum UserCommand {
    Exit,
    Get(String),
    Put(String, String),
}

fn parse_user_command(cmd : String) -> Option<UserCommand> {
    let cmds = cmd.trim_right_matches(|c| c == '\r' || c == '\n')
                  .split(' ')
                  .collect::<Vec<_>>();

    if cmds.is_empty() {
        return None;
    }
    else if cmds.len() == 1 && cmds[0] == "exit" {
        return Some(UserCommand::Exit);
    }
    else if cmds.len() == 2 && cmds[0] == "get" {
        return Some(UserCommand::Get(cmds[1].to_string()));
    }
    else if cmds.len() == 3 && cmds[0] == "put" {
        return Some(UserCommand::Put(cmds[1].to_string(), cmds[2].to_string()));
    }

    None
}

////////////////////////////////////////////////////////////////////////////////
struct Client {
    routing          : Routing,
    event_receiver   : Receiver<Event>,
    command_receiver : Receiver<UserCommand>,
    is_done          : bool,
}

impl Client {
    fn new(_bootstrap_peers: Vec<Endpoint>) -> Result<Client, RoutingError> {
        let (event_sender, event_receiver) = mpsc::channel::<Event>();
        let routing = try!(Routing::new_client(event_sender));

        let (command_sender, command_receiver) = mpsc::channel::<UserCommand>();

        thread::spawn(move || { Client::read_user_commands(command_sender); });

        Ok(Client {
            routing          : routing,
            event_receiver   : event_receiver,
            command_receiver : command_receiver,
            is_done          : false,
        })
    }

    fn run(&mut self) {
        // Need to do poll as Select is not yet stable in the current
        // rust implementation.
        loop {
            while let Ok(command) = self.command_receiver.try_recv() {
                self.handle_user_command(command);
            }

            if self.is_done { break; }

            while let Ok(event) = self.event_receiver.try_recv() {
                self.handle_routing_event(event);
            }

            if self.is_done { break; }

            thread::sleep_ms(10);
        }

        println!("Bye");
    }

    fn read_user_commands(command_sender: Sender<UserCommand>) {
        loop {
            let mut command = String::new();
            let mut stdin = io::stdin();

            print!("Enter command (exit | put <key> <value> | get <key>)\n> ");
            let _ = io::stdout().flush();

            let _ = stdin.read_line(&mut command);

            match parse_user_command(command) {
                Some(cmd) => {
                    let _ = command_sender.send(cmd.clone());
                    if cmd == UserCommand::Exit {
                        break;
                    }
                },
                None => {
                    println!("Unrecognised command");
                    continue;
                }
            }
        }
    }

    fn handle_user_command(&mut self, cmd : UserCommand) {
        match cmd {
            UserCommand::Exit => {
                self.is_done = true;
            }
            UserCommand::Get(what) => {
                self.send_get_request(what);
            }
            UserCommand::Put(put_where, put_what) => {
                self.send_put_request(put_where, put_what);
            }
        }
    }

    fn handle_routing_event(&mut self, event : Event) {
        println!("Client received routing event: {:?}", event);
    }

    fn send_get_request(&self, what: String) {
        let name = Client::calculate_key_name(&what);

        self.routing.get_request(Authority::NaeManager(name.clone()),
                                 DataRequest::PlainData(name));
    }

    fn send_put_request(&self, put_where: String, put_what: String) {
        let mngr = public_key_to_client_name(&self.routing.signing_public_key());
        let name = Client::calculate_key_name(&put_where);
        let data = encode(&put_what).unwrap();

        self.routing.put_request(Authority::ClientManager(mngr),
                                 Data::PlainData(PlainData::new(name, data)));
    }

    fn calculate_key_name(key: &String) -> NameType {
        NameType::new(crypto::hash::sha512::hash(key.as_bytes()).0)
    }
}

////////////////////////////////////////////////////////////////////////////////
fn main() {
    match env_logger::init() {
        Ok(()) => {},
        Err(e) => println!("Error initialising logger; continuing without: {:?}", e)
    }

    let args: Args = Docopt::new(USAGE)
                            .and_then(|docopt| docopt.decode())
                            .unwrap_or_else(|error| error.exit());

    let bootstrap_peers = args.arg_peer.into_iter()
                                       .map(|ep| ep.to_crust_endpoint())
                                       .collect::<Vec<_>>();

    if args.flag_node {
        let mut node = match Node::new(bootstrap_peers) {
            Ok(node) => node,
            Err(err) => { println!("Failed to create Node: {:?}", err); return; }
        };

        node.run();
    } else {
        let mut client = match Client::new(bootstrap_peers) {
            Ok(client) => client,
            Err(err) => { println!("Failed to create Client: {:?}", err); return; }
        };

        client.run();
    }
}

