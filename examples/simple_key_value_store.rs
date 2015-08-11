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
//extern crate core;
extern crate docopt;
extern crate rustc_serialize;
extern crate maidsafe_sodiumoxide as sodiumoxide;

extern crate crust;
extern crate routing;

//use core::iter::FromIterator;
use std::io;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::thread;
use std::thread::spawn;
use std::collections::BTreeMap;

use cbor::CborError;
use docopt::Docopt;
use rustc_serialize::{Decodable, Decoder};
use sodiumoxide::crypto;

use crust::Endpoint;
use routing::routing::Routing;
use routing::types;
use routing::id::Id;
use routing::authority::Authority;
use routing::NameType;
use routing::error::{ResponseError, RoutingError};
use routing::event::Event;
use routing::data::{Data, DataRequest};
use routing::plain_data::PlainData;
use routing::utils::{encode, decode, public_key_to_client_name};
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

////////////////////////////////////////////////////////////////////////////////
struct Node {
    routing  : Routing,
    receiver : Receiver<Event>,
}

impl Node {
    fn new(_bootstrap_peers: Vec<Endpoint>) -> Result<Node, RoutingError> {
        let (sender, receiver) = mpsc::channel::<Event>();
        let routing = try!(Routing::new(sender));

        Ok(Node {
            routing  : routing,
            receiver : receiver,
        })
    }

    fn run(&self) {
        loop {
            let event = match self.receiver.recv() {
                Ok(event) => event,
                Err(err)  => {
                    println!("Got error from node: {:?}", err);
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

    fn handle_request(&self, request        : ExternalRequest,
                             our_authority  : Authority,
                             from_authority : Authority,
                             response_token : SignedToken) {
        match request {
            ExternalRequest::Get(DataRequest) => {
            },
            ExternalRequest::Put(Data) => {
            },
            ExternalRequest::Post(Data) => {
                println!("Node: Post is not implemented, ignoring.");
            },
            ExternalRequest::Delete(DataRequest) => {
                println!("Node: Delete is not implemented, ignoring.");
            },
        }
    }

    fn handle_get_request(&self, data_request   : DataRequest,
                                 our_authority  : Authority,
                                 from_authority : Authority,
                                 response_token : SignedToken) {
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
    routing_receiver : Receiver<Event>,
    user_receiver    : Receiver<UserCommand>,
    is_done          : bool,
}

impl Client {
    fn new(_bootstrap_peers: Vec<Endpoint>) -> Result<Client, RoutingError> {
        let (routing_sender, routing_receiver) = mpsc::channel::<Event>();
        let routing = try!(Routing::new_client(routing_sender));

        let (user_sender, user_receiver) = mpsc::channel::<UserCommand>();

        thread::spawn(move || { Client::read_user_commands(user_sender); });

        Ok(Client {
            routing          : routing,
            routing_receiver : routing_receiver,
            user_receiver    : user_receiver,
            is_done          : false,
        })
    }

    fn run(&mut self) {
        // Need to do poll as Select is not yet stable in the current
        // rust implementation.
        loop {
            while let Ok(command) = self.user_receiver.try_recv() {
                self.handle_user_command(command);
            }

            if self.is_done { break; }

            while let Ok(event) = self.routing_receiver.try_recv() {
                self.handle_routing_event(event);
            }

            if self.is_done { break; }

            thread::sleep_ms(10);
        }

        println!("Bye");
    }

    fn read_user_commands(user_sender: Sender<UserCommand>) {
        loop {
            let mut command = String::new();
            let mut stdin = io::stdin();
            println!("Type command:");
            let _ = stdin.read_line(&mut command);

            match parse_user_command(command) {
                Some(cmd) => {
                    user_sender.send(cmd.clone());
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
                println!("TODO: send Get('{}')", what);
            }
            UserCommand::Put(put_where, what) => {
                println!("TODO: send Put('{}', '{}')", put_where, what);
            }
        }
    }

    fn handle_routing_event(&mut self, event : Event) {
        println!("Client received routing event: {:?}", event);
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

////////////////////////////////////////////////////////////////////////////////
// Old code for reference, will be slowly disappearing.
// ==========================   Implement traits   =================================
//
//struct TestClient {
//    pub key_reverse_lookup : BTreeMap<NameType, String>
//}
//
//impl TestClient {
//    pub fn new() -> TestClient {
//        TestClient {
//            key_reverse_lookup: BTreeMap::new()
//        }
//    }
//}
//
//impl routing::client_interface::Interface for TestClient {
//    fn handle_get_response(&mut self, data_location : NameType, data : Data) {
//        println!("Testing client received get_response from {:?} with testdata {:?}",
//                    data_location, data);
//        match data {
//            Data::PlainData(plain_data) => {
//                match decode_key_value(plain_data.value()) {
//                    Ok((key, value)) => {
//                        println!("Client received {} under key {} from {}",
//                            value, key, data_location);
//                    },
//                    Err(_) => {
//                        println!("Client received get response from {} but failed to decode",
//                            data_location);
//                    }
//                }
//            },
//            _ => {
//                println!("Client received get response from {} but it is not PlainData.",
//                    data_location);}
//        }
//    }
//
//    fn handle_put_response(&mut self, response_error: ResponseError, _request_data: Data) {
//        match response_error {
//            ResponseError::NoData =>
//                println!("Testing client received put_response with error NoData"),
//            ResponseError::InvalidRequest =>
//                println!("Testing client received put_response with error InvalidRequest"),
//            ResponseError::FailedToStoreData(data) =>
//                println!("Testing client received put_response with error FailedToStoreData for {}", data.name()),
//        }
//    }
//
//    fn handle_post_response(&mut self, _response_error: ResponseError, _request_data: Data) {
//         unimplemented!();
//    }
//
//    fn handle_delete_response(&mut self, _response_error: ResponseError, _request_data: Data) {
//        unimplemented!();
//    }
//}
//
//struct TestNode {
//  db: BTreeMap<NameType, PlainData>
//}
//
//impl TestNode {
//    pub fn new() -> TestNode {
//        TestNode {
//            db : BTreeMap::new()
//        }
//    }
//}
//
//impl Interface for TestNode {
//    fn handle_get(&mut self,
//                  data_request: DataRequest, our_authority: Authority,
//                  _from_authority: Authority, _from_address: types::SourceAddress)
//                   -> Result<Vec<MethodCall>, InterfaceError> {
//        match data_request {
//              DataRequest::PlainData => {
//                  match our_authority {
//                      Authority::NaeManager(group_name) => {
//                          match self.db.get(&group_name) {
//                              Some(plain_data) => {
//                                  info!("node replied to get request for chunk {}",
//                                      group_name);
//                                  return Ok(vec![MethodCall::Reply {
//                                      data : Data::PlainData(plain_data.clone()) }]);
//                              },
//                              None => {
//                                  info!("node didn't have chunk {}",
//                                      group_name);
//                              }
//                          }
//                      },
//                      _ => {}
//                  };
//              },
//              _ => {}
//        };
//        Err(InterfaceError::Response(ResponseError::NoData))
//    }
//
//    fn handle_put(&mut self, our_authority: Authority, _from_authority: Authority,
//                _from_address: types::SourceAddress, _dest_address: types::DestinationAddress,
//                data: Data) -> Result<Vec<MethodCall>, InterfaceError> {
//        match data {
//            Data::PlainData(plain_data) => {
//                match our_authority {
//                    Authority::ClientManager(client_name) => {
//                        info!("ClientManager of {:?} forwarding data to DataManager around {:?}",
//                            client_name, plain_data.name());
//                        return Ok(vec![MethodCall::Put {
//                            destination: plain_data.name(),
//                            content: Data::PlainData(plain_data) }]);
//                    },
//                    Authority::NaeManager(group_name) => {
//                        info!("DataManager of {:?} asked to put plain data named {:?}",
//                            group_name, plain_data.name());
//                        assert_eq!(group_name, plain_data.name());
//                        let data_name = plain_data.name();
//                        let _ = self.db.entry(plain_data.name())
//                            .or_insert(plain_data);
//                        assert!(self.db.contains_key(&data_name));
//                    },
//                    _ => {}
//                }
//            },
//            _ => {}
//        };
//        return Ok(vec![]);
//    }
//
//    fn handle_post(&mut self, _our_authority: Authority, _from_authority: Authority,
//        _from_address: types::SourceAddress, _dest_address: types::DestinationAddress,
//        _data: Data) -> Result<Vec<MethodCall>, InterfaceError> {
//        Err(InterfaceError::Abort)
//    }
//
//    fn handle_refresh(&mut self, _type_tag: u64, _from_group: NameType, _payloads: Vec<Vec<u8>>) {
//        unimplemented!()
//    }
//
//    fn handle_get_response(&mut self, from_address: NameType, response: Data) -> Vec<MethodCall> {
//        println!("testing node received get_response from {} with data {:?}", from_address, response);
//        vec![]
//    }
//
//    fn handle_put_response(&mut self, _from_authority : Authority, _from_address: types::SourceAddress,
//                                      response: ResponseError) -> Vec<MethodCall> {
//        println!("testing node received error put_response {}", response);
//        vec![]
//    }
//
//    fn handle_post_response(&mut self, _from_authority: Authority,
//        _from_address: types::SourceAddress, _response: ResponseError)
//        -> Vec<MethodCall> {
//        unimplemented!();
//    }
//
//    fn handle_churn(&mut self, close_group: Vec<NameType>) -> Vec<MethodCall> {
//        for name in close_group {
//          println!("RT: {:?}", name);
//        }
//        vec![]
//    }
//
//    fn handle_cache_get(&mut self, _data_request: DataRequest, _data_location: NameType,
//                                   _from_address: NameType) -> Result<MethodCall, InterfaceError> {
//        // FIXME(ben): 17/7/2015 implement a proper caching mechanism;
//        // separate from the key-value store
//        Err(InterfaceError::Abort)
//    }
//
//    fn handle_cache_put(&mut self, _from_authority: Authority, _from_address: NameType,
//                        _data: Data) -> Result<MethodCall, InterfaceError> {
//        // FIXME(ben): 17/7/2015 implement a proper caching mechanism;
//        // separate from the key-value store
//        Err(InterfaceError::Abort)
//    }
//}
//
//struct TestNodeGenerator;
//
//impl CreatePersonas<TestNode> for TestNodeGenerator {
//    fn create_personas(&mut self) -> TestNode {
//        TestNode::new()
//    }
//}
//
//fn calculate_key_name(key: &String) -> NameType {
//    NameType::new(crypto::hash::sha512::hash(key.as_bytes()).0)
//}
//
//#[allow(dead_code)]
//fn encode_key_value(key : String, value : String) -> Result<Vec<u8>, CborError> {
//    encode(&(key, value))
//}
//
//#[allow(dead_code)]
//fn decode_key_value(data : &Vec<u8>) -> Result<(String, String), CborError> {
//    decode(data)
//}
//
//fn run_passive_node(_bootstrap_peers: Option<Vec<Endpoint>>) {
//}
//
//fn run_interactive_node(_bootstrap_peers: Option<Vec<Endpoint>>) {
//    let our_id = Id::new();
//    let our_client_name : NameType = public_key_to_client_name(&our_id.signing_public_key());
//    let test_client = RoutingClient::new(Arc::new(Mutex::new(TestClient::new())), our_id);
//    let mutate_client = Arc::new(Mutex::new(test_client));
//    let copied_client = mutate_client.clone();
//    let _ = spawn(move || {
//        let _ = copied_client.lock().unwrap().bootstrap();
//        thread::sleep_ms(100);
//        loop {
//            thread::sleep_ms(10);
//            copied_client.lock().unwrap().poll_one();
//        }
//    });
//    let ref mut command = String::new();
//    let docopt: Docopt = Docopt::new(CLI_USAGE).unwrap_or_else(|error| error.exit());
//    let stdin = io::stdin();
//    loop {
//        command.clear();
//        println!("Enter command (stop | put <key> <value> | get <key>)>");
//        let _ = stdin.read_line(command);
//        let x: &[_] = &['\r', '\n'];
//        let mut raw_args: Vec<&str> = command.trim_right_matches(x).split(' ').collect();
//        raw_args.insert(0, "cli");
//        let args: CliArgs = match docopt.clone().argv(raw_args.into_iter()).decode() {
//            Ok(args) => args,
//            Err(error) => {
//                match error {
//                    docopt::Error::Decode(what) => println!("{}", what),
//                    _ => println!("Invalid command."),
//                };
//                continue
//            },
//        };
//
//        if args.cmd_put {
//            // docopt should ensure arg_key and arg_value are valid
//            assert!(args.arg_key.is_some() && !args.arg_value.is_empty());
//            match args.arg_key {
//                Some(key) => {
//                    let key_name : NameType = calculate_key_name(&key);
//                    println!("Putting value \"{}\" to network under key \"{}\" at location {}.",
//                        args.arg_value, key, key_name);
//                    match encode_key_value(key, args.arg_value) {
//                        Ok(serialised_key_value) => {
//                            let data = PlainData::new(key_name, serialised_key_value);
//                            let _ = mutate_client.lock().unwrap()
//                                .put(our_client_name, Data::PlainData(data));
//                        },
//                        Err(_) => { println!("Failed to encode key and value."); }
//                    }
//                },
//                None => ()
//            }
//        } else if args.cmd_get {
//            // docopt should ensure arg_key is valid
//            assert!(args.arg_key.is_some());
//            match args.arg_key {
//                Some(key) => {
//                    let key_name : NameType = calculate_key_name(&key);
//                    println!("Getting value for key \"{}\" from network at location {}.",
//                        key, key_name);
//                    let _ = mutate_client.lock().unwrap().get(key_name, DataRequest::PlainData);
//                },
//                None => ()
//            }
//        } else if args.cmd_stop {
//            break;
//        }
//    }
//}

