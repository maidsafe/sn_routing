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
       unconditional_recursion, unknown_lints, unsafe_code, unused,
       unused_allocation, unused_attributes, unused_comparisons, unused_features, unused_parens,
       while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
       unused_qualifications, unused_results, variant_size_differences)]

#[macro_use]
extern crate log;
extern crate env_logger;

extern crate docopt;
extern crate rustc_serialize;
extern crate sodiumoxide;

extern crate routing;

use std::io;
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::thread;
use std::thread::spawn;
use std::collections::BTreeMap;
use std::io::Write;

use docopt::Docopt;
use rustc_serialize::{Decodable, Decoder};
use sodiumoxide::crypto;

use routing::routing::Routing;
use routing::routing_client::RoutingClient;
use routing::authority::Authority;
use routing::NameType;
use routing::event::Event;
use routing::data::{Data, DataRequest};
use routing::plain_data::PlainData;
use routing::utils::{encode, decode};
use routing::{ExternalRequest, ExternalResponse, SignedToken};
use routing::id::Id;
use routing::public_id::PublicId;

// ==========================   Program Options   =================================
static USAGE: &'static str = "
Usage:
  simple_key_value_store
  simple_key_value_store --node
  simple_key_value_store --help

Options:
  -n, --node   Run as a non-interactive routing node in the network.
  -h, --help   Display this help message.

  Running without the --node option will start an interactive node.
  Such a node can be used to send requests such as 'put' and
  'get' to the network.

  A passive node is one that simply reacts on received requests. Such nodes are
  the workers; they route messages and store and provide data.

  The crust configuration file can be used to provide information on what
  network discovery patterns to use, or which seed nodes to use.
";

#[derive(RustcDecodable, Debug)]
struct Args {
    flag_node: bool,
    flag_help: bool,
}

////////////////////////////////////////////////////////////////////////////////
struct Node {
    routing  : Routing,
    receiver : Receiver<Event>,
    db       : BTreeMap<NameType, PlainData>,
}

impl Node {
    fn new() -> Node {
        let (sender, receiver) = mpsc::channel::<Event>();
        let routing = Routing::new(sender);

        Node {
            routing  : routing,
            receiver : receiver,
            db       : BTreeMap::new(),
        }
    }

    fn run(&mut self) {
        loop {
            let event = match self.receiver.recv() {
                Ok(event) => event,
                Err(_)  => {
                    error!("Node: Routing closed the event channel");
                    return;
                }
            };

            debug!("Node: Received event {:?}", event);

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
                Event::Churn(our_close_group) => {
                    self.handle_churn(our_close_group);
                }
                _ => {}
            }
        }
    }

    fn handle_request(&mut self, request        : ExternalRequest,
                                 our_authority  : Authority,
                                 from_authority : Authority,
                                 response_token : Option<SignedToken>) {
        match request {
            ExternalRequest::Get(data_request, _) => {
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
                error!("Node: Post is not implemented, ignoring.");
            },
            ExternalRequest::Delete(_) => {
                error!("Node: Delete is not implemented, ignoring.");
            },
        }
    }

    fn handle_get_request(&mut self, data_request: DataRequest,
                                     our_authority: Authority,
                                     from_authority: Authority,
                                     response_token: Option<SignedToken>) {
        let name = match data_request {
            DataRequest::PlainData(name) => name,
            _ => { error!("Node: Only serving plain data in this example"); return; }
        };

        let data = match self.db.get(&name) {
            Some(data) => data.clone(),
            None => return,
        };
        println!("GET {:?}", name);
        self.routing.get_response(our_authority,
                                  from_authority,
                                  Data::PlainData(data),
                                  data_request,
                                  response_token);
    }

    fn handle_put_request(&mut self, data            : Data,
                                     our_authority   : Authority,
                                     _from_authority : Authority,
                                     _response_token : Option<SignedToken>) {
        let plain_data = match data {
            Data::PlainData(plain_data) => plain_data,
            _ => { error!("Node: Only storing plain data in this example"); return; }
        };

        match our_authority {
            Authority::NaeManager(_) => {
                println!("PUT {:?}", plain_data.name());
                let _ = self.db.insert(plain_data.name(), plain_data);
            },
            _ => {
                error!("Node: Unexpected our_authority ({:?})", our_authority);
                assert!(false);
            }
        }
    }

    fn handle_churn(&mut self, _our_close_group: Vec<::routing::NameType>) {
        info!("Handle churn for close group size {:?}", _our_close_group.len());
        for value in self.db.values() {
            println!("CHURN {:?}", value.name());
            self.routing.put_request(::routing::authority::Authority::NaeManager(value.name()),
                ::routing::authority::Authority::NaeManager(value.name()),
                ::routing::data::Data::PlainData(value.clone()));
        }
        // self.db = BTreeMap::new();
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
    routing_client   : RoutingClient,
    event_receiver   : Receiver<Event>,
    command_receiver : Receiver<UserCommand>,
    is_done          : bool,
}

impl Client {
    fn new() -> Client {
        let (event_sender, event_receiver) = mpsc::channel::<Event>();

        let id = Id::new();
        info!("Client has set name {:?}", PublicId::new(&id));
        let routing_client = RoutingClient::new(event_sender, Some(id));

        let (command_sender, command_receiver) = mpsc::channel::<UserCommand>();

        let _ = spawn(move || { Client::read_user_commands(command_sender); });

        Client {
            routing_client   : routing_client,
            event_receiver   : event_receiver,
            command_receiver : command_receiver,
            is_done          : false,
        }
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
            let stdin = io::stdin();

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
        debug!("Client received routing event: {:?}", event);
        match event {
            Event::Response{
                response, our_authority : _our_authority,
                from_authority : _from_authority} => {
                match response {
                    ExternalResponse::Get(data, _data_request, _opt_signed_token) => {
                        let plain_data = match data {
                            Data::PlainData(plain_data) => plain_data,
                            _ => {
                                error!("Node: Only storing plain data in this example");
                                return; },
                        };
                        let (key, value) : (String, String) = match decode(plain_data.value()) {
                            Ok((key, value)) => (key, value),
                            Err(_) => {
                                error!("Failed to decode get response.");
                                return; },
                        };
                        println!("Got value {:?} on key {:?}", value, key);
                    },
                    ExternalResponse::Put(response_error, _opt_signed_token) => {
                        error!("Failed to store: {:?}", response_error);
                    },
                    _ => error!("Received external response {:?}, but not handled in example",
                        response),
                };
            },
            _ => {},
        };
    }

    fn send_get_request(&mut self, what: String) {
        let name = Client::calculate_key_name(&what);

        self.routing_client.get_request(Authority::NaeManager(name.clone()),
            DataRequest::PlainData(name));
    }

    fn send_put_request(&self, put_where: String, put_what: String) {
        let name = Client::calculate_key_name(&put_where);
        let data = encode(&(put_where, put_what)).unwrap();

        self.routing_client.put_request(Authority::NaeManager(name.clone()),
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

    if args.flag_node {
        let mut node = Node::new();
        node.run();
    } else {
        let mut client = Client::new();
        client.run();
    }
}
