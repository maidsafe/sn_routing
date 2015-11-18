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
#[macro_use]
#[allow(unused_extern_crates)]
extern crate maidsafe_utilities;
extern crate docopt;
extern crate rustc_serialize;
extern crate sodiumoxide;

extern crate routing;

use std::io;
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
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
  key_value_store
  key_value_store --node
  key_value_store --help

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
    routing: Routing,
    receiver: Receiver<Event>,
    db: BTreeMap<::routing::NameType, PlainData>,
    client_accounts: BTreeMap<::routing::NameType, u64>,
    connected: bool,
}

impl Node {
    fn new() -> Node {
        let (sender, receiver) = mpsc::channel::<Event>();
        let routing = Routing::new(sender);

        Node {
            routing: routing,
            receiver: receiver,
            db: BTreeMap::new(),
            client_accounts: BTreeMap::new(),
            connected: false,
        }
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

            info!("Node: Received event {:?}", event);

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
                Event::Connected => {
                    self.connected = true;
                    println!("Node is connected.")
                },
                Event::Churn(our_close_group, cause) => {
                    self.handle_churn(our_close_group, cause);
                },
                Event::Refresh(type_tag, our_authority, vec_of_bytes) => {
                    if type_tag != 1u64 { error!("Received refresh for tag {:?} from {:?}",
                        type_tag, our_authority); continue; };
                    self.handle_refresh(our_authority, vec_of_bytes);
                },
                Event::DoRefresh(type_tag, our_authority, cause) => {
                    // on DoRefresh, refresh the explicit record provided with that cause
                    if type_tag != 1u64 { error!("Received DoRefresh for tag {:?} from {:?}",
                        type_tag, our_authority); continue; };
                    self.handle_do_refresh(our_authority, cause);
                }
                Event::Terminated => {
                    break;
                },
                _ => {},
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
                println!("Node: Post is not implemented, ignoring.");
            },
            ExternalRequest::Delete(_) => {
                println!("Node: Delete is not implemented, ignoring.");
            },
        }
    }

    fn handle_get_request(&mut self, data_request: DataRequest,
                                     our_authority: Authority,
                                     from_authority: Authority,
                                     response_token: Option<SignedToken>) {
        let name = match data_request {
            DataRequest::PlainData(name) => name,
            _ => { println!("Node: Only serving plain data in this example"); return; }
        };

        let data = match self.db.get(&name) {
            Some(data) => data.clone(),
            None => return,
        };

        self.routing.get_response(our_authority,
                                  from_authority,
                                  Data::PlainData(data),
                                  data_request,
                                  response_token);
    }

    fn handle_put_request(&mut self, data            : Data,
                                     our_authority   : Authority,
                                     from_authority  : Authority,
                                     _response_token : Option<SignedToken>) {
        let plain_data = match data.clone() {
            Data::PlainData(plain_data) => plain_data,
            _ => { println!("Node: Only storing plain data in this example"); return; }
        };

        match our_authority {
            Authority::NaeManager(_) => {
                println!("Storing: key {:?}, value {:?}", plain_data.name(), plain_data);
                let _ = self.db.insert(plain_data.name(), plain_data);
            },
            Authority::ClientManager(_) => {
                match from_authority {
                    ::routing::authority::Authority::Client(_, public_key) => {
                        let client_name = ::routing::NameType::new(
                            ::sodiumoxide::crypto::hash::sha512::hash(&public_key[..]).0);
                        *self.client_accounts.entry(client_name)
                            .or_insert(0u64) += data.payload_size() as u64;
                        println!("Client ({:?}) stored {:?} bytes", client_name,
                            self.client_accounts.get(&client_name));
                        debug!("Sending: key {:?}, value {:?}", plain_data.name(), plain_data);
                        self.routing.put_request(
                            our_authority, Authority::NaeManager(plain_data.name()), data);
                    },
                    _ => {
                        println!("Node: Unexpected from_authority ({:?})", from_authority);
                        assert!(false);
                    },
                };

            },
            _ => {
                println!("Node: Unexpected our_authority ({:?})", our_authority);
                assert!(false);
            }
        }
    }

    fn handle_churn(&mut self, our_close_group: Vec<::routing::NameType>,
        cause: ::routing::NameType) {
        // let mut exit = false;
        let exit = false;
        if our_close_group.len() < ::routing::types::GROUP_SIZE {
            if self.connected {
                println!("Close group ({:?}) has fallen below group size {:?}, terminating node",
                    our_close_group.len(), ::routing::types::GROUP_SIZE);
                // exit = true;
            } else {
                println!("Ignoring churn as we are not yet connected.");
                return;
            }
        }
        println!("Handle churn for close group size {:?}", our_close_group.len());
        // for value in self.db.values() {
        //     println!("CHURN {:?}", value.name());
        //     self.routing.put_request(::routing::authority::Authority::NaeManager(value.name()),
        //         ::routing::authority::Authority::NaeManager(value.name()),
        //         ::routing::data::Data::PlainData(value.clone()));
        // }

        for (client_name, stored) in self.client_accounts.iter() {
            println!("REFRESH {:?} - {:?}", client_name, stored);
            self.routing.refresh_request(1u64,
                ::routing::authority::Authority::ClientManager(client_name.clone()),
                encode(&stored).unwrap(), cause.clone());
        }
        // self.db = BTreeMap::new();
        if exit { self.routing.stop(); };
    }

    fn handle_refresh(&mut self, our_authority: Authority, vec_of_bytes: Vec<Vec<u8>>) {
        let mut records : Vec<u64> = Vec::new();
        let mut fail_parsing_count = 0usize;
        for bytes in vec_of_bytes {
            match decode(&bytes) {
                Ok(record) => records.push(record),
                Err(_) => fail_parsing_count += 1usize,
            };
        }
        let median = median(records.clone());
        println!("Refresh for {:?}: median {:?} from {:?} (errs {:?})", our_authority, median,
            records, fail_parsing_count);
        match our_authority {
             ::routing::authority::Authority::ClientManager(client_name) => {
                 let _ = self.client_accounts.insert(client_name, median);
             },
             _ => {},
        };
    }

    fn handle_do_refresh(&self, our_authority: ::routing::authority::Authority,
        cause: ::routing::NameType) {
        match our_authority {
            ::routing::authority::Authority::ClientManager(client_name) => {
                match self.client_accounts.get(&client_name) {
                    Some(stored) => {
                        println!("DoRefresh for client {:?} storing {:?} caused by {:?}",
                            client_name, stored, cause);
                        self.routing.refresh_request(1u64,
                            ::routing::authority::Authority::ClientManager(client_name.clone()),
                            encode(&stored).unwrap(), cause.clone());
                    },
                    None => {},
                };
            },
            _ => {},
        };
    }
}

/// Returns the median (rounded down to the nearest integral value) of `values` which can be
/// unsorted.  If `values` is empty, returns `0`.
pub fn median(mut values: Vec<u64>) -> u64 {
    match values.len() {
        0 => 0u64,
        1 => values[0],
        len if len % 2 == 0 => {
            values.sort();
            let lower_value = values[(len / 2) - 1];
            let upper_value = values[len / 2];
            (lower_value + upper_value) / 2
        }
        len => {
            values.sort();
            values[len / 2]
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
    routing_client: RoutingClient,
    event_receiver: Receiver<Event>,
    command_receiver: Receiver<UserCommand>,
    public_id: PublicId,
    exit: bool,
}

impl Client {
    fn new() -> Client {
        let (event_sender, event_receiver) = mpsc::channel::<Event>();

        let id = Id::new();
        let public_id = PublicId::new(&id);
        println!("Client has set name {:?}", public_id.clone());
        let routing_client = RoutingClient::new(event_sender, Some(id));

        let (command_sender, command_receiver) = mpsc::channel::<UserCommand>();

        let _ = thread!("Command reader", move || { Client::read_user_commands(command_sender); });

        Client {
            routing_client: routing_client,
            event_receiver: event_receiver,
            command_receiver: command_receiver,
            public_id: public_id,
            exit: false,
        }
    }

    fn run(&mut self) {
        // Need to do poll as Select is not yet stable in the current
        // rust implementation.
        loop {
            while let Ok(command) = self.command_receiver.try_recv() {
                self.handle_user_command(command);
            }

            if self.exit { break; }

            while let Ok(event) = self.event_receiver.try_recv() {
                self.handle_routing_event(event);
            }

            if self.exit { break; }

            let interval = ::std::time::Duration::from_millis(10);
            ::std::thread::sleep(interval);
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
                self.exit = true;
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

        self.routing_client.get_request(Authority::ClientManager(name.clone()),
            DataRequest::PlainData(name));
    }

    fn send_put_request(&self, put_where: String, put_what: String) {
        let name = Client::calculate_key_name(&put_where);
        let data = encode(&(put_where, put_what)).unwrap();

        self.routing_client.put_request(Authority::ClientManager(self.public_id.name()),
            Data::PlainData(PlainData::new(name, data)));
    }

    fn calculate_key_name(key: &String) -> NameType {
        NameType::new(crypto::hash::sha512::hash(key.as_bytes()).0)
    }
}

////////////////////////////////////////////////////////////////////////////////
fn main() {
    routing::utils::initialise_logger(true);

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
