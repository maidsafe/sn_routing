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

// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(bad_style, exceeding_bitshifts, mutable_transmutes, no_mangle_const_items,
          unknown_crate_types, warnings)]
#![deny(deprecated, drop_with_repr_extern, improper_ctypes, missing_docs,
        non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
        private_no_mangle_fns, private_no_mangle_statics, stable_features, unconditional_recursion,
        unknown_lints, unsafe_code, unused, unused_allocation, unused_attributes,
        unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results)]
#![allow(box_pointers, fat_ptr_transmutes, missing_copy_implementations,
         missing_debug_implementations, variant_size_differences)]

#[macro_use]
extern crate log;
// extern crate rand;
#[macro_use]
#[allow(unused_extern_crates)]
extern crate maidsafe_utilities;
extern crate docopt;
extern crate rustc_serialize;
extern crate sodiumoxide;

extern crate routing;
extern crate xor_name;

use std::io;
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::collections::BTreeMap;
use std::io::Write;

use docopt::Docopt;
use xor_name::XorName;
use rustc_serialize::{Decodable, Decoder};
use sodiumoxide::crypto;

use maidsafe_utilities::serialisation::{serialise, deserialise};
use routing::Routing;
use routing::RoutingClient;
use routing::Authority;
use routing::Event;
use routing::{Data, DataRequest};
use routing::PlainData;
use routing::{RequestMessage, RequestContent, ResponseContent};
use routing::{FullId, PublicId};

// ==========================   Program Options   =================================
static USAGE: &'static str = "
Usage:
  key_value_store
  key_value_store --node
  \
                              key_value_store --help

Options:
  -n, --node   Run as a \
                              non-interactive routing node in the network.
  -h, --help   Display \
                              this help message.

  Running without the --node option will start \
                              an interactive node.
  Such a node can be used to send requests \
                              such as 'put' and
  'get' to the network.

  A passive node is one \
                              that simply reacts on received requests. Such nodes are
  the \
                              workers; they route messages and store and provide data.

  The \
                              crust configuration file can be used to provide information on what
  \
                              network discovery patterns to use, or which seed nodes to use.
";

#[derive(RustcDecodable, Debug)]
struct Args {
    flag_node: bool,
    flag_help: bool,
}

/// /////////////////////////////////////////////////////////////////////////////
struct Node {
    routing: Routing,
    receiver: Receiver<Event>,
    db: BTreeMap<::xor_name::XorName, PlainData>,
    client_accounts: BTreeMap<::xor_name::XorName, u64>,
    connected: bool,
    our_close_group: Vec<::xor_name::XorName>,
}

impl Node {
    fn new() -> Node {
        let (sender, receiver) = mpsc::channel::<Event>();
        let routing = unwrap_result!(Routing::new(sender));

        Node {
            routing: routing,
            receiver: receiver,
            db: BTreeMap::new(),
            client_accounts: BTreeMap::new(),
            connected: false,
            our_close_group: vec![],
        }
    }

    fn run(&mut self) {
        loop {
            let event = match self.receiver.recv() {
                Ok(event) => event,
                Err(_) => {
                    println!("Node: Routing closed the event channel");
                    return;
                }
            };

            info!("Node: Received event {:?}", event);

            match event {
                Event::Request(msg) => {
                    self.handle_request(msg);
                }
                Event::Connected => {
                    self.connected = true;
                    println!("Node is connected.")
                },
                Event::Churn(our_close_group) => {
                    self.handle_churn(our_close_group);
                },
                Event::Refresh(type_tag, our_authority, vec_of_bytes) => {
                    if type_tag != 1u64 {
                        error!("Received refresh for tag {:?} from {:?}", type_tag, our_authority);
                        continue;
                    };
                    self.handle_refresh(our_authority, vec_of_bytes);
                },
                Event::DoRefresh(type_tag, our_authority, cause) => {
                    if type_tag != 1u64 {
                        error!("Received DoRefresh for tag {:?} from {:?}", type_tag, our_authority);
                        continue;
                    };
                    self.handle_do_refresh(our_authority, cause);
                }
                Event::Terminated => {
                    break;
                }
                _ => (),
            }
        }
    }

    fn handle_request(&mut self, request_msg: RequestMessage) {
        match request_msg.content {
            RequestContent::Get(data_request) => {
                self.handle_get_request(data_request, request_msg.src, request_msg.dst);
            }
            RequestContent::Put(data) => {
                self.handle_put_request(data, request_msg.src, request_msg.dst);
            }
            _ => println!("Node: Request {:?} not handled, ignoring.", request_msg),
        }
    }

    fn handle_get_request(&mut self, data_request: DataRequest, src: Authority, dst: Authority) {
        let name = match data_request {
            DataRequest::PlainData(name) => name,
            _ => {
                println!("Node: Only serving plain data in this example");
                return;
            }
        };

        let data = match self.db.get(&name) {
            Some(data) => data.clone(),
            None => return,
        };

        let response_content = ResponseContent::GetSuccess(Data::PlainData(data));

        unwrap_result!(self.routing.send_get_response(dst, src, response_content))
    }

    fn handle_put_request(&mut self, data: Data, src: Authority, dst: Authority) {
        let plain_data = match data.clone() {
            Data::PlainData(plain_data) => plain_data,
            _ => {
                println!("Node: Only storing plain data in this example");
                return;
            }
        };

        match dst {
            Authority::NaeManager(_) => {
                println!("Storing: key {:?}, value {:?}",
                         plain_data.name(),
                         plain_data);
                let _ = self.db.insert(plain_data.name(), plain_data);
            }
            Authority::ClientManager(_) => {
                match src {
                    Authority::Client { client_key, .. } => {
                        let client_name = ::xor_name::XorName::new(
                            ::sodiumoxide::crypto::hash::sha512::hash(&client_key[..]).0);
                        *self.client_accounts
                             .entry(client_name)
                             .or_insert(0u64) += data.payload_size() as u64;
                        println!("Client ({:?}) stored {:?} bytes",
                                 client_name,
                                 self.client_accounts.get(&client_name));
                        debug!("Sending: key {:?}, value {:?}",
                               plain_data.name(),
                               plain_data);
                        let name = data.name();
                        let request_content = RequestContent::Put(data);
                        unwrap_result!(self.routing.send_put_request(dst,
                                                                     Authority::NaeManager(name),
                                                                     request_content));
                    }
                    _ => {
                        println!("Node: Unexpected from_authority ({:?})", src);
                        assert!(false);
                    }
                }
            }
            _ => {
                println!("Node: Unexpected our_authority ({:?})", dst);
                assert!(false);
            }
        }
    }

    fn handle_churn(&mut self, our_close_group: Vec<::xor_name::XorName>) {
        println!("Handle churn for close group size {:?}", our_close_group.len());
        // FIXME Cause needs to get removed from refresh as well
        // TODO(Fraser) Trying to remove cause but Refresh requires one so creating a random one
        // just so that interface requirements are met
        // let cause = rand::random::<XorName>();

        // Not having access to our close group on startup means refresh won't
        // be called for the first node that goes offline.
        if self.our_close_group.len() == 0 {
            self.our_close_group = our_close_group.clone();
            return
        }

        for (client_name, stored) in self.client_accounts.iter() {
            let mut updated = false;
            for close_node in self.our_close_group.iter() {
                if !our_close_group.contains(&close_node) {
                    println!("Refresh {:?} - {:?}", client_name, stored);
                    let request_content = RequestContent::Refresh {
                        type_tag: 1u64,
                        message: unwrap_result!(serialise(&stored)),
                        cause: close_node.clone(),
                    };
                    updated = true;
                    unwrap_result!(self.routing.send_refresh_request(
                        Authority::ClientManager(client_name.clone()),
                        request_content));
                }
            }
            if updated {
                self.our_close_group = our_close_group.clone();
            }
        }
    }

    fn handle_refresh(&mut self, src: Authority, vec_of_bytes: Vec<Vec<u8>>) {
        let mut records: Vec<u64> = Vec::new();
        let mut fail_parsing_count = 0usize;
        for bytes in vec_of_bytes {
            match deserialise(&bytes) {
                Ok(record) => records.push(record),
                Err(_) => fail_parsing_count += 1usize,
            }
        }
        let median = median(records.clone());
        println!("Refresh for {:?}: median {:?} from {:?} (errs {:?})",
               src,
               median,
               records,
               fail_parsing_count);
        if let Authority::ClientManager(client_name) = src {
            let _ = self.client_accounts.insert(client_name, median);
        }
    }

    fn handle_do_refresh(&self, src: Authority, cause: XorName) {
        if let Authority::ClientManager(client_name) = src {
            match self.client_accounts.get(&client_name) {
                Some(stored) => {
                    println!("DoRefresh for client {:?} storing {:?} caused by {:?}", client_name, stored, cause);

                    let request_content = RequestContent::Refresh {
                        type_tag: 1u64,
                        message: unwrap_result!(serialise(&stored)),
                        cause: cause,
                    };
                    let _ = self.routing.send_refresh_request(Authority::ClientManager(client_name.clone()),
                                                              request_content);
                },
                None => (),
            }
        }
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

/// /////////////////////////////////////////////////////////////////////////////
#[derive(PartialEq, Eq, Debug, Clone)]
enum UserCommand {
    Exit,
    Get(String),
    Put(String, String),
}

fn parse_user_command(cmd: String) -> Option<UserCommand> {
    let cmds = cmd.trim_right_matches(|c| c == '\r' || c == '\n')
                  .split(' ')
                  .collect::<Vec<_>>();

    if cmds.is_empty() {
        return None;
    } else if cmds.len() == 1 && cmds[0] == "exit" {
        return Some(UserCommand::Exit);
    } else if cmds.len() == 2 && cmds[0] == "get" {
        return Some(UserCommand::Get(cmds[1].to_string()));
    } else if cmds.len() == 3 && cmds[0] == "put" {
        return Some(UserCommand::Put(cmds[1].to_string(), cmds[2].to_string()));
    }

    None
}

/// /////////////////////////////////////////////////////////////////////////////
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

        let full_id = FullId::new();
        let public_id = full_id.public_id().clone();
        println!("Client has set name {:?}", public_id);
        let routing_client = unwrap_result!(RoutingClient::new(event_sender, Some(full_id)));

        let (command_sender, command_receiver) = mpsc::channel::<UserCommand>();

        let _ = thread!("Command reader", move || {
            Client::read_user_commands(command_sender);
        });

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

            if self.exit {
                break;
            }

            while let Ok(event) = self.event_receiver.try_recv() {
                self.handle_routing_event(event);
            }

            if self.exit {
                break;
            }

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
                }
                None => {
                    println!("Unrecognised command");
                    continue;
                }
            }
        }
    }

    fn handle_user_command(&mut self, cmd: UserCommand) {
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

    fn handle_routing_event(&mut self, event: Event) {
        debug!("Client received routing event: {:?}", event);
        match event {
            Event::Response(msg) => {
                match msg.content {
                    ResponseContent::GetSuccess(data) => {
                        let plain_data = match data {
                            Data::PlainData(plain_data) => plain_data,
                            _ => {
                                error!("Node: Only storing plain data in this example");
                                return;
                            }
                        };
                        let (key, value): (String, String) = match deserialise(plain_data.value()) {
                            Ok((key, value)) => (key, value),
                            Err(_) => {
                                error!("Failed to decode get response.");
                                return;
                            }
                        };
                        println!("Got value {:?} on key {:?}", value, key);
                    }
                    ResponseContent::PutFailure { ..} => {
                        error!("Failed to store");
                    }
                    _ => error!("Received response {:?}, but not handled in example", msg),
                }
            }
            _ => (),
        }
    }

    fn send_get_request(&mut self, what: String) {
        let name = Client::calculate_key_name(&what);

        unwrap_result!(self.routing_client
                           .send_get_request(Authority::NaeManager(name.clone()),
                                             DataRequest::PlainData(name)));
    }

    fn send_put_request(&self, put_where: String, put_what: String) {
        let name = Client::calculate_key_name(&put_where);
        let data = unwrap_result!(serialise(&(put_where, put_what)));

        unwrap_result!(self.routing_client
                           .send_put_request(Authority::ClientManager(self.public_id
                                                                          .name()
                                                                          .clone()),
                                             Data::PlainData(PlainData::new(name, data))));
    }

    fn calculate_key_name(key: &String) -> XorName {
        XorName::new(crypto::hash::sha512::hash(key.as_bytes()).0)
    }
}

/// /////////////////////////////////////////////////////////////////////////////
fn main() {
    ::maidsafe_utilities::log::init(false);

    let args: Args = Docopt::new(USAGE)
                         .and_then(|docopt| docopt.decode())
                         .unwrap_or_else(|error| error.exit());

    if args.flag_node {
        let mut node = Node::new();
        node.run();
        debug!("[key_value_store -> Node Example] Exiting main...");
    } else {
        let mut client = Client::new();
        client.run();
        debug!("[key_value_store -> Client Example] Exiting main...");
    }
}
