// // Copyright 2015 MaidSafe.net limited.
// //
// // This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// // version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// // licence you accepted on initial access to the Software (the "Licences").
// //
// // By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// // bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// // Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
// //
// // Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// // under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// // KIND, either express or implied.
// //
// // Please review the Licences for the specific language governing permissions and limitations
// // relating to use of the SAFE Network Software.

// // Executable test
// // Two optional docopts args
// // 		1. Number of nodes to run, or default 10.
// //		2. Number of random messages to put and get, default 100, extend to post, delete later.
// //      3. Maximum runtime, if empty run forever.
// // We want 20% stable nodes, 80% churn nodes
// // Minimum online time 2 mins upto max 20mins for churn nodes.
// //
// // Start up nodes do the puts and gets.

// #[macro_use]
// extern crate log;
// #[macro_use]
// extern crate maidsafe_utilities;
// extern crate rustc_serialize;
// extern crate docopt;

// use docopt::Docopt;

// // ==========================   Program Options   =================================
// static USAGE: &'static str = "
// Usage:
//   local_network [options]
//   local_network --help

// Options:
//   -n, --nodes  Number of network nodes to run.
//   -r, --reqs   Number of put requests sent to the network.
//   -h, --help   Display this help message.

//   Runs n nodes 20% long lived, 80% churn.
//   Sends r 'put' requests.
//   Sends an arbitrary number of 'get' requests.
// ";

// #[derive(PartialEq, Eq, Debug, Clone, RustcDecodable)]
// struct Args {
// 	nodes: usize,
// 	requests: usize,
// }

// fn parse_user_command(cmd: String) -> Option<Args> {
//     let cmds = cmd.trim_right_matches(|c| c == '\r' || c == '\n')
//                   .split(' ')
//                   .collect::<Vec<_>>();

//     if cmds.is_empty() {
//         return None;
//     } else if cmds.len() == 4 && cmds[0] == "nodes" && cmds[2] == "reqs" {
//     	let nodes: usize = match cmds[1].parse::<usize>() {
//     		Ok(nodes) => nodes,
//     		Err(err) => {
//     			println!("Failed to parse nodes {} to usize.", cmds[1]);
//     			return None
//     		}
//     	};

//     	let requests: usize = match cmds[3].parse::<usize>() {
//     		Ok(requests) => requests,
//     		Err(err) => {
//     			println!("Failed to parse reqs {} to usize.", cmds[3]);
//     			return None
//     		}
//     	};

//         return Some(Args { nodes: nodes, requests: requests });
//     }

//     None
// }

// // struct Client {
// //     routing_client: RoutingClient,
// //     event_receiver: Receiver<Event>,
// //     command_receiver: Receiver<UserCommand>,
// //     public_id: PublicId,
// //     exit: bool,
// // }

// // impl Client {
// //     fn new() -> Client {
// //         let (event_sender, event_receiver) = mpsc::channel::<Event>();

// //         let full_id = FullId::new();
// //         let public_id = full_id.public_id().clone();
// //         println!("Client has set name {:?}", public_id);
// //         let routing_client = unwrap_result!(RoutingClient::new(event_sender, Some(full_id)));

// //         let (command_sender, command_receiver) = mpsc::channel::<UserCommand>();

// //         let _ = thread!("Command reader", move || {
// //             Client::read_user_commands(command_sender);
// //         });

// //         Client {
// //             routing_client: routing_client,
// //             event_receiver: event_receiver,
// //             command_receiver: command_receiver,
// //             public_id: public_id,
// //             exit: false,
// //         }
// //     }

// //     fn run(&mut self) {
// //         // Need to do poll as Select is not yet stable in the current
// //         // rust implementation.
// //         loop {
// //             while let Ok(command) = self.command_receiver.try_recv() {
// //                 self.handle_user_command(command);
// //             }

// //             if self.exit {
// //                 break;
// //             }

// //             while let Ok(event) = self.event_receiver.try_recv() {
// //                 self.handle_routing_event(event);
// //             }

// //             if self.exit {
// //                 break;
// //             }

// //             let interval = ::std::time::Duration::from_millis(10);
// //             ::std::thread::sleep(interval);
// //         }

// //         println!("Bye");
// //     }

// //     fn read_user_commands(command_sender: Sender<UserCommand>) {
// //         loop {
// //             let mut command = String::new();
// //             let stdin = io::stdin();

// //             print!("Enter command (exit | put <key> <value> | get <key>)\n> ");
// //             let _ = io::stdout().flush();

// //             let _ = stdin.read_line(&mut command);

// //             match parse_user_command(command) {
// //                 Some(cmd) => {
// //                     let _ = command_sender.send(cmd.clone());
// //                     if cmd == UserCommand::Exit {
// //                         break;
// //                     }
// //                 }
// //                 None => {
// //                     println!("Unrecognised command");
// //                     continue;
// //                 }
// //             }
// //         }
// //     }

// //     fn handle_user_command(&mut self, cmd: UserCommand) {
// //         match cmd {
// //             UserCommand::Exit => {
// //                 self.exit = true;
// //             }
// //             UserCommand::Get(what) => {
// //                 self.send_get_request(what);
// //             }
// //             UserCommand::Put(put_where, put_what) => {
// //                 self.send_put_request(put_where, put_what);
// //             }
// //         }
// //     }

// //     fn handle_routing_event(&mut self, event: Event) {
// //         debug!("Client received routing event: {:?}", event);
// //         match event {
// //             Event::Response(msg) => {
// //                 match msg.content {
// //                     ResponseContent::GetSuccess(data) => {
// //                         let plain_data = match data {
// //                             Data::PlainData(plain_data) => plain_data,
// //                             _ => {
// //                                 error!("Node: Only storing plain data in this example");
// //                                 return;
// //                             }
// //                         };
// //                         let (key, value): (String, String) = match deserialise(plain_data.value()) {
// //                             Ok((key, value)) => (key, value),
// //                             Err(_) => {
// //                                 error!("Failed to decode get response.");
// //                                 return;
// //                             }
// //                         };
// //                         println!("Got value {:?} on key {:?}", value, key);
// //                     }
// //                     ResponseContent::PutFailure { ..} => {
// //                         error!("Failed to store");
// //                     }
// //                     _ => error!("Received response {:?}, but not handled in example", msg),
// //                 }
// //             }
// //             _ => (),
// //         }
// //     }

// //     fn send_get_request(&mut self, what: String) {
// //         let name = Client::calculate_key_name(&what);

// //         unwrap_result!(self.routing_client
// //                            .send_get_request(Authority::NaeManager(name.clone()),
// //                                              DataRequest::PlainData(name)));
// //     }

// //     fn send_put_request(&self, put_where: String, put_what: String) {
// //         let name = Client::calculate_key_name(&put_where);
// //         let data = unwrap_result!(serialise(&(put_where, put_what)));

// //         unwrap_result!(self.routing_client
// //                            .send_put_request(Authority::ClientManager(self.public_id
// //                                                                           .name()
// //                                                                           .clone()),
// //                                              Data::PlainData(PlainData::new(name, data))));
// //     }

// //     fn calculate_key_name(key: &String) -> XorName {
// //         XorName::new(crypto::hash::sha512::hash(key.as_bytes()).0)
// //     }
// // }

// fn main() {
//     maidsafe_utilities::log::init(false);

//     let args: Args = Docopt::new(USAGE).and_then(|docopt| docopt.decode())
//                          			   .unwrap_or_else(|error| error.exit());
//     println!("{:?}", args);

//     // if args.flag_node {
//     //     let mut node = Node::new();
//     //     node.run();
//     //     debug!("[key_value_store -> Node Example] Exiting main...");
//     // } else {
//     //     let mut client = Client::new();
//     //     client.run();
//     //     debug!("[key_value_store -> Client Example] Exiting main...");
//     // }
// }
