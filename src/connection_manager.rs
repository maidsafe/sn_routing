// Copyright 2015 MaidSafe.net limited
// This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
// By contributing code to the MaidSafe Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
// directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
// available at: http://www.maidsafe.net/licenses
// Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
// OF ANY KIND, either express or implied.
// See the Licences for the specific language governing permissions and limitations relating to
// use of the MaidSafe
// Software.                                                                 

use std::net::{SocketAddr};
use std::io::Error as IoError;
use messages::RoutingMessage;
use std::thread::spawn;
use bchannel::Receiver;
use bchannel::Sender;
use tcp_connections::listen;
use std::sync::{Arc, Mutex, Weak};

pub type Address = Vec<u8>;

// use net::ip::SocketAddr;
type IoResult<T> = Result<T, IoError>;

pub type IoReceiver<T> = Receiver<T, IoError>;
pub type IoSender<T>   = Sender<T, IoError>;

/// Will hold tcp udt sentinel routing_table beacon boostrap_file
pub struct ConnectionManager {
    //routing_table: routing_table::RoutingTable,
    //boostrap_list: bootstrap::BootStrapHandler,
    state: Arc<Mutex<State>>,
}

pub enum Event {
    NewMessage(Address, RoutingMessage),
    NewConnection(Address),
    LostConnection(Address),
    AcceptingOn(u16)
}

impl ConnectionManager {
pub fn new(our_id: Address, event_pipe: IoSender<Event>) -> ConnectionManager {
    let state = Arc::new(Mutex::new(State{ our_id: our_id, event_pipe: event_pipe }));
    
    let weak_state = state.downgrade();

    spawn(move || {
        let _ = start_accepting_connections(weak_state);
    });

    ConnectionManager { state: state }
}

pub fn connect(endpoint: SocketAddr) {
    unimplemented!();
}

/// We will send to this address, by getting targets from routing table.
pub fn send(message: Vec<u8>, address : Address) {
    unimplemented!();
}

pub fn drop_node(address: Address) {
    unimplemented!();
}

///// We add connections the routing table tells us are nodes
//fn maintain_connection(socket: SocketAddr) {}
///// will send a message to another node with our interested node included in message
///// the other node will try and connect to the interested node and report back to 
///// us if it can connect. If so its a good bootstrap node
//fn send_nat_traverse_message() {}
//
///// Acting as a rquest form another node, we will try and connect to the node they suggest
///// and send back a response IF we can connect, drop otherwise
//fn handle_nat_traverse_message() {}
//
///// A node we have asked about is actually able to be connected to as though direct
//fn handle_nat_traverse_response() {}
//
//
///// this is a routing message may be 
///// connect connect response get_key etc. as well as JOIN LEAVE 
///// Only nodes from connect response / connect will be added to 
///// routing table
//fn handle_message() {}

}

struct State {
    our_id: Address,
    event_pipe: IoSender<Event>,
}

fn send_message_to_user(state: Weak<Mutex<State>>) -> Result<(), ()> {
    let opt_arc_state = state.upgrade();
    if opt_arc_state.is_none() { return Err(()) }
    let arc_state = opt_arc_state.unwrap();
    let state = arc_state.lock();
    Ok(())
}

fn start_accepting_connections(state: Weak<Mutex<State>>) -> IoResult<()> {
    //unimplemented!();
    //let state = try!(state.upgrade());
    let (listener, port) = try!(listen());

    for (connection, u32) in listener.into_blocking_iter() {
    }

    Ok(())
}

