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
use std::io;
use messages::RoutingMessage as Msg;
use std::thread::spawn;
use bchannel::Receiver;
use bchannel::Sender;
use tcp_connections::{listen, connect_tcp, TcpReader, TcpWriter, upgrade_tcp};
use std::sync::{Arc, Mutex, Weak};

pub type Address = Vec<u8>;

type IoResult<T> = Result<T, IoError>;

pub type IoReceiver<T> = Receiver<T, IoError>;
pub type IoSender<T>   = Sender<T, IoError>;

pub type SocketReader = TcpReader<Msg>;
pub type SocketWriter = TcpWriter<Msg>;

type WeakState = Weak<Mutex<State>>;

pub struct ConnectionManager {
    state: Arc<Mutex<State>>,
}

pub enum Event {
    NewMessage(Address, Msg),
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
    
    pub fn connect(&self, endpoint: SocketAddr) -> IoResult<()> {
        let ws = self.state.downgrade();

        spawn(move || {
            let _ = connect_tcp(endpoint)
                    .and_then(|(i, o)| { handle_new_connection(ws, i, o) });
        });

        Ok(())
    }
    
    /// We will send to this address, by getting targets from routing table.
    pub fn send(message: Vec<u8>, address : Address) {
        unimplemented!();
    }
    
    pub fn drop_node(address: Address) {
        unimplemented!();
    }
}

struct State {
    our_id: Address,
    event_pipe: IoSender<Event>,
}

fn with_state<T, F: Fn(&State) -> T>(state: WeakState, f: F) -> IoResult<T> {
    state.upgrade().ok_or(io::Error::new(io::ErrorKind::Interrupted,
                                         "Can't dereference weak",
                                         None))
    .and_then(|arc_state| {
        let opt_state = arc_state.lock();
        match opt_state {
            Ok(s)  => Ok(f(&s)),
            Err(e) => Err(io::Error::new(io::ErrorKind::Interrupted, "?", None))
        }
    })
}

fn start_accepting_connections(state: WeakState) -> IoResult<()> {
    let (listener, port) = try!(listen());

    for (connection, u32) in listener.into_blocking_iter() {
        let _ =
            upgrade_tcp(connection)
            .and_then(|(i, o)| { handle_new_connection(state.clone(), i, o) });
    }

    Ok(())
}

fn handle_new_connection(state: WeakState, i: SocketReader, o: SocketWriter) -> IoResult<()> {
    let (our_id, sink) = try!(with_state(state.clone(), |s| (s.our_id.clone(),
                                                             s.event_pipe.clone())));

    let (i, o, his_id) = try!(exchange(i, o, our_id));
    try!(register_new_writer(state.clone(), his_id.clone(), o));
    start_reading(i, his_id, sink.clone())
}

fn register_new_writer(state: WeakState, his_id: Address, o: SocketWriter) -> IoResult<()> {
    unimplemented!()
}

fn start_reading(i: SocketReader, his_id: Address, sink: IoSender<Event>) -> IoResult<()> {
    unimplemented!()
}

fn exchange(i: SocketReader, o: SocketWriter, our_id: Address)
    -> IoResult<(SocketReader, SocketWriter, Address)> {
    unimplemented!()
    //Ok((i, o, his_id))
}

#[cfg(test)]
mod test {

#[test]
    fn connection_manager() {
    }
}
