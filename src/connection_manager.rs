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
use std::collections::HashMap;
use std::thread::spawn;
use bchannel::Receiver;
use bchannel::Sender;
use tcp_connections::{listen, connect_tcp, TcpReader, TcpWriter, upgrade_tcp};
use std::sync::{Arc, Mutex, Weak};
use std::sync::mpsc;
use cbor::{Encoder, Decoder};
use rustc_serialize::{Decodable, Encodable};

//use types::Address;

pub type Address = Vec<u8>;
pub type Bytes   = Vec<u8>;

pub type IoResult<T> = Result<T, IoError>;

pub type IoReceiver<T> = Receiver<T, IoError>;
pub type IoSender<T>   = Sender<T, IoError>;

pub type SocketReader = TcpReader<Bytes>;
pub type SocketWriter = TcpWriter<Bytes>;

type WeakState = Weak<Mutex<State>>;

pub struct ConnectionManager {
    state: Arc<Mutex<State>>,
}

#[derive(Debug)]
pub enum Event {
    NewMessage(Address, Bytes),
    NewConnection(Address),
    LostConnection(Address),
    AcceptingOn(u16)
}

impl ConnectionManager {

    pub fn new(our_id: Address, event_pipe: IoSender<Event>) -> ConnectionManager {
        let writer_channels: HashMap<Address, mpsc::Sender<Bytes>> = HashMap::new();
        let state = Arc::new(Mutex::new(State{ our_id: our_id, event_pipe: event_pipe,
                                               writer_channels : writer_channels }));
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

    /// Sends a message to address. Returns Ok(()) if the sending might succeed, and returns an
    /// Err if the address is not connected. Return value of Ok does not mean that the data will be
    /// received. It is possible for the corresponding connection to hang up immediately after this
    /// function returns Ok.
    pub fn send(&self, message: Bytes, address : Address)-> IoResult<()> {
    let ws = self.state.downgrade();
    let writer_channel = try!(with_state(&ws, |s| {
        match s.writer_channels.get(&address) {
            Some(x) =>  Ok(x.clone()),
            None => Err(io::Error::new(io::ErrorKind::NotConnected, "?", None))
        }
    }));
    // writer_channel.unwrap().send(message)  // TODO(team) need to convert SendError to IoResult
        Ok(())
    }

    pub fn drop_node(address: Address) {
        unimplemented!();
    }
}

struct State {
    our_id: Address,
    event_pipe: IoSender<Event>,
    writer_channels: HashMap<Address, mpsc::Sender<Bytes>>,
}

fn with_state<T, F: Fn(&State) -> T>(state: &WeakState, f: F) -> IoResult<T> {
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
    println!("start_accepting_connections");
    let (event_receiver, listener) = try!(listen());

    let local_port = try!(listener.local_addr()).port();

    try!(with_state(&state, |s| {
        s.event_pipe.send(Event::AcceptingOn(local_port));
    }));

    for (connection, u32) in event_receiver.into_blocking_iter() {
        println!("start_accepting_connections accepted");
        let _ =
            upgrade_tcp(connection)
            .and_then(|(i, o)| { handle_new_connection(state.clone(), i, o) });
    }

    Ok(())
}

fn handle_new_connection(state: WeakState, i: SocketReader, o: SocketWriter) -> IoResult<()> {
    let (our_id, sink) = try!(with_state(&state, |s| (s.our_id.clone(),
                                                      s.event_pipe.clone())));

    let (i, o, his_data) = try!(exchange(i, o, encode(&our_id)));
    let his_id: Address = decode(his_data);
    println!("handle_new_connection our_id:{:?} his_id:{:?}", our_id, his_id);
    try!(register_new_writer(state.clone(), his_id.clone(), o));
    start_reading(i, his_id, sink.clone())
}

fn register_new_writer(state: WeakState, his_id: Address, o: SocketWriter) -> IoResult<()> {
    unimplemented!()
}

// pushing events out to event_pipe
fn start_reading(i: SocketReader, his_id: Address, sink: IoSender<Event>) -> IoResult<()> {
    spawn(move || {
        for msg in i.into_blocking_iter() {
            if sink.send(Event::NewMessage(his_id.clone(), msg)).is_err() {
              return;  // exit thread if sink closed
            }
        }
        sink.send(Event::LostConnection(his_id.clone()));
    });
    Ok(())
}

// pushing messges out to socket
fn start_writing_thread(mut o: SocketWriter, his_id: Address, writer_channel: mpsc::Receiver<Bytes>) -> IoResult<()> {
    spawn (move || {
         loop {
            let mut writer_iter = writer_channel.iter();
            let msg = match writer_iter.next() {
                None => { break; }
                Some(msg) => {
                    if o.send(&msg).is_err() {
                        break;
                    }
                }
            };
        }
        // FIXME remove entry from the map and send to sink
        });
    Ok(())
}

fn exchange(socket_input:  SocketReader, socket_output: SocketWriter, data: Bytes)
            -> IoResult<(SocketReader, SocketWriter, Bytes)>
{
    let (output, input) = mpsc::channel();

    spawn(move || {
        let mut s = socket_output;
        if s.send(&data).is_err() {
            return;
        }
        let _ = output.send(s);
    });

    let opt_result = socket_input.recv_block();
    let opt_send_result = input.recv();

    let cant_send = io::Error::new(io::ErrorKind::Other,
                                   "Can't exchage (send error)", None);
    let cant_recv = io::Error::new(io::ErrorKind::Other,
                                   "Can't exchage (send error)", None);

    let socket_output = try!(opt_send_result.map_err(|_|cant_send));
    let result = try!(opt_result.ok_or(cant_recv));

    Ok((socket_input, socket_output, result))
}

fn encode<T>(value: &T) -> Bytes where T: Encodable
{
    let mut enc = Encoder::from_memory();
    let _ = enc.encode(&[value]);
    enc.into_bytes()
}

// TODO(Peter): This should return Option<T>
fn decode<T>(bytes: Bytes) -> T where T: Decodable {
    let mut dec = Decoder::from_bytes(bytes.as_slice());
    dec.decode().next().unwrap().unwrap()
}

#[cfg(test)]
mod test {
    use super::*;
    use std::thread::spawn;
    use bchannel;
    use std::net::{SocketAddr};
    use std::str::FromStr;

#[test]
    fn connection_manager() {
        let spawn_node = |id| {
            spawn(||{
                let (i, o) = bchannel::channel();
                let cm = ConnectionManager::new(id, i);
                for i in o.into_blocking_iter() {
                    match i {
                        Event::AcceptingOn(port) => {
                            if (port != 5483) {
                                let addr = SocketAddr::from_str("127.0.0.1:5483").unwrap();
                                cm.connect(addr);
                            }
                        },
                        _ => println!("unhandled"),
                    }
                }
            })
        };

        let t1 = spawn_node(vec![1]);
        let t2 = spawn_node(vec![2]);

        t1.join();
        t2.join();
    }
}
