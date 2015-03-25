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

extern crate cbor;

use std::net::{UdpSocket, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::io::Result as IoResult;
use std::io::Error as IoError;
use std::io::{ Error };
use cbor::{ CborError }; 
use std::thread::spawn;
use std::marker::PhantomData;
use rustc_serialize::{ Decodable, Encodable };
use bchannel::channel;

pub use bchannel::Receiver;
pub type InBeaconStream<T> = Receiver<T, CborError>;

pub fn array_as_vector(arr: &[u8]) -> Vec<u8> {
  let mut vector = Vec::new();
  for i in arr.iter() {
    vector.push(*i);
  }
  vector
}

pub struct Notification {
  peer_addr : SocketAddr,
  buf : [u8; 1048576]
}

pub struct OutBeaconStream<T> {
  udp_socket: UdpSocket,
  peer_addr : SocketAddr,
  _phantom: PhantomData<T>
}

impl <'a, T> OutBeaconStream<T> where T: Encodable {
  pub fn send(&mut self, m: &T) -> Result<usize, Error> {
    let mut e = cbor::Encoder::from_memory();
    e.encode(&[&m]).unwrap();
    self.udp_socket.send_to(e.as_bytes(), self.peer_addr)
  }

  pub fn close(self) {
    // instead of closing the whole socket, stop expecting msg from it
    // drop(self.udp_socket);
    if (self.udp_socket.leave_multicast(&self.peer_addr)).is_err() {
      panic!("can not disconnect the specified udp peer");
    }
  }
}

/// Connect to a server and open a send-receive pair.  See `upgrade` for more details.
pub fn connect_udp<'a, 'b, I, O>(addr: SocketAddr, peer_addr: SocketAddr) ->
  IoResult<(Receiver<I, CborError>, OutBeaconStream<O>)>
      where I: Send + Decodable + 'static, O: Encodable {
  Ok(try!(upgrade_udp(try!(UdpSocket::bind(&addr)), peer_addr)))
}

pub fn listen()  -> IoResult<(Receiver<Notification, IoError>, UdpSocket)> {
  let live_address = SocketAddrV4::new(Ipv4Addr::new(0,0,0,0), 5483);
  // let any_address = SocketAddrV4::new(Ipv4Addr::new(0,0,0,0), 0);
  let socket = try!(UdpSocket::bind(live_address));
  let (tx, rx) = channel();
  let socket2 = try!(socket.try_clone());
  spawn(move || {
    loop {
      if tx.is_closed() {
        break;
      }
      let mut buf = [0; 1024 * 1024];
      let result = socket2.recv_from(&mut buf);
      if result.is_ok() {
        let (amt, src) = result.unwrap();
        if amt > 0 {
          if tx.send(Notification{peer_addr: src, buf: buf}).is_err() {
            continue;
          }
        }
        // put the new sender under monitor
        if socket2.join_multicast(&src).is_err() {
          panic!("can not expecting another udp peer");
        }
      }
    }
    drop(socket2);
  });
  Ok((rx, socket))
}


// Almost a straight copy of https://github.com/TyOverby/wire/blob/master/src/tcp.rs
/// Upgrades an UdpSocket to a Sender-Receiver pair that you can use to send and
/// receive objects automatically.  If there is an error decoding or encoding
/// values, that respective part is shut down.
pub fn upgrade_udp<'a, 'b, I, O>(udp_socket: UdpSocket, peer_addr: SocketAddr)
    -> IoResult<(InBeaconStream<I>, OutBeaconStream<O>)> where I: Send + Decodable + 'static, O: Encodable {
  let s1 = udp_socket;
  let s2 = try!(s1.try_clone());
  Ok((upgrade_reader(s1, peer_addr), upgrade_writer(s2, peer_addr)))
}

fn upgrade_writer<'a, T>(udp_socket: UdpSocket, peer_addr: SocketAddr) -> OutBeaconStream<T> where T: Encodable {
  OutBeaconStream { udp_socket: udp_socket, peer_addr: peer_addr, _phantom: PhantomData }
}

fn upgrade_reader<'a, T>(socket: UdpSocket, peer_address : SocketAddr)
    -> InBeaconStream<T> where T: Send + Decodable + 'static {
  let (in_snd, in_rec) = channel();
  spawn(move || {
    let mut buf = [0; 1024 * 1024];
    loop {
      let result = socket.recv_from(&mut buf);
      if result.is_ok() {
        let (amt, src) = result.unwrap();
        // only process the incoming msg when it is expected
        if amt > 0 && src == peer_address {
          let mut d = cbor::Decoder::from_bytes(array_as_vector(&buf));
          let received: T = d.decode().next().unwrap().unwrap();
          if in_snd.send(received).is_err() {
            break;
          }
        }
      }
    }
    // instead of closing the whole socket, stop expecting msg from it
    // drop(self.udp_socket);
    if (socket.leave_multicast(&peer_address)).is_err() {
      panic!("can not disconnect the specified udp peer");
    }
  });
  in_rec
}

