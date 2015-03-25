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
use std::thread::spawn;
use rustc_serialize::{ Encodable };
use bchannel::channel;

pub use bchannel::Receiver;

pub struct Notification {
  peer_addr : SocketAddr,
  buf : [u8; 1024 * 1024]
}

pub fn broadcast<T>(m: &T) -> IoResult<Receiver<Notification, IoError>> where T: Encodable {
  let live_address = SocketAddrV4::new(Ipv4Addr::new(127,0,0,1), 5483);
  let any_address = SocketAddrV4::new(Ipv4Addr::new(0,0,0,0), 0);
  let socket = try!(UdpSocket::bind(live_address));
  let mut e = cbor::Encoder::from_memory();
  e.encode(&[&m]).unwrap();
  let send_result = socket.send_to(e.as_bytes(), any_address);
  if send_result.is_err() {
    return Err(send_result.err().unwrap());
  }
  let (tx, rx) = channel();
  spawn(move || {
    loop {
      if tx.is_closed() {
        break;
      }
      let mut buf = [0; 1024 * 1024];
      let result = socket.recv_from(&mut buf);
      if result.is_ok() {
        let (amt, src) = result.unwrap();
        if amt > 0 {
          if tx.send(Notification{peer_addr: src, buf: buf}).is_err() {
            continue;
          }
        }
      }
    }
    drop(socket);
  });
  Ok(rx)
}
