/*  Copyright 2014 MaidSafe.net limited
    This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
    version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
    licence you accepted on initial access to the Software (the "Licences").
    By contributing code to the MaidSafe Software, or to this project generally, you agree to be
    bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
    directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
    available at: http://www.maidsafe.net/licenses
    Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
    under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
    OF ANY KIND, either express or implied.
    See the Licences for the specific language governing permissions and limitations relating to
    use of the MaidSafe
    Software.                                                                 */


use std::net::{TcpListener, TcpStream, Ipv4Addr, SocketAddrV4};
use std::io::{stdout, stderr, Write};
use std::sync::mpsc::{Sender};


/// Tcp and Udt Connections 
pub struct Connections {
  /* utp: UtpStream, */
  tcp: TcpListener,
  sender: Sender<TcpStream>
}

impl Connections {
  fn new(sender: Sender<TcpStream>) -> Connections {
    let live_address = SocketAddrV4::new(Ipv4Addr::new(127,0,0,1), 5483);
    let any_address = SocketAddrV4::new(Ipv4Addr::new(127,0,0,1), 0);
    let tcp_listener = match TcpListener::bind(&live_address) {
      Ok(x) => x,
      Err(_) => TcpListener::bind(&any_address).unwrap()
    };
    // [TODO]: Wait of Utp updating to std::net - 2015-03-08 01:11pm
    /* let mut utp_stream =   match  UtpStream::bind(&live_address)  { */
    /*   Ok(x) => x, */
    /*   Err(_) => UtpStream::bind(&any_address).unwrap() */
    /* }; */
    let writer = stdout();
    let _ = writeln!(&mut stderr(), "Serving Tcp on {:?}", tcp_listener.local_addr());
    /* let _ = writeln!(&mut stderr(), "Serving Utp on {}", &live_address); */
      

    Connections { /* utp: utp_stream,  */tcp: tcp_listener, sender: sender }
  }
 // see https://avacariu.me/articles/rust-echo-server-example.html 
  fn tcp_listener(&self) {
      for stream in self.tcp.incoming() {
        match stream {

        Ok(stream) => {
          /* thread::spawn(move || { */
          self.sender.clone().send(stream).unwrap();
          /* }); */

        }
        Err(e) => { /* connection failed */ }
        }
      }
  }
  
  fn receive_tcp_message(&self, message: TcpStream) {
    
  }
}

