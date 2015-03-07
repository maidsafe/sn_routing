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

//! The main API for routing nodes (this is where you give the network it's rules)
//! The network will report **From Authority your Authority** and validate cryptographically
//! and via group consensus any message. This means any facade you implement will set out 
//! what you deem to be a valid operation, routing will provide a valid message sender and authority
//! that will allow you to set up many decentralised services
//! See maidsafe.net to see what thye are doing as an example
//! # Use
#![doc(html_logo_url = "http://maidsafe.net/img/Resources/branding/maidsafe_logo.fab2.png",
       html_favicon_url = "http://maidsafe.net/img/favicon.ico",
              html_root_url = "http://doc.rust-lang.org/log/")]
#![warn(missing_docs)]
#![feature(io, collections, slicing_syntax)]

extern crate utp;
use utp::UtpStream;
use std::old_io::net::ip::{Ipv4Addr, SocketAddr};
mod types;

struct IpAddress { address: Ipv4Addr, port: u32 }

trait Facade {
  fn handle_get_response(&self)->u32;
  fn handle_put_response(&self);
  fn handle_post_response(&self);
  }



pub struct RoutingNode<'a> {
facade: &'a mut (Facade + 'a),
}

impl<'a> RoutingNode<'a> {
  fn new(my_facade: &'a mut Facade) -> RoutingNode<'a> {
    RoutingNode { facade: my_facade }
  }

  /// Retreive something from the network (non mutating)   
  pub fn get(&self, name: types::DhtAddress) {}

  /// Add something to the network 
  pub fn put(&self, name: types::DhtAddress, content: Vec<u8>) {}

  /// Mutate something on the network (you must prove ownership)
  pub fn post(&self, name: types::DhtAddress, content: Vec<u8>) {}

  fn add_bootstrap(&self) {}


  fn get_facade(&'a mut self) -> &'a mut Facade {
    self.facade
  }
  
  fn receive_message() {
    
    }

  fn add(self)->u32 {
     self.facade.handle_get_response()

  }
}


#[test]
fn facade_implementation() {

  struct MyFacade;
  
  impl Facade for MyFacade {
    fn handle_get_response(&self)->u32 {
      999u32
      }
    fn handle_put_response(&self) { unimplemented!(); }
    fn handle_post_response(&self) {}  
    } 
  let mut my_facade = MyFacade;
  let mut my_routing = RoutingNode::new(&mut my_facade as &mut Facade);
  assert_eq!(999, my_routing.get_facade().handle_get_response()); 
}
