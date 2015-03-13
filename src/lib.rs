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
              html_root_url = "http://dirvine.github.io/routing")]
#![warn(missing_docs)]
#![feature(io, collections, slicing_syntax, custom_derive)]

extern crate sodiumoxide;
extern crate "rustc-serialize" as rustc_serialize;
extern crate cbor;
extern crate utp;

use std::str::FromStr;
use std::io::{stdin, stdout, stderr, Write};
use std::net::{TcpListener, TcpStream, IpAddr, SocketAddr};
use std::thread;
use sodiumoxide::crypto;
use std::sync::mpsc;
use std::sync::mpsc::{Sender, Receiver};
use std::default::Default;
mod types;
mod connections;

//#[derive(RustcEncodable, RustcDecodable)]
struct SignedKey {
sign_public_key: crypto::sign::PublicKey,
encrypt_public_key: crypto::asymmetricbox::PublicKey,
signature: crypto::sign::Signature // detached signature  
}

//#[derive(RustcEncodable, RustcDecodable, Default)]
pub struct DhtIdentity {
id: [u8; 64]  
}

impl Default for DhtIdentity {
  #[inline]
  fn default()->DhtIdentity {
    DhtIdentity { id: [0; 64] }
  }
}

impl DhtIdentity {
  /* fn name(&self) { */
  /*  msgpack::Encoder::to_msgpack(&self.signed_key).ok().unwrap()  */
  /* }   */
  
}

enum Authority {
Client,
Node,
ClientManager,
NaeManager,
NodeManager  
}

pub enum GetReply {
  Data(Vec<u8>),
  SendOn(DhtIdentity)
}

pub enum PutPostReply {
  Data(Vec<u8>),
  SendOn(DhtIdentity)
}

pub enum RoutingError {
NoData,
InvalidRequest  
}

trait Facade : Sync {
  fn handle_get(&self, our_authority: Authority, from_authority: Authority, from_address: DhtIdentity, data: Vec<u8>);
  fn handle_put(&self, our_authority: Authority, from_authority: Authority, from_address: DhtIdentity, data: Vec<u8>);
  fn handle_post(&self, our_authority: Authority, from_authority: Authority, from_address: DhtIdentity, data: Vec<u8>);
  fn handle_get_response(&self, our_authority: Authority, from_authority: Authority, from_address: DhtIdentity, data: Vec<u8>)->u32;
  fn handle_put_response(&self, our_authority: Authority, from_authority: Authority, from_address: DhtIdentity, data: Vec<u8>);
  fn handle_post_response(&self, our_authority: Authority, from_authority: Authority, from_address: DhtIdentity, data: Vec<u8>);
  }

/// DHT node 
pub struct RoutingNode<'a> {
facade: &'a (Facade + 'a),
sign_public_key: crypto::sign::PublicKey,
sign_secret_key: crypto::sign::SecretKey,
encrypt_public_key: crypto::asymmetricbox::PublicKey,
encrypt_secret_key: crypto::asymmetricbox::SecretKey,
sender: Sender<TcpStream>, 
receiver: Receiver<TcpStream>
}

impl<'a> RoutingNode<'a> {
  fn new(my_facade: &'a Facade) -> RoutingNode<'a> {
    sodiumoxide::init(); // enable shared global (i.e. safe to mutlithread now)
    let key_pair = crypto::sign::gen_keypair(); 
    let encrypt_key_pair = crypto::asymmetricbox::gen_keypair(); 
    let (tx, rx) : (Sender<TcpStream>, Receiver<TcpStream>) = mpsc::channel();

    RoutingNode { facade: my_facade, 
                  sign_public_key: key_pair.0, sign_secret_key: key_pair.1,
                  encrypt_public_key: encrypt_key_pair.0, encrypt_secret_key: encrypt_key_pair.1, sender: tx, receiver: rx }
  }

  /// Retreive something from the network (non mutating)   
  pub fn get(&self, name: types::DhtAddress)->Result<GetReply, RoutingError> { unimplemented!()}

  /// Add something to the network 
  pub fn put(&self, name: types::DhtAddress, content: Vec<u8>)->Result<PutPostReply, RoutingError> { unimplemented!() }

  /// Mutate something on the network (you must prove ownership)
  pub fn post(&self, name: types::DhtAddress, content: Vec<u8>)->Result<PutPostReply, RoutingError> { unimplemented!() }
  
  pub fn start() {
    
  }
  
  fn add_bootstrap(&self) {}


  fn get_facade(&'a mut self) -> &'a Facade {
    self.facade
  }
}


#[test]
fn facade_implementation() {

  struct MyFacade;
  
  impl Facade for MyFacade {
    fn handle_get(&self, our_authority: Authority, from_authority: Authority,from_address: DhtIdentity , data: Vec<u8>) { unimplemented!(); }
    fn handle_put(&self, our_authority: Authority, from_authority: Authority,from_address: DhtIdentity , data: Vec<u8>) { unimplemented!(); }
    fn handle_post(&self, our_authority: Authority, from_authority: Authority,from_address: DhtIdentity , data: Vec<u8>) { unimplemented!(); }
    fn handle_get_response(&self, our_authority: Authority, from_authority: Authority,from_address: DhtIdentity , data: Vec<u8>)->u32 { 999u32 }
    fn handle_put_response(&self, our_authority: Authority, from_authority: Authority,from_address: DhtIdentity , data: Vec<u8>) { unimplemented!(); }
    fn handle_post_response(&self, our_authority: Authority, from_authority: Authority,from_address: DhtIdentity , data: Vec<u8>) { unimplemented!(); }  
  } 
  let my_facade = MyFacade;
  let mut my_routing = RoutingNode::new(&my_facade as & Facade);
  /* assert_eq!(999, my_routing.get_facade().handle_get_response());  */
}
