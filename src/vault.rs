/*  Copyright 2015 MaidSafe.net limited
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

// extern crate Routing;
// extern crate sodiumoxide;
// extern crate "lru-cache" as lru_cache;
// extern crate "rustc-serialize" as rustc_serialize;
// extern crate cbor;
// extern crate time;
// extern crate bchannel;
//
// use std::net::{TcpStream};
// use sodiumoxide::crypto;
// use std::sync::mpsc;
// use std::sync::mpsc::{Sender, Receiver};
// use std::default::Default;
//
//
// use pmid_node::PmidNode;
// use self::Routing::Authority;
// use self::Routing::DhtIdentity;
// use self::Routing::Action;
// use self::Routing::RoutingError;
//
// impl Routing::Facade for PmidNode {
//   fn handle_get(&self, our_authority: Authority, from_authority: Authority, from_address: DhtIdentity, data: Vec<u8>)->Result<Action, RoutingError> {
//     let get_result = self.store.get(data);
//     Ok(Action::Reply(get_result))
//   }
//
//   fn handle_put(&mut self, our_authority: Authority, from_authority: Authority, from_address: DhtIdentity, data: Vec<u8>)->Result<Action, RoutingError> {
// 	let mut e = cbor::Encoder::from_memory();
// 	e.encode(&data).unwrap();
//     self.store.put(data, e.into_bytes());
//     Ok(Action::SendOn(from_address))
//   }
//
//   fn handle_post(&self, our_authority: Authority, from_authority: Authority, from_address: DhtIdentity, data: Vec<u8>)->Result<Action, RoutingError> {
//     ;
//     Err(RoutingError::InvalidRequest)
//   }
//
//   fn handle_get_response(&self, from_address: DhtIdentity, response: Result<Vec<u8>, RoutingError>) {
//     ;
//   }
//
//   fn handle_put_response(&self, from_authority: Authority, from_address: DhtIdentity, response: Result<Vec<u8>, RoutingError>) {
//     ;
//   }
//
//   fn handle_post_response(&self, from_authority: Authority, from_address: DhtIdentity, response: Result<Vec<u8>, RoutingError>) {
//     ;
//   }
// }
