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

#![allow(unused_variables)]

extern crate routing;

#[path="data_manager/data_manager.rs"]
mod data_manager;

use self::routing::Authority;
use self::routing::DhtIdentity;
use self::routing::Action;
use self::routing::RoutingError;

use self::data_manager::DataManager;

pub struct VaultFacade {
  data_manager : DataManager
}

impl routing::Facade for VaultFacade {
  fn handle_get(&mut self, our_authority: Authority, from_authority: Authority, from_address: DhtIdentity, data: Vec<u8>)->Result<Action, RoutingError> {
    // let from = self::routing::types::SourceAddress { from_node : self::routing::types::array_as_vector(&from_address.id),
    //     from_group : Vec::<u8>::new(), reply_to : Vec::<u8>::new() };
    self.data_manager.handle_get(&data)
  }

  fn handle_put(&mut self, our_authority: Authority, from_authority: Authority, from_address: DhtIdentity, data: Vec<u8>)->Result<Action, RoutingError> {
    ;
    Err(RoutingError::InvalidRequest)
	// let mut e = cbor::Encoder::from_memory();
	// e.encode(&data).unwrap();
 //    self.store.put(data, e.into_bytes());
 //    Ok(Action::SendOn(from_address))
  }

  fn handle_post(&mut self, our_authority: Authority, from_authority: Authority, from_address: DhtIdentity, data: Vec<u8>)->Result<Action, RoutingError> {
    ;
    Err(RoutingError::InvalidRequest)
  }

  fn handle_get_response(&mut self, from_address: DhtIdentity, response: Result<Vec<u8>, RoutingError>) {
    ;
  }

  fn handle_put_response(&mut self, from_authority: Authority, from_address: DhtIdentity, response: Result<Vec<u8>, RoutingError>) {
    ;
  }

  fn handle_post_response(&mut self, from_authority: Authority, from_address: DhtIdentity, response: Result<Vec<u8>, RoutingError>) {
    ;
  }
}
