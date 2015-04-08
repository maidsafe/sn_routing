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

use sodiumoxide;
use crust;
use std::sync::mpsc;
use sodiumoxide::crypto;
use std::sync::mpsc::{Receiver};
use facade::*;
use super::*;

type ConnectionManager = crust::ConnectionManager<DhtId>;
type Event             = crust::Event<DhtId>;

/// DHT node
pub struct RoutingNode<'a> {
    facade: &'a (Facade + 'a),
    sign_public_key: crypto::sign::PublicKey,
    sign_secret_key: crypto::sign::SecretKey,
    encrypt_public_key: crypto::asymmetricbox::PublicKey,
    encrypt_secret_key: crypto::asymmetricbox::SecretKey,
    event_input: Receiver<Event>,
    connections: ConnectionManager
}

impl<'a> RoutingNode<'a> {
    pub fn new(id: DhtId, my_facade: &'a Facade) -> RoutingNode<'a> {
        sodiumoxide::init(); // enable shared global (i.e. safe to mutlithread now)
        let key_pair = crypto::sign::gen_keypair();
        let encrypt_key_pair = crypto::asymmetricbox::gen_keypair();
        let (event_output, event_input) = mpsc::channel();
        
        RoutingNode { facade: my_facade,
                      sign_public_key: key_pair.0,
                      sign_secret_key: key_pair.1,
                      encrypt_public_key: encrypt_key_pair.0,
                      encrypt_secret_key: encrypt_key_pair.1,
                      event_input: event_input,
                      connections: crust::ConnectionManager::new(id, event_output)
                    }
    }
    
    /// Retreive something from the network (non mutating) - Direct call
    pub fn get(&self, type_id: u64, name: DhtId) { unimplemented!() }
    
    /// Add something to the network, will always go via ClientManager group
    pub fn put(&self, name: DhtId, content: Vec<u8>) { unimplemented!() }
    
    /// Mutate something on the network (you must prove ownership) - Direct call
    pub fn post(&self, name: DhtId, content: Vec<u8>) { unimplemented!() }
    
    pub fn start(&self) {
        //self.connections.start_accepting();
    }
    
    fn add_bootstrap(&self) {}
    
    fn get_facade(&'a mut self) -> &'a Facade {
        self.facade
    }
}

#[cfg(test)]
mod test {
    use routing_node::{RoutingNode};
    use facade::{Facade};
    use maidsafe_types::NameType;
    use types::{Authority, DhtId};
    use super::super::{Action, RoutingError, DestinationAddress};

    struct NullFacade;

    impl Facade for NullFacade {
      fn handle_get(&mut self, type_id: u64, our_authority: Authority, from_authority: Authority,from_address: DhtId , data: Vec<u8>)->Result<Action, RoutingError> { Err(RoutingError::Success) }
      fn handle_put(&mut self, our_authority: Authority, from_authority: Authority,
                    from_address: DhtId, dest_address: DestinationAddress, data: Vec<u8>)->Result<Action, RoutingError> { Err(RoutingError::Success) }
      fn handle_post(&mut self, our_authority: Authority, from_authority: Authority, from_address: DhtId, data: Vec<u8>)->Result<Action, RoutingError> { Err(RoutingError::Success) }
      fn handle_get_response(&mut self, from_address: DhtId , response: Result<Vec<u8>, RoutingError>) { }
      fn handle_put_response(&mut self, from_authority: Authority,from_address: DhtId , response: Result<Vec<u8>, RoutingError>) { }
      fn handle_post_response(&mut self, from_authority: Authority,from_address: DhtId , response: Result<Vec<u8>, RoutingError>) { }
      fn add_node(&mut self, node: NameType) {}
      fn drop_node(&mut self, node: NameType) {}
    }

    //#[test]
    fn test_routing_node() {
        let facade = NullFacade;
        let n = RoutingNode::new(DhtId::generate_random(), &facade);
    }
}
