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
use crust::connection_manager::*;
use std::sync::mpsc;
use sodiumoxide::crypto;
use std::sync::mpsc::{Receiver};
use std::net::{TcpStream};
use super::*;

/// DHT node
pub struct RoutingNode<'a> {
    facade: &'a (Facade + 'a),
    sign_public_key: crypto::sign::PublicKey,
    sign_secret_key: crypto::sign::SecretKey,
    encrypt_public_key: crypto::asymmetricbox::PublicKey,
    encrypt_secret_key: crypto::asymmetricbox::SecretKey,
    //sender: Sender<TcpStream>,
    //receiver: Receiver<TcpStream>,
    event_input: Receiver<Event>,
    //connections: ConnectionManager
}

impl<'a> RoutingNode<'a> {
    pub fn new(/*id: types::DhtAddress, */my_facade: &'a Facade) -> RoutingNode<'a> {
        sodiumoxide::init(); // enable shared global (i.e. safe to mutlithread now)
        let key_pair = crypto::sign::gen_keypair();
        let encrypt_key_pair = crypto::asymmetricbox::gen_keypair();
        let (event_output, event_input) = mpsc::channel();
        
        //let types::DhtAddress(id) = id;

        RoutingNode { facade: my_facade,
                      sign_public_key: key_pair.0,
                      sign_secret_key: key_pair.1,
                      encrypt_public_key: encrypt_key_pair.0,
                      encrypt_secret_key: encrypt_key_pair.1,
                      event_input: event_input,
                      //connections: ConnectionManager::new(vec![0], event_output)
                    }
    }
    
    /// Retreive something from the network (non mutating) - Direct call
    pub fn get(&self, type_id: u64, name: types::DhtAddress) { unimplemented!()}
    
    /// Add something to the network, will always go via ClientManager group
    pub fn put(&self, name: types::DhtAddress, content: Vec<u8>) { unimplemented!() }
    
    /// Mutate something on the network (you must prove ownership) - Direct call
    pub fn post(&self, name: types::DhtAddress, content: Vec<u8>) { unimplemented!() }
    
    pub fn start() { }
    
    fn add_bootstrap(&self) {}
    
    fn get_facade(&'a mut self) -> &'a Facade {
        self.facade
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn test_routing_node() {
    }
}
