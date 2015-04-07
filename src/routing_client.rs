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

extern crate crust;
extern crate sodiumoxide;
extern crate cbor;
extern crate maidsafe_types;

use sodiumoxide::crypto;
use maidsafe_types::Random;
use std::sync::mpsc::{Receiver, Sender, channel};
use types;

pub struct RoutingClient {
    sign_public_key: crypto::sign::PublicKey,
    sign_secret_key: crypto::sign::SecretKey,
    encrypt_public_key: crypto::asymmetricbox::PublicKey,
    encrypt_secret_key: crypto::asymmetricbox::SecretKey,
    connection_manager: crust::connection_manager::ConnectionManager,
}

impl RoutingClient {
    /// Retreive something from the network (non mutating) - Direct call
    pub fn get(&self, type_id: u64, name: types::DhtAddress) { unimplemented!()}

    /// Add something to the network, will always go via ClientManager group
    pub fn put(&self, name: types::DhtAddress, content: Vec<u8>) -> crust::connection_manager::IoResult<()> {
        let mut encoder = cbor::Encoder::from_memory();
        let encode_result = encoder.encode(&[&content]);
        self.connection_manager.send(encoder.into_bytes(), name.0.to_vec())
    }

    /// Mutate something on the network (you must prove ownership) - Direct call
    pub fn post(&self, name: types::DhtAddress, content: Vec<u8>) { unimplemented!() }

    pub fn start() {

    }

    fn add_bootstrap(&self) {}
}

impl Random for RoutingClient {
    fn generate_random() -> RoutingClient {
        let (tx, rx) = channel::<crust::connection_manager::Event>();
        let sign_pair = crypto::sign::gen_keypair();
        let asym_pair = crypto::asymmetricbox::gen_keypair();

        RoutingClient {
            sign_public_key: sign_pair.0,
            sign_secret_key: sign_pair.1,
            encrypt_public_key: asym_pair.0,
            encrypt_secret_key: asym_pair.1,
            connection_manager: crust::connection_manager::ConnectionManager::new(types::generate_random_vec_u8(64), tx/*, rx*/), // TODO(Spandan) how will it rx without storing the receiver
        }
    }
}
