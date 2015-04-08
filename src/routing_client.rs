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
use std::sync::mpsc::{Receiver, Sender};
use std::sync::mpsc;
use std::net::{TcpStream};
use types;
use Facade;
use message_header;
use messages;

/// DHT node
pub struct RoutingClient<'a> {
    facade: &'a (Facade + 'a),
    sign_public_key: crypto::sign::PublicKey,
    sign_secret_key: crypto::sign::SecretKey,
    encrypt_public_key: crypto::asymmetricbox::PublicKey,
    encrypt_secret_key: crypto::asymmetricbox::SecretKey,
    sender: Sender<TcpStream>,
    receiver: Receiver<TcpStream>,
    //connection_manager: crust::connection_manager::ConnectionManager,
    own_address: Vec<u8>,
    message_id: u32,
}

impl<'a> RoutingClient<'a> {
    pub fn new(my_facade: &'a Facade) -> RoutingClient<'a> {
      sodiumoxide::init(); // enable shared global (i.e. safe to mutlithread now)
      let key_pair = crypto::sign::gen_keypair();
      let encrypt_key_pair = crypto::asymmetricbox::gen_keypair();
      let (tx, rx) : (Sender<TcpStream>, Receiver<TcpStream>) = mpsc::channel();

      RoutingClient { facade: my_facade,
                    sign_public_key: key_pair.0, sign_secret_key: key_pair.1,
                    encrypt_public_key: encrypt_key_pair.0, encrypt_secret_key: encrypt_key_pair.1, sender: tx, receiver: rx,
                    own_address: types::generate_random_vec_u8(64),
                    message_id: 0,
      }
    }

    /// Retreive something from the network (non mutating) - Direct call
    pub fn get(&mut self, type_id: u64, name: types::DhtAddress) {
        // Make GetData message
        let get_data = messages::get_data::GetData {
            requester: types::SourceAddress {
                from_node: self.own_address.clone(), // Should be boost-strap node address ?
                from_group: vec![0; 64], // Dont now what is this so making it invalid
                reply_to: self.own_address.clone(),
            },
            name_and_type_id: types::NameAndTypeId {
                name: name.0.to_vec(),
                type_id: type_id as u32,
            },
        };

        // Serialise GetData message
        let mut encoder = cbor::Encoder::from_memory();
        encoder.encode(&[&get_data]).unwrap();

        // Make MessageHeader
        let header = message_header::MessageHeader::new(
            self.message_id,
            types::DestinationAddress {
                dest: name.0.to_vec(),
                reply_to: vec![0; 64], // None
            },
            get_data.requester.clone(),
            types::Authority::Client,
            types::Signature::generate_random(), // What to do here?
        );

        self.message_id += 1;

        // Make RoutingMessage
        let routing_msg = messages::RoutingMessage::new(
            messages::MessageTypeTag::GetData,
            header,
            encoder.as_bytes().to_vec(),
        );

        // Serialise RoutingMessage
        let mut encoder_routingmsg = cbor::Encoder::from_memory();
        encoder_routingmsg.encode(&[&routing_msg]).unwrap();

        // Give Serialised RoutingMessage to connection manager
        // connection_manager.send(...); // Prakash/Peter will implement this according to mail.
    }

    /// Add something to the network, will always go via ClientManager group
    pub fn put(&self, name: types::DhtAddress, content: Vec<u8>) {
        // Make PutData message
        let put_data = messages::put_data::PutData {
            name_and_type_id: types::NameAndTypeId {
                name: name.0.to_vec(),
                type_id: 0,
            },
            data: content,
        };

        // Serialise PutData message
        let mut encoder = cbor::Encoder::from_memory();
        encoder.encode(&[&put_data]).unwrap();

        // Make MessageHeader
        let header = message_header::MessageHeader::new(
            0, // type_id as u32,
            types::DestinationAddress {
                dest: types::generate_random_vec_u8(64),
                reply_to: self.own_address.clone(),
            },
            types::SourceAddress {
                from_node: types::generate_random_vec_u8(64),
                from_group: types::generate_random_vec_u8(64),
                reply_to: self.own_address.clone(),
            },
            types::Authority::Client,
            types::Signature::generate_random(),
        );

        // Make RoutingMessage
        let routing_msg = messages::RoutingMessage::new(
            messages::MessageTypeTag::GetData,
            header,
            encoder.as_bytes().to_vec(),
        );

        // Serialise RoutingMessage
        let mut encoder_routingmsg = cbor::Encoder::from_memory();
        encoder_routingmsg.encode(&[&routing_msg]).unwrap();

        // Give Serialised RoutingMessage to connection manager
        // connection_manager.send(...); // Prakash/Peter will implement this according to mail.
    }

    /// Mutate something on the network (you must prove ownership) - Direct call
    pub fn post(&self, name: types::DhtAddress, content: Vec<u8>) {
        // Make PutData message
        let post = messages::post::Post {
            name_and_type_id: types::NameAndTypeId {
                name: name.0.to_vec(),
                type_id: 0,
            },
            data: content,
        };

        // Serialise PutData message
        let mut encoder = cbor::Encoder::from_memory();
        encoder.encode(&[&post]).unwrap();

        // Make MessageHeader
        let header = message_header::MessageHeader::new(
            0, // type_id as u32,
            types::DestinationAddress {
                dest: types::generate_random_vec_u8(64),
                reply_to: self.own_address.clone(),
            },
            types::SourceAddress {
                from_node: types::generate_random_vec_u8(64),
                from_group: types::generate_random_vec_u8(64),
                reply_to: self.own_address.clone(),
            },
            types::Authority::Client,
            types::Signature::generate_random(),
        );

        // Make RoutingMessage
        let routing_msg = messages::RoutingMessage::new(
            messages::MessageTypeTag::GetData,
            header,
            encoder.as_bytes().to_vec(),
        );

        // Serialise RoutingMessage
        let mut encoder_routingmsg = cbor::Encoder::from_memory();
        encoder_routingmsg.encode(&[&routing_msg]).unwrap();

        // Give Serialised RoutingMessage to connection manager
        // connection_manager.send(...);
    }

    pub fn start() {

    }

    fn add_bootstrap(&self) {}


    fn get_facade(&'a mut self) -> &'a Facade {
      self.facade
    }
}

// pub struct RoutingClient {
//     sign_public_key: crypto::sign::PublicKey,
//     sign_secret_key: crypto::sign::SecretKey,
//     encrypt_public_key: crypto::asymmetricbox::PublicKey,
//     encrypt_secret_key: crypto::asymmetricbox::SecretKey,
//     connection_manager: crust::connection_manager::ConnectionManager,
// }
// 
// impl RoutingClient {
//     /// Retreive something from the network (non mutating) - Direct call
//     pub fn get(&self, type_id: u64, name: types::DhtAddress) { unimplemented!()}
// 
//     /// Add something to the network, will always go via ClientManager group
//     pub fn put(&self, name: types::DhtAddress, content: Vec<u8>) -> crust::connection_manager::IoResult<()> {
//         let mut encoder = cbor::Encoder::from_memory();
//         let encode_result = encoder.encode(&[&content]);
//         self.connection_manager.send(encoder.into_bytes(), name.0.to_vec())
//     }
// 
//     /// Mutate something on the network (you must prove ownership) - Direct call
//     pub fn post(&self, name: types::DhtAddress, content: Vec<u8>) { unimplemented!() }
// 
//     pub fn start() {
// 
//     }
// 
//     fn add_bootstrap(&self) {}
// }
// 
// impl Random for RoutingClient {
//     fn generate_random() -> RoutingClient {
//         let (tx, rx) = channel::<crust::connection_manager::Event>();
//         let sign_pair = crypto::sign::gen_keypair();
//         let asym_pair = crypto::asymmetricbox::gen_keypair();
// 
//         RoutingClient {
//             sign_public_key: sign_pair.0,
//             sign_secret_key: sign_pair.1,
//             encrypt_public_key: asym_pair.0,
//             encrypt_secret_key: asym_pair.1,
//             connection_manager: crust::connection_manager::ConnectionManager::new(types::generate_random_vec_u8(64), tx/*, rx*/), // TODO(Spandan) how will it rx without storing the receiver
//         }
//     }
// }
