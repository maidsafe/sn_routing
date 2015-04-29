// Copyright 2015 MaidSafe.net limited
//
// This Safe Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the Safe Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
// directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
// available at: http://maidsafe.net/network-platform-licensing
//
// Unless required by applicable law or agreed to in writing, the Safe Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
// OF ANY KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations relating to
// use of the Safe Network Software.

use cbor;
use rand;
use rustc_serialize;
use rustc_serialize::{Decodable, Encodable};
use sodiumoxide;
use sodiumoxide::crypto;
use std::io::Error as IoError;
use std::sync::{Mutex, Arc, mpsc};
use std::thread;

use client_interface::Interface;
use crust;
use messages;
use message_header;
use name_type::NameType;
use sendable::Sendable;
use types;

pub use crust::Endpoint;

type ConnectionManager = crust::ConnectionManager;
type Event = crust::Event;

pub enum CryptoError {
    Unknown
}

#[derive(Clone)]
pub struct ClientIdPacket {
    public_keys: (crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey),
    secret_keys: (crypto::sign::SecretKey, crypto::asymmetricbox::SecretKey),
}

impl ClientIdPacket {
    pub fn new(public_keys: (crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey),
               secret_keys: (crypto::sign::SecretKey, crypto::asymmetricbox::SecretKey)) -> ClientIdPacket {
        ClientIdPacket {
            public_keys: public_keys,
            secret_keys: secret_keys
        }
    }

    //FIXME(ben 2015-04-22) :
    //  pub fn get_id(&self) -> [u8; NameType::NAME_TYPE_LEN] {
    //  gives a rustc compiler error; follow up and report bug
    pub fn get_id(&self) -> [u8; 64usize] {

      let sign_arr = &(self.public_keys.0).0;
      let asym_arr = &(self.public_keys.1).0;

      let mut arr_combined = [0u8; 64 * 2];

      for i in 0..sign_arr.len() {
         arr_combined[i] = sign_arr[i];
      }
      for i in 0..asym_arr.len() {
         arr_combined[64 + i] = asym_arr[i];
      }

      let digest = crypto::hash::sha512::hash(&arr_combined);
      digest.0
    }

    pub fn get_name(&self) -> NameType {
      NameType::new(self.get_id())
    }

    pub fn get_public_keys(&self) -> &(crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey){
        &self.public_keys
    }

    pub fn sign(&self, data : &[u8]) -> crypto::sign::Signature {
        return crypto::sign::sign_detached(&data, &self.secret_keys.0)
    }

    pub fn encrypt(&self, data : &[u8], to : &crypto::asymmetricbox::PublicKey) -> (Vec<u8>, crypto::asymmetricbox::Nonce) {
        let nonce = crypto::asymmetricbox::gen_nonce();
        let encrypted = crypto::asymmetricbox::seal(data, &nonce, &to, &self.secret_keys.1);
        return (encrypted, nonce);
    }

    pub fn decrypt(&self, data : &[u8], nonce : &crypto::asymmetricbox::Nonce,
                   from : &crypto::asymmetricbox::PublicKey) -> Result<Vec<u8>, CryptoError> {
        return crypto::asymmetricbox::open(&data, &nonce, &from, &self.secret_keys.1).ok_or(CryptoError::Unknown);
    }

}

impl Encodable for ClientIdPacket {
    fn encode<E: rustc_serialize::Encoder>(&self, e: &mut E)->Result<(), E::Error> {
        let (crypto::sign::PublicKey(pub_sign_vec), crypto::asymmetricbox::PublicKey(pub_asym_vec)) = self.public_keys;
        let (crypto::sign::SecretKey(sec_sign_vec), crypto::asymmetricbox::SecretKey(sec_asym_vec)) = self.secret_keys;

        cbor::CborTagEncode::new(5483_001, &(
            pub_sign_vec.as_ref(),
            pub_asym_vec.as_ref(),
            sec_sign_vec.as_ref(),
            sec_asym_vec.as_ref())).encode(e)
    }
}

impl Decodable for ClientIdPacket {
    fn decode<D: rustc_serialize::Decoder>(d: &mut D)-> Result<ClientIdPacket, D::Error> {
        try!(d.read_u64());
        let (pub_sign_vec, pub_asym_vec, sec_sign_vec, sec_asym_vec) : (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) = try!(Decodable::decode(d));

        let pub_sign_arr = container_of_u8_to_array!(pub_sign_vec, crypto::sign::PUBLICKEYBYTES);
        let pub_asym_arr =
            container_of_u8_to_array!(pub_asym_vec, crypto::asymmetricbox::PUBLICKEYBYTES);
        let sec_sign_arr = container_of_u8_to_array!(sec_sign_vec, crypto::sign::SECRETKEYBYTES);
        let sec_asym_arr =
            container_of_u8_to_array!(sec_asym_vec, crypto::asymmetricbox::SECRETKEYBYTES);

        if pub_sign_arr.is_none() || pub_asym_arr.is_none() || sec_sign_arr.is_none() || sec_asym_arr.is_none() {
            return Err(d.error("Bad Maid size"));
        }

        let pub_keys = (crypto::sign::PublicKey(pub_sign_arr.unwrap()),
                        crypto::asymmetricbox::PublicKey(pub_asym_arr.unwrap()));
        let sec_keys = (crypto::sign::SecretKey(sec_sign_arr.unwrap()),
                        crypto::asymmetricbox::SecretKey(sec_asym_arr.unwrap()));
        Ok(ClientIdPacket{ public_keys: pub_keys, secret_keys: sec_keys })
    }
}

pub struct RoutingClient<'a, F: Interface + 'a> {
    interface: Arc<Mutex<F>>,
    connection_manager: ConnectionManager,
    id_packet: ClientIdPacket,
    bootstrap_address: (NameType, Endpoint),
    message_id: u32,
    join_guard: thread::JoinGuard<'a, ()>,
}

impl<'a, F> Drop for RoutingClient<'a, F> where F: Interface {
    fn drop(&mut self) {
        // self.connection_manager.stop(); // TODO This should be coded in ConnectionManager once Peter
        // implements it.
    }
}

impl<'a, F> RoutingClient<'a, F> where F: Interface {
    pub fn new(my_interface: Arc<Mutex<F>>,
               id_packet: ClientIdPacket,
               bootstrap_add: (NameType, crust::Endpoint)) -> RoutingClient<'a, F> {
        sodiumoxide::init();  // enable shared global (i.e. safe to multithread now)
        let (tx, rx): (mpsc::Sender<Event>, mpsc::Receiver<Event>) = mpsc::channel();

        RoutingClient {
            interface: my_interface.clone(),
            connection_manager: crust::ConnectionManager::new(tx),
            id_packet: id_packet.clone(),
            bootstrap_address: bootstrap_add.clone(),
            message_id: rand::random::<u32>(),
            join_guard: thread::scoped(move || RoutingClient::start(rx, bootstrap_add.0, id_packet.get_name(), my_interface)),
        }
    }

    /// Retrieve something from the network (non mutating) - Direct call
    pub fn get(&mut self, type_id: u64, name: NameType) -> Result<u32, IoError> {
        // Make GetData message
        let get_data = messages::get_data::GetData {
            requester: types::SourceAddress {
                from_node: self.bootstrap_address.0.clone(),
                from_group: None,
                reply_to: Some(self.id_packet.get_name()),
            },
            name_and_type_id: types::NameAndTypeId {
                name: name.clone(),
                type_id: type_id,
            },
        };

        // Make MessageHeader
        let header = message_header::MessageHeader::new(
            self.message_id,
            types::DestinationAddress {
                dest: name.clone(),
                reply_to: None
            },
            get_data.requester.clone(),
            types::Authority::Client,
            None,
        );

        self.message_id += 1;

        // Make RoutingMessage
        let routing_msg = messages::RoutingMessage::new(
            messages::MessageTypeTag::GetData,
            header,
            get_data,
        );

        // Serialise RoutingMessage
        let mut encoder_routingmsg = cbor::Encoder::from_memory();
        encoder_routingmsg.encode(&[&routing_msg]).unwrap();

        // Give Serialised RoutingMessage to connection manager
        match self.connection_manager.send(self.bootstrap_address.1.clone(), encoder_routingmsg.into_bytes()) {
            Ok(_) => Ok(self.message_id - 1),
            Err(error) => Err(error),
        }
    }

    /// Add something to the network, will always go via ClientManager group
    pub fn put<T>(&mut self, content: T) -> Result<u32, IoError> where T: Sendable {
        use test_utils::Random;
        // Make PutData message
        let put_data = messages::put_data::PutData {
            name: content.name(),
            data: content.serialised_contents(),
        };

        // Make MessageHeader
        let header = message_header::MessageHeader::new(
            self.message_id,
            types::DestinationAddress {
                dest: self.id_packet.get_name(),
                reply_to: None,
            },
            types::SourceAddress {
                from_node: self.bootstrap_address.0.clone(),
                from_group: None,
                reply_to: Some(self.id_packet.get_name()),
            },
            types::Authority::Client,
            Some(Random::generate_random()), // What is the signature -- see in c++ Secret - signing key
        );

        self.message_id += 1;

        // Make RoutingMessage
        let routing_msg = messages::RoutingMessage::new(
            messages::MessageTypeTag::PutData,
            header,
            put_data,
        );

        // Serialise RoutingMessage
        let mut encoder_routingmsg = cbor::Encoder::from_memory();
        encoder_routingmsg.encode(&[&routing_msg]).unwrap();

        // Give Serialised RoutingMessage to connection manager
        match self.connection_manager.send(self.bootstrap_address.1.clone(), encoder_routingmsg.into_bytes()) {
            Ok(_) => Ok(self.message_id - 1),
            Err(error) => Err(error),
        }
    }

    fn start(rx: mpsc::Receiver<Event>, bootstrap_add: NameType, own_address: NameType,
             my_interface: Arc<Mutex<F>>) {
        for it in rx.iter() {
            match it {
                crust::connection_manager::Event::NewMessage(id, bytes) => {
                    // The received id is Endpoint(i.e. ip + socket) which is no use to upper layer
                    let mut decode_routing_msg = cbor::Decoder::from_bytes(&bytes[..]);
                    let routing_msg: messages::RoutingMessage = decode_routing_msg.decode().next().unwrap().unwrap();

                    if routing_msg.message_header.destination.dest == bootstrap_add &&
                       routing_msg.message_header.destination.reply_to.is_some() &&
                       routing_msg.message_header.destination.reply_to.unwrap() == own_address {
                        match routing_msg.message_type {
                            messages::MessageTypeTag::GetDataResponse => {
                                let mut interface = my_interface.lock().unwrap();
                                interface.handle_get_response(routing_msg.message_header.message_id,
                                                              Ok(routing_msg.serialised_body));
                            }
                            _ => unimplemented!(),
                        }
                    }
                },
                _ => unimplemented!(),
            };
        }
    }

    fn add_bootstrap(&self) { unimplemented!() }
}

// #[cfg(test)]
// mod test {
//     extern crate cbor;
//     extern crate rand;
//
//     use super::*;
//     use std::sync::{Mutex, Arc};
//     use types::*;
//     use client_interface::Interface;
//     use Action;
//     use RoutingError;
//     use maidsafe_types::Random;
//     use maidsafe_types::Maid;
//
//     struct TestInterface;
//
//     impl Interface for TestInterface {
//         fn handle_get(&mut self, type_id: u64, our_authority: Authority, from_authority: Authority,from_address: NameType , data: Vec<u8>)->Result<Action, RoutingError> { unimplemented!(); }
//         fn handle_put(&mut self, our_authority: Authority, from_authority: Authority,
//                       from_address: NameType, dest_address: DestinationAddress, data: Vec<u8>)->Result<Action, RoutingError> { unimplemented!(); }
//         fn handle_post(&mut self, our_authority: Authority, from_authority: Authority, from_address: NameType, data: Vec<u8>)->Result<Action, RoutingError> { unimplemented!(); }
//         fn handle_get_response(&mut self, from_address: NameType , response: Result<Vec<u8>, RoutingError>) { unimplemented!() }
//         fn handle_put_response(&mut self, from_authority: Authority,from_address: NameType , response: Result<Vec<u8>, RoutingError>) { unimplemented!(); }
//         fn handle_post_response(&mut self, from_authority: Authority,from_address: NameType , response: Result<Vec<u8>, RoutingError>) { unimplemented!(); }
//         fn add_node(&mut self, node: NameType) { unimplemented!(); }
//         fn drop_node(&mut self, node: NameType) { unimplemented!(); }
//     }
//
//     pub fn generate_random(size : usize) -> Vec<u8> {
//         let mut content: Vec<u8> = vec![];
//         for _ in (0..size) {
//             content.push(rand::random::<u8>());
//         }
//         content
//     }
//
//     // #[test]
//     // fn routing_client_put() {
//     //     let interface = Arc::new(Mutex::new(TestInterface));
//     //     let maid = Maid::generate_random();
//     //     let dht_id = NameType::generate_random();
//     //     let mut routing_client = RoutingClient::new(interface, maid, dht_id);
//     //     let name = NameType::generate_random();
//     //     let content = generate_random(1024);
//     //
//     //     let put_result = routing_client.put(name, content);
//     //     // assert_eq!(put_result.is_err(), false);
//     // }
// }
