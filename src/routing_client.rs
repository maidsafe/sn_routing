// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use cbor;
use rand;
use rustc_serialize;
use rustc_serialize::{Decodable, Encodable};
use sodiumoxide;
use sodiumoxide::crypto;
use std::io::Error as IoError;
use std::sync::{Mutex, Arc, mpsc};
use std::sync::mpsc::Receiver;

use client_interface::Interface;
use crust;
use messages;
use message_header;
use name_type::NameType;
use sendable::Sendable;
use types;
use error::{RoutingError, ResponseError};
use cbor::{Decoder, Encoder};
use messages::bootstrap_id_request::BootstrapIdRequest;
use messages::bootstrap_id_response::BootstrapIdResponse;
use messages::get_data_response::GetDataResponse;
use messages::put_data::PutData;
use messages::get_data::GetData;
use name_type::{NAME_TYPE_LEN};
use message_header::MessageHeader;
use messages::{RoutingMessage, MessageTypeTag};
use types::MessageId;
use authority::Authority;
use utils::*;

pub use crust::Endpoint;

type Bytes = Vec<u8>;
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

    pub fn get_crypto_secret_sign_key(&self) -> crypto::sign::SecretKey {
      self.secret_keys.0.clone()
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

pub struct RoutingClient<F: Interface> {
    interface: Arc<Mutex<F>>,
    event_input: Receiver<Event>,
    connection_manager: ConnectionManager,
    id_packet: ClientIdPacket,
    bootstrap_address: (Option<NameType>, Option<Endpoint>),
    next_message_id: MessageId
}

impl<F> Drop for RoutingClient<F> where F: Interface {
    fn drop(&mut self) {
        // self.connection_manager.stop(); // TODO This should be coded in ConnectionManager once Peter
        // implements it.
    }
}

impl<F> RoutingClient<F> where F: Interface {
    pub fn new(my_interface: F, id_packet: ClientIdPacket) -> RoutingClient<F> {
        sodiumoxide::init();  // enable shared global (i.e. safe to multithread now)
        let (tx, rx) = mpsc::channel::<Event>();
        RoutingClient {
            interface: Arc::new(Mutex::new(my_interface)),
            event_input: rx,
            connection_manager: crust::ConnectionManager::new(tx),
            id_packet: id_packet.clone(),
            bootstrap_address: (None, None),
            next_message_id: rand::random::<MessageId>()
        }
    }

    /// Retrieve something from the network (non mutating) - Direct call
    pub fn get(&mut self, type_id: u64, name: NameType) -> Result<MessageId, IoError> {
        let requester = types::SourceAddress {
            from_node: self.bootstrap_address.0.clone().unwrap(),
            from_group: None,
            reply_to: Some(self.id_packet.get_name())
        };

        let message_id = self.get_next_message_id();

        let message = messages::RoutingMessage::new(
            messages::MessageTypeTag::GetData,
            message_header::MessageHeader::new(
                self.get_next_message_id(),
                types::DestinationAddress {
                    dest: name.clone(),
                    reply_to: None
                },
                requester.clone(),
                Authority::Client
            ),
            GetData {requester: requester.clone(), name_and_type_id: types::NameAndTypeId {
                name: name.clone(), type_id: type_id }},
            &self.id_packet.secret_keys.0
        );

        let _ = encode(&message).map(|msg| self.send_to_bootstrap_node(&msg));
        Ok(message_id)    }

    /// Add something to the network, will always go via ClientManager group
    pub fn put<T>(&mut self, content: T) -> Result<MessageId, IoError> where T: Sendable {
        let message_id = self.get_next_message_id();
        let message = messages::RoutingMessage::new(
            messages::MessageTypeTag::PutData,
            MessageHeader::new(
                message_id,
                types::DestinationAddress {dest: self.id_packet.get_name(), reply_to: None },
                types::SourceAddress {
                    from_node: self.bootstrap_address.0.clone().unwrap(),
                    from_group: None,
                    reply_to: Some(self.id_packet.get_name()),
                },
                Authority::Client
            ),
            PutData {name: content.name(), data: content.serialised_contents()},
            &self.id_packet.secret_keys.0
        );
        let _ = encode(&message).map(|msg| self.send_to_bootstrap_node(&msg));
        Ok(message_id)
    }

    /// Add content to the network
    pub fn unauthorised_put(&mut self, destination: NameType, content: Box<Sendable>) {
        let message = RoutingMessage::new(MessageTypeTag::UnauthorisedPut,
            MessageHeader::new(self.get_next_message_id(),
                types::DestinationAddress{ dest: destination, reply_to: None },
                types::SourceAddress {
                                from_node: self.bootstrap_address.0.clone().unwrap(),
                                from_group: None,
                                reply_to: Some(self.id_packet.get_name()),
                            },
                Authority::Unknown),
            PutData{ name: content.name(), data: content.serialised_contents() },
            &self.id_packet.secret_keys.0);
        let _ = encode(&message).map(|msg| self.send_to_bootstrap_node(&msg));
    }

    pub fn run(&mut self) {
        let event = self.event_input.try_recv();

        if event.is_err() { return; }

        match event.unwrap() {
            crust::connection_manager::Event::NewMessage(endpoint, bytes) => {
                // The received id is Endpoint(i.e. ip + socket) which is no use to upper layer
                // println!("received a new message from {}",
                //          match endpoint.clone() { Tcp(socket_addr) => socket_addr });
                let mut decode_routing_msg = cbor::Decoder::from_bytes(&bytes[..]);
                let routing_msg: messages::RoutingMessage = decode_routing_msg.decode().next().unwrap().unwrap();
                // println!("received a {:?} from {}", routing_msg.message_type,
                //          match endpoint.clone() { Tcp(socket_addr) => socket_addr });
                if self.bootstrap_address.1 == Some(endpoint.clone()) {
                    if routing_msg.message_type == messages::MessageTypeTag::BootstrapIdResponse {
                //         println!("set bootstrap node to {:?} ", routing_msg.message_header.source.from_node.clone());
                        self.handle_bootstrap_id_response(endpoint, routing_msg.serialised_body);
                    } else if routing_msg.message_header.destination.reply_to.is_some() &&
                              routing_msg.message_header.destination.reply_to.clone().unwrap() == self.id_packet.get_name() {
                        match routing_msg.message_type {
                            messages::MessageTypeTag::GetDataResponse => {
                                self.handle_get_data_response(routing_msg.message_header, routing_msg.serialised_body);
                            }
                            _ => unimplemented!(),
                        }
                    }
                }
            },
            _ => { // as a client, shall not handle any connection related change
                   // TODO : try to re-bootstrap when lost the connection to the bootstrap node ?
                 }
        }
    }

    pub fn bootstrap(&mut self, bootstrap_list: Option<Vec<Endpoint>>,
                     beacon_port: Option<u16>) -> Result<(), RoutingError> {
         let bootstrapped_to = try!(self.connection_manager.bootstrap(bootstrap_list, beacon_port)
                                    .map_err(|_|RoutingError::FailedToBootstrap));
         self.bootstrap_address.1 = Some(bootstrapped_to);
         // starts swapping ID with the bootstrap peer
         self.send_bootstrap_id_request();
         Ok(())
    }

    fn send_bootstrap_id_request(&mut self) {
        let message = RoutingMessage::new(
            MessageTypeTag::BootstrapIdRequest,
            MessageHeader::new(
                self.get_next_message_id(),
                types::DestinationAddress{ dest: NameType::new([0u8; NAME_TYPE_LEN]), reply_to: None },
                types::SourceAddress{ from_node: self.id_packet.get_name().clone(), from_group: None, reply_to: None },
                Authority::Client),
            BootstrapIdRequest { sender_id: self.id_packet.get_name().clone() },
            &self.id_packet.get_crypto_secret_sign_key());
        let _ = encode(&message).map(|msg| self.send_to_bootstrap_node(&msg));
    }

    fn handle_bootstrap_id_response(&mut self, peer_endpoint: Endpoint, bytes: Bytes) {
        let bootstrap_id_response_msg = decode::<BootstrapIdResponse>(&bytes);
        if bootstrap_id_response_msg.is_err() {  // TODO handle non routing connection here
            return;
        }
        let bootstrap_id_response_msg = bootstrap_id_response_msg.unwrap();
        assert!(self.bootstrap_address.0.is_none());
        assert_eq!(self.bootstrap_address.1, Some(peer_endpoint.clone()));
        self.bootstrap_address.0 = Some(bootstrap_id_response_msg.sender_id);
    }

    fn send_to_bootstrap_node(&mut self, serialised_message: &Vec<u8>) {
        let _ = self.connection_manager.send(self.bootstrap_address.1.clone().unwrap(), serialised_message.clone());
    }

    fn get_next_message_id(&mut self) -> MessageId {
        let current = self.next_message_id;
        self.next_message_id += 1;
        current
    }

    fn handle_get_data_response(&self, header: MessageHeader, body: Bytes) {
        let get_data_response = decode::<GetDataResponse>(&body).unwrap();
        let response = match get_data_response.data {
            Ok(data) => Ok(data),
            Err(_)   => Err(ResponseError::NoData)
        };
        let mut interface = self.interface.lock().unwrap();
        interface.handle_get_response(header.message_id, response);
    }
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
//     use ResponseError;
//     use maidsafe_types::Random;
//     use maidsafe_types::Maid;
//
//     struct TestInterface;
//
//     impl Interface for TestInterface {
//         fn handle_get(&mut self, type_id: u64, our_authority: Authority, from_authority: Authority,from_address: NameType , data: Vec<u8>)->Result<Action, ResponseError> { unimplemented!(); }
//         fn handle_put(&mut self, our_authority: Authority, from_authority: Authority,
//                       from_address: NameType, dest_address: DestinationAddress, data: Vec<u8>)->Result<Action, ResponseError> { unimplemented!(); }
//         fn handle_post(&mut self, our_authority: Authority, from_authority: Authority, from_address: NameType, data: Vec<u8>)->Result<Action, ResponseError> { unimplemented!(); }
//         fn handle_get_response(&mut self, from_address: NameType , response: Result<Vec<u8>, ResponseError>) { unimplemented!() }
//         fn handle_put_response(&mut self, from_authority: Authority,from_address: NameType , response: Result<Vec<u8>, ResponseError>) { unimplemented!(); }
//         fn handle_post_response(&mut self, from_authority: Authority,from_address: NameType , response: Result<Vec<u8>, ResponseError>) { unimplemented!(); }
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
