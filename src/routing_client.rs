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
extern crate rand;

use maidsafe_types::Random;
use std::sync::{Mutex, Arc, mpsc};
use std::io::Error as IoError;
use types;
use Facade;
use message_header;
use messages;
use maidsafe_types::traits::RoutingTrait;
use std::thread;

type ConnectionManager = crust::ConnectionManager<types::DhtId>;
type Event             = crust::Event<types::DhtId>;

pub struct RoutingClient<'a> {
    //facade: &'a (Facade + 'a),
    maid_id: maidsafe_types::Maid,
    connection_manager: ConnectionManager,
    own_address: types::DhtId,
    bootstrap_address: types::DhtId,
    message_id: u32,
    join_guard: thread::JoinGuard<'a()>,
}

impl<'a> Drop for RoutingClient<'a> {
    fn drop(&mut self) {
        // self.connection_manager.stop(); // This should be coded in ConnectionManager
    }
}

impl<'a> RoutingClient<'a> {
    pub fn new(my_facade: Arc<Mutex<Facade>>/*&'a mut Facade*/, maid_id: maidsafe_types::Maid, bootstrap_add: types::DhtId) -> RoutingClient<'a> {
        sodiumoxide::init(); // enable shared global (i.e. safe to mutlithread now)
        let (tx, rx): (mpsc::Sender<Event>, mpsc::Receiver<Event>) = mpsc::channel();
        let own_add = types::DhtId(maid_id.get_name().0.to_vec());

        RoutingClient {
            //facade: my_facade,
            maid_id: maid_id,
            connection_manager: crust::ConnectionManager::new(own_add.clone(), tx),
            own_address: own_add.clone(),
            bootstrap_address: bootstrap_add.clone(),
            message_id: rand::random::<u32>(),
            join_guard: thread::scoped(move || RoutingClient::start(rx, bootstrap_add, own_add, my_facade)),
        }
    }

    /// Retreive something from the network (non mutating) - Direct call
    pub fn get(&mut self, type_id: u64, name: types::DhtId) -> Result<u32, IoError> {
        // Make GetData message
        let get_data = messages::get_data::GetData {
            requester: types::SourceAddress {
                from_node: self.bootstrap_address.clone(),
                from_group: None,
                reply_to: Some(self.own_address.clone()),
            },
            name_and_type_id: types::NameAndTypeId {
                name: name.0.clone(),
                type_id: type_id as u32,
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
        match self.connection_manager.send(encoder_routingmsg.into_bytes(), self.bootstrap_address.clone()) {
            Ok(_) => Ok(self.message_id - 1),
            Err(error) => Err(error),
        }
    }

    /// Add something to the network, will always go via ClientManager group
    pub fn put<T>(&mut self, name: types::DhtId, content: Vec<u8>) -> Result<(u32), IoError>
    where T: maidsafe_types::traits::RoutingTrait {
        // Make PutData message
        let put_data = messages::put_data::PutData {
            name: name.0.clone(),
            data: content,
        };

        // Make MessageHeader
        let header = message_header::MessageHeader::new(
            self.message_id,
            types::DestinationAddress {
                dest: self.own_address.clone(),
                reply_to: None,
            },
            types::SourceAddress {
                from_node: self.bootstrap_address.clone(),
                from_group: None,
                reply_to: Some(self.own_address.clone()),
            },
            types::Authority::Client,
            Some(types::Signature::generate_random()), // What is the signautre -- see in c++ Secret - signing key
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
        match self.connection_manager.send(encoder_routingmsg.into_bytes(), self.bootstrap_address.clone()) {
            Ok(_) => Ok(self.message_id - 1),
            Err(error) => Err(error),
        }
    }

    fn start(rx: mpsc::Receiver<Event>, bootstrap_add: types::DhtId, own_address: types::DhtId, my_facade: Arc<Mutex<Facade>>/*&'a mut Facade*/) {
        for it in rx.iter() {
            match it {
                // Event::NewMessage(id, bytes) => {
                //     let mut decode_routing_msg = cbor::Decoder::from_bytes(&bytes[..]);
                //     let routing_msg: messages::RoutingMessage = decode_routing_msg.decode().next().unwrap().unwrap();

                //     if routing_msg.message_header.destination.dest == bootstrap_add &&
                //        routing_msg.message_header.destination.reply_to.is_some() &&
                //        routing_msg.message_header.destination.reply_to.unwrap() == own_address {
                //         match routing_msg.message_type {
                //             messages::MessageTypeTag::GetDataResponse => {
                //                 // my_facade.handle_get_response(id, Ok(routing_msg.serialised_body));
                //             }
                //             _ => unimplemented!(),
                //         }
                //     }
                // },
                _ => unimplemented!(),
            };
        }
    }

    fn add_bootstrap(&self) {}


    // fn get_facade(&'a mut self) -> &'a Facade {
    //   self.facade
    // }
}
