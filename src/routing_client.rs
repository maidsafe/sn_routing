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
use std::sync::mpsc;
use std::io::Error as IoError;
use types;
use Facade;
use message_header;
use messages;
use maidsafe_types::traits::RoutingTrait;

type ConnectionManager = crust::ConnectionManager<types::DhtId>;
type Event             = crust::Event<types::DhtId>;

pub struct RoutingClient<'a> {
    facade: &'a (Facade + 'a),
    maid_id: maidsafe_types::Maid,
    event_input: mpsc::Receiver<Event>,
    connection_manager: ConnectionManager,
    own_address: types::DhtId,
    bootstrap_address: types::DhtId,
    message_id: u32,
}

impl<'a> RoutingClient<'a> {
    pub fn new(my_facade: &'a Facade, maid_id: maidsafe_types::Maid, bootstrap_add: types::DhtId) -> RoutingClient<'a> {
        sodiumoxide::init(); // enable shared global (i.e. safe to mutlithread now)
        let (tx, rx): (mpsc::Sender<Event>, mpsc::Receiver<Event>) = mpsc::channel();
        let own_add = types::DhtId::generate_random(); // How do we get our own address ?

        RoutingClient {
            facade: my_facade,
            maid_id: maid_id,
            event_input: rx,
            connection_manager: crust::ConnectionManager::new(own_add.clone(), tx),
            own_address: own_add,
            bootstrap_address: bootstrap_add,
            message_id: rand::random::<u32>(),
        }
    }

    /// Retreive something from the network (non mutating) - Direct call
    pub fn get(&mut self, type_id: u64, name: types::DhtId) -> Result<(), IoError> {
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

        // Serialise GetData message
        let mut encoder = cbor::Encoder::from_memory();
        encoder.encode(&[&get_data]).unwrap();

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
            encoder.as_bytes().to_vec(),
        );

        // Serialise RoutingMessage
        let mut encoder_routingmsg = cbor::Encoder::from_memory();
        encoder_routingmsg.encode(&[&routing_msg]).unwrap();

        // Give Serialised RoutingMessage to connection manager
        self.connection_manager.send(encoder_routingmsg.into_bytes(), name) // Is this fine ?
    }

    /// Add something to the network, will always go via ClientManager group
    pub fn put<T>(&mut self, name: types::DhtId, content: Vec<u8>) -> Result<(), IoError>
    where T: maidsafe_types::traits::RoutingTrait {
        // Make PutData message
        let put_data = messages::put_data::PutData {
            name: name.0.clone(),
            data: content,
        };

        // Serialise PutData message
        let mut encoder = cbor::Encoder::from_memory();
        encoder.encode(&[&put_data]).unwrap();

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
            Some(types::Signature::generate_random()), // What is the signautre
        );

        self.message_id += 1;

        // Make RoutingMessage
        let routing_msg = messages::RoutingMessage::new(
            messages::MessageTypeTag::PutData,
            header,
            encoder.as_bytes().to_vec(),
        );

        // Serialise RoutingMessage
        let mut encoder_routingmsg = cbor::Encoder::from_memory();
        encoder_routingmsg.encode(&[&routing_msg]).unwrap();

        // Give Serialised RoutingMessage to connection manager
        self.connection_manager.send(encoder_routingmsg.into_bytes(), name) // Is this fine?
    }

    pub fn start() {

    }

    fn add_bootstrap(&self) {}


    fn get_facade(&'a mut self) -> &'a Facade {
      self.facade
    }
}
