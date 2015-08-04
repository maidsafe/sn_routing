// Copyright 2015 MaidSafe.net limited.
//
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

use cbor::{CborError};
use rand;
use sodiumoxide;
use std::sync::mpsc;
use std::boxed::Box;
use std::marker::PhantomData;

use crust;
use NameType;
use node_interface::{Interface, CreatePersonas};
use routing_membrane::RoutingMembrane;
use id::Id;
use public_id::PublicId;
use who_are_you::IAm;
use types::{MessageId, SourceAddress, DestinationAddress, Address};
use utils::{encode, decode};
use authority::{Authority};
use messages::{RoutingMessage, SignedMessage, MessageType};
use error::{RoutingError};
use std::thread::spawn;
use std::collections::BTreeMap;

static MAX_BOOTSTRAP_CONNECTIONS : usize = 1;

type CrustEvent = crust::Event;
pub type Endpoint = crust::Endpoint;

type RoutingResult = Result<(), RoutingError>;

/// DHT node
pub struct RoutingNode {
    sender : mpsc::Sender<>
}

impl RoutingNode {
    pub fn new() -> RoutingNode {
        sodiumoxide::init();  // enable shared global (i.e. safe to multithread now)

        // start the handler for routing
        let routing_handler = RoutingHandler::new();
        RoutingNode {
        }
    }

    /// Retrieve something from the network (non mutating) - Direct call
    pub fn get(&mut self, location: NameType, data : DataRequest) {
        let message_id = self.get_next_message_id();
        let message =  RoutingMessage {
            destination : DestinationAddress::Direct(location),
            source      : SourceAddress::Direct(self.id.name()),
            orig_message: None,
            message_type: MessageType::GetData(data),
            message_id  : message_id,
            authority   : Authority::Unknown
        };

        ignore(self.send_swarm_or_parallel(&message));
    }

    /// Add something to the network, will always go via ClientManager group
    pub fn put(&mut self, destination: NameType, data : Data) {
        let message_id = self.get_next_message_id();
        let message = RoutingMessage {
            destination : DestinationAddress::Direct(destination),
            source      : SourceAddress::Direct(self.id.name()),
            orig_message: None,
            message_type: MessageType::PutData(data),
            message_id  : message_id,
            authority   : Authority::Unknown,
        };

        ignore(self.send_swarm_or_parallel(&message));
    }

    /// Add something to the network, will always go via ClientManager group
    pub fn post(&mut self, destination: NameType, data : Data) {
        let message_id = self.get_next_message_id();
        let message = RoutingMessage {
            destination : DestinationAddress::Direct(destination),
            source      : SourceAddress::Direct(self.id.name()),
            orig_message: None,
            message_type: MessageType::Post(data),
            message_id  : message_id,
            authority   : Authority::Unknown,
        };

        ignore(self.send_swarm_or_parallel(&message));
    }

    pub fn delete(&mut self, _destination: NameType, _data : Data) {
        unimplemented!()
    }

    /// Refresh the content in the close group nodes of group address content::name.
    /// This method needs to be called when churn is triggered.
    /// all the group members need to call this, otherwise it will not be resolved as a valid
    /// content.
    pub fn refresh(&mut self, type_tag: u64, from_group: NameType, content: Bytes) {
        let message_id = self.get_next_message_id();
        let message = RoutingMessage {
            destination : DestinationAddress::Direct(from_group.clone()),
            source      : SourceAddress::Direct(self.id.name()),
            orig_message: None,
            message_type: MessageType::Refresh(type_tag, content),
            message_id  : message_id,
            authority   : Authority::Unknown,
        };

        ignore(self.send_swarm_or_parallel(&message));
    }
}
