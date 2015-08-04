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

use sodiumoxide;
use std::sync::mpsc;

use id::Id;
use action::Action;
use event::Event;
use routing_node::RoutingNode;
//use crust;
use NameType;
//use node_interface::{Interface, CreatePersonas};
//use routing_membrane::RoutingMembrane;
//use id::Id;
//use public_id::PublicId;
//use who_are_you::IAm;
//use types::{MessageId, SourceAddress, DestinationAddress, Address};
//use utils::{encode, decode};
//use authority::{Authority};
//use messages::{RoutingMessage, SignedMessage, MessageType};
//use error::{RoutingError};
//use std::thread::spawn;
//use std::collections::BTreeMap;

/// RoutingIdentity provides an actionable interface to RoutingNode.
/// On constructing a new Identity a RoutingNode will be started.
/// Identities are clonable for multithreading, or an Identity can be
/// cloned with a new set of keys.
#[derive(Clone)]
pub struct RoutingIdentity {
    given_keys    : Option<Id>,
    action_sender : mpsc::Sender<Action>,
}

impl RoutingIdentity {
    /// Starts a new RoutingIdentity, which will also start a new RoutingNode.
    /// The RoutingNode will attempt to achieve full routing node status.
    pub fn new(event_receiver : mpsc::Receiver<Event>) -> RoutingIdentity {
        sodiumoxide::init();  // enable shared global (i.e. safe to multithread now)

        let (action_sender, action_receiver) = mpsc::channel::<Action>();

        // start the handler for routing
        let routing_node = RoutingNode::new(event_receiver);
        RoutingIdentity {
            given_keys    : None,
            action_sender : action_sender,
        }
    }

    /// Starts a new RoutingIdentity, which will also start a new RoutingNode.
    /// The RoutingNode will only bootstrap to the network and not attempt to
    /// achieve full routing node status.
    pub fn new_client(event_receiver : mpsc::Receiver<Event>) -> RoutingIdentity {
        unimplemented!()
    }

    pub fn clone_with_keys() -> RoutingIdentity {
        unimplemented!()
    }

    /// Retrieve something from the network (non mutating) - Direct call
    pub fn get(&mut self, location: NameType, data : DataRequest) {
        unimplemented!()
    }

    /// Add something to the network, will always go via ClientManager group
    pub fn put(&mut self, destination: NameType, data : Data) {
        unimplemented!()
    }

    /// Add something to the network, will always go via ClientManager group
    pub fn post(&mut self, destination: NameType, data : Data) {
        unimplemented!()
    }

    pub fn delete(&mut self, _destination: NameType, _data : Data) {
        unimplemented!()
    }

    /// Refresh the content in the close group nodes of group address content::name.
    /// This method needs to be called when churn is triggered.
    /// all the group members need to call this, otherwise it will not be resolved as a valid
    /// content.
    pub fn refresh(&mut self, type_tag: u64, from_group: NameType, content: Bytes) {
        unimplemented!()
    }
}
