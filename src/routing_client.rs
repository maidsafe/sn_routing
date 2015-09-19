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
use std::thread::spawn;

use id::Id;
use action::Action;
use event::Event;
use routing_node::RoutingNode;
use data::{Data, DataRequest};
use error::RoutingError;
use authority::Authority;
use messages::{ExternalRequest, Content};

type RoutingResult = Result<(), RoutingError>;

/// Routing provides an actionable interface to RoutingNode.  On constructing a new Routing object a
/// RoutingNode will also be started. Routing objects are clonable for multithreading, or a Routing
/// object can be cloned with a new set of keys while preserving a single RoutingNode.
#[derive(Clone)]
pub struct RoutingClient {
    action_sender: mpsc::Sender<Action>,
    get_counter: u8,
}

impl RoutingClient {
    /// Starts a new RoutingIdentity, which will also start a new RoutingNode.
    /// The RoutingNode will only bootstrap to the network and not attempt to
    /// achieve full routing node status.
    /// If the client is started with a relocated id (ie the name has been reassigned),
    /// the core will instantely instantiate termination of the client.
    pub fn new(event_sender: mpsc::Sender<Event>, keys: Option<Id>) -> RoutingClient {
        sodiumoxide::init();  // enable shared global (i.e. safe to multithread now)

        let (action_sender, action_receiver) = mpsc::channel::<Action>();

        // start the handler for routing with a restriction to become a full node
        let mut routing_node =
            RoutingNode::new(action_sender.clone(), action_receiver, event_sender, true, keys);

        let _ = spawn(move || {
            debug!("Started routing client run().");
            routing_node.run();
            debug!("Routing client node terminated running.");
        });

        RoutingClient { action_sender: action_sender, get_counter: 0u8 }
    }

    /// Send a Get message with a DataRequest to an Authority, signed with given keys.
    pub fn get_request(&mut self, location: Authority, data_request: DataRequest) {
        self.get_counter = self.get_counter.wrapping_add(1);
        let _ = self.action_sender.send(Action::ClientSendContent(
                location,
                Content::ExternalRequest(
                    ExternalRequest::Get(data_request, self.get_counter))));
    }

    /// Add something to the network
    pub fn put_request(&self, location: Authority, data: Data) {
        debug!("Received put request from Client for {:?}", data);
        let _ = self.action_sender.send(Action::ClientSendContent(
                location,
                Content::ExternalRequest(ExternalRequest::Put(data))));
    }

    /// Change something already on the network
    pub fn post_request(&self, location: Authority, data: Data) {
        let _ = self.action_sender.send(Action::ClientSendContent(
                location,
                Content::ExternalRequest(ExternalRequest::Post(data))));
    }

    /// Remove something from the network
    pub fn delete_request(&self, location: Authority, data: Data) {
        let _ = self.action_sender.send(Action::ClientSendContent(
                location,
                Content::ExternalRequest(ExternalRequest::Delete(data))));
    }

    /// Signal to RoutingNode that it needs to refuse new messages and handle all outstanding
    /// messages.  After handling all messages it will send an Event::Terminated to the user.
    pub fn stop(&mut self) {
        let _ = self.action_sender.send(Action::Terminate);
    }
}
