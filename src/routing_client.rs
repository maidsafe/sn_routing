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

use id::FullId;
use action::Action;
use event::Event;
use routing_node::RoutingNode;
use data::{Data, DataRequest};
use error::RoutingError;
use authority::Authority;
use messages::{RequestMessage, RequestContent, RoutingMessage};

type RoutingResult = Result<(), RoutingError>;

/// Routing provides an actionable interface to RoutingNode.  On constructing a new Routing object a
/// RoutingNode will also be started. Routing objects are clonable for multithreading, or a Routing
/// object can be cloned with a new set of keys while preserving a single RoutingNode.
pub struct RoutingClient {
    action_sender: ::types::RoutingActionSender,
    _raii_joiner: ::maidsafe_utilities::thread::RaiiThreadJoiner,
}

impl RoutingClient {
    /// Starts a new RoutingIdentity, which will also start a new RoutingNode.
    /// The RoutingNode will only bootstrap to the network and not attempt to
    /// achieve full routing node status.
    /// If the client is started with a relocated id (ie the name has been reassigned),
    /// the core will instantely instantiate termination of the client.
    pub fn new(event_sender: mpsc::Sender<Event>, keys: Option<FullId>) -> Result<RoutingClient, RoutingError> {
        sodiumoxide::init();  // enable shared global (i.e. safe to multithread now)

        // start the handler for routing with a restriction to become a full node
        let (action_sender, raii_joiner) = try!(RoutingNode::new(event_sender, true, keys));

        Ok(RoutingClient {
            action_sender: action_sender,
            _raii_joiner: raii_joiner,
        })
    }

    /// Send a Get message with a DataRequest to an Authority, signed with given keys.
    pub fn send_get_request(&mut self, dst: Authority, data_request: DataRequest) {
        let _ = self.action_sender.send(create_send_action(RequestContent::Get(data_request), dst));
    }

    /// Add something to the network
    pub fn send_put_request(&self, dst: Authority, data: Data) {
        let _ = self.action_sender.send(create_send_action(RequestContent::Put(data), dst));
    }

    /// Change something already on the network
    pub fn send_post_request(&self, dst: Authority, data: Data) {
        let _ = self.action_sender.send(create_send_action(RequestContent::Post(data), dst));
    }

    /// Remove something from the network
    pub fn send_delete_request(&self, dst: Authority, data: Data) {
        let _ = self.action_sender.send(create_send_action(RequestContent::Delete(data), dst));
    }
}

impl Drop for RoutingClient {
    fn drop(&mut self) {
        if let Err(err) = self.action_sender.send(Action::Terminate) {
            error!("Error {:?} sending event to RoutingNode", err);
        }
    }
}

fn create_send_action(content: RequestContent, dst: Authority) -> Action {
    Action::ClientSendRequest {
        content: content,
        dst: dst,
    }
}
