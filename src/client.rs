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

use sodiumoxide;
use std::sync::mpsc::{Receiver, Sender, channel};

use id::FullId;
use action::Action;
use event::Event;
use core::Core;
use data::{Data, DataRequest};
use error::{InterfaceError, RoutingError};
use authority::Authority;
use messages::RequestContent;
use types::MessageId;

type RoutingResult = Result<(), RoutingError>;

/// Client provides an actionable interface to Core.  On constructing a new Client object a
/// Core will also be started.
pub struct Client {
    interface_result_tx: Sender<Result<(), InterfaceError>>,
    interface_result_rx: Receiver<Result<(), InterfaceError>>,
    action_sender: ::types::RoutingActionSender,
    _raii_joiner: ::maidsafe_utilities::thread::RaiiThreadJoiner,
}

impl Client {
    /// Starts a new RoutingIdentity, which will also start a new Core.
    /// The Core will only bootstrap to the network and not attempt to
    /// achieve full routing node status.
    /// If the client is started with a relocated id (ie the name has been reassigned),
    /// the core will instantly instantiate termination of the client.
    pub fn new(event_sender: Sender<Event>, keys: Option<FullId>) -> Result<Client, RoutingError> {
        sodiumoxide::init();  // enable shared global (i.e. safe to multithread now)

        // start the handler for routing with a restriction to become a full node
        let (action_sender, raii_joiner) = try!(Core::new(event_sender, true, keys));

        let (tx, rx) = channel();

        Ok(Client {
            interface_result_tx: tx,
            interface_result_rx: rx,
            action_sender: action_sender,
            _raii_joiner: raii_joiner,
        })
    }

    /// Send a Get message with a DataRequest to an Authority, signed with given keys.
    pub fn send_get_request(&mut self,
                            dst: Authority,
                            data_request: DataRequest)
                            -> Result<(), InterfaceError> {
        self.send_action(RequestContent::Get(data_request, MessageId::new()), dst)
    }

    /// Add something to the network
    pub fn send_put_request(&self, dst: Authority, data: Data) -> Result<(), InterfaceError> {
        self.send_action(RequestContent::Put(data, MessageId::new()), dst)
    }

    /// Change something already on the network
    pub fn send_post_request(&self, dst: Authority, data: Data) -> Result<(), InterfaceError> {
        self.send_action(RequestContent::Post(data, MessageId::new()), dst)
    }

    /// Remove something from the network
    pub fn send_delete_request(&self, dst: Authority, data: Data) -> Result<(), InterfaceError> {
        self.send_action(RequestContent::Delete(data, MessageId::new()), dst)
    }

    fn send_action(&self, content: RequestContent, dst: Authority) -> Result<(), InterfaceError> {
        let action = Action::ClientSendRequest {
            content: content,
            dst: dst,
            result_tx: self.interface_result_tx.clone(),
        };

        try!(self.action_sender.send(action));

        try!(self.interface_result_rx.recv())
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        if let Err(err) = self.action_sender.send(Action::Terminate) {
            error!("Error {:?} sending event to Core", err);
        }
    }
}
