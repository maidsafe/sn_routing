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

#[cfg(not(feature = "use-mock-crust"))]
use maidsafe_utilities::thread::RaiiThreadJoiner;
#[cfg(not(feature = "use-mock-crust"))]
use rust_sodium;
#[cfg(feature = "use-mock-crust")]
use std::cell::RefCell;
use std::sync::mpsc::{Receiver, Sender, channel};

use id::FullId;
use action::Action;
use event::Event;
use cache::NullCache;
use core::{Core, Role};
use data::{Data, DataIdentifier};
use error::{InterfaceError, RoutingError};
use authority::Authority;
use messages::{Request, DEFAULT_PRIORITY, CLIENT_GET_PRIORITY};
use pub_appendable_data::PubAppendWrapper;
use types::MessageId;
use xor_name::XorName;

type RoutingResult = Result<(), RoutingError>;

/// Interface for sending and receiving messages to and from a network of nodes in the role of a
/// client.
///
/// A client is connected to the network via one or more nodes. Messages are never routed via a
/// client, and a client cannot be part of a group authority.
pub struct Client {
    interface_result_tx: Sender<Result<(), InterfaceError>>,
    interface_result_rx: Receiver<Result<(), InterfaceError>>,
    action_sender: ::types::RoutingActionSender,

    #[cfg(feature = "use-mock-crust")]
    core: RefCell<Core>,

    #[cfg(not(feature = "use-mock-crust"))]
    _raii_joiner: ::maidsafe_utilities::thread::RaiiThreadJoiner,
}

impl Client {
    /// Create a new `Client`.
    ///
    /// It will automatically connect to the network, but not attempt to achieve full routing node
    /// status. The name of the client will be the name of the `PublicId` of the `keys` and must
    /// equal the SHA512 hash of its public signing key, otherwise the client will be instantly
    /// terminated.
    ///
    /// Keys will be exchanged with the `ClientAuthority` so that communication with the network is
    /// cryptographically secure and uses group consensus. The restriction for the client name
    /// exists to ensure that the client cannot choose its `ClientAuthority`.
    #[cfg(not(feature = "use-mock-crust"))]
    pub fn new(event_sender: Sender<Event>, keys: Option<FullId>) -> Result<Client, RoutingError> {
        rust_sodium::init();  // enable shared global (i.e. safe to multithread now)

        // start the handler for routing with a restriction to become a full node
        let (action_sender, mut core) =
            Core::new(event_sender, Role::Client, keys, Box::new(NullCache), false);
        let (tx, rx) = channel();

        let raii_joiner = RaiiThreadJoiner::new(thread!("Client thread", move || {
            core.run();
        }));

        Ok(Client {
            interface_result_tx: tx,
            interface_result_rx: rx,
            action_sender: action_sender,
            _raii_joiner: raii_joiner,
        })
    }

    /// Create a new `Client` for unit testing.
    #[cfg(feature = "use-mock-crust")]
    pub fn new(event_sender: Sender<Event>, keys: Option<FullId>) -> Result<Client, RoutingError> {
        // start the handler for routing with a restriction to become a full node
        let (action_sender, core) =
            Core::new(event_sender, Role::Client, keys, Box::new(NullCache), false);
        let (tx, rx) = channel();

        Ok(Client {
            interface_result_tx: tx,
            interface_result_rx: rx,
            action_sender: action_sender,
            core: RefCell::new(core),
        })
    }

    #[cfg(feature = "use-mock-crust")]
    /// Poll and process all events in this client's `Core` instance.
    pub fn poll(&self) -> bool {
        self.core.borrow_mut().poll()
    }

    #[cfg(feature = "use-mock-crust")]
    /// Resend all unacknowledged messages.
    pub fn resend_unacknowledged(&self) -> bool {
        self.core.borrow_mut().resend_unacknowledged()
    }

    #[cfg(feature = "use-mock-crust")]
    /// Are there any unacknowledged messages?
    pub fn has_unacknowledged(&self) -> bool {
        self.core.borrow().has_unacknowledged()
    }

    /// Send a Get message with a `DataIdentifier` to an `Authority`, signed with given keys.
    pub fn send_get_request(&mut self,
                            dst: Authority,
                            data_id: DataIdentifier,
                            message_id: MessageId)
                            -> Result<(), InterfaceError> {
        self.send_action(Request::Get(data_id, message_id), dst, CLIENT_GET_PRIORITY)
    }

    /// Add something to the network
    pub fn send_put_request(&self,
                            dst: Authority,
                            data: Data,
                            message_id: MessageId)
                            -> Result<(), InterfaceError> {
        self.send_action(Request::Put(data, message_id), dst, DEFAULT_PRIORITY)
    }

    /// Change something already on the network
    pub fn send_post_request(&self,
                             dst: Authority,
                             data: Data,
                             message_id: MessageId)
                             -> Result<(), InterfaceError> {
        self.send_action(Request::Post(data, message_id), dst, DEFAULT_PRIORITY)
    }

    /// Remove something from the network
    pub fn send_delete_request(&self,
                               dst: Authority,
                               data: Data,
                               message_id: MessageId)
                               -> Result<(), InterfaceError> {
        self.send_action(Request::Delete(data, message_id), dst, DEFAULT_PRIORITY)
    }

    /// Append an item to public appendable data.
    pub fn send_pub_append_request(&self,
                                   dst: Authority,
                                   wrapper: PubAppendWrapper,
                                   message_id: MessageId)
                                   -> Result<(), InterfaceError> {
        self.send_action(Request::Append(wrapper, message_id), dst, DEFAULT_PRIORITY)
    }


    /// Request account information for the Client calling this function
    pub fn send_get_account_info_request(&mut self,
                                         dst: Authority,
                                         message_id: MessageId)
                                         -> Result<(), InterfaceError> {
        self.send_action(Request::GetAccountInfo(message_id),
                         dst,
                         CLIENT_GET_PRIORITY)
    }

    /// Returns the name of this node.
    pub fn name(&self) -> Result<XorName, InterfaceError> {
        let (result_tx, result_rx) = channel();
        try!(self.action_sender.send(Action::Name { result_tx: result_tx }));

        self.receive_action_result(&result_rx)
    }

    fn send_action(&self,
                   content: Request,
                   dst: Authority,
                   priority: u8)
                   -> Result<(), InterfaceError> {
        let action = Action::ClientSendRequest {
            content: content,
            dst: dst,
            priority: priority,
            result_tx: self.interface_result_tx.clone(),
        };

        try!(self.action_sender.send(action));
        try!(self.receive_action_result(&self.interface_result_rx))
    }

    #[cfg(not(feature = "use-mock-crust"))]
    fn receive_action_result<T>(&self, rx: &Receiver<T>) -> Result<T, InterfaceError> {
        Ok(try!(rx.recv()))
    }

    #[cfg(feature = "use-mock-crust")]
    fn receive_action_result<T>(&self, rx: &Receiver<T>) -> Result<T, InterfaceError> {
        while self.poll() {}
        Ok(try!(rx.recv()))
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        if let Err(err) = self.action_sender.send(Action::Terminate) {
            error!("Error {:?} sending event to Core", err);
        }
    }
}
