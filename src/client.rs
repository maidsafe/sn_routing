// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.1.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use action::Action;
use authority::Authority;
use cache::NullCache;
use data::{EntryAction, MutableData, PermissionSet, User, Value};
use error::{InterfaceError, RoutingError};
use event::Event;
use id::FullId;
#[cfg(not(feature = "use-mock-crust"))]
use maidsafe_utilities::thread::{self, Joiner};
use messages::Request;
#[cfg(not(feature = "use-mock-crust"))]
use rust_sodium;
use rust_sodium::crypto::sign;
use state_machine::{State, StateMachine};
use states;
#[cfg(feature = "use-mock-crust")]
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::mpsc::{Receiver, Sender, channel};
use types::{MessageId, RoutingActionSender};
use xor_name::XorName;

type RoutingResult = Result<(), RoutingError>;

/// Interface for sending and receiving messages to and from a network of nodes in the role of a
/// client.
///
/// A client is connected to the network via one or more nodes. Messages are never routed via a
/// client, and a client cannot be part of a group authority.
#[allow(unused)] // <-- TODO: remove this
pub struct Client {
    interface_result_tx: Sender<Result<(), InterfaceError>>,
    interface_result_rx: Receiver<Result<(), InterfaceError>>,
    action_sender: ::types::RoutingActionSender,

    #[cfg(feature = "use-mock-crust")]
    machine: RefCell<StateMachine>,

    #[cfg(not(feature = "use-mock-crust"))]
    _raii_joiner: Joiner,
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
        let (action_sender, mut machine) = Self::make_state_machine(event_sender, keys);
        let (tx, rx) = channel();

        let raii_joiner = thread::named("Client thread", move || machine.run());

        Ok(Client {
            interface_result_tx: tx,
            interface_result_rx: rx,
            action_sender: action_sender,
            _raii_joiner: raii_joiner,
        })
    }

    fn make_state_machine(event_sender: Sender<Event>,
                          keys: Option<FullId>)
                          -> (RoutingActionSender, StateMachine) {
        let cache = Box::new(NullCache);
        let full_id = keys.unwrap_or_else(FullId::new);

        StateMachine::new(move |crust_service, timer| {
            State::Bootstrapping(states::Bootstrapping::new(cache,
                                                            true,
                                                            crust_service,
                                                            event_sender,
                                                            full_id,
                                                            timer))
        })
    }

    /// Fetches a latest version number of the provided MutableData
    #[allow(unused)] // <-- TODO: remove this
    pub fn get_mutable_data_version(&self,
                                    dst: Authority,
                                    name: XorName,
                                    tag: u64,
                                    msg_id: MessageId) {
        unimplemented!();
    }

    /// Fetches a list of entries (keys + values) of the provided MutableData
    #[allow(unused)] // <-- TODO: remove this
    pub fn list_mutable_data_entries(&self,
                                     dst: Authority,
                                     name: XorName,
                                     tag: u64,
                                     msg_id: MessageId) {
        unimplemented!();
    }

    /// Fetches a list of keys of the provided MutableData
    #[allow(unused)] // <-- TODO: remove this
    pub fn list_mutable_data_keys(&self,
                                  dst: Authority,
                                  name: XorName,
                                  tag: u64,
                                  msg_id: MessageId) {
        unimplemented!();
    }

    /// Fetches a list of values of the provided MutableData
    #[allow(unused)] // <-- TODO: remove this
    pub fn list_mutable_data_values(&self,
                                    dst: Authority,
                                    name: XorName,
                                    tag: u64,
                                    msg_id: MessageId) {
        unimplemented!();
    }

    /// Fetches a single value from the provided MutableData by the given key
    #[allow(unused)] // <-- TODO: remove this
    pub fn get_mutable_data_value(&self,
                                  dst: Authority,
                                  name: XorName,
                                  tag: u64,
                                  key: Vec<u8>,
                                  msg_id: MessageId) {
        unimplemented!();
    }

    /// Creates a new `MutableData` in the network
    #[allow(unused)] // <-- TODO: remove this
    pub fn put_mutable_data(&self,
                            dst: Authority,
                            data: MutableData,
                            msg_id: MessageId,
                            requester: sign::PublicKey) {
        unimplemented!();
    }

    /// Updates `MutableData` entries in bulk
    #[allow(unused)] // <-- TODO: remove this
    pub fn mutate_mutable_data_entries(&self,
                                       name: XorName,
                                       tag: u64,
                                       actions: BTreeMap<Vec<u8>, EntryAction>,
                                       msg_id: MessageId,
                                       requester: sign::PublicKey) {
        unimplemented!();
    }

    /// Updates a single entry in the provided MutableData by the given key
    #[allow(unused)] // <-- TODO: remove this
    pub fn update_mutable_data_value(&self,
                                     dst: Authority,
                                     name: XorName,
                                     tag: u64,
                                     key: Vec<u8>,
                                     value: Value,
                                     msg_id: MessageId,
                                     requester: sign::PublicKey) {
        unimplemented!();
    }

    /// Inserts a new entry (key-value pair) to the provided MutableData
    #[allow(unused)] // <-- TODO: remove this
    pub fn insert_mutable_data_entry(&self,
                                     dst: Authority,
                                     name: XorName,
                                     tag: u64,
                                     key: Vec<u8>,
                                     value: Value,
                                     msg_id: MessageId,
                                     requester: sign::PublicKey) {
        unimplemented!();
    }

    /// Deletes a single entry from the provided MutableData by the given key
    #[allow(unused)] // <-- TODO: remove this
    pub fn delete_mutable_data_entry(&self,
                                     dst: Authority,
                                     name: XorName,
                                     tag: u64,
                                     key: Vec<u8>,
                                     entry_version: u64,
                                     msg_id: MessageId,
                                     requester: sign::PublicKey) {
        unimplemented!();
    }

    /// Lists all permissions for a given `MutableData`
    #[allow(unused)] // <-- TODO: remove this
    pub fn list_mutable_data_permissions(&self,
                                         dst: Authority,
                                         name: XorName,
                                         tag: u64,
                                         msg_id: MessageId) {
        unimplemented!();
    }

    /// Lists a permission set for a given user
    #[allow(unused)] // <-- TODO: remove this
    pub fn list_mutable_data_user_permissions(&self,
                                              dst: Authority,
                                              name: XorName,
                                              tag: u64,
                                              user: User,
                                              msg_id: MessageId) {
        unimplemented!();
    }

    /// Updates or inserts a permission set for a given user
    #[allow(unused)] // <-- TODO: remove this
    pub fn set_mutable_data_user_permissions(&self,
                                             dst: Authority,
                                             name: XorName,
                                             tag: u64,
                                             user: User,
                                             permissions: PermissionSet,
                                             version: u64,
                                             msg_id: MessageId,
                                             requester: sign::PublicKey) {
        unimplemented!();
    }

    /// Deletes a permission set for a given user
    #[allow(unused)] // <-- TODO: remove this
    pub fn del_mutable_data_user_permissions(&self,
                                             dst: Authority,
                                             name: XorName,
                                             tag: u64,
                                             user: User,
                                             version: u64,
                                             msg_id: MessageId,
                                             requester: sign::PublicKey) {
        unimplemented!();
    }

    /// Sends an ownership transfer request
    #[allow(unused)] // <-- TODO: remove this
    pub fn send_ownership_transfer(&self,
                                   dst: Authority,
                                   name: XorName,
                                   tag: u64,
                                   new_owners: BTreeSet<sign::PublicKey>,
                                   version: u64,
                                   message_id: MessageId) {
        unimplemented!();
    }

    /// Returns the name of this node.
    pub fn name(&self) -> Result<XorName, InterfaceError> {
        let (result_tx, result_rx) = channel();
        self.action_sender.send(Action::Name { result_tx: result_tx })?;

        self.receive_action_result(&result_rx)
    }

    #[allow(unused)] // <-- TODO: remove this
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

        self.action_sender.send(action)?;
        self.receive_action_result(&self.interface_result_rx)?
    }

    #[cfg(not(feature = "use-mock-crust"))]
    fn receive_action_result<T>(&self, rx: &Receiver<T>) -> Result<T, InterfaceError> {
        Ok(rx.recv()?)
    }
}

#[cfg(feature = "use-mock-crust")]
impl Client {
    /// Create a new `Client` for unit testing.
    pub fn new(event_sender: Sender<Event>, keys: Option<FullId>) -> Result<Client, RoutingError> {
        // start the handler for routing with a restriction to become a full node
        let (action_sender, machine) = Self::make_state_machine(event_sender, keys);
        let (tx, rx) = channel();

        Ok(Client {
            interface_result_tx: tx,
            interface_result_rx: rx,
            action_sender: action_sender,
            machine: RefCell::new(machine),
        })
    }

    /// Poll and process all events in this client's `Core` instance.
    pub fn poll(&self) -> bool {
        self.machine.borrow_mut().poll()
    }

    /// Resend all unacknowledged messages.
    pub fn resend_unacknowledged(&self) -> bool {
        self.machine.borrow_mut().current_mut().resend_unacknowledged()
    }

    /// Are there any unacknowledged messages?
    pub fn has_unacknowledged(&self) -> bool {
        self.machine.borrow().current().has_unacknowledged()
    }

    fn receive_action_result<T>(&self, rx: &Receiver<T>) -> Result<T, InterfaceError> {
        while self.poll() {}
        Ok(rx.recv()?)
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        if let Err(err) = self.action_sender.send(Action::Terminate) {
            debug!("Error {:?} sending event to Core", err);
        }
    }
}
