// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

#[cfg(feature = "use-mock-crust")]
use BootstrapConfig;
use action::Action;
use cache::NullCache;
use crust::Config;
use data::{EntryAction, ImmutableData, MutableData, PermissionSet, User};
use error::{InterfaceError, RoutingError};
use event::Event;
use event_stream::{EventStepper, EventStream};
use id::FullId;
use messages::{CLIENT_GET_PRIORITY, DEFAULT_PRIORITY, Request};
use outbox::{EventBox, EventBuf};
use routing_table::Authority;
#[cfg(not(feature = "use-mock-crust"))]
use rust_sodium;
use rust_sodium::crypto::sign;
use state_machine::{State, StateMachine};
use states;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::mpsc::{Receiver, RecvError, Sender, TryRecvError, channel};
use types::MessageId;
use xor_name::XorName;

/// Interface for sending and receiving messages to and from a network of nodes in the role of a
/// client.
///
/// A client is connected to the network via one or more nodes. Messages are never routed via a
/// client, and a client cannot be part of a section authority.
pub struct Client {
    interface_result_tx: Sender<Result<(), InterfaceError>>,
    interface_result_rx: Receiver<Result<(), InterfaceError>>,
    machine: StateMachine,
    event_buffer: EventBuf,
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
    /// cryptographically secure and uses section consensus. The restriction for the client name
    /// exists to ensure that the client cannot choose its `ClientAuthority`.
    pub fn new(keys: Option<FullId>,
               config: Option<Config>,
               min_section_size: usize)
               -> Result<Client, RoutingError> {
        // If we're not in a test environment where we might want to manually seed the crypto RNG
        // then seed randomly.
        #[cfg(not(feature = "use-mock-crust"))]
        rust_sodium::init(); // enable shared global (i.e. safe to multithread now)

        // start the handler for routing with a restriction to become a full node
        let mut event_buffer = EventBuf::new();
        let machine = Self::make_state_machine(keys, min_section_size, &mut event_buffer, config);

        let (tx, rx) = channel();

        Ok(Client {
               interface_result_tx: tx,
               interface_result_rx: rx,
               machine: machine,
               event_buffer: event_buffer,
           })
    }

    fn make_state_machine(keys: Option<FullId>,
                          min_section_size: usize,
                          outbox: &mut EventBox,
                          config: Option<Config>)
                          -> StateMachine {
        let cache = Box::new(NullCache);
        let full_id = keys.unwrap_or_else(FullId::new);

        StateMachine::new(move |crust_service, timer, _outbox2| {
            states::Bootstrapping::new(cache, true, crust_service, full_id, min_section_size, timer)
                .map_or(State::Terminated, State::Bootstrapping)
        },
                          outbox,
                          config)
    }

    /// Gets MAID account information.
    pub fn get_account_info(&mut self,
                            dst: Authority<XorName>,
                            msg_id: MessageId)
                            -> Result<(), InterfaceError> {
        let request = Request::GetAccountInfo(msg_id);
        self.send_request(dst, request, CLIENT_GET_PRIORITY)
    }

    /// Puts ImmutableData to the network
    pub fn put_idata(&mut self,
                     dst: Authority<XorName>,
                     data: ImmutableData,
                     msg_id: MessageId)
                     -> Result<(), InterfaceError> {
        let request = Request::PutIData {
            data: data,
            msg_id: msg_id,
        };

        self.send_request(dst, request, DEFAULT_PRIORITY)
    }

    /// Fetches ImmutableData from the network by the given name.
    pub fn get_idata(&mut self,
                     dst: Authority<XorName>,
                     name: XorName,
                     msg_id: MessageId)
                     -> Result<(), InterfaceError> {
        let request = Request::GetIData {
            name: name,
            msg_id: msg_id,
        };

        self.send_request(dst, request, CLIENT_GET_PRIORITY)
    }

    /// Fetches a latest version number of the provided MutableData
    pub fn get_mdata_version(&mut self,
                             dst: Authority<XorName>,
                             name: XorName,
                             tag: u64,
                             msg_id: MessageId)
                             -> Result<(), InterfaceError> {
        let request = Request::GetMDataVersion {
            name: name,
            tag: tag,
            msg_id: msg_id,
        };

        self.send_request(dst, request, CLIENT_GET_PRIORITY)
    }

    /// Fetches the shell of the provided MutableData
    pub fn get_mdata_shell(&mut self,
                           dst: Authority<XorName>,
                           name: XorName,
                           tag: u64,
                           msg_id: MessageId)
                           -> Result<(), InterfaceError> {
        let request = Request::GetMDataShell {
            name: name,
            tag: tag,
            msg_id: msg_id,
        };

        self.send_request(dst, request, CLIENT_GET_PRIORITY)
    }

    /// Fetches a list of entries (keys + values) of the provided MutableData
    pub fn list_mdata_entries(&mut self,
                              dst: Authority<XorName>,
                              name: XorName,
                              tag: u64,
                              msg_id: MessageId)
                              -> Result<(), InterfaceError> {
        let request = Request::ListMDataEntries {
            name: name,
            tag: tag,
            msg_id: msg_id,
        };

        self.send_request(dst, request, CLIENT_GET_PRIORITY)
    }

    /// Fetches a list of keys of the provided MutableData
    pub fn list_mdata_keys(&mut self,
                           dst: Authority<XorName>,
                           name: XorName,
                           tag: u64,
                           msg_id: MessageId)
                           -> Result<(), InterfaceError> {
        let request = Request::ListMDataKeys {
            name: name,
            tag: tag,
            msg_id: msg_id,
        };

        self.send_request(dst, request, CLIENT_GET_PRIORITY)
    }

    /// Fetches a list of values of the provided MutableData
    pub fn list_mdata_values(&mut self,
                             dst: Authority<XorName>,
                             name: XorName,
                             tag: u64,
                             msg_id: MessageId)
                             -> Result<(), InterfaceError> {
        let request = Request::ListMDataValues {
            name: name,
            tag: tag,
            msg_id: msg_id,
        };

        self.send_request(dst, request, CLIENT_GET_PRIORITY)
    }

    /// Fetches a single value from the provided MutableData by the given key
    pub fn get_mdata_value(&mut self,
                           dst: Authority<XorName>,
                           name: XorName,
                           tag: u64,
                           key: Vec<u8>,
                           msg_id: MessageId)
                           -> Result<(), InterfaceError> {
        let request = Request::GetMDataValue {
            name: name,
            tag: tag,
            key: key,
            msg_id: msg_id,
        };

        self.send_request(dst, request, CLIENT_GET_PRIORITY)
    }

    /// Creates a new `MutableData` in the network
    pub fn put_mdata(&mut self,
                     dst: Authority<XorName>,
                     data: MutableData,
                     msg_id: MessageId,
                     requester: sign::PublicKey)
                     -> Result<(), InterfaceError> {
        let request = Request::PutMData {
            data: data,
            msg_id: msg_id,
            requester: requester,
        };

        self.send_request(dst, request, DEFAULT_PRIORITY)
    }

    /// Updates `MutableData` entries in bulk
    pub fn mutate_mdata_entries(&mut self,
                                dst: Authority<XorName>,
                                name: XorName,
                                tag: u64,
                                actions: BTreeMap<Vec<u8>, EntryAction>,
                                msg_id: MessageId,
                                requester: sign::PublicKey)
                                -> Result<(), InterfaceError> {
        let request = Request::MutateMDataEntries {
            name: name,
            tag: tag,
            actions: actions,
            msg_id: msg_id,
            requester: requester,
        };

        self.send_request(dst, request, DEFAULT_PRIORITY)
    }

    /// Lists all permissions for a given `MutableData`
    pub fn list_mdata_permissions(&mut self,
                                  dst: Authority<XorName>,
                                  name: XorName,
                                  tag: u64,
                                  msg_id: MessageId)
                                  -> Result<(), InterfaceError> {
        let request = Request::ListMDataPermissions {
            name: name,
            tag: tag,
            msg_id: msg_id,
        };

        self.send_request(dst, request, CLIENT_GET_PRIORITY)
    }

    /// Lists a permission set for a given user
    pub fn list_mdata_user_permissions(&mut self,
                                       dst: Authority<XorName>,
                                       name: XorName,
                                       tag: u64,
                                       user: User,
                                       msg_id: MessageId)
                                       -> Result<(), InterfaceError> {
        let request = Request::ListMDataUserPermissions {
            name: name,
            tag: tag,
            user: user,
            msg_id: msg_id,
        };

        self.send_request(dst, request, CLIENT_GET_PRIORITY)
    }

    /// Updates or inserts a permission set for a given user
    #[cfg_attr(feature = "cargo-clippy", allow(too_many_arguments))]
    pub fn set_mdata_user_permissions(&mut self,
                                      dst: Authority<XorName>,
                                      name: XorName,
                                      tag: u64,
                                      user: User,
                                      permissions: PermissionSet,
                                      version: u64,
                                      msg_id: MessageId,
                                      requester: sign::PublicKey)
                                      -> Result<(), InterfaceError> {
        let request = Request::SetMDataUserPermissions {
            name: name,
            tag: tag,
            user: user,
            permissions: permissions,
            version: version,
            msg_id: msg_id,
            requester: requester,
        };

        self.send_request(dst, request, DEFAULT_PRIORITY)
    }

    /// Deletes a permission set for a given user
    #[cfg_attr(feature = "cargo-clippy", allow(too_many_arguments))]
    pub fn del_mdata_user_permissions(&mut self,
                                      dst: Authority<XorName>,
                                      name: XorName,
                                      tag: u64,
                                      user: User,
                                      version: u64,
                                      msg_id: MessageId,
                                      requester: sign::PublicKey)
                                      -> Result<(), InterfaceError> {
        let request = Request::DelMDataUserPermissions {
            name: name,
            tag: tag,
            user: user,
            version: version,
            msg_id: msg_id,
            requester: requester,
        };

        self.send_request(dst, request, DEFAULT_PRIORITY)
    }

    /// Sends an ownership transfer request
    pub fn change_mdata_owner(&mut self,
                              dst: Authority<XorName>,
                              name: XorName,
                              tag: u64,
                              new_owners: BTreeSet<sign::PublicKey>,
                              version: u64,
                              msg_id: MessageId)
                              -> Result<(), InterfaceError> {
        let request = Request::ChangeMDataOwner {
            name: name,
            tag: tag,
            new_owners: new_owners,
            version: version,
            msg_id: msg_id,
        };

        self.send_request(dst, request, DEFAULT_PRIORITY)
    }

    /// Fetches a list of authorised keys and version in MaidManager
    pub fn list_auth_keys_and_version(&mut self,
                                      dst: Authority<XorName>,
                                      message_id: MessageId)
                                      -> Result<(), InterfaceError> {
        let request = Request::ListAuthKeysAndVersion(message_id);
        self.send_request(dst, request, CLIENT_GET_PRIORITY)
    }

    /// Adds a new authorised key to MaidManager
    pub fn ins_auth_key(&mut self,
                        dst: Authority<XorName>,
                        key: sign::PublicKey,
                        version: u64,
                        message_id: MessageId)
                        -> Result<(), InterfaceError> {
        let request = Request::InsAuthKey {
            key: key,
            version: version,
            msg_id: message_id,
        };

        self.send_request(dst, request, DEFAULT_PRIORITY)
    }

    /// Removes an authorised key from MaidManager
    pub fn del_auth_key(&mut self,
                        dst: Authority<XorName>,
                        key: sign::PublicKey,
                        version: u64,
                        message_id: MessageId)
                        -> Result<(), InterfaceError> {
        let request = Request::DelAuthKey {
            key: key,
            version: version,
            msg_id: message_id,
        };

        self.send_request(dst, request, DEFAULT_PRIORITY)
    }

    /// Returns the name of this node.
    pub fn name(&self) -> Result<XorName, RoutingError> {
        self.machine.name().ok_or(RoutingError::Terminated)
    }

    fn send_request(&mut self,
                    dst: Authority<XorName>,
                    request: Request,
                    priority: u8)
                    -> Result<(), InterfaceError> {
        // Make sure the state machine has processed any outstanding crust events.
        self.poll();

        let action = Action::ClientSendRequest {
            content: request,
            dst: dst,
            priority: priority,
            result_tx: self.interface_result_tx.clone(),
        };

        let transition = self.machine
            .current_mut()
            .handle_action(action, &mut self.event_buffer);
        self.machine
            .apply_transition(transition, &mut self.event_buffer);
        self.interface_result_rx.recv()?
    }
}

#[cfg(feature = "use-mock-crust")]
impl Client {
    /// Resend all unacknowledged messages.
    pub fn resend_unacknowledged(&mut self) -> bool {
        self.machine.current_mut().resend_unacknowledged()
    }

    /// Are there any unacknowledged messages?
    pub fn has_unacknowledged(&self) -> bool {
        self.machine.current().has_unacknowledged()
    }

    /// Returns the `crust::Config` associated with the `crust::Service` (if any).
    pub fn bootstrap_config(&self) -> BootstrapConfig {
        self.machine
            .bootstrap_config()
            .unwrap_or_else(BootstrapConfig::default)
    }
}

impl EventStepper for Client {
    type Item = Event;

    fn produce_events(&mut self) -> Result<(), RecvError> {
        self.machine.step(&mut self.event_buffer)
    }

    fn try_produce_events(&mut self) -> Result<(), TryRecvError> {
        self.machine.try_step(&mut self.event_buffer)
    }

    fn pop_item(&mut self) -> Option<Event> {
        self.event_buffer.take_first()
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.poll();
        let _ = self.machine
            .current_mut()
            .handle_action(Action::Terminate, &mut self.event_buffer);
        let _ = self.event_buffer.take_all();
    }
}
