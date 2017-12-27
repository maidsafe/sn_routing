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

use {BootstrapConfig, MIN_SECTION_SIZE};
use action::Action;
use cache::NullCache;
use config_handler::{self, Config};
#[cfg(not(feature = "use-mock-crust"))]
use crust::read_config_file as read_bootstrap_config_file;
use data::{EntryAction, ImmutableData, MutableData, PermissionSet, User};
use error::{InterfaceError, RoutingError};
use event::Event;
#[cfg(feature = "use-mock-crust")]
use event_stream::{EventStepper, EventStream};
use id::{FullId, PublicId};
#[cfg(not(feature = "use-mock-crust"))]
use maidsafe_utilities::thread::{self, Joiner};
use messages::{CLIENT_GET_PRIORITY, DEFAULT_PRIORITY, Request};
use outbox::{EventBox, EventBuf};
use routing_table::Authority;
#[cfg(not(feature = "use-mock-crust"))]
use rust_sodium;
use rust_sodium::crypto::sign;
use state_machine::{State, StateMachine};
use states::{Bootstrapping, BootstrappingTargetState};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::mpsc::{Receiver, Sender, channel};
#[cfg(feature = "use-mock-crust")]
use std::sync::mpsc::{RecvError, TryRecvError};
use std::time::Duration;
use types::{MessageId, RoutingActionSender};
use xor_name::XorName;

/// Interface for sending and receiving messages to and from a network of nodes in the role of a
/// client.
///
/// A client is connected to the network via one or more nodes. Messages are never routed via a
/// client, and a client cannot be part of a section authority.
pub struct Client {
    interface_result_tx: Sender<Result<(), InterfaceError>>,
    interface_result_rx: Receiver<Result<(), InterfaceError>>,

    #[cfg(not(feature = "use-mock-crust"))]
    action_sender: RoutingActionSender,
    #[cfg(not(feature = "use-mock-crust"))]
    _joiner: Joiner,

    #[cfg(feature = "use-mock-crust")]
    machine: StateMachine,
    #[cfg(feature = "use-mock-crust")]
    event_buffer: EventBuf,
}

impl Client {
    fn make_state_machine(
        keys: Option<FullId>,
        outbox: &mut EventBox,
        bootstrap_config: Option<BootstrapConfig>,
        config: Option<Config>,
        msg_expiry_dur: Duration,
    ) -> (RoutingActionSender, StateMachine) {
        let full_id = keys.unwrap_or_else(FullId::new);
        let pub_id = *full_id.public_id();
        let config = config.unwrap_or_else(config_handler::get_config);
        let dev_config = config.dev.unwrap_or_default();
        let min_section_size = dev_config.min_section_size.unwrap_or(MIN_SECTION_SIZE);

        StateMachine::new(
            move |action_sender, crust_service, timer, _outbox2| {
                Bootstrapping::new(
                    action_sender,
                    Box::new(NullCache),
                    BootstrappingTargetState::Client { msg_expiry_dur },
                    crust_service,
                    full_id,
                    min_section_size,
                    timer,
                ).map_or(State::Terminated, State::Bootstrapping)
            },
            pub_id,
            bootstrap_config,
            outbox,
        )
    }

    /// Gets MAID account information.
    pub fn get_account_info(
        &mut self,
        dst: Authority<XorName>,
        msg_id: MessageId,
    ) -> Result<(), InterfaceError> {
        let request = Request::GetAccountInfo(msg_id);
        self.send_request(dst, request, CLIENT_GET_PRIORITY)
    }

    /// Puts ImmutableData to the network
    pub fn put_idata(
        &mut self,
        dst: Authority<XorName>,
        data: ImmutableData,
        msg_id: MessageId,
    ) -> Result<(), InterfaceError> {
        let request = Request::PutIData {
            data: data,
            msg_id: msg_id,
        };

        self.send_request(dst, request, DEFAULT_PRIORITY)
    }

    /// Fetches ImmutableData from the network by the given name.
    pub fn get_idata(
        &mut self,
        dst: Authority<XorName>,
        name: XorName,
        msg_id: MessageId,
    ) -> Result<(), InterfaceError> {
        let request = Request::GetIData {
            name: name,
            msg_id: msg_id,
        };

        self.send_request(dst, request, CLIENT_GET_PRIORITY)
    }

    /// Fetches a latest version number of the provided MutableData
    pub fn get_mdata_version(
        &mut self,
        dst: Authority<XorName>,
        name: XorName,
        tag: u64,
        msg_id: MessageId,
    ) -> Result<(), InterfaceError> {
        let request = Request::GetMDataVersion {
            name: name,
            tag: tag,
            msg_id: msg_id,
        };

        self.send_request(dst, request, CLIENT_GET_PRIORITY)
    }

    /// Fetches the shell of the provided MutableData
    pub fn get_mdata_shell(
        &mut self,
        dst: Authority<XorName>,
        name: XorName,
        tag: u64,
        msg_id: MessageId,
    ) -> Result<(), InterfaceError> {
        let request = Request::GetMDataShell {
            name: name,
            tag: tag,
            msg_id: msg_id,
        };

        self.send_request(dst, request, CLIENT_GET_PRIORITY)
    }

    /// Fetches the entire MutableData
    pub fn get_mdata(
        &mut self,
        dst: Authority<XorName>,
        name: XorName,
        tag: u64,
        msg_id: MessageId,
    ) -> Result<(), InterfaceError> {
        let request = Request::GetMData {
            name: name,
            tag: tag,
            msg_id: msg_id,
        };

        self.send_request(dst, request, CLIENT_GET_PRIORITY)
    }

    /// Fetches a list of entries (keys + values) of the provided MutableData
    /// Note: response to this request is unlikely to accumulate during churn.
    pub fn list_mdata_entries(
        &mut self,
        dst: Authority<XorName>,
        name: XorName,
        tag: u64,
        msg_id: MessageId,
    ) -> Result<(), InterfaceError> {
        let request = Request::ListMDataEntries {
            name: name,
            tag: tag,
            msg_id: msg_id,
        };

        self.send_request(dst, request, CLIENT_GET_PRIORITY)
    }

    /// Fetches a list of keys of the provided MutableData
    /// Note: response to this request is unlikely to accumulate during churn.
    pub fn list_mdata_keys(
        &mut self,
        dst: Authority<XorName>,
        name: XorName,
        tag: u64,
        msg_id: MessageId,
    ) -> Result<(), InterfaceError> {
        let request = Request::ListMDataKeys {
            name: name,
            tag: tag,
            msg_id: msg_id,
        };

        self.send_request(dst, request, CLIENT_GET_PRIORITY)
    }

    /// Fetches a list of values of the provided MutableData
    /// Note: response to this request is unlikely to accumulate during churn.
    pub fn list_mdata_values(
        &mut self,
        dst: Authority<XorName>,
        name: XorName,
        tag: u64,
        msg_id: MessageId,
    ) -> Result<(), InterfaceError> {
        let request = Request::ListMDataValues {
            name: name,
            tag: tag,
            msg_id: msg_id,
        };

        self.send_request(dst, request, CLIENT_GET_PRIORITY)
    }

    /// Fetches a single value from the provided MutableData by the given key
    pub fn get_mdata_value(
        &mut self,
        dst: Authority<XorName>,
        name: XorName,
        tag: u64,
        key: Vec<u8>,
        msg_id: MessageId,
    ) -> Result<(), InterfaceError> {
        let request = Request::GetMDataValue {
            name: name,
            tag: tag,
            key: key,
            msg_id: msg_id,
        };

        self.send_request(dst, request, CLIENT_GET_PRIORITY)
    }

    /// Creates a new `MutableData` in the network
    pub fn put_mdata(
        &mut self,
        dst: Authority<XorName>,
        data: MutableData,
        msg_id: MessageId,
        requester: sign::PublicKey,
    ) -> Result<(), InterfaceError> {
        let request = Request::PutMData {
            data: data,
            msg_id: msg_id,
            requester: requester,
        };

        self.send_request(dst, request, DEFAULT_PRIORITY)
    }

    /// Updates `MutableData` entries in bulk
    pub fn mutate_mdata_entries(
        &mut self,
        dst: Authority<XorName>,
        name: XorName,
        tag: u64,
        actions: BTreeMap<Vec<u8>, EntryAction>,
        msg_id: MessageId,
        requester: sign::PublicKey,
    ) -> Result<(), InterfaceError> {
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
    pub fn list_mdata_permissions(
        &mut self,
        dst: Authority<XorName>,
        name: XorName,
        tag: u64,
        msg_id: MessageId,
    ) -> Result<(), InterfaceError> {
        let request = Request::ListMDataPermissions {
            name: name,
            tag: tag,
            msg_id: msg_id,
        };

        self.send_request(dst, request, CLIENT_GET_PRIORITY)
    }

    /// Lists a permission set for a given user
    pub fn list_mdata_user_permissions(
        &mut self,
        dst: Authority<XorName>,
        name: XorName,
        tag: u64,
        user: User,
        msg_id: MessageId,
    ) -> Result<(), InterfaceError> {
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
    pub fn set_mdata_user_permissions(
        &mut self,
        dst: Authority<XorName>,
        name: XorName,
        tag: u64,
        user: User,
        permissions: PermissionSet,
        version: u64,
        msg_id: MessageId,
        requester: sign::PublicKey,
    ) -> Result<(), InterfaceError> {
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
    pub fn del_mdata_user_permissions(
        &mut self,
        dst: Authority<XorName>,
        name: XorName,
        tag: u64,
        user: User,
        version: u64,
        msg_id: MessageId,
        requester: sign::PublicKey,
    ) -> Result<(), InterfaceError> {
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
    pub fn change_mdata_owner(
        &mut self,
        dst: Authority<XorName>,
        name: XorName,
        tag: u64,
        new_owners: BTreeSet<sign::PublicKey>,
        version: u64,
        msg_id: MessageId,
    ) -> Result<(), InterfaceError> {
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
    pub fn list_auth_keys_and_version(
        &mut self,
        dst: Authority<XorName>,
        message_id: MessageId,
    ) -> Result<(), InterfaceError> {
        let request = Request::ListAuthKeysAndVersion(message_id);
        self.send_request(dst, request, CLIENT_GET_PRIORITY)
    }

    /// Adds a new authorised key to MaidManager
    pub fn ins_auth_key(
        &mut self,
        dst: Authority<XorName>,
        key: sign::PublicKey,
        version: u64,
        message_id: MessageId,
    ) -> Result<(), InterfaceError> {
        let request = Request::InsAuthKey {
            key: key,
            version: version,
            msg_id: message_id,
        };

        self.send_request(dst, request, DEFAULT_PRIORITY)
    }

    /// Removes an authorised key from MaidManager
    pub fn del_auth_key(
        &mut self,
        dst: Authority<XorName>,
        key: sign::PublicKey,
        version: u64,
        message_id: MessageId,
    ) -> Result<(), InterfaceError> {
        let request = Request::DelAuthKey {
            key: key,
            version: version,
            msg_id: message_id,
        };

        self.send_request(dst, request, DEFAULT_PRIORITY)
    }
}

#[cfg(not(feature = "use-mock-crust"))]
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
    pub fn new(
        event_sender: Sender<Event>,
        keys: Option<FullId>,
        bootstrap_config: Option<BootstrapConfig>,
        msg_expiry_dur: Duration,
    ) -> Result<Client, RoutingError> {
        let _ = rust_sodium::init(); // enable shared global (i.e. safe to multithread now)

        let (tx, rx) = channel();
        let (get_action_sender_tx, get_action_sender_rx) = channel();

        let joiner = thread::named("Client thread", move || {
            // start the handler for routing with a restriction to become a full node
            let mut event_buffer = EventBuf::new();
            let (action_sender, mut machine) = Self::make_state_machine(
                keys,
                &mut event_buffer,
                bootstrap_config,
                None,
                msg_expiry_dur,
            );

            for ev in event_buffer.take_all() {
                unwrap!(event_sender.send(ev));
            }

            unwrap!(get_action_sender_tx.send(action_sender));

            // Gather events from the state machine's event loop and proxy them over the
            // event_sender channel.
            while Ok(()) == machine.step(&mut event_buffer) {
                for ev in event_buffer.take_all() {
                    // If sending the event fails, terminate this thread.
                    if event_sender.send(ev).is_err() {
                        return;
                    }
                }
            }
            // When there are no more events to process, terminate this thread.
        });

        let action_sender = get_action_sender_rx.recv().map_err(
            |_| RoutingError::NotBootstrapped,
        )?;

        Ok(Client {
            interface_result_tx: tx,
            interface_result_rx: rx,
            action_sender: action_sender,
            _joiner: joiner,
        })
    }

    /// Returns the `PublicId` of this client.
    pub fn id(&self) -> Result<PublicId, InterfaceError> {
        let (result_tx, result_rx) = channel();
        self.action_sender.send(Action::Id { result_tx: result_tx })?;
        Ok(result_rx.recv()?)
    }

    /// Returns the bootstrap config that this client was created with.
    pub fn bootstrap_config() -> Result<BootstrapConfig, RoutingError> {
        Ok(read_bootstrap_config_file()?)
    }

    fn send_request(
        &self,
        dst: Authority<XorName>,
        request: Request,
        priority: u8,
    ) -> Result<(), InterfaceError> {
        let action = Action::ClientSendRequest {
            content: request,
            dst: dst,
            priority: priority,
            result_tx: self.interface_result_tx.clone(),
        };

        self.action_sender.send(action)?;
        self.interface_result_rx.recv()?
    }
}

#[cfg(feature = "use-mock-crust")]
impl Client {
    /// Create a new `Client` for testing with mock crust.
    pub fn new(
        keys: Option<FullId>,
        bootstrap_config: Option<BootstrapConfig>,
        config: Config,
        msg_expiry_dur: Duration,
    ) -> Result<Client, RoutingError> {
        let mut event_buffer = EventBuf::new();
        let (_, machine) = Self::make_state_machine(
            keys,
            &mut event_buffer,
            bootstrap_config,
            Some(config),
            msg_expiry_dur,
        );

        let (tx, rx) = channel();

        Ok(Client {
            interface_result_tx: tx,
            interface_result_rx: rx,
            machine: machine,
            event_buffer: event_buffer,
        })
    }

    /// Returns the name of this client.
    pub fn id(&self) -> Result<PublicId, RoutingError> {
        self.machine.id().ok_or(RoutingError::Terminated)
    }

    /// FIXME: Review the usage poll here
    pub fn send_request(
        &mut self,
        dst: Authority<XorName>,
        request: Request,
        priority: u8,
    ) -> Result<(), InterfaceError> {
        // Make sure the state machine has processed any outstanding crust events.
        let _ = self.poll();

        let action = Action::ClientSendRequest {
            content: request,
            dst: dst,
            priority: priority,
            result_tx: self.interface_result_tx.clone(),
        };

        let transition = self.machine.current_mut().handle_action(
            action,
            &mut self.event_buffer,
        );
        self.machine.apply_transition(
            transition,
            &mut self.event_buffer,
        );
        self.interface_result_rx.recv()?
    }

    /// Returns the number of received and sent user message parts.
    pub fn get_user_msg_parts_count(&self) -> u64 {
        self.machine.current().get_user_msg_parts_count()
    }
}

#[cfg(feature = "use-mock-crust")]
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

#[cfg(not(feature = "use-mock-crust"))]
impl Drop for Client {
    fn drop(&mut self) {
        if let Err(err) = self.action_sender.send(Action::Terminate) {
            debug!("Error {:?} sending event to Core", err);
        }
    }
}

#[cfg(feature = "use-mock-crust")]
impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.poll();
        let _ = self.machine.current_mut().handle_action(
            Action::Terminate,
            &mut self.event_buffer,
        );
        let _ = self.event_buffer.take_all();
    }
}
