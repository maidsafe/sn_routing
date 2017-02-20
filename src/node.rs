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
use cache::{Cache, NullCache};
use client_error::ClientError;
use data::{ImmutableData, MutableData};
use error::{InterfaceError, RoutingError};
use event::Event;
use event_stream::{EventStepper, EventStream};
use id::FullId;
#[cfg(feature = "use-mock-crust")]
use id::PublicId;
use messages::{AccountInfo, CLIENT_GET_PRIORITY, DEFAULT_PRIORITY, RELOCATE_PRIORITY, Request,
               Response, UserMessage};
use outbox::{EventBox, EventBuf};
#[cfg(feature = "use-mock-crust")]
use routing_table::{Prefix, RoutingTable};
use routing_table::Authority;
#[cfg(not(feature = "use-mock-crust"))]
use rust_sodium;
use rust_sodium::crypto::sign;
use state_machine::{State, StateMachine};
use states;
#[cfg(feature = "use-mock-crust")]
use std::collections::BTreeMap;
use std::collections::BTreeSet;
#[cfg(feature = "use-mock-crust")]
use std::fmt::{self, Debug, Formatter};
use std::sync::mpsc::{Receiver, RecvError, Sender, TryRecvError, channel};
use types::{MessageId, RoutingActionSender};
use xor_name::XorName;

// Helper macro to implement response sending methods.
macro_rules! impl_response {
    ($method:ident, $message:ident, $payload:ty, $priority:expr) => {
        #[allow(missing_docs)]
        pub fn $method(&mut self,
                       src: Authority<XorName>,
                       dst: Authority<XorName>,
                       res: Result<$payload, ClientError>,
                       msg_id: MessageId)
                       -> Result<(), InterfaceError> {
            let msg = UserMessage::Response(Response::$message {
                res: res,
                msg_id: msg_id,
            });
            self.send_action(src, dst, msg, $priority)
        }
    };

    ($method:ident, $message:ident) => {
        impl_response!($method, $message, (), DEFAULT_PRIORITY);
    }
}

/// A builder to configure and create a new `Node`.
pub struct NodeBuilder {
    cache: Box<Cache>,
    first: bool,
    deny_other_local_nodes: bool,
}

impl NodeBuilder {
    /// Configures the node to use the given request cache.
    pub fn cache(self, cache: Box<Cache>) -> NodeBuilder {
        NodeBuilder { cache: cache, ..self }
    }

    /// Configures the node to start a new network instead of joining an existing one.
    pub fn first(self, first: bool) -> NodeBuilder {
        NodeBuilder { first: first, ..self }
    }

    /// Causes node creation to fail if another node on the local network is detected.
    pub fn deny_other_local_nodes(self) -> NodeBuilder {
        NodeBuilder { deny_other_local_nodes: true, ..self }
    }

    /// Creates new `Node`.
    ///
    /// It will automatically connect to the network in the same way a client does, but then
    /// request a new name and integrate itself into the network using the new name.
    ///
    /// The initial `Node` object will have newly generated keys.
    pub fn create(self, min_section_size: usize) -> Result<Node, RoutingError> {
        // If we're not in a test environment where we might want to manually seed the crypto RNG
        // then seed randomly.
        #[cfg(not(feature = "use-mock-crust"))]
        rust_sodium::init();

        let mut ev_buffer = EventBuf::new();

        // start the handler for routing without a restriction to become a full node
        let (_, machine) = self.make_state_machine(min_section_size, &mut ev_buffer);

        let (tx, rx) = channel();

        Ok(Node {
            interface_result_tx: tx,
            interface_result_rx: rx,
            machine: machine,
            event_buffer: ev_buffer,
        })
    }

    // TODO - remove this `rustfmt_skip` once rustfmt stops adding trailing space at `else if`.
    #[cfg_attr(rustfmt, rustfmt_skip)]
    fn make_state_machine(self,
                          min_section_size: usize,
                          outbox: &mut EventBox)
                          -> (RoutingActionSender, StateMachine) {
        let full_id = FullId::new();

        StateMachine::new(move |crust_service, timer, outbox2| if self.first {
                              if let Some(state) = states::Node::first(self.cache,
                                                                       crust_service,
                                                                       full_id,
                                                                       min_section_size,
                                                                       timer) {
                                  State::Node(state)
                              } else {
                                  State::Terminated
                              }
                          } else if
                              self.deny_other_local_nodes && crust_service.has_peers_on_lan() {
                              error!("Bootstrapping({:?}) More than 1 routing node found on LAN. \
                                      Currently this is not supported",
                                     full_id.public_id().name());

                              outbox2.send_event(Event::Terminate);
                              State::Terminated
                          } else {
                              states::Bootstrapping::new(self.cache,
                                                         false,
                                                         crust_service,
                                                         full_id,
                                                         min_section_size,
                                                         timer)
                                  .map_or(State::Terminated, State::Bootstrapping)
                          },
                          outbox, None)
    }
}

/// Interface for sending and receiving messages to and from other nodes, in the role of a full
/// routing node.
///
/// A node is a part of the network that can route messages and be a member of a section or group
/// authority. Its methods can be used to send requests and responses as either an individual
/// `ManagedNode` or as a part of a section or group authority. Their `src` argument indicates that
/// role, and can be any [`Authority`](enum.Authority.html) other than `Client`.
pub struct Node {
    interface_result_tx: Sender<Result<(), InterfaceError>>,
    interface_result_rx: Receiver<Result<(), InterfaceError>>,
    machine: StateMachine,
    event_buffer: EventBuf,
}

impl Node {
    /// Creates a new builder to configure and create a `Node`.
    pub fn builder() -> NodeBuilder {
        NodeBuilder {
            cache: Box::new(NullCache),
            first: false,
            deny_other_local_nodes: false,
        }
    }

    /// Send a `GetIData` request to `dst` to retrieve data from the network.
    pub fn send_get_idata_request(&mut self,
                                  src: Authority<XorName>,
                                  dst: Authority<XorName>,
                                  name: XorName,
                                  msg_id: MessageId)
                                  -> Result<(), InterfaceError> {
        let user_msg = UserMessage::Request(Request::GetIData {
            name: name,
            msg_id: msg_id,
        });
        self.send_action(src, dst, user_msg, RELOCATE_PRIORITY)
    }

    /// Send a `PutIData` request to `dst` to store data on the network.
    pub fn send_put_idata_request(&mut self,
                                  src: Authority<XorName>,
                                  dst: Authority<XorName>,
                                  data: ImmutableData,
                                  msg_id: MessageId)
                                  -> Result<(), InterfaceError> {
        let msg = UserMessage::Request(Request::PutIData {
            data: data,
            msg_id: msg_id,
        });
        self.send_action(src, dst, msg, DEFAULT_PRIORITY)
    }

    /// Send a `PutMData` request.
    pub fn send_put_mdata_request(&mut self,
                                  src: Authority<XorName>,
                                  dst: Authority<XorName>,
                                  data: MutableData,
                                  msg_id: MessageId,
                                  requester: sign::PublicKey)
                                  -> Result<(), InterfaceError> {
        let msg = UserMessage::Request(Request::PutMData {
            data: data,
            msg_id: msg_id,
            requester: requester,
        });

        self.send_action(src, dst, msg, DEFAULT_PRIORITY)
    }

    /// Send a `Refresh` request from `src` to `dst` to trigger churn.
    pub fn send_refresh_request(&mut self,
                                src: Authority<XorName>,
                                dst: Authority<XorName>,
                                content: Vec<u8>,
                                id: MessageId)
                                -> Result<(), InterfaceError> {
        let user_msg = UserMessage::Request(Request::Refresh(content, id));
        self.send_action(src, dst, user_msg, RELOCATE_PRIORITY)
    }

    /// Respond to a `GetAccountInfo` request.
    impl_response!(send_get_account_info_response,
                   GetAccountInfo,
                   AccountInfo,
                   CLIENT_GET_PRIORITY);

    /// Respond to a `PutIData` request.
    impl_response!(send_put_idata_response, PutIData);

    /// Respond to a `PutMData` request.
    impl_response!(send_put_mdata_response, PutMData);

    /// Respond to a `MutateMDataEntries` request.
    impl_response!(send_mutate_mdata_entries_response, MutateMDataEntries);

    /// Respond to a `SetMDataUserPermissions` request.
    impl_response!(send_set_mdata_user_permissions_response,
                   SetMDataUserPermissions);

    /// Respond to a `ListAuthKeysAndVersion` request.
    impl_response!(send_list_auth_keys_and_version_response,
        ListAuthKeysAndVersion,
        (BTreeSet<sign::PublicKey>, u64),
        CLIENT_GET_PRIORITY);

    /// Respond to a `InsAuthKey` request.
    impl_response!(send_ins_auth_key_response, InsAuthKey);

    /// Respond to a `DelAuthKey` request.
    impl_response!(send_del_auth_key_response, DelAuthKey);

    /// Respond to a `DelMDataUserPermissions` request.
    impl_response!(send_del_mdata_user_permissions_response, DelMDataUserPermissions);

    /// Respond to a `ChangeMDataOwner` request.
    impl_response!(send_change_mdata_owner_response, ChangeMDataOwner);

    /*
    /// Respond to a `Get` request indicating success and sending the requested data.
    pub fn send_get_success(&mut self,
                            src: Authority<XorName>,
                            dst: Authority<XorName>,
                            data: Data,
                            id: MessageId)
                            -> Result<(), InterfaceError> {
        let user_msg = UserMessage::Response(Response::GetSuccess(data, id));
        let priority = if dst.is_client() {
            CLIENT_GET_PRIORITY
        } else {
            RELOCATE_PRIORITY
        };
        self.send_action(src, dst, user_msg, priority)
    }

    /// Respond to a `Get` request indicating failure.
    pub fn send_get_failure(&mut self,
                            src: Authority<XorName>,
                            dst: Authority<XorName>,
                            data_id: DataIdentifier,
                            external_error_indicator: Vec<u8>,
                            id: MessageId)
                            -> Result<(), InterfaceError> {
        let user_msg = UserMessage::Response(Response::GetFailure {
            id: id,
            data_id: data_id,
            external_error_indicator: external_error_indicator,
        });
        let priority = if dst.is_client() {
            CLIENT_GET_PRIORITY
        } else {
            RELOCATE_PRIORITY
        };
        self.send_action(src, dst, user_msg, priority)
    }

    */

    /// Returns the first `count` names of the nodes in the routing table which are closest
    /// to the given one.
    pub fn close_group(&self, name: XorName, count: usize) -> Option<Vec<XorName>> {
        self.machine.close_group(name, count)
    }

    /// Returns the name of this node.
    pub fn name(&self) -> Result<XorName, RoutingError> {
        self.machine.name().ok_or(RoutingError::Terminated)
    }

    fn send_action(&mut self,
                   src: Authority<XorName>,
                   dst: Authority<XorName>,
                   user_msg: UserMessage,
                   priority: u8)
                   -> Result<(), InterfaceError> {
        // Make sure the state machine has processed any outstanding crust events.
        self.poll();

        let action = Action::NodeSendMessage {
            src: src,
            dst: dst,
            content: user_msg,
            priority: priority,
            result_tx: self.interface_result_tx.clone(),
        };

        let transition = self.machine.current_mut().handle_action(action, &mut self.event_buffer);
        self.machine.apply_transition(transition, &mut self.event_buffer);

        self.receive_action_result(&self.interface_result_rx)?
    }

    fn receive_action_result<T>(&self, rx: &Receiver<T>) -> Result<T, InterfaceError> {
        Ok(rx.recv()?)
    }
}

impl EventStepper for Node {
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

#[cfg(feature = "use-mock-crust")]
impl Node {
    /// Resend all unacknowledged messages.
    pub fn resend_unacknowledged(&mut self) -> bool {
        self.machine.current_mut().resend_unacknowledged()
    }

    /// Are there any unacknowledged messages?
    pub fn has_unacknowledged(&mut self) -> bool {
        self.machine.current().has_unacknowledged()
    }

    /// Routing table of this node.
    pub fn routing_table(&self) -> Option<RoutingTable<XorName>> {
        self.machine.current().routing_table().cloned()
    }

    /// Resend all unacknowledged messages.
    pub fn clear_state(&mut self) {
        self.machine.current_mut().clear_state();
    }

    /// Returns a quorum of signatures for the neighbouring section's list or `None` if we don't
    /// have one
    pub fn section_list_signatures(&self,
                                   prefix: Prefix<XorName>)
                                   -> Option<BTreeMap<PublicId, sign::Signature>> {
        self.machine.current().section_list_signatures(prefix)
    }

    /// Returns whether the current state is `Node`.
    pub fn is_node(&self) -> bool {
        if let State::Node(..) = *self.machine.current() {
            true
        } else {
            false
        }
    }

    /// Sets a name to be used when the next node relocation request is received by this node.
    pub fn set_next_node_name(&mut self, relocation_name: XorName) {
        self.machine.current_mut().set_next_node_name(Some(relocation_name))
    }

    /// Clears the name to be used when the next node relocation request is received by this node so
    /// the normal process is followed to calculate the relocated name.
    pub fn clear_next_node_name(&mut self) {
        self.machine.current_mut().set_next_node_name(None)
    }
}

#[cfg(feature = "use-mock-crust")]
impl Debug for Node {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        self.machine.fmt(formatter)
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.poll();
        let _ = self.machine.current_mut().handle_action(Action::Terminate, &mut self.event_buffer);
        let _ = self.event_buffer.take_all();
    }
}
