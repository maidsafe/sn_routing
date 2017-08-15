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

use MIN_SECTION_SIZE;
use action::Action;
use cache::{Cache, NullCache};
use client_error::ClientError;
use config_handler::{self, Config};
use data::{EntryAction, ImmutableData, MutableData, PermissionSet, User, Value};
use error::{InterfaceError, RoutingError};
use event::Event;
use event_stream::{EventStepper, EventStream};
use id::{FullId, PublicId};
use messages::{AccountInfo, CLIENT_GET_PRIORITY, DEFAULT_PRIORITY, RELOCATE_PRIORITY, Request,
               Response, UserMessage};
use outbox::{EventBox, EventBuf};
use routing_table::{Authority, RoutingTable};
#[cfg(feature = "use-mock-crust")]
use routing_table::Prefix;
#[cfg(not(feature = "use-mock-crust"))]
use rust_sodium;
use rust_sodium::crypto::sign;
use state_machine::{State, StateMachine};
use states::{self, Bootstrapping, BootstrappingTargetState};
use std::collections::{BTreeMap, BTreeSet};
#[cfg(feature = "use-mock-crust")]
use std::fmt::{self, Debug, Formatter};
#[cfg(feature = "use-mock-crust")]
use std::net::IpAddr;
use std::sync::mpsc::{Receiver, RecvError, Sender, TryRecvError, channel};
use types::{MessageId, RoutingActionSender};
use xor_name::XorName;

// Helper macro to implement request sending methods.
macro_rules! impl_request {
    ($method:ident, $message:ident { $($pname:ident : $ptype:ty),*, }, $priority:expr) => {
        #[allow(missing_docs)]
        #[cfg_attr(feature = "cargo-clippy", allow(too_many_arguments))]
        pub fn $method(&mut self,
                       src: Authority<XorName>,
                       dst: Authority<XorName>,
                       $($pname: $ptype),*)
                       -> Result<(), InterfaceError> {
            let msg = UserMessage::Request(Request::$message {
                $($pname: $pname),*,
            });

            self.send_action(src, dst, msg, $priority)
        }
    };

    ($method:ident, $message:ident { $($pname:ident : $ptype:ty),* }, $priority:expr) => {
        impl_request!($method, $message { $($pname:$ptype),*, }, $priority);
    };
}

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
}

/// A builder to configure and create a new `Node`.
pub struct NodeBuilder {
    cache: Box<Cache>,
    first: bool,
    config: Option<Config>,
}

impl NodeBuilder {
    /// Configures the node to use the given request cache.
    pub fn cache(self, cache: Box<Cache>) -> NodeBuilder {
        NodeBuilder { cache, ..self }
    }

    /// Configures the node to start a new network instead of joining an existing one.
    pub fn first(self, first: bool) -> NodeBuilder {
        NodeBuilder { first, ..self }
    }

    /// The node will use the configuration options from `config` rather than defaults.
    pub fn config(self, config: Config) -> NodeBuilder {
        NodeBuilder {
            config: Some(config),
            ..self
        }
    }

    /// Creates new `Node`.
    ///
    /// It will automatically connect to the network in the same way a client does, but then
    /// request a new name and integrate itself into the network using the new name.
    ///
    /// The initial `Node` object will have newly generated keys.
    pub fn create(self) -> Result<Node, RoutingError> {
        // If we're not in a test environment where we might want to manually seed the crypto RNG
        // then seed randomly.
        #[cfg(not(feature = "use-mock-crust"))] rust_sodium::init();

        let mut ev_buffer = EventBuf::new();

        // start the handler for routing without a restriction to become a full node
        let (_, machine) = self.make_state_machine(&mut ev_buffer);
        let (tx, rx) = channel();

        Ok(Node {
            interface_result_tx: tx,
            interface_result_rx: rx,
            machine: machine,
            event_buffer: ev_buffer,
        })
    }

    fn make_state_machine(self, outbox: &mut EventBox) -> (RoutingActionSender, StateMachine) {
        let full_id = FullId::new();
        let pub_id = *full_id.public_id();
        let config = self.config.unwrap_or_else(config_handler::get_config);
        let dev_config = config.dev.unwrap_or_default();
        let min_section_size = dev_config.min_section_size.unwrap_or(MIN_SECTION_SIZE);

        StateMachine::new(
            move |action_sender, crust_service, timer, outbox2| if self.first {
                if let Some(state) = states::Node::first(
                    action_sender,
                    self.cache,
                    crust_service,
                    full_id,
                    min_section_size,
                    timer,
                )
                {
                    State::Node(state)
                } else {
                    State::Terminated
                }
            } else if !dev_config.allow_multiple_lan_nodes && crust_service.has_peers_on_lan() {
                error!("More than one routing node found on LAN. Currently this is not supported.");
                outbox2.send_event(Event::Terminate);
                State::Terminated
            } else {
                Bootstrapping::new(
                    action_sender,
                    self.cache,
                    BootstrappingTargetState::JoiningNode,
                    crust_service,
                    full_id,
                    min_section_size,
                    timer,
                ).map_or(State::Terminated, State::Bootstrapping)
            },
            pub_id,
            None,
            outbox,
        )
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
            config: None,
        }
    }

    /// Send a `GetIData` request to `dst` to retrieve data from the network.
    impl_request!(
        send_get_idata_request,
        GetIData {
            name: XorName,
            msg_id: MessageId,
        },
        RELOCATE_PRIORITY
    );

    /// Send a `PutIData` request to `dst` to store data on the network.
    impl_request!(
        send_put_idata_request,
        PutIData {
            data: ImmutableData,
            msg_id: MessageId,
        },
        DEFAULT_PRIORITY
    );

    /// Send a `GetMData` request to `dst` to retrieve data from the network.
    /// Note: responses to this request are unlikely to accumulate during churn.
    impl_request!(
        send_get_mdata_request,
        GetMData {
            name: XorName,
            tag: u64,
            msg_id: MessageId,
        },
        RELOCATE_PRIORITY
    );

    /// Send a `PutMData` request.
    impl_request!(
        send_put_mdata_request,
        PutMData {
            data: MutableData,
            msg_id: MessageId,
            requester: sign::PublicKey,
        },
        DEFAULT_PRIORITY
    );

    /// Send a `MutateMDataEntries` request.
    impl_request!(send_mutate_mdata_entries_request,
                  MutateMDataEntries {
                      name: XorName,
                      tag: u64,
                      actions: BTreeMap<Vec<u8>, EntryAction>,
                      msg_id: MessageId,
                      requester: sign::PublicKey,
                  },
                  DEFAULT_PRIORITY);

    /// Send a `GetMDataShell` request.
    impl_request!(send_get_mdata_shell_request,
                  GetMDataShell {
                      name: XorName,
                      tag: u64,
                      msg_id: MessageId,
                  },
                  RELOCATE_PRIORITY);

    /// Send a `GetMDataValue` request.
    impl_request!(send_get_mdata_value_request,
                  GetMDataValue {
                      name: XorName,
                      tag: u64,
                      key: Vec<u8>,
                      msg_id: MessageId,
                  },
                  RELOCATE_PRIORITY);

    /// Send a `SetMDataUserPermissions` request.
    impl_request!(send_set_mdata_user_permissions_request,
                  SetMDataUserPermissions {
                      name: XorName,
                      tag: u64,
                      user: User,
                      permissions: PermissionSet,
                      version: u64,
                      msg_id: MessageId,
                      requester: sign::PublicKey,
                  }, DEFAULT_PRIORITY);

    /// Send a `DelMDataUserPermissions` request.
    impl_request!(send_del_mdata_user_permissions_request,
                  DelMDataUserPermissions {
                      name: XorName,
                      tag: u64,
                      user: User,
                      version: u64,
                      msg_id: MessageId,
                      requester: sign::PublicKey,
                  }, DEFAULT_PRIORITY);

    /// Send a `ChangeMDataOwner` request.
    impl_request!(send_change_mdata_owner_request,
                  ChangeMDataOwner {
                      name: XorName,
                      tag: u64,
                      new_owners: BTreeSet<sign::PublicKey>,
                      version: u64,
                      msg_id: MessageId,
                  }, DEFAULT_PRIORITY);

    /// Send a `Refresh` request from `src` to `dst` to trigger churn.
    pub fn send_refresh_request(
        &mut self,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        content: Vec<u8>,
        msg_id: MessageId,
    ) -> Result<(), InterfaceError> {
        let msg = UserMessage::Request(Request::Refresh(content, msg_id));
        self.send_action(src, dst, msg, RELOCATE_PRIORITY)
    }

    /// Respond to a `GetAccountInfo` request.
    impl_response!(send_get_account_info_response,
                   GetAccountInfo,
                   AccountInfo,
                   CLIENT_GET_PRIORITY);

    /// Respond to a `GetIData` request.
    pub fn send_get_idata_response(
        &mut self,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        res: Result<ImmutableData, ClientError>,
        msg_id: MessageId,
    ) -> Result<(), InterfaceError> {
        let msg = UserMessage::Response(Response::GetIData {
            res: res,
            msg_id: msg_id,
        });

        let priority = relocate_priority(&dst);
        self.send_action(src, dst, msg, priority)
    }

    /// Respond to a `PutIData` request.
    impl_response!(send_put_idata_response, PutIData, (), DEFAULT_PRIORITY);

    /// Respond to a `GetMData` request.
    /// Note: this response is unlikely to accumulate during churn.
    pub fn send_get_mdata_response(
        &mut self,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        res: Result<MutableData, ClientError>,
        msg_id: MessageId,
    ) -> Result<(), InterfaceError> {

        let msg = UserMessage::Response(Response::GetMData {
            res: res,
            msg_id: msg_id,
        });

        let priority = relocate_priority(&dst);
        self.send_action(src, dst, msg, priority)
    }

    /// Respond to a `PutMData` request.
    impl_response!(send_put_mdata_response, PutMData, (), DEFAULT_PRIORITY);

    /// Respond to a `GetMDataVersion` request.
    impl_response!(send_get_mdata_version_response,
                   GetMDataVersion,
                   u64,
                   CLIENT_GET_PRIORITY);

    /// Respond to a `GetMDataShell` request.
    pub fn send_get_mdata_shell_response(
        &mut self,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        res: Result<MutableData, ClientError>,
        msg_id: MessageId,
    ) -> Result<(), InterfaceError> {

        let msg = UserMessage::Response(Response::GetMDataShell {
            res: res,
            msg_id: msg_id,
        });

        let priority = relocate_priority(&dst);
        self.send_action(src, dst, msg, priority)
    }

    /// Respond to a `ListMDataEntries` request.
    /// Note: this response is unlikely to accumulate during churn.
    impl_response!(send_list_mdata_entries_response,
                   ListMDataEntries,
                   BTreeMap<Vec<u8>, Value>,
                   CLIENT_GET_PRIORITY);

    /// Respond to a `ListMDataKeys` request.
    /// Note: this response is unlikely to accumulate during churn.
    impl_response!(send_list_mdata_keys_response,
                   ListMDataKeys,
                   BTreeSet<Vec<u8>>,
                   CLIENT_GET_PRIORITY);

    /// Respond to a `ListMDataValues` request.
    /// Note: this response is unlikely to accumulate during churn.
    impl_response!(send_list_mdata_values_response,
                   ListMDataValues,
                   Vec<Value>,
                   CLIENT_GET_PRIORITY);

    /// Respond to a `GetMDataValue` request.
    pub fn send_get_mdata_value_response(
        &mut self,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        res: Result<Value, ClientError>,
        msg_id: MessageId,
    ) -> Result<(), InterfaceError> {

        let msg = UserMessage::Response(Response::GetMDataValue {
            res: res,
            msg_id: msg_id,
        });

        let priority = relocate_priority(&dst);
        self.send_action(src, dst, msg, priority)
    }

    /// Respond to a `MutateMDataEntries` request.
    impl_response!(send_mutate_mdata_entries_response,
                   MutateMDataEntries,
                   (),
                   DEFAULT_PRIORITY);

    /// Respond to a `ListMDataPermissions` request.
    impl_response!(send_list_mdata_permissions_response,
                   ListMDataPermissions,
                   BTreeMap<User, PermissionSet>,
                   CLIENT_GET_PRIORITY);

    /// Respond to a `ListMDataUserPermissions` request.
    impl_response!(send_list_mdata_user_permissions_response,
                   ListMDataUserPermissions,
                   PermissionSet,
                   CLIENT_GET_PRIORITY);

    /// Respond to a `SetMDataUserPermissions` request.
    impl_response!(send_set_mdata_user_permissions_response,
                   SetMDataUserPermissions,
                   (),
                   DEFAULT_PRIORITY);

    /// Respond to a `ListAuthKeysAndVersion` request.
    impl_response!(send_list_auth_keys_and_version_response,
                   ListAuthKeysAndVersion,
                   (BTreeSet<sign::PublicKey>, u64),
                   CLIENT_GET_PRIORITY);

    /// Respond to a `InsAuthKey` request.
    impl_response!(send_ins_auth_key_response,
                   InsAuthKey,
                   (),
                   DEFAULT_PRIORITY);

    /// Respond to a `DelAuthKey` request.
    impl_response!(send_del_auth_key_response,
                   DelAuthKey,
                   (),
                   DEFAULT_PRIORITY);

    /// Respond to a `DelMDataUserPermissions` request.
    impl_response!(send_del_mdata_user_permissions_response,
                   DelMDataUserPermissions,
                   (),
                   DEFAULT_PRIORITY);

    /// Respond to a `ChangeMDataOwner` request.
    impl_response!(send_change_mdata_owner_response,
                   ChangeMDataOwner,
                   (),
                   DEFAULT_PRIORITY);

    /// Returns the first `count` names of the nodes in the routing table which are closest
    /// to the given one.
    pub fn close_group(&self, name: XorName, count: usize) -> Option<Vec<XorName>> {
        self.machine.close_group(name, count)
    }

    /// Returns the `PublicId` of this node.
    pub fn id(&self) -> Result<PublicId, RoutingError> {
        self.machine.id().ok_or(RoutingError::Terminated)
    }

    /// Returns the routing table of this node.
    pub fn routing_table(&self) -> Result<&RoutingTable<XorName>, RoutingError> {
        self.machine.routing_table().ok_or(RoutingError::Terminated)
    }

    /// Returns the minimum section size this vault is using.
    pub fn min_section_size(&self) -> usize {
        self.machine.min_section_size()
    }

    fn send_action(
        &mut self,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        user_msg: UserMessage,
        priority: u8,
    ) -> Result<(), InterfaceError> {
        // Make sure the state machine has processed any outstanding crust events.
        self.poll();

        let action = Action::NodeSendMessage {
            src: src,
            dst: dst,
            content: user_msg,
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
    /// Purge invalid routing entries.
    pub fn purge_invalid_rt_entry(&mut self) {
        self.machine.current_mut().purge_invalid_rt_entry()
    }

    /// Check whether this node acts as a tunnel node between `client_1` and `client_2`.
    pub fn has_tunnel_clients(&self, client_1: PublicId, client_2: PublicId) -> bool {
        self.machine.current().has_tunnel_clients(
            client_1,
            client_2,
        )
    }

    /// Returns a quorum of signatures for the neighbouring section's list or `None` if we don't
    /// have one
    pub fn section_list_signatures(
        &self,
        prefix: Prefix<XorName>,
    ) -> Option<BTreeMap<PublicId, sign::Signature>> {
        self.machine.current().section_list_signatures(prefix)
    }

    /// Returns the list of banned clients' IPs held by this node.
    pub fn get_banned_client_ips(&self) -> BTreeSet<IpAddr> {
        self.machine.current().get_banned_client_ips()
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
    pub fn set_next_relocation_dst(&mut self, dst: XorName) {
        self.machine.current_mut().set_next_relocation_dst(
            Some(dst),
        )
    }

    /// Sets an interval to be used when a node is required to generate a new name.
    pub fn set_next_relocation_interval(&mut self, interval: (XorName, XorName)) {
        self.machine.current_mut().set_next_relocation_interval(
            interval,
        )
    }

    /// Clears the name to be used when the next node relocation request is received by this node so
    /// the normal process is followed to calculate the relocated name.
    pub fn clear_next_relocation_dst(&mut self) {
        self.machine.current_mut().set_next_relocation_dst(None)
    }

    /// Normalisation of routing connection means converting the
    /// `PeerState::Routing(RoutingConnnection::Proxy)` or
    /// `PeerState::Routing(RoutingConnnection::JoiningNode)` to
    /// `PeerState::Routing(RoutingConnection::Direct` after `JOINING_NODE_TIMEOUT_SECS` seconds
    /// have elapsed for the peer with whom we have the connection.
    pub fn has_unnormalised_routing_conn(&self, excludes: &BTreeSet<XorName>) -> bool {
        self.machine.current().has_unnormalised_routing_conn(
            excludes,
        )
    }

    /// Returns the number of received and sent user message parts.
    pub fn get_user_msg_parts_count(&self) -> u64 {
        self.machine.current().get_user_msg_parts_count()
    }

    /// Get the rate limiter's bandwidth usage map.
    pub fn get_clients_usage(&self) -> BTreeMap<IpAddr, u64> {
        unwrap!(self.machine.current().get_clients_usage())
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
        let _ = self.machine.current_mut().handle_action(
            Action::Terminate,
            &mut self.event_buffer,
        );
        let _ = self.event_buffer.take_all();
    }
}

// Priority of messages that might be used during relocation/churn, depending
// on the destination.
fn relocate_priority(dst: &Authority<XorName>) -> u8 {
    if dst.is_client() {
        CLIENT_GET_PRIORITY
    } else {
        RELOCATE_PRIORITY
    }
}
