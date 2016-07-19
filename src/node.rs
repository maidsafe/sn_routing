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
use sodiumoxide;
#[cfg(feature = "use-mock-crust")]
use std::cell::RefCell;
use std::sync::mpsc::{Receiver, Sender, channel};

use action::Action;
use authority::Authority;
use cache::{Cache, NullCache};
use data::{Data, DataIdentifier};
use error::{InterfaceError, RoutingError};
use event::Event;
#[cfg(feature = "use-mock-crust")]
use kademlia_routing_table::RoutingTable;
use messages::{CLIENT_GET_PRIORITY, DEFAULT_PRIORITY, RELOCATE_PRIORITY, Request, Response,
               UserMessage};
use xor_name::XorName;
use state_machine::{Role, StateMachine};
use types::MessageId;

type RoutingResult = Result<(), RoutingError>;

/// A builder to configure and create a new `Node`.
pub struct NodeBuilder {
    cache: Box<Cache>,
    role: Role,
    deny_other_local_nodes: bool,
}

impl NodeBuilder {
    /// Configures the node to use the given request cache.
    pub fn cache(self, cache: Box<Cache>) -> NodeBuilder {
        NodeBuilder { cache: cache, ..self }
    }

    /// Configures the node to start a new network instead of joining an existing one.
    pub fn first(self, first: bool) -> NodeBuilder {
        if first {
            NodeBuilder { role: Role::FirstNode, ..self }
        } else {
            NodeBuilder { role: Role::Node, ..self }
        }
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
    #[cfg(not(feature = "use-mock-crust"))]
    pub fn create(self, event_sender: Sender<Event>) -> Result<Node, RoutingError> {
        sodiumoxide::init();  // enable shared global (i.e. safe to multithread now)

        // start the handler for routing without a restriction to become a full node
        let (action_sender, mut machine) = StateMachine::new(event_sender,
                                                             self.role,
                                                             None,
                                                             self.cache,
                                                             self.deny_other_local_nodes);
        let (tx, rx) = channel();

        let raii_joiner = RaiiThreadJoiner::new(thread!("Node thread", move || {
            machine.run();
        }));

        Ok(Node {
            interface_result_tx: tx,
            interface_result_rx: rx,
            action_sender: action_sender,
            _raii_joiner: raii_joiner,
        })
    }

    /// Creates a new `Node` for unit testing.
    #[cfg(feature = "use-mock-crust")]
    pub fn create(self, event_sender: Sender<Event>) -> Result<Node, RoutingError> {
        // start the handler for routing without a restriction to become a full node
        let (action_sender, machine) = StateMachine::new(event_sender,
                                                         self.role,
                                                         None,
                                                         self.cache,
                                                         self.deny_other_local_nodes);
        let (tx, rx) = channel();

        Ok(Node {
            interface_result_tx: tx,
            interface_result_rx: rx,
            action_sender: action_sender,
            machine: RefCell::new(machine),
        })
    }
}

/// Interface for sending and receiving messages to and from other nodes, in the role of a full
/// routing node.
///
/// A node is a part of the network that can route messages and be member of a group authority. Its
/// methods can be used to send requests and responses as either an individual `ManagedNode` or as
/// a part of a group authority. Their `src` argument indicates that role, so it must always either
/// be the `ManagedNode` with this node's name, or the `ClientManager` or `NodeManager` or
/// `NaeManager` with the address of a client, node or data element that this node is close to.
pub struct Node {
    interface_result_tx: Sender<Result<(), InterfaceError>>,
    interface_result_rx: Receiver<Result<(), InterfaceError>>,
    action_sender: ::types::RoutingActionSender,

    #[cfg(feature = "use-mock-crust")]
    machine: RefCell<StateMachine>,

    #[cfg(not(feature = "use-mock-crust"))]
    _raii_joiner: RaiiThreadJoiner,
}

impl Node {
    /// Creates a new builder to configure and create a `Node`.
    pub fn builder() -> NodeBuilder {
        NodeBuilder {
            cache: Box::new(NullCache),
            role: Role::Node,
            deny_other_local_nodes: false,
        }
    }

    #[cfg(feature = "use-mock-crust")]
    /// Poll and process all events in this node's `Core` instance.
    pub fn poll(&self) -> bool {
        self.machine.borrow_mut().poll()
    }

    #[cfg(feature = "use-mock-crust")]
    /// Resend all unacknowledged messages.
    pub fn resend_unacknowledged(&self) -> bool {
        self.machine.borrow_mut().resend_unacknowledged()
    }

    #[cfg(feature = "use-mock-crust")]
    /// Are there any unacknowledged messages?
    pub fn has_unacknowledged(&self) -> bool {
        self.machine.borrow().has_unacknowledged()
    }

    #[cfg(feature = "use-mock-crust")]
    /// Routing table of this node.
    pub fn routing_table(&self) -> RoutingTable<XorName> {
        self.machine.borrow().routing_table().to_names()
    }

    #[cfg(feature = "use-mock-crust")]
    /// Resend all unacknowledged messages.
    pub fn clear_state(&self) {
        self.machine.borrow_mut().clear_state()
    }

    /// Send a `Get` request to `dst` to retrieve data from the network.
    pub fn send_get_request(&self,
                            src: Authority,
                            dst: Authority,
                            data_request: DataIdentifier,
                            id: MessageId)
                            -> Result<(), InterfaceError> {
        let user_msg = UserMessage::Request(Request::Get(data_request, id));
        self.send_action(src, dst, user_msg, RELOCATE_PRIORITY)
    }

    /// Send a `Put` request to `dst` to store data on the network.
    pub fn send_put_request(&self,
                            src: Authority,
                            dst: Authority,
                            data: Data,
                            id: MessageId)
                            -> Result<(), InterfaceError> {
        let user_msg = UserMessage::Request(Request::Put(data, id));
        self.send_action(src, dst, user_msg, DEFAULT_PRIORITY)
    }

    /// Send a `Post` request to `dst` to modify data on the network.
    pub fn send_post_request(&self,
                             src: Authority,
                             dst: Authority,
                             data: Data,
                             id: MessageId)
                             -> Result<(), InterfaceError> {
        let user_msg = UserMessage::Request(Request::Post(data, id));
        self.send_action(src, dst, user_msg, DEFAULT_PRIORITY)
    }

    /// Send a `Delete` request to `dst` to remove data from the network.
    pub fn send_delete_request(&self,
                               src: Authority,
                               dst: Authority,
                               data: Data,
                               id: MessageId)
                               -> Result<(), InterfaceError> {
        let user_msg = UserMessage::Request(Request::Delete(data, id));
        self.send_action(src, dst, user_msg, DEFAULT_PRIORITY)
    }

    /// Respond to a `Get` request indicating success and sending the requested data.
    pub fn send_get_success(&self,
                            src: Authority,
                            dst: Authority,
                            data: Data,
                            id: MessageId)
                            -> Result<(), InterfaceError> {
        let user_msg = UserMessage::Response(Response::GetSuccess(data, id));
        let priority = if let Authority::Client { .. } = dst {
            CLIENT_GET_PRIORITY
        } else {
            RELOCATE_PRIORITY
        };
        self.send_action(src, dst, user_msg, priority)
    }

    /// Respond to a `Get` request indicating failure.
    pub fn send_get_failure(&self,
                            src: Authority,
                            dst: Authority,
                            data_id: DataIdentifier,
                            external_error_indicator: Vec<u8>,
                            id: MessageId)
                            -> Result<(), InterfaceError> {
        let user_msg = UserMessage::Response(Response::GetFailure {
            id: id,
            data_id: data_id,
            external_error_indicator: external_error_indicator,
        });
        let priority = if let Authority::Client { .. } = dst {
            CLIENT_GET_PRIORITY
        } else {
            RELOCATE_PRIORITY
        };
        self.send_action(src, dst, user_msg, priority)
    }

    /// Respond to a `Put` request indicating success.
    pub fn send_put_success(&self,
                            src: Authority,
                            dst: Authority,
                            name: DataIdentifier,
                            id: MessageId)
                            -> Result<(), InterfaceError> {
        let user_msg = UserMessage::Response(Response::PutSuccess(name, id));
        self.send_action(src, dst, user_msg, DEFAULT_PRIORITY)
    }

    /// Respond to a `Put` request indicating failure.
    pub fn send_put_failure(&self,
                            src: Authority,
                            dst: Authority,
                            data_id: DataIdentifier,
                            external_error_indicator: Vec<u8>,
                            id: MessageId)
                            -> Result<(), InterfaceError> {
        let user_msg = UserMessage::Response(Response::PutFailure {
            id: id,
            data_id: data_id,
            external_error_indicator: external_error_indicator,
        });
        self.send_action(src, dst, user_msg, DEFAULT_PRIORITY)
    }

    /// Respond to a `Post` request indicating success.
    pub fn send_post_success(&self,
                             src: Authority,
                             dst: Authority,
                             name: DataIdentifier,
                             id: MessageId)
                             -> Result<(), InterfaceError> {
        let user_msg = UserMessage::Response(Response::PostSuccess(name, id));
        self.send_action(src, dst, user_msg, DEFAULT_PRIORITY)
    }

    /// Respond to a `Post` request indicating failure.
    pub fn send_post_failure(&self,
                             src: Authority,
                             dst: Authority,
                             data_id: DataIdentifier,
                             external_error_indicator: Vec<u8>,
                             id: MessageId)
                             -> Result<(), InterfaceError> {
        let user_msg = UserMessage::Response(Response::PostFailure {
            id: id,
            data_id: data_id,
            external_error_indicator: external_error_indicator,
        });
        self.send_action(src, dst, user_msg, DEFAULT_PRIORITY)
    }

    /// Respond to a `Delete` request indicating success.
    pub fn send_delete_success(&self,
                               src: Authority,
                               dst: Authority,
                               name: DataIdentifier,
                               id: MessageId)
                               -> Result<(), InterfaceError> {
        let user_msg = UserMessage::Response(Response::DeleteSuccess(name, id));
        self.send_action(src, dst, user_msg, DEFAULT_PRIORITY)
    }

    /// Respond to a `Delete` request indicating failure.
    pub fn send_delete_failure(&self,
                               src: Authority,
                               dst: Authority,
                               data_id: DataIdentifier,
                               external_error_indicator: Vec<u8>,
                               id: MessageId)
                               -> Result<(), InterfaceError> {
        let user_msg = UserMessage::Response(Response::DeleteFailure {
            id: id,
            data_id: data_id,
            external_error_indicator: external_error_indicator,
        });
        self.send_action(src, dst, user_msg, DEFAULT_PRIORITY)
    }

    /// Respond to a `GetAccountInfo` request indicating success.
    pub fn send_get_account_info_success(&self,
                                         src: Authority,
                                         dst: Authority,
                                         data_stored: u64,
                                         space_available: u64,
                                         id: MessageId)
                                         -> Result<(), InterfaceError> {
        let user_msg = UserMessage::Response(Response::GetAccountInfoSuccess {
            id: id,
            data_stored: data_stored,
            space_available: space_available,
        });
        self.send_action(src, dst, user_msg, CLIENT_GET_PRIORITY)
    }

    /// Respond to a `GetAccountInfo` request indicating failure.
    pub fn send_get_account_info_failure(&self,
                                         src: Authority,
                                         dst: Authority,
                                         external_error_indicator: Vec<u8>,
                                         id: MessageId)
                                         -> Result<(), InterfaceError> {
        let user_msg = UserMessage::Response(Response::GetAccountInfoFailure {
            id: id,
            external_error_indicator: external_error_indicator,
        });
        self.send_action(src, dst, user_msg, CLIENT_GET_PRIORITY)
    }

    /// Send a `Refresh` request from `src` to `dst` to trigger churn.
    pub fn send_refresh_request(&self,
                                src: Authority,
                                dst: Authority,
                                content: Vec<u8>,
                                id: MessageId)
                                -> Result<(), InterfaceError> {
        let user_msg = UserMessage::Request(Request::Refresh(content, id));
        self.send_action(src, dst, user_msg, RELOCATE_PRIORITY)
    }

    /// Returns the names of the nodes in the routing table which are closest to the given one.
    pub fn close_group(&self, name: XorName) -> Result<Option<Vec<XorName>>, InterfaceError> {
        let (result_tx, result_rx) = channel();
        try!(self.action_sender.send(Action::CloseGroup {
            name: name,
            result_tx: result_tx,
        }));

        self.receive_action_result(&result_rx)
    }

    /// Returns the name of this node.
    pub fn name(&self) -> Result<XorName, InterfaceError> {
        let (result_tx, result_rx) = channel();
        try!(self.action_sender.send(Action::Name { result_tx: result_tx }));

        self.receive_action_result(&result_rx)
    }

    /// Returns the name of this node.
    pub fn quorum_size(&self) -> Result<usize, InterfaceError> {
        let (result_tx, result_rx) = channel();
        try!(self.action_sender.send(Action::QuorumSize { result_tx: result_tx }));

        self.receive_action_result(&result_rx)
    }

    fn send_action(&self,
                   src: Authority,
                   dst: Authority,
                   user_msg: UserMessage,
                   priority: u8)
                   -> Result<(), InterfaceError> {
        try!(self.action_sender.send(Action::NodeSendMessage {
            src: src,
            dst: dst,
            content: user_msg,
            priority: priority,
            result_tx: self.interface_result_tx.clone(),
        }));

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

impl Drop for Node {
    fn drop(&mut self) {
        if let Err(err) = self.action_sender.send(Action::Terminate) {
            error!("Error {:?} sending event Core", err);
        }
    }
}

// #[cfg(test)]
// mod test {

// pub struct RoutingNetwork;

// impl RoutingNetwork {

//         fn new(size: u32) -> RoutingNetwork {
//             ::utils::initialise_logger(true);


//             let node = || { let _ =
//                 ::std::thread::spawn(move || ::test_utils::node::Node::new().run());
//             };
//             for i in 0..size { node(); ::std::thread::sleep_ms(1000 + i * 1000); }
//             ::std::thread::sleep_ms(size * 1000);

//             RoutingNetwork
//         }
//     }

//     fn calculate_key_name(key: &::std::string::String) -> XorName {
//         XorName::new(::sodiumoxide::crypto::hash::sha256::hash(key.as_bytes()).0)
//     }

//     #[test]
//     fn unit_client_put_get() {
//         // let _ = RoutingNetwork::new(10u32);
//         debug!("Starting client");
//         let mut client = ::test_utils::client::Client::new();
//         ::std::thread::sleep_ms(2000);

//         let key = ::std::string::String::from("key");
//         let value = ::std::string::String::from("value");
//         let name = calculate_key_name(&key.clone());
//         let data = unwrap_result!(::utils::encode(&(key, value)));
//         let data = ::data::Data::PlainData(::plain_data::PlainData::new(name.clone(), data));

//         debug!("Putting data {:?}", data);
//         client.put(data.clone());
//         ::std::thread::sleep_ms(5000);

//         let recovered_data = match client.get(::data::DataIdentifier::PlainData(name)) {
//             Some(data) => data,
//             None => panic!("Failed to recover stored data: {}.", name),
//         };

//         debug!("Recovered data {:?}", recovered_data);
//         assert_eq!(recovered_data, data);
//     }
// }
