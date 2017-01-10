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
use cache::NullCache;
use data::{AppendWrapper, Data, DataIdentifier};
use error::{InterfaceError, RoutingError};
use event::Event;
use evented::{Evented, ToEvented};
use id::FullId;
#[cfg(not(feature = "use-mock-crust"))]
use maidsafe_utilities::thread::{self, Joiner};
use messages::{CLIENT_GET_PRIORITY, DEFAULT_PRIORITY, Request};
use routing_table::Authority;
#[cfg(not(feature = "use-mock-crust"))]
use rust_sodium;
use state_machine::{State, StateMachine};
use states;
#[cfg(feature = "use-mock-crust")]
use std::cell::RefCell;
#[cfg(feature = "use-mock-crust")]
use std::collections::VecDeque;
use std::sync::mpsc::{Receiver, Sender, channel};
#[cfg(feature = "use-mock-crust")]
use std::sync::mpsc::TryRecvError;
use types::MessageId;
use types::RoutingActionSender;
use xor_name::XorName;

/// Interface for sending and receiving messages to and from a network of nodes in the role of a
/// client.
///
/// A client is connected to the network via one or more nodes. Messages are never routed via a
/// client, and a client cannot be part of a section authority.
pub struct Client {
    interface_result_tx: Sender<Result<(), InterfaceError>>,
    interface_result_rx: Receiver<Result<(), InterfaceError>>,
    action_sender: RoutingActionSender,

    #[cfg(feature = "use-mock-crust")]
    machine: RefCell<StateMachine>,

    #[cfg(feature = "use-mock-crust")]
    event_buffer: RefCell<VecDeque<Event>>,

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
    /// cryptographically secure and uses section consensus. The restriction for the client name
    /// exists to ensure that the client cannot choose its `ClientAuthority`.
    #[cfg(not(feature = "use-mock-crust"))]
    pub fn new(event_sender: Sender<Event>,
               keys: Option<FullId>,
               min_section_size: usize)
               -> Result<Client, RoutingError> {
        rust_sodium::init();  // enable shared global (i.e. safe to multithread now)

        // start the handler for routing with a restriction to become a full node
        let mut events = Evented::empty();
        let (action_sender, mut machine) = Self::make_state_machine(keys, min_section_size)
            .extract(&mut events);

        for ev in events.into_events() {
            event_sender.send(ev)?;
        }

        let (tx, rx) = channel();

        let raii_joiner = thread::named("Client thread", move || {
            // Gather events from the state machine's event loop and proxy them over the
            // event_sender channel.
            while let Ok(events) = machine.step() {
                for ev in events {
                    // If sending the event fails, terminate this thread.
                    if event_sender.send(ev).is_err() {
                        return;
                    }
                }
            }
            // When there are no more events to process, terminate this thread.
        });

        Ok(Client {
            interface_result_tx: tx,
            interface_result_rx: rx,
            action_sender: action_sender,
            _raii_joiner: raii_joiner,
        })
    }

    fn make_state_machine(keys: Option<FullId>,
                          min_section_size: usize)
                          -> Evented<(RoutingActionSender, StateMachine)> {
        let cache = Box::new(NullCache);
        let full_id = keys.unwrap_or_else(FullId::new);

        StateMachine::new(move |crust_service, timer| {
            State::Bootstrapping(states::Bootstrapping::new(cache,
                                                            true,
                                                            crust_service,
                                                            full_id,
                                                            min_section_size,
                                                            timer))
                .to_evented()
        })
    }

    /// Send a Get message with a `DataIdentifier` to an `Authority`, signed with given keys.
    pub fn send_get_request(&self,
                            dst: Authority<XorName>,
                            data_id: DataIdentifier,
                            message_id: MessageId)
                            -> Result<(), InterfaceError> {
        self.send_action(Request::Get(data_id, message_id), dst, CLIENT_GET_PRIORITY)
    }

    /// Add something to the network
    pub fn send_put_request(&self,
                            dst: Authority<XorName>,
                            data: Data,
                            message_id: MessageId)
                            -> Result<(), InterfaceError> {
        self.send_action(Request::Put(data, message_id), dst, DEFAULT_PRIORITY)
    }

    /// Change something already on the network
    pub fn send_post_request(&self,
                             dst: Authority<XorName>,
                             data: Data,
                             message_id: MessageId)
                             -> Result<(), InterfaceError> {
        self.send_action(Request::Post(data, message_id), dst, DEFAULT_PRIORITY)
    }

    /// Remove something from the network
    pub fn send_delete_request(&self,
                               dst: Authority<XorName>,
                               data: Data,
                               message_id: MessageId)
                               -> Result<(), InterfaceError> {
        self.send_action(Request::Delete(data, message_id), dst, DEFAULT_PRIORITY)
    }

    /// Append an item to appendable data.
    pub fn send_append_request(&self,
                               dst: Authority<XorName>,
                               wrapper: AppendWrapper,
                               message_id: MessageId)
                               -> Result<(), InterfaceError> {
        self.send_action(Request::Append(wrapper, message_id), dst, DEFAULT_PRIORITY)
    }


    /// Request account information for the Client calling this function
    pub fn send_get_account_info_request(&self,
                                         dst: Authority<XorName>,
                                         message_id: MessageId)
                                         -> Result<(), InterfaceError> {
        self.send_action(Request::GetAccountInfo(message_id),
                         dst,
                         CLIENT_GET_PRIORITY)
    }

    /// Returns the name of this node.
    pub fn name(&self) -> Result<XorName, InterfaceError> {
        let (result_tx, result_rx) = channel();
        self.action_sender.send(Action::Name { result_tx: result_tx })?;

        self.receive_action_result(&result_rx)
    }

    fn send_action(&self,
                   content: Request,
                   dst: Authority<XorName>,
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

    fn receive_action_result<T>(&self, rx: &Receiver<T>) -> Result<T, InterfaceError> {
        // If we're running with mock_crust, then the state machine needs to be stepped
        // manually in order to process the action we just sent it.
        #[cfg(feature = "use-mock-crust")]
        assert!(self.poll());

        Ok(rx.recv()?)
    }
}

#[cfg(feature = "use-mock-crust")]
impl Client {
    /// Create a new `Client` for unit testing.
    pub fn new(keys: Option<FullId>, min_section_size: usize) -> Result<Client, RoutingError> {
        // start the handler for routing with a restriction to become a full node
        let mut events = VecDeque::new();

        let (action_sender, machine) = Self::make_state_machine(keys, min_section_size)
            .extract_to_buf(&mut events);

        let (tx, rx) = channel();

        Ok(Client {
            interface_result_tx: tx,
            interface_result_rx: rx,
            action_sender: action_sender,
            machine: RefCell::new(machine),
            event_buffer: RefCell::new(events),
        })
    }

    /// Get the next event in a non-blocking manner.
    ///
    /// Either reads from the internal buffer, or prompts a state machine step.
    pub fn try_next_ev(&self) -> Result<Event, TryRecvError> {
        if let Some(cached_ev) = self.event_buffer.borrow_mut().pop_front() {
            return Ok(cached_ev);
        }
        if let Ok(new_events) = self.try_step() {
            self.event_buffer.borrow_mut().extend(new_events);
        }
        self.event_buffer.borrow_mut().pop_front().ok_or(TryRecvError::Empty)
    }

    /// Process all inbound events and buffer any produced events on the internal buffer.
    pub fn poll(&self) -> bool {
        let mut result = false;
        while let Ok(new_events) = self.try_step() {
            self.event_buffer.borrow_mut().extend(new_events);
            result = true;
        }
        result
    }

    /// Step the underlying state machine if there are any events for it to process.
    fn try_step(&self) -> Result<Vec<Event>, TryRecvError> {
        self.machine.borrow_mut().try_step()
    }

    /// Resend all unacknowledged messages.
    pub fn resend_unacknowledged(&self) -> bool {
        let mut events = Evented::empty();
        let result =
            self.machine.borrow_mut().current_mut().resend_unacknowledged().extract(&mut events);
        self.event_buffer.borrow_mut().extend(events.into_events());
        result
    }

    /// Are there any unacknowledged messages?
    pub fn has_unacknowledged(&self) -> bool {
        self.machine.borrow().current().has_unacknowledged()
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        if let Err(err) = self.action_sender.send(Action::Terminate) {
            debug!("Error {:?} sending event to Core", err);
        }
    }
}
