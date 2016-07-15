// Copyright 2016 MaidSafe.net limited.
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

use crust::Event as CrustEvent;
use crust::{CrustEventSender, Service};
#[cfg(feature = "use-mock-crust")]
use kademlia_routing_table::RoutingTable;
use maidsafe_utilities::event_sender::MaidSafeEventCategory;
use std::collections::HashSet;
use std::mem;
use std::sync::mpsc::{self, Receiver, Sender};

use action::Action;
use authority::Authority;
use cache::Cache;
use event::Event;
use id::{FullId, PublicId};
use states::{Client, Node};
use timer::Timer;
use types::RoutingActionSender;
#[cfg(feature = "use-mock-crust")]
use xor_name::XorName;

/// Holds the current state and handles state transitions.
pub struct StateMachine {
    state: State,
    category_rx: Receiver<MaidSafeEventCategory>,
    crust_rx: Receiver<CrustEvent>,
    action_rx: Receiver<Action>,
}

pub enum State {
    Client(Client),
    Node(Node),
    Transitioning,
    Terminated,
}

pub enum Transition {
    // Stay in the current state
    Stay,
    // Transition to Node
    IntoNode {
        close_group_ids: Vec<PublicId>,
        dst: Authority,
    },
    // Terminate
    Terminate,
}

/// The role this `StateMachine` instance intends to act as once it joined the network.
#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone, Copy)]
pub enum Role {
    /// Remain a client and not become a full routing node.
    Client,
    /// Join an existing network as a routing node.
    Node,
    /// Start a new network as its first node.
    FirstNode,
}

impl StateMachine {
    pub fn new(event_sender: Sender<Event>,
               role: Role,
               keys: Option<FullId>,
               cache: Box<Cache>,
               deny_other_local_nodes: bool)
               -> (RoutingActionSender, Self) {
        let (category_tx, category_rx) = mpsc::channel();
        let (crust_tx, crust_rx) = mpsc::channel();
        let (action_tx, action_rx) = mpsc::channel();

        let action_sender = RoutingActionSender::new(action_tx,
                                                     MaidSafeEventCategory::Routing,
                                                     category_tx.clone());

        let crust_sender =
            CrustEventSender::new(crust_tx, MaidSafeEventCategory::Crust, category_tx);

        let mut crust_service = match Service::new(crust_sender) {
            Ok(service) => service,
            Err(error) => panic!("Unable to start crust::Service {:?}", error),
        };
        crust_service.start_service_discovery();

        let timer = Timer::new(action_sender.clone());
        let full_id = keys.unwrap_or_else(FullId::new);

        let state = if role == Role::FirstNode {
            State::Node(Node::first(cache, crust_service, event_sender, full_id, timer))
        } else if deny_other_local_nodes && crust_service.has_peers_on_lan() {
            error!("Disconnected({:?}) More than 1 routing node found on LAN. Currently this is \
                    not supported",
                   full_id.public_id().name());
            let _ = event_sender.send(Event::Terminate);
            State::Terminated
        } else {
            State::Client(Client::new(HashSet::new(),
                                      cache,
                                      role == Role::Client,
                                      crust_service,
                                      event_sender,
                                      full_id,
                                      timer))
        };

        let machine = StateMachine {
            category_rx: category_rx,
            crust_rx: crust_rx,
            action_rx: action_rx,
            state: state,
        };

        (action_sender, machine)
    }

    /// If there is an event in the queue, processes it and returns true.
    /// otherwise returns false. Never blocks.
    #[cfg(feature = "use-mock-crust")]
    pub fn poll(&mut self) -> bool {
        if let State::Terminated = self.state {
            return false;
        }

        match self.category_rx.try_recv() {
            Ok(category) => {
                self.handle_event(category);
                true
            }
            _ => false,
        }
    }

    /// Run the event loop for sending and receiving messages. Blocks until
    /// the core is terminated, so it must be called in a separate thread.
    #[cfg(not(feature = "use-mock-crust"))]
    pub fn run(&mut self) {
        loop {
            if let State::Terminated = self.state {
                break;
            }

            if let Ok(category) = self.category_rx.recv() {
                self.handle_event(category);
            } else {
                break;
            }
        }
    }

    /// Routing table of this node.
    #[cfg(feature = "use-mock-crust")]
    pub fn routing_table(&self) -> &RoutingTable<XorName> {
        match self.state {
            State::Client(ref state) => state.routing_table(),
            State::Node(ref state) => state.routing_table(),
            _ => unreachable!(),
        }
    }

    /// resends all unacknowledged messages.
    #[cfg(feature = "use-mock-crust")]
    pub fn resend_unacknowledged(&mut self) -> bool {
        match self.state {
            State::Client(ref mut state) => state.resend_unacknowledged(),
            State::Node(ref mut state) => state.resend_unacknowledged(),
            _ => unreachable!(),
        }
    }

    /// Are there any unacknowledged messages?
    #[cfg(feature = "use-mock-crust")]
    pub fn has_unacknowledged(&self) -> bool {
        match self.state {
            State::Client(ref state) => state.has_unacknowledged(),
            State::Node(ref state) => state.has_unacknowledged(),
            _ => unreachable!(),
        }
    }

    /// Clears all state containers except `bootstrap_blacklist`.
    #[cfg(feature = "use-mock-crust")]
    pub fn clear_state(&mut self) {
        match self.state {
            State::Client(ref mut state) => state.clear_state(),
            State::Node(ref mut state) => state.clear_state(),
            _ => unreachable!(),
        }
    }

    fn handle_event(&mut self, category: MaidSafeEventCategory) {
        let transition = match category {
            MaidSafeEventCategory::Routing => {
                if let Ok(action) = self.action_rx.try_recv() {
                    self.state.handle_action(action)
                } else {
                    Transition::Terminate
                }
            }
            MaidSafeEventCategory::Crust => {
                if let Ok(crust_event) = self.crust_rx.try_recv() {
                    self.state.handle_crust_event(crust_event)
                } else {
                    Transition::Terminate
                }
            }
        };

        match transition {
            Transition::Stay => (),
            Transition::Terminate => self.terminate(),
            Transition::IntoNode { close_group_ids, dst } => {
                self.transition_to_node(close_group_ids, dst)
            }
        }
    }

    fn transition_to_node(&mut self, close_group_ids: Vec<PublicId>, dst: Authority) {
        let prev_state = mem::replace(&mut self.state, State::Transitioning);
        self.state = prev_state.into_node(close_group_ids, dst);
    }

    fn terminate(&mut self) {
        self.state = State::Terminated;
    }
}

impl State {
    fn handle_action(&mut self, action: Action) -> Transition {
        match *self {
            State::Client(ref mut state) => state.handle_action(action),
            State::Node(ref mut state) => state.handle_action(action),
            State::Terminated | State::Transitioning => unreachable!(),
        }
    }

    fn handle_crust_event(&mut self, event: CrustEvent) -> Transition {
        match *self {
            State::Client(ref mut state) => state.handle_crust_event(event),
            State::Node(ref mut state) => state.handle_crust_event(event),
            State::Terminated | State::Transitioning => unreachable!(),
        }
    }

    fn into_node(self, close_group_ids: Vec<PublicId>, dst: Authority) -> State {
        match self {
            State::Client(state) => State::Node(state.into_node(close_group_ids, dst)),
            _ => unreachable!(),
        }
    }
}
