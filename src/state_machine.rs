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
use maidsafe_utilities::event_sender::MaidSafeEventCategory;
use std::mem;
use std::sync::mpsc::{self, Receiver, Sender};

use action::Action;
use cache::Cache;
use event::Event;
use id::FullId;
#[cfg(feature = "use-mock-crust")]
use routing_table::RoutingTable;
use states::{Client, Node};
use timer::Timer;
use types::RoutingActionSender;

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
}

pub enum Transition {
    Client,
    Node,
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
               -> (RoutingActionSender, Self)
    {
        let (category_tx, category_rx) = mpsc::channel();
        let (crust_tx, crust_rx) = mpsc::channel();
        let (action_tx, action_rx) = mpsc::channel();

        let action_sender = RoutingActionSender::new(action_tx,
                                                     MaidSafeEventCategory::Routing,
                                                     category_tx.clone());

        let crust_sender = CrustEventSender::new(crust_tx,
                                                 MaidSafeEventCategory::Crust,
                                                 category_tx);

        let crust_service = match Service::new(crust_sender) {
            Ok(service) => service,
            Err(error) => panic!("Unable to start crust::Service {:?}", error),
        };

        let timer = Timer::new(action_sender.clone());

        // TODO: start in the `Client` state
        let state = Node::new(event_sender,
                              crust_service,
                              timer,
                              role,
                              keys,
                              cache,
                              deny_other_local_nodes);

        let machine = StateMachine {
            category_rx: category_rx,
            crust_rx: crust_rx,
            action_rx: action_rx,
            state: State::Node(state),
        };

        (action_sender, machine)
    }

    /// If there is an event in the queue, processes it and returns true.
    /// otherwise returns false. Never blocks.
    #[cfg(feature = "use-mock-crust")]
    pub fn poll(&mut self) -> bool {
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
        // Note: can't use self.category_rx.iter()... because of borrow checker.
        loop {
            let run = self.category_rx
                .recv()
                .map(|category| self.handle_event(category))
                .unwrap_or(false);

            if !run {
                break;
            }
        }
    }

    /// Routing table of this node.
    #[cfg(feature = "use-mock-crust")]
    pub fn routing_table(&self) -> &RoutingTable {
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

    fn handle_event(&mut self, category: MaidSafeEventCategory) -> bool {
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
            Transition::Client => {
                self.transition_to_client();
                true
            }
            Transition::Node => {
                self.transition_to_node();
                true
            }
            Transition::Terminate => false,
        }
    }

    fn transition_to_client(&mut self) {
        if let State::Client(_) = self.state {
            return;
        }

        self.transition(State::into_client)
    }

    fn transition_to_node(&mut self) {
        if let State::Node(_) = self.state {
            return;
        }

        self.transition(State::into_node)
    }

    fn transition<F>(&mut self, f: F) where F: FnOnce(State) -> State {
        let prev_state = mem::replace(&mut self.state, State::Transitioning);
        let next_state = f(prev_state);
        let _ = mem::replace(&mut self.state, next_state);
    }
}

impl State {
    fn handle_action(&mut self, action: Action) -> Transition {
        match *self {
            State::Client(ref mut state) => state.handle_action(action),
            State::Node(ref mut state) => state.handle_action(action),
            State::Transitioning => unreachable!(),
        }
    }

    fn handle_crust_event(&mut self, event: CrustEvent) -> Transition {
        match *self {
            State::Client(ref mut state) => state.handle_crust_event(event),
            State::Node(ref mut state) => state.handle_crust_event(event),
            State::Transitioning => unreachable!(),
        }
    }

    fn into_client(self) -> State {
        match self {
            State::Node(state) => State::Client(state.into_client()),
            _ => unreachable!(),
        }
    }

    fn into_node(self) -> State {
        match self {
            State::Client(state) => State::Node(state.into_node()),
            _ => unreachable!(),
        }
    }
}
