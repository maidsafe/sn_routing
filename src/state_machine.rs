// Copyright 2016 MaidSafe.net limited.
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
use crust::{CrustEventSender, PeerId, Service};
use crust::Event as CrustEvent;
use id::PublicId;
use maidsafe_utilities::event_sender::MaidSafeEventCategory;
#[cfg(feature = "use-mock-crust")]
use routing_table::{Prefix, RoutingTable};
use rust_sodium::crypto::sign;
use states::{Bootstrapping, Client, Node};
use std::collections::BTreeMap;
use std::fmt::{self, Debug, Formatter};
use std::mem;
use std::sync::mpsc::{self, Receiver};
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
    is_running: bool,
}

pub enum State {
    Bootstrapping(Bootstrapping),
    Client(Client),
    Node(Node),
    Terminated,
}

impl State {
    fn handle_action(&mut self, action: Action) -> Transition {
        match *self {
            State::Bootstrapping(ref mut state) => state.handle_action(action),
            State::Client(ref mut state) => state.handle_action(action),
            State::Node(ref mut state) => state.handle_action(action),
            State::Terminated => Transition::Terminate,
        }
    }

    fn handle_crust_event(&mut self, event: CrustEvent) -> Transition {
        match *self {
            State::Bootstrapping(ref mut state) => state.handle_crust_event(event),
            State::Client(ref mut state) => state.handle_crust_event(event),
            State::Node(ref mut state) => state.handle_crust_event(event),
            State::Terminated => Transition::Terminate,
        }
    }

    fn into_bootstrapped(self, proxy_peer_id: PeerId, proxy_public_id: PublicId) -> Self {
        match self {
            State::Bootstrapping(state) => {
                if state.client_restriction() {
                    State::Client(state.into_client(proxy_peer_id, proxy_public_id))
                } else if let Some(state) = state.into_node(proxy_peer_id, proxy_public_id) {
                    State::Node(state)
                } else {
                    State::Terminated
                }
            }
            _ => unreachable!(),
        }
    }
}

impl Debug for State {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match *self {
            State::Bootstrapping(ref inner) => write!(formatter, "State::{:?}", inner),
            State::Client(ref inner) => write!(formatter, "State::{:?}", inner),
            State::Node(ref inner) => write!(formatter, "State::{:?}", inner),
            State::Terminated => write!(formatter, "State::Terminated"),
        }
    }
}

#[cfg(feature = "use-mock-crust")]
impl State {
    pub fn resend_unacknowledged(&mut self) -> bool {
        match *self {
            State::Client(ref mut state) => state.resend_unacknowledged(),
            State::Node(ref mut state) => state.resend_unacknowledged(),
            State::Bootstrapping(_) |
            State::Terminated => false,
        }
    }

    pub fn has_unacknowledged(&self) -> bool {
        match *self {
            State::Client(ref state) => state.has_unacknowledged(),
            State::Node(ref state) => state.has_unacknowledged(),
            State::Bootstrapping(_) |
            State::Terminated => false,
        }
    }

    pub fn routing_table(&self) -> Option<&RoutingTable<XorName>> {
        match *self {
            State::Node(ref state) => Some(state.routing_table()),
            _ => None,
        }
    }

    pub fn clear_state(&mut self) {
        match *self {
            State::Node(ref mut state) => state.clear_state(),
            State::Bootstrapping(_) |
            State::Client(_) |
            State::Terminated => (),
        }
    }

    pub fn section_list_signatures(&self,
                                   prefix: Prefix<XorName>)
                                   -> Option<BTreeMap<PublicId, sign::Signature>> {
        match *self {
            State::Node(ref state) => Some(state.section_list_signatures(prefix)),
            _ => None,
        }
    }

    pub fn set_next_node_name(&mut self, relocation_name: Option<XorName>) {
        if let State::Node(ref mut state) = *self {
            state.set_next_node_name(relocation_name);
        }
    }
}

/// Enum returned from many message handlers
pub enum Transition {
    // Stay in the current state.
    Stay,
    // Transition into a bootstrapped state (Node or Client).
    IntoBootstrapped {
        proxy_peer_id: PeerId,
        proxy_public_id: PublicId,
    },
    // Terminate
    Terminate,
}

impl StateMachine {
    // Construct a new StateMachine by passing a function returning the initial
    // state.
    pub fn new<F>(init_state: F) -> (RoutingActionSender, Self)
        where F: FnOnce(Service, Timer) -> State
    {
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

        let state = init_state(crust_service, timer);
        let is_running = match state {
            State::Terminated => false,
            _ => true,
        };

        let machine = StateMachine {
            category_rx: category_rx,
            crust_rx: crust_rx,
            action_rx: action_rx,
            state: state,
            is_running: is_running,
        };

        (action_sender, machine)
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
            Transition::IntoBootstrapped { proxy_peer_id, proxy_public_id } => {
                // Temporarily switch to `Terminated` to allow moving out of the current
                // state without moving `self`.
                let prev_state = mem::replace(&mut self.state, State::Terminated);
                self.state = prev_state.into_bootstrapped(proxy_peer_id, proxy_public_id);
            }
            Transition::Terminate => self.terminate(),
        }
    }

    fn terminate(&mut self) {
        self.is_running = false;
    }
}

impl Debug for StateMachine {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        self.state.fmt(formatter)
    }
}

#[cfg(not(feature = "use-mock-crust"))]
impl StateMachine {
    /// Run the event loop for sending and receiving messages. Blocks until
    /// the core is terminated, so it must be called in a separate thread.
    pub fn run(&mut self) {
        while self.is_running {
            if let Ok(category) = self.category_rx.recv() {
                self.handle_event(category);
            } else {
                break;
            }
        }
    }
}

#[cfg(feature = "use-mock-crust")]
impl StateMachine {
    /// If there is an event in the queue, processes it and returns true.
    /// otherwise returns false. Never blocks.
    pub fn poll(&mut self) -> bool {
        match self.category_rx.try_recv() {
            Ok(category) => {
                self.handle_event(category);
                true
            }
            _ => false,
        }
    }

    /// Get reference to the current state.
    pub fn current(&self) -> &State {
        &self.state
    }

    /// Get mutable reference to the current state.
    pub fn current_mut(&mut self) -> &mut State {
        &mut self.state
    }
}
