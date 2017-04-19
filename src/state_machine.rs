// Copyright 2016 MaidSafe.net limited.
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

use action::Action;
use crust::{CrustEventSender, PeerId, Service};
use crust::Event as CrustEvent;
use id::{FullId, PublicId};
use maidsafe_utilities::event_sender::MaidSafeEventCategory;
use outbox::EventBox;
#[cfg(feature = "use-mock-crust")]
use routing_table::Prefix;
use routing_table::RoutingTable;
#[cfg(feature = "use-mock-crust")]
use rust_sodium::crypto::sign;
use states::{Bootstrapping, Client, JoiningNode, Node};
use states::common::Base;
#[cfg(feature = "use-mock-crust")]
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt::{self, Debug, Formatter};
use std::mem;
use std::sync::mpsc::{self, Receiver, RecvError, Sender, TryRecvError};
use timer::Timer;
use types::RoutingActionSender;
use xor_name::XorName;

/// Holds the current state and handles state transitions.
pub struct StateMachine {
    state: State,
    category_rx: Receiver<MaidSafeEventCategory>,
    category_tx: Sender<MaidSafeEventCategory>,
    crust_rx: Receiver<CrustEvent>,
    crust_tx: Sender<CrustEvent>,
    action_rx: Receiver<Action>,
    is_running: bool,
}

// FIXME - See https://maidsafe.atlassian.net/browse/MAID-2026 for info on removing this exclusion.
#[cfg_attr(feature="cargo-clippy", allow(large_enum_variant))]
pub enum State {
    Bootstrapping(Bootstrapping),
    Client(Client),
    JoiningNode(JoiningNode),
    Node(Node),
    Terminated,
}

impl State {
    pub fn handle_action(&mut self, action: Action, outbox: &mut EventBox) -> Transition {
        match *self {
            State::Bootstrapping(ref mut state) => state.handle_action(action),
            State::Client(ref mut state) => state.handle_action(action),
            State::JoiningNode(ref mut state) => state.handle_action(action, outbox),
            State::Node(ref mut state) => state.handle_action(action, outbox),
            State::Terminated => Transition::Terminate,
        }
    }

    fn handle_crust_event(&mut self, event: CrustEvent, outbox: &mut EventBox) -> Transition {
        match *self {
            State::Bootstrapping(ref mut state) => state.handle_crust_event(event, outbox),
            State::Client(ref mut state) => state.handle_crust_event(event, outbox),
            State::JoiningNode(ref mut state) => state.handle_crust_event(event, outbox),
            State::Node(ref mut state) => state.handle_crust_event(event, outbox),
            State::Terminated => Transition::Terminate,
        }
    }

    fn name(&self) -> Option<XorName> {
        self.base_state().map(|state| *state.name())
    }

    fn routing_table(&self) -> Option<&RoutingTable<XorName>> {
        match *self {
            State::Node(ref state) => Some(state.routing_table()),
            _ => None,
        }
    }

    fn close_group(&self, name: XorName, count: usize) -> Option<Vec<XorName>> {
        self.base_state()
            .and_then(|state| state.close_group(name, count))
    }

    fn base_state(&self) -> Option<&Base> {
        match *self {
            State::Bootstrapping(ref bootstrapping) => Some(bootstrapping),
            State::Client(ref client) => Some(client),
            State::JoiningNode(ref joining_node) => Some(joining_node),
            State::Node(ref node) => Some(node),
            State::Terminated => None,
        }
    }
}

impl Debug for State {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match *self {
            State::Bootstrapping(ref inner) => write!(formatter, "State::{:?}", inner),
            State::Client(ref inner) => write!(formatter, "State::{:?}", inner),
            State::JoiningNode(ref inner) => write!(formatter, "State::{:?}", inner),
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
            State::JoiningNode(ref mut state) => state.resend_unacknowledged(),
            State::Node(ref mut state) => state.resend_unacknowledged(),
            State::Bootstrapping(_) |
            State::Terminated => false,
        }
    }

    pub fn has_unacknowledged(&self) -> bool {
        match *self {
            State::Client(ref state) => state.has_unacknowledged(),
            State::Node(ref state) => state.has_unacknowledged(),
            State::JoiningNode(ref state) => state.has_unacknowledged(),
            State::Bootstrapping(_) |
            State::Terminated => false,
        }
    }

    pub fn purge_invalid_rt_entry(&mut self) {
        if let State::Node(ref mut state) = *self {
            state.purge_invalid_rt_entry();
        }
    }

    pub fn has_tunnel_clients(&self, client_1: PeerId, client_2: PeerId) -> bool {
        match *self {
            State::Node(ref state) => state.has_tunnel_clients(client_1, client_2),
            _ => false,
        }
    }

    pub fn clear_state(&mut self) {
        match *self {
            State::Node(ref mut state) => state.clear_state(),
            State::Bootstrapping(_) |
            State::Client(_) |
            State::JoiningNode(_) |
            State::Terminated => (),
        }
    }

    pub fn section_list_signatures(&self,
                                   prefix: Prefix<XorName>)
                                   -> Option<BTreeMap<PublicId, sign::Signature>> {
        match *self {
            State::Node(ref state) => state.section_list_signatures(prefix).ok(),
            _ => None,
        }
    }

    pub fn set_next_relocation_dst(&mut self, dst: Option<XorName>) {
        if let State::Node(ref mut node) = *self {
            node.set_next_relocation_dst(dst);
        }
    }

    pub fn set_next_relocation_interval(&mut self, interval: (XorName, XorName)) {
        if let State::Node(ref mut node) = *self {
            node.set_next_relocation_interval(interval);
        }
    }
}

/// Enum returned from many message handlers
// FIXME - See https://maidsafe.atlassian.net/browse/MAID-2026 for info on removing this exclusion.
#[cfg_attr(feature="cargo-clippy", allow(large_enum_variant))]
pub enum Transition {
    Stay,
    // `Bootstrapping` state transitioning to `Client`, `JoiningNode`, or `Node`.
    IntoBootstrapped {
        proxy_peer_id: PeerId,
        proxy_public_id: PublicId,
    },
    // `JoiningNode` state transitioning back to `Bootstrapping`.
    IntoBootstrapping {
        new_id: FullId,
        our_section: BTreeSet<PublicId>,
    },
    Terminate,
}

impl StateMachine {
    // Construct a new StateMachine by passing a function returning the initial state.
    pub fn new<F>(init_state: F, outbox: &mut EventBox) -> (RoutingActionSender, Self)
        where F: FnOnce(RoutingActionSender, Service, Timer, &mut EventBox) -> State
    {
        let (category_tx, category_rx) = mpsc::channel();
        let (crust_tx, crust_rx) = mpsc::channel();
        let (action_tx, action_rx) = mpsc::channel();

        let action_sender = RoutingActionSender::new(action_tx,
                                                     MaidSafeEventCategory::Routing,
                                                     category_tx.clone());

        let crust_sender = CrustEventSender::new(crust_tx.clone(),
                                                 MaidSafeEventCategory::Crust,
                                                 category_tx.clone());

        let mut crust_service = match Service::new(crust_sender) {
            Ok(service) => service,
            Err(error) => panic!("Unable to start crust::Service {:?}", error),
        };
        crust_service.start_service_discovery();

        let timer = Timer::new(action_sender.clone());

        let state = init_state(action_sender.clone(), crust_service, timer, outbox);
        let is_running = match state {
            State::Terminated => false,
            _ => true,
        };

        let machine = StateMachine {
            category_rx: category_rx,
            category_tx: category_tx,
            crust_rx: crust_rx,
            crust_tx: crust_tx,
            action_rx: action_rx,
            state: state,
            is_running: is_running,
        };

        (action_sender, machine)
    }

    // Handle an event from the given category and send any events produced for higher layers.
    fn handle_event(&mut self, category: MaidSafeEventCategory, outbox: &mut EventBox) {
        let transition = match category {
            MaidSafeEventCategory::Routing => {
                if let Ok(action) = self.action_rx.try_recv() {
                    self.state.handle_action(action, outbox)
                } else {
                    Transition::Terminate
                }
            }
            MaidSafeEventCategory::Crust => {
                match self.crust_rx.try_recv() {
                    Ok(crust_event) => self.state.handle_crust_event(crust_event, outbox),
                    Err(TryRecvError::Empty) => {
                        debug!("Crust receiver temporarily empty, probably due to node \
                               relocation.");
                        Transition::Stay
                    }
                    Err(TryRecvError::Disconnected) => {
                        debug!("Logic error: Crust receiver disconnected.");
                        Transition::Terminate
                    }
                }
            }
        };

        self.apply_transition(transition, outbox)
    }

    pub fn apply_transition(&mut self, transition: Transition, outbox: &mut EventBox) {
        use self::Transition::*;
        match transition {
            Stay => (),
            IntoBootstrapped {
                proxy_peer_id,
                proxy_public_id,
            } => {
                let new_state = match mem::replace(&mut self.state, State::Terminated) {
                    State::Bootstrapping(bootstrapping) => {
                        bootstrapping.into_target_state(proxy_peer_id, proxy_public_id, outbox)
                    }
                    _ => unreachable!(),
                };
                self.state = new_state;
            }
            IntoBootstrapping {
                new_id,
                our_section,
            } => {
                let new_state = match mem::replace(&mut self.state, State::Terminated) {
                    State::JoiningNode(joining_node) => {
                        let crust_sender = CrustEventSender::new(self.crust_tx.clone(),
                                                                 MaidSafeEventCategory::Crust,
                                                                 self.category_tx.clone());
                        joining_node.into_bootstrapping(&mut self.crust_rx,
                                                        crust_sender,
                                                        new_id,
                                                        our_section,
                                                        outbox)
                    }
                    _ => unreachable!(),
                };
                self.state = new_state;
            }
            Terminate => self.terminate(),
        }
    }

    fn terminate(&mut self) {
        debug!("{:?} Terminating state machine", self);
        self.is_running = false;
    }

    /// Block until the machine steps and returns some events.
    ///
    /// Errors are permanent failures due to either: state machine termination or
    /// the permanent closing of the `category_rx` event channel.
    pub fn step(&mut self, outbox: &mut EventBox) -> Result<(), RecvError> {
        if self.is_running {
            let category = self.category_rx.recv()?;
            self.handle_event(category, outbox);
            Ok(())
        } else {
            Err(RecvError)
        }
    }

    /// Query for a result, or yield: Err(NothingAvailable), Err(Disconnected) or Err(Terminated).
    pub fn try_step(&mut self, outbox: &mut EventBox) -> Result<(), TryRecvError> {
        if self.is_running {
            let category = self.category_rx.try_recv()?;
            self.handle_event(category, outbox);
            Ok(())
        } else {
            Err(TryRecvError::Disconnected)
        }
    }

    pub fn name(&self) -> Option<XorName> {
        self.state.name()
    }

    pub fn routing_table(&self) -> Option<&RoutingTable<XorName>> {
        self.state.routing_table()
    }

    pub fn close_group(&self, name: XorName, count: usize) -> Option<Vec<XorName>> {
        self.state.close_group(name, count)
    }

    #[cfg(feature = "use-mock-crust")]
    /// Get reference to the current state.
    pub fn current(&self) -> &State {
        &self.state
    }

    /// Get mutable reference to the current state.
    pub fn current_mut(&mut self) -> &mut State {
        &mut self.state
    }
}

impl Debug for StateMachine {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        self.state.fmt(formatter)
    }
}
