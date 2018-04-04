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

use {CrustEvent, CrustEventSender, MIN_SECTION_SIZE, Service};
use BootstrapConfig;
use action::Action;
use id::{FullId, PublicId};
use log::Level;
use maidsafe_utilities::event_sender::MaidSafeEventCategory;
#[cfg(feature = "use-mock-crust")]
use mock_crust;
use outbox::EventBox;
use routing_table::{Prefix, RoutingTable};
#[cfg(feature = "use-mock-crust")]
use rust_sodium::crypto::sign;
use states::{Bootstrapping, Client, JoiningNode, Node};
use states::common::Base;
#[cfg(feature = "use-mock-crust")]
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt::{self, Debug, Formatter};
use std::mem;
#[cfg(feature = "use-mock-crust")]
use std::net::IpAddr;
use std::sync::mpsc::{self, Receiver, RecvError, Sender, TryRecvError};
use timer::Timer;
use types::RoutingActionSender;
use xor_name::XorName;

/// Holds the current state and handles state transitions.
pub struct StateMachine {
    state: State,
    category_rx: Receiver<MaidSafeEventCategory>,
    category_tx: Sender<MaidSafeEventCategory>,
    crust_rx: Receiver<CrustEvent<PublicId>>,
    crust_tx: Sender<CrustEvent<PublicId>>,
    action_rx: Receiver<Action>,
    is_running: bool,
    #[cfg(feature = "use-mock-crust")]
    events: Vec<EventType>,
}

// FIXME - See https://maidsafe.atlassian.net/browse/MAID-2026 for info on removing this exclusion.
#[cfg_attr(feature = "cargo-clippy", allow(large_enum_variant))]
pub enum State {
    Bootstrapping(Bootstrapping),
    Client(Client),
    JoiningNode(JoiningNode),
    Node(Node),
    Terminated,
}

#[cfg(feature = "use-mock-crust")]
enum EventType {
    CrustEvent(CrustEvent<PublicId>),
    Action(Box<Action>),
}

#[cfg(feature = "use-mock-crust")]
impl EventType {
    fn is_not_a_timeout(&self) -> bool {
        use std::borrow::Borrow;
        match *self {
            EventType::Action(ref action) => {
                match *action.borrow() {
                    Action::Timeout(_) => false,
                    _ => true,
                }
            }
            _ => true,
        }
    }
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

    fn handle_crust_event(
        &mut self,
        event: CrustEvent<PublicId>,
        outbox: &mut EventBox,
    ) -> Transition {
        match *self {
            State::Bootstrapping(ref mut state) => state.handle_crust_event(event, outbox),
            State::Client(ref mut state) => state.handle_crust_event(event, outbox),
            State::JoiningNode(ref mut state) => state.handle_crust_event(event, outbox),
            State::Node(ref mut state) => state.handle_crust_event(event, outbox),
            State::Terminated => Transition::Terminate,
        }
    }

    fn id(&self) -> Option<PublicId> {
        self.base_state().map(|state| *state.id())
    }

    fn routing_table(&self) -> Option<&RoutingTable<XorName>> {
        match *self {
            State::Node(ref state) => Some(state.routing_table()),
            _ => None,
        }
    }

    fn close_group(&self, name: XorName, count: usize) -> Option<Vec<XorName>> {
        self.base_state().and_then(
            |state| state.close_group(name, count),
        )
    }

    fn min_section_size(&self) -> usize {
        self.base_state().map_or_else(
            || {
                log_or_panic!(Level::Error, "Can't get min_section_size when Terminated.");
                MIN_SECTION_SIZE
            },
            Base::min_section_size,
        )
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
    pub fn purge_invalid_rt_entry(&mut self) {
        if let State::Node(ref mut state) = *self {
            state.purge_invalid_rt_entry();
        }
    }

    pub fn has_tunnel_clients(&self, client_1: PublicId, client_2: PublicId) -> bool {
        match *self {
            State::Node(ref state) => state.has_tunnel_clients(client_1, client_2),
            _ => false,
        }
    }

    pub fn section_list_signatures(
        &self,
        prefix: Prefix<XorName>,
    ) -> Option<BTreeMap<PublicId, sign::Signature>> {
        match *self {
            State::Node(ref state) => state.section_list_signatures(prefix).ok(),
            _ => None,
        }
    }

    pub fn get_banned_client_ips(&self) -> BTreeSet<IpAddr> {
        match *self {
            State::Node(ref state) => state.get_banned_client_ips(),
            _ => panic!("Should be State::Node"),
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

    pub fn get_timed_out_tokens(&mut self) -> Vec<u64> {
        match *self {
            State::Node(ref mut state) => state.get_timed_out_tokens(),
            State::Client(ref mut state) => state.get_timed_out_tokens(),
            State::JoiningNode(ref mut state) => state.get_timed_out_tokens(),
            _ => vec![],
        }
    }

    pub fn has_unnormalised_routing_conn(&self, excludes: &BTreeSet<XorName>) -> bool {
        match *self {
            State::Node(ref state) => state.has_unnormalised_routing_conn(excludes),
            _ => false,
        }
    }

    pub fn get_user_msg_parts_count(&self) -> u64 {
        match *self {
            State::Node(ref state) => state.get_user_msg_parts_count(),
            State::Client(ref state) => state.get_user_msg_parts_count(),
            _ => 0,
        }
    }

    pub fn get_clients_usage(&self) -> Option<BTreeMap<IpAddr, u64>> {
        match *self {
            State::Node(ref state) => Some(state.get_clients_usage()),
            _ => None,
        }
    }
}

/// Enum returned from many message handlers
// FIXME - See https://maidsafe.atlassian.net/browse/MAID-2026 for info on removing this exclusion.
#[cfg_attr(feature = "cargo-clippy", allow(large_enum_variant))]
pub enum Transition {
    Stay,
    // `Bootstrapping` state transitioning to `Client`, `JoiningNode`, or `Node`.
    IntoBootstrapped { proxy_public_id: PublicId },
    // `JoiningNode` state transitioning back to `Bootstrapping`.
    IntoBootstrapping {
        new_id: FullId,
        our_section: (Prefix<XorName>, BTreeSet<PublicId>),
    },
    Terminate,
}

impl StateMachine {
    // Construct a new StateMachine by passing a function returning the initial state.
    pub fn new<F>(
        init_state: F,
        pub_id: PublicId,
        bootstrap_config: Option<BootstrapConfig>,
        outbox: &mut EventBox,
    ) -> (RoutingActionSender, Self)
    where
        F: FnOnce(RoutingActionSender, Service, Timer, &mut EventBox) -> State,
    {
        let (category_tx, category_rx) = mpsc::channel();
        let (crust_tx, crust_rx) = mpsc::channel();
        let (action_tx, action_rx) = mpsc::channel();

        let action_sender = RoutingActionSender::new(
            action_tx,
            MaidSafeEventCategory::Routing,
            category_tx.clone(),
        );

        let crust_sender = CrustEventSender::new(
            crust_tx.clone(),
            MaidSafeEventCategory::Crust,
            category_tx.clone(),
        );

        let res = match bootstrap_config {
            #[cfg(feature = "use-mock-crust")]
            Some(c) => Service::with_config(mock_crust::take_current(), crust_sender, c, pub_id),
            #[cfg(not(feature = "use-mock-crust"))]
            Some(c) => Service::with_config(crust_sender, c, pub_id),
            #[cfg(feature = "use-mock-crust")]
            None => Service::new(mock_crust::take_current(), crust_sender, pub_id),
            #[cfg(not(feature = "use-mock-crust"))]
            None => Service::new(crust_sender, pub_id),
        };

        let mut crust_service = unwrap!(res, "Unable to start crust::Service");

        crust_service.start_service_discovery();

        let timer = Timer::new(action_sender.clone());

        let state = init_state(action_sender.clone(), crust_service, timer, outbox);
        let is_running = match state {
            State::Terminated => false,
            _ => true,
        };
        #[cfg(feature = "use-mock-crust")]
        let machine = StateMachine {
            category_rx: category_rx,
            category_tx: category_tx,
            crust_rx: crust_rx,
            crust_tx: crust_tx,
            action_rx: action_rx,
            state: state,
            is_running: is_running,
            events: Vec::new(),
        };
        #[cfg(not(feature = "use-mock-crust"))]
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
                        debug!(
                            "Crust receiver temporarily empty, probably due to node \
                               relocation."
                        );
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

    // Handle an event from the list and send any events produced for higher layers.
    #[cfg(feature = "use-mock-crust")]
    fn handle_event_from_list(&mut self, outbox: &mut EventBox) {
        assert!(!self.events.is_empty());
        let event = self.events.remove(0);
        let transition = match event {
            EventType::Action(action) => self.state.handle_action(*action, outbox),
            EventType::CrustEvent(crust_event) => {
                self.state.handle_crust_event(crust_event, outbox)
            }
        };

        self.apply_transition(transition, outbox)
    }

    pub fn apply_transition(&mut self, transition: Transition, outbox: &mut EventBox) {
        use self::Transition::*;
        match transition {
            Stay => (),
            IntoBootstrapped { proxy_public_id } => {
                let new_state = match mem::replace(&mut self.state, State::Terminated) {
                    State::Bootstrapping(bootstrapping) => {
                        bootstrapping.into_target_state(proxy_public_id, outbox)
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
                        let crust_sender = CrustEventSender::new(
                            self.crust_tx.clone(),
                            MaidSafeEventCategory::Crust,
                            self.category_tx.clone(),
                        );
                        joining_node.into_bootstrapping(
                            &mut self.crust_rx,
                            crust_sender,
                            new_id,
                            our_section,
                            outbox,
                        )
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
    #[cfg(not(feature = "use-mock-crust"))]
    pub fn try_step(&mut self, outbox: &mut EventBox) -> Result<(), TryRecvError> {
        if self.is_running {
            let category = self.category_rx.try_recv()?;
            self.handle_event(category, outbox);
            Ok(())
        } else {
            Err(TryRecvError::Disconnected)
        }
    }

    /// Query for a result, or yield: Err(NothingAvailable), Err(Disconnected).
    #[cfg(feature = "use-mock-crust")]
    pub fn try_step(&mut self, outbox: &mut EventBox) -> Result<(), TryRecvError> {
        use itertools::Itertools;
        use maidsafe_utilities::SeededRng;
        use rand::Rng;
        use std::iter::{self, Iterator};

        if !self.is_running {
            return Err(TryRecvError::Disconnected);
        }
        let mut events = Vec::new();
        while let Ok(category) = self.category_rx.try_recv() {
            match category {
                MaidSafeEventCategory::Routing => {
                    if let Ok(action) = self.action_rx.try_recv() {
                        events.push(EventType::Action(Box::new(action)));
                    } else {
                        self.apply_transition(Transition::Terminate, outbox);
                        return Ok(());
                    }
                }
                MaidSafeEventCategory::Crust => {
                    match self.crust_rx.try_recv() {
                        Ok(crust_event) => events.push(EventType::CrustEvent(crust_event)),
                        Err(TryRecvError::Empty) => {}
                        Err(TryRecvError::Disconnected) => {
                            self.apply_transition(Transition::Terminate, outbox);
                            return Ok(());
                        }
                    }
                }
            }
        }

        let mut timed_out_events = self.state
            .get_timed_out_tokens()
            .iter()
            .map(|token| EventType::Action(Box::new(Action::Timeout(*token))))
            .collect_vec();

        // Interleave timer events with routing or crust events.
        let mut positions = iter::repeat(true)
            .take(timed_out_events.len())
            .chain(iter::repeat(false).take(events.len()))
            .collect_vec();
        SeededRng::thread_rng().shuffle(&mut positions);
        let mut interleaved = positions
            .iter()
            .filter_map(|is_timed_out| if *is_timed_out {
                timed_out_events.pop()
            } else {
                events.pop()
            })
            .collect_vec();
        interleaved.reverse();
        self.events.extend(interleaved);

        if self.events.iter().any(EventType::is_not_a_timeout) {
            self.handle_event_from_list(outbox);
            return Ok(());
        }
        while !self.events.is_empty() {
            self.handle_event_from_list(outbox);
        }
        Err(TryRecvError::Empty)
    }

    pub fn id(&self) -> Option<PublicId> {
        self.state.id()
    }

    pub fn routing_table(&self) -> Option<&RoutingTable<XorName>> {
        self.state.routing_table()
    }

    pub fn close_group(&self, name: XorName, count: usize) -> Option<Vec<XorName>> {
        self.state.close_group(name, count)
    }

    pub fn min_section_size(&self) -> usize {
        self.state.min_section_size()
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
