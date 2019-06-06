// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    action::Action,
    chain::{GenesisPfxInfo, SectionInfo},
    id::{FullId, PublicId},
    outbox::EventBox,
    routing_table::Prefix,
    states::common::Base,
    states::{Adult, BootstrappingPeer, Client, Elder, ProvingNode, RelocatingNode},
    timer::Timer,
    types::RoutingActionSender,
    xor_name::XorName,
    BootstrapConfig, {CrustEvent, CrustEventSender, Service, MIN_SECTION_SIZE},
};
#[cfg(feature = "mock_base")]
use crate::{routing_table::Authority, states::common::Bootstrapped, Chain};
use log::LogLevel;
use maidsafe_utilities::event_sender::MaidSafeEventCategory;
use std::{
    collections::BTreeSet,
    fmt::{self, Debug, Display, Formatter},
    mem,
    sync::mpsc::{self, Receiver, RecvError, Sender, TryRecvError},
};
use unwrap::unwrap;

// Execute $expr on the current variant of $self. Execute $term_expr if the current variant is
// `Terminated`.
macro_rules! state_dispatch {
    ($self:expr, $state:pat => $expr:expr, Terminated => $term_expr:expr) => {
        match $self {
            State::BootstrappingPeer($state) => $expr,
            State::Client($state) => $expr,
            State::RelocatingNode($state) => $expr,
            State::ProvingNode($state) => $expr,
            State::Adult($state) => $expr,
            State::Elder($state) => $expr,
            State::Terminated => $term_expr,
        }
    };
}

/// Holds the current state and handles state transitions.
pub struct StateMachine {
    state: State,
    category_rx: Receiver<MaidSafeEventCategory>,
    category_tx: Sender<MaidSafeEventCategory>,
    crust_rx: Receiver<CrustEvent<PublicId>>,
    crust_tx: Sender<CrustEvent<PublicId>>,
    action_rx: Receiver<Action>,
    is_running: bool,
    #[cfg(feature = "mock_base")]
    events: Vec<EventType>,
}

// FIXME - See https://maidsafe.atlassian.net/browse/MAID-2026 for info on removing this exclusion.
#[allow(clippy::large_enum_variant)]
pub enum State {
    BootstrappingPeer(BootstrappingPeer),
    Client(Client),
    RelocatingNode(RelocatingNode),
    ProvingNode(ProvingNode),
    Adult(Adult),
    Elder(Elder),
    Terminated,
}

#[cfg(feature = "mock_base")]
enum EventType {
    CrustEvent(CrustEvent<PublicId>),
    Action(Box<Action>),
}

#[cfg(feature = "mock_base")]
impl EventType {
    fn is_not_a_timeout(&self) -> bool {
        use std::borrow::Borrow;
        match *self {
            EventType::Action(ref action) => match *action.borrow() {
                Action::HandleTimeout(_) => false,
                _ => true,
            },
            _ => true,
        }
    }
}

impl State {
    pub fn handle_action(&mut self, action: Action, outbox: &mut EventBox) -> Transition {
        state_dispatch!(
            *self,
            ref mut state => state.handle_action(action, outbox),
            Terminated => Transition::Terminate
        )
    }

    fn handle_network_event(
        &mut self,
        event: CrustEvent<PublicId>,
        outbox: &mut EventBox,
    ) -> Transition {
        state_dispatch!(
            *self,
            ref mut state => state.handle_network_event(event, outbox),
            Terminated => Transition::Terminate
        )
    }

    pub fn id(&self) -> Option<PublicId> {
        state_dispatch!(
            *self,
            ref state => Some(*state.id()),
            Terminated => None
        )
    }

    pub fn close_group(&self, name: XorName, count: usize) -> Option<Vec<XorName>> {
        state_dispatch!(
            *self,
            ref state => state.close_group(name, count),
            Terminated => None
        )
    }

    pub fn min_section_size(&self) -> usize {
        state_dispatch!(
            *self,
            ref state => state.min_section_size(),
            Terminated => {
                log_or_panic!(
                    LogLevel::Error,
                    "Can't get min_section_size when Terminated."
                );
                MIN_SECTION_SIZE
            }
        )
    }

    fn replace_with<F, E>(&mut self, f: F)
    where
        F: FnOnce(Self) -> Result<Self, E>,
        E: Debug,
    {
        let old_state = mem::replace(self, State::Terminated);
        let old_state_log_ident = format!("{}", old_state);

        match f(old_state) {
            Ok(new_state) => *self = new_state,
            Err(error) => error!(
                "{} - Failed state transition: {:?}",
                old_state_log_ident, error
            ),
        }
    }
}

impl Display for State {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        state_dispatch!(
            *self,
            ref state => write!(formatter, "{}", state),
            Terminated => write!(formatter, "Terminated")
        )
    }
}

impl Debug for State {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        state_dispatch!(
            *self,
            ref state => write!(formatter, "State::{}", state),
            Terminated => write!(formatter, "State::Terminated")
        )
    }
}

#[cfg(feature = "mock_base")]
impl State {
    pub fn chain(&self) -> Option<&Chain> {
        match *self {
            State::Adult(ref state) => Some(state.chain()),
            State::Elder(ref state) => Some(state.chain()),
            State::BootstrappingPeer(_)
            | State::Client(_)
            | State::RelocatingNode(_)
            | State::ProvingNode(_)
            | State::Terminated => None,
        }
    }

    /// Returns this elder state.
    pub fn elder_state(&self) -> Option<&Elder> {
        match *self {
            State::Elder(ref state) => Some(state),
            _ => None,
        }
    }

    /// Returns this elder mut state.
    pub fn elder_state_mut(&mut self) -> Option<&mut Elder> {
        match *self {
            State::Elder(ref mut state) => Some(state),
            _ => None,
        }
    }

    pub fn get_timed_out_tokens(&mut self) -> Vec<u64> {
        match *self {
            State::BootstrappingPeer(_) | State::Terminated => vec![],
            State::Client(ref mut state) => state.get_timed_out_tokens(),
            State::RelocatingNode(ref mut state) => state.get_timed_out_tokens(),
            State::ProvingNode(ref mut state) => state.get_timed_out_tokens(),
            State::Adult(ref mut state) => state.get_timed_out_tokens(),
            State::Elder(ref mut state) => state.get_timed_out_tokens(),
        }
    }

    pub fn has_unpolled_observations(&self) -> bool {
        match *self {
            State::Terminated
            | State::BootstrappingPeer(_)
            | State::Client(_)
            | State::RelocatingNode(_)
            | State::ProvingNode(_) => false,
            State::Adult(ref state) => state.has_unpolled_observations(),
            State::Elder(ref state) => state.has_unpolled_observations(),
        }
    }

    pub fn in_authority(&self, auth: &Authority<XorName>) -> bool {
        state_dispatch!(
            *self,
            ref state => state.in_authority(auth),
            Terminated => false
        )
    }

    pub fn has_unacked_msg(&self) -> bool {
        match *self {
            State::Terminated | State::BootstrappingPeer(_) => false,
            State::Client(ref state) => state.ack_mgr().has_unacked_msg(),
            State::RelocatingNode(ref state) => state.ack_mgr().has_unacked_msg(),
            State::ProvingNode(ref state) => state.ack_mgr().has_unacked_msg(),
            State::Adult(ref state) => state.ack_mgr().has_unacked_msg(),
            State::Elder(ref state) => state.ack_mgr().has_unacked_msg(),
        }
    }
}

/// Enum returned from many message handlers
// FIXME - See https://maidsafe.atlassian.net/browse/MAID-2026 for info on removing this exclusion.
#[allow(clippy::large_enum_variant)]
pub enum Transition {
    Stay,
    // `Bootstrapping` state transitioning to `Client`, `RelocatingNode`, or `ProvingNode`.
    IntoBootstrapped {
        proxy_public_id: PublicId,
    },
    // `RelocatingNode` state transitioning back to `Bootstrapping`.
    IntoBootstrapping {
        new_id: FullId,
        our_section: (Prefix<XorName>, BTreeSet<PublicId>),
    },
    // `ProvingNode` state transitioning to `Adult`.
    IntoAdult {
        gen_pfx_info: GenesisPfxInfo,
    },
    // `Adult` state transition to `Elder`.
    IntoElder {
        sec_info: SectionInfo,
        old_pfx: Prefix<XorName>,
    },
    Terminate,
}

impl StateMachine {
    // Construct a new StateMachine by passing a function returning the initial state.
    #[allow(clippy::new_ret_no_self)]
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
            Some(config) => Service::with_config(crust_sender, config, pub_id),
            None => Service::new(crust_sender, pub_id),
        };

        let mut network_service = unwrap!(res, "Unable to start crust::Service");
        network_service.start_service_discovery();

        let timer = Timer::new(action_sender.clone());

        let state = init_state(action_sender.clone(), network_service, timer, outbox);
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
            #[cfg(feature = "mock_base")]
            events: Vec::new(),
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
            MaidSafeEventCategory::Crust => match self.crust_rx.try_recv() {
                Ok(crust_event) => self.state.handle_network_event(crust_event, outbox),
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
            },
        };

        self.apply_transition(transition, outbox)
    }

    // Handle an event from the list and send any events produced for higher layers.
    #[cfg(feature = "mock_base")]
    fn handle_event_from_list(&mut self, outbox: &mut EventBox) {
        assert!(!self.events.is_empty());
        let event = self.events.remove(0);
        let transition = match event {
            EventType::Action(action) => self.state.handle_action(*action, outbox),
            EventType::CrustEvent(crust_event) => {
                self.state.handle_network_event(crust_event, outbox)
            }
        };

        self.apply_transition(transition, outbox)
    }

    pub fn apply_transition(&mut self, transition: Transition, outbox: &mut EventBox) {
        use self::Transition::*;
        match transition {
            Stay => (),
            IntoBootstrapped { proxy_public_id } => self.state.replace_with(|state| match state {
                State::BootstrappingPeer(src) => src.into_target_state(proxy_public_id, outbox),
                _ => unreachable!(),
            }),
            IntoBootstrapping {
                new_id,
                our_section,
            } => {
                let category_tx = self.category_tx.clone();
                let crust_tx = self.crust_tx.clone();
                let crust_rx = &mut self.crust_rx;

                self.state.replace_with(|state| match state {
                    State::RelocatingNode(src) => {
                        let crust_sender = CrustEventSender::new(
                            crust_tx,
                            MaidSafeEventCategory::Crust,
                            category_tx,
                        );
                        src.into_bootstrapping(crust_rx, crust_sender, new_id, our_section, outbox)
                    }
                    _ => unreachable!(),
                })
            }
            IntoAdult { gen_pfx_info } => self.state.replace_with(|state| match state {
                State::ProvingNode(src) => src.into_establishing_node(gen_pfx_info, outbox),
                _ => unreachable!(),
            }),
            IntoElder { sec_info, old_pfx } => self.state.replace_with(|state| match state {
                State::Adult(src) => src.into_elder(sec_info, old_pfx, outbox),
                _ => unreachable!(),
            }),
            Terminate => self.terminate(),
        }
    }

    fn terminate(&mut self) {
        debug!("{} Terminating state machine", self);
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
    #[cfg(not(feature = "mock_base"))]
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
    #[cfg(feature = "mock_base")]
    pub fn try_step(&mut self, outbox: &mut EventBox) -> Result<(), TryRecvError> {
        use itertools::Itertools;
        use maidsafe_utilities::SeededRng;
        use rand::Rng;
        use std::iter;

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
                MaidSafeEventCategory::Crust => match self.crust_rx.try_recv() {
                    Ok(crust_event) => events.push(EventType::CrustEvent(crust_event)),
                    Err(TryRecvError::Empty) => {}
                    Err(TryRecvError::Disconnected) => {
                        self.apply_transition(Transition::Terminate, outbox);
                        return Ok(());
                    }
                },
            }
        }

        let mut timed_out_events = self
            .state
            .get_timed_out_tokens()
            .iter()
            .map(|token| EventType::Action(Box::new(Action::HandleTimeout(*token))))
            .collect_vec();

        // Interleave timer events with routing or crust events.
        let mut positions = iter::repeat(true)
            .take(timed_out_events.len())
            .chain(iter::repeat(false).take(events.len()))
            .collect_vec();
        SeededRng::thread_rng().shuffle(&mut positions);
        let mut interleaved = positions
            .iter()
            .filter_map(|is_timed_out| {
                if *is_timed_out {
                    timed_out_events.pop()
                } else {
                    events.pop()
                }
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

    /// Get reference to the current state.
    pub fn current(&self) -> &State {
        &self.state
    }

    /// Get mutable reference to the current state.
    pub fn current_mut(&mut self) -> &mut State {
        &mut self.state
    }
}

impl Display for StateMachine {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{:?}", self.state)
    }
}
