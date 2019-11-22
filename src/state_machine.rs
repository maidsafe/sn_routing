// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    action::Action,
    chain::{EldersInfo, GenesisPfxInfo},
    error::RoutingError,
    id::{P2pNode, PublicId},
    network_service::NetworkBuilder,
    outbox::EventBox,
    pause::PausedState,
    relocation::{RelocatePayload, SignedRelocateDetails},
    routing_table::Prefix,
    states::common::Base,
    states::{Adult, BootstrappingPeer, Elder, JoiningPeer},
    timer::Timer,
    xor_name::XorName,
    ConnectionInfo, NetworkConfig, NetworkEvent, NetworkService,
};
#[cfg(feature = "mock_base")]
use crate::{chain::DevParams, rng::MainRng, routing_table::Authority, Chain};
use crossbeam_channel as mpmc;
#[cfg(feature = "mock_base")]
use std::net::SocketAddr;
use std::{
    fmt::{self, Debug, Display, Formatter},
    mem,
};
use unwrap::unwrap;

// Execute $expr on the current variant of $self. Execute $term_expr if the current variant is
// `Terminated`.
macro_rules! state_dispatch {
    ($self:expr, $state:pat => $expr:expr, Terminated => $term_expr:expr) => {
        match $self {
            State::BootstrappingPeer($state) => $expr,
            State::JoiningPeer($state) => $expr,
            State::Adult($state) => $expr,
            State::Elder($state) => $expr,
            State::Terminated => $term_expr,
        }
    };
}

/// Holds the current state and handles state transitions.
pub struct StateMachine {
    state: State,
    network_rx: mpmc::Receiver<NetworkEvent>,
    network_rx_idx: usize,
    action_rx: mpmc::Receiver<Action>,
    action_rx_idx: usize,
    is_running: bool,
    #[cfg(feature = "mock_base")]
    events: Vec<EventType>,
}

// FIXME - See https://maidsafe.atlassian.net/browse/MAID-2026 for info on removing this exclusion.
#[allow(clippy::large_enum_variant)]
pub enum State {
    BootstrappingPeer(BootstrappingPeer),
    JoiningPeer(JoiningPeer),
    Adult(Adult),
    Elder(Elder),
    Terminated,
}

#[cfg(feature = "mock_base")]
enum EventType {
    NetworkEvent(NetworkEvent),
    Action(Box<Action>),
}

#[cfg(feature = "mock_base")]
impl EventType {
    fn is_not_a_timeout(&self) -> bool {
        match *self {
            EventType::Action(ref action) => match **action {
                Action::HandleTimeout(_) => false,
                _ => true,
            },
            _ => true,
        }
    }
}

impl State {
    pub fn handle_action(&mut self, action: Action, outbox: &mut dyn EventBox) -> Transition {
        state_dispatch!(
            *self,
            ref mut state => state.handle_action(action, outbox),
            Terminated => Transition::Terminate
        )
    }

    pub fn finish_handle_transition(&mut self, outbox: &mut dyn EventBox) -> Transition {
        state_dispatch!(
            *self,
            ref mut state => state.finish_handle_transition(outbox),
            Terminated => Transition::Terminate
        )
    }

    fn handle_network_event(
        &mut self,
        event: NetworkEvent,
        outbox: &mut dyn EventBox,
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

    pub fn our_elders(&self) -> Option<impl Iterator<Item = &P2pNode>> {
        match *self {
            State::Elder(ref state) => Some(state.our_elders()),
            State::BootstrappingPeer(_)
            | State::JoiningPeer(_)
            | State::Adult(_)
            | State::Terminated => None,
        }
    }

    pub fn our_connection_info(&mut self) -> Result<ConnectionInfo, RoutingError> {
        state_dispatch!(
            self,
            state => state.network_service_mut().our_connection_info().map_err(RoutingError::from),
            Terminated => Err(RoutingError::InvalidStateForOperation)
        )
    }

    /// Returns this elder mut state.
    pub fn elder_state_mut(&mut self) -> Option<&mut Elder> {
        match *self {
            State::Elder(ref mut state) => Some(state),
            _ => None,
        }
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
    pub fn dev_params(&self) -> &DevParams {
        state_dispatch!(
            *self,
            ref state => state.dev_params(),
            Terminated => unreachable!()
        )
    }

    pub fn dev_params_mut(&mut self) -> &mut DevParams {
        state_dispatch!(
            *self,
            ref mut state => state.dev_params_mut(),
            Terminated => unreachable!()
        )
    }

    pub fn chain(&self) -> Option<&Chain> {
        match *self {
            State::Adult(ref state) => Some(state.chain()),
            State::Elder(ref state) => Some(state.chain()),
            State::BootstrappingPeer(_) | State::JoiningPeer(_) | State::Terminated => None,
        }
    }

    /// Returns this elder state.
    pub fn elder_state(&self) -> Option<&Elder> {
        match *self {
            State::Elder(ref state) => Some(state),
            _ => None,
        }
    }

    pub fn get_timed_out_tokens(&mut self) -> Vec<u64> {
        match *self {
            State::BootstrappingPeer(_) | State::Terminated => vec![],
            State::JoiningPeer(ref mut state) => state.get_timed_out_tokens(),
            State::Adult(ref mut state) => state.get_timed_out_tokens(),
            State::Elder(ref mut state) => state.get_timed_out_tokens(),
        }
    }

    pub fn has_unpolled_observations(&self) -> bool {
        match *self {
            State::Terminated | State::BootstrappingPeer(_) | State::JoiningPeer(_) => false,
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

    pub fn is_connected(&self, socket_addr: &SocketAddr) -> bool {
        state_dispatch!(
            self,
            state => state.peer_map().has(socket_addr),
            Terminated => false
        )
    }

    pub fn rng(&mut self) -> &mut MainRng {
        state_dispatch!(
            self,
            state => state.rng(),
            Terminated => unreachable!()
        )
    }
}

/// Enum returned from many message handlers
// FIXME - See https://maidsafe.atlassian.net/browse/MAID-2026 for info on removing this exclusion.
#[allow(clippy::large_enum_variant)]
pub enum Transition {
    Stay,
    // `BootstrappingPeer` state transitioning to `JoiningPeer`
    IntoJoining {
        p2p_nodes: Vec<P2pNode>,
        relocate_payload: Option<RelocatePayload>,
    },
    // `JoiningPeer` failing to join and transitioning back to `BootstrappingPeer`
    Rebootstrap,
    // Node getting relocated.
    Relocate {
        conn_infos: Vec<ConnectionInfo>,
        details: SignedRelocateDetails,
    },
    // `JoiningPeer` state transitioning to `Adult`.
    IntoAdult {
        gen_pfx_info: GenesisPfxInfo,
    },
    // `Adult` state transition to `Elder`.
    IntoElder {
        elders_info: EldersInfo,
        old_pfx: Prefix<XorName>,
    },
    Terminate,
}

impl Debug for Transition {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::Stay => write!(f, "Stay"),
            Self::IntoJoining { .. } => write!(f, "IntoJoining"),
            Self::Rebootstrap => write!(f, "Rebootstrap"),
            Self::Relocate { .. } => write!(f, "Relocate"),
            Self::IntoAdult { .. } => write!(f, "IntoAdult"),
            Self::IntoElder { .. } => write!(f, "IntoElder"),
            Self::Terminate => write!(f, "Terminate"),
        }
    }
}

impl StateMachine {
    // Construct a new StateMachine by passing a function returning the initial state.
    pub fn new<F>(
        init_state: F,
        network_config: NetworkConfig,
        outbox: &mut dyn EventBox,
    ) -> (mpmc::Sender<Action>, Self)
    where
        F: FnOnce(NetworkService, Timer, &mut dyn EventBox) -> State,
    {
        let (action_tx, action_rx) = mpmc::unbounded();
        let (network_tx, network_rx) = mpmc::unbounded();

        let network_service = unwrap!(
            NetworkBuilder::new(network_tx)
                .with_config(network_config)
                .build(),
            "Unable to start network service"
        );

        let timer = Timer::new(action_tx.clone());
        let state = init_state(network_service, timer, outbox);
        let is_running = match state {
            State::Terminated => false,
            _ => true,
        };

        let machine = StateMachine {
            state,
            network_rx,
            network_rx_idx: 0,
            action_rx,
            action_rx_idx: 0,
            is_running,
            #[cfg(feature = "mock_base")]
            events: Vec::new(),
        };

        (action_tx, machine)
    }

    pub fn pause(self) -> Result<PausedState, RoutingError> {
        // TODO: should we allow pausing from other states too?
        match self.state {
            State::Elder(state) => {
                let mut state = state.pause()?;
                state.network_rx = Some(self.network_rx);
                Ok(state)
            }
            _ => Err(RoutingError::InvalidStateForOperation),
        }
    }

    pub fn resume(mut state: PausedState) -> (mpmc::Sender<Action>, Self) {
        let (action_tx, action_rx) = mpmc::unbounded();
        let network_rx = state.network_rx.take().expect("PausedState is incomplete");

        let timer = Timer::new(action_tx.clone());
        let state = State::Elder(Elder::resume(state, timer));
        let machine = StateMachine {
            state,
            network_rx,
            network_rx_idx: 0,
            action_rx,
            action_rx_idx: 0,
            is_running: true,
            #[cfg(feature = "mock_base")]
            events: Vec::new(),
        };

        (action_tx, machine)
    }

    fn handle_network_event(&mut self, event: NetworkEvent, outbox: &mut dyn EventBox) {
        let transition = self.state.handle_network_event(event, outbox);
        self.apply_transition(transition, outbox)
    }

    fn handle_action(&mut self, action: Action, outbox: &mut dyn EventBox) {
        let transition = self.state.handle_action(action, outbox);
        self.apply_transition(transition, outbox)
    }

    pub fn apply_transition(&mut self, transition: Transition, outbox: &mut dyn EventBox) {
        use self::Transition::*;
        match transition {
            Stay => return,
            Terminate => {
                self.terminate();
                return;
            }
            IntoJoining {
                p2p_nodes,
                relocate_payload,
            } => self.state.replace_with(|state| match state {
                State::BootstrappingPeer(src) => {
                    src.into_joining(p2p_nodes, relocate_payload, outbox)
                }
                _ => unreachable!(),
            }),
            Rebootstrap => self.state.replace_with(|state| match state {
                State::JoiningPeer(src) => src.rebootstrap(),
                State::Adult(src) => src.rebootstrap(),
                _ => unreachable!(),
            }),
            Relocate {
                details,
                conn_infos,
            } => self.state.replace_with(|state| match state {
                State::Elder(src) => src.relocate(conn_infos, details),
                _ => unreachable!(),
            }),
            IntoAdult { gen_pfx_info } => self.state.replace_with(|state| match state {
                State::JoiningPeer(src) => src.into_adult(gen_pfx_info, outbox),
                _ => unreachable!(),
            }),
            IntoElder {
                elders_info,
                old_pfx,
            } => self.state.replace_with(|state| match state {
                State::Adult(src) => src.into_elder(elders_info, old_pfx, outbox),
                _ => unreachable!(),
            }),
        }

        let new_transition = self.state.finish_handle_transition(outbox);
        self.apply_transition(new_transition, outbox)
    }

    fn terminate(&mut self) {
        debug!("{} Terminating state machine", self);
        self.is_running = false;
    }

    /// Register the state machine event channels with the provided [selector](mpmc::Select).
    pub fn register<'a>(&'a mut self, select: &mut mpmc::Select<'a>) {
        let network_rx_idx = select.recv(&self.network_rx);
        let action_rx_idx = select.recv(&self.action_rx);
        self.network_rx_idx = network_rx_idx;
        self.action_rx_idx = action_rx_idx;
    }

    /// Processes events received externally from one of the channels.
    /// For this function to work properly, the state machine event channels need to
    /// be registered by calling [`StateMachine::register`](#method.register).
    /// [`Select::ready`] needs to be called to get `op_index`, the event channel index.
    /// The resulting events are streamed into `outbox`.
    ///
    /// This function is non-blocking.
    ///
    /// Errors are permanent failures due to either: state machine termination,
    /// the permanent closing of one of the event channels, or an invalid (unknown)
    /// channel index.
    ///
    /// [`Select::ready`]: https://docs.rs/crossbeam-channel/0.3/crossbeam_channel/struct.Select.html#method.ready
    pub fn step(
        &mut self,
        op_index: usize,
        outbox: &mut dyn EventBox,
    ) -> Result<(), mpmc::RecvError> {
        if !self.is_running {
            return Err(mpmc::RecvError);
        }
        match op_index {
            idx if idx == self.network_rx_idx => {
                let event = self.network_rx.recv()?;
                self.handle_network_event(event, outbox)
            }
            idx if idx == self.action_rx_idx => {
                let action = self.action_rx.recv()?;
                self.handle_action(action, outbox)
            }
            _idx => return Err(mpmc::RecvError),
        };
        Ok(())
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

#[cfg(not(feature = "mock_base"))]
impl StateMachine {
    /// Query for a result, or yield: Err(NothingAvailable), Err(Disconnected) or Err(Terminated).
    pub fn try_step(&mut self, outbox: &mut dyn EventBox) -> Result<(), mpmc::TryRecvError> {
        if self.is_running {
            match self.network_rx.try_recv() {
                Ok(event) => {
                    self.handle_network_event(event, outbox);
                    return Ok(());
                }
                Err(mpmc::TryRecvError::Empty) => (),
                Err(error) => return Err(error),
            }

            let action = self.action_rx.try_recv()?;
            self.handle_action(action, outbox);
            Ok(())
        } else {
            Err(mpmc::TryRecvError::Disconnected)
        }
    }
}

#[cfg(feature = "mock_base")]
impl StateMachine {
    // Handle an event from the list and send any events produced for higher layers.
    fn handle_event_from_list(&mut self, outbox: &mut dyn EventBox) {
        assert!(!self.events.is_empty());
        let event = self.events.remove(0);
        match event {
            EventType::Action(action) => self.handle_action(*action, outbox),
            EventType::NetworkEvent(event) => self.handle_network_event(event, outbox),
        };
    }

    /// Query for a result, or yield: Err(NothingAvailable), Err(Disconnected).
    pub fn try_step(&mut self, outbox: &mut dyn EventBox) -> Result<(), mpmc::TryRecvError> {
        use itertools::Itertools;
        use rand::Rng;
        use std::iter;

        if !self.is_running {
            return Err(mpmc::TryRecvError::Disconnected);
        }

        let mut events = Vec::new();
        let mut received = true;

        while received {
            received = false;

            match self.network_rx.try_recv() {
                Ok(event) => {
                    received = true;
                    events.push(EventType::NetworkEvent(event));
                }
                Err(mpmc::TryRecvError::Empty) => (),
                Err(mpmc::TryRecvError::Disconnected) => {
                    self.apply_transition(Transition::Terminate, outbox);
                    return Ok(());
                }
            }

            if let Ok(action) = self.action_rx.try_recv() {
                received = true;
                events.push(EventType::Action(Box::new(action)));
            }
        }

        let mut timed_out_events = self
            .state
            .get_timed_out_tokens()
            .iter()
            .map(|token| EventType::Action(Box::new(Action::HandleTimeout(*token))))
            .collect_vec();

        // Interleave timer events with routing or network events.
        let mut positions = iter::repeat(true)
            .take(timed_out_events.len())
            .chain(iter::repeat(false).take(events.len()))
            .collect_vec();

        self.state.rng().shuffle(&mut positions);

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
        Err(mpmc::TryRecvError::Empty)
    }
}

impl Display for StateMachine {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{:?}", self.state)
    }
}
