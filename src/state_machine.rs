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
    network_service::NetworkBuilder,
    outbox::EventBox,
    routing_table::Prefix,
    states::common::Base,
    states::{Adult, BootstrappingPeer, Client, Elder, ProvingNode, RelocatingNode},
    timer::Timer,
    xor_name::XorName,
    NetworkConfig, NetworkEvent, NetworkService, MIN_SECTION_SIZE,
};
#[cfg(feature = "mock_base")]
use crate::{routing_table::Authority, Chain};
use crossbeam_channel as mpmc;
use log::LogLevel;
use std::{
    collections::BTreeSet,
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
    network_rx: mpmc::Receiver<NetworkEvent>,
    action_rx: mpmc::Receiver<Action>,
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
    pub fn handle_action(&mut self, action: Action, outbox: &mut EventBox) -> Transition {
        state_dispatch!(
            *self,
            ref mut state => state.handle_action(action, outbox),
            Terminated => Transition::Terminate
        )
    }

    fn handle_network_event(&mut self, event: NetworkEvent, outbox: &mut EventBox) -> Transition {
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
        network_config: NetworkConfig,
        outbox: &mut EventBox,
    ) -> (mpmc::Sender<Action>, Self)
    where
        F: FnOnce(mpmc::Sender<Action>, NetworkService, Timer, &mut EventBox) -> State,
    {
        let (network_tx, network_rx) = mpmc::unbounded();
        let (action_tx, action_rx) = mpmc::unbounded();

        let network_service = unwrap!(
            NetworkBuilder::new(network_tx)
                .with_config(network_config)
                .build(),
            "Unable to start network service"
        );

        let timer = Timer::new(action_tx.clone());
        let state = init_state(action_tx.clone(), network_service, timer, outbox);
        let is_running = match state {
            State::Terminated => false,
            _ => true,
        };
        let machine = StateMachine {
            state: state,
            network_rx,
            action_rx,
            is_running: is_running,
            #[cfg(feature = "mock_base")]
            events: Vec::new(),
        };

        (action_tx, machine)
    }

    fn handle_network_event(&mut self, event: NetworkEvent, outbox: &mut EventBox) {
        let transition = self.state.handle_network_event(event, outbox);
        self.apply_transition(transition, outbox)
    }

    fn handle_action(&mut self, action: Action, outbox: &mut EventBox) {
        let transition = self.state.handle_action(action, outbox);
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
            } => self.state.replace_with::<_, ()>(|state| match state {
                State::RelocatingNode(src) => {
                    Ok(src.into_bootstrapping(new_id, our_section, outbox))
                }
                _ => unreachable!(),
            }),
            IntoAdult { gen_pfx_info } => self.state.replace_with(|state| match state {
                State::ProvingNode(src) => src.into_adult(gen_pfx_info, outbox),
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
    // TODO: remove the #[allow]s below once crossbeam-channel gets fixed
    #[allow(clippy::drop_copy)]
    #[allow(clippy::zero_ptr)]
    pub fn step(&mut self, outbox: &mut EventBox) -> Result<(), mpmc::RecvError> {
        if self.is_running {
            mpmc::select! {
                recv(self.network_rx) -> event => self.handle_network_event(event?, outbox),
                recv(self.action_rx) -> action => self.handle_action(action?, outbox),
            }
            Ok(())
        } else {
            Err(mpmc::RecvError)
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

#[cfg(not(feature = "mock_base"))]
impl StateMachine {
    /// Query for a result, or yield: Err(NothingAvailable), Err(Disconnected) or Err(Terminated).
    pub fn try_step(&mut self, outbox: &mut EventBox) -> Result<(), mpmc::TryRecvError> {
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
    fn handle_event_from_list(&mut self, outbox: &mut EventBox) {
        assert!(!self.events.is_empty());
        let event = self.events.remove(0);
        let transition = match event {
            EventType::Action(action) => self.state.handle_action(*action, outbox),
            EventType::NetworkEvent(event) => self.state.handle_network_event(event, outbox),
        };

        self.apply_transition(transition, outbox)
    }

    /// Query for a result, or yield: Err(NothingAvailable), Err(Disconnected).
    pub fn try_step(&mut self, outbox: &mut EventBox) -> Result<(), mpmc::TryRecvError> {
        use itertools::Itertools;
        use maidsafe_utilities::SeededRng;
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
        Err(mpmc::TryRecvError::Empty)
    }
}

impl Display for StateMachine {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{:?}", self.state)
    }
}
