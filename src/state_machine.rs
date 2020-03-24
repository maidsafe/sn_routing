// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    action::Action, error::RoutingError, outbox::EventBox, pause::PausedState,
    states::ApprovedPeer, timer::Timer, NetworkEvent,
};
use crossbeam_channel::{Receiver, RecvError, Select, Sender};

/// Holds the current state and handles state transitions.
pub struct StateMachine {
    state: ApprovedPeer,
    network_rx: Receiver<NetworkEvent>,
    network_rx_idx: usize,
    action_rx: Receiver<Action>,
    action_rx_idx: usize,
}

impl StateMachine {
    // Construct a new StateMachine by passing a function returning the initial state.
    pub fn new(
        state: ApprovedPeer,
        action_rx: Receiver<Action>,
        network_rx: Receiver<NetworkEvent>,
    ) -> Self {
        Self {
            state,
            network_rx,
            network_rx_idx: 0,
            action_rx,
            action_rx_idx: 0,
        }
    }

    pub fn pause(self) -> Result<PausedState, RoutingError> {
        info!("Pause");

        let mut paused_state = self.state.pause();
        paused_state.network_rx = Some(self.network_rx);

        Ok(paused_state)
    }

    pub fn resume(mut state: PausedState) -> (Sender<Action>, Self) {
        let (action_tx, action_rx) = crossbeam_channel::unbounded();
        let network_rx = state.network_rx.take().expect("PausedState is incomplete");

        let timer = Timer::new(action_tx.clone());
        let state = ApprovedPeer::resume(state, timer);

        let machine = Self {
            state,
            network_rx,
            network_rx_idx: 0,
            action_rx,
            action_rx_idx: 0,
        };

        info!("Resume");

        (action_tx, machine)
    }

    fn handle_network_event(&mut self, event: NetworkEvent, outbox: &mut dyn EventBox) {
        self.state.handle_network_event(event, outbox)
    }

    fn handle_action(&mut self, action: Action, outbox: &mut dyn EventBox) {
        self.state.handle_action(action, outbox)
    }

    /// Register the state machine event channels with the provided [selector](mpmc::Select).
    pub fn register<'a>(&'a mut self, select: &mut Select<'a>) {
        // Populate action_rx timeouts
        #[cfg(feature = "mock_base")]
        self.state.process_timers();

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
    ///
    /// The returned `bool` can be safely ignored by the consumers of this crate. It is for
    /// internal uses only and will always be `true` unless compiled with `feature=mock_base`.
    pub fn step(&mut self, op_index: usize, outbox: &mut dyn EventBox) -> Result<bool, RecvError> {
        if !self.state.is_running() {
            return Err(RecvError);
        }
        match op_index {
            idx if idx == self.network_rx_idx => {
                let event = self.network_rx.recv()?;
                self.handle_network_event(event, outbox);
                Ok(true)
            }
            idx if idx == self.action_rx_idx => {
                let action = self.action_rx.recv()?;

                let status = is_busy(&action);
                self.handle_action(action, outbox);
                Ok(status)
            }
            _idx => Err(RecvError),
        }
    }

    /// Get reference to the current state.
    pub fn current(&self) -> &ApprovedPeer {
        &self.state
    }

    /// Get mutable reference to the current state.
    pub fn current_mut(&mut self) -> &mut ApprovedPeer {
        &mut self.state
    }
}

#[cfg(not(feature = "mock_base"))]
fn is_busy(_: &Action) -> bool {
    true
}

#[cfg(feature = "mock_base")]
fn is_busy(action: &Action) -> bool {
    match action {
        // Don't consider handling a timeout as being busy. This is a workaround to prevent
        // infinite polling.
        Action::HandleTimeout(_) => false,
        _ => true,
    }
}
