// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    action::Action, error::RoutingError, outbox::EventBox, pause::PausedState,
    states::ApprovedPeer, NetworkEvent,
};
use crossbeam_channel::{RecvError, Select, Sender};

/// Holds the current state and handles state transitions.
pub struct StateMachine {
    state: ApprovedPeer,
}

impl StateMachine {
    // Construct a new StateMachine by passing a function returning the initial state.
    pub fn new(state: ApprovedPeer) -> Self {
        Self { state }
    }

    pub fn pause(self) -> Result<PausedState, RoutingError> {
        Ok(self.state.pause())
    }

    pub fn resume(state: PausedState) -> (Self, Sender<Action>) {
        let (state, action_tx) = ApprovedPeer::resume(state);
        let machine = Self { state };
        (machine, action_tx)
    }

    fn handle_network_event(&mut self, event: NetworkEvent, outbox: &mut dyn EventBox) {
        self.state.handle_network_event(event, outbox)
    }

    fn handle_action(&mut self, action: Action, outbox: &mut dyn EventBox) {
        self.state.handle_action(action, outbox)
    }

    /// Register the state machine event channels with the provided [selector](mpmc::Select).
    pub fn register<'a>(&'a mut self, select: &mut Select<'a>) {
        self.state.register(select);
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
            idx if idx == self.state.network_rx_idx => {
                let event = self.state.network_rx.recv()?;
                self.handle_network_event(event, outbox);
                Ok(true)
            }
            idx if idx == self.state.action_rx_idx => {
                let action = self.state.action_rx.recv()?;

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
