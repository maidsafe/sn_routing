// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    action::Action,
    error::RoutingError,
    outbox::EventBox,
    pause::PausedState,
    quic_p2p::EventSenders,
    states::ApprovedPeer,
    timer::Timer,
    transport::{Transport, TransportBuilder},
    NetworkConfig, NetworkEvent,
};
use crossbeam_channel as mpmc;

/// Holds the current state and handles state transitions.
pub struct StateMachine {
    state: ApprovedPeer,
    network_rx: mpmc::Receiver<NetworkEvent>,
    network_rx_idx: usize,
    action_rx: mpmc::Receiver<Action>,
    action_rx_idx: usize,
}

impl StateMachine {
    // Construct a new StateMachine by passing a function returning the initial state.
    pub fn new<F>(
        init_state: F,
        network_config: NetworkConfig,
        client_tx: mpmc::Sender<NetworkEvent>,
        outbox: &mut dyn EventBox,
    ) -> (mpmc::Sender<Action>, Self)
    where
        F: FnOnce(Transport, Timer, &mut dyn EventBox) -> ApprovedPeer,
    {
        let (action_tx, action_rx) = mpmc::unbounded();
        let (network_tx, network_rx) = {
            let (node_tx, node_rx) = mpmc::unbounded();
            (EventSenders { node_tx, client_tx }, node_rx)
        };

        let transport = match TransportBuilder::new(network_tx)
            .with_config(network_config)
            .build()
        {
            Ok(transport) => transport,
            Err(err) => panic!("Unable to start network service: {:?}", err),
        };

        let timer = Timer::new(action_tx.clone());
        let state = init_state(transport, timer, outbox);

        let machine = Self {
            state,
            network_rx,
            network_rx_idx: 0,
            action_rx,
            action_rx_idx: 0,
        };

        (action_tx, machine)
    }

    pub fn pause(self) -> Result<PausedState, RoutingError> {
        info!("Pause");

        let mut paused_state = self.state.pause();
        paused_state.network_rx = Some(self.network_rx);

        Ok(paused_state)
    }

    pub fn resume(mut state: PausedState) -> (mpmc::Sender<Action>, Self) {
        let (action_tx, action_rx) = mpmc::unbounded();
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
    pub fn register<'a>(&'a mut self, select: &mut mpmc::Select<'a>) {
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
    pub fn step(
        &mut self,
        op_index: usize,
        outbox: &mut dyn EventBox,
    ) -> Result<bool, mpmc::RecvError> {
        if !self.state.is_running() {
            return Err(mpmc::RecvError);
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
            _idx => Err(mpmc::RecvError),
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
