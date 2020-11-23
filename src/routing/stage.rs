// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{bootstrap, Approved, Comm, Command};
use crate::{error::Result, event::Event, messages::Message, relocation::SignedRelocateDetails};
use bytes::Bytes;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    sync::{mpsc, watch, Mutex},
    time,
};

// Node's current stage which is responsible
// for accessing current info and trigger operations.
pub(crate) struct Stage {
    pub(super) state: Mutex<Approved>,
    pub(super) comm: Comm,

    cancel_timer_tx: watch::Sender<bool>,
    cancel_timer_rx: watch::Receiver<bool>,
}

impl Stage {
    pub fn new(state: Approved, comm: Comm) -> Self {
        let (cancel_timer_tx, mut cancel_timer_rx) = watch::channel(false);

        // Take out the initial value.
        let _ = futures::executor::block_on(cancel_timer_rx.recv());

        Self {
            state: Mutex::new(state),
            comm,
            cancel_timer_tx,
            cancel_timer_rx,
        }
    }

    /// Send provided Event to the user which shall receive it through the EventStream
    pub async fn send_event(&self, event: Event) {
        self.state.lock().await.send_event(event)
    }

    /// Handles the given command and transitively any new commands that are produced during its
    /// handling.
    pub async fn handle_commands(self: Arc<Self>, command: Command) -> Result<()> {
        let commands = self.handle_command(command).await?;
        for command in commands {
            self.clone().spawn_handle_commands(command)
        }

        Ok(())
    }

    /// Handles a single command.
    pub async fn handle_command(&self, command: Command) -> Result<Vec<Command>> {
        trace!("Handling command {:?}", command);

        let result = async {
            match command {
                Command::HandleMessage { message, sender } => {
                    self.state
                        .lock()
                        .await
                        .handle_message(sender, message)
                        .await
                }
                Command::HandleTimeout(token) => self.state.lock().await.handle_timeout(token),
                Command::HandleVote { vote, proof_share } => {
                    self.state.lock().await.handle_vote(vote, proof_share)
                }
                Command::HandleConsensus { vote, proof } => {
                    self.state.lock().await.handle_consensus(vote, proof)
                }
                Command::HandleConnectionLost(addr) => Ok(self
                    .state
                    .lock()
                    .await
                    .handle_connection_lost(&addr)
                    .into_iter()
                    .collect()),
                Command::HandlePeerLost(addr) => self.state.lock().await.handle_peer_lost(&addr),
                Command::HandleDkgParticipationResult {
                    dkg_key,
                    elders_info,
                    result,
                } => self.state.lock().await.handle_dkg_participation_result(
                    dkg_key,
                    elders_info,
                    result,
                ),
                Command::HandleDkgObservationResult {
                    elders_info,
                    result,
                } => self
                    .state
                    .lock()
                    .await
                    .handle_dkg_observation_result(elders_info, result),
                Command::SendMessage {
                    recipients,
                    delivery_group_size,
                    message,
                } => Ok(self
                    .send_message(&recipients, delivery_group_size, message)
                    .await),
                Command::SendUserMessage { src, dst, content } => {
                    self.state.lock().await.send_user_message(src, dst, content)
                }
                Command::ScheduleTimeout { duration, token } => Ok(self
                    .handle_schedule_timeout(duration, token)
                    .await
                    .into_iter()
                    .collect()),
                Command::Relocate {
                    bootstrap_addrs,
                    details,
                    message_rx,
                } => {
                    self.handle_relocate(bootstrap_addrs, details, message_rx)
                        .await
                }
            }
        }
        .await;

        if let Err(error) = &result {
            error!("Error encountered when handling command: {}", error);
        }

        result
    }

    // Terminate this routing instance - cancel all scheduled timers including any future ones,
    // close all network connections and stop accepting new connections.
    pub fn terminate(&self) {
        let _ = self.cancel_timer_tx.broadcast(true);
        self.comm.terminate()
    }

    // Note: this indirecton is needed. Trying to call `spawn(self.handle_commands(...))` directly
    // inside `handle_commands` causes compile error about type check cycle.
    fn spawn_handle_commands(self: Arc<Self>, command: Command) {
        let _ = tokio::spawn(self.handle_commands(command));
    }

    async fn send_message(
        &self,
        recipients: &[SocketAddr],
        delivery_group_size: usize,
        message: Bytes,
    ) -> Vec<Command> {
        self.comm
            .send_message_to_targets(recipients, delivery_group_size, message)
            .await
            .1
            .into_iter()
            .map(Command::HandlePeerLost)
            .collect()
    }

    async fn handle_schedule_timeout(&self, duration: Duration, token: u64) -> Option<Command> {
        let mut cancel_rx = self.cancel_timer_rx.clone();

        if *cancel_rx.borrow() {
            // Timers are already cancelled, do nothing.
            return None;
        }

        tokio::select! {
            _ = time::delay_for(duration) => Some(Command::HandleTimeout(token)),
            _ = cancel_rx.recv() => None,
        }
    }

    async fn handle_relocate(
        &self,
        bootstrap_addrs: Vec<SocketAddr>,
        details: SignedRelocateDetails,
        message_rx: mpsc::Receiver<(Message, SocketAddr)>,
    ) -> Result<Vec<Command>> {
        let node = self.state.lock().await.node().clone();
        let previous_name = node.name();

        let (node, section, backlog) =
            bootstrap::relocate(node, &self.comm, message_rx, bootstrap_addrs, details).await?;

        let mut state = self.state.lock().await;
        let event_tx = state.event_tx.clone();
        *state = Approved::new(node, section, None, event_tx);

        state.send_event(Event::Relocated { previous_name });

        let commands = backlog
            .into_iter()
            .map(|(message, sender)| Command::HandleMessage {
                message,
                sender: Some(sender),
            })
            .collect();
        Ok(commands)
    }
}
