// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{bootstrap, Approved, Comm, Command};
use crate::{error::Result, event::Event, relocation::SignedRelocateDetails};
use sn_messaging::MessageType;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    sync::{mpsc, watch, Mutex},
    time,
};
use tracing::Instrument;

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
        // Create a tracing span containing info about the current node. This is very useful when
        // analyzing logs produced by running multiple nodes within the same process, for example
        // from integration tests.
        let span = {
            let state = self.state.lock().await;
            trace_span!(
                "handle_command",
                name = %state.node().name(),
                prefix = format_args!("({:b})", state.section().prefix()),
                age = state.node().age,
                elder = state.is_elder(),
            )
        };

        async {
            trace!(?command);

            self.try_handle_command(command).await.map_err(|error| {
                error!("Error encountered when handling command: {}", error);
                error
            })
        }
        .instrument(span)
        .await
    }

    // Terminate this routing instance - cancel all scheduled timers including any future ones,
    // close all network connections and stop accepting new connections.
    pub fn terminate(&self) {
        let _ = self.cancel_timer_tx.broadcast(true);
        self.comm.terminate()
    }

    async fn try_handle_command(&self, command: Command) -> Result<Vec<Command>> {
        match command {
            Command::HandleMessage { sender, message } => {
                self.state
                    .lock()
                    .await
                    .handle_message(sender, message)
                    .await
            }
            Command::HandleInfrastructureQuery { sender, message } => {
                self.state
                    .lock()
                    .await
                    .handle_infrastructure_query(sender, message)
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
                .handle_connection_lost(addr)
                .into_iter()
                .collect()),
            Command::HandlePeerLost(addr) => self.state.lock().await.handle_peer_lost(&addr),
            Command::HandleDkgOutcome {
                elders_info,
                outcome,
            } => self
                .state
                .lock()
                .await
                .handle_dkg_outcome(elders_info, outcome),
            Command::HandleDkgFailure {
                elders_info,
                proofs,
            } => self
                .state
                .lock()
                .await
                .handle_dkg_failure(elders_info, proofs)
                .map(|command| vec![command]),
            Command::SendMessage {
                recipients,
                delivery_group_size,
                message,
            } => {
                self.send_message(&recipients, delivery_group_size, message)
                    .await
            }
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
            Command::SetJoinsAllowed(joins_allowed) => {
                self.state.lock().await.set_joins_allowed(joins_allowed)
            }
        }
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
        message: MessageType,
    ) -> Result<Vec<Command>> {
        let msg_bytes = message.serialize()?;

        let cmds = match message {
            MessageType::Ping | MessageType::NodeMessage(_) => self
                .comm
                .send(recipients, delivery_group_size, msg_bytes)
                .await
                .1
                .into_iter()
                .map(Command::HandlePeerLost)
                .collect(),
            MessageType::ClientMessage(_) => {
                for recipient in recipients {
                    if self
                        .comm
                        .send_on_existing_connection(recipient, msg_bytes.clone())
                        .await
                        .is_err()
                    {
                        self.send_event(Event::ClientLost(*recipient)).await;
                    }
                }
                vec![]
            }
            MessageType::InfrastructureQuery(_) => {
                for recipient in recipients {
                    let _ = self
                        .comm
                        .send_on_existing_connection(recipient, msg_bytes.clone())
                        .await;
                }
                vec![]
            }
        };

        Ok(cmds)
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
        message_rx: mpsc::Receiver<(MessageType, SocketAddr)>,
    ) -> Result<Vec<Command>> {
        let node = self.state.lock().await.node().clone();
        let previous_name = node.name();

        let (node, section, backlog) =
            bootstrap::relocate(node, &self.comm, message_rx, bootstrap_addrs, details).await?;

        let mut state = self.state.lock().await;
        let event_tx = state.event_tx.clone();
        let new_keypair = node.keypair.clone();
        *state = Approved::new(node, section, None, event_tx);

        state.send_event(Event::Relocated {
            previous_name,
            new_keypair,
        });

        let commands = backlog
            .into_iter()
            .map(|(message, sender)| Command::HandleMessage {
                message: Box::new(message),
                sender: Some(sender),
            })
            .collect();
        Ok(commands)
    }
}
