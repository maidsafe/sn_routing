// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{bootstrap, Comm, Command, Core};
use crate::{
    error::Result, event::Event, relocation::SignedRelocateDetails, routing::comm::SendStatus,
    Error, XorName,
};
use sn_messaging::MessageType;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    sync::{mpsc, watch, Mutex},
    time,
};
use tracing::Instrument;

// `Command` Dispatcher.
pub(crate) struct Dispatcher {
    pub(super) core: Mutex<Core>,
    pub(super) comm: Comm,

    cancel_timer_tx: watch::Sender<bool>,
    cancel_timer_rx: watch::Receiver<bool>,
}

impl Dispatcher {
    pub fn new(state: Core, comm: Comm) -> Self {
        let (cancel_timer_tx, cancel_timer_rx) = watch::channel(false);

        // Take out the initial value.

        Self {
            core: Mutex::new(state),
            comm,
            cancel_timer_tx,
            cancel_timer_rx,
        }
    }

    /// Send provided Event to the user which shall receive it through the EventStream
    pub async fn send_event(&self, event: Event) {
        self.core.lock().await.send_event(event)
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
            let state = self.core.lock().await;
            trace_span!(
                "handle_command",
                name = %state.node().name(),
                prefix = format_args!("({:b})", state.section().prefix()),
                age = state.node().age(),
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
        let _ = self.cancel_timer_tx.send(true);
        self.comm.terminate()
    }

    async fn try_handle_command(&self, command: Command) -> Result<Vec<Command>> {
        match command {
            Command::HandleMessage {
                sender,
                message,
                dest_info,
            } => {
                self.core
                    .lock()
                    .await
                    .handle_message(sender, message, dest_info)
                    .await
            }
            Command::HandleSectionInfoMsg {
                sender,
                message,
                dest_info,
            } => Ok(self
                .core
                .lock()
                .await
                .handle_section_info_msg(sender, message, dest_info)
                .await),
            Command::HandleTimeout(token) => self.core.lock().await.handle_timeout(token),
            Command::HandleAgreement { proposal, proof } => {
                self.core.lock().await.handle_agreement(proposal, proof)
            }
            Command::HandleConnectionLost(addr) => {
                self.core.lock().await.handle_connection_lost(addr)
            }
            Command::HandlePeerLost(addr) => self.core.lock().await.handle_peer_lost(&addr),
            Command::HandleDkgOutcome {
                section_auth,
                outcome,
            } => self
                .core
                .lock()
                .await
                .handle_dkg_outcome(section_auth, outcome),
            Command::HandleDkgFailure(proofs) => self
                .core
                .lock()
                .await
                .handle_dkg_failure(proofs)
                .map(|command| vec![command]),
            Command::SendMessage {
                recipients,
                delivery_group_size,
                message,
            } => {
                self.send_message(&recipients, delivery_group_size, message)
                    .await
            }
            Command::SendUserMessage {
                itinerary,
                content,
                additional_proof_chain_key,
            } => {
                self.core
                    .lock()
                    .await
                    .send_user_message(itinerary, content, additional_proof_chain_key.as_ref())
                    .await
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
                self.core.lock().await.set_joins_allowed(joins_allowed)
            }
            Command::TestConnectivity {
                mut peer,
                previous_name,
                their_knowledge,
            } => {
                peer.set_reachable(self.comm.is_reachable(peer.addr()).await.is_ok());
                self.core
                    .lock()
                    .await
                    .make_online_proposal(peer, previous_name, their_knowledge)
                    .await
            }
            Command::ProposeOffline(name) => self.core.lock().await.propose_offline(name),
        }
    }

    // Note: this indirecton is needed. Trying to call `spawn(self.handle_commands(...))` directly
    // inside `handle_commands` causes compile error about type check cycle.
    fn spawn_handle_commands(self: Arc<Self>, command: Command) {
        let _ = tokio::spawn(self.handle_commands(command));
    }

    async fn send_message(
        &self,
        recipients: &[(SocketAddr, XorName)],
        delivery_group_size: usize,
        message: MessageType,
    ) -> Result<Vec<Command>> {
        let cmds = match message {
            MessageType::Ping(_) | MessageType::Node { .. } | MessageType::Routing { .. } => {
                let status = self
                    .comm
                    .send(recipients, delivery_group_size, message)
                    .await?;
                match status {
                    SendStatus::MinDeliveryGroupSizeReached(failed_recipients)
                    | SendStatus::MinDeliveryGroupSizeFailed(failed_recipients) => {
                        Ok(failed_recipients
                            .into_iter()
                            .map(Command::HandlePeerLost)
                            .collect())
                    }
                    _ => Ok(vec![]),
                }
                .map_err(|e: Error| e)?
            }
            MessageType::Client { .. } => {
                for recipient in recipients {
                    if self
                        .comm
                        .send_on_existing_connection(*recipient, message.clone())
                        .await
                        .is_err()
                    {
                        trace!(
                            "Lost connection to client {:?} when sending message {:?}",
                            recipient,
                            message
                        );
                        self.send_event(Event::ClientLost(recipient.0)).await;
                    }
                }
                vec![]
            }
            MessageType::SectionInfo { .. } => {
                for recipient in recipients {
                    let _ = self
                        .comm
                        .send_on_existing_connection(*recipient, message.clone())
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
            _ = time::sleep(duration) => Some(Command::HandleTimeout(token)),
            _ = cancel_rx.changed() => None,
        }
    }

    async fn handle_relocate(
        &self,
        bootstrap_addrs: Vec<SocketAddr>,
        details: SignedRelocateDetails,
        message_rx: mpsc::Receiver<(MessageType, SocketAddr)>,
    ) -> Result<Vec<Command>> {
        let (genesis_key, node) = {
            let state = self.core.lock().await;
            (*state.section().genesis_key(), state.node().clone())
        };
        let previous_name = node.name();

        let (node, section, backlog) = bootstrap::relocate(
            node,
            &self.comm,
            message_rx,
            bootstrap_addrs,
            genesis_key,
            details,
        )
        .await?;

        let mut state = self.core.lock().await;
        let event_tx = state.event_tx.clone();
        let new_keypair = node.keypair.clone();
        *state = Core::new(node, section, None, event_tx);

        state.send_event(Event::Relocated {
            previous_name,
            new_keypair,
        });

        let commands = backlog
            .into_iter()
            .map(|(message, sender, dest_info)| Command::HandleMessage {
                message,
                sender: Some(sender),
                dest_info,
            })
            .collect();
        Ok(commands)
    }
}
