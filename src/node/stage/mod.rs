// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod approved;
mod bootstrapping;
mod comm;
mod joining;

pub(super) use self::{approved::Approved, bootstrapping::Bootstrapping, comm::Comm};

use self::joining::Joining;
use super::{command, Command};
use crate::{
    consensus::{ProofShare, Vote},
    crypto::{name, Keypair},
    error::{Error, Result},
    event::Event,
    location::{DstLocation, SrcLocation},
    log_ident,
    messages::Message,
    network_params::NetworkParams,
    peer::Peer,
    section::{EldersInfo, SectionProofChain},
};
use bytes::Bytes;
use ed25519_dalek::PublicKey;
use std::{
    fmt::{self, Debug, Formatter},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};
use tokio::{
    sync::{mpsc, Mutex},
    time,
};
use xor_name::{Prefix, XorName};

#[cfg(feature = "mock")]
pub use self::{bootstrapping::BOOTSTRAP_TIMEOUT, joining::JOIN_TIMEOUT};

// Type to hold the various states a node goes through during its lifetime.
#[allow(clippy::large_enum_variant)]
pub(crate) enum State {
    Bootstrapping(Bootstrapping),
    Joining(Joining),
    Approved(Approved),
}

impl State {
    fn approved(&self) -> Option<&Approved> {
        match self {
            Self::Approved(state) => Some(state),
            _ => None,
        }
    }
}

impl From<Bootstrapping> for State {
    fn from(state: Bootstrapping) -> Self {
        Self::Bootstrapping(state)
    }
}

impl From<Approved> for State {
    fn from(state: Approved) -> Self {
        Self::Approved(state)
    }
}

impl Debug for State {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::Bootstrapping(_) => write!(f, "Bootstrapping"),
            Self::Joining(_) => write!(f, "Joining"),
            Self::Approved(_) => write!(f, "Approved"),
        }
    }
}

// Node's information.
#[derive(Clone)]
pub(crate) struct NodeInfo {
    // Keep the secret key in Box to allow Clone while also preventing multiple copies to exist in
    // memory which might be insecure.
    pub keypair: Arc<Keypair>,
    pub network_params: NetworkParams,
    event_tx: mpsc::UnboundedSender<Event>,
}

impl NodeInfo {
    pub(super) fn new(
        keypair: Keypair,
        network_params: NetworkParams,
        event_tx: mpsc::UnboundedSender<Event>,
    ) -> Self {
        Self {
            keypair: Arc::new(keypair),
            network_params,
            event_tx,
        }
    }

    pub fn name(&self) -> XorName {
        name(&self.keypair.public)
    }

    pub fn send_event(&self, event: Event) {
        // Note: cloning the sender to avoid mutable access. Should have negligible cost.
        if self.event_tx.clone().send(event).is_err() {
            error!("Event receiver has been closed");
        }
    }
}

// Node's current stage whcich is responsible
// for accessing current info and trigger operations.
pub(crate) struct Stage {
    state: Mutex<State>,
    comm: Comm,
}

impl Stage {
    pub fn new(state: State, comm: Comm) -> Self {
        Self {
            state: Mutex::new(state),
            comm,
        }
    }

    /// Send provided Event to the user which shall receive it through the EventStream
    pub async fn send_event(&self, event: Event) {
        match &*self.state.lock().await {
            State::Bootstrapping(state) => state.node_info.send_event(event),
            State::Joining(state) => state.node_info.send_event(event),
            State::Approved(state) => state.node_info.send_event(event),
        }
    }

    /// Returns the name of the node
    pub async fn name(&self) -> XorName {
        let state = self.state.lock().await;
        let node_info = match &*state {
            State::Bootstrapping(state) => &state.node_info,
            State::Joining(state) => &state.node_info,
            State::Approved(state) => &state.node_info,
        };

        node_info.name()
    }

    /// Returns the public key of the node
    pub async fn public_key(&self) -> PublicKey {
        let state = self.state.lock().await;
        let node_info = match &*state {
            State::Bootstrapping(state) => &state.node_info,
            State::Joining(state) => &state.node_info,
            State::Approved(state) => &state.node_info,
        };

        node_info.keypair.public
    }

    /// Our `Prefix` once we are a part of the section.
    pub async fn our_prefix(&self) -> Option<Prefix> {
        self.state
            .lock()
            .await
            .approved()
            .map(|state| state.shared_state.our_prefix())
            .cloned()
    }

    /// Returns connection info of this node.
    pub fn our_connection_info(&self) -> Result<SocketAddr> {
        self.comm.our_connection_info()
    }

    /// Returns whether the node is Elder.
    pub async fn is_elder(&self) -> bool {
        self.state
            .lock()
            .await
            .approved()
            .map(|state| state.is_elder())
            .unwrap_or(false)
    }

    /// Returns the information of all the current section elders.
    pub async fn our_elders(&self) -> Vec<Peer> {
        self.state
            .lock()
            .await
            .approved()
            .map(|state| state.shared_state.sections.our_elders().copied().collect())
            .unwrap_or_default()
    }

    /// Returns the information of all the current section adults.
    pub async fn our_adults(&self) -> Vec<Peer> {
        self.state
            .lock()
            .await
            .approved()
            .map(|state| state.shared_state.our_adults().copied().collect())
            .unwrap_or_default()
    }

    /// Returns the info about our section or `None` if we are not joined yet.
    pub async fn our_section(&self) -> Option<EldersInfo> {
        self.state
            .lock()
            .await
            .approved()
            .map(|state| state.shared_state.sections.our().clone())
    }

    /// Returns the info about our neighbour sections.
    pub async fn neighbour_sections(&self) -> Vec<EldersInfo> {
        self.state
            .lock()
            .await
            .approved()
            .map(|state| state.shared_state.sections.neighbours().cloned().collect())
            .unwrap_or_default()
    }

    /// Returns the current BLS public key set or `Error::InvalidState` if we are not joined
    /// yet.
    pub async fn public_key_set(&self) -> Result<bls::PublicKeySet> {
        self.state
            .lock()
            .await
            .approved()
            .and_then(|state| state.section_key_share())
            .map(|share| share.public_key_set.clone())
            .ok_or(Error::InvalidState)
    }

    /// Returns the current BLS secret key share or `Error::InvalidState` if we are not
    /// elder.
    pub async fn secret_key_share(&self) -> Result<bls::SecretKeyShare> {
        self.state
            .lock()
            .await
            .approved()
            .and_then(|stage| stage.section_key_share())
            .map(|share| share.secret_key_share.clone())
            .ok_or(Error::InvalidState)
    }

    /// Returns our section proof chain, or `None` if we are not joined yet.
    pub async fn our_history(&self) -> Option<SectionProofChain> {
        self.state
            .lock()
            .await
            .approved()
            .map(|stage| stage.shared_state.our_history.clone())
    }

    /// Returns our index in the current BLS group or `Error::InvalidState` if section key was
    /// not generated yet.
    pub async fn our_index(&self) -> Result<usize> {
        self.state
            .lock()
            .await
            .approved()
            .and_then(|stage| stage.section_key_share())
            .map(|share| share.index)
            .ok_or(Error::InvalidState)
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
        let result = log_ident::set(self.log_ident().await, async {
            trace!("Handling command {:?}", command);

            match command {
                Command::HandleMessage { message, sender } => {
                    self.handle_message(sender, message).await
                }
                Command::HandleTimeout(token) => self.handle_timeout(token).await,
                Command::HandleVote { vote, proof_share } => {
                    self.handle_vote(vote, proof_share).await
                }
                Command::HandlePeerLost(addr) => self.handle_peer_lost(addr).await,
                Command::SendMessage {
                    recipients,
                    delivery_group_size,
                    message,
                } => Ok(self
                    .send_message(&recipients, delivery_group_size, message)
                    .await),
                Command::SendUserMessage { src, dst, content } => {
                    self.send_user_message(src, dst, content).await
                }
                Command::SendBootstrapRequest(recipients) => {
                    Ok(vec![self.send_bootstrap_request(recipients).await?])
                }
                Command::ScheduleTimeout { duration, token } => {
                    Ok(vec![self.handle_schedule_timeout(duration, token).await])
                }
                Command::Transition(state) => {
                    *self.state.lock().await = *state;
                    Ok(vec![])
                }
            }
        })
        .await;

        if let Err(error) = &result {
            error!("Error encountered when handling command: {}", error);
        }

        result
    }

    // Note: this indirecton is needed. Trying to call `spawn(self.handle_commands(...))` directly
    // inside `handle_commands` causes compile error about type check cycle.
    fn spawn_handle_commands(self: Arc<Self>, command: Command) {
        let _ = tokio::spawn(self.handle_commands(command));
    }

    async fn handle_message(
        &self,
        sender: Option<SocketAddr>,
        msg: Message,
    ) -> Result<Vec<Command>> {
        match &mut *self.state.lock().await {
            State::Bootstrapping(state) => state.handle_message(sender, msg),
            State::Joining(state) => state.handle_message(sender, msg),
            State::Approved(state) => state.handle_message(sender, msg),
        }
    }

    async fn handle_timeout(&self, token: u64) -> Result<Vec<Command>> {
        match &mut *self.state.lock().await {
            State::Approved(state) => state.handle_timeout(token),
            _ => Ok(vec![]),
        }
    }

    async fn handle_vote(&self, vote: Vote, proof_share: ProofShare) -> Result<Vec<Command>> {
        match &mut *self.state.lock().await {
            State::Approved(state) => state.handle_vote(vote, proof_share),
            _ => Err(Error::InvalidState),
        }
    }

    async fn handle_peer_lost(&self, addr: SocketAddr) -> Result<Vec<Command>> {
        match &*self.state.lock().await {
            State::Approved(state) => state.handle_peer_lost(&addr),
            _ => Ok(vec![]),
        }
    }

    async fn send_message(
        &self,
        recipients: &[SocketAddr],
        delivery_group_size: usize,
        message: Bytes,
    ) -> Vec<Command> {
        match self
            .comm
            .send_message_to_targets(recipients, delivery_group_size, message)
            .await
        {
            Ok(()) => vec![],
            Err(error) => error
                .failed_recipients
                .into_iter()
                .map(Command::HandlePeerLost)
                .collect(),
        }
    }

    async fn send_user_message(
        &self,
        src: SrcLocation,
        dst: DstLocation,
        content: Bytes,
    ) -> Result<Vec<Command>> {
        match &mut *self.state.lock().await {
            State::Approved(stage) => stage.send_user_message(src, dst, content),
            _ => Err(Error::InvalidState),
        }
    }

    async fn send_bootstrap_request(&self, recipients: Vec<SocketAddr>) -> Result<Command> {
        match &*self.state.lock().await {
            State::Bootstrapping(state) => state.send_bootstrap_request(&recipients),
            _ => Err(Error::InvalidState),
        }
    }

    async fn handle_schedule_timeout(&self, duration: Duration, token: u64) -> Command {
        time::delay_for(duration).await;
        Command::HandleTimeout(token)
    }

    async fn log_ident(&self) -> String {
        match &*self.state.lock().await {
            State::Bootstrapping(state) => format!("{}(?) ", state.node_info.name()),
            State::Joining(state) => format!(
                "{}({:b}?) ",
                state.node_info.name(),
                state.target_section_elders_info().prefix,
            ),
            State::Approved(state) => {
                if state.is_elder() {
                    format!(
                        "{}({:b}v{}!) ",
                        state.node_info.name(),
                        state.shared_state.our_prefix(),
                        state.shared_state.our_history.last_key_index()
                    )
                } else {
                    format!(
                        "{}({:b}) ",
                        state.node_info.name(),
                        state.shared_state.our_prefix()
                    )
                }
            }
        }
    }
}
