// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod approved;
mod comm;
mod update_barrier;

pub(super) use self::{approved::Approved, comm::Comm};

use self::update_barrier::UpdateBarrier;
use super::{bootstrap, command, Command};
use crate::{
    consensus::{ProofShare, Vote},
    error::{Error, Result},
    event::{Connected, Event},
    location::{DstLocation, SrcLocation},
    log_ident,
    messages::Message,
    peer::Peer,
    relocation::SignedRelocateDetails,
    section::{EldersInfo, SectionProofChain},
};
use bls_signature_aggregator::Proof;
use bytes::Bytes;
use ed25519_dalek::{PublicKey, Signature, Signer};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{sync::mpsc, sync::Mutex, time};
use xor_name::{Prefix, XorName};

// Node's current stage which is responsible
// for accessing current info and trigger operations.
pub(crate) struct Stage {
    state: Mutex<Approved>,
    comm: Comm,
}

impl Stage {
    pub fn new(state: Approved, comm: Comm) -> Self {
        Self {
            state: Mutex::new(state),
            comm,
        }
    }

    /// Send provided Event to the user which shall receive it through the EventStream
    pub async fn send_event(&self, event: Event) {
        self.state.lock().await.node().send_event(event)
    }

    /// Returns the name of the node
    pub async fn name(&self) -> XorName {
        self.state.lock().await.node().name()
    }

    /// Returns the public key of the node
    pub async fn public_key(&self) -> PublicKey {
        self.state.lock().await.node().keypair.public
    }

    pub async fn sign(&self, msg: &[u8]) -> Signature {
        self.state.lock().await.node().keypair.sign(msg)
    }

    pub async fn verify(&self, msg: &[u8], signature: &Signature) -> bool {
        self.state
            .lock()
            .await
            .node()
            .keypair
            .verify(msg, signature)
            .is_ok()
    }

    /// `Prefix` of our section.
    pub async fn our_prefix(&self) -> Prefix {
        *self.state.lock().await.section().prefix()
    }

    /// Returns connection info of this node.
    pub fn our_connection_info(&self) -> Result<SocketAddr> {
        self.comm.our_connection_info()
    }

    /// Returns whether the node is Elder.
    pub async fn is_elder(&self) -> bool {
        self.state.lock().await.is_elder()
    }

    /// Returns the information of all the current section elders.
    pub async fn our_elders(&self) -> Vec<Peer> {
        self.state
            .lock()
            .await
            .section()
            .elders_info()
            .peers()
            .copied()
            .collect()
    }

    /// Returns the information of all the current section adults.
    pub async fn our_adults(&self) -> Vec<Peer> {
        self.state
            .lock()
            .await
            .section()
            .adults()
            .copied()
            .collect()
    }

    /// Returns the info about our section.
    pub async fn our_section(&self) -> EldersInfo {
        self.state.lock().await.section().elders_info().clone()
    }

    /// Returns the info about our neighbour sections.
    pub async fn neighbour_sections(&self) -> Vec<EldersInfo> {
        self.state.lock().await.network().all().cloned().collect()
    }

    /// Returns the current BLS public key set or `Error::InvalidState` if we are not elder.
    pub async fn public_key_set(&self) -> Result<bls::PublicKeySet> {
        self.state
            .lock()
            .await
            .section_key_share()
            .map(|share| share.public_key_set.clone())
            .ok_or(Error::InvalidState)
    }

    /// Returns the current BLS secret key share or `Error::InvalidState` if we are not
    /// elder.
    pub async fn secret_key_share(&self) -> Result<bls::SecretKeyShare> {
        self.state
            .lock()
            .await
            .section_key_share()
            .map(|share| share.secret_key_share.clone())
            .ok_or(Error::InvalidState)
    }

    /// Returns our section proof chain.
    pub async fn our_history(&self) -> SectionProofChain {
        self.state.lock().await.section().chain().clone()
    }

    /// Returns our index in the current BLS group or `Error::InvalidState` if section key was
    /// not generated yet.
    pub async fn our_index(&self) -> Result<usize> {
        self.state
            .lock()
            .await
            .section_key_share()
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
                Command::HandleConsensus { vote, proof } => {
                    self.handle_consensus(vote, proof).await
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
                Command::ScheduleTimeout { duration, token } => {
                    Ok(vec![self.handle_schedule_timeout(duration, token).await])
                }
                Command::Relocate {
                    bootstrap_addrs,
                    details,
                    message_rx,
                } => {
                    self.handle_relocate(bootstrap_addrs, details, message_rx)
                        .await?;
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
        self.state.lock().await.handle_message(sender, msg).await
    }

    async fn handle_timeout(&self, token: u64) -> Result<Vec<Command>> {
        self.state.lock().await.handle_timeout(token)
    }

    async fn handle_vote(&self, vote: Vote, proof_share: ProofShare) -> Result<Vec<Command>> {
        self.state.lock().await.handle_vote(vote, proof_share)
    }

    async fn handle_consensus(&self, vote: Vote, proof: Proof) -> Result<Vec<Command>> {
        self.state.lock().await.handle_consensus(vote, proof)
    }

    async fn handle_peer_lost(&self, addr: SocketAddr) -> Result<Vec<Command>> {
        self.state.lock().await.handle_peer_lost(&addr)
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
        self.state.lock().await.send_user_message(src, dst, content)
    }

    async fn handle_schedule_timeout(&self, duration: Duration, token: u64) -> Command {
        time::delay_for(duration).await;
        Command::HandleTimeout(token)
    }

    async fn handle_relocate(
        &self,
        bootstrap_addrs: Vec<SocketAddr>,
        details: SignedRelocateDetails,
        message_rx: mpsc::Receiver<(Message, SocketAddr)>,
    ) -> Result<()> {
        let node = self.state.lock().await.node().clone();
        let previous_name = node.name();

        let (node, section) =
            bootstrap::relocate(node, &self.comm, message_rx, bootstrap_addrs, details).await?;

        *self.state.lock().await = Approved::new(section, None, node);
        self.send_event(Event::Connected(Connected::Relocate { previous_name }))
            .await;

        Ok(())
    }

    async fn log_ident(&self) -> String {
        let state = self.state.lock().await;

        if state.is_elder() {
            format!(
                "{}({:b}v{}!) ",
                state.node().name(),
                state.section().prefix(),
                state.section().chain().last_key_index()
            )
        } else {
            format!("{}({:b}) ", state.node().name(), state.section().prefix())
        }
    }
}
