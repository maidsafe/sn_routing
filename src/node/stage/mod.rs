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

use self::{approved::Approved, bootstrapping::Bootstrapping, comm::Comm, joining::Joining};
use super::command::{Command, Context};
use crate::{
    consensus::{self, Proof, ProofShare, Proven, Vote},
    crypto::{name, Keypair},
    error::{Error, Result},
    event::{Connected, Event},
    location::{DstLocation, SrcLocation},
    log_ident,
    messages::Message,
    network_params::NetworkParams,
    peer::Peer,
    rng::MainRng,
    section::{EldersInfo, MemberInfo, SectionKeyShare, SectionProofChain, SharedState, MIN_AGE},
    TransportConfig,
};
use bytes::Bytes;
use ed25519_dalek::PublicKey;
use qp2p::IncomingConnections;
use serde::Serialize;
use std::{
    fmt::{self, Debug, Formatter},
    iter,
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
    events_tx: mpsc::UnboundedSender<Event>,
}

impl NodeInfo {
    pub fn name(&self) -> XorName {
        name(&self.keypair.public)
    }

    /// Send provided Event to the user which shall receive it through the EventStream
    pub fn send_event(&mut self, event: Event) {
        if let Err(err) = self.events_tx.send(event) {
            trace!("Error reporting new Event: {:?}", err);
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
    // Private constructor
    fn new(state: State, comm: Comm) -> Result<(Self, IncomingConnections)> {
        let incoming_conns = comm.listen()?;

        let stage = Self {
            state: Mutex::new(state),
            comm,
        };

        Ok((stage, incoming_conns))
    }

    // Create the approved stage for the first node in the network.
    pub async fn first_node(
        transport_config: TransportConfig,
        keypair: Keypair,
        network_params: NetworkParams,
    ) -> Result<(Self, IncomingConnections, mpsc::UnboundedReceiver<Event>)> {
        let comm = Comm::new(transport_config)?;
        let connection_info = comm.our_connection_info()?;
        let peer = Peer::new(name(&keypair.public), connection_info, MIN_AGE);

        let mut rng = MainRng::default();
        let secret_key_set = consensus::generate_secret_key_set(&mut rng, 1);
        let public_key_set = secret_key_set.public_keys();
        let secret_key_share = secret_key_set.secret_key_share(0);

        // Note: `ElderInfo` is normally signed with the previous key, but as we are the first node
        // of the network there is no previous key. Sign with the current key instead.
        let elders_info = create_first_elders_info(&public_key_set, &secret_key_share, peer)?;
        let shared_state =
            create_first_shared_state(&public_key_set, &secret_key_share, elders_info)?;

        let section_key_share = SectionKeyShare {
            public_key_set,
            index: 0,
            secret_key_share,
        };

        let (events_tx, events_rx) = mpsc::unbounded_channel();
        let mut node_info = NodeInfo {
            keypair: Arc::new(keypair),
            network_params,
            events_tx,
        };

        node_info.send_event(Event::Connected(Connected::First));
        node_info.send_event(Event::PromotedToElder);

        let state = Approved::new(shared_state, Some(section_key_share), node_info)?;
        let (stage, incomming_connections) = Self::new(State::Approved(state), comm)?;

        Ok((stage, incomming_connections, events_rx))
    }

    pub async fn bootstrap(
        cx: &mut Context,
        transport_config: TransportConfig,
        keypair: Keypair,
        network_params: NetworkParams,
    ) -> Result<(Self, IncomingConnections, mpsc::UnboundedReceiver<Event>)> {
        let (comm, addr) = Comm::from_bootstrapping(transport_config).await?;

        let (events_tx, events_rx) = mpsc::unbounded_channel();
        let node_info = NodeInfo {
            keypair: Arc::new(keypair),
            network_params,
            events_tx,
        };

        let state = Bootstrapping::new(cx, None, vec![addr], node_info);
        let state = State::Bootstrapping(state);
        let (stage, incomming_connections) = Self::new(state, comm)?;

        Ok((stage, incomming_connections, events_rx))
    }

    /// Send provided Event to the user which shall receive it through the EventStream
    pub async fn send_event(&self, event: Event) {
        let mut state = self.state.lock().await;
        let node_info = match &mut *state {
            State::Bootstrapping(state) => &mut state.node_info,
            State::Joining(state) => &mut state.node_info,
            State::Approved(state) => &mut state.node_info,
        };

        node_info.send_event(event)
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

    pub async fn handle_command(self: Arc<Self>, command: Command) -> Result<()> {
        let mut cx = Context::new();

        log_ident::set(self.log_ident().await, async {
            trace!("Processing command {:?}", command);

            let result = match command {
                Command::HandleMessage { message, sender } => {
                    self.handle_message(&mut cx, sender, message).await
                }
                Command::HandleTimeout(token) => self.handle_timeout(&mut cx, token).await,
                Command::HandleVote { vote, proof_share } => {
                    self.handle_vote(&mut cx, vote, proof_share).await
                }
                Command::HandlePeerLost(addr) => self.handle_peer_lost(&mut cx, addr).await,
                Command::SendMessage {
                    recipients,
                    delivery_group_size,
                    message,
                } => {
                    self.send_message(&mut cx, &recipients, delivery_group_size, message)
                        .await
                }
                Command::SendUserMessage { src, dst, content } => {
                    self.send_user_message(&mut cx, src, dst, content).await
                }
                Command::SendBootstrapRequest(recipients) => {
                    self.send_bootstrap_request(&mut cx, recipients).await
                }
                Command::ScheduleTimeout { duration, token } => {
                    self.handle_schedule_timeout(&mut cx, duration, token).await;
                    Ok(())
                }
                Command::Transition(state) => {
                    *self.state.lock().await = *state;
                    Ok(())
                }
            };

            if let Err(error) = &result {
                error!("Error encountered when processing command: {}", error);
            }

            result
        })
        .await?;

        for command in cx.into_commands() {
            self.clone().spawn_handle_command(command)
        }

        Ok(())
    }

    // Note: this indirecton is needed. Trying to call `spawn(self.handle_command(...))` directly
    // inside `handle_command` causes compile error about type check cycle.
    fn spawn_handle_command(self: Arc<Self>, command: Command) {
        let _ = tokio::spawn(self.handle_command(command));
    }

    async fn handle_message(
        &self,
        cx: &mut Context,
        sender: Option<SocketAddr>,
        msg: Message,
    ) -> Result<()> {
        trace!("try handle {:?} from {:?}", msg, sender);

        match &mut *self.state.lock().await {
            State::Bootstrapping(stage) => stage.handle_message(cx, sender, msg),
            State::Joining(stage) => stage.handle_message(cx, sender, msg),
            State::Approved(stage) => stage.handle_message(cx, sender, msg),
        }
    }

    async fn handle_timeout(&self, cx: &mut Context, token: u64) -> Result<()> {
        match &mut *self.state.lock().await {
            State::Bootstrapping(_) => Ok(()),
            State::Joining(stage) => stage.handle_timeout(cx, token),
            State::Approved(stage) => stage.handle_timeout(cx, token),
        }
    }

    async fn handle_vote(
        &self,
        cx: &mut Context,
        vote: Vote,
        proof_share: ProofShare,
    ) -> Result<()> {
        match &mut *self.state.lock().await {
            State::Approved(state) => state.handle_vote(cx, vote, proof_share),
            _ => Err(Error::InvalidState),
        }
    }

    async fn handle_peer_lost(&self, cx: &mut Context, addr: SocketAddr) -> Result<()> {
        match &*self.state.lock().await {
            State::Approved(state) => state.handle_peer_lost(cx, &addr),
            _ => Ok(()),
        }
    }

    async fn send_message(
        &self,
        cx: &mut Context,
        recipients: &[SocketAddr],
        delivery_group_size: usize,
        message: Bytes,
    ) -> Result<()> {
        match self
            .comm
            .send_message_to_targets(recipients, delivery_group_size, message)
            .await
        {
            Ok(()) => Ok(()),
            Err(error) => {
                for addr in error.failed_recipients {
                    cx.push(Command::HandlePeerLost(addr));
                }

                Err(Error::FailedSend)
            }
        }
    }

    async fn send_user_message(
        &self,
        cx: &mut Context,
        src: SrcLocation,
        dst: DstLocation,
        content: Bytes,
    ) -> Result<()> {
        match &mut *self.state.lock().await {
            State::Approved(stage) => stage.send_user_message(cx, src, dst, content),
            _ => Err(Error::InvalidState),
        }
    }

    async fn send_bootstrap_request(
        &self,
        cx: &mut Context,
        recipients: Vec<SocketAddr>,
    ) -> Result<()> {
        match &*self.state.lock().await {
            State::Bootstrapping(state) => state.send_bootstrap_request(cx, &recipients),
            _ => Err(Error::InvalidState),
        }
    }

    async fn handle_schedule_timeout(&self, cx: &mut Context, duration: Duration, token: u64) {
        time::delay_for(duration).await;
        cx.push(Command::HandleTimeout(token))
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

// Create `EldersInfo` for the first node.
fn create_first_elders_info(
    pk_set: &bls::PublicKeySet,
    sk_share: &bls::SecretKeyShare,
    peer: Peer,
) -> Result<Proven<EldersInfo>> {
    let name = *peer.name();
    let node = (name, peer);
    let elders_info = EldersInfo::new(iter::once(node).collect(), Prefix::default());
    let proof = create_first_proof(pk_set, sk_share, &elders_info)?;
    Ok(Proven::new(elders_info, proof))
}

fn create_first_shared_state(
    pk_set: &bls::PublicKeySet,
    sk_share: &bls::SecretKeyShare,
    elders_info: Proven<EldersInfo>,
) -> Result<SharedState> {
    let mut shared_state = SharedState::new(
        SectionProofChain::new(elders_info.proof.public_key),
        elders_info,
    );

    for peer in shared_state.sections.our().elders.values() {
        let member_info = MemberInfo::joined(*peer);
        let proof = create_first_proof(pk_set, sk_share, &member_info)?;
        let _ = shared_state
            .our_members
            .update(member_info, proof, &shared_state.our_history);
    }

    Ok(shared_state)
}

fn create_first_proof<T: Serialize>(
    pk_set: &bls::PublicKeySet,
    sk_share: &bls::SecretKeyShare,
    payload: &T,
) -> Result<Proof> {
    let bytes = bincode::serialize(payload)?;
    let signature_share = sk_share.sign(&bytes);
    let signature = pk_set
        .combine_signatures(iter::once((0, &signature_share)))
        .map_err(|_| Error::InvalidSignatureShare)?;

    Ok(Proof {
        public_key: pk_set.public_key(),
        signature,
    })
}
