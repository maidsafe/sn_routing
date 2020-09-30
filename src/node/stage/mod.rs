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
    consensus::{self, Proof, Proven},
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
    timer::Timer,
    TransportConfig,
};
use bytes::Bytes;
use qp2p::IncomingConnections;
use serde::Serialize;
use std::{
    fmt::{self, Debug, Formatter},
    iter,
    net::SocketAddr,
    sync::Arc,
};
use tokio::sync::mpsc;
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
    state: State,
    comm: Comm,
}

impl Stage {
    // Private constructor
    fn new(state: State, comm: Comm) -> Result<(Self, IncomingConnections)> {
        let incoming_conns = comm.listen()?;

        let stage = Self { state, comm };

        Ok((stage, incoming_conns))
    }

    // Create the approved stage for the first node in the network.
    pub async fn first_node(
        transport_config: TransportConfig,
        keypair: Keypair,
        network_params: NetworkParams,
    ) -> Result<(
        Self,
        IncomingConnections,
        mpsc::UnboundedReceiver<u64>,
        mpsc::UnboundedReceiver<Event>,
    )> {
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

        let (timer_tx, timer_rx) = mpsc::unbounded_channel();
        let timer = Timer::new(timer_tx);

        let state = Approved::new(
            comm.clone(),
            shared_state,
            Some(section_key_share),
            node_info,
            timer,
        )?;

        let (stage, incomming_connections) = Self::new(State::Approved(state), comm)?;

        Ok((stage, incomming_connections, timer_rx, events_rx))
    }

    pub async fn bootstrap(
        transport_config: TransportConfig,
        keypair: Keypair,
        network_params: NetworkParams,
    ) -> Result<(
        Self,
        IncomingConnections,
        mpsc::UnboundedReceiver<u64>,
        mpsc::UnboundedReceiver<Event>,
    )> {
        let (comm, addr) = Comm::from_bootstrapping(transport_config).await?;

        let (events_tx, events_rx) = mpsc::unbounded_channel();
        let node_info = NodeInfo {
            keypair: Arc::new(keypair),
            network_params,
            events_tx,
        };

        let (timer_tx, timer_rx) = mpsc::unbounded_channel();
        let timer = Timer::new(timer_tx);

        let (stage, incomming_connections) =
            log_ident::set(format!("{} ", node_info.name()), async {
                let state =
                    Bootstrapping::new(None, vec![addr], comm.clone(), node_info.clone(), timer)
                        .await?;
                let state = State::Bootstrapping(state);
                Self::new(state, comm)
            })
            .await?;

        Ok((stage, incomming_connections, timer_rx, events_rx))
    }

    pub fn approved(&self) -> Option<&Approved> {
        match &self.state {
            State::Approved(stage) => Some(stage),
            _ => None,
        }
    }

    /// Send provided Event to the user which shall receive it through the EventStream
    pub fn send_event(&mut self, event: Event) {
        self.node_info_mut().send_event(event);
    }

    /// Returns current Keypair of the node
    pub fn keypair(&self) -> &Keypair {
        &self.node_info().keypair
    }

    /// Returns the name of the node
    pub fn name(&self) -> XorName {
        self.node_info().name()
    }

    /// Our `Prefix` once we are a part of the section.
    pub fn our_prefix(&self) -> Option<&Prefix> {
        match &self.state {
            State::Bootstrapping(_) | State::Joining(_) => None,
            State::Approved(stage) => Some(stage.shared_state.our_prefix()),
        }
    }

    /// Returns connection info of this node.
    pub fn our_connection_info(&mut self) -> Result<SocketAddr> {
        self.comm.our_connection_info()
    }

    pub async fn send_message_to_target(
        &mut self,
        recipient: &SocketAddr,
        msg: Bytes,
    ) -> Result<()> {
        self.comm.send_message_to_target(recipient, msg).await?;
        Ok(())
    }

    pub async fn handle_command(&mut self, cx: &mut Context, command: Command) -> Result<()> {
        log_ident::set(self.log_ident(), async {
            trace!("Processing command {:?}", command);

            let result = match command {
                Command::HandleMessage { message, sender } => {
                    self.handle_message(cx, sender, message).await
                }
                Command::HandleTimeout(token) => self.handle_timeout(cx, token).await,
                // Command::HandleVote { .. } => todo!(),
                Command::HandlePeerLost(addr) => self.handle_peer_lost(cx, addr).await,
                Command::SendMessage {
                    recipients,
                    delivery_group_size,
                    message,
                } => {
                    self.send_message(cx, &recipients, delivery_group_size, message)
                        .await
                }
                Command::SendUserMessage { src, dst, content } => {
                    self.send_user_message(src, dst, content, cx).await
                }
                Command::Transition(state) => {
                    self.state = *state;
                    Ok(())
                }
            };

            if let Err(error) = &result {
                error!("Error encountered when processing command: {}", error);
            }

            result
        })
        .await
    }

    async fn handle_message(
        &mut self,
        cx: &mut Context,
        sender: SocketAddr,
        msg: Message,
    ) -> Result<()> {
        trace!("try handle {:?} from {}", msg, sender);

        if !self.in_dst_location(&msg, cx)? {
            return Ok(());
        }

        match &mut self.state {
            State::Bootstrapping(stage) => stage.handle_message(cx, sender, msg).await,
            State::Joining(stage) => stage.handle_message(cx, sender, msg).await,
            State::Approved(stage) => stage.handle_message(cx, sender, msg).await,
        }
    }

    async fn handle_timeout(&mut self, cx: &mut Context, token: u64) -> Result<()> {
        match &mut self.state {
            State::Bootstrapping(stage) => stage.handle_timeout(token).await,
            State::Joining(stage) => stage.handle_timeout(token).await,
            State::Approved(stage) => stage.handle_timeout(cx, token).await,
        }
    }

    async fn handle_peer_lost(&mut self, cx: &mut Context, addr: SocketAddr) -> Result<()> {
        match &mut self.state {
            State::Approved(state) => state.handle_peer_lost(cx, &addr).await,
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
        &mut self,
        src: SrcLocation,
        dst: DstLocation,
        content: Bytes,
        cx: &mut Context,
    ) -> Result<()> {
        match &mut self.state {
            State::Approved(stage) => stage.send_user_message(cx, src, dst, content).await,
            _ => Err(Error::InvalidState),
        }
    }

    // Checks whether the given location represents self.
    fn in_dst_location(&mut self, msg: &Message, cx: &mut Context) -> Result<bool> {
        let in_dst = match &mut self.state {
            State::Bootstrapping(_) | State::Joining(_) => match msg.dst() {
                DstLocation::Node(name) => name == &self.node_info().name(),
                DstLocation::Section(_) => false,
                DstLocation::Direct => true,
            },
            State::Approved(stage) => {
                let is_dst_location = msg
                    .dst()
                    .contains(&stage.node_info.name(), stage.shared_state.our_prefix());

                // Relay a message to the network if the message
                // is not for us, or if it is for the section.
                if !is_dst_location || msg.dst().is_section() {
                    // Relay closer to the destination or
                    // broadcast to the rest of our section.
                    stage.relay_message(cx, msg)?;
                }

                is_dst_location
            }
        };

        Ok(in_dst)
    }

    fn node_info(&self) -> &NodeInfo {
        match &self.state {
            State::Bootstrapping(state) => &state.node_info,
            State::Joining(state) => &state.node_info,
            State::Approved(state) => &state.node_info,
        }
    }

    fn node_info_mut(&mut self) -> &mut NodeInfo {
        match &mut self.state {
            State::Bootstrapping(state) => &mut state.node_info,
            State::Joining(state) => &mut state.node_info,
            State::Approved(state) => &mut state.node_info,
        }
    }

    fn log_ident(&self) -> String {
        match &self.state {
            State::Bootstrapping(state) => format!("{}(?) ", state.node_info.name()),
            State::Joining(state) => format!(
                "{}({:b}?) ",
                state.node_info.name(),
                state.target_section_elders_info().prefix,
            ),
            State::Approved(state) => {
                if state.is_our_elder(&state.node_info.name()) {
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
