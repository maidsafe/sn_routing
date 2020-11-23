// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

pub(crate) mod command;

mod approved;
mod bootstrap;
mod comm;
mod event_stream;
mod stage;
#[cfg(test)]
mod tests;
mod update_barrier;

pub use self::event_stream::EventStream;
use self::{
    approved::Approved,
    comm::{Comm, ConnectionEvent},
    command::Command,
    stage::Stage,
    update_barrier::UpdateBarrier,
};
use crate::{
    crypto,
    error::{Error, Result},
    event::Event,
    location::{DstLocation, SrcLocation},
    messages::{Message, PING},
    node::Node,
    peer::Peer,
    relocation::STARTUP_PHASE_AGE_RANGE,
    section::{EldersInfo, SectionProofChain},
    TransportConfig,
};
use bytes::Bytes;
use ed25519_dalek::{Keypair, PublicKey, Signature, Signer};
use itertools::Itertools;
use std::{net::SocketAddr, sync::Arc};
use tokio::{sync::mpsc, task};
use xor_name::{Prefix, XorName};

/// Routing configuration.
#[derive(Debug)]
pub struct Config {
    /// If true, configures the node to start a new network instead of joining an existing one.
    pub first: bool,
    /// The `Keypair` of the node or `None` for randomly generated one.
    pub keypair: Option<Keypair>,
    /// Configuration for the underlying network transport.
    pub transport_config: TransportConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            first: false,
            keypair: None,
            transport_config: TransportConfig::default(),
        }
    }
}

/// Interface for sending and receiving messages to and from other nodes, in the role of a full
/// routing node.
///
/// A node is a part of the network that can route messages and be a member of a section or group
/// location. Its methods can be used to send requests and responses as either an individual
/// `Node` or as a part of a section or group location. Their `src` argument indicates that
/// role, and can be any [`SrcLocation`](enum.SrcLocation.html).
pub struct Routing {
    stage: Arc<Stage>,
}

impl Routing {
    ////////////////////////////////////////////////////////////////////////////
    // Public API
    ////////////////////////////////////////////////////////////////////////////

    /// Creates new node using the given config and bootstraps it to the network.
    ///
    /// NOTE: It's not guaranteed this function ever returns. This can happen due to messages being
    /// lost in transit during bootstrapping, or other reasons. It's the responsibility of the
    /// caller to handle this case, for example by using a timeout.
    pub async fn new(config: Config) -> Result<(Self, EventStream)> {
        let keypair = config.keypair.unwrap_or_else(crypto::gen_keypair);
        let node_name = crypto::name(&keypair.public);

        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let (connection_event_tx, mut connection_event_rx) = mpsc::channel(1);

        let (state, comm, backlog) = if config.first {
            info!("{} Starting a new network as the seed node.", node_name);
            let comm = Comm::new(config.transport_config, connection_event_tx)?;
            let node = Node::new(keypair, comm.our_connection_info().await?)
                .with_age(STARTUP_PHASE_AGE_RANGE.end);
            let state = Approved::first_node(node, event_tx)?;

            state.send_event(Event::PromotedToElder);

            (state, comm, vec![])
        } else {
            info!("{} Bootstrapping a new node.", node_name);
            let (comm, bootstrap_addr) =
                Comm::bootstrap(config.transport_config, connection_event_tx).await?;
            let node = Node::new(keypair, comm.our_connection_info().await?);
            let (node, section, backlog) =
                bootstrap::infant(node, &comm, &mut connection_event_rx, bootstrap_addr).await?;
            let state = Approved::new(node, section, None, event_tx);

            (state, comm, backlog)
        };

        let stage = Arc::new(Stage::new(state, comm));
        let event_stream = EventStream::new(event_rx);

        // Process message backlog
        for (message, sender) in backlog {
            stage
                .clone()
                .handle_commands(Command::HandleMessage {
                    message,
                    sender: Some(sender),
                })
                .await?;
        }

        // Start listening to incoming connections.
        let _ = task::spawn(handle_connection_events(stage.clone(), connection_event_rx));

        let routing = Self { stage };

        Ok((routing, event_stream))
    }

    /// Returns the current age of this node.
    pub async fn age(&self) -> u8 {
        self.stage.state.lock().await.node().age
    }

    /// Returns the `PublicKey` of this node.
    pub async fn public_key(&self) -> PublicKey {
        self.stage.state.lock().await.node().keypair.public
    }

    /// Sign any data with the key of this node.
    pub async fn sign(&self, data: &[u8]) -> Signature {
        self.stage.state.lock().await.node().keypair.sign(data)
    }

    /// Verify any signed data with the key of this node.
    pub async fn verify(&self, data: &[u8], signature: &Signature) -> bool {
        self.stage
            .state
            .lock()
            .await
            .node()
            .keypair
            .verify(data, signature)
            .is_ok()
    }

    /// The name of this node.
    pub async fn name(&self) -> XorName {
        self.stage.state.lock().await.node().name()
    }

    /// Returns connection info of this node.
    pub async fn our_connection_info(&self) -> Result<SocketAddr> {
        self.stage.comm.our_connection_info().await
    }

    /// Prefix of our section
    pub async fn our_prefix(&self) -> Prefix {
        *self.stage.state.lock().await.section().prefix()
    }

    /// Finds out if the given XorName matches our prefix.
    pub async fn matches_our_prefix(&self, name: &XorName) -> bool {
        self.our_prefix().await.matches(name)
    }

    /// Returns whether the node is Elder.
    pub async fn is_elder(&self) -> bool {
        self.stage.state.lock().await.is_elder()
    }

    /// Returns the information of all the current section elders.
    pub async fn our_elders(&self) -> Vec<Peer> {
        self.stage
            .state
            .lock()
            .await
            .section()
            .elders_info()
            .peers()
            .copied()
            .collect()
    }

    /// Returns the elders of our section sorted by their distance to `name` (closest first).
    pub async fn our_elders_sorted_by_distance_to(&self, name: &XorName) -> Vec<Peer> {
        self.our_elders()
            .await
            .into_iter()
            .sorted_by(|lhs, rhs| name.cmp_distance(lhs.name(), rhs.name()))
            .collect()
    }

    /// Returns the information of all the current section adults.
    pub async fn our_adults(&self) -> Vec<Peer> {
        self.stage
            .state
            .lock()
            .await
            .section()
            .adults()
            .copied()
            .collect()
    }

    /// Returns the adults of our section sorted by their distance to `name` (closest first).
    /// If we are not elder or if there are no adults in the section, returns empty vec.
    pub async fn our_adults_sorted_by_distance_to(&self, name: &XorName) -> Vec<Peer> {
        self.our_adults()
            .await
            .into_iter()
            .sorted_by(|lhs, rhs| name.cmp_distance(lhs.name(), rhs.name()))
            .collect()
    }

    /// Returns the info about our section or `None` if we are not joined yet.
    pub async fn our_section(&self) -> EldersInfo {
        self.stage
            .state
            .lock()
            .await
            .section()
            .elders_info()
            .clone()
    }

    /// Returns the info about our neighbour sections.
    pub async fn neighbour_sections(&self) -> Vec<EldersInfo> {
        self.stage
            .state
            .lock()
            .await
            .network()
            .all()
            .cloned()
            .collect()
    }

    /// Send a message.
    /// Messages sent here, either section to section or node to node are signed
    /// and validated upon receipt by routing itself.
    pub async fn send_message(
        &self,
        src: SrcLocation,
        dst: DstLocation,
        content: Bytes,
    ) -> Result<()> {
        let command = Command::SendUserMessage { src, dst, content };
        self.stage.clone().handle_commands(command).await
    }

    /// Send a message to a client peer.
    /// Messages sent to a client are not signed or validated as part of the
    /// routing library.
    pub async fn send_message_to_client(
        &self,
        recipient: SocketAddr,
        message: Bytes,
    ) -> Result<()> {
        let command = Command::SendMessage {
            recipients: vec![recipient],
            delivery_group_size: 1,
            message,
        };
        self.stage.clone().handle_commands(command).await
    }

    /// Returns the current BLS public key set or `Error::InvalidState` if we are not joined
    /// yet.
    pub async fn public_key_set(&self) -> Result<bls::PublicKeySet> {
        self.stage
            .state
            .lock()
            .await
            .section_key_share()
            .map(|share| share.public_key_set.clone())
            .ok_or(Error::InvalidState)
    }

    /// Returns the current BLS secret key share or `Error::InvalidState` if we are not
    /// elder.
    pub async fn secret_key_share(&self) -> Result<bls::SecretKeyShare> {
        self.stage
            .state
            .lock()
            .await
            .section_key_share()
            .map(|share| share.secret_key_share.clone())
            .ok_or(Error::InvalidState)
    }

    /// Returns our section proof chain, or `None` if we are not joined yet.
    pub async fn our_history(&self) -> SectionProofChain {
        self.stage.state.lock().await.section().chain().clone()
    }

    /// Returns our index in the current BLS group or `Error::InvalidState` if section key was
    /// not generated yet.
    pub async fn our_index(&self) -> Result<usize> {
        self.stage
            .state
            .lock()
            .await
            .section_key_share()
            .map(|share| share.index)
            .ok_or(Error::InvalidState)
    }
}

impl Drop for Routing {
    fn drop(&mut self) {
        self.stage.terminate()
    }
}

// Listen for incoming connection events and handle them.
async fn handle_connection_events(
    stage: Arc<Stage>,
    mut incoming_conns: mpsc::Receiver<ConnectionEvent>,
) {
    while let Some(event) = incoming_conns.recv().await {
        match event {
            ConnectionEvent::Received(qp2p::Message::UniStream { bytes, src, .. }) => {
                trace!(
                    "New message ({} bytes) received on a uni-stream from: {}",
                    bytes.len(),
                    src
                );
                // Since it's arriving on a uni-stream we treat it as a Node
                // message which needs to be processed by us, as well as
                // potentially reported to the event stream consumer.

                // Ignore pings.
                if bytes == PING {
                    continue;
                }

                let _ = task::spawn(handle_message(stage.clone(), bytes, src));
            }
            ConnectionEvent::Received(qp2p::Message::BiStream {
                bytes,
                src,
                send,
                recv,
            }) => {
                trace!(
                    "New message ({} bytes) received on a bi-stream from: {}",
                    bytes.len(),
                    src
                );

                // Since it's arriving on a bi-stream we treat it as a Client
                // message which we report directly to the event stream consumer
                // without doing any intermediate processing.
                let event = Event::ClientMessageReceived {
                    content: bytes,
                    src,
                    send,
                    recv,
                };

                stage.send_event(event).await;
            }
            ConnectionEvent::Disconnected(addr) => {
                let _ = stage
                    .clone()
                    .handle_commands(Command::HandleConnectionLost(addr))
                    .await;
            }
        }
    }
}

async fn handle_message(stage: Arc<Stage>, msg_bytes: Bytes, sender: SocketAddr) {
    match Message::from_bytes(&msg_bytes) {
        Ok(message) => {
            let command = Command::HandleMessage {
                message,
                sender: Some(sender),
            };
            let _ = stage.handle_commands(command).await;
        }
        Err(error) => {
            debug!("Failed to deserialize message: {}", error);
        }
    }
}
