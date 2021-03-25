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
mod enduser_registry;
mod event_stream;
mod lazy_messaging;
mod split_barrier;
mod stage;
#[cfg(test)]
mod tests;

pub use self::event_stream::EventStream;
use self::{
    approved::Approved,
    comm::{Comm, ConnectionEvent},
    command::Command,
    split_barrier::SplitBarrier,
    stage::Stage,
};
use crate::{
    crypto,
    error::Result,
    event::Event,
    messages::Message,
    node::Node,
    peer::Peer,
    section::{EldersInfo, SectionChain},
    TransportConfig, MIN_AGE,
};
use bytes::Bytes;
use ed25519_dalek::{Keypair, PublicKey, Signature, Signer};
use itertools::Itertools;
use sn_messaging::{
    client::Message as ClientMessage,
    node::NodeMessage,
    section_info::{ErrorResponse, Message as SectionInfoMsg},
    DstLocation, EndUser, HeaderInfo, Itinerary, MessageType, WireMsg,
};
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
/// role, and can be `sn_messaging::SrcLocation::Node` or `sn_messaging::SrcLocation::Section`.
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
        let node_name = crypto::name(&sn_data_types::PublicKey::from(keypair.public));

        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let (connection_event_tx, mut connection_event_rx) = mpsc::channel(1);

        let (state, comm, backlog) = if config.first {
            info!("{} Starting a new network as the genesis node.", node_name);
            let comm = Comm::new(config.transport_config, connection_event_tx).await?;
            let node = Node::new(keypair, comm.our_connection_info()).with_age(MIN_AGE + 1);
            let state = Approved::first_node(node, event_tx)?;

            state.send_event(Event::Genesis);

            (state, comm, vec![])
        } else {
            info!("{} Bootstrapping a new node.", node_name);
            let (comm, bootstrap_addr) =
                Comm::bootstrap(config.transport_config, connection_event_tx).await?;
            let node = Node::new(keypair, comm.our_connection_info()).with_age(MIN_AGE + 1);
            let (node, section, backlog) =
                bootstrap::initial(node, &comm, &mut connection_event_rx, bootstrap_addr).await?;
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

    /// Sets the JoinsAllowed flag.
    pub async fn set_joins_allowed(&self, joins_allowed: bool) -> Result<()> {
        let command = Command::SetJoinsAllowed(joins_allowed);
        self.stage.clone().handle_commands(command).await
    }

    /// Returns the current age of this node.
    pub async fn age(&self) -> u8 {
        self.stage.state.lock().await.node().age
    }

    /// Returns the ed25519 public key of this node.
    pub async fn public_key(&self) -> PublicKey {
        self.stage.state.lock().await.node().keypair.public
    }

    /// Signs `data` with the ed25519 key of this node.
    pub async fn sign_as_node(&self, data: &[u8]) -> Signature {
        self.stage.state.lock().await.node().keypair.sign(data)
    }

    /// Signs `data` with the BLS secret key share of this node, if it has any. Returns
    /// `Error::MissingSecretKeyShare` otherwise.
    pub async fn sign_as_elder(
        &self,
        data: &[u8],
        public_key: &bls::PublicKey,
    ) -> Result<bls::SignatureShare> {
        self.stage
            .state
            .lock()
            .await
            .sign_with_section_key_share(data, public_key)
    }

    /// Verifies `signature` on `data` with the ed25519 public key of this node.
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
    pub fn our_connection_info(&self) -> SocketAddr {
        self.stage.comm.our_connection_info()
    }

    /// Returns the Section Proof Chain
    pub async fn section_chain(&self) -> SectionChain {
        self.stage.state.lock().await.section_chain()
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

    /// Returns the info about other sections in the network known to us.
    pub async fn other_sections(&self) -> Vec<EldersInfo> {
        self.stage
            .state
            .lock()
            .await
            .network()
            .all()
            .cloned()
            .collect()
    }

    /// Returns the last known public key of the section with `prefix`.
    pub async fn section_key(&self, prefix: &Prefix) -> Option<bls::PublicKey> {
        self.stage.state.lock().await.section_key(prefix).copied()
    }

    /// Returns the info about the section matching the name.
    pub async fn matching_section(
        &self,
        name: &XorName,
    ) -> (Option<bls::PublicKey>, Option<EldersInfo>) {
        let state = self.stage.state.lock().await;
        let (key, elders_info) = state.matching_section(name);
        (key.copied(), elders_info.cloned())
    }

    /// Send a message.
    /// Messages sent here, either section to section or node to node are signed
    /// and validated upon receipt by routing itself.
    pub async fn send_message(&self, itinerary: Itinerary, content: Bytes) -> Result<()> {
        if let DstLocation::EndUser(EndUser::Client {
            socket_id,
            public_key,
        }) = itinerary.dst
        {
            let socket_addr = self
                .stage
                .state
                .lock()
                .await
                .get_socket_addr(socket_id)
                .copied();

            if let Some(socket_addr) = socket_addr {
                return self
                    .send_message_to_client(socket_addr, ClientMessage::from(content)?)
                    .await;
            } else {
                debug!(
                    "Could not find socketaddr corresponding to socket_id {:?} and public_key {:?}",
                    socket_id, public_key
                );
                debug!("Sending user message instead.. (Command::SendUserMessage)");
            }
        }
        let command = Command::SendUserMessage { itinerary, content };
        self.stage.clone().handle_commands(command).await
    }

    /// Send a message to a client peer.
    /// Messages sent to a client are not signed or validated as part of the
    /// routing library.
    async fn send_message_to_client(
        &self,
        recipient: SocketAddr,
        message: ClientMessage,
    ) -> Result<()> {
        let end_user = self
            .stage
            .state
            .lock()
            .await
            .get_enduser_by_addr(&recipient)
            .copied();
        let end_user_pk = match end_user {
            Some(end_user) => match end_user {
                EndUser::AllClients(pk) => pk,
                EndUser::Client { public_key, .. } => public_key,
            },
            None => {
                error!("No client end user known of to send ");
                return Ok(());
            }
        };
        let user_xor_name = XorName::from(end_user_pk);
        let (target_section_pk, _) = self.matching_section(&user_xor_name).await;
        if let Some(section_pk) = target_section_pk {
            let command = Command::SendMessage {
                recipients: vec![(recipient, user_xor_name)],
                delivery_group_size: 1,
                message: MessageType::ClientMessage {
                    msg: message,
                    hdr_info: HeaderInfo {
                        dest: XorName::from(end_user_pk),
                        dest_section_pk: section_pk,
                    },
                },
            };
            self.stage.clone().handle_commands(command).await
        } else {
            warn!(
                "No section PK matching our client PK xorname: {:?}",
                user_xor_name
            );
            Ok(())
        }
    }

    /// Returns the current BLS public key set if this node has one, or
    /// `Error::InvalidState` otherwise.
    pub async fn public_key_set(&self) -> Result<bls::PublicKeySet> {
        self.stage.state.lock().await.public_key_set()
    }

    /// Returns our section proof chain.
    pub async fn our_history(&self) -> SectionChain {
        self.stage.state.lock().await.section().chain().clone()
    }

    /// Returns our index in the current BLS group if this node is a member of one, or
    /// `Error::MissingSecretKeyShare` otherwise.
    pub async fn our_index(&self) -> Result<usize> {
        self.stage.state.lock().await.our_index()
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
            ConnectionEvent::Received((src, bytes)) => {
                trace!("New message ({} bytes) received from: {}", bytes.len(), src);
                handle_message(stage.clone(), bytes, src).await;
            }
            ConnectionEvent::Disconnected(addr) => {
                trace!("Lost connection to {:?}", addr);
                let _ = stage
                    .clone()
                    .handle_commands(Command::HandleConnectionLost(addr))
                    .await;
            }
        }
    }
}

async fn handle_message(stage: Arc<Stage>, bytes: Bytes, sender: SocketAddr) {
    let span = {
        let state = stage.state.lock().await;
        trace_span!("handle_message", name = %state.node().name(), %sender)
    };
    let _span_guard = span.enter();

    let message_type = match WireMsg::deserialize(bytes) {
        Ok(message_type) => message_type,
        Err(error) => {
            error!("Failed to deserialize message: {}", error);
            return;
        }
    };

    match message_type {
        MessageType::Ping(_) => {
            // Pings are not handled
        }
        MessageType::SectionInfo { msg, hdr_info } => {
            let command = Command::HandleSectionInfoMsg {
                sender,
                message: msg,
                hdr_info,
            };
            let _ = task::spawn(stage.handle_commands(command));
        }
        MessageType::NodeMessage {
            msg: NodeMessage(msg_bytes),
            ..
        } => match Message::from_bytes(Bytes::from(msg_bytes)) {
            Ok(message) => {
                let command = Command::HandleMessage {
                    message,
                    sender: Some(sender),
                };
                let _ = task::spawn(stage.handle_commands(command));
            }
            Err(error) => {
                error!("Failed to deserialize node message: {}", error);
            }
        },
        MessageType::ClientMessage { msg, hdr_info } => {
            let end_user = stage
                .state
                .lock()
                .await
                .get_enduser_by_addr(&sender)
                .copied();
            let end_user = match end_user {
                Some(end_user) => end_user,
                None => {
                    // TODO: Update to handle messages, w/ added PK to all msgs...?

                    // we are not yet bootstrapped, todo: inform enduser in a better way of this

                    // let command = Command::SendMessage {
                    //     recipients: vec![sender],
                    //     delivery_group_size: 1,
                    //     message: MessageType::SectionInfo{
                    //         msg: SectionInfoMsg::RegisterEndUserError(
                    //         TargetSectionError::InvalidBootstrap(format!(
                    //             "No enduser found for {} and msg {:?}",
                    //             sender, msg
                    //         )),
                    //     ),
                    // hdr_info: HeaderInfo{
                    //     dest: "x",
                    //     dest_section_pk: "s"
                    // }
                    //     },
                    // };
                    // let _ = task::spawn(stage.handle_commands(command));
                    return;
                }
            };

            let dest = hdr_info.dest;
            let client_pk = hdr_info.dest_section_pk;
            if let Err(error) = stage.check_key_status(&client_pk).await {
                let correlation_id = msg.id();
                let command = Command::SendMessage {
                    recipients: vec![(sender, dest)],
                    delivery_group_size: 1,
                    message: MessageType::SectionInfo {
                        msg: SectionInfoMsg::SectionInfoUpdate(ErrorResponse {
                            correlation_id,
                            error,
                        }),
                        hdr_info: HeaderInfo {
                            dest,
                            dest_section_pk: client_pk,
                        },
                    },
                };
                let _ = task::spawn(stage.handle_commands(command));
                return;
            }

            let event = Event::ClientMessageReceived {
                msg: Box::new(msg),
                user: end_user,
            };

            stage.send_event(event).await;
        }
    }
}
