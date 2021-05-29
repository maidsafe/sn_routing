// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

pub(crate) mod command;

mod bootstrap;
mod comm;
mod connectivity_complaints;
mod core;
mod dispatcher;
mod enduser_registry;
mod event_stream;
mod split_barrier;
#[cfg(test)]
pub(crate) mod tests;

pub use self::event_stream::EventStream;
use self::{
    comm::{Comm, ConnectionEvent},
    command::Command,
    core::Core,
    dispatcher::Dispatcher,
};
use crate::{
    crypto,
    error::Result,
    event::{Elders, Event, NodeElderChange},
    messages::RoutingMsgUtils,
    network::NetworkUtils,
    node::Node,
    peer::PeerUtils,
    section::{SectionAuthorityProviderUtils, SectionUtils},
    Error, TransportConfig, MIN_ADULT_AGE,
};
use bytes::Bytes;
use ed25519_dalek::{Keypair, PublicKey, Signature, Signer, KEYPAIR_LENGTH};
use itertools::Itertools;
use secured_linked_list::SecuredLinkedList;
use sn_messaging::{
    client::ClientMsg,
    node::{Peer, RoutingMsg, SectionAuthorityProvider},
    DestInfo, DstLocation, EndUser, Itinerary, MessageType, WireMsg,
};
use std::{
    collections::BTreeSet,
    fmt::{self, Debug, Formatter},
    net::SocketAddr,
    sync::Arc,
};

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
    dispatcher: Arc<Dispatcher>,
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
        let keypair = config.keypair.unwrap_or_else(|| {
            crypto::gen_keypair(&Prefix::default().range_inclusive(), MIN_ADULT_AGE)
        });
        let node_name = crypto::name(&keypair.public);

        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let (connection_event_tx, mut connection_event_rx) = mpsc::channel(1);

        let (state, comm, backlog) = if config.first {
            // Genesis node having a fix age of 255.
            let keypair = crypto::gen_keypair(&Prefix::default().range_inclusive(), 255);
            let node_name = crypto::name(&keypair.public);

            info!("{} Starting a new network as the genesis node.", node_name);

            let comm = Comm::new(config.transport_config, connection_event_tx).await?;
            let node = Node::new(keypair, comm.our_connection_info());
            let state = Core::first_node(node, event_tx)?;

            let section = state.section();

            let elders = Elders {
                prefix: *section.prefix(),
                key: *section.chain().last_key(),
                remaining: BTreeSet::new(),
                added: section.authority_provider().names(),
                removed: BTreeSet::new(),
            };

            state.send_event(Event::EldersChanged {
                elders,
                self_status_change: NodeElderChange::Promoted,
            });

            (state, comm, vec![])
        } else {
            info!("{} Bootstrapping a new node.", node_name);
            let (comm, bootstrap_addr) =
                Comm::bootstrap(config.transport_config, connection_event_tx).await?;
            let node = Node::new(keypair, comm.our_connection_info());
            let (node, section, backlog) =
                bootstrap::initial(node, &comm, &mut connection_event_rx, bootstrap_addr).await?;
            let state = Core::new(node, section, None, event_tx);

            (state, comm, backlog)
        };

        let dispatcher = Arc::new(Dispatcher::new(state, comm));
        let event_stream = EventStream::new(event_rx);
        info!("{} Bootstrapped!", node_name);

        // Process message backlog
        for (message, sender, dest_info) in backlog {
            dispatcher
                .clone()
                .handle_commands(Command::HandleMessage {
                    message,
                    sender: Some(sender),
                    dest_info,
                })
                .await?;
        }

        // Start listening to incoming connections.
        let _ = task::spawn(handle_connection_events(
            dispatcher.clone(),
            connection_event_rx,
        ));

        let routing = Self { dispatcher };

        Ok((routing, event_stream))
    }

    /// Sets the JoinsAllowed flag.
    pub async fn set_joins_allowed(&self, joins_allowed: bool) -> Result<()> {
        let command = Command::SetJoinsAllowed(joins_allowed);
        self.dispatcher.clone().handle_commands(command).await
    }

    /// Starts a proposal that a node has gone offline.
    /// This can be done only by an Elder.
    pub async fn propose_offline(&self, name: XorName) -> Result<()> {
        if !self.is_elder().await {
            return Err(Error::InvalidState);
        }
        let command = Command::ProposeOffline(name);
        self.dispatcher.clone().handle_commands(command).await
    }

    /// Returns the current age of this node.
    pub async fn age(&self) -> u8 {
        self.dispatcher.core.lock().await.node().age()
    }

    /// Returns the ed25519 public key of this node.
    pub async fn public_key(&self) -> PublicKey {
        self.dispatcher.core.lock().await.node().keypair.public
    }

    /// Returns the ed25519 keypair of this node, as bytes.
    pub async fn keypair_as_bytes(&self) -> [u8; KEYPAIR_LENGTH] {
        self.dispatcher.core.lock().await.node().keypair.to_bytes()
    }

    /// Signs `data` with the ed25519 key of this node.
    pub async fn sign_as_node(&self, data: &[u8]) -> Signature {
        self.dispatcher.core.lock().await.node().keypair.sign(data)
    }

    /// Signs `data` with the BLS secret key share of this node, if it has any. Returns
    /// `Error::MissingSecretKeyShare` otherwise.
    pub async fn sign_as_elder(
        &self,
        data: &[u8],
        public_key: &bls::PublicKey,
    ) -> Result<bls::SignatureShare> {
        self.dispatcher
            .core
            .lock()
            .await
            .sign_with_section_key_share(data, public_key)
    }

    /// Verifies `signature` on `data` with the ed25519 public key of this node.
    pub async fn verify(&self, data: &[u8], signature: &Signature) -> bool {
        self.dispatcher
            .core
            .lock()
            .await
            .node()
            .keypair
            .verify(data, signature)
            .is_ok()
    }

    /// The name of this node.
    pub async fn name(&self) -> XorName {
        self.dispatcher.core.lock().await.node().name()
    }

    /// Returns connection info of this node.
    pub fn our_connection_info(&self) -> SocketAddr {
        self.dispatcher.comm.our_connection_info()
    }

    /// Returns the Section Proof Chain
    pub async fn section_chain(&self) -> SecuredLinkedList {
        self.dispatcher.core.lock().await.section_chain().clone()
    }

    /// Prefix of our section
    pub async fn our_prefix(&self) -> Prefix {
        *self.dispatcher.core.lock().await.section().prefix()
    }

    /// Finds out if the given XorName matches our prefix.
    pub async fn matches_our_prefix(&self, name: &XorName) -> bool {
        self.our_prefix().await.matches(name)
    }

    /// Returns whether the node is Elder.
    pub async fn is_elder(&self) -> bool {
        self.dispatcher.core.lock().await.is_elder()
    }

    /// Returns the information of all the current section elders.
    pub async fn our_elders(&self) -> Vec<Peer> {
        self.dispatcher
            .core
            .lock()
            .await
            .section()
            .authority_provider()
            .peers()
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
        self.dispatcher
            .core
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
    pub async fn our_section(&self) -> SectionAuthorityProvider {
        self.dispatcher
            .core
            .lock()
            .await
            .section()
            .authority_provider()
            .clone()
    }

    /// Returns the info about other sections in the network known to us.
    pub async fn other_sections(&self) -> Vec<SectionAuthorityProvider> {
        self.dispatcher
            .core
            .lock()
            .await
            .network()
            .all()
            .cloned()
            .collect()
    }

    /// Returns the last known public key of the section with `prefix`.
    pub async fn section_key(&self, prefix: &Prefix) -> Option<bls::PublicKey> {
        self.dispatcher
            .core
            .lock()
            .await
            .section_key(prefix)
            .copied()
    }

    /// Returns the info about the section matching the name.
    pub async fn matching_section(
        &self,
        name: &XorName,
    ) -> (Option<bls::PublicKey>, Option<SectionAuthorityProvider>) {
        let state = self.dispatcher.core.lock().await;
        let (key, section_auth) = state.matching_section(name);
        (key.copied(), section_auth.cloned())
    }

    /// Send a message.
    /// Messages sent here, either section to section or node to node are signed
    /// and validated upon receipt by routing itself.
    ///
    /// `additional_proof_chain_key` is a key to be included in the proof chain attached to the
    /// message. This is useful when the message contains some data that is signed with a different
    /// key than the whole message is so that the recipient can verify such key.
    pub async fn send_message(
        &self,
        itinerary: Itinerary,
        content: Bytes,
        additional_proof_chain_key: Option<bls::PublicKey>,
    ) -> Result<()> {
        if let DstLocation::EndUser(EndUser { socket_id, xorname }) = itinerary.dst {
            if self.our_prefix().await.matches(&xorname) {
                let addr = self
                    .dispatcher
                    .core
                    .lock()
                    .await
                    .get_socket_addr(socket_id)
                    .copied();

                if let Some(socket_addr) = addr {
                    debug!("Sending client msg to {:?}", socket_addr);
                    return self
                        .send_message_to_client(socket_addr, xorname, ClientMsg::from(content)?)
                        .await;
                } else {
                    debug!(
                        "Could not find socketaddr corresponding to socket_id {:?}",
                        socket_id
                    );
                    debug!("Relaying user message instead.. (Command::SendUserMessage)");
                }
            } else {
                debug!("Relaying message with sending user message (Command::SendUserMessage)");
            }
        }

        let command = Command::SendUserMessage {
            itinerary,
            content,
            additional_proof_chain_key,
        };
        self.dispatcher.clone().handle_commands(command).await
    }

    /// Send a message to a client peer.
    /// Messages sent to a client are not signed or validated as part of the
    /// routing library.
    async fn send_message_to_client(
        &self,
        recipient: SocketAddr,
        user_xorname: XorName,
        message: ClientMsg,
    ) -> Result<()> {
        let command = Command::SendMessage {
            recipients: vec![(user_xorname, recipient)],
            delivery_group_size: 1,
            message: MessageType::Client {
                msg: message,
                dest_info: DestInfo {
                    dest: user_xorname,
                    dest_section_pk: *self.section_chain().await.last_key(),
                },
            },
        };
        self.dispatcher.clone().handle_commands(command).await
    }

    /// Returns the current BLS public key set if this node has one, or
    /// `Error::InvalidState` otherwise.
    pub async fn public_key_set(&self) -> Result<bls::PublicKeySet> {
        self.dispatcher.core.lock().await.public_key_set()
    }

    /// Returns our section proof chain.
    pub async fn our_history(&self) -> SecuredLinkedList {
        self.dispatcher.core.lock().await.section().chain().clone()
    }

    /// Returns our index in the current BLS group if this node is a member of one, or
    /// `Error::MissingSecretKeyShare` otherwise.
    pub async fn our_index(&self) -> Result<usize> {
        self.dispatcher.core.lock().await.our_index()
    }
}

impl Drop for Routing {
    fn drop(&mut self) {
        self.dispatcher.terminate()
    }
}

impl Debug for Routing {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "Routing")
    }
}

// Listen for incoming connection events and handle them.
async fn handle_connection_events(
    dispatcher: Arc<Dispatcher>,
    mut incoming_conns: mpsc::Receiver<ConnectionEvent>,
) {
    while let Some(event) = incoming_conns.recv().await {
        match event {
            ConnectionEvent::Received((src, bytes)) => {
                trace!("New message ({} bytes) received from: {}", bytes.len(), src);
                handle_message(dispatcher.clone(), bytes, src).await;
            }
            ConnectionEvent::Disconnected(addr) => {
                trace!("Lost connection to {:?}", addr);
                let _ = dispatcher
                    .clone()
                    .handle_commands(Command::HandleConnectionLost(addr))
                    .await;
            }
        }
    }
}

async fn handle_message(dispatcher: Arc<Dispatcher>, bytes: Bytes, sender: SocketAddr) {
    let wire_msg = match WireMsg::from(bytes) {
        Ok(wire_msg) => wire_msg,
        Err(error) => {
            error!("Failed to deserialize message header: {}", error);
            return;
        }
    };
    let span = {
        let mut state = dispatcher.core.lock().await;

        if !state.add_to_filter(&wire_msg.msg_id()) {
            trace!(
                "not handling message - already handled: {:?}",
                wire_msg.msg_id()
            );
            return;
        }

        trace_span!("handle_message", name = %state.node().name(), %sender)
    };
    let _span_guard = span.enter();

    let message_type = match wire_msg.to_message() {
        Ok(message_type) => message_type,
        Err(error) => {
            error!(
                "Failed to deserialize message payload ({:?}): {}",
                wire_msg.msg_id(),
                error
            );
            return;
        }
    };

    match message_type {
        MessageType::SectionInfo { msg, dest_info } => {
            let command = Command::HandleSectionInfoMsg {
                sender,
                message: msg,
                dest_info,
            };
            let _ = task::spawn(dispatcher.handle_commands(command));
        }
        MessageType::Routing { msg, dest_info } => {
            if let Err(err) = RoutingMsg::check_signature(&msg) {
                error!(
                    "Discarding message received ({:?}) due to invalid signature: {:?}",
                    msg.id, err
                );
                return;
            }

            let command = Command::HandleMessage {
                message: msg,
                sender: Some(sender),
                dest_info,
            };
            let _ = task::spawn(dispatcher.handle_commands(command));
        }
        MessageType::Node {
            msg: _,
            dest_info: _,
            src_section_pk: _,
        } => unimplemented!(),
        MessageType::Client { msg, .. } => {
            let end_user = dispatcher
                .core
                .lock()
                .await
                .get_enduser_by_addr(&sender)
                .copied();

            let end_user = match end_user {
                Some(end_user) => {
                    debug!(
                        "Message from client {}, socket id already exists: {:?}",
                        sender, end_user
                    );
                    end_user
                }
                None => {
                    // this is the first time we receive a message from this client
                    debug!("First message from client {}, creating a socket id", sender);

                    // TODO: remove the enduser registry and simply encrypt socket addr with
                    // this node's keypair and use that as the socket id
                    match dispatcher.core.lock().await.try_add(sender) {
                        Ok(end_user) => end_user,
                        Err(err) => {
                            error!(
                                "Failed to cache client socket address for message {:?}: {:?}",
                                msg, err
                            );
                            return;
                        }
                    }
                }
            };

            let event = Event::ClientMsgReceived {
                msg: Box::new(msg),
                user: end_user,
            };

            dispatcher.send_event(event).await;
        }
    }
}
