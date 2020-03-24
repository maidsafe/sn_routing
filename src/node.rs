// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

// #[cfg(all(test, feature = "mock"))]
// mod tests;

use crate::{
    action::Action,
    chain::{EldersInfo, GenesisPfxInfo, NetworkParams},
    core::Core,
    error::{Result, RoutingError},
    event::{Connected, Event},
    id::{FullId, P2pNode, PublicId},
    location::{DstLocation, SrcLocation},
    log_utils,
    messages::{BootstrapResponse, Message, MessageHash, MessageWithBytes, QueuedMessage, Variant},
    pause::PausedState,
    quic_p2p::{EventSenders, Peer, Token},
    relocation::{RelocatePayload, SignedRelocateDetails},
    rng::{self, MainRng},
    stage::{Approved, Bootstrapping, BootstrappingStatus, Joining, RelocateParams, Stage},
    time::Duration,
    timer::Timer,
    transport::PeerStatus,
    xor_space::{Prefix, XorName},
    NetworkConfig, NetworkEvent,
};
use bytes::Bytes;
use crossbeam_channel::{Receiver, RecvError, Select, Sender};
use std::net::SocketAddr;

#[cfg(feature = "mock_base")]
use {
    crate::chain::{Chain, SectionProofSlice},
    std::collections::{BTreeMap, BTreeSet},
};

/// Delay after which a bounced message is resent.
pub const BOUNCE_RESEND_DELAY: Duration = Duration::from_secs(1);

/// Node configuration.
pub struct NodeConfig {
    /// If true, configures the node to start a new network instead of joining an existing one.
    pub first: bool,
    /// The ID of the node or `None` for randomly generated one.
    pub full_id: Option<FullId>,
    /// Configuration for the underlying network transport.
    pub network_config: NetworkConfig,
    /// Global network parameters. Must be identical for all nodes in the network.
    pub network_params: NetworkParams,
    /// Random number generator to be used by the node. Can be used to achieve repeatable tests by
    /// providing a pre-seeded RNG. By default uses a random seed provided by the OS.
    pub rng: MainRng,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            first: false,
            full_id: None,
            network_config: NetworkConfig::default(),
            network_params: NetworkParams::default(),
            rng: rng::new(),
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
pub struct Node {
    core: Core,
    stage: Stage,

    action_rx: Receiver<Action>,
    action_rx_idx: usize,
    network_rx: Receiver<NetworkEvent>,
    network_rx_idx: usize,
    user_event_tx: Sender<Event>,

    // TODO: remove these. Handle actions directly.
    interface_result_tx: Sender<Result<()>>,
    interface_result_rx: Receiver<Result<()>>,
}

impl Node {
    ////////////////////////////////////////////////////////////////////////////
    // Public API
    ////////////////////////////////////////////////////////////////////////////

    /// Create new node using the given config.
    ///
    /// Returns the node itself, the user event receiver and the client network
    /// event receiver.
    pub fn new(config: NodeConfig) -> (Self, Receiver<Event>, Receiver<NetworkEvent>) {
        let (action_tx, action_rx) = crossbeam_channel::unbounded();
        let (network_tx, network_node_rx, network_client_rx) = {
            let (client_tx, client_rx) = crossbeam_channel::unbounded();
            let (node_tx, node_rx) = crossbeam_channel::unbounded();
            (EventSenders { node_tx, client_tx }, node_rx, client_rx)
        };
        let (user_event_tx, user_event_rx) = crossbeam_channel::unbounded();
        let (interface_result_tx, interface_result_rx) = crossbeam_channel::bounded(1);

        let first = config.first;
        let network_params = config.network_params;
        let mut core = Core::new(config, action_tx, network_tx);

        let stage = if first {
            match Approved::first(&mut core, network_params) {
                Ok(stage) => {
                    info!("{} Started a new network as a seed node.", core.name());
                    let _ = user_event_tx.send(Event::Connected(Connected::First));
                    let _ = user_event_tx.send(Event::Promoted);
                    Stage::Approved(stage)
                }
                Err(error) => {
                    error!(
                        "{} Failed to start the first node: {:?}",
                        core.name(),
                        error
                    );
                    Stage::Terminated
                }
            }
        } else {
            info!("{} Bootstrapping a new node.", core.name());
            core.transport.bootstrap();
            Stage::Bootstrapping(Bootstrapping::new(network_params, None))
        };

        let node = Self {
            stage,
            core,
            action_rx,
            action_rx_idx: 0,
            network_rx: network_node_rx,
            network_rx_idx: 0,
            user_event_tx,
            interface_result_tx,
            interface_result_rx,
        };

        (node, user_event_rx, network_client_rx)
    }

    /// Pauses the node in order to be upgraded and/or restarted.
    // TODO: return Result instead of panic
    pub fn pause(self) -> PausedState {
        let stage = match self.stage {
            Stage::Approved(stage) => stage,
            _ => unreachable!(),
        };

        info!("Pause");

        let mut state = stage.pause(self.core);
        state.network_rx = Some(self.network_rx);
        state
    }

    /// Resume previously paused node.
    pub fn resume(mut state: PausedState) -> (Self, Receiver<Event>) {
        let (action_tx, action_rx) = crossbeam_channel::unbounded();
        let network_rx = state.network_rx.take().expect("PausedState is incomplete");
        let (user_event_tx, user_event_rx) = crossbeam_channel::unbounded();
        let (interface_result_tx, interface_result_rx) = crossbeam_channel::bounded(1);

        let timer = Timer::new(action_tx);

        let (stage, core) = Approved::resume(state, timer);

        info!("Resume");

        let node = Self {
            stage: Stage::Approved(stage),
            core,
            action_rx,
            action_rx_idx: 0,
            network_rx,
            network_rx_idx: 0,
            user_event_tx,
            interface_result_tx,
            interface_result_rx,
        };

        (node, user_event_rx)
    }

    /// Register the node event channels with the provided [selector](mpmc::Select).
    pub fn register<'a>(&'a mut self, select: &mut Select<'a>) {
        // Populate action_rx timeouts
        #[cfg(feature = "mock_base")]
        self.core.timer.process_timers();

        self.action_rx_idx = select.recv(&self.action_rx);
        self.network_rx_idx = select.recv(&self.network_rx);
    }

    /// Processes events received externally from one of the channels.
    /// For this function to work properly, the node event channels need to
    /// be registered by calling [`ApprovedPeer::register`](#method.register).
    /// [`Select::ready`] needs to be called to get `op_index`, the event channel index.
    ///
    /// This function is non-blocking.
    ///
    /// Errors are permanent failures due to either: node termination, the permanent closing of one
    /// of the event channels, or an invalid (unknown) channel index.
    ///
    /// [`Select::ready`]: https://docs.rs/crossbeam-channel/0.3/crossbeam_channel/struct.Select.html#method.ready
    ///
    /// The returned `bool` can be safely ignored by the consumers of this crate. It is for
    /// internal uses only and will always be `true` unless compiled with `feature=mock_base`.
    pub fn handle_selected_operation(&mut self, op_index: usize) -> Result<bool, RecvError> {
        if !self.is_running() {
            return Err(RecvError);
        }

        match op_index {
            idx if idx == self.network_rx_idx => {
                let event = self.network_rx.recv()?;
                self.handle_network_event(event);
                Ok(true)
            }
            idx if idx == self.action_rx_idx => {
                let action = self.action_rx.recv()?;

                let status = is_busy(&action);
                self.handle_action(action);
                Ok(status)
            }
            _idx => Err(RecvError),
        }
    }

    /// Returns whether this node is running or has been terminated.
    pub fn is_running(&self) -> bool {
        !matches!(self.stage, Stage::Terminated)
    }

    /// Returns the `PublicId` of this node.
    pub fn id(&self) -> &PublicId {
        self.core.id()
    }

    /// The name of this node.
    pub fn name(&self) -> &XorName {
        self.id().name()
    }

    /// Returns connection info of this node.
    pub fn our_connection_info(&mut self) -> Result<SocketAddr> {
        self.core.our_connection_info()
    }

    /// Our `Prefix` once we are a part of the section.
    pub fn our_prefix(&self) -> Option<&Prefix<XorName>> {
        if let Stage::Approved(stage) = &self.stage {
            Some(stage.chain.our_prefix())
        } else {
            None
        }
    }

    /// Finds out if the given XorName matches our prefix. Returns error if we don't have a prefix
    /// because we haven't joined any section yet.
    pub fn matches_our_prefix(&self, name: &XorName) -> Result<bool> {
        if let Some(prefix) = self.our_prefix() {
            Ok(prefix.matches(name))
        } else {
            Err(RoutingError::InvalidState)
        }
    }

    /// Returns the information of all the current section elders.
    pub fn our_elders(&self) -> impl Iterator<Item = &P2pNode> {
        self.stage
            .approved()
            .into_iter()
            .flat_map(|stage| stage.chain.our_elders())
    }

    /// Find out the closest Elders to a given XorName that we know of.
    ///
    /// Note that the Adults of a section only know about their section Elders. Hence they will
    /// always return the section Elders' info.
    pub fn closest_known_elders_to<'a>(
        &'a self,
        name: &XorName,
    ) -> impl Iterator<Item = &'a P2pNode> + 'a {
        let name = *name;
        self.stage
            .approved()
            .into_iter()
            .flat_map(move |stage| stage.chain.closest_section_info(name).1.member_nodes())
    }

    /// Returns the first `count` names of the nodes in the routing table which are closest
    /// to the given one.
    pub fn close_group(&self, name: XorName, count: usize) -> Option<Vec<XorName>> {
        let stage = if let Some(stage) = self.stage.approved() {
            stage
        } else {
            return None;
        };

        let mut conn_peers: Vec<_> = stage.chain.elders().map(P2pNode::name).collect();
        conn_peers.sort_unstable();
        conn_peers.dedup();

        stage.chain.closest_names(&name, count, &conn_peers)
    }

    /// Checks whether the given location represents self.
    pub fn in_dst_location(&self, dst: &DstLocation) -> bool {
        match &self.stage {
            Stage::Bootstrapping(_) | Stage::Joining(_) => match dst {
                DstLocation::Node(name) => name == self.core.name(),
                DstLocation::Section(_) | DstLocation::Prefix(_) => false,
                DstLocation::Direct => true,
            },
            Stage::Approved(stage) => stage.chain.in_dst_location(dst),
            Stage::Terminated => false,
        }
    }

    /// Vote for a user-defined event.
    // TODO: return error if not elder
    pub fn vote_for_user_event(&mut self, event: Vec<u8>) {
        if let Some(stage) = self.stage.approved_mut() {
            stage.vote_for_user_event(event)
        }
    }

    /// Send a message.
    pub fn send_message(
        &mut self,
        src: SrcLocation,
        dst: DstLocation,
        content: Vec<u8>,
    ) -> Result<(), RoutingError> {
        let action = Action::SendMessage {
            src,
            dst,
            content,
            result_tx: self.interface_result_tx.clone(),
        };

        self.perform_action(action)
    }

    /// Send a message to a client peer.
    pub fn send_message_to_client(
        &mut self,
        peer_addr: SocketAddr,
        msg: Bytes,
        token: Token,
    ) -> Result<()> {
        let action = Action::SendMessageToClient {
            peer_addr,
            msg,
            token,
            result_tx: self.interface_result_tx.clone(),
        };

        self.perform_action(action)
    }

    /// Disconnect form a client peer.
    pub fn disconnect_from_client(&mut self, peer_addr: SocketAddr) -> Result<()> {
        let action = Action::DisconnectClient {
            peer_addr,
            result_tx: self.interface_result_tx.clone(),
        };

        self.perform_action(action)
    }

    ////////////////////////////////////////////////////////////////////////////
    // Input handling
    ////////////////////////////////////////////////////////////////////////////

    fn perform_action(&mut self, action: Action) -> Result<(), RoutingError> {
        self.handle_action(action);
        self.interface_result_rx.recv()?
    }

    fn handle_action(&mut self, action: Action) {
        let _log_ident = self.set_log_ident();

        match action {
            Action::SendMessage {
                src,
                dst,
                content,
                result_tx,
            } => {
                let result = self.handle_send_message(src, dst, content);
                let _ = result_tx.send(result);
            }
            Action::HandleTimeout(token) => self.handle_timeout(token),
            Action::DisconnectClient {
                peer_addr,
                result_tx,
            } => {
                self.core.transport.disconnect(peer_addr);
                let _ = result_tx.send(Ok(()));
            }
            Action::SendMessageToClient {
                peer_addr,
                msg,
                token,
                result_tx,
            } => {
                self.core
                    .transport
                    .send_message_to_client(peer_addr, msg, token);
                let _ = result_tx.send(Ok(()));
            }
        }

        self.finish_handle_input()
    }

    fn handle_network_event(&mut self, event: NetworkEvent) {
        use crate::NetworkEvent::*;

        let _log_ident = self.set_log_ident();

        match event {
            BootstrappedTo { node } => self.handle_bootstrapped_to(node),
            BootstrapFailure => self.handle_bootstrap_failure(),
            ConnectedTo { peer } => match peer {
                Peer::Client(_) => (),
                Peer::Node(peer_addr) => self.handle_connected_to(peer_addr),
            },
            ConnectionFailure { peer, .. } => match peer {
                Peer::Client(_) => (),
                Peer::Node(peer_addr) => self.handle_connection_failure(peer_addr),
            },
            NewMessage { peer, msg } => match peer {
                Peer::Client(_) => (),
                Peer::Node(peer_addr) => self.handle_new_message(peer_addr, msg),
            },
            UnsentUserMessage { peer, msg, token } => match peer {
                Peer::Client(_) => (),
                Peer::Node(peer_addr) => self.handle_unsent_message(peer_addr, msg, token),
            },
            SentUserMessage { peer, msg, token } => match peer {
                Peer::Client(_) => (),
                Peer::Node(peer_addr) => self.handle_sent_message(peer_addr, msg, token),
            },
            Finish => {
                self.stage = Stage::Terminated;
                return;
            }
        };

        self.finish_handle_input()
    }

    fn finish_handle_input(&mut self) {
        self.handle_messages();

        if let Stage::Approved(stage) = &mut self.stage {
            stage.finish_handle_input(&mut self.core, &mut self.user_event_tx);
        }
    }

    fn handle_send_message(
        &mut self,
        src: SrcLocation,
        dst: DstLocation,
        content: Vec<u8>,
    ) -> Result<(), RoutingError> {
        if let DstLocation::Direct = dst {
            return Err(RoutingError::BadLocation);
        }

        match &mut self.stage {
            Stage::Bootstrapping(_) | Stage::Joining(_) | Stage::Terminated => {
                warn!("Cannot handle SendMessage - not joined.");
                // TODO: return Err here eventually. Returning Ok for now to
                // preserve the pre-refactor behaviour.
                Ok(())
            }
            Stage::Approved(stage) => stage.send_routing_message(
                &mut self.core,
                src,
                dst,
                Variant::UserMessage(content),
                None,
            ),
        }
    }

    fn handle_bootstrapped_to(&mut self, addr: SocketAddr) {
        match &mut self.stage {
            Stage::Bootstrapping(stage) => stage.send_bootstrap_request(&mut self.core, addr),
            Stage::Joining(_) | Stage::Approved(_) => {
                // A bootstrapped node doesn't need another bootstrap connection
                self.core.transport.disconnect(addr);
            }
            Stage::Terminated => {}
        }
    }

    fn handle_bootstrap_failure(&mut self) {
        assert!(matches!(self.stage, Stage::Bootstrapping(_)));

        info!("Failed to bootstrap. Terminating.");
        let _ = self.user_event_tx.send(Event::Terminated);
        self.stage = Stage::Terminated;
    }

    fn handle_connected_to(&mut self, _addr: SocketAddr) {}

    fn handle_connection_failure(&mut self, addr: SocketAddr) {
        if let Stage::Approved(stage) = &mut self.stage {
            stage.handle_connection_failure(&mut self.core, addr);
        } else {
            trace!("ConnectionFailure from {}", addr);
        }
    }

    fn handle_new_message(&mut self, sender: SocketAddr, bytes: Bytes) {
        let msg = match MessageWithBytes::partial_from_bytes(bytes) {
            Ok(msg) => msg,
            Err(error) => {
                debug!("Failed to deserialize message: {:?}", error);
                return;
            }
        };

        if let Err(error) = self.try_handle_message(Some(sender), msg) {
            debug!("Failed to handle message: {:?}", error);
        }
    }

    fn handle_unsent_message(&mut self, addr: SocketAddr, msg: Bytes, msg_token: Token) {
        match self.core.handle_unsent_message(addr, msg, msg_token) {
            PeerStatus::Normal => (),
            PeerStatus::Lost => self.handle_peer_lost(addr),
        }
    }

    fn handle_sent_message(&mut self, addr: SocketAddr, _msg: Bytes, token: Token) {
        trace!("Successfully sent message with ID {} to {:?}", token, addr);
        self.core.transport.target_succeeded(token, addr);
    }

    fn handle_timeout(&mut self, token: u64) {
        if self.core.transport.handle_timeout(token) {
            return;
        }

        match &mut self.stage {
            Stage::Bootstrapping(stage) => stage.handle_timeout(&mut self.core, token),
            Stage::Joining(stage) => {
                if stage.handle_timeout(&mut self.core, token) {
                    let network_cfg = stage.network_cfg;
                    self.rebootstrap(network_cfg)
                }
            }
            Stage::Approved(stage) => stage.handle_timeout(&mut self.core, token),
            Stage::Terminated => {}
        }
    }

    fn handle_peer_lost(&mut self, peer_addr: SocketAddr) {
        if let Stage::Approved(stage) = &mut self.stage {
            stage.handle_peer_lost(peer_addr);
        }
    }

    ////////////////////////////////////////////////////////////////////////////
    // Message handling
    ////////////////////////////////////////////////////////////////////////////

    fn try_handle_message(
        &mut self,
        sender: Option<SocketAddr>,
        mut msg_with_bytes: MessageWithBytes,
    ) -> Result<()> {
        trace!("try handle message {:?}", msg_with_bytes);

        self.try_relay_message(sender, &msg_with_bytes)?;

        if !self.in_dst_location(msg_with_bytes.message_dst()) {
            return Ok(());
        }

        if self.core.msg_filter.contains_incoming(&msg_with_bytes) {
            trace!(
                "not handling message - already handled: {:?}",
                msg_with_bytes
            );
            return Ok(());
        }

        let msg = msg_with_bytes.take_or_deserialize_message()?;

        if self.should_handle_message(&msg) && self.verify_message(&msg)? {
            self.core.msg_filter.insert_incoming(&msg_with_bytes);
            self.handle_message(sender, msg)
        } else {
            self.unhandled_message(sender, msg, msg_with_bytes.full_bytes().clone());
            Ok(())
        }
    }

    fn try_relay_message(
        &mut self,
        sender: Option<SocketAddr>,
        msg: &MessageWithBytes,
    ) -> Result<()> {
        if !self.in_dst_location(msg.message_dst()) || msg.message_dst().is_multiple() {
            // Relay closer to the destination or broadcast to the rest of our section.
            self.relay_message(sender, msg)
        } else {
            Ok(())
        }
    }

    fn relay_message(&mut self, sender: Option<SocketAddr>, msg: &MessageWithBytes) -> Result<()> {
        match &mut self.stage {
            Stage::Bootstrapping(_) | Stage::Joining(_) => {
                let sender = sender.expect("sender missing");

                trace!("Message not for us, bouncing: {:?}", msg);

                let variant = Variant::Bounce {
                    elders_version: None,
                    message: msg.full_bytes().clone(),
                };

                self.core.send_direct_message(&sender, variant);

                Ok(())
            }
            Stage::Approved(stage) => stage.send_signed_message(&mut self.core, msg),
            Stage::Terminated => unreachable!(),
        }
    }

    fn should_handle_message(&self, msg: &Message) -> bool {
        match &self.stage {
            Stage::Bootstrapping(stage) => stage.should_handle_message(msg),
            Stage::Joining(stage) => stage.should_handle_message(msg),
            Stage::Approved(stage) => stage.should_handle_message(msg),
            Stage::Terminated => false,
        }
    }

    fn verify_message(&self, msg: &Message) -> Result<bool> {
        match &self.stage {
            Stage::Bootstrapping(stage) => stage.verify_message(msg),
            Stage::Joining(stage) => stage.verify_message(msg),
            Stage::Approved(stage) => stage.verify_message(msg),
            Stage::Terminated => unreachable!(),
        }
    }

    fn handle_message(&mut self, sender: Option<SocketAddr>, msg: Message) -> Result<()> {
        if let Stage::Approved(stage) = &mut self.stage {
            stage.update_our_knowledge(&msg);
        }

        self.core.msg_queue.push_back(msg.into_queued(sender));

        Ok(())
    }

    fn handle_messages(&mut self) {
        while let Some(QueuedMessage { message, sender }) = self.core.msg_queue.pop_front() {
            if self.in_dst_location(&message.dst) {
                match self.dispatch_message(sender, message) {
                    Ok(()) => (),
                    Err(err) => debug!("Routing message dispatch failed: {:?}", err),
                }
            }
        }
    }

    fn dispatch_message(&mut self, sender: Option<SocketAddr>, msg: Message) -> Result<()> {
        // Common messages
        match msg.variant {
            Variant::UserMessage(_) => (),
            _ => trace!("Got {:?}", msg),
        }

        match &mut self.stage {
            Stage::Bootstrapping(stage) => match msg.variant {
                Variant::BootstrapResponse(response) => {
                    match stage.handle_bootstrap_response(
                        &mut self.core,
                        msg.src.to_sender_node(sender)?,
                        response,
                    )? {
                        BootstrappingStatus::Ongoing => (),
                        BootstrappingStatus::Finished {
                            elders_info,
                            relocate_payload,
                        } => {
                            let network_cfg = stage.network_cfg;
                            self.join(network_cfg, elders_info, relocate_payload);
                        }
                    }
                }
                Variant::Bounce {
                    elders_version,
                    message,
                } => self.handle_bounce(msg.src.to_sender_node(sender)?, elders_version, message),
                _ => unreachable!(),
            },
            Stage::Joining(stage) => match msg.variant {
                Variant::BootstrapResponse(BootstrapResponse::Join(elders_info)) => stage
                    .handle_bootstrap_response(
                        &mut self.core,
                        msg.src.to_sender_node(sender)?,
                        elders_info,
                    )?,
                Variant::NodeApproval(gen_pfx_info) => {
                    let network_cfg = stage.network_cfg;
                    let connect_type = stage.connect_type();
                    self.approve(network_cfg, connect_type, *gen_pfx_info)
                }
                Variant::Bounce {
                    elders_version,
                    message,
                } => self.handle_bounce(msg.src.to_sender_node(sender)?, elders_version, message),
                _ => unreachable!(),
            },
            Stage::Approved(stage) => match msg.variant {
                Variant::NeighbourInfo(elders_info) => {
                    // Ensure the src and dst are what we expect.
                    let _: &Prefix<_> = msg.src.as_section()?;
                    let _: &Prefix<_> = msg.dst.as_prefix()?;
                    stage.handle_neighbour_info(elders_info, msg.src, msg.dst)?;
                }
                Variant::AckMessage {
                    src_prefix,
                    ack_version,
                } => {
                    stage.handle_ack_message(
                        src_prefix,
                        ack_version,
                        *msg.src.as_section()?,
                        *msg.dst.as_section()?,
                    )?;
                }
                Variant::GenesisUpdate(info) => {
                    let _: &Prefix<_> = msg.src.as_section()?;
                    stage.handle_genesis_update(&mut self.core, *info)?;
                }
                Variant::Relocate(_) => {
                    let _: &Prefix<_> = msg.src.as_section()?;
                    let signed_relocate = SignedRelocateDetails::new(msg)?;
                    if let Some(params) = stage.handle_relocate(&mut self.core, signed_relocate) {
                        self.relocate(params)
                    }
                }
                Variant::MessageSignature(accumulating_msg) => {
                    stage.handle_message_signature(
                        &mut self.core,
                        *accumulating_msg,
                        *msg.src.as_node()?,
                    )?;
                }
                Variant::BootstrapRequest(name) => stage.handle_bootstrap_request(
                    &mut self.core,
                    msg.src.to_sender_node(sender)?,
                    name,
                ),
                Variant::JoinRequest(join_request) => stage.handle_join_request(
                    &mut self.core,
                    msg.src.to_sender_node(sender)?,
                    *join_request,
                ),
                Variant::MemberKnowledge(payload) => stage.handle_member_knowledge(
                    &mut self.core,
                    msg.src.to_sender_node(sender)?,
                    payload,
                ),
                Variant::ParsecRequest(version, request) => {
                    stage.handle_parsec_request(
                        &mut self.core,
                        version,
                        request,
                        msg.src.to_sender_node(sender)?,
                        &mut self.user_event_tx,
                    )?;
                }
                Variant::ParsecResponse(version, response) => {
                    stage.handle_parsec_response(
                        &mut self.core,
                        version,
                        response,
                        *msg.src.as_node()?,
                        &mut self.user_event_tx,
                    )?;
                }
                Variant::UserMessage(content) => {
                    let _ = self.user_event_tx.send(Event::MessageReceived {
                        content,
                        src: msg.src.location(),
                        dst: msg.dst,
                    });
                }
                Variant::Bounce {
                    elders_version,
                    message,
                } => self.handle_bounce(msg.src.to_sender_node(sender)?, elders_version, message),
                Variant::NodeApproval(_) | Variant::BootstrapResponse(_) | Variant::Ping => {
                    unreachable!()
                }
            },
            Stage::Terminated => unreachable!(),
        }

        Ok(())
    }

    fn handle_bounce(&mut self, sender: P2pNode, sender_version: Option<u64>, msg_bytes: Bytes) {
        let known_version = match &self.stage {
            Stage::Bootstrapping(_) | Stage::Joining(_) => {
                trace!(
                    "Received Bounce of {:?} from {}. Resending",
                    MessageHash::from_bytes(&msg_bytes),
                    sender
                );
                self.core.send_message_to_target_later(
                    sender.peer_addr(),
                    msg_bytes,
                    BOUNCE_RESEND_DELAY,
                );
                return;
            }
            Stage::Approved(stage) => stage
                .chain
                .find_section_by_member(sender.public_id())
                .map(|(_, version)| version),
            Stage::Terminated => unreachable!(),
        };

        if let Some(known_version) = known_version {
            if sender_version
                .map(|sender_version| sender_version < known_version)
                .unwrap_or(true)
            {
                trace!(
                    "Received Bounce of {:?} from {}. Peer is lagging behind, resending in {:?}",
                    MessageHash::from_bytes(&msg_bytes),
                    sender,
                    BOUNCE_RESEND_DELAY
                );
                self.core.send_message_to_target_later(
                    sender.peer_addr(),
                    msg_bytes,
                    BOUNCE_RESEND_DELAY,
                );
            } else {
                trace!(
                    "Received Bounce of {:?} from {}. Peer has moved on, not resending",
                    MessageHash::from_bytes(&msg_bytes),
                    sender
                );
            }
        } else {
            trace!(
                "Received Bounce of {:?} from {}. Peer not known, not resending",
                MessageHash::from_bytes(&msg_bytes),
                sender
            );
        }
    }

    fn unhandled_message(&mut self, sender: Option<SocketAddr>, msg: Message, msg_bytes: Bytes) {
        match &mut self.stage {
            Stage::Bootstrapping(stage) => {
                stage.unhandled_message(&mut self.core, sender, msg, msg_bytes)
            }
            Stage::Joining(stage) => {
                stage.unhandled_message(&mut self.core, sender, msg, msg_bytes)
            }
            Stage::Approved(stage) => {
                stage.unhandled_message(&mut self.core, sender, msg, msg_bytes)
            }
            Stage::Terminated => {}
        }
    }

    ////////////////////////////////////////////////////////////////////////////
    // Transitions
    ////////////////////////////////////////////////////////////////////////////

    // Transition from Bootstrapping to Joining
    fn join(
        &mut self,
        network_cfg: NetworkParams,
        elders_info: EldersInfo,
        relocate_payload: Option<RelocatePayload>,
    ) {
        self.stage = Stage::Joining(Joining::new(
            &mut self.core,
            network_cfg,
            elders_info,
            relocate_payload,
        ));
    }

    // Transition from Joining to Approved
    fn approve(
        &mut self,
        network_cfg: NetworkParams,
        connect_type: Connected,
        gen_pfx_info: GenesisPfxInfo,
    ) {
        info!(
            "This node has been approved to join the network at {:?}!",
            gen_pfx_info.elders_info.prefix(),
        );

        let stage = Approved::new(&mut self.core, network_cfg, gen_pfx_info, None);
        self.stage = Stage::Approved(stage);
        let _ = self.user_event_tx.send(Event::Connected(connect_type));
    }

    // Transition from Approved to Bootstrapping on relocation
    fn relocate(&mut self, params: RelocateParams) {
        let RelocateParams {
            network_cfg,
            conn_infos,
            details,
        } = params;

        let mut stage = Bootstrapping::new(network_cfg, Some(details));

        for conn_info in conn_infos {
            stage.send_bootstrap_request(&mut self.core, conn_info)
        }

        self.stage = Stage::Bootstrapping(stage);
    }

    // Transition from Joining to Bootstrapping on join failure
    fn rebootstrap(&mut self, network_cfg: NetworkParams) {
        // TODO: preserve relocation details
        self.stage = Stage::Bootstrapping(Bootstrapping::new(network_cfg, None));
        self.core.full_id = FullId::gen(&mut self.core.rng);
        self.core.transport.bootstrap();
    }

    fn set_log_ident(&self) -> log_utils::Guard {
        use std::fmt::Write;
        log_utils::set_ident(|buffer| match &self.stage {
            Stage::Bootstrapping(_) => write!(buffer, "Bootstrapping({}) ", self.name()),
            Stage::Joining(stage) => write!(
                buffer,
                "Joining({}({:b})) ",
                self.name(),
                stage.target_section_prefix()
            ),
            Stage::Approved(stage) if !stage.chain.is_self_elder() => write!(
                buffer,
                "Adult({}({:b})) ",
                self.core.name(),
                stage.chain.our_prefix()
            ),
            Stage::Approved(stage) => write!(
                buffer,
                "Elder({}({:b})) ",
                self.core.name(),
                stage.chain.our_prefix()
            ),
            Stage::Terminated => write!(buffer, "Terminated"),
        })
    }
}

#[cfg(feature = "mock_base")]
impl Node {
    /// Returns whether the node is approved member of a section.
    pub fn is_approved(&self) -> bool {
        self.stage.approved().is_some()
    }

    /// Returns whether the node is Elder.
    pub fn is_elder(&self) -> bool {
        self.chain()
            .map(|chain| chain.is_self_elder())
            .unwrap_or(false)
    }

    /// Indicates if there are any pending observations in the parsec object
    pub fn has_unpolled_observations(&self) -> bool {
        self.stage
            .approved()
            .map(|stage| stage.parsec_map.has_unpolled_observations())
            .unwrap_or(false)
    }

    /// Indicates if there are any pending observations in the parsec object
    pub fn unpolled_observations_string(&self) -> String {
        self.stage
            .approved()
            .map(|stage| stage.parsec_map.unpolled_observations_string())
            .unwrap_or_else(String::new)
    }

    /// Returns whether the given peer is an elder of our section.
    pub fn is_peer_our_elder(&self, pub_id: &PublicId) -> bool {
        self.stage
            .approved()
            .map(|stage| stage.chain.is_peer_our_elder(pub_id))
            .unwrap_or(false)
    }

    /// Send a message to the given targets using the given delivery group size.
    pub fn send_message_to_targets(
        &mut self,
        dst_targets: &[SocketAddr],
        dg_size: usize,
        message: Message,
    ) -> Result<(), RoutingError> {
        let message = message.to_bytes()?;
        self.core
            .send_message_to_targets(dst_targets, dg_size, message);
        Ok(())
    }

    /// Returns the version of the latest Parsec instance of this node.
    pub fn parsec_last_version(&self) -> u64 {
        self.stage
            .approved()
            .map(|stage| stage.parsec_map.last_version())
            .unwrap_or(0)
    }

    /// Checks whether the given location represents self.
    pub fn in_src_location(&self, src: &SrcLocation) -> bool {
        self.stage
            .approved()
            .map(|stage| stage.chain.in_src_location(src))
            .unwrap_or(false)
    }

    /// Returns the prefixes of all our neighbours
    pub fn neighbour_prefixes(&self) -> BTreeSet<Prefix<XorName>> {
        self.chain()
            .map(|chain| {
                chain
                    .neighbour_infos()
                    .map(|info| info.prefix())
                    .copied()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Returns the prefixes of all sections known to us
    pub fn prefixes(&self) -> BTreeSet<Prefix<XorName>> {
        self.chain().map(Chain::prefixes).unwrap_or_default()
    }

    /// Returns the elder info version of a section with the given prefix.
    /// Prefix must be either our prefix or of one of our neighbours.
    /// Returns 0 otherwise.
    pub fn section_elder_info_version(&self, prefix: &Prefix<XorName>) -> u64 {
        self.chain()
            .and_then(|chain| chain.get_section(prefix))
            .map(|info| info.version())
            .unwrap_or_default()
    }

    /// Returns the elder of a section with the given prefix.
    /// Prefix must be either our prefix or of one of our neighbours. Returns empty set otherwise.
    pub fn section_elders(&self, prefix: &Prefix<XorName>) -> BTreeSet<XorName> {
        self.chain()
            .and_then(|chain| chain.get_section(prefix))
            .map(|info| info.member_names().copied().collect())
            .unwrap_or_default()
    }

    /// Returns the elders in our and neighbouring sections.
    pub fn elders(&self) -> impl Iterator<Item = &PublicId> {
        self.elder_nodes().map(P2pNode::public_id)
    }

    /// Returns the elders in our and neighbouring sections.
    pub fn elder_nodes(&self) -> impl Iterator<Item = &P2pNode> {
        self.chain().into_iter().flat_map(Chain::elders)
    }

    /// Returns the members in our section and elders we know.
    pub fn known_nodes(&self) -> impl Iterator<Item = &P2pNode> {
        self.chain().into_iter().flat_map(Chain::known_nodes)
    }

    /// Returns whether the given `PublicId` is a member of our section.
    pub fn is_peer_our_member(&self, id: &PublicId) -> bool {
        self.chain()
            .map(|chain| chain.is_peer_our_member(id))
            .unwrap_or(false)
    }

    /// Returns their knowledge
    pub fn get_their_knowledge(&self) -> BTreeMap<Prefix<XorName>, u64> {
        self.chain()
            .map(Chain::get_their_knowledge)
            .cloned()
            .unwrap_or_default()
    }

    /// If our section is the closest one to `name`, returns all names in our section *including
    /// ours*, otherwise returns `None`.
    pub fn close_names(&self, name: &XorName) -> Option<Vec<XorName>> {
        self.chain().and_then(|chain| chain.close_names(name))
    }

    /// Returns the number of elders this node is using.
    /// Only if we have a chain (meaning we are elders or adults) we will process this API
    pub fn elder_size(&self) -> Option<usize> {
        self.chain().map(Chain::elder_size)
    }

    /// Size at which our section splits. Since this is configurable, this method is used to
    /// obtain it.
    ///
    /// Only if we have a chain (meaning we are elders) we will process this API
    pub fn safe_section_size(&self) -> Option<usize> {
        self.chain().map(|chain| chain.safe_section_size())
    }

    /// Provide a SectionProofSlice that proves the given signature to the given destination.
    pub fn prove(&self, target: &DstLocation) -> Option<SectionProofSlice> {
        self.chain().map(|chain| chain.prove(target, None))
    }

    /// Returns the age counter of the given node if it is member of the same section as this node,
    /// `None` otherwise.
    pub fn member_age_counter(&self, name: &XorName) -> Option<u32> {
        self.chain()
            .and_then(|chain| chain.member_age_counter(name))
    }

    fn chain(&self) -> Option<&Chain> {
        self.stage.approved().map(|stage| &stage.chain)
    }
}

#[cfg(not(feature = "mock_base"))]
fn is_busy(_: &Action) -> bool {
    true
}

#[cfg(feature = "mock_base")]
fn is_busy(action: &Action) -> bool {
    match action {
        // Don't consider handling a timeout as being busy. This is a workaround to prevent
        // infinite polling.
        Action::HandleTimeout(_) => false,
        _ => true,
    }
}
