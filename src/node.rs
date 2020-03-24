// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    action::Action,
    chain::NetworkParams,
    core::{Core, CoreConfig},
    error::RoutingError,
    event::Event,
    id::{FullId, P2pNode, PublicId},
    location::{DstLocation, SrcLocation},
    pause::PausedState,
    quic_p2p::{EventSenders, Token},
    rng,
    states::ApprovedPeer,
    xor_space::XorName,
    NetworkConfig, NetworkEvent,
};
use bytes::Bytes;
use crossbeam_channel as mpmc;
use rand::RngCore;
use std::{net::SocketAddr, sync::mpsc};

#[cfg(feature = "mock_base")]
use {
    crate::{
        chain::{Chain, SectionProofSlice},
        Prefix,
    },
    std::collections::{BTreeMap, BTreeSet},
};

/// A builder to configure and create a new `Node`.
pub struct Builder {
    first: bool,
    config: CoreConfig,
}

impl Builder {
    /// Configures the node to start a new network instead of joining an existing one.
    pub fn first(self, first: bool) -> Self {
        Self { first, ..self }
    }

    /// The node will use the given network config rather than default.
    pub fn network_config(mut self, config: NetworkConfig) -> Self {
        self.config.network_config = config;
        self
    }

    /// The node will use the given full id rather than default, randomly generated one.
    pub fn full_id(mut self, full_id: FullId) -> Self {
        self.config.full_id = Some(full_id);
        self
    }

    /// Override the default network params.
    pub fn network_params(mut self, network_params: NetworkParams) -> Self {
        self.config.network_params = network_params;
        self
    }

    /// Use the supplied random number generator. If this is not called, a default `OsRng` is used.
    pub fn rng<R: RngCore>(mut self, rng: &mut R) -> Self {
        self.config.rng = rng::new_from(rng);
        self
    }

    /// Creates new `Node`.
    pub fn create(self) -> (Node, mpmc::Receiver<Event>, mpmc::Receiver<NetworkEvent>) {
        let (interface_result_tx, interface_result_rx) = mpsc::channel();
        let (mut user_event_tx, user_event_rx) = mpmc::unbounded();

        let (action_tx, action_rx) = mpmc::unbounded();

        let (network_tx, network_node_rx, network_client_rx) = {
            let (client_tx, client_rx) = mpmc::unbounded();
            let (node_tx, node_rx) = mpmc::unbounded();
            (EventSenders { node_tx, client_tx }, node_rx, client_rx)
        };

        let network_params = self.config.network_params;
        let core = Core::new(self.config, action_tx, network_tx);
        let state = if self.first {
            debug!("Creating the first node");
            ApprovedPeer::first(
                core,
                network_params,
                action_rx,
                network_node_rx,
                &mut user_event_tx,
            )
        } else {
            debug!("Creating a regular node");
            ApprovedPeer::new(core, network_params, action_rx, network_node_rx)
        };

        let node = Node {
            user_event_tx,
            interface_result_tx,
            interface_result_rx,
            state,
        };

        (node, user_event_rx, network_client_rx)
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
    user_event_tx: mpmc::Sender<Event>,
    interface_result_tx: mpsc::Sender<Result<(), RoutingError>>,
    interface_result_rx: mpsc::Receiver<Result<(), RoutingError>>,
    state: ApprovedPeer,
}

impl Node {
    /// Creates a new builder to configure and create a `Node`.
    pub fn builder() -> Builder {
        Builder {
            first: false,
            config: Default::default(),
        }
    }

    /// Pauses the node in order to be upgraded and/or restarted.
    pub fn pause(self) -> Result<PausedState, RoutingError> {
        Ok(self.state.pause())
    }

    /// Resume previously paused node.
    pub fn resume(state: PausedState) -> (Self, mpmc::Receiver<Event>) {
        let (interface_result_tx, interface_result_rx) = mpsc::channel();
        let (user_event_tx, user_event_rx) = mpmc::unbounded();
        let (state, _) = ApprovedPeer::resume(state);

        let node = Self {
            interface_result_tx,
            interface_result_rx,
            user_event_tx,
            state,
        };

        (node, user_event_rx)
    }

    /// Returns the first `count` names of the nodes in the routing table which are closest
    /// to the given one.
    pub fn close_group(&self, name: XorName, count: usize) -> Option<Vec<XorName>> {
        self.state.close_group(name, count)
    }

    /// Returns the connection information of all the current section elders.
    pub fn our_elders_info(&self) -> impl Iterator<Item = &P2pNode> {
        self.state.our_elders()
    }

    /// Find out if the given XorName matches our prefix.
    pub fn matches_our_prefix(&self, name: &XorName) -> Result<bool, RoutingError> {
        if let Some(prefix) = self.state.our_prefix() {
            Ok(prefix.matches(name))
        } else {
            Err(RoutingError::InvalidState)
        }
    }

    /// Find out the closest Elders to a given XorName that we know of.
    ///
    /// Note that the Adults of a section only know about their section Elders. Hence they will
    /// always return the section Elders' info.
    pub fn closest_known_elders_to(&self, name: &XorName) -> impl Iterator<Item = &P2pNode> {
        self.state.closest_known_elders_to(name)
    }

    /// Returns the `PublicId` of this node.
    pub fn id(&self) -> &PublicId {
        self.state.id()
    }

    /// The name of this node.
    pub fn name(&self) -> &XorName {
        self.id().name()
    }

    /// Vote for a custom event.
    pub fn vote_for(&mut self, event: Vec<u8>) {
        self.state.vote_for_user_event(event)
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
    ) -> Result<(), RoutingError> {
        let action = Action::SendMessageToClient {
            peer_addr,
            msg,
            token,
            result_tx: self.interface_result_tx.clone(),
        };

        self.perform_action(action)
    }

    /// Disconnect form a client peer.
    pub fn disconnect_from_client(&mut self, peer_addr: SocketAddr) -> Result<(), RoutingError> {
        let action = Action::DisconnectClient {
            peer_addr,
            result_tx: self.interface_result_tx.clone(),
        };

        self.perform_action(action)
    }

    fn perform_action(&mut self, action: Action) -> Result<(), RoutingError> {
        self.state.handle_action(action, &mut self.user_event_tx);
        self.interface_result_rx.recv()?
    }

    /// Register the node event channels with the provided
    /// [selector](https://docs.rs/crossbeam-channel/0.3/crossbeam_channel/struct.Select.html).
    pub fn register<'a>(&'a mut self, select: &mut mpmc::Select<'a>) {
        self.state.register(select)
    }

    /// Processes events received externally from one of the channels.
    /// For this function to work properly, the state machine event channels need to
    /// be registered by calling [`Node::register`].
    /// [`Select::ready`] needs to be called to get `op_index`,
    /// the event channel index. The resulting events are streamed into `outbox`.
    ///
    /// This function is non-blocking.
    ///
    /// Errors are permanent failures due to either: state machine termination,
    /// the permanent closing of one of the event channels, or an invalid (unknown)
    /// channel index.
    ///
    /// [`Node::register`]: #method.register
    /// [`Select::ready`]: https://docs.rs/crossbeam-channel/0.3/crossbeam_channel/struct.Select.html#method.ready
    pub fn handle_selected_operation(&mut self, op_index: usize) -> Result<bool, mpmc::RecvError> {
        self.state.step(op_index, &mut self.user_event_tx)
    }

    /// Returns connection info of this node.
    pub fn our_connection_info(&mut self) -> Result<SocketAddr, RoutingError> {
        self.state.our_connection_info()
    }
}

#[cfg(feature = "mock_base")]
impl Node {
    /// Returns the chain for this node.
    fn chain(&self) -> Option<&Chain> {
        self.state.chain()
    }

    /// Returns the underlying ApprovedPeer state.
    pub fn approved_peer_state(&self) -> &ApprovedPeer {
        &self.state
    }

    /// Returns mutable reference to the underlying ApprovedPeer state.
    pub fn approved_peer_state_mut(&mut self) -> &mut ApprovedPeer {
        &mut self.state
    }

    /// Returns whether the node is Elder.
    pub fn is_elder(&self) -> bool {
        self.chain()
            .map(|chain| chain.is_self_elder())
            .unwrap_or(false)
    }

    /// Returns whether the node is approved member of a section (Infant, Adult or Elder).
    pub fn is_approved(&self) -> bool {
        self.state.is_approved()
    }

    /// Our `Prefix` once we are a part of the section.
    pub fn our_prefix(&self) -> Option<&Prefix<XorName>> {
        self.chain().map(Chain::our_prefix)
    }

    /// Returns the prefixes of all out neighbours signed by our section
    pub fn neighbour_prefixes(&self) -> BTreeSet<Prefix<XorName>> {
        if let Some(chain) = self.chain() {
            chain
                .neighbour_infos()
                .map(|info| info.prefix())
                .cloned()
                .collect()
        } else {
            Default::default()
        }
    }

    /// Collects prefixes of all sections known by the routing table into a `BTreeSet`.
    pub fn prefixes(&self) -> BTreeSet<Prefix<XorName>> {
        self.chain().map(Chain::prefixes).unwrap_or_default()
    }

    /// Returns the elder info version of a section with the given prefix.
    /// Prefix must be either our prefix or of one of our neighbours. 0 otherwise.
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

    /// Returns the number of elders this vault is using.
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

    /// Indicates if there are any pending observations in the parsec object
    pub fn has_unpolled_observations(&self) -> bool {
        self.state.has_unpolled_observations()
    }

    /// Indicates if there are any pending observations in the parsec object
    pub fn unpolled_observations_string(&self) -> String {
        self.state.unpolled_observations_string()
    }

    /// Provide a SectionProofSlice that proves the given signature to the given destination.
    pub fn prove(&self, target: &DstLocation) -> Option<SectionProofSlice> {
        self.chain().map(|chain| chain.prove(target, None))
    }

    /// Checks whether the given location represents self.
    pub fn in_src_location(&self, src: &SrcLocation) -> bool {
        self.state.in_src_location(src)
    }

    /// Checks whether the given location represents self.
    pub fn in_dst_location(&self, dst: &DstLocation) -> bool {
        self.state.in_dst_location(dst)
    }

    /// Returns the age counter of the given node if it is member of the same section as this node,
    /// `None` otherwise.
    pub fn member_age_counter(&self, name: &XorName) -> Option<u32> {
        self.chain()
            .and_then(|chain| chain.member_age_counter(name))
    }
}
