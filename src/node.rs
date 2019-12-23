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
    error::{InterfaceError, RoutingError},
    event_stream::{EventStepper, EventStream},
    id::{FullId, P2pNode, PublicId},
    outbox::EventBox,
    pause::PausedState,
    quic_p2p::{OurType, Token},
    rng::{self, MainRng},
    state_machine::{State, StateMachine},
    states::{self, BootstrappingPeer, BootstrappingPeerDetails},
    xor_space::XorName,
    Authority, ConnectionInfo, Event, NetworkBytes, NetworkConfig,
};
use crossbeam_channel as mpmc;
use std::{net::SocketAddr, sync::mpsc};

#[cfg(feature = "mock_base")]
use {
    crate::{chain::SectionProofChain, Chain, Prefix},
    std::{
        collections::{BTreeMap, BTreeSet},
        fmt::{self, Display, Formatter},
    },
    unwrap::unwrap,
};

/// A builder to configure and create a new `Node`.
pub struct NodeBuilder {
    first: bool,
    rng: Option<MainRng>,
    network_config: Option<NetworkConfig>,
    full_id: Option<FullId>,
    network_cfg: NetworkParams,
}

impl NodeBuilder {
    /// Configures the node to start a new network instead of joining an existing one.
    pub fn first(self, first: bool) -> Self {
        Self { first, ..self }
    }

    /// The node will use the given network config rather than default.
    pub fn network_config(self, config: NetworkConfig) -> Self {
        Self {
            network_config: Some(config),
            ..self
        }
    }

    /// The node will use the given full id rather than default, randomly generated one.
    pub fn full_id(self, full_id: FullId) -> Self {
        Self {
            full_id: Some(full_id),
            ..self
        }
    }

    /// Override the default network config.
    pub fn network_cfg(self, network_cfg: NetworkParams) -> Self {
        Self {
            network_cfg,
            ..self
        }
    }

    /// Use the supplied random number generator. If this is not called, a default `OsRng` is used.
    pub fn rng(self, rng: MainRng) -> Self {
        Self {
            rng: Some(rng),
            ..self
        }
    }

    /// Creates new `Node`.
    ///
    /// It will automatically connect to the network in the same way a client does, but then
    /// request a new name and integrate itself into the network using the new name.
    ///
    /// The initial `Node` object will have newly generated keys.
    pub fn create(self) -> Result<(Node, mpmc::Receiver<Event>), RoutingError> {
        // start the handler for routing without a restriction to become a full node
        let (interface_result_tx, interface_result_rx) = mpsc::channel();
        let (mut user_event_tx, user_event_rx) = mpmc::unbounded();

        let (_, machine) = self.make_state_machine(&mut user_event_tx);

        let node = Node {
            user_event_tx,
            user_event_rx: user_event_rx.clone(),
            interface_result_tx,
            interface_result_rx,
            machine,
        };

        Ok((node, user_event_rx))
    }

    fn make_state_machine(self, outbox: &mut dyn EventBox) -> (mpmc::Sender<Action>, StateMachine) {
        let mut rng = self.rng.unwrap_or_else(rng::new);

        let full_id = self.full_id.unwrap_or_else(|| FullId::gen(&mut rng));
        let network_cfg = self.network_cfg;
        let first = self.first;

        let mut network_config = self.network_config.unwrap_or_default();
        network_config.our_type = OurType::Node;

        StateMachine::new(
            move |network_service, timer, outbox| {
                if first {
                    debug!("Creating a first node in the Elder state");

                    states::Elder::first(network_service, full_id, network_cfg, timer, rng, outbox)
                        .map(State::Elder)
                        .unwrap_or(State::Terminated)
                } else {
                    debug!("Creating a node in the BootstrappingPeer state");

                    State::BootstrappingPeer(BootstrappingPeer::new(BootstrappingPeerDetails {
                        network_service,
                        full_id,
                        network_cfg,
                        timer,
                        rng,
                    }))
                }
            },
            network_config,
            outbox,
        )
    }
}

/// Interface for sending and receiving messages to and from other nodes, in the role of a full
/// routing node.
///
/// A node is a part of the network that can route messages and be a member of a section or group
/// authority. Its methods can be used to send requests and responses as either an individual
/// `Node` or as a part of a section or group authority. Their `src` argument indicates that
/// role, and can be any [`Authority`](enum.Authority.html).
pub struct Node {
    user_event_tx: mpmc::Sender<Event>,
    user_event_rx: mpmc::Receiver<Event>,
    interface_result_tx: mpsc::Sender<Result<(), InterfaceError>>,
    interface_result_rx: mpsc::Receiver<Result<(), InterfaceError>>,
    machine: StateMachine,
}

impl Node {
    /// Creates a new builder to configure and create a `Node`.
    pub fn builder() -> NodeBuilder {
        NodeBuilder {
            first: false,
            rng: None,
            network_config: None,
            full_id: None,
            network_cfg: Default::default(),
        }
    }

    /// Pauses the node in order to be upgraded and/or restarted.
    pub fn pause(self) -> Result<PausedState, RoutingError> {
        self.machine.pause()
    }

    /// Resume previously paused node.
    pub fn resume(state: PausedState) -> (Self, mpmc::Receiver<Event>) {
        let (interface_result_tx, interface_result_rx) = mpsc::channel();
        let (user_event_tx, user_event_rx) = mpmc::unbounded();
        let (_, machine) = StateMachine::resume(state);

        let node = Self {
            interface_result_tx,
            interface_result_rx,
            user_event_tx,
            user_event_rx: user_event_rx.clone(),
            machine,
        };

        (node, user_event_rx)
    }

    /// Returns the first `count` names of the nodes in the routing table which are closest
    /// to the given one.
    pub fn close_group(&self, name: XorName, count: usize) -> Option<Vec<XorName>> {
        self.machine.current().close_group(name, count)
    }

    /// Returns the connection information of all the current section elders.
    pub fn our_elders_info(&self) -> Option<impl Iterator<Item = &P2pNode>> {
        self.machine.current().our_elders()
    }

    /// Find out if the given XorName matches our prefix.
    pub fn matches_our_prefix(&self, name: &XorName) -> Result<bool, RoutingError> {
        self.machine.current().matches_our_prefix(name)
    }

    /// Find out the closest Elders to a given XorName that we know of.
    ///
    /// Note that the Adults of a section only know about their section Elders. Hence they will
    /// always return the section Elders' info.
    pub fn closest_known_elders_to(
        &self,
        name: &XorName,
    ) -> Result<impl Iterator<Item = &P2pNode>, RoutingError> {
        self.machine.current().closest_known_elders_to(name)
    }

    /// Returns the `PublicId` of this node.
    pub fn id(&self) -> Result<PublicId, RoutingError> {
        self.machine.current().id().ok_or(RoutingError::Terminated)
    }

    /// Vote for a custom event.
    pub fn vote_for(&mut self, event: Vec<u8>) {
        // TODO: Return interface error here
        let _ = self
            .machine
            .current_mut()
            .elder_state_mut()
            .map(|elder| elder.vote_for_user_event(event));
    }

    /// Send a message.
    pub fn send_message(
        &mut self,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        content: Vec<u8>,
    ) -> Result<(), InterfaceError> {
        // Make sure the state machine has processed any outstanding network events.
        let _ = self.poll();

        let action = Action::SendMessage {
            src: src,
            dst: dst,
            content,
            result_tx: self.interface_result_tx.clone(),
        };

        self.perform_action(action)
    }

    /// Send a message to a client peer.
    pub fn send_message_to_client(
        &mut self,
        peer_addr: SocketAddr,
        msg: NetworkBytes,
        token: Token,
    ) -> Result<(), InterfaceError> {
        // Make sure the state machine has processed any outstanding network events.
        let _ = self.poll();

        let action = Action::SendMessageToClient {
            peer_addr,
            msg,
            token,
            result_tx: self.interface_result_tx.clone(),
        };

        self.perform_action(action)
    }

    /// Disconnect form a client peer.
    pub fn disconnect_from_client(&mut self, peer_addr: SocketAddr) -> Result<(), InterfaceError> {
        // Make sure the state machine has processed any outstanding network events.
        let _ = self.poll();

        let action = Action::DisconnectClient {
            peer_addr,
            result_tx: self.interface_result_tx.clone(),
        };

        self.perform_action(action)
    }

    fn perform_action(&mut self, action: Action) -> Result<(), InterfaceError> {
        let transition = self
            .machine
            .current_mut()
            .handle_action(action, &mut self.user_event_tx);
        self.machine
            .apply_transition(transition, &mut self.user_event_tx);
        self.interface_result_rx.recv()?
    }

    /// Register the node event channels with the provided
    /// [selector](https://docs.rs/crossbeam-channel/0.3/crossbeam_channel/struct.Select.html).
    pub fn register<'a>(&'a mut self, select: &mut mpmc::Select<'a>) {
        self.machine.register(select)
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
    pub fn handle_selected_operation(&mut self, op_index: usize) -> Result<(), mpmc::RecvError> {
        self.machine.step(op_index, &mut self.user_event_tx)
    }

    /// Returns connection info of this node.
    pub fn our_connection_info(&mut self) -> Result<ConnectionInfo, RoutingError> {
        self.machine.current_mut().our_connection_info()
    }
}

impl EventStepper for Node {
    type Item = Event;

    fn produce_events(&mut self) -> Result<(), mpmc::RecvError> {
        let mut sel = mpmc::Select::new();
        self.register(&mut sel);

        let op_index = sel.ready();
        self.machine.step(op_index, &mut self.user_event_tx)
    }

    fn try_produce_events(&mut self) -> Result<(), mpmc::TryRecvError> {
        self.machine.try_step(&mut self.user_event_tx)
    }

    fn pop_item(&mut self) -> Option<Event> {
        self.user_event_rx.try_recv().ok()
    }
}

#[cfg(feature = "mock_base")]
impl Node {
    /// Returns the chain for this node.
    fn chain(&self) -> Option<&Chain> {
        self.machine.current().chain()
    }

    /// Returns the underlying Elder state.
    pub fn elder_state(&self) -> Option<&crate::states::Elder> {
        self.machine.current().elder_state()
    }

    /// Returns mutable reference to the underlying Elder state.
    pub fn elder_state_mut(&mut self) -> Option<&mut crate::states::Elder> {
        self.machine.current_mut().elder_state_mut()
    }

    /// Returns the underlying Elder state unwrapped - panics if not Elder.
    pub fn elder_state_unchecked(&self) -> &crate::states::Elder {
        unwrap!(self.elder_state(), "Should be State::Elder")
    }

    /// Returns whether the current state is `Elder`.
    pub fn is_elder(&self) -> bool {
        self.elder_state().is_some()
    }

    /// Returns whether the current state is `Elder` or `Adult`.
    pub fn is_approved(&self) -> bool {
        match self.machine.current() {
            State::Elder(_) | State::Adult(_) => true,
            _ => false,
        }
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
        self.machine.current().has_unpolled_observations()
    }

    /// Indicates if there are any pending observations in the parsec object
    pub fn unpolled_observations_string(&self) -> String {
        self.machine.current().unpolled_observations_string()
    }

    /// Indicates if this node has the connection info to the given peer.
    pub fn is_connected(&self, socket_addr: &SocketAddr) -> bool {
        self.machine.current().is_connected(socket_addr)
    }

    /// Provide a SectionProofChain that proves the given signature to the section with a given
    /// prefix
    pub fn prove(&self, target: &Authority<XorName>) -> Option<SectionProofChain> {
        self.chain().map(|chain| chain.prove(target, None))
    }

    /// Checks whether the given authority represents self.
    pub fn in_authority(&self, auth: &Authority<XorName>) -> bool {
        self.machine.current().in_authority(auth)
    }

    /// Returns the age counter of the given node if it is member of the same section as this node,
    /// `None` otherwise.
    pub fn member_age_counter(&self, name: &XorName) -> Option<u32> {
        self.chain()
            .and_then(|chain| chain.member_age_counter(name))
    }
}

#[cfg(feature = "mock_base")]
impl Display for Node {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        self.machine.fmt(formatter)
    }
}
