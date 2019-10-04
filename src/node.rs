// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    action::Action,
    error::{InterfaceError, RoutingError},
    event::Event,
    event_stream::{EventStepper, EventStream},
    id::{FullId, PublicId},
    outbox::{EventBox, EventBuf},
    pause::PausedState,
    quic_p2p::OurType,
    routing_table::Authority,
    state_machine::{State, StateMachine},
    states::{self, BootstrappingPeer},
    xor_name::XorName,
    NetworkConfig, MIN_SECTION_SIZE,
};
#[cfg(feature = "mock_base")]
use crate::{quic_p2p::NodeInfo, utils::XorTargetInterval, Chain, Prefix};
use crossbeam_channel as mpmc;
use std::sync::mpsc;
#[cfg(feature = "mock_base")]
use std::{
    collections::BTreeSet,
    fmt::{self, Display, Formatter},
};
#[cfg(feature = "mock_base")]
use unwrap::unwrap;

/// A builder to configure and create a new `Node`.
pub struct NodeBuilder {
    first: bool,
    network_config: Option<NetworkConfig>,
    full_id: Option<FullId>,
    min_section_size: usize,
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

    /// Override the default min section size.
    pub fn min_section_size(self, min_section_size: usize) -> Self {
        Self {
            min_section_size,
            ..self
        }
    }

    /// Creates new `Node`.
    ///
    /// It will automatically connect to the network in the same way a client does, but then
    /// request a new name and integrate itself into the network using the new name.
    ///
    /// The initial `Node` object will have newly generated keys.
    pub fn create(self) -> Result<Node, RoutingError> {
        let mut ev_buffer = EventBuf::new();

        // start the handler for routing without a restriction to become a full node
        let (_, machine) = self.make_state_machine(&mut ev_buffer);
        let (tx, rx) = mpsc::channel();

        Ok(Node {
            interface_result_tx: tx,
            interface_result_rx: rx,
            machine: machine,
            event_buffer: ev_buffer,
        })
    }

    fn make_state_machine(self, outbox: &mut dyn EventBox) -> (mpmc::Sender<Action>, StateMachine) {
        let full_id = self.full_id.unwrap_or_else(FullId::new);
        let min_section_size = self.min_section_size;

        let first = self.first;

        let mut network_config = self.network_config.unwrap_or_default();
        network_config.our_type = OurType::Node;

        StateMachine::new(
            move |network_service, timer, outbox| {
                if first {
                    states::Elder::first(network_service, full_id, min_section_size, timer, outbox)
                        .map(State::Elder)
                        .unwrap_or(State::Terminated)
                } else {
                    State::BootstrappingPeer(BootstrappingPeer::new(
                        network_service,
                        full_id,
                        min_section_size,
                        timer,
                    ))
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
    interface_result_tx: mpsc::Sender<Result<(), InterfaceError>>,
    interface_result_rx: mpsc::Receiver<Result<(), InterfaceError>>,
    machine: StateMachine,
    event_buffer: EventBuf,
}

impl Node {
    /// Creates a new builder to configure and create a `Node`.
    pub fn builder() -> NodeBuilder {
        NodeBuilder {
            first: false,
            network_config: None,
            full_id: None,
            min_section_size: MIN_SECTION_SIZE,
        }
    }

    /// Pauses the node in order to be upgraded and/or restarted.
    pub fn pause(self) -> Result<PausedState, RoutingError> {
        self.machine.pause()
    }

    /// Resume previously paused node.
    pub fn resume(state: PausedState) -> Self {
        let (interface_result_tx, interface_result_rx) = mpsc::channel();
        let event_buffer = EventBuf::new();
        let (_, machine) = StateMachine::resume(state);

        Self {
            interface_result_tx,
            interface_result_rx,
            machine,
            event_buffer,
        }
    }

    /// Returns the first `count` names of the nodes in the routing table which are closest
    /// to the given one.
    pub fn close_group(&self, name: XorName, count: usize) -> Option<Vec<XorName>> {
        self.machine.current().close_group(name, count)
    }

    /// Returns the `PublicId` of this node.
    pub fn id(&self) -> Result<PublicId, RoutingError> {
        self.machine.current().id().ok_or(RoutingError::Terminated)
    }

    /// Returns the minimum section size this vault is using.
    pub fn min_section_size(&self) -> usize {
        self.machine.current().min_section_size()
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

        let transition = self
            .machine
            .current_mut()
            .handle_action(action, &mut self.event_buffer);
        self.machine
            .apply_transition(transition, &mut self.event_buffer);
        self.interface_result_rx.recv()?
    }
}

impl EventStepper for Node {
    type Item = Event;

    fn produce_events(&mut self) -> Result<(), mpmc::RecvError> {
        self.machine.step(&mut self.event_buffer)
    }

    fn try_produce_events(&mut self) -> Result<(), mpmc::TryRecvError> {
        self.machine.try_step(&mut self.event_buffer)
    }

    fn pop_item(&mut self) -> Option<Event> {
        self.event_buffer.take_first()
    }
}

#[cfg(feature = "mock_base")]
impl Node {
    /// Returns the chain for this node.
    pub fn chain(&self) -> Option<&Chain> {
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

    /// Our `Prefix` once we are a part of the section.
    pub fn our_prefix(&self) -> Option<&Prefix<XorName>> {
        self.chain().map(|chain| chain.our_prefix())
    }

    /// Our `XorName`.
    pub fn our_name(&self) -> Option<&XorName> {
        self.chain().map(|chain| chain.our_id().name())
    }

    /// Returns the prefixes of all out neighbours.
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

    /// Returns the members of a section with the given prefix.
    /// Prefix must be either our prefix or of one of our neighbours. Returns empty set otherwise.
    pub fn section_members(&self, prefix: &Prefix<XorName>) -> BTreeSet<XorName> {
        self.chain()
            .and_then(|chain| {
                chain
                    .all_sections()
                    .find(|(sec_prefix, _)| prefix == *sec_prefix)
                    .map(|(_, elder_info)| elder_info.member_names())
            })
            .unwrap_or_default()
    }

    /// Sets a name to be used when the next node relocation request is received by this node.
    pub fn set_next_relocation_dst(&mut self, dst: Option<XorName>) {
        let _ = self
            .elder_state_mut()
            .map(|state| state.set_next_relocation_dst(dst));
    }

    /// Sets an interval to be used when a node is required to generate a new name.
    pub fn set_next_relocation_interval(&mut self, interval: Option<XorTargetInterval>) {
        let _ = self
            .elder_state_mut()
            .map(|state| state.set_next_relocation_interval(interval));
    }

    /// Indicates if there are any pending observations in the parsec object
    pub fn has_unpolled_observations(&self) -> bool {
        self.machine.current().has_unpolled_observations()
    }

    /// Indicates if this node has the connection info to the given peer.
    pub fn is_connected<N: AsRef<XorName>>(&self, name: N) -> bool {
        self.machine.current().is_connected(name)
    }

    /// Checks whether the given authority represents self.
    pub fn in_authority(&self, auth: &Authority<XorName>) -> bool {
        self.machine.current().in_authority(auth)
    }

    /// Returns connection info of this node.
    pub fn our_connection_info(&mut self) -> Result<NodeInfo, RoutingError> {
        self.machine.current_mut().our_connection_info()
    }
}

#[cfg(feature = "mock_base")]
impl Display for Node {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        self.machine.fmt(formatter)
    }
}
