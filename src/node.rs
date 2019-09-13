// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    action::Action,
    config_handler::{self, Config},
    error::{InterfaceError, RoutingError},
    event::Event,
    event_stream::{EventStepper, EventStream},
    id::{FullId, PublicId},
    messages::{Request, Response, UserMessage},
    outbox::{EventBox, EventBuf},
    quic_p2p::OurType,
    routing_table::Authority,
    state_machine::{State, StateMachine},
    states::{self, BootstrappingPeer, TargetState},
    xor_name::XorName,
    NetworkConfig, MIN_SECTION_SIZE,
};
#[cfg(feature = "mock_base")]
use crate::{utils::XorTargetInterval, Chain};
use crossbeam_channel as mpmc;
#[cfg(not(feature = "mock_base"))]
use safe_crypto;
#[cfg(feature = "mock_base")]
use std::fmt::{self, Display, Formatter};
use std::sync::mpsc;
#[cfg(feature = "mock_base")]
use unwrap::unwrap;

/// A builder to configure and create a new `Node`.
pub struct NodeBuilder {
    first: bool,
    config: Option<Config>,
    network_config: Option<NetworkConfig>,
}

impl NodeBuilder {

    /// Configures the node to start a new network instead of joining an existing one.
    pub fn first(self, first: bool) -> NodeBuilder {
        NodeBuilder { first, ..self }
    }

    /// The node will use the configuration options from `config` rather than defaults.
    pub fn config(self, config: Config) -> NodeBuilder {
        NodeBuilder {
            config: Some(config),
            ..self
        }
    }

    /// The node will use the given network config rather than default.
    pub fn network_config(self, config: NetworkConfig) -> NodeBuilder {
        NodeBuilder {
            network_config: Some(config),
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
        // If we're not in a test environment where we might want to manually seed the crypto RNG
        // then seed randomly.
        #[cfg(not(feature = "mock_base"))]
        safe_crypto::init()?;

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
        let full_id = FullId::new();
        let config = self.config.unwrap_or_else(config_handler::get_config);
        let dev_config = config.dev.unwrap_or_default();
        let min_section_size = dev_config.min_section_size.unwrap_or(MIN_SECTION_SIZE);

        let first = self.first;

        let mut network_config = self.network_config.unwrap_or_default();
        network_config.our_type = OurType::Node;

        StateMachine::new(
            move |action_sender, network_service, timer, outbox| {
                if first {
                    states::Elder::first(
                        network_service,
                        full_id,
                        min_section_size,
                        timer,
                        outbox,
                    )
                    .map(State::Elder)
                    .unwrap_or(State::Terminated)
                } else {
                    State::BootstrappingPeer(BootstrappingPeer::new(
                        action_sender,
                        TargetState::RelocatingNode,
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
/// `ManagedNode` or as a part of a section or group authority. Their `src` argument indicates that
/// role, and can be any [`Authority`](enum.Authority.html) other than `Client`.
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
            config: None,
            network_config: None,
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

    /// Send a user request message
    pub fn send_request(
        &mut self,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        msg: Request,
    ) -> Result<(), InterfaceError> {
        self.send_message(src, dst, UserMessage::Request(msg))
    }

    /// Send a user response message
    pub fn send_response(
        &mut self,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        msg: Response,
    ) -> Result<(), InterfaceError> {
        self.send_message(src, dst, UserMessage::Response(msg))
    }

    fn send_message(
        &mut self,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        user_msg: UserMessage,
    ) -> Result<(), InterfaceError> {
        // Make sure the state machine has processed any outstanding network events.
        let _ = self.poll();

        let action = Action::NodeSendMessage {
            src: src,
            dst: dst,
            content: user_msg,
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

    /// Returns this node state.
    pub fn node_state(&self) -> Option<&crate::states::Elder> {
        self.machine.current().elder_state()
    }

    /// Returns this node mut state.
    pub fn node_state_mut(&mut self) -> Option<&mut crate::states::Elder> {
        self.machine.current_mut().elder_state_mut()
    }

    /// Returns this node state unwraped: assume state is Elder.
    pub fn node_state_unchecked(&self) -> &crate::states::Elder {
        unwrap!(self.node_state(), "Should be State::Elder")
    }

    /// Returns whether the current state is `ProvingNode`.
    pub fn proving_node_state(&self) -> Option<&crate::states::ProvingNode> {
        match *self.machine.current() {
            State::ProvingNode(ref state) => Some(state),
            _ => None,
        }
    }

    /// Returns whether the current state is `Node`.
    pub fn is_node(&self) -> bool {
        self.node_state().is_some()
    }

    /// Returns whether the current state is `ProvingNode`.
    pub fn is_proving_node(&self) -> bool {
        self.proving_node_state().is_some()
    }

    /// Sets a name to be used when the next node relocation request is received by this node.
    pub fn set_next_relocation_dst(&mut self, dst: Option<XorName>) {
        let _ = self
            .node_state_mut()
            .map(|state| state.set_next_relocation_dst(dst));
    }

    /// Sets an interval to be used when a node is required to generate a new name.
    pub fn set_next_relocation_interval(&mut self, interval: Option<XorTargetInterval>) {
        let _ = self
            .node_state_mut()
            .map(|state| state.set_next_relocation_interval(interval));
    }

    /// Indicates if there are any pending observations in the parsec object
    pub fn has_unpolled_observations(&self) -> bool {
        self.machine.current().has_unpolled_observations()
    }

    /// Indicates if a given `PublicId` is in the peer manager as a Node
    pub fn is_node_peer(&self, pub_id: &PublicId) -> bool {
        self.node_state()
            .map(|state| state.is_node_peer(pub_id))
            .unwrap_or(false)
    }

    /// Checks whether the given authority represents self.
    pub fn in_authority(&self, auth: &Authority<XorName>) -> bool {
        self.machine.current().in_authority(auth)
    }

    /// Sets a counter to be used ignoring certain number of `CandidateInfo`.
    pub fn set_ignore_candidate_info_counter(&mut self, counter: u8) {
        let _ = self
            .node_state_mut()
            .map(|state| state.set_ignore_candidate_info_counter(counter));
    }
}

#[cfg(feature = "mock_base")]
impl Display for Node {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        self.machine.fmt(formatter)
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self
            .machine
            .current_mut()
            .handle_action(Action::Terminate, &mut self.event_buffer);
        let _ = self.event_buffer.take_all();
    }
}
