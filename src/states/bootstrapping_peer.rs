// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    client::{Client, ClientDetails},
    common::Base,
    proving_node::{ProvingNode, ProvingNodeDetails},
    relocating_node::{RelocatingNode, RelocatingNodeDetails},
};
use crate::{
    action::Action,
    cache::Cache,
    error::{InterfaceError, RoutingError},
    event::Event,
    id::{FullId, PublicId},
    messages::{DirectMessage, HopMessage, Request, UserMessage},
    outbox::EventBox,
    peer_map::PeerMap,
    quic_p2p::NodeInfo,
    quic_p2p::Peer,
    routing_table::{Authority, Prefix},
    state_machine::{State, Transition},
    timer::Timer,
    xor_name::XorName,
    NetworkService,
};
use crossbeam_channel as mpmc;
use std::{
    collections::BTreeSet,
    fmt::{self, Display, Formatter},
    net::SocketAddr,
    time::Duration,
};

// Time (in seconds) after which bootstrap is cancelled (and possibly retried).
const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(20);

// State to transition into after bootstrap process is complete.
// FIXME - See https://maidsafe.atlassian.net/browse/MAID-2026 for info on removing this exclusion.
#[allow(clippy::large_enum_variant)]
pub enum TargetState {
    Client {
        msg_expiry_dur: Duration,
    },
    RelocatingNode,
    ProvingNode {
        old_full_id: FullId,
        our_section: (Prefix<XorName>, BTreeSet<PublicId>),
    },
}

// State of Client or Node while bootstrapping.
pub struct BootstrappingPeer {
    action_sender: mpmc::Sender<Action>,
    bootstrap_connection: Option<(NodeInfo, u64)>,
    cache: Box<Cache>,
    network_service: NetworkService,
    full_id: FullId,
    min_section_size: usize,
    peer_map: PeerMap,
    target_state: TargetState,
    timer: Timer,
}

impl BootstrappingPeer {
    pub fn new(
        action_sender: mpmc::Sender<Action>,
        cache: Box<Cache>,
        target_state: TargetState,
        mut network_service: NetworkService,
        full_id: FullId,
        min_section_size: usize,
        timer: Timer,
    ) -> Self {
        network_service.bootstrap();

        Self {
            action_sender,
            cache: cache,
            network_service,
            full_id,
            min_section_size,
            timer: timer,
            bootstrap_connection: None,
            peer_map: PeerMap::new(),
            target_state,
        }
    }

    pub fn into_target_state(
        self,
        proxy_pub_id: PublicId,
        outbox: &mut EventBox,
    ) -> Result<State, RoutingError> {
        match self.target_state {
            TargetState::Client { msg_expiry_dur } => {
                Ok(State::Client(Client::from_bootstrapping(
                    ClientDetails {
                        network_service: self.network_service,
                        full_id: self.full_id,
                        min_section_size: self.min_section_size,
                        msg_expiry_dur,
                        peer_map: self.peer_map,
                        proxy_pub_id,
                        timer: self.timer,
                    },
                    outbox,
                )))
            }
            TargetState::RelocatingNode => {
                let details = RelocatingNodeDetails {
                    action_sender: self.action_sender,
                    cache: self.cache,
                    network_service: self.network_service,
                    full_id: self.full_id,
                    min_section_size: self.min_section_size,
                    peer_map: self.peer_map,
                    proxy_pub_id,
                    timer: self.timer,
                };

                RelocatingNode::from_bootstrapping(details)
                    .map(State::RelocatingNode)
                    .map_err(|err| {
                        outbox.send_event(Event::RestartRequired);
                        err
                    })
            }
            TargetState::ProvingNode {
                old_full_id,
                our_section,
                ..
            } => {
                let details = ProvingNodeDetails {
                    action_sender: self.action_sender,
                    cache: self.cache,
                    network_service: self.network_service,
                    full_id: self.full_id,
                    min_section_size: self.min_section_size,
                    old_full_id,
                    our_section,
                    peer_map: self.peer_map,
                    proxy_pub_id,
                    timer: self.timer,
                };

                ProvingNode::from_bootstrapping(details, outbox).map(State::ProvingNode)
            }
        }
    }

    fn send_bootstrap_request(&mut self, dst: NodeInfo) {
        debug!("{} Sending BootstrapRequest to {}.", self, dst.peer_addr);

        let token = self.timer.schedule(BOOTSTRAP_TIMEOUT);
        self.bootstrap_connection = Some((dst.clone(), token));

        let message =
            if let Ok(message) = self.to_signed_direct_message(DirectMessage::BootstrapRequest) {
                message
            } else {
                return;
            };

        self.send_message_over_network(Peer::Node { node_info: dst }, message);
    }

    fn rebootstrap(&mut self) {
        if let Some((node_info, _)) = self.bootstrap_connection.take() {
            debug!(
                "{} Dropping bootstrap node at {} and retrying.",
                self, node_info.peer_addr
            );
            self.network_service.disconnect_from(node_info.peer_addr);
            self.network_service.bootstrap();
        }
    }
}

impl Base for BootstrappingPeer {
    fn network_service(&self) -> &NetworkService {
        &self.network_service
    }

    fn network_service_mut(&mut self) -> &mut NetworkService {
        &mut self.network_service
    }

    fn full_id(&self) -> &FullId {
        &self.full_id
    }

    fn in_authority(&self, _: &Authority<XorName>) -> bool {
        false
    }

    fn min_section_size(&self) -> usize {
        self.min_section_size
    }

    fn peer_map(&self) -> &PeerMap {
        &self.peer_map
    }

    fn peer_map_mut(&mut self) -> &mut PeerMap {
        &mut self.peer_map
    }

    fn handle_client_send_request(
        &mut self,
        _: Authority<XorName>,
        _: Request,
        _: u8,
    ) -> Result<(), InterfaceError> {
        warn!(
            "{} - Cannot handle ClientSendRequest - not bootstrapped.",
            self
        );
        // TODO: return Err here eventually. Returning Ok for now to
        // preserve the pre-refactor behaviour.
        Ok(())
    }

    fn handle_node_send_message(
        &mut self,
        _: Authority<XorName>,
        _: Authority<XorName>,
        _: UserMessage,
        _: u8,
    ) -> Result<(), InterfaceError> {
        warn!(
            "{} - Cannot handle NodeSendMessage - not bootstrapped.",
            self
        );
        // TODO: return Err here eventually. Returning Ok for now to
        // preserve the pre-refactor behaviour.
        Ok(())
    }

    fn handle_timeout(&mut self, token: u64, _: &mut EventBox) -> Transition {
        if let Some((node_info, bootstrap_token)) = self.bootstrap_connection.as_ref() {
            if *bootstrap_token == token {
                debug!(
                    "{} - Timeout when trying to bootstrap against {}.",
                    self, node_info.peer_addr
                );

                self.rebootstrap();
            }
        }

        Transition::Stay
    }

    fn handle_bootstrapped_to(&mut self, node_info: NodeInfo) -> Transition {
        self.peer_map_mut().connect(Peer::Node {
            node_info: node_info.clone(),
        });

        if self.bootstrap_connection.is_none() {
            debug!(
                "{} Received BootstrappedTo event from {}.",
                self, node_info.peer_addr
            );

            // Established connection. Pending Validity checks
            self.send_bootstrap_request(node_info);
        } else {
            warn!("{} Received more than one BootstrappedTo event", self);
        }

        Transition::Stay
    }

    fn handle_bootstrap_failure(&mut self, outbox: &mut EventBox) -> Transition {
        info!("{} Failed to bootstrap. Terminating.", self);
        outbox.send_event(Event::Terminated);
        Transition::Terminate
    }

    fn handle_connection_failure(&mut self, peer_addr: SocketAddr, _: &mut EventBox) -> Transition {
        let _ = self.peer_map_mut().disconnect(peer_addr);

        if let Some((node_info, _)) = self.bootstrap_connection.as_ref() {
            if node_info.peer_addr == peer_addr {
                info!("{} Lost connection to proxy {}.", self, peer_addr);
                self.rebootstrap();
            }
        }

        Transition::Stay
    }

    fn handle_direct_message(
        &mut self,
        msg: DirectMessage,
        pub_id: PublicId,
        _: &mut EventBox,
    ) -> Result<Transition, RoutingError> {
        use crate::messages::DirectMessage::*;
        match msg {
            BootstrapResponse(Ok(())) => Ok(Transition::IntoBootstrapped {
                proxy_public_id: pub_id,
            }),
            BootstrapResponse(Err(error)) => {
                info!("{} Connection failed: {}", self, error);
                self.rebootstrap();
                Ok(Transition::Stay)
            }
            _ => {
                debug!("{} - Unhandled direct message: {:?}", self, msg);
                Ok(Transition::Stay)
            }
        }
    }

    fn handle_hop_message(
        &mut self,
        msg: HopMessage,
        _: &mut EventBox,
    ) -> Result<Transition, RoutingError> {
        debug!("{} - Unhandled hop message: {:?}", self, msg);
        Ok(Transition::Stay)
    }
}

impl Display for BootstrappingPeer {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "BootstrappingPeer({})", self.name())
    }
}

#[cfg(all(test, feature = "mock_base"))]
mod tests {
    use super::*;
    use crate::{
        cache::NullCache, id::FullId, messages::Message, mock::Network, outbox::EventBuf,
        quic_p2p::Builder, state_machine::StateMachine, states::common::from_network_bytes,
        NetworkConfig, NetworkEvent,
    };
    use crossbeam_channel as mpmc;
    use unwrap::unwrap;

    #[test]
    // Check that losing our proxy connection while in the `BootstrappingPeer` state doesn't stall
    // and instead triggers a re-bootstrap attempt..
    fn lose_proxy_connection() {
        let min_section_size = 8;
        let network = Network::new(min_section_size, None);

        // Start a bare-bones network service.
        let (event_tx, event_rx) = mpmc::unbounded();
        let node_endpoint = network.gen_next_addr();
        let node_network_service = unwrap!(Builder::new(event_tx).build());

        // Construct a `StateMachine` which will start in the `BootstrappingPeer` state and
        // bootstrap off the network service above.
        let config = NetworkConfig::client().with_hard_coded_contact(node_endpoint);
        let client_endpoint = network.gen_next_addr();
        let client_full_id = FullId::new();
        let mut client_outbox = EventBuf::new();
        let mut client_state_machine = StateMachine::new(
            move |action_tx, network_service, timer, _outbox2| {
                State::BootstrappingPeer(BootstrappingPeer::new(
                    action_tx,
                    Box::new(NullCache),
                    TargetState::Client {
                        msg_expiry_dur: Duration::from_secs(60),
                    },
                    network_service,
                    client_full_id,
                    min_section_size,
                    timer,
                ))
            },
            config,
            &mut client_outbox,
        )
        .1;

        // Check the network service received `ConnectedTo`.
        network.poll();
        match unwrap!(event_rx.try_recv()) {
            NetworkEvent::ConnectedTo {
                peer: Peer::Client { .. },
            } => (),
            _ => panic!("Should have received `ConnectedTo` event."),
        }

        // The state machine should have received the `BootstrappedTo` event and this will have
        // caused it to send a `BootstrapRequest` message.
        network.poll();
        step_at_least_once(&mut client_state_machine, &mut client_outbox);

        // Check the network service received the `BootstrapRequest`
        network.poll();
        if let NetworkEvent::NewMessage { peer_addr, msg } = unwrap!(event_rx.try_recv()) {
            assert_eq!(peer_addr, client_endpoint);

            let ok = match unwrap!(from_network_bytes(msg)) {
                Message::Direct(msg) => match *msg.content() {
                    DirectMessage::BootstrapRequest => true,
                    _ => false,
                },
                _ => false,
            };

            if !ok {
                panic!("Should have received a `BootstrapRequest`.");
            }
        } else {
            panic!("Should have received `NewMessage` event.");
        }

        // Drop the network service...
        drop(node_network_service);
        network.poll();

        // ...which triggers `ConnectionFailure` on the state machine which then attempts to
        // rebootstrap..
        step_at_least_once(&mut client_state_machine, &mut client_outbox);
        assert!(client_outbox.take_all().is_empty());
        network.poll();

        // ... but there is no one to bootstrap to, so the bootstrap fails which causes the state
        // machine to terminate.
        step_at_least_once(&mut client_state_machine, &mut client_outbox);
        let events = client_outbox.take_all();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0], Event::Terminated);
    }
    fn step_at_least_once(machine: &mut StateMachine, outbox: &mut EventBox) {
        // Blocking step for the first one. Must not err.
        unwrap!(machine.step(outbox));
        // Exhaust any remaining step
        while machine.try_step(outbox).is_ok() {}
    }
}
